"""Phase 4 exit criterion (spec 17, 16.3, D31): every TLS mode on localnet.

Kit miners run as processes (``e2e_miner_app.py``, configured by ``TW_*``
only) and publish with the real chain gateway; the validator side queries
them here from the metagraph the chain serves. Certificates are generated in
``tmp_path`` at test time.

1. ``miner_go`` serves TLS from uvicorn (P-256): it publishes its key with
   ``ServeAxonTls`` and reads it back; ``https-if-tls-published`` and
   ``https`` pin it, ``http`` ignores it. Then it rotates its certificate
   with publishing off: refused (``tw.tls_pin_mismatch``, nothing reaches
   the miner over HTTP). Then it publishes the new key: accepted again.
2. ``miner_py`` publishes no key: ``https-if-tls-published`` and ``http``
   use plain HTTP, ``https`` fails (``tw.connect_error``).
3. ``miner_go`` behind Caddy (``deploy/proxy/Caddyfile``, Docker): proxy
   mode with ``TW_TLS_PUBLISHED_CERT_FILE``; pinned through the proxy.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from localnet_env import ENDPOINT, Localnet
from test_validator_e2e_localnet import (
    EXTERNAL_IP,
    PUBLISH_TIMEOUT_S,
    VALIDATOR_WALLET,
    Process,
    _base_env,
    _free_port,
    _stop,
    _until,
)

from taowire.auth.signer import RequestSigner
from taowire.chain.axon import Endpoint
from taowire.chain.gateway import BittensorGateway, NeuronView
from taowire.observability.metrics import Metrics
from taowire.testing.tls import TestCertificate, make_certificate
from taowire.tls import load_published_certificate, pinned_context
from taowire.validator.client import MinerResult, SchemePolicy, ValidatorClient

HERE = Path(__file__).resolve().parent
DEPLOY = HERE.parents[2] / "deploy" / "proxy"
TLS_WALLET = "miner_go"
PLAIN_WALLET = "miner_py"
BODY = json.dumps({"text": "tls", "op": "upper"}).encode()
CADDY_IMAGE = "caddy:2.10.2-alpine"

pytestmark = pytest.mark.localnet


def _start(env: dict[str, str], log: Path) -> Process:
    out = log.open("ab")
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, this test's own script
        [sys.executable, str(HERE / "e2e_miner_app.py")],
        env=env,
        cwd=HERE,
        stdout=out,
        stderr=subprocess.STDOUT,
    )
    return Process(proc, log, out)


def _env(
    localnet: Localnet, wallet: str, tmp: Path, port: int, **tw: str
) -> dict[str, str]:
    env = _base_env(localnet, wallet, tmp / f"{wallet}-state")
    env.update(
        {
            "TW_BIND_HOST": EXTERNAL_IP,
            "TW_BIND_PORT": str(port),
            "TW_EXTERNAL_IP": EXTERNAL_IP,
            "PYTHONPATH": str(HERE),
        }
    )
    env.update({f"TW_{k.upper()}": v for k, v in tw.items()})
    return env


def _tls(cert: TestCertificate) -> dict[str, str]:
    return {"tls_cert_file": str(cert.cert_file), "tls_key_file": str(cert.key_file)}


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    target = os.environ.get("TAOWIRE_E2E_EVIDENCE_DIR")
    path = Path(target) if target else tmp_path / "evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture
async def gateway() -> Any:
    gw = BittensorGateway(ENDPOINT, allow_private_axons=True)
    await gw.connect()
    try:
        yield gw
    finally:
        await gw.close()


async def _neuron(gw: BittensorGateway, netuid: int, hotkey: str) -> NeuronView:
    neuron = (await gw.metagraph(netuid)).by_hotkey(hotkey)
    assert neuron is not None
    return neuron


async def _published(
    gw: BittensorGateway,
    localnet: Localnet,
    wallet: str,
    want: Endpoint,
    key: bytes | None,
    process: Process,
) -> NeuronView:
    """Wait until the chain shows ``want`` (and ``key``) for ``wallet``."""
    hotkey = localnet.wallets[wallet]["hotkey"]

    async def check() -> NeuronView | None:
        neuron = await _neuron(gw, localnet.netuid, hotkey)
        if neuron.axon != want or (key is not None and neuron.tls_key != key):
            return None
        return neuron

    timeout = localnet.wait_s(120, PUBLISH_TIMEOUT_S)  # may wait out the rate limit
    neuron: NeuronView = await _until(f"{wallet}'s axon", check, timeout, process)
    return neuron


async def _ready(
    url: str, process: Process, verify: Any, timeout_s: float = 60
) -> None:
    async def check() -> bool:
        async with httpx.AsyncClient(timeout=2, verify=verify) as http:
            try:
                r = await http.get(url + "/readyz")
            except httpx.TransportError:
                return False
        return r.status_code == 200

    await _until(f"{url}/readyz", check, timeout_s, process)


async def _query(
    localnet: Localnet,
    neuron: NeuronView,
    policy: SchemePolicy,
    metrics: Metrics | None = None,
) -> MinerResult:
    signer = RequestSigner(localnet.hotkey(VALIDATOR_WALLET))
    async with ValidatorClient(
        signer, timeout_s=10, max_attempts=2, scheme_policy=policy, metrics=metrics
    ) as client:
        return await client.query(neuron, "/v1/transform", BODY)


def _row(result: MinerResult) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "status": result.status,
        "error_code": result.error_code,
        "verified": result.response_verified,
        "attempts": result.attempts,
    }


def _requests(process: Process) -> int:
    return sum(1 for e in process.events() if e.get("event") == "request")


async def test_uvicorn_tls_pinning_and_rotation_on_localnet(
    localnet: Localnet, gateway: BittensorGateway, tmp_path: Path, evidence_dir: Path
) -> None:
    port = _free_port(EXTERNAL_IP)
    want = Endpoint(EXTERNAL_IP, port, is_ipv6=False)
    url = want.base_url("https")
    old = make_certificate(tmp_path / "old", kind="p256", ip=EXTERNAL_IP)
    new = make_certificate(tmp_path / "new", kind="ed25519", ip=EXTERNAL_IP)
    old_key = load_published_certificate(old.cert_file)
    new_key = load_published_certificate(new.cert_file)
    log = evidence_dir / "tls-miner.log"
    results: dict[str, Any] = {"netuid": localnet.netuid, "wallet": TLS_WALLET}
    process = _start(_env(localnet, TLS_WALLET, tmp_path, port, **_tls(old)), log)
    try:
        # 1. Published, read back, pinned.
        neuron = await _published(gateway, localnet, TLS_WALLET, want, old_key, process)
        await _ready(url, process, pinned_context(old_key))
        results["published_key"] = neuron.tls_key.hex() if neuron.tls_key else None
        for policy in ("https-if-tls-published", "https", "http"):
            result = await _query(localnet, neuron, policy)
            results[f"query_{policy}"] = _row(result)
            if policy == "http":
                assert not result.ok  # keys are ignored: plain HTTP to a TLS port
            else:
                assert result.ok, result
                assert result.response_verified
        _stop(process)

        # 2. Rotated certificate, not re-published: refused before any request.
        env = _env(
            localnet, TLS_WALLET, tmp_path, port, axon_publisher="0", **_tls(new)
        )
        process = _start(env, log)
        await _ready(url, process, pinned_context(new_key))
        before = _requests(process)
        neuron = await _neuron(gateway, localnet.netuid, neuron.hotkey)
        assert neuron.tls_key == old_key
        metrics = Metrics()
        refused = await _query(localnet, neuron, "https-if-tls-published", metrics)
        results["query_rotated_not_published"] = _row(refused)
        assert refused.error_code == "tw.tls_pin_mismatch"
        assert refused.attempts == 1
        assert metrics.registry.get_sample_value("tw_tls_pin_failures_total") == 1
        assert _requests(process) == before
        _stop(process)

        # 3. The new key published: accepted again.
        process = _start(_env(localnet, TLS_WALLET, tmp_path, port, **_tls(new)), log)
        neuron = await _published(gateway, localnet, TLS_WALLET, want, new_key, process)
        await _ready(url, process, pinned_context(new_key))
        result = await _query(localnet, neuron, "https")
        results["query_after_republish"] = _row(result)
        results["republished_key"] = new_key.hex()
        assert result.ok, result
        assert result.response_verified
    finally:
        _stop(process)
        (evidence_dir / "tls-results.json").write_text(json.dumps(results, indent=2))


async def test_miner_without_a_published_key_on_localnet(
    localnet: Localnet, gateway: BittensorGateway, tmp_path: Path, evidence_dir: Path
) -> None:
    port = _free_port(EXTERNAL_IP)
    want = Endpoint(EXTERNAL_IP, port, is_ipv6=False)
    process = _start(
        _env(localnet, PLAIN_WALLET, tmp_path, port), evidence_dir / "plain-miner.log"
    )
    results: dict[str, Any] = {"wallet": PLAIN_WALLET}
    try:
        neuron = await _published(gateway, localnet, PLAIN_WALLET, want, None, process)
        await _ready(want.base_url("http"), process, True)
        assert neuron.tls_key is None, "this wallet must never publish a TLS key"
        for policy in ("https-if-tls-published", "http", "https"):
            result = await _query(localnet, neuron, policy)
            results[f"query_{policy}"] = _row(result)
            if policy == "https":
                assert result.error_code == "tw.connect_error"  # never plain HTTP
            else:
                assert result.ok, result
                assert result.response_verified
    finally:
        _stop(process)
        (evidence_dir / "plain-results.json").write_text(json.dumps(results, indent=2))


def _caddy_available() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(  # noqa: S603
        ["docker", "image", "inspect", CADDY_IMAGE],  # noqa: S607
        capture_output=True,
        check=False,
    )
    return probe.returncode == 0


def _start_caddy(name: str, certs: Path, caddyfile: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603
        [  # noqa: S607
            "docker", "run", "--rm", "--name", name, "--network", "host",
            "-v", f"{certs}:/etc/taowire/proxy:ro",
            "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            CADDY_IMAGE, "caddy", "run", "--config", "/etc/caddy/Caddyfile",
            "--adapter", "caddyfile",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )  # fmt: skip


def _stop_caddy(name: str, caddy: subprocess.Popen[bytes]) -> None:
    subprocess.run(  # noqa: S603
        ["docker", "stop", "-t", "2", name],  # noqa: S607
        capture_output=True,
        check=False,
    )
    caddy.wait(timeout=30)


async def test_reverse_proxy_mode_on_localnet(
    localnet: Localnet, gateway: BittensorGateway, tmp_path: Path, evidence_dir: Path
) -> None:
    if not _caddy_available():
        pytest.skip(f"needs Docker and {CADDY_IMAGE} (docker pull {CADDY_IMAGE})")
    upstream = _free_port("127.0.0.1")
    public = _free_port(EXTERNAL_IP)
    certs = tmp_path / "proxy"
    cert = make_certificate(certs, "cert", kind="p256", ip=EXTERNAL_IP)
    key = load_published_certificate(cert.cert_file)
    cert.cert_file.rename(certs / "cert.pem")
    cert.key_file.rename(certs / "key.pem")
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text(
        (DEPLOY / "Caddyfile")
        .read_text()
        .replace(":8443 {", f"{EXTERNAL_IP}:{public} {{")
        .replace("127.0.0.1:8091", f"127.0.0.1:{upstream}")
    )
    name = f"tw-localnet-caddy-{public}"
    caddy = _start_caddy(name, certs, caddyfile)
    env = _env(
        localnet,
        TLS_WALLET,
        tmp_path,
        upstream,
        bind_host="127.0.0.1",
        external_port=str(public),
        trusted_proxies="127.0.0.1/32",
        tls_published_cert_file=str(certs / "cert.pem"),
    )
    process = _start(env, evidence_dir / "proxy-miner.log")
    want = Endpoint(EXTERNAL_IP, public, is_ipv6=False)
    results: dict[str, Any] = {"wallet": TLS_WALLET, "proxy": CADDY_IMAGE}
    try:
        neuron = await _published(gateway, localnet, TLS_WALLET, want, key, process)
        await _ready(want.base_url("https"), process, pinned_context(key))
        result = await _query(localnet, neuron, "https-if-tls-published")
        results["query_through_proxy"] = _row(result)
        assert result.ok, result
        assert result.response_verified
    finally:
        _stop(process)
        _stop_caddy(name, caddy)
        (evidence_dir / "proxy-results.json").write_text(json.dumps(results, indent=2))
