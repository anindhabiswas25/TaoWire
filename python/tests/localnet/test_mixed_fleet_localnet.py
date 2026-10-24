"""Mixed fleet on localnet (spec 13.8): v10 and TaoWire nodes on one subnet.

The fleet is described in
``examples/migrations/template-v10-to-v11/mixed-fleet.yml``: a real
bittensor==10.5.0 miner (Axon + v10 ``serve_axon``) and validator (v10
metagraph + Dendrite) from ``scripts/legacy_venv.sh``, next to a TaoWire
miner (subprocess, ``TW_LEGACY_V10_UNTIL`` set) and a TaoWire validator
(``ValidatorClient`` with the legacy client and ``ProtocolSelector``).

Pass = every cell answers ``requests_per_cell`` template requests, all
correct; TaoWire → TaoWire answers are twresp/1-verified.

Run with ``just mixed-fleet`` after ``just localnet-up``. Set
``TAOWIRE_MIXED_FLEET_EVIDENCE=<dir>`` to keep the results and node logs.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import datetime as dt
import importlib
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
import pytest_asyncio
import yaml
from localnet_env import ENDPOINT, Localnet

from taowire import crypto
from taowire.chain.gateway import BittensorGateway, NeuronView
from taowire.extensions.legacy_v10.client import LegacyClient, ProtocolSelector

pytestmark = pytest.mark.mixed_fleet

REPO = Path(__file__).resolve().parents[3]
FLEET_FILE = REPO / "examples/migrations/template-v10-to-v11/mixed-fleet.yml"
FLEET: dict[str, Any] = yaml.safe_load(FLEET_FILE.read_text(encoding="utf-8"))
PEER = REPO / "scripts" / "v10_peer.py"
LEGACY_PY = Path(
    os.environ.get(
        "TW_LEGACY_PYTHON",
        str(Path.home() / ".taowire/venvs/bittensor-10.5.0/bin/python"),
    )
)
PROTOCOL_TAG = 87
TIMEOUT_S = 180.0

try:
    _compat: Any = importlib.import_module("taowire.compat.synapse")
    _validator: Any = importlib.import_module("taowire.validator.client")
    _signer: Any = importlib.import_module("taowire.auth.signer")
except ImportError:
    pytest.skip("needs Engineer A's compat and validator", allow_module_level=True)
if not LEGACY_PY.exists():
    pytest.skip(
        "legacy venv missing: run scripts/legacy_venv.sh", allow_module_level=True
    )


class Dummy(_compat.Synapse):  # type: ignore[misc]
    """The archived template's Synapse (same as the miners')."""

    dummy_input: int
    dummy_output: int | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def node(name: str) -> dict[str, Any]:
    spec: dict[str, Any] = FLEET["nodes"][name]
    return spec


def until() -> str:
    days = int(FLEET["legacy_days"])
    return (
        dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=days)
    ).isoformat()


def evidence_dir() -> Path | None:
    value = os.environ.get("TAOWIRE_MIXED_FLEET_EVIDENCE")
    if not value:
        return None
    path = Path(value)
    path.mkdir(parents=True, exist_ok=True)
    return path


def stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.stdin is not None:
        proc.stdin.close()
    proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@contextlib.contextmanager
def logged(name: str, tmp: Path) -> Iterator[Path]:
    log = tmp / f"{name}.log"
    try:
        yield log
    finally:
        out = evidence_dir()
        if out is not None and log.exists():
            (out / log.name).write_bytes(log.read_bytes())


@pytest.fixture
def v10_miner(localnet: Localnet, tmp_path: Path) -> Iterator[dict[str, Any]]:
    spec = node("v10_miner")
    argv = [
        str(LEGACY_PY), "-I", str(PEER), "axon",
        "--ip", spec["ip"], "--port", str(spec["port"]),
        "--chain", ENDPOINT, "--netuid", str(localnet.netuid),
        "--wallet-name", spec["wallet"], "--wallet-path", str(localnet.wallet_path),
    ]  # fmt: skip
    with logged("v10_miner", tmp_path) as log, log.open("wb") as out:
        proc = subprocess.Popen(  # noqa: S603 - fixed interpreter and script
            argv, stdin=subprocess.PIPE, stdout=out, stderr=subprocess.STDOUT
        )
        try:
            deadline = time.monotonic() + TIMEOUT_S
            while b"READY" not in log.read_bytes():
                if proc.poll() is not None or time.monotonic() > deadline:
                    tail = log.read_text(errors="replace")[-3000:]
                    raise AssertionError(f"v10 miner did not start:\n{tail}")
                time.sleep(0.5)
            yield spec
        finally:
            stop(proc)


@pytest.fixture
def tw_miner(localnet: Localnet, tmp_path: Path) -> Iterator[dict[str, Any]]:
    spec = node("tw_miner")
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("TW_")}
    env.update(
        {
            "TW_NETWORK": ENDPOINT,
            "TW_NETUID": str(localnet.netuid),
            "TW_WALLET_NAME": spec["wallet"],
            "TW_WALLET_PATH": str(localnet.wallet_path),
            "TW_REFUSE_IF_COLDKEY_PRESENT": "0",  # localnet dev wallets
            "TW_STATE_DIR": str(tmp_path / "state"),
            "TW_BIND_HOST": spec["ip"],
            "TW_BIND_PORT": str(spec["port"]),
            "TW_EXTERNAL_IP": spec["ip"],
            "TW_ALLOW_PRIVATE_AXONS": "1",
            "TW_PROTOCOL_TAG": str(PROTOCOL_TAG),
            "TW_METRICS_BIND": f"127.0.0.1:{free_port()}",
            "TW_NTP_SERVERS": "",
            "TW_METAGRAPH_REFRESH_S": "10",
            "TW_LEGACY_V10_UNTIL": until(),
            # Both validators run on this host, so they share one source IP
            # (127.0.0.1) and the pre-auth per-IP bucket (default 50/s, burst
            # 100). On a real subnet each validator has its own address.
            "TW_RATE_IP_PER_S": "1000",
            "TW_RATE_IP_BURST": "1000",
            # 200 back-to-back requests per validator: above 20/s, burst 40.
            "TW_RATE_HOTKEY_PER_S": "200",
            "TW_RATE_HOTKEY_BURST": "400",
        }
    )
    app = Path(__file__).with_name("mixed_fleet_miner_app.py")
    with logged("tw_miner", tmp_path) as log, log.open("wb") as out:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, our own script
            [sys.executable, str(app)], env=env, stdout=out, stderr=subprocess.STDOUT
        )
        try:
            _wait_ready(f"http://{spec['ip']}:{spec['port']}/readyz", proc, log)
            yield spec
        finally:
            stop(proc)


def _wait_ready(url: str, proc: subprocess.Popen[bytes], log: Path) -> None:
    deadline = time.monotonic() + TIMEOUT_S
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        with contextlib.suppress(httpx.TransportError):
            if httpx.get(url, timeout=2.0).status_code == 200:
                return
        time.sleep(0.5)
    tail = log.read_text(errors="replace")[-4000:]
    raise AssertionError(f"TaoWire miner never became ready at {url}:\n{tail}")


@pytest_asyncio.fixture
async def chain(localnet: Localnet) -> AsyncIterator[BittensorGateway]:
    gw = BittensorGateway(ENDPOINT, allow_private_axons=True, timeout_s=30.0)
    await gw.connect()
    yield gw
    await gw.close()


async def published(
    gw: BittensorGateway, localnet: Localnet, spec: dict[str, Any]
) -> NeuronView:
    hotkey = localnet.wallets[spec["wallet"]]["hotkey"]
    deadline = asyncio.get_running_loop().time() + TIMEOUT_S
    while asyncio.get_running_loop().time() < deadline:
        neuron = (await gw.metagraph(localnet.netuid)).by_hotkey(hotkey)
        axon = None if neuron is None else neuron.axon
        if (
            neuron is not None
            and axon is not None
            and (axon.host, axon.port)
            == (
                spec["ip"],
                spec["port"],
            )
        ):
            return neuron
        await asyncio.sleep(1.0)
    raise AssertionError(
        f"{spec['wallet']} never published {spec['ip']}:{spec['port']}"
    )


async def v10_validator_cells(
    localnet: Localnet, uids: list[int], count: int
) -> dict[int, dict[str, Any]]:
    spec = node("v10_validator")
    argv = [
        str(LEGACY_PY), "-I", str(PEER), "validator",
        "--chain", ENDPOINT, "--netuid", str(localnet.netuid),
        "--wallet-name", spec["wallet"], "--wallet-path", str(localnet.wallet_path),
        "--count", str(count), "--uids", *map(str, uids),
    ]  # fmt: skip
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    out, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
    text = out.decode(errors="replace")
    if (dest := evidence_dir()) is not None:
        (dest / "v10_validator.log").write_text(text)
    assert proc.returncode == 0, text[-4000:]
    results = [
        json.loads(line[7:]) for line in text.splitlines() if line.startswith("RESULT ")
    ]
    return {r["uid"]: r for r in results}


async def tw_validator_cell(
    localnet: Localnet, neuron: NeuronView, count: int
) -> dict[str, Any]:
    hotkey = localnet.hotkey(node("tw_validator")["wallet"])
    selector = ProtocolSelector(PROTOCOL_TAG, until=dt.date.fromisoformat(until()))
    client = _validator.ValidatorClient(
        _signer.RequestSigner(hotkey),
        timeout_s=12.0,
        legacy=LegacyClient(crypto.HotkeySigner(hotkey)),
        selector=selector,
    )
    protocols: collections.Counter[str] = collections.Counter()
    codes: collections.Counter[str] = collections.Counter()
    ok = verified = 0
    async with client:
        for i in range(count):
            synapse = Dummy(dummy_input=i)
            result = await client.query(
                neuron,
                "/Dummy",
                synapse.model_dump_json(include={"dummy_input"}).encode(),
                response_model=Dummy,
                legacy_synapse=synapse,
            )
            protocols[result.protocol] += 1
            codes[result.error_code or "ok"] += 1
            good = (
                result.ok
                and result.data is not None
                and result.data.dummy_output == i * 2
            )
            ok += good
            verified += result.response_verified
    return {
        "uid": neuron.uid,
        "axon": str(neuron.axon),
        "axon_protocol": neuron.axon_protocol,
        "count": count,
        "ok": ok,
        "verified": verified,
        "protocols": dict(protocols),
        "codes": dict(codes),
        "remembered": selector.known(neuron.hotkey),
    }


async def test_mixed_fleet_all_four_cells(
    localnet: Localnet,
    chain: BittensorGateway,
    v10_miner: dict[str, Any],
    tw_miner: dict[str, Any],
) -> None:
    count = int(FLEET["requests_per_cell"])
    v10_neuron = await published(chain, localnet, v10_miner)
    tw_neuron = await published(chain, localnet, tw_miner)
    assert tw_neuron.axon_protocol == PROTOCOL_TAG
    assert v10_neuron.axon_protocol != PROTOCOL_TAG

    started = time.monotonic()
    v10_results, tw_to_v10, tw_to_tw = await asyncio.gather(
        v10_validator_cells(localnet, [v10_neuron.uid, tw_neuron.uid], count),
        tw_validator_cell(localnet, v10_neuron, count),
        tw_validator_cell(localnet, tw_neuron, count),
    )
    cells = {
        "v10_validator->v10_miner": v10_results[v10_neuron.uid],
        "v10_validator->tw_miner": v10_results[tw_neuron.uid],
        "tw_validator->v10_miner": tw_to_v10,
        "tw_validator->tw_miner": tw_to_tw,
    }
    report = {
        "fleet_file": str(FLEET_FILE.relative_to(REPO)),
        "netuid": localnet.netuid,
        "requests_per_cell": count,
        "elapsed_s": round(time.monotonic() - started, 1),
        "cells": cells,
    }
    if (dest := evidence_dir()) is not None:
        (dest / "mixed-fleet-results.json").write_text(json.dumps(report, indent=1))

    for name, cell in cells.items():
        assert cell["ok"] == count, (name, cell)
    assert tw_to_v10["protocols"] == {"v10": count}
    assert tw_to_v10["remembered"] == "v10"
    assert tw_to_tw["protocols"] == {"btauth/1": count}
    assert tw_to_tw["verified"] == count
