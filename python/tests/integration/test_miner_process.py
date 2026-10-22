"""``Miner.run()`` as a real process: uvicorn, metrics listener, signals, exit codes.

The chain is a FakeChain inside the miner process; everything else is real:
TCP, uvicorn, ``tensorwire sign-request --send``, SIGTERM.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from bittensor import sp_core

from tensorwire.testing.keys import dev_key

MINER_SCRIPT = """
import sys
from pydantic import BaseModel
from tensorwire import Miner, RouteContext
from tensorwire.config import MinerSettings
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource

bob, alice = dev_key("bob"), dev_key("alice")
chain = FakeChain(signer_hotkey=bob.ss58)
chain.add_subnet(1)
if sys.argv[1] == "registered":
    chain.register(1, bob.ss58)
chain.register(1, alice.ss58, validator_permit=True, stake_tao=1000)

class Req(BaseModel):
    text: str

class Resp(BaseModel):
    result: str

miner = Miner(MinerSettings.from_env(), gateway=chain,
              metagraph=FakeMetagraphSource(chain, 1), hotkey=bob.keypair)

@miner.route("/v1/upper", request=Req, response=Resp)
async def upper(req: Req, ctx: RouteContext) -> Resp:
    return Resp(result=req.text.upper())

@miner.route("/v1/slow", request=Req, response=Resp, timeout_s=30)
async def slow(req: Req, ctx: RouteContext) -> Resp:
    import asyncio
    await asyncio.sleep(float(req.text))
    return Resp(result="done")

miner.run()
"""


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def setup(tmp_path: Path) -> dict[str, object]:
    (tmp_path / "miner.py").write_text(MINER_SCRIPT)
    hotkey = tmp_path / "wallets" / "validator" / "hotkeys" / "default"
    hotkey.parent.mkdir(parents=True)
    hotkey.write_bytes(
        sp_core.serialized_keypair_to_keyfile_data(dev_key("alice").keypair)
    )
    port, metrics_port = free_port(), free_port()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "TW_NETUID": "1",
        "TW_WALLET_NAME": "miner",
        "TW_WALLET_PATH": str(tmp_path / "empty"),
        "TW_EXTERNAL_IP": "127.0.0.2",
        "TW_ALLOW_PRIVATE_AXONS": "1",
        "TW_BIND_HOST": "127.0.0.1",
        "TW_BIND_PORT": str(port),
        "TW_METRICS_BIND": f"127.0.0.1:{metrics_port}",
        "TW_NTP_SERVERS": "",
        "TW_DRAIN_S": "1",
    }
    return {"dir": tmp_path, "env": env, "port": port, "metrics_port": metrics_port}


def start(setup: dict[str, object], mode: str) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "miner.py", mode],
        cwd=setup["dir"],  # type: ignore[arg-type]
        env=setup["env"],  # type: ignore[arg-type]
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def wait_ready(port: int, proc: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"miner exited early:\n{proc.communicate()[0]}")
        try:
            if (
                httpx.get(f"http://127.0.0.1:{port}/readyz", timeout=0.5).status_code
                == 200
            ):
                return
        except httpx.TransportError:
            time.sleep(0.1)
    raise AssertionError("miner did not become ready")


def test_run_serves_signed_requests_and_stops_cleanly(setup: dict[str, object]) -> None:
    proc = start(setup, "registered")
    try:
        wait_ready(setup["port"], proc)  # type: ignore[arg-type]
        url = f"http://127.0.0.1:{setup['port']}/v1/upper"
        cli = [
            str(Path(sys.executable).with_name("tensorwire")), "sign-request", url,
            "-r", dev_key("bob").ss58, "-w", "validator",
            "--wallet-path", str(Path(setup["dir"]) / "wallets"),  # type: ignore[arg-type]
            "-d", '{"text":"hello"}', "--send",
        ]  # fmt: skip
        result = subprocess.run(  # noqa: S603 - fixed argv
            cli,
            capture_output=True,
            text=True,
            timeout=30,
            env=setup["env"],  # type: ignore[arg-type]
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout.splitlines()[0] == "HTTP 200"
        assert result.stdout.splitlines()[-1] == '{"result":"HELLO"}'
        unsigned = httpx.post(url, json={"text": "x"})
        assert unsigned.status_code == 401
        metrics = httpx.get(f"http://127.0.0.1:{setup['metrics_port']}/metrics").text
        assert (
            'tw_requests_total{code="ok",route="/v1/upper",status="200"} 1.0' in metrics
        )
        public_metrics = httpx.get(f"http://127.0.0.1:{setup['port']}/metrics")
        assert public_metrics.status_code == 404  # never on the public port
    finally:
        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=20)
    assert proc.returncode in (0, -signal.SIGTERM), out
    assert '"event": "miner_ready"' in out
    assert '"event": "miner_stopped"' in out


def test_ctrl_c_stops_cleanly_without_a_traceback(setup: dict[str, object]) -> None:
    proc = start(setup, "registered")
    try:
        wait_ready(setup["port"], proc)  # type: ignore[arg-type]
    finally:
        proc.send_signal(signal.SIGINT)
        out, _ = proc.communicate(timeout=20)
    assert proc.returncode == 130, out
    assert '"event": "miner_stopped"' in out
    assert "Traceback" not in out


def test_unregistered_hotkey_exits_with_code_3(setup: dict[str, object]) -> None:
    proc = start(setup, "unregistered")
    out, _ = proc.communicate(timeout=30)
    assert proc.returncode == 3, out
    assert "register first: btcli tx burned-register --netuid 1" in out


def send_slow(port: int, seconds: float, out: dict[str, object]) -> None:
    """A signed request (alice → bob) to /v1/slow; result or exception in ``out``."""
    body = json.dumps({"text": str(seconds)}).encode()
    headers = (
        dev_key("alice")
        .signer()
        .sign(
            method="POST",
            target="/v1/slow",
            body=body,
            receiver_ss58=dev_key("bob").ss58,
        )
    )
    headers["Content-Type"] = "application/json"
    started = time.monotonic()
    try:
        out["response"] = httpx.post(
            f"http://127.0.0.1:{port}/v1/slow",
            content=body,
            headers=headers,
            timeout=30,
        )
    except httpx.HTTPError as exc:
        out["error"] = exc
    out["elapsed"] = time.monotonic() - started


def test_sigterm_drains_in_flight_requests(setup: dict[str, object]) -> None:
    # Spec 8.7.3: stop accepting, let in-flight requests finish (TW_DRAIN_S),
    # then close the chain and the stores.
    setup["env"]["TW_DRAIN_S"] = "5"  # type: ignore[index]
    port: int = setup["port"]  # type: ignore[assignment]
    proc = start(setup, "registered")
    out: dict[str, object] = {}
    try:
        wait_ready(port, proc)
        sender = threading.Thread(target=send_slow, args=(port, 1.5, out))
        sender.start()
        time.sleep(0.5)  # the request is in the handler
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.3)
        with pytest.raises(httpx.ConnectError):  # no new connections while draining
            httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=1)
        sender.join(timeout=10)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
        log, _ = proc.communicate(timeout=20)
    response = out.get("response")
    assert isinstance(response, httpx.Response), out
    assert response.status_code == 200
    assert response.json() == {"result": "done"}
    assert proc.returncode in (0, -signal.SIGTERM), log
    assert log.index('"event": "miner_stopped"') > log.index('"event": "miner_ready"')


def test_drain_is_bounded_by_drain_s(setup: dict[str, object]) -> None:
    port: int = setup["port"]  # type: ignore[assignment]
    proc = start(setup, "registered")  # TW_DRAIN_S=1
    out: dict[str, object] = {}
    try:
        wait_ready(port, proc)
        sender = threading.Thread(target=send_slow, args=(port, 20, out))
        sender.start()
        time.sleep(0.5)
        stopped = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        log, _ = proc.communicate(timeout=20)
        exit_s = time.monotonic() - stopped
        sender.join(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert exit_s < 1 + 3, exit_s  # TW_DRAIN_S plus shutdown work, not 20 s
    assert '"event": "miner_stopped"' in log
    response = out.get("response")
    # uvicorn cancels the request once the drain time is up.
    assert "error" in out or (
        isinstance(response, httpx.Response) and response.status_code >= 500
    ), out


WORKERS_SCRIPT = MINER_SCRIPT.replace(
    "miner.run()",
    'if __name__ == "__main__":\n    miner.run(app_import="miner:miner.app")',
)


def test_workers_share_one_metrics_endpoint(setup: dict[str, object]) -> None:
    # TW_WORKERS > 1: each worker writes its metrics to a shared directory and
    # the supervising process serves the aggregate on TW_METRICS_BIND.
    Path(setup["dir"], "miner.py").write_text(WORKERS_SCRIPT)  # type: ignore[arg-type]
    env: dict[str, str] = setup["env"]  # type: ignore[assignment]
    env["TW_WORKERS"] = "2"
    redis_url = os.environ.get("TENSORWIRE_TEST_REDIS_URL")
    if redis_url:
        env["TW_REDIS_URL"] = redis_url
    else:
        env["TW_UNSAFE_ALLOW_MEMORY_NONCE_MULTIWORKER"] = "1"
    port: int = setup["port"]  # type: ignore[assignment]
    proc = start(setup, "registered")
    try:
        wait_ready(port, proc)
        signer = dev_key("alice").signer()
        for i in range(6):
            body = json.dumps({"text": f"m{i}"}).encode()
            headers = signer.sign(
                method="POST",
                target="/v1/upper",
                body=body,
                receiver_ss58=dev_key("bob").ss58,
            )
            headers["Content-Type"] = "application/json"
            # A fresh connection each time, so both workers get requests.
            r = httpx.post(f"http://127.0.0.1:{port}/v1/upper", content=body,
                           headers=headers)  # fmt: skip
            assert r.status_code == 200, r.text
        metrics = httpx.get(f"http://127.0.0.1:{setup['metrics_port']}/metrics").text
    finally:
        proc.send_signal(signal.SIGTERM)
        log, _ = proc.communicate(timeout=30)
    assert 'tw_requests_total{code="ok",route="/v1/upper",status="200"} 6.0' in metrics
    assert "tw_clock_offset_seconds" in metrics
    # The supervisor's startup checks, then one startup per worker.
    assert log.count('"event": "miner_ready"') == 3
    assert '"event": "startup_checks_passed"' in log


def test_workers_keep_the_startup_exit_code(setup: dict[str, object]) -> None:
    Path(setup["dir"], "miner.py").write_text(WORKERS_SCRIPT)  # type: ignore[arg-type]
    env: dict[str, str] = setup["env"]  # type: ignore[assignment]
    env["TW_WORKERS"] = "2"
    env["TW_UNSAFE_ALLOW_MEMORY_NONCE_MULTIWORKER"] = "1"
    proc = start(setup, "unregistered")
    out, _ = proc.communicate(timeout=30)
    assert proc.returncode == 3, out
    assert "register first" in out
    assert "Traceback" not in out
