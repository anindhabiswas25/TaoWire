"""``Miner.run()`` as a real process: uvicorn, metrics listener, signals, exit codes.

The chain is a FakeChain inside the miner process; everything else is real:
TCP, uvicorn, ``tensorwire sign-request --send``, SIGTERM.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
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


def test_unregistered_hotkey_exits_with_code_3(setup: dict[str, object]) -> None:
    proc = start(setup, "unregistered")
    out, _ = proc.communicate(timeout=30)
    assert proc.returncode == 3, out
    assert "register first: btcli tx burned-register --netuid 1" in out
