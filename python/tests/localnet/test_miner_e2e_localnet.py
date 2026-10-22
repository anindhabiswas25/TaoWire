"""Phase 1 exit criterion (spec 17): a Python miner runs on localnet, publishes
its axon, and serves a signed request.

The miner runs as a subprocess (``e2e_miner_app.py``) configured only by
``TW_*`` variables. It must publish ``127.0.0.2:<port>`` with protocol 87 by
itself (lifecycle 8.7.3 step 7); the test finds it through the chain, like a
validator would, and calls it with a btauth/1 request signed by the localnet
validator's hotkey.

Skipped until Engineer A's ``tensorwire.Miner`` is in the tree.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib
import json
import os
import socket
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from bittensor import http_auth
from bittensor.keyfiles import Keypair
from localnet_env import ENDPOINT, Localnet

from tensorwire.chain.axon import Endpoint
from tensorwire.chain.gateway import BittensorGateway

ROUTE = "/v1/transform"
MINER_WALLET = "miner_py"
EXTERNAL_IP = "127.0.0.2"
PROTOCOL_TAG = 87
PUBLISH_TIMEOUT_S = 180.0

if not hasattr(importlib.import_module("tensorwire"), "Miner"):
    pytest.skip(
        "tensorwire.Miner is not in this tree yet (Engineer A, Phase 1)",
        allow_module_level=True,
    )


def _free_port(host: str) -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        port: int = s.getsockname()[1]
        return port


@pytest.fixture
def miner_process(localnet: Localnet, tmp_path: Path) -> Iterator[tuple[int, Path]]:
    port = _free_port(EXTERNAL_IP)
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("TW_")}
    env.update(
        {
            "TW_NETWORK": ENDPOINT,
            "TW_NETUID": str(localnet.netuid),
            "TW_WALLET_NAME": MINER_WALLET,
            "TW_WALLET_PATH": str(localnet.wallet_path),
            # localnet dev wallets keep plaintext coldkeys next to the hotkey
            "TW_REFUSE_IF_COLDKEY_PRESENT": "0",
            "TW_STATE_DIR": str(tmp_path / "state"),
            "TW_BIND_HOST": EXTERNAL_IP,
            "TW_BIND_PORT": str(port),
            "TW_EXTERNAL_IP": EXTERNAL_IP,
            "TW_ALLOW_PRIVATE_AXONS": "1",
            "TW_PROTOCOL_TAG": str(PROTOCOL_TAG),
            "TW_METRICS_BIND": f"127.0.0.1:{_free_port('127.0.0.1')}",
            "TW_NTP_SERVERS": "",
            "TW_METAGRAPH_REFRESH_S": "10",
            "TW_LOG_LEVEL": "INFO",
        }
    )
    log = tmp_path / "miner.log"
    app = Path(__file__).with_name("e2e_miner_app.py")
    with log.open("wb") as out:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, our own script
            [sys.executable, str(app)], env=env, stdout=out, stderr=subprocess.STDOUT
        )
        try:
            yield port, log
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            evidence = os.environ.get("TENSORWIRE_E2E_EVIDENCE")
            if evidence:
                Path(evidence).write_bytes(log.read_bytes())


@pytest_asyncio.fixture
async def chain(localnet: Localnet) -> AsyncIterator[BittensorGateway]:
    gw = BittensorGateway(ENDPOINT, allow_private_axons=True)
    await gw.connect()
    yield gw
    await gw.close()


async def _published_axon(
    gw: BittensorGateway, localnet: Localnet, hotkey: str, port: int, log: Path
) -> tuple[Endpoint, int]:
    want = Endpoint(EXTERNAL_IP, port, is_ipv6=False)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + PUBLISH_TIMEOUT_S
    while loop.time() < deadline:
        neuron = (await gw.metagraph(localnet.netuid)).by_hotkey(hotkey)
        if neuron is not None and neuron.axon == want:
            assert neuron.axon_protocol is not None
            return neuron.axon, neuron.axon_protocol
        await asyncio.sleep(1.0)
    tail = (await asyncio.to_thread(log.read_text, errors="replace"))[-4000:]
    raise AssertionError(f"miner did not publish {want} on chain; miner log:\n{tail}")


def _signed(signer: Keypair, receiver: str, body: bytes) -> dict[str, str]:
    headers = http_auth.sign(
        signer, method="POST", path=ROUTE, body=body, receiver_ss58=receiver
    )
    return {**headers, "content-type": "application/json"}


async def test_miner_publishes_axon_and_serves_signed_request(
    localnet: Localnet,
    chain: BittensorGateway,
    miner_process: tuple[int, Path],
) -> None:
    port, log = miner_process
    miner_hotkey = localnet.wallets[MINER_WALLET]["hotkey"]
    axon, protocol = await _published_axon(chain, localnet, miner_hotkey, port, log)
    assert protocol == PROTOCOL_TAG
    url = axon.base_url("http") + ROUTE

    body = json.dumps({"text": "TensorWire", "op": "sha256"}).encode()
    validator = localnet.hotkey("validator")
    stranger = localnet.hotkey("miner_ts")  # registered, no validator permit
    results: dict[str, Any] = {"miner_axon": str(axon), "protocol": protocol}
    async with httpx.AsyncClient(timeout=10.0) as http:
        ok = await http.post(
            url, content=body, headers=_signed(validator, miner_hotkey, body)
        )
        assert ok.status_code == 200, ok.text
        assert ok.json() == {"result": hashlib.sha256(b"TensorWire").hexdigest()}
        results["signed_by_validator"] = ok.status_code

        unsigned = await http.post(
            url, content=body, headers={"content-type": "application/json"}
        )
        assert unsigned.status_code == 401
        assert unsigned.json()["error"]["code"] == "tw.auth_malformed"
        results["unsigned"] = unsigned.status_code

        no_permit = await http.post(
            url, content=body, headers=_signed(stranger, miner_hotkey, body)
        )
        assert no_permit.status_code == 403
        assert no_permit.json()["error"]["code"] == "tw.forbidden_not_validator"
        results["signed_without_permit"] = no_permit.status_code

        replay_headers = _signed(validator, miner_hotkey, body)
        first = await http.post(url, content=body, headers=replay_headers)
        replay = await http.post(url, content=body, headers=replay_headers)
        assert first.status_code == 200
        assert replay.status_code == 401
        assert replay.json()["error"]["code"] == "tw.auth_replayed"
        results["replay"] = replay.status_code

    evidence = os.environ.get("TENSORWIRE_E2E_RESULTS")
    if evidence:
        text = json.dumps(results, indent=2) + "\n"
        with contextlib.suppress(OSError):
            await asyncio.to_thread(Path(evidence).write_text, text)
