"""The legacy bridge against a real bittensor==10.5.0 Axon and Dendrite (no chain).

``scripts/v10_peer.py`` runs the real v10 side in the legacy venv
(``scripts/legacy_venv.sh``); the tests are skipped when it is absent.

- Kit client → real v10 Axon: v10 requests succeed; a btauth/1 request gets
  the v10 marker (N7, live), and the selector falls back.
- Real v10 Dendrite → kit server (a minimal app around ``LegacyServer``, the
  same calls the miner pipeline makes): answers parse, carry the axon
  signature, and a denied caller gets a v10-shaped 403.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import importlib.util
import json
import os
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from bittensor import http_auth
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from legacy_v10_models import BOB, Dummy
from taowire import crypto
from taowire.auth.nonce_store import MemoryNonceStore
from taowire.chain.axon import Endpoint
from taowire.chain.gateway import NeuronView
from taowire.errors import Forbidden, TWError
from taowire.extensions.legacy_v10.client import LegacyClient, ProtocolSelector
from taowire.extensions.legacy_v10.server import LegacyServer

REPO = Path(__file__).resolve().parents[3]
PEER = REPO / "scripts" / "v10_peer.py"
LEGACY_PY = Path(
    os.environ.get(
        "TW_LEGACY_PYTHON",
        str(Path.home() / ".taowire/venvs/bittensor-10.5.0/bin/python"),
    )
)
CHARLIE = crypto.keypair_from_uri("//Charlie").ss58_address
PROTOCOL = (
    REPO
    / "examples/migrations/template-v10-to-v11/after/docs/stream_tutorial/protocol.py"
)

pytestmark = pytest.mark.skipif(
    not LEGACY_PY.exists(), reason="legacy venv missing: run scripts/legacy_venv.sh"
)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def neuron(port: int, hotkey: str = BOB, protocol: int | None = 0) -> NeuronView:
    return NeuronView(
        uid=1,
        hotkey=hotkey,
        coldkey=hotkey,
        validator_permit=False,
        active=True,
        total_stake_tao=0.0,
        alpha_stake=0.0,
        tao_stake=0.0,
        axon=Endpoint(host="127.0.0.1", port=port, is_ipv6=False),
        last_update=0,
        incentive=0.0,
        dividends=0.0,
        axon_protocol=protocol,
    )


@pytest.fixture(scope="module")
def v10_axon() -> Iterator[int]:
    port = free_port()
    proc = subprocess.Popen(  # noqa: S603 - fixed interpreter and script
        [str(LEGACY_PY), "-I", str(PEER), "axon", "--port", str(port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    line = proc.stdout.readline()
    assert line.startswith("READY"), line
    yield port
    proc.terminate()
    proc.wait(timeout=20)
    proc.stdout.close()
    if proc.stdin is not None:
        proc.stdin.close()


async def test_kit_client_against_real_v10_axon(v10_axon: int) -> None:
    client = LegacyClient(crypto.HotkeySigner(crypto.keypair_from_uri("//Alice")))
    async with httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(retries=0), follow_redirects=False
    ) as http:
        for i in range(25):
            result = await client.query(
                http,
                neuron(v10_axon),
                Dummy(dummy_input=i),
                timeout_s=12.0,
                max_response_bytes=1 << 20,
            )
            assert result.status == 200, result
            assert result.error_code is None
            assert isinstance(result.synapse, Dummy)
            assert result.synapse.dummy_output == i * 2
        # Signed for another axon: the real v10 Axon refuses it.
        wrong = await client.query(
            http,
            neuron(v10_axon, hotkey=CHARLIE),
            Dummy(dummy_input=1),
            timeout_s=12.0,
            max_response_bytes=1 << 20,
        )
        assert wrong.status == 401
        assert wrong.error_code == "tw.http_401"
        assert wrong.status_message


async def test_btauth_request_to_v10_axon_gets_the_marker(v10_axon: int) -> None:
    body = b'{"dummy_input": 1}'
    headers = http_auth.sign(
        crypto.keypair_from_uri("//Alice"),
        method="POST",
        path="/Dummy",
        body=body,
        receiver_ss58=BOB,
    )
    async with httpx.AsyncClient() as http:
        answer = await http.post(
            f"http://127.0.0.1:{v10_axon}/Dummy", content=body, headers=dict(headers)
        )
    selector = ProtocolSelector(
        87, until=dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=30)
    )
    target = neuron(v10_axon)
    assert selector.choose(target) == "btauth/1"
    assert selector.after_btauth(
        target,
        status=answer.status_code,
        headers=answer.headers.items(),
        verified=False,
    )
    assert selector.choose(target) == "v10"


class _App:
    """The miner pipeline's v10 path in miniature.

    verify → policy → handler → respond, as ``miner/pipeline.py`` does.
    """

    def __init__(self, server: LegacyServer, denied: str) -> None:
        self.server = server
        self.denied = denied

    async def dummy(self, request: Request) -> Response:
        started = time.perf_counter()
        body = await request.body()
        verified = None
        try:
            verified = await self.server.verify(
                list(request.headers.items()), body, synapse_cls=Dummy, body_hash=None
            )
            if verified.caller.hotkey_ss58 == self.denied:
                raise Forbidden(code="tw.forbidden_denied")
            synapse = verified.synapse
            assert isinstance(synapse, Dummy)
            result = synapse.model_copy(
                update={"dummy_output": synapse.dummy_input * 2}
            )
            status, error = 200, None
        except TWError as err:
            result, status, error = None, err.http_status, err
        content, headers = self.server.respond(
            request.headers,
            request=verified,
            status=status,
            synapse=result,
            error=error,
            process_time_s=time.perf_counter() - started,
        )
        response = Response(content=content, status_code=status)
        for name, value in headers:
            response.headers.append(name, value)
        return response


@pytest.fixture(scope="module")
def kit_server() -> Iterator[int]:
    port = free_port()
    legacy = LegacyServer(
        signer=crypto.HotkeySigner(crypto.keypair_from_uri("//Bob")),
        store=MemoryNonceStore(60.0),
        until=dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=30),
        external_ip="127.0.0.1",
        external_port=port,
    )
    app = Starlette(
        routes=[Route("/Dummy", _App(legacy, CHARLIE).dummy, methods=["POST"])]
    )
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    yield port
    server.should_exit = True
    thread.join(timeout=10)


def run_dendrite(port: int, uri: str, count: int) -> list[dict[str, object]]:
    out = subprocess.run(  # noqa: S603 - fixed interpreter and script
        [
            str(LEGACY_PY),
            "-I",
            str(PEER),
            "dendrite",
            "--port",
            str(port),
            "--axon-hotkey",
            BOB,
            "--hotkey-uri",
            uri,
            "--count",
            str(count),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout.splitlines()
    oks = sum(1 for line in out[:-1] if json.loads(line)["ok"])
    assert out[-1] == f"SUMMARY {oks}/{count}"
    return [json.loads(line) for line in out[:-1]]


def test_real_v10_dendrite_against_kit_server(kit_server: int) -> None:
    answers = run_dendrite(kit_server, "//Alice", 50)
    assert len(answers) == 50
    assert all(a["ok"] for a in answers), [a for a in answers if not a["ok"]][:3]
    assert all(a["axon_signature"] for a in answers)  # signed: request was verified


def test_denied_v10_caller_gets_a_v10_shaped_403(kit_server: int) -> None:
    (answer,) = run_dendrite(kit_server, "//Charlie", 1)
    assert answer["status_code"] == 403
    assert answer["status_message"] == Forbidden().public_message
    assert answer["axon_signature"]


# ------------------------------------------------------------ D33: no v10 streaming


@pytest.fixture(scope="module")
def compat_stream_miner(tmp_path_factory: pytest.TempPathFactory) -> Iterator[int]:
    """A kit miner serving the template's StreamPrompting on compat.Axon, bridge on."""
    import warnings

    from taowire.compat import Axon
    from taowire.config import MinerSettings
    from taowire.miner.app import Miner
    from taowire.testing.fake_chain import FakeChain
    from taowire.testing.metagraph import FakeMetagraphSource

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # the template's pydantic v1 Field options
        spec = importlib.util.spec_from_file_location("stream_protocol_live", PROTOCOL)
        assert spec is not None
        assert spec.loader is not None
        protocol = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(protocol)
    port = free_port()
    chain = FakeChain()
    chain.add_subnet(2)
    chain.register(2, BOB)
    chain.register(
        2, crypto.keypair_from_uri("//Alice").ss58_address, validator_permit=True
    )
    gateway = chain.with_signer(BOB)
    settings = MinerSettings(
        netuid=2,
        wallet_name="bob",
        wallet_path=tmp_path_factory.mktemp("wallets"),
        external_ip="127.0.0.2",
        allow_private_axons=True,
        bind_host="127.0.0.2",
        bind_port=port,
        ntp_servers=(),
        legacy_v10_until=dt.datetime.now(dt.timezone.utc).date()
        + dt.timedelta(days=30),
    )
    miner = Miner(
        settings,
        gateway=gateway,
        metagraph=FakeMetagraphSource(gateway, 2),
        hotkey=crypto.keypair_from_uri("//Bob"),
        check_sdk=False,
    )

    def forward(synapse: Any) -> Any:
        async def streamer(send: Any) -> None:
            await send(
                {"type": "http.response.body", "body": b"never", "more_body": True}
            )

        return synapse.create_streaming_response(streamer)

    forward.__annotations__ = {"synapse": protocol.StreamPrompting}
    Axon(miner=miner).attach(forward_fn=forward)
    server = uvicorn.Server(
        uvicorn.Config(miner.app, host="127.0.0.2", port=port, log_level="warning")
    )
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    yield port
    server.should_exit = True
    thread.join(timeout=10)


def test_d33_real_v10_streaming_dendrite_gets_invalid_request(
    compat_stream_miner: int,
) -> None:
    """A real v10 StreamingSynapse Dendrite against a TaoWire streaming route."""
    from taowire.errors import InvalidRequest

    out = subprocess.run(  # noqa: S603 - fixed interpreter and script
        [
            str(LEGACY_PY),
            "-I",
            str(PEER),
            "stream-dendrite",
            "--ip",
            "127.0.0.2",
            "--port",
            str(compat_stream_miner),
            "--axon-hotkey",
            BOB,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout.splitlines()
    answer = json.loads(out[-1])
    assert answer["status_code"] == 422, answer
    assert answer["status_message"] == InvalidRequest().public_message
    assert answer["completion"] != "never"  # nothing was streamed to it
