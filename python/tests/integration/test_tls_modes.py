"""The validator's TLS modes against a real TLS miner (spec 8.6, 16.3, D31, ADR-0011).

A kit miner on FakeChain serves the same app twice on 127.0.0.2: over TLS
with uvicorn's options from ``Miner.uvicorn_options`` (certificates generated
in ``tmp_path``), and over plain HTTP. The validator reaches it through the
real network stack in every ``TW_SCHEME_POLICY`` mode. The neuron the
validator sees is the miner's FakeChain row with its axon moved to the port
under test and, where a test says so, another published key.
"""

from __future__ import annotations

import asyncio
import dataclasses
import socket
import ssl
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from pydantic import BaseModel

from taowire.chain.axon import Endpoint
from taowire.chain.gateway import NeuronView
from taowire.extensions.streaming import StreamingReply
from taowire.miner.app import Miner, NoSignalServer
from taowire.miner.routes import RouteContext
from taowire.observability.metrics import Metrics
from taowire.testing.clock import FakeClock
from taowire.testing.fake_chain import FakeChain
from taowire.testing.keys import dev_key
from taowire.testing.pytest_plugin import MINER_KEY, TEST_NETUID
from taowire.testing.tls import (
    KeyKind,
    TestCertificate,
    make_ca,
    make_certificate,
)
from taowire.tls import load_published_certificate
from taowire.validator import client as client_mod
from taowire.validator.client import SchemePolicy, ValidatorClient

pytestmark = pytest.mark.asyncio

HOST = "127.0.0.2"
BODY = b'{"n": 2}'


class Gen(BaseModel):
    n: int


class Token(BaseModel):
    token: str


@dataclass
class Fleet:
    miner: Miner
    neuron: NeuronView  # as the chain shows it after the miner's startup
    key: bytes  # the miner's published key
    tls_port: int
    plain_port: int
    seen: list[str]
    clock: FakeClock

    def at(self, port: int, **changes: Any) -> NeuronView:
        axon = Endpoint(HOST, port, is_ipv6=False)
        return dataclasses.replace(self.neuron, axon=axon, **changes)

    def client(self, policy: SchemePolicy, **kw: Any) -> ValidatorClient:
        signer = dev_key("alice").signer(clock_ns=self.clock.now_ns)
        return ValidatorClient(signer, timeout_s=5.0, scheme_policy=policy, **kw)


def _socket() -> socket.socket:
    sock = socket.socket()
    sock.bind((HOST, 0))
    return sock


async def _serve(app: Any, sock: socket.socket, **options: Any) -> NoSignalServer:
    server = NoSignalServer(uvicorn.Config(app, lifespan="off", **options))
    asyncio.get_running_loop().create_task(server.serve([sock]))
    while not server.started:
        await asyncio.sleep(0.01)
    return server


async def _fleet(
    kwargs: dict[str, Any], chain: FakeChain, clock: FakeClock, cert: TestCertificate
) -> AsyncIterator[Fleet]:
    settings = kwargs["settings"].model_copy(
        update={"tls_cert_file": cert.cert_file, "tls_key_file": cert.key_file}
    )
    miner = Miner(**{**kwargs, "settings": settings})
    seen: list[str] = []

    @miner.route("/v1/gen", request=Gen, response=Token)
    async def gen(req: Gen, ctx: RouteContext) -> Token:
        seen.append("gen")
        return Token(token="x" * req.n)

    @miner.route("/v1/stream", request=Gen, response=Token, stream=True)
    async def stream(req: Gen, ctx: RouteContext) -> StreamingReply:
        seen.append("stream")

        async def chunks() -> AsyncIterator[Token]:
            for i in range(req.n):
                yield Token(token=str(i))

        return StreamingReply(chunks())

    options = miner.uvicorn_options()
    del options["host"], options["port"]
    assert options["ssl_certfile"] == str(cert.cert_file)
    tls_sock, plain_sock = _socket(), _socket()
    async with miner.running() as app:
        tls_server = await _serve(app, tls_sock, **options)
        plain_server = await _serve(app, plain_sock, log_config=None)
        neuron = (await chain.metagraph(TEST_NETUID)).by_hotkey(dev_key(MINER_KEY).ss58)
        assert neuron is not None
        key = load_published_certificate(cert.cert_file)
        assert neuron.tls_key == key  # published and read back at startup
        try:
            yield Fleet(
                miner,
                neuron,
                key,
                tls_sock.getsockname()[1],
                plain_sock.getsockname()[1],
                seen,
                clock,
            )
        finally:
            for server in (tls_server, plain_server):
                server.should_exit = True
            await asyncio.sleep(0.2)
    tls_sock.close()
    plain_sock.close()


@pytest.fixture(params=["p256", "ed25519"])
async def fleet(
    request: pytest.FixtureRequest,
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    tmp_path: Path,
) -> AsyncIterator[Fleet]:
    kind: KeyKind = request.param
    cert = make_certificate(tmp_path / "tls", kind=kind, ip=HOST)
    async for f in _fleet(tw_miner_kwargs, fake_chain, tw_clock, cert):
        yield f


def other_key(tmp_path: Path, kind: KeyKind = "p256") -> bytes:
    """A usable published key that is not the miner's: a rotated certificate."""
    return load_published_certificate(
        make_certificate(tmp_path / "rotated", kind=kind).cert_file
    )


def pin_failures(metrics: Metrics) -> float:
    value = metrics.registry.get_sample_value("tw_tls_pin_failures_total")
    return 0.0 if value is None else value


# ------------------------------------------------------------ pinned


@pytest.mark.parametrize("policy", ["https", "https-if-tls-published"])
async def test_pinned_https_to_a_miner_with_a_published_key(
    fleet: Fleet, policy: SchemePolicy
) -> None:
    async with fleet.client(policy) as client:
        result = await client.query(
            fleet.at(fleet.tls_port), "/v1/gen", BODY, response_model=Token
        )
    assert result.ok, result
    assert result.response_verified
    assert result.data == Token(token="xx")


async def test_streaming_over_pinned_tls(fleet: Fleet) -> None:
    async with fleet.client("https-if-tls-published") as client:
        result = await client.query_stream(
            fleet.at(fleet.tls_port), "/v1/stream", BODY, chunk_model=Token
        )
    assert result.ok, result
    assert result.response_verified
    assert result.data == (Token(token="0"), Token(token="1"))


@pytest.mark.parametrize("policy", ["https", "https-if-tls-published"])
async def test_a_key_mismatch_is_refused_before_any_request(
    fleet: Fleet, policy: SchemePolicy, tmp_path: Path
) -> None:
    """The miner rotated its certificate without re-publishing (16.3)."""
    metrics = Metrics()
    neuron = fleet.at(fleet.tls_port, tls_key=other_key(tmp_path))
    async with fleet.client(policy, metrics=metrics, max_attempts=3) as client:
        result = await client.query(neuron, "/v1/gen", BODY)
        stream_result = await client.query_stream(neuron, "/v1/stream", BODY)
    assert (result.ok, result.error_code, result.attempts) == (
        False,
        "tw.tls_pin_mismatch",
        1,  # never retried
    )
    assert stream_result.error_code == "tw.tls_pin_mismatch"
    assert fleet.seen == []  # no request reached the miner
    assert pin_failures(metrics) == 2


async def test_an_unusable_published_key_is_refused_without_connecting(
    fleet: Fleet,
) -> None:
    metrics = Metrics()
    async with fleet.client("https-if-tls-published", metrics=metrics) as client:
        for raw in (b"", b"\x07", b"\x01" + b"\x11" * 31):
            neuron = fleet.at(fleet.plain_port, tls_key=raw)
            result = await client.query(neuron, "/v1/gen", BODY)
            assert (result.error_code, result.attempts) == ("tw.tls_pin_mismatch", 0)
    assert fleet.seen == []  # not even over plain HTTP
    assert pin_failures(metrics) == 3


async def test_a_published_key_is_never_reached_over_plain_http(
    fleet: Fleet,
) -> None:
    """The axon points at a plain-HTTP port: the TLS handshake fails, no HTTP."""
    async with fleet.client("https-if-tls-published") as client:
        result = await client.query(fleet.at(fleet.plain_port), "/v1/gen", BODY)
    assert not result.ok
    assert result.error_code == "tw.connect_error"
    assert fleet.seen == []


# ------------------------------------------------------------ unpinned


async def test_https_if_tls_published_uses_http_without_a_key(fleet: Fleet) -> None:
    async with fleet.client("https-if-tls-published") as client:
        result = await client.query(
            fleet.at(fleet.plain_port, tls_key=None), "/v1/gen", BODY
        )
    assert result.ok, result
    assert fleet.seen == ["gen"]


async def test_http_mode_ignores_published_keys(fleet: Fleet) -> None:
    async with fleet.client("http") as client:
        result = await client.query(fleet.at(fleet.plain_port), "/v1/gen", BODY)
        on_tls = await client.query(fleet.at(fleet.tls_port), "/v1/gen", BODY)
    assert result.ok, result
    assert not on_tls.ok  # plain HTTP to a TLS port
    assert fleet.seen == ["gen"]


async def test_https_mode_never_uses_plain_http(fleet: Fleet) -> None:
    async with fleet.client("https") as client:
        result = await client.query(
            fleet.at(fleet.plain_port, tls_key=None), "/v1/gen", BODY
        )
    assert result.error_code == "tw.connect_error"
    assert fleet.seen == []


async def test_https_without_a_key_uses_ca_verification(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    tmp_path: Path,
) -> None:
    ca = make_ca(tmp_path / "ca")
    cert = make_certificate(tmp_path / "tls", ca=ca, ip=HOST)
    trusted = ssl.create_default_context(cafile=str(ca.cert_file))
    async for f in _fleet(tw_miner_kwargs, fake_chain, tw_clock, cert):
        neuron = f.at(f.tls_port, tls_key=None)
        async with f.client("https") as default_trust:
            untrusted = await default_trust.query(neuron, "/v1/gen", BODY)
        transport = httpx.AsyncHTTPTransport(verify=trusted, retries=0)
        async with f.client("https", transport=transport) as with_ca:
            result = await with_ca.query(neuron, "/v1/gen", BODY)
        assert untrusted.error_code == "tw.connect_error"  # not a public CA
        assert result.ok, result
        assert f.seen == ["gen"]


# ------------------------------------------------------------ v10 and pools


class _V10Everywhere:
    """A selector that would send everything over v10 (plain HTTP)."""

    def __init__(self) -> None:
        self.calls = 0

    def choose(self, neuron: NeuronView) -> str:
        return "v10"

    def after_btauth(self, neuron: NeuronView, **_: Any) -> bool:
        return True

    def reprobe(self) -> None: ...

    def forget(self, hotkey: str) -> None: ...

    async def query(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        raise AssertionError("v10 must not be used for this miner")


@pytest.mark.parametrize("tls_key", ["published", None])
async def test_no_v10_for_miners_reached_over_tls(
    fleet: Fleet, tls_key: str | None
) -> None:
    legacy = _V10Everywhere()
    neuron = fleet.at(fleet.tls_port, tls_key=fleet.key if tls_key else None)
    async with fleet.client(
        "https" if tls_key is None else "https-if-tls-published",
        legacy=legacy,
        selector=legacy,
    ) as client:
        result = await client.query(neuron, "/v1/gen", BODY, legacy_synapse=Gen(n=1))
    assert legacy.calls == 0
    if tls_key:
        assert result.ok, result
    else:
        assert result.error_code == "tw.connect_error"  # self-signed, CA mode


async def test_a_rotated_key_retires_the_old_pool(fleet: Fleet, tmp_path: Path) -> None:
    """One pool per miner: a new published key replaces (and later closes) the old."""
    client = fleet.client("https-if-tls-published")
    try:
        await client.query(fleet.at(fleet.tls_port), "/v1/gen", BODY)
        (old,) = (c for _, c in client._pinned.values())
        rotated = fleet.at(fleet.tls_port, tls_key=other_key(tmp_path))
        await client.query(rotated, "/v1/gen", BODY)
        assert len(client._pinned) == 1
        assert len(client._retired) == 1
        assert old is not None
        assert not old.is_closed
    finally:
        await client.aclose()
    assert old.is_closed  # aclose waits for retired pools
    assert not client._retired


async def test_pinned_pools_are_bounded(
    fleet: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_mod, "MAX_PINNED_CLIENTS", 1)
    async with fleet.client("https-if-tls-published") as client:
        other = dataclasses.replace(fleet.at(fleet.tls_port), hotkey="5Other")
        await client.query(other, "/v1/gen", BODY)  # (bad signature: not the miner)
        result = await client.query(fleet.at(fleet.tls_port), "/v1/gen", BODY)
        assert list(client._pinned) == [fleet.neuron.hotkey]
        assert len(client._retired) == 1
    assert result.ok, result


async def test_the_grace_covers_the_longest_call(fleet: Fleet) -> None:
    async with fleet.client("https-if-tls-published") as client:
        before = client._longest_hold_s
        await client.query_stream(
            fleet.at(fleet.tls_port), "/v1/stream", BODY, timeout_s=30, max_s=500
        )
        assert client._longest_hold_s >= 30 * 2 + 500 > before


async def test_a_peer_with_an_unsupported_certificate_is_a_mismatch(
    fleet: Fleet, tmp_path: Path
) -> None:
    """A server that is not a kit miner presents an RSA certificate."""
    rsa = make_certificate(tmp_path / "rsa", kind="rsa", ip=HOST)

    async def app(scope: Any, receive: Any, send: Any) -> None:
        raise AssertionError("no request may reach a server with another key")

    sock = _socket()
    server = await _serve(
        app,
        sock,
        log_config=None,
        ssl_certfile=str(rsa.cert_file),
        ssl_keyfile=str(rsa.key_file),
    )
    try:
        async with fleet.client("https") as client:
            result = await client.query(
                fleet.at(sock.getsockname()[1]), "/v1/gen", BODY
            )
        assert result.error_code == "tw.tls_pin_mismatch"
    finally:
        server.should_exit = True
        await asyncio.sleep(0.2)
        sock.close()
