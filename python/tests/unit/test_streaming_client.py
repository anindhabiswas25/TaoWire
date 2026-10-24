"""The validator's stream limits and rejections (spec 9.2, 8.8, D29).

A scripted transport plays the miner: it answers with a real, signed SSE
stream (bob's key, bound to the request's nonce and sender), delivered piece
by piece with real delays, so the client's time, idle and byte limits run as
they do on a network.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import replace
from typing import Any

import httpx
import pytest
from pydantic import BaseModel

from taowire.chain.axon import Endpoint
from taowire.chain.gateway import NeuronView
from taowire.crypto import HotkeySigner
from taowire.extensions import streaming as sse
from taowire.extensions.response_sig import HEADER_SIGNATURE, sign_response
from taowire.miner.streaming import start_headers
from taowire.observability.metrics import Metrics
from taowire.testing.keys import dev_key
from taowire.validator.client import ValidatorClient

pytestmark = pytest.mark.asyncio

MINER = dev_key("bob")
SIGNER = HotkeySigner(MINER.keypair)
NEURON = NeuronView(
    uid=1,
    hotkey=MINER.ss58,
    coldkey=MINER.ss58,
    validator_permit=False,
    active=True,
    total_stake_tao=0.0,
    alpha_stake=0.0,
    tao_stake=0.0,
    axon=Endpoint("44.0.0.1", 8091, is_ipv6=False),
    last_update=0,
    incentive=0.0,
    dividends=0.0,
)
CHUNKS = [{"t": "a"}, {"t": "b"}, {"t": "c"}]


def signed_stream(
    request: httpx.Request, chunks: Sequence[Any] = CHUNKS
) -> tuple[list[bytes], bytes]:
    """The chunk frames and a valid trailer frame for ``request``."""
    digest = sse.StreamDigest()
    out = []
    for item in chunks:
        data = sse.encode_chunk(item)
        digest.update(data)
        out.append(sse.encode_event(sse.EVENT_CHUNK, data))
    signature = sign_response(
        SIGNER,
        request_nonce=int(request.headers["X-Bittensor-Nonce"]),
        sender_ss58=request.headers["X-Bittensor-Hotkey"],
        status=200,
        digest=digest.hexdigest(),
    )[HEADER_SIGNATURE]
    trailer = sse.Trailer(digest.hexdigest(), digest.count, signature)
    return out, sse.encode_event(sse.EVENT_END, sse.encode_trailer(trailer))


class Pieces(httpx.AsyncByteStream):
    def __init__(self, pieces: AsyncIterator[bytes]) -> None:
        self._pieces = pieces

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for piece in self._pieces:
            yield piece


Script = Callable[[httpx.Request], AsyncIterator[bytes]]


class Scripted(httpx.AsyncBaseTransport):
    """Answers each request with the next script: a body iterator or a response."""

    def __init__(self, *scripts: Script | httpx.Response | Exception, **headers: str):
        self.scripts = list(scripts)
        self.headers = headers
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        script = self.scripts.pop(0) if len(self.scripts) > 1 else self.scripts[0]
        if isinstance(script, Exception):
            raise script
        if isinstance(script, httpx.Response):
            return script
        headers = {
            "content-type": "text/event-stream",
            **start_headers(SIGNER),
            **self.headers,
        }
        return httpx.Response(200, headers=headers, stream=Pieces(script(request)))


def client(transport: httpx.AsyncBaseTransport, **kw: Any) -> ValidatorClient:
    options: dict[str, Any] = {"timeout_s": 5.0, "transport": transport}
    options.update(kw)
    return ValidatorClient(dev_key("alice").signer(), **options)


async def good(request: httpx.Request) -> AsyncIterator[bytes]:
    frames, trailer = signed_stream(request)
    for frame in frames:
        yield frame
    yield trailer


async def run(transport: httpx.AsyncBaseTransport, **kw: Any) -> Any:
    options = {k: kw.pop(k) for k in list(kw) if k in ("metrics", "timeout_s")}
    async with client(transport, **options) as vc:
        return await vc.query_stream(NEURON, "/v1/gen", b"{}", **kw)


async def test_a_good_stream() -> None:
    result = await run(Scripted(good))
    assert result.ok
    assert result.response_verified
    assert result.data == tuple(CHUNKS)


async def test_slow_drip_is_cut_by_the_idle_limit() -> None:
    async def drip(request: httpx.Request) -> AsyncIterator[bytes]:
        frames, trailer = signed_stream(request)
        for byte in b"".join([*frames, trailer]):
            yield bytes([byte])
            await asyncio.sleep(0.05)  # a byte well inside the idle time, but no event

    metrics = Metrics()
    started = asyncio.get_running_loop().time()
    result = await run(Scripted(drip), idle_s=1, metrics=metrics)
    assert result.error_code == "tw.timeout"
    assert asyncio.get_running_loop().time() - started < 3
    assert metrics.registry.get_sample_value(
        "tw_stream_aborted_total", {"side": "validator", "reason": "timeout"}
    )


async def test_endless_stream_is_cut_at_max_s() -> None:
    async def endless(request: httpx.Request) -> AsyncIterator[bytes]:
        while True:
            yield b'event: chunk\ndata: {"t":1}\n\n'
            await asyncio.sleep(0.02)

    started = asyncio.get_running_loop().time()
    result = await run(Scripted(endless), max_s=1, max_bytes=64 * 1024 * 1024)
    assert result.error_code == "tw.timeout"
    assert 0.9 < asyncio.get_running_loop().time() - started < 3


async def test_the_query_budget_also_bounds_a_stream() -> None:
    async def slow(request: httpx.Request) -> AsyncIterator[bytes]:
        while True:
            yield b": still here\n\n"
            yield b'event: chunk\ndata: {"t":1}\n\n'
            await asyncio.sleep(0.05)

    started = asyncio.get_running_loop().time()
    result = await run(Scripted(slow), timeout_s=0.5, max_s=60)  # budget 2 x 0.5 s
    assert result.error_code == "tw.timeout"
    assert asyncio.get_running_loop().time() - started < 2


async def test_no_end_after_the_trailer_times_out() -> None:
    async def hangs(request: httpx.Request) -> AsyncIterator[bytes]:
        async for piece in good(request):
            yield piece
        await asyncio.sleep(30)

    assert (await run(Scripted(hangs), idle_s=1)).error_code == "tw.timeout"


async def test_byte_limit() -> None:
    async def big(request: httpx.Request) -> AsyncIterator[bytes]:
        frames, trailer = signed_stream(request, [{"pad": "x" * 600}] * 3)
        for frame in frames:
            yield frame
        yield trailer

    metrics = Metrics()
    result = await run(Scripted(big), max_bytes=1024, metrics=metrics)
    assert result.error_code == "tw.response_too_large"
    assert metrics.registry.get_sample_value(
        "tw_stream_aborted_total", {"side": "validator", "reason": "too_large"}
    )


class Model(BaseModel):
    t: int


@pytest.mark.parametrize(
    ("frame", "kw"),
    [
        (b"event: chunk\ndata: not json\n\n", {}),
        (b"event: chunk\ndata: 5\n\n", {}),
        (b'event: chunk\ndata: {"t": "a"}\n\n', {"chunk_model": Model}),
        (b"event: chunk\ndata: " + b"[" * 129 + b"]" * 129 + b"\n\n", {}),  # D43
    ],
)
async def test_bad_chunks_are_invalid_responses(frame: bytes, kw: Any) -> None:
    async def bad(request: httpx.Request) -> AsyncIterator[bytes]:
        yield frame

    assert (await run(Scripted(bad), **kw)).error_code == "tw.invalid_response"


async def test_a_dropped_connection_mid_stream_has_no_trailer() -> None:
    async def drops(request: httpx.Request) -> AsyncIterator[bytes]:
        frames, _ = signed_stream(request)
        yield frames[0]
        raise httpx.ReadError("connection reset")

    result = await run(Scripted(drops))
    assert result.error_code == "tw.bad_response_signature"


async def test_answers_that_are_not_streams() -> None:
    plain = httpx.Response(200, json={"ok": True})
    assert (await run(Scripted(plain))).error_code == "tw.bad_response_signature"
    async with client(Scripted(plain), verify_responses=False) as vc:
        unverified = await vc.query_stream(NEURON, "/v1/gen", b"{}")
    assert unverified.error_code == "tw.invalid_response"  # a 200 that is not SSE
    assert (await run(Scripted(httpx.Response(404)))).error_code == "tw.http_404"


async def test_an_encoded_stream_is_refused() -> None:
    result = await run(Scripted(good, **{"content-encoding": "gzip"}))
    assert result.error_code == "tw.invalid_response"


async def test_retries_before_the_stream_starts_with_fresh_signatures() -> None:
    transport = Scripted(httpx.Response(503), good)
    result = await run(transport)
    assert result.ok
    assert result.attempts == 2
    nonces = {r.headers["X-Bittensor-Nonce"] for r in transport.requests}
    assert len(nonces) == 2
    assert transport.requests[0].headers["accept"] == "text/event-stream"


async def test_connect_errors_are_retried_then_reported() -> None:
    result = await run(Scripted(httpx.ConnectError("refused")))
    assert (result.error_code, result.attempts) == ("tw.connect_error", 2)


async def test_no_axon_is_never_contacted() -> None:
    transport = Scripted(good)
    async with client(transport) as vc:
        result = await vc.query_stream(replace(NEURON, axon=None), "/x", b"")
    assert result.error_code == "tw.no_axon"
    assert transport.requests == []


async def test_chunks_are_handed_out_unverified_and_early_close_frees_the_slot() -> (
    None
):
    async def forever(request: httpx.Request) -> AsyncIterator[bytes]:
        while True:
            yield b'event: chunk\ndata: {"t":1}\n\n'
            await asyncio.sleep(0.01)

    async with client(Scripted(forever, good), max_concurrency=1) as vc:
        async with vc.stream(NEURON, "/v1/gen", b"{}") as stream:
            first = await anext(stream)
            assert (first.index, first.data, first.verified) == (0, {"t": 1}, False)
        assert stream.result is None  # closed early: no result
        with pytest.raises(RuntimeError, match="closed before it ended"):
            await stream.finish()
        # The only concurrency slot was released by the early close.
        result = await asyncio.wait_for(vc.query_stream(NEURON, "/v1/gen", b"{}"), 5)
    assert result.ok


async def test_stream_many() -> None:
    other = replace(NEURON, uid=2)
    async with client(Scripted(good)) as vc:
        results = await vc.query_stream_many([NEURON, other], "/v1/gen", b"{}")
    assert sorted(results) == [1, 2]
    assert all(r.ok for r in results.values())


async def test_bad_limits_are_refused() -> None:
    vc = client(Scripted(good))
    with pytest.raises(ValueError, match="between"):
        vc.stream(NEURON, "/x", b"", idle_s=0)
    with pytest.raises(ValueError, match="timeout_s"):
        vc.stream(NEURON, "/x", b"", timeout_s=0)


async def test_stream_requests_have_no_read_timeout_and_no_compression() -> None:
    transport = Scripted(good)
    assert (await run(transport, timeout_s=1)).ok
    request = transport.requests[0]
    assert request.extensions["timeout"]["read"] is None  # the reader times reads
    assert request.headers["accept-encoding"] == "identity"


async def test_a_slow_caller_does_not_use_up_the_miners_idle_time() -> None:
    vc = client(Scripted(good))
    async with vc, vc.stream(NEURON, "/v1/gen", b"{}", idle_s=1) as stream:
        async for _ in stream:
            await asyncio.sleep(1.3)  # scoring each chunk takes longer than idle_s
    assert stream.result is not None
    assert stream.result.ok, stream.result


class Closing(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while True:
            yield b'event: chunk\ndata: {"t":1}\n\n'
            await asyncio.sleep(0.01)

    async def aclose(self) -> None:
        self.closed = True


async def test_an_early_close_closes_the_response_at_once() -> None:
    body = Closing()
    transport = Scripted(
        httpx.Response(
            200,
            headers={"content-type": "text/event-stream", **start_headers(SIGNER)},
            stream=body,
        )
    )
    async with client(transport) as vc:
        async with vc.stream(NEURON, "/v1/gen", b"{}") as stream:
            await anext(stream)
        assert body.closed  # before the slot is reused, not later by the GC
