"""Integration test 11 (spec 13.4) and the streaming rules of 9.2 (D29).

A real miner app on FakeChain with streaming routes, reached by the real
``ValidatorClient`` through ``AppRouter``. A rewriting ASGI wrapper plays the
man in the middle: it changes the signed stream on its way to the validator.
The ASGI transport delivers a response once the app has finished, so time
limits on the validator side are tested separately with a scripted transport
(``tests/unit/test_streaming_client.py``); here the miner enforces its own limits.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable, MutableMapping
from typing import Any

import pytest
from pydantic import BaseModel

from tensorwire.chain.gateway import NeuronView
from tensorwire.config import MinerSettings
from tensorwire.extensions.response_sig import HEADER_HOTKEY
from tensorwire.extensions.streaming import StreamingReply
from tensorwire.miner.app import Miner
from tensorwire.miner.routes import RouteContext
from tensorwire.observability.metrics import Metrics
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.pytest_plugin import MINER_KEY, TEST_NETUID
from tensorwire.testing.transport import AppRouter
from tensorwire.validator.client import MinerResult, ValidatorClient

pytestmark = pytest.mark.asyncio

ADDRESS = "44.1.2.3:8091"
BODY = b'{"n": 3}'
Rewrite = Callable[[bytes], bytes]


HELD = asyncio.Event()


class Gen(BaseModel):
    n: int


class Token(BaseModel):
    token: str


def frames(body: bytes) -> list[bytes]:
    return [f + b"\n\n" for f in body.split(b"\n\n") if f]


def rewriting(app: Any, body: Rewrite | None = None, *, strip: bool = False) -> Any:
    """ASGI wrapper: rewrite the whole streamed body, or drop ``X-TW-Resp-*``."""

    async def wrapped(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await app(scope, receive, send)
            return
        parts: list[bytes] = []

        async def send_rewritten(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                if strip:
                    message["headers"] = [
                        (k, v)
                        for k, v in message["headers"]
                        if not k.lower().startswith(b"x-tw-resp-")
                    ]
                await send(message)
                return
            parts.append(message.get("body", b""))
            if not message.get("more_body"):
                joined = b"".join(parts)
                out = body(joined) if body is not None else joined
                await send({"type": "http.response.body", "body": out})

        await app(scope, receive, send_rewritten)

    return wrapped


@pytest.fixture
def tw_miner(tw_miner_kwargs: dict[str, Any]) -> Miner:
    miner = Miner(**tw_miner_kwargs)

    @miner.route("/v1/gen", request=Gen, response=Token, stream=True)
    async def gen(req: Gen, ctx: RouteContext) -> AsyncIterator[Token]:
        for i, text in enumerate(["Hel", "lo ☃", "!", "?", "+"][: req.n]):
            yield Token(token=text if i < 5 else str(i))

    @miner.route("/v1/reply", request=Gen, stream=True)
    def reply(req: Gen, ctx: RouteContext) -> StreamingReply:  # a sync handler
        async def chunks() -> AsyncIterator[Any]:
            for i in range(req.n):
                yield {"i": i} if i % 2 else [i]

        return StreamingReply(chunks())

    @miner.route("/v1/broken", request=Gen, stream=True)
    async def broken(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        yield {"i": 0}
        yield {"i": 1}
        raise RuntimeError("model crashed")

    @miner.route("/v1/early", request=Gen, stream=True)
    async def early(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        raise RuntimeError("before the first chunk")
        yield {}  # pragma: no cover - makes this an async generator

    @miner.route("/v1/slow-start", request=Gen, stream=True, timeout_s=0.2)
    async def slow_start(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        await asyncio.sleep(5)
        yield {}

    @miner.route("/v1/slow-setup", request=Gen, stream=True, timeout_s=0.3)
    async def slow_setup(req: Gen, ctx: RouteContext) -> StreamingReply:
        await asyncio.sleep(0.2)  # inside timeout_s on its own ...

        async def chunks() -> AsyncIterator[Any]:
            await asyncio.sleep(0.2)  # ... and so is this, but not both
            yield {}

        return StreamingReply(chunks())

    @miner.route("/v1/held", request=Gen, stream=True)
    async def held(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        yield {"i": 0}
        await HELD.wait()
        yield {"i": 1}

    @miner.route("/v1/stall", request=Gen, stream=True, stream_idle_s=1)
    async def stall(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        yield {"i": 0}
        await asyncio.sleep(30)
        yield {"i": 1}

    @miner.route("/v1/endless", request=Gen, stream=True, stream_max_s=1)
    async def endless(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        i = 0
        while True:
            yield {"i": i}
            i += 1
            await asyncio.sleep(0.01)

    @miner.route("/v1/big", request=Gen, stream=True, stream_max_bytes=2048)
    async def big(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        for _ in range(100):
            yield {"pad": "x" * 100}

    @miner.route("/v1/scalar", request=Gen, stream=True)
    async def scalar(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        yield {"i": 0}
        yield 7

    @miner.route("/v1/wrong-model", request=Gen, response=Token, stream=True)
    async def wrong_model(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        yield {"token": "a dict, not a Token"}

    @miner.route("/v1/not-a-stream", request=Gen, stream=True)
    async def not_a_stream(req: Gen, ctx: RouteContext) -> Token:
        return Token(token="x")

    return miner


@pytest.fixture
async def setup(
    miner_app: Any, fake_chain: FakeChain
) -> tuple[AppRouter, NeuronView, Any]:
    fake_chain.set_axon(TEST_NETUID, dev_key(MINER_KEY).ss58, ADDRESS, protocol=87)
    mg = await fake_chain.metagraph(TEST_NETUID)
    neuron = mg.by_hotkey(dev_key(MINER_KEY).ss58)
    assert neuron is not None
    return AppRouter({ADDRESS: miner_app}), neuron, miner_app


def validator(router: AppRouter, clock: FakeClock, **kw: Any) -> ValidatorClient:
    options: dict[str, Any] = {"timeout_s": 5.0, "transport": router}
    options.update(kw)
    return ValidatorClient(dev_key("alice").signer(clock_ns=clock.now_ns), **options)


async def query(
    setup: tuple[AppRouter, NeuronView, Any],
    clock: FakeClock,
    route: str = "/v1/gen",
    rewrite: Rewrite | None = None,
    *,
    strip: bool = False,
    body: bytes = BODY,
    **kw: Any,
) -> MinerResult:
    router, neuron, app = setup
    if rewrite is not None or strip:
        router.add(ADDRESS, rewriting(app, rewrite, strip=strip))
    async with validator(router, clock) as vc:
        return await vc.query_stream(neuron, route, body, **kw)


def miner_aborts(miner: Miner, reason: str) -> float:
    value = miner.metrics.registry.get_sample_value(
        "tw_stream_aborted_total", {"side": "miner", "reason": reason}
    )
    return value or 0.0


# ------------------------------------------------------------ test 11


async def test_11_valid_trailer_is_accepted(setup: Any, tw_clock: FakeClock) -> None:
    router, neuron, _ = setup
    metrics = Metrics()
    async with validator(router, tw_clock, metrics=metrics) as vc:
        stream = vc.stream(neuron, "/v1/gen", BODY, chunk_model=Token)
        seen = [chunk async for chunk in stream]
    result = stream.result
    assert result is not None
    assert result.ok, result
    assert result.response_verified
    assert result.status == 200
    assert result.error_code is None
    assert result.data == (Token(token="Hel"), Token(token="lo ☃"), Token(token="!"))
    assert [c.index for c in seen] == [0, 1, 2]
    assert all(not c.verified for c in seen)  # only the result is trustworthy
    assert seen[1].raw == '{"token":"lo ☃"}'.encode()
    assert metrics.registry.get_sample_value(
        "tw_validator_miner_results_total", {"ok": "true", "code": "ok"}
    )


def _swap(body: bytes) -> bytes:
    f = frames(body)
    return b"".join([f[1], f[0], *f[2:]])


def _drop(body: bytes) -> bytes:
    f = frames(body)
    return b"".join([f[0], *f[2:]])


def _extra(body: bytes) -> bytes:
    f = frames(body)
    return b"".join([f[0], b'event: chunk\ndata: {"token":"X"}\n\n', *f[1:]])


def _duplicate_trailer(body: bytes) -> bytes:
    return body + frames(body)[-1]


def _event_after_trailer(body: bytes) -> bytes:
    return body + b'event: chunk\ndata: {"token":"late"}\n\n'


def _unknown_after_trailer(body: bytes) -> bytes:
    return body + b"event: ping\ndata: 1\n\n"


def _trailer_field(field: str, value: Any) -> Rewrite:
    def rewrite(body: bytes) -> bytes:
        f = frames(body)
        head, data = f[-1].split(b"data: ", 1)
        trailer = json.loads(data)
        trailer[field] = value
        return b"".join(
            [*f[:-1], head + b"data: " + json.dumps(trailer).encode() + b"\n\n"]
        )

    return rewrite


def _flip_signature(body: bytes) -> bytes:
    f = frames(body)
    data = json.loads(f[-1].split(b"data: ", 1)[1])
    sig = data["signature"]
    data["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    return b"".join(
        [*f[:-1], b"event: tw-end\ndata: " + json.dumps(data).encode() + b"\n\n"]
    )


@pytest.mark.parametrize(
    ("name", "rewrite"),
    [
        ("tampered chunk", lambda b: b.replace(b'"Hel"', b'"Hex"')),
        ("reordered chunks", _swap),
        ("dropped chunk", _drop),
        ("extra chunk", _extra),
        ("tampered trailer digest", _trailer_field("digest", "0" * 64)),
        ("tampered trailer count", _trailer_field("count", 2)),
        ("tampered trailer signature", _flip_signature),
        ("unsigned trailer", _trailer_field("signature", None)),
        ("duplicate trailer", _duplicate_trailer),
        ("event after the trailer", _event_after_trailer),
        ("unknown event after the trailer", _unknown_after_trailer),
        ("missing trailer", lambda b: b"".join(frames(b)[:-1])),
        ("truncated mid-chunk", lambda b: b[: len(b) // 2]),
    ],
)
async def test_11_tampered_streams_are_rejected(
    setup: Any, tw_clock: FakeClock, name: str, rewrite: Rewrite
) -> None:
    result = await query(setup, tw_clock, rewrite=rewrite)
    assert not result.ok, name
    assert result.error_code == "tw.bad_response_signature", name
    assert not result.response_verified
    assert result.data is None


async def test_11_missing_trailer_after_a_handler_error(
    setup: Any, tw_clock: FakeClock, tw_miner: Miner
) -> None:
    result = await query(setup, tw_clock, "/v1/broken")
    assert result.error_code == "tw.bad_response_signature"
    assert result.status == 200
    assert miner_aborts(tw_miner, "handler_error") == 1


async def test_missing_start_headers_are_rejected(
    setup: Any, tw_clock: FakeClock
) -> None:
    result = await query(setup, tw_clock, strip=True)
    assert result.error_code == "tw.bad_response_signature"


async def test_a_resplit_of_the_signed_bytes_is_rejected(
    setup: Any, tw_clock: FakeClock
) -> None:
    """Moving a chunk boundary keeps digest and count; object chunks make it invalid."""

    def resplit(body: bytes) -> bytes:
        f = frames(body)
        first, second = (fr.split(b"data: ", 1)[1][:-2] for fr in f[:2])
        joined = first + second
        cut = len(first) + 3
        moved = [
            b"event: chunk\ndata: " + joined[:cut] + b"\n\n",
            b"event: chunk\ndata: " + joined[cut:] + b"\n\n",
        ]
        return b"".join([*moved, *f[2:]])

    result = await query(setup, tw_clock, rewrite=resplit)
    assert result.error_code == "tw.invalid_response"


async def test_unknown_events_and_comments_are_ignored(
    setup: Any, tw_clock: FakeClock
) -> None:
    def noise(body: bytes) -> bytes:
        f = frames(body)
        return (
            b": hello\n\nevent: ping\ndata: {}\n\n" + f[0] + b":x\n\n" + b"".join(f[1:])
        )

    result = await query(setup, tw_clock, rewrite=noise)
    assert result.ok, result
    assert result.response_verified


async def test_unverified_mode_still_checks_digest_and_count(
    setup: Any, tw_clock: FakeClock
) -> None:
    router, neuron, app = setup
    async with validator(router, tw_clock, verify_responses=False) as vc:
        router.add(ADDRESS, rewriting(app, strip=True))
        ok = await vc.query_stream(neuron, "/v1/gen", BODY)
        router.add(ADDRESS, rewriting(app, _drop))
        bad = await vc.query_stream(neuron, "/v1/gen", BODY)
    assert ok.ok
    assert not ok.response_verified
    assert bad.error_code == "tw.bad_response_signature"


# ------------------------------------------------------------ miner rules


async def test_sync_handler_reply_and_raw_values(
    setup: Any, tw_clock: FakeClock
) -> None:
    result = await query(setup, tw_clock, "/v1/reply", body=b'{"n": 4}')
    assert result.ok, result
    assert result.data == ([0], {"i": 1}, [2], {"i": 3})


async def test_empty_stream(setup: Any, tw_clock: FakeClock) -> None:
    result = await query(setup, tw_clock, body=b'{"n": 0}')
    assert result.ok
    assert result.data == ()
    assert result.response_verified


@pytest.mark.parametrize(
    ("route", "code", "status"),
    [
        ("/v1/early", "tw.handler_error", 500),
        ("/v1/slow-start", "tw.handler_timeout", 504),
        ("/v1/slow-setup", "tw.handler_timeout", 504),  # one deadline for both
        ("/v1/not-a-stream", "tw.handler_error", 500),
    ],
)
async def test_failures_before_the_first_chunk_are_signed_json_errors(
    setup: Any, tw_clock: FakeClock, route: str, code: str, status: int
) -> None:
    result = await query(setup, tw_clock, route)
    assert (result.error_code, result.status) == (code, status)
    assert result.response_verified  # a signed error, verified like any other


@pytest.mark.parametrize(
    ("route", "reason"),
    [
        ("/v1/stall", "idle_timeout"),
        ("/v1/endless", "max_duration"),
        ("/v1/big", "max_bytes"),
        ("/v1/scalar", "bad_chunk"),
        ("/v1/wrong-model", "bad_chunk"),
    ],
)
async def test_miner_limits_end_the_stream_without_a_trailer(
    setup: Any, tw_clock: FakeClock, tw_miner: Miner, route: str, reason: str
) -> None:
    result = await query(setup, tw_clock, route)
    assert result.error_code == "tw.bad_response_signature"
    assert miner_aborts(tw_miner, reason) == 1
    logged = tw_miner.metrics.registry.get_sample_value(
        "tw_requests_total", {"route": route, "status": "200", "code": "stream_aborted"}
    )
    assert logged == 1  # not "ok" in the request metrics and log


async def test_pipeline_failures_are_json_not_streams(
    setup: Any, tw_clock: FakeClock
) -> None:
    assert (await query(setup, tw_clock, body=b'{"n": "x"}')).error_code == (
        "tw.invalid_request"
    )
    router, neuron, _ = setup
    other = ValidatorClient(
        dev_key("charlie").signer(clock_ns=tw_clock.now_ns), transport=router
    )
    async with other:
        refused = await other.query_stream(neuron, "/v1/gen", BODY)
    assert refused.error_code == "tw.forbidden_not_validator"
    assert refused.status == 403


async def test_stream_headers(setup: Any, tw_clock: FakeClock) -> None:
    router, neuron, app = setup
    seen: dict[bytes, bytes] = {}

    async def capture(scope: Any, receive: Any, send: Any) -> None:
        async def send_capturing(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                seen.update(dict(message["headers"]))
            await send(message)

        await app(scope, receive, send_capturing)

    router.add(ADDRESS, capture)
    async with validator(router, tw_clock) as vc:
        assert (await vc.query_stream(neuron, "/v1/gen", BODY)).ok
    assert seen[b"content-type"].startswith(b"text/event-stream")
    assert seen[b"cache-control"] == b"no-store"
    assert seen[HEADER_HOTKEY.lower().encode()] == dev_key(MINER_KEY).ss58.encode()
    assert b"x-tw-resp-signature" not in seen


async def test_registration_rules(tw_miner_kwargs: dict[str, Any]) -> None:
    miner = Miner(**tw_miner_kwargs)

    async def agen(req: Any, ctx: Any) -> AsyncIterator[Any]:
        yield {}

    with pytest.raises(ValueError, match="needs stream=True"):
        miner.route("/a")(agen)
    with pytest.raises(ValueError, match="need stream=True"):
        miner.route("/b", stream_idle_s=5)(agen)
    with pytest.raises(ValueError, match="between"):
        miner.route("/c", stream=True, stream_max_s=0.5)(agen)
    with pytest.raises(ValueError, match="no encode"):
        miner.route("/d", stream=True, encode=bytes)(agen)


async def test_a_caller_cannot_hold_more_than_its_stream_slots(
    setup: Any, tw_clock: FakeClock, tw_miner: Miner
) -> None:
    router, neuron, _ = setup
    tw_miner._stream_slots.limit = 1
    HELD.clear()
    async with validator(router, tw_clock) as vc:
        first = asyncio.create_task(vc.query_stream(neuron, "/v1/held", BODY))
        while tw_miner._stream_slots.open_for(dev_key("alice").ss58) == 0:
            await asyncio.sleep(0.01)
        second = await vc.query_stream(neuron, "/v1/gen", BODY)
        HELD.set()
        held = await first
        third = await vc.query_stream(neuron, "/v1/gen", BODY)  # the slot is back
    assert (second.error_code, second.status) == ("tw.rate_limited", 429)
    assert second.response_verified  # a signed refusal
    assert held.ok, held
    assert third.ok, third


async def test_stream_max_per_caller_setting_limits_open_streams(
    tw_env: Any,
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
) -> None:
    """TW_STREAM_MAX_PER_CALLER=2 (D36): the third open stream of a caller is 429."""
    tw_env.set(stream_max_per_caller=2)
    base = tw_miner_kwargs["settings"]
    settings = MinerSettings(
        netuid=base.netuid,
        wallet_name=base.wallet_name,
        wallet_path=base.wallet_path,
        external_ip=base.external_ip,
        ntp_servers=(),
    )
    miner = Miner(**{**tw_miner_kwargs, "settings": settings})
    release = (
        asyncio.Event()
    )  # this test's loop (the module's HELD may be bound elsewhere)

    @miner.route("/v1/held", request=Gen, stream=True)
    async def held(req: Gen, ctx: RouteContext) -> AsyncIterator[Any]:
        yield {"i": 0}
        await release.wait()

    @miner.route("/v1/gen", request=Gen, response=Token, stream=True)
    async def gen(req: Gen, ctx: RouteContext) -> AsyncIterator[Token]:
        yield Token(token="x")

    assert miner._stream_slots.limit == 2
    async with miner.running() as app:
        fake_chain.set_axon(TEST_NETUID, dev_key(MINER_KEY).ss58, ADDRESS, protocol=87)
        mg = await fake_chain.metagraph(TEST_NETUID)
        neuron = mg.by_hotkey(dev_key(MINER_KEY).ss58)
        assert neuron is not None
        router = AppRouter({ADDRESS: app})
        async with validator(router, tw_clock) as vc:
            holders = [
                asyncio.create_task(vc.query_stream(neuron, "/v1/held", BODY))
                for _ in range(2)
            ]
            while miner._stream_slots.open_for(dev_key("alice").ss58) < 2:
                await asyncio.sleep(0.01)
            third = await vc.query_stream(neuron, "/v1/gen", BODY)
            release.set()
            results = await asyncio.gather(*holders)
    assert (third.error_code, third.status) == ("tw.rate_limited", 429)
    assert third.response_verified
    assert all(r.ok for r in results), results
