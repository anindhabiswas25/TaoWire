"""The miner's SSE response on its own: disconnects, drains, closing (spec 9.2, D29)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import anyio
import pytest
import structlog

from tensorwire.auth.verifier import Caller
from tensorwire.crypto import HotkeySigner
from tensorwire.errors import RateLimited
from tensorwire.extensions.streaming import StreamLimits
from tensorwire.miner.streaming import MAX_STREAMS_PER_CALLER, StreamSlots, open_stream
from tensorwire.observability.metrics import Metrics
from tensorwire.testing.keys import dev_key

pytestmark = pytest.mark.asyncio

CALLER = Caller(hotkey_ss58=dev_key("alice").ss58, nonce_ns=1, crypto_type=1)


class Handler:
    """A chunk source that records whether it was closed."""

    def __init__(self, *, forever: bool = False) -> None:
        self.closed = False
        self.forever = forever

    async def chunks(self) -> AsyncIterator[Any]:
        try:
            yield {"i": 0}
            while self.forever:
                await asyncio.sleep(0.01)
                yield {"i": 1}
        finally:
            self.closed = True


async def response(
    handler: Handler,
    metrics: Metrics,
    state: dict[str, Any] | None = None,
    **limits: Any,
) -> Any:
    return await open_stream(
        handler.chunks(),
        route="/r",
        request_id="rid",
        timeout_s=1.0,
        limits=StreamLimits(**limits),
        chunk_model=None,
        signer=HotkeySigner(dev_key("bob").keypair),
        caller=CALLER,
        metrics=metrics,
        state={} if state is None else state,
    )


def aborted(metrics: Metrics, reason: str) -> float:
    value = metrics.registry.get_sample_value(
        "tw_stream_aborted_total", {"side": "miner", "reason": reason}
    )
    return value or 0.0


async def test_a_disconnect_stops_the_handler_at_once() -> None:
    handler, metrics = Handler(forever=True), Metrics()
    sent: list[dict[str, Any]] = []
    disconnect = anyio.Event()

    async def receive() -> dict[str, Any]:
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)
        if len(sent) == 5:
            disconnect.set()

    state: dict[str, Any] = {}
    resp = await response(handler, metrics, state)
    with structlog.testing.capture_logs() as logs, anyio.fail_after(5):
        await resp({"type": "http"}, receive, send)
    assert handler.closed
    assert aborted(metrics, "cancelled") == 1
    assert state["tw_code"] == "stream_aborted"  # the request log says so
    assert any(e["event"] == "stream_aborted" for e in logs)
    assert all(m.get("more_body", True) for m in sent)  # nothing after the disconnect
    assert all(b"tw-end" not in m.get("body", b"") for m in sent)


async def test_a_drain_cancels_the_stream_and_is_counted() -> None:
    handler, metrics = Handler(forever=True), Metrics()

    async def receive() -> dict[str, Any]:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        return None

    resp = await response(handler, metrics)
    with anyio.move_on_after(0.2):  # the server cancels the request task
        await resp({"type": "http"}, receive, send)
    assert handler.closed
    assert aborted(metrics, "cancelled") == 1


async def test_a_finished_stream_ends_with_the_trailer() -> None:
    handler, metrics = Handler(), Metrics()
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    resp = await response(handler, metrics)
    await resp({"type": "http"}, receive, send)
    bodies = [m["body"] for m in sent if m["type"] == "http.response.body"]
    assert bodies[-2].startswith(b"event: tw-end\n")
    assert sent[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
    assert handler.closed
    assert metrics.registry.get_sample_value("tw_stream_aborted_total", {}) is None


async def test_a_send_blocked_by_a_reader_that_stopped_is_cut_at_max_s() -> None:
    handler, metrics = Handler(forever=True), Metrics()
    calls = 0

    async def receive() -> dict[str, Any]:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        nonlocal calls
        calls += 1
        if calls > 2:
            await asyncio.Event().wait()  # the socket buffer is full, forever

    resp = await response(handler, metrics, max_s=1)
    with anyio.fail_after(5):
        await resp({"type": "http"}, receive, send)
    assert aborted(metrics, "max_duration") == 1
    assert handler.closed


async def test_a_disconnect_after_the_trailer_is_not_an_abort() -> None:
    handler, metrics = Handler(), Metrics()
    delivered = anyio.Event()

    async def receive() -> dict[str, Any]:
        await delivered.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if b"tw-end" in message.get("body", b""):
            delivered.set()
            await asyncio.sleep(0.05)  # the validator leaves while we finish

    state: dict[str, Any] = {}
    resp = await response(handler, metrics, state)
    with anyio.fail_after(5):
        await resp({"type": "http"}, receive, send)
    assert (
        metrics.registry.get_sample_value(
            "tw_stream_aborted_total", {"side": "miner", "reason": "cancelled"}
        )
        is None
    )
    assert "tw_code" not in state


async def test_stream_slots_cap_each_caller() -> None:
    slots = StreamSlots(limit=2)
    first = slots.acquire("a")
    slots.acquire("a")
    with pytest.raises(RateLimited) as refused:
        slots.acquire("a")
    assert refused.value.signed  # a verified caller: the 429 is signed
    slots.acquire("b")  # other callers are not affected
    first()
    first()  # idempotent
    assert slots.open_for("a") == 1
    slots.acquire("a")
    assert MAX_STREAMS_PER_CALLER == 16
    with pytest.raises(ValueError, match="at least 1"):
        StreamSlots(limit=0)


async def test_the_slot_is_released_when_the_stream_ends_or_fails() -> None:
    slots = StreamSlots(limit=1)
    release = slots.acquire("alice")
    handler, metrics = Handler(), Metrics()
    resp = await open_stream(
        handler.chunks(),
        route="/r",
        request_id=None,
        timeout_s=1.0,
        limits=StreamLimits(),
        chunk_model=None,
        signer=None,
        caller=CALLER,
        metrics=metrics,
        state={},
        release=release,
    )
    assert slots.open_for("alice") == 1

    async def receive() -> dict[str, Any]:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        return None

    await resp({"type": "http"}, receive, send)
    assert slots.open_for("alice") == 0

    async def broken() -> AsyncIterator[Any]:
        raise RuntimeError("no first chunk")
        yield {}  # pragma: no cover

    release = slots.acquire("alice")
    with pytest.raises(Exception, match="handler"):
        await open_stream(
            broken(),
            route="/r",
            request_id=None,
            timeout_s=1.0,
            limits=StreamLimits(),
            chunk_model=None,
            signer=None,
            caller=CALLER,
            metrics=metrics,
            state={},
            release=release,
        )
    assert slots.open_for("alice") == 0
