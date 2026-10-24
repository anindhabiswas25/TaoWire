"""The miner side of streaming routes (spec 9.2, D29).

A route registered with ``stream=True`` runs the whole 5.3 pipeline first
(body cap, rate limits, verification, replay store, caller policy,
per-hotkey limit, request parsing) and then the handler, which returns an
async iterable of chunks or a :class:`~taowire.extensions.streaming.StreamingReply`.
The first chunk is fetched **before** any byte is sent, within the route's
``timeout_s``: a handler that fails or stalls there gets the ordinary signed
JSON 500 / 504.

After that the answer is ``200 text/event-stream``: one ``chunk`` event per
item and a final ``tw-end`` with the digest, the count and the ``twresp/1``
signature. The limits apply on the miner too: the whole stream within
``max_s`` (sends to a reader that stops reading included), at most
``idle_s`` between two chunks from the handler, at most ``max_bytes`` on the
wire (``TRAILER_RESERVE`` kept for the trailer). A limit hit, a handler
exception, a chunk that is not a JSON object or array, a client disconnect
or a drain ends the stream **without** ``tw-end``, so the validator rejects
it; the miner never signs a trailer over partial data. Each abort is logged
(``stream_aborted``) and counted in ``tw_stream_aborted_total{side="miner"}``.

A caller may hold at most ``TW_STREAM_MAX_PER_CALLER`` (default
:data:`MAX_STREAMS_PER_CALLER`, 1-256, D36) open streams per miner process
(:class:`StreamSlots`); more are refused with the signed 429
``tw.rate_limited``. Streams live up to ``max_s``, far longer than a plain
request, so without this one permitted validator could fill the server's
connection limit and starve the others.
"""

from __future__ import annotations

import contextlib
from collections import Counter
from collections.abc import AsyncIterator, Callable, MutableMapping
from dataclasses import dataclass
from typing import Any, Literal

import anyio
import structlog
from pydantic import BaseModel
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from taowire.auth.verifier import Caller
from taowire.config import STREAM_MAX_PER_CALLER_RANGE
from taowire.crypto import HotkeySigner
from taowire.errors import HandlerError, HandlerTimeout, RateLimited, TWError
from taowire.extensions.response_sig import (
    HEADER_SIGNATURE,
    identity_headers,
    sign_response,
)
from taowire.extensions.streaming import (
    CONTENT_TYPE,
    EVENT_CHUNK,
    EVENT_END,
    TRAILER_RESERVE,
    ChunkError,
    StreamDigest,
    StreamingReply,
    StreamLimits,
    Trailer,
    encode_chunk,
    encode_event,
    encode_trailer,
)
from taowire.observability.metrics import Metrics

__all__ = ["MAX_STREAMS_PER_CALLER", "AbortReason", "StreamSlots", "open_stream"]

#: Default open streams one caller hotkey may hold per miner process
#: (``TW_STREAM_MAX_PER_CALLER``, D36).
MAX_STREAMS_PER_CALLER = 16

AbortReason = Literal[
    "handler_error",
    "idle_timeout",
    "max_duration",
    "max_bytes",
    "bad_chunk",
    "cancelled",
]

_log = structlog.stdlib.get_logger("taowire.miner")
_DONE: Any = object()
#: How long the final empty body frame may take after an abort.
_CLOSE_S = 1.0


@dataclass(frozen=True, slots=True)
class _Context:
    route: str
    request_id: str | None
    limits: StreamLimits
    chunk_model: type[BaseModel] | None
    signer: HotkeySigner | None
    """``None`` when ``TW_SIGN_RESPONSES=0``: the trailer has no signature."""
    caller: Caller
    metrics: Metrics
    state: MutableMapping[str, Any]
    """The request's state: an abort sets ``tw_code`` for the request log."""
    release: Callable[[], None]
    """Gives the caller's stream slot back (:class:`StreamSlots`)."""


class StreamSlots:
    """Open streams per caller hotkey in this process (see the module docstring)."""

    def __init__(self, limit: int = MAX_STREAMS_PER_CALLER) -> None:
        low, high = STREAM_MAX_PER_CALLER_RANGE
        if isinstance(limit, bool) or not low <= limit <= high:
            raise ValueError(f"limit must be between {low} and {high}")
        self.limit = limit
        self._open: Counter[str] = Counter()

    def acquire(self, hotkey: str) -> Callable[[], None]:
        """Take a slot or raise :class:`RateLimited`; return its release."""
        if self._open[hotkey] >= self.limit:
            raise RateLimited(retry_after_s=1, layer="hotkey")
        self._open[hotkey] += 1
        released = False

        def release() -> None:
            nonlocal released
            if released:
                return
            released = True
            self._open[hotkey] -= 1
            if not self._open[hotkey]:
                del self._open[hotkey]

        return release

    def open_for(self, hotkey: str) -> int:
        """How many streams ``hotkey`` holds now."""
        return self._open[hotkey]


class _Abort(Exception):
    def __init__(self, reason: AbortReason) -> None:
        super().__init__(reason)
        self.reason: AbortReason = reason


def _chunks(result: Any, route: str) -> AsyncIterator[Any]:
    if isinstance(result, StreamingReply):
        result = result.chunks
    if hasattr(result, "__aiter__"):
        iterator: AsyncIterator[Any] = result.__aiter__()
        return iterator
    _log.error(
        "handler_bad_return",
        route=route,
        returned=type(result).__name__,
        expected="an async iterable of chunks or StreamingReply",
    )
    raise HandlerError()


async def open_stream(
    result: Any,
    *,
    route: str,
    request_id: str | None,
    timeout_s: float,
    limits: StreamLimits,
    chunk_model: type[BaseModel] | None,
    signer: HotkeySigner | None,
    caller: Caller,
    metrics: Metrics,
    state: MutableMapping[str, Any],
    release: Callable[[], None] = lambda: None,
) -> Response:
    """Fetch the first chunk (within ``timeout_s``) and return the SSE response.

    Raises :class:`HandlerError` / :class:`HandlerTimeout` when the handler
    fails or stalls before its first chunk: nothing has been sent yet, so the
    caller answers with the ordinary JSON error. ``release`` is called when
    the stream ends, or at once when this raises.
    """
    try:
        return await _open(
            result, route, request_id, timeout_s, limits, chunk_model,
            signer, caller, metrics, state, release,
        )  # fmt: skip
    except BaseException:
        release()
        raise


async def _open(  # noqa: PLR0917 - the private body of open_stream
    result: Any,
    route: str,
    request_id: str | None,
    timeout_s: float,
    limits: StreamLimits,
    chunk_model: type[BaseModel] | None,
    signer: HotkeySigner | None,
    caller: Caller,
    metrics: Metrics,
    state: MutableMapping[str, Any],
    release: Callable[[], None],
) -> Response:
    chunks = _chunks(result, route)
    first: Any = _DONE
    try:
        with anyio.move_on_after(timeout_s) as scope:
            first = await anext(chunks, _DONE)
    except TWError:
        raise
    except Exception:  # noqa: BLE001 - a handler bug before the first byte is a 500
        _log.exception("handler_error", route=route, request_id=request_id)
        raise HandlerError() from None
    if scope.cancelled_caught:
        await _close(chunks)
        _log.warning(
            "handler_timeout", route=route, request_id=request_id, timeout_s=timeout_s
        )
        raise HandlerTimeout()
    ctx = _Context(
        route, request_id, limits, chunk_model, signer, caller, metrics, state, release
    )
    return _SSEResponse(ctx, chunks, first)


def start_headers(signer: HotkeySigner | None) -> dict[str, str]:
    """Response headers at stream start: ``X-TW-Resp-*`` without a signature."""
    headers = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}
    if signer is not None:
        headers.update(identity_headers(signer))
    return headers


class _SSEResponse(Response):
    """Sends the events of one stream; see the module docstring for the rules."""

    media_type = CONTENT_TYPE

    def __init__(self, ctx: _Context, chunks: AsyncIterator[Any], first: Any) -> None:
        self.status_code = 200
        self.background = None
        self._ctx = ctx
        self._chunks = chunks
        self._first = first
        self._delivered = False  # the tw-end frame was handed to the server
        self.init_headers(start_headers(ctx.signer))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:  # noqa: ARG002 - ASGI signature
        await send(
            {"type": "http.response.start", "status": 200, "headers": self.raw_headers}
        )
        reason: AbortReason | None = None
        disconnected = anyio.Event()
        try:
            async with anyio.create_task_group() as tg:
                tg.start_soon(self._watch, receive, disconnected, tg.cancel_scope)
                with anyio.move_on_after(self._ctx.limits.max_s) as deadline:
                    try:
                        await self._send_events(send)
                    except _Abort as abort:
                        reason = abort.reason
                if deadline.cancelled_caught:
                    reason = "max_duration"
                tg.cancel_scope.cancel()  # stop the watcher
        except anyio.get_cancelled_exc_class():
            if not self._delivered:
                self._aborted("cancelled")  # the server is draining or shutting down
            raise
        finally:
            await _close(self._chunks)
            self._ctx.release()
        if disconnected.is_set() and reason is None:
            if not self._delivered:  # a validator leaving after tw-end is no abort
                self._aborted("cancelled")
            return
        if reason is not None:
            self._aborted(reason)
        with anyio.move_on_after(_CLOSE_S):
            await send({"type": "http.response.body", "body": b"", "more_body": False})

    @staticmethod
    async def _watch(
        receive: Receive, disconnected: anyio.Event, scope: anyio.CancelScope
    ) -> None:
        """Stop the stream at once when the client goes away."""
        while (await receive())["type"] != "http.disconnect":
            pass
        disconnected.set()
        scope.cancel()

    async def _send_events(self, send: Send) -> None:
        ctx = self._ctx
        budget = ctx.limits.max_bytes - TRAILER_RESERVE
        digest = StreamDigest()
        sent = 0
        item = self._first
        while item is not _DONE:
            frame, data = self._frame(item)
            if sent + len(frame) > budget:
                raise _Abort("max_bytes")
            await send({"type": "http.response.body", "body": frame, "more_body": True})
            digest.update(data)
            sent += len(frame)
            item = await self._next()
        trailer = Trailer(
            digest=digest.hexdigest(), count=digest.count, signature=self._sign(digest)
        )
        frame = encode_event(EVENT_END, encode_trailer(trailer))
        self._delivered = True  # handed over: a disconnect from here on is no abort
        await send({"type": "http.response.body", "body": frame, "more_body": True})

    def _frame(self, item: Any) -> tuple[bytes, bytes]:
        model = self._ctx.chunk_model
        if model is not None and not isinstance(item, (model, bytes, bytearray)):
            _log.error(
                "stream_bad_chunk",
                route=self._ctx.route,
                returned=type(item).__name__,
                expected=model.__name__,
            )
            raise _Abort("bad_chunk")
        try:
            data = encode_chunk(item)
        except ChunkError as exc:
            _log.error("stream_bad_chunk", route=self._ctx.route, reason=str(exc))
            raise _Abort("bad_chunk") from None
        return encode_event(EVENT_CHUNK, data), data

    async def _next(self) -> Any:
        try:
            with anyio.move_on_after(self._ctx.limits.idle_s) as idle:
                item = await anext(self._chunks, _DONE)
        except Exception:  # noqa: BLE001 - any handler failure ends the stream
            _log.exception(
                "handler_error", route=self._ctx.route, request_id=self._ctx.request_id
            )
            raise _Abort("handler_error") from None
        if idle.cancelled_caught:
            raise _Abort("idle_timeout")
        return item

    def _sign(self, digest: StreamDigest) -> str | None:
        ctx = self._ctx
        if ctx.signer is None:
            return None
        headers = sign_response(
            ctx.signer,
            request_nonce=ctx.caller.nonce_ns,
            sender_ss58=ctx.caller.hotkey_ss58,
            status=200,
            digest=digest.hexdigest(),
        )
        return headers[HEADER_SIGNATURE]

    def _aborted(self, reason: AbortReason) -> None:
        ctx = self._ctx
        ctx.state["tw_code"] = "stream_aborted"
        ctx.metrics.stream_aborted.labels(side="miner", reason=reason).inc()
        _log.warning(
            "stream_aborted",
            route=ctx.route,
            reason=reason,
            request_id=ctx.request_id,
            hint="ended without tw-end; the validator rejects the stream",
        )


async def _close(chunks: AsyncIterator[Any]) -> None:
    """Close the handler's generator (bounded, never raising)."""
    aclose = getattr(chunks, "aclose", None)
    if aclose is None:
        return
    with anyio.move_on_after(_CLOSE_S, shield=True), contextlib.suppress(Exception):
        await aclose()
