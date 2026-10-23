"""Reading one miner's SSE stream on the validator (spec 9.2, D29).

:class:`StreamReader` consumes a ``200 text/event-stream`` answer that has
already started and applies every rule of 9.2:

- limits: the stream ends by its deadline (the query's time budget or
  ``max_s``, whichever comes first, ``tw.timeout``); at most ``idle_s``
  between two complete events, so a one-byte-per-period drip is cut
  (``tw.timeout``); at most ``max_bytes`` on the wire
  (``tw.response_too_large``); after ``tw-end`` the body must end within
  ``idle_s``;
- every chunk is a JSON object or array (and fits ``chunk_model``), else
  ``tw.invalid_response``;
- ``tw.bad_response_signature`` for the whole stream when ``tw-end`` is
  missing, malformed, repeated or followed by another event, when ``count``
  or ``digest`` do not match what arrived, or (with verification on) when the
  ``X-TW-Resp-*`` start headers are missing or the trailer signature does
  not verify for this request (responder, nonce and sender bound as in 9.1);
- unknown events and SSE comments are ignored and are not part of the digest.

Chunks are handed out as they arrive as :class:`UnverifiedChunk`: **nothing
in them is trustworthy until the stream's result says
``response_verified=True``**. Score from the final result only.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import anyio
import httpx
from pydantic import BaseModel, ValidationError

from tensorwire.extensions.response_sig import (
    HEADER_HOTKEY,
    HEADER_SIGNATURE,
    HEADER_VERSION,
    VERSION,
    ResponseSignatureError,
    verify_response,
)
from tensorwire.extensions.streaming import (
    CONTENT_TYPE,
    EVENT_CHUNK,
    EVENT_END,
    ChunkError,
    SSEEvent,
    SSEParser,
    StreamDigest,
    StreamLimits,
    Trailer,
    TrailerError,
    decode_chunk,
    parse_trailer,
)

__all__ = ["StreamFailure", "StreamReader", "UnverifiedChunk", "is_event_stream"]


@dataclass(frozen=True, slots=True)
class UnverifiedChunk:
    """One chunk as it arrived. **Not verified**: wait for the stream's result."""

    index: int
    data: Any
    """The ``chunk_model`` instance, or the parsed JSON object / array."""
    raw: bytes
    """The chunk's exact ``data`` bytes (what the digest covers)."""
    verified: bool = False
    """Always ``False``: only the final ``MinerResult`` can be trusted."""


class StreamFailure(Exception):
    """The stream is rejected as a whole; ``code`` is the ``tw.*`` result code."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason

    @property
    def metric_reason(self) -> str:
        """The ``reason`` label of ``tw_stream_aborted_total{side="validator"}``."""
        return _METRIC_REASON.get(self.code, "transport")


_METRIC_REASON = {
    "tw.timeout": "timeout",
    "tw.response_too_large": "too_large",
    "tw.bad_response_signature": "bad_trailer",
    "tw.invalid_response": "bad_chunk",
}


def is_event_stream(headers: httpx.Headers) -> bool:
    """Whether the answer is declared ``text/event-stream``."""
    media: str = headers.get("content-type", "")
    return media.split(";", 1)[0].strip().lower() == CONTENT_TYPE


class StreamReader:
    """Reads and checks one started stream; see the module docstring."""

    def __init__(
        self,
        response: httpx.Response,
        *,
        limits: StreamLimits,
        deadline: float,
        monotonic: Callable[[], float],
        chunk_model: type[BaseModel] | None,
        verify: bool,
        expected_responder: str,
        request_nonce: int,
        sender_ss58: str,
    ) -> None:
        self._response = response
        self._limits = limits
        self._deadline = deadline
        self._monotonic = monotonic
        self._chunk_model = chunk_model
        self._verify = verify
        self._responder = expected_responder
        self._nonce = request_nonce
        self._sender = sender_ss58
        self._digest = StreamDigest()
        self._trailer: Trailer | None = None
        self.values: list[Any] = []
        """The chunk values, in order (complete once :meth:`chunks` ends)."""

    async def chunks(self) -> AsyncGenerator[UnverifiedChunk, None]:
        """Yield chunks as they arrive; raise :class:`StreamFailure` on any rule.

        When the iteration ends without an exception, the trailer matched and
        (with verification on) its signature verified.
        """
        self._check_start()
        parser = SSEParser()
        received = 0
        idle_from = self._monotonic()
        raw = self._response.aiter_raw()
        while True:
            piece = await self._read(raw, idle_from)
            if piece is None:
                events = parser.finish()
            else:
                received += len(piece)
                if received > self._limits.max_bytes:
                    raise StreamFailure(
                        "tw.response_too_large", "stream over max_bytes"
                    )
                events = parser.feed(piece)
            for event in events:
                chunk = self._event(event)
                if chunk is not None:
                    yield chunk
                # The idle clock restarts after the caller's turn: the time the
                # caller spends on a chunk is not the miner's.
                idle_from = self._monotonic()
            if piece is None:
                break
        if self._trailer is None:
            raise StreamFailure(
                "tw.bad_response_signature", "stream ended without tw-end"
            )

    async def _read(self, raw: AsyncIterator[bytes], idle_from: float) -> bytes | None:
        now = self._monotonic()
        wait = min(self._deadline - now, idle_from + self._limits.idle_s - now)
        if wait <= 0:
            raise StreamFailure("tw.timeout", "stream limit reached")
        try:
            with anyio.fail_after(wait):
                return await anext(raw, None)
        except TimeoutError:
            raise StreamFailure("tw.timeout", "stream limit reached") from None
        except httpx.HTTPError:
            # Cut mid-stream (e.g. the miner aborted): no valid tw-end.
            raise StreamFailure(
                "tw.bad_response_signature", "stream broken before tw-end"
            ) from None

    def _check_start(self) -> None:
        headers = self._response.headers
        if headers.get("content-encoding"):
            raise StreamFailure("tw.invalid_response", "encoded event stream")
        if not self._verify:
            return
        if HEADER_SIGNATURE.lower() in headers:
            raise StreamFailure(
                "tw.bad_response_signature", "signature header at stream start"
            )
        if headers.get(HEADER_VERSION) != VERSION or headers.get(HEADER_HOTKEY) is None:
            raise StreamFailure(
                "tw.bad_response_signature", "X-TW-Resp-* missing at stream start"
            )

    def _event(self, event: SSEEvent) -> UnverifiedChunk | None:
        if self._trailer is not None:
            raise StreamFailure("tw.bad_response_signature", "event after tw-end")
        if event.event == EVENT_CHUNK:
            return self._chunk(event.data)
        if event.event == EVENT_END:
            self._end(event.data)
        return None  # unknown events are ignored

    def _chunk(self, data: bytes) -> UnverifiedChunk:
        try:
            value = decode_chunk(data)
        except ChunkError as exc:
            raise StreamFailure("tw.invalid_response", str(exc)) from None
        if self._chunk_model is not None:
            try:
                value = self._chunk_model.model_validate(value)
            except ValidationError:
                raise StreamFailure(
                    "tw.invalid_response", "chunk does not fit the chunk model"
                ) from None
        index = self._digest.count
        self._digest.update(data)
        self.values.append(value)
        return UnverifiedChunk(index=index, data=value, raw=data)

    def _end(self, data: bytes) -> None:
        try:
            trailer = parse_trailer(data)
        except TrailerError as exc:
            raise StreamFailure("tw.bad_response_signature", str(exc)) from None
        if trailer.count != self._digest.count:
            raise StreamFailure("tw.bad_response_signature", "chunk count mismatch")
        if trailer.digest != self._digest.hexdigest():
            raise StreamFailure("tw.bad_response_signature", "stream digest mismatch")
        if self._verify:
            self._verify_signature(trailer)
        self._trailer = trailer

    def _verify_signature(self, trailer: Trailer) -> None:
        if trailer.signature is None:
            raise StreamFailure("tw.bad_response_signature", "tw-end is not signed")
        headers = [
            *self._response.headers.multi_items(),
            (HEADER_SIGNATURE, trailer.signature),
        ]
        try:
            verify_response(
                headers,
                expected_responder=self._responder,
                request_nonce=self._nonce,
                sender_ss58=self._sender,
                status=200,
                digest=trailer.digest,
            )
        except ResponseSignatureError as exc:
            raise StreamFailure("tw.bad_response_signature", exc.reason) from None
