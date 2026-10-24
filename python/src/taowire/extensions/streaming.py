"""Streaming responses over SSE with a signed trailer (spec 9.2, D29).

A streaming route answers ``200 text/event-stream``. The ``X-TW-Resp-Version``,
``X-TW-Resp-Hotkey`` (and ``X-TW-Resp-Crypto``) headers of ``twresp/1`` are
sent at stream start; the signature comes last::

    event: chunk
    data: {"token": "Hel"}

    event: chunk
    data: {"token": "lo"}

    event: tw-end
    data: {"digest": "<sha256 hex>", "count": 2, "signature": "0x..."}

``digest`` is sha256 over the concatenation of every chunk's exact ``data``
bytes, in order. The ``tw-end`` signature is the ``twresp/1`` payload with
status ``200`` and the body-hash line set to ``digest``.

**Chunks are JSON objects or arrays.** A plain concatenation does not say
where one chunk ends: the chunks ``1``, ``23`` and ``12``, ``3`` have the same
digest and count. Objects and arrays are self-delimiting (no proper prefix of
one is a complete one), so with them only one split of the signed bytes is
possible and a relay cannot move chunk boundaries under a valid signature.
The miner refuses to emit anything else; the validator rejects anything else.

**Depth and trailer form (D43).** A chunk nests at most :data:`MAX_CHUNK_DEPTH`
(128) levels, arrays and objects counted together. In ``tw-end``, ``count`` is
a plain non-negative integer literal that fits a u64 (no ``-0``, fraction or
exponent) and no string holds a lone UTF-16 surrogate escape. Go, Rust and
TypeScript apply the same rules.

This module holds what both sides share: the SSE parser (it reads untrusted
bytes), framing, the digest, chunk and trailer encoding, and the limits. The
miner side is ``taowire.miner.streaming``; the validator side is
``ValidatorClient.stream`` / ``query_stream``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import AsyncIterable, Iterator
from dataclasses import dataclass
from typing import Any, Final

from pydantic import BaseModel

from taowire.config import (
    STREAM_IDLE_S_RANGE,
    STREAM_MAX_BYTES_RANGE,
    STREAM_MAX_S_RANGE,
    CommonSettings,
)

__all__ = [
    "CONTENT_TYPE",
    "EVENT_CHUNK",
    "EVENT_END",
    "IDLE_S_RANGE",
    "MAX_BYTES_RANGE",
    "MAX_CHUNK_DEPTH",
    "MAX_S_RANGE",
    "TRAILER_RESERVE",
    "ChunkError",
    "SSEEvent",
    "SSEParser",
    "StreamDigest",
    "StreamLimits",
    "StreamingReply",
    "Trailer",
    "TrailerError",
    "decode_chunk",
    "encode_chunk",
    "encode_event",
    "encode_trailer",
    "parse_trailer",
]

CONTENT_TYPE: Final = "text/event-stream"
EVENT_CHUNK: Final = "chunk"
EVENT_END: Final = "tw-end"

#: Allowed ranges (spec 12.1), defined once in ``taowire.config``.
MAX_S_RANGE: Final = STREAM_MAX_S_RANGE
MAX_BYTES_RANGE: Final = STREAM_MAX_BYTES_RANGE
IDLE_S_RANGE: Final = STREAM_IDLE_S_RANGE

_LINE_END = re.compile(rb"\r\n|\r|\n")
_BOM: Final = b"\xef\xbb\xbf"
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
_TRAILER_KEYS = frozenset({"digest", "count", "signature"})
_U64_MAX: Final = 2**64 - 1

#: Deepest nesting a chunk may have (D43): ``[]`` is 1, ``[[]]`` is 2.
MAX_CHUNK_DEPTH: Final = 128


class ChunkError(ValueError):
    """A chunk is not a JSON object or array (or not valid JSON at all)."""


class TrailerError(ValueError):
    """The ``tw-end`` data is not a well-formed trailer."""


@dataclass(frozen=True, slots=True)
class StreamLimits:
    """Per-stream limits (spec 9.2): both the miner and the validator enforce them.

    ``max_s``: the whole stream; ``max_bytes``: bytes on the wire;
    ``idle_s``: the longest gap between two events.
    """

    max_s: float = 60.0
    max_bytes: int = 4 * 1024 * 1024
    idle_s: float = 10.0

    def __post_init__(self) -> None:
        for name, value, (low, high) in (
            ("max_s", self.max_s, MAX_S_RANGE),
            ("max_bytes", self.max_bytes, MAX_BYTES_RANGE),
            ("idle_s", self.idle_s, IDLE_S_RANGE),
        ):
            if isinstance(value, bool) or not (
                isinstance(value, (int, float)) and math.isfinite(value)
            ):
                raise ValueError(f"{name} must be a number")
            if not low <= value <= high:
                raise ValueError(f"{name} must be between {low:g} and {high:g}")
        if not isinstance(self.max_bytes, int):
            raise ValueError("max_bytes must be an integer")

    @classmethod
    def from_settings(cls, settings: CommonSettings) -> StreamLimits:
        """``TW_STREAM_MAX_S`` / ``_MAX_BYTES`` / ``_IDLE_S``."""
        return cls(
            max_s=settings.stream_max_s,
            max_bytes=settings.stream_max_bytes,
            idle_s=settings.stream_idle_s,
        )

    def override(
        self,
        *,
        max_s: float | None = None,
        max_bytes: int | None = None,
        idle_s: float | None = None,
    ) -> StreamLimits:
        """A copy with the given limits replaced (per route or per call)."""
        return StreamLimits(
            max_s=self.max_s if max_s is None else max_s,
            max_bytes=self.max_bytes if max_bytes is None else max_bytes,
            idle_s=self.idle_s if idle_s is None else idle_s,
        )


@dataclass(frozen=True, slots=True)
class StreamingReply:
    """What a streaming handler returns (spec 8.7.1): an async iterable of chunks.

    Each chunk is a ``BaseModel``, a ``dict`` / ``list``, or ``bytes`` holding a
    JSON object or array. A handler may also return the async iterable itself.
    """

    chunks: AsyncIterable[Any]


# ---------------------------------------------------------------- chunks


def _reject_constant(name: str) -> Any:
    raise ChunkError(f"{name} is not valid JSON")


def _too_deep(value: Any) -> bool:
    """True if ``value`` nests deeper than :data:`MAX_CHUNK_DEPTH`.

    Iterative, and stops at the first level past the limit, so neither a deep
    nor a self-referencing value can exhaust the stack or loop.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if not isinstance(item, (dict, list)):
            continue
        if depth > MAX_CHUNK_DEPTH:
            return True
        stack.extend((child, depth + 1) for child in _children(item))
    return False


def _children(item: dict[Any, Any] | list[Any]) -> Any:
    return item.values() if isinstance(item, dict) else item


def encode_chunk(item: Any) -> bytes:
    """The ``data`` bytes of one chunk (miner side). Raises :class:`ChunkError`.

    Models and plain values are written as compact JSON (no NaN / infinity);
    ``bytes`` are checked and sent as they are. Nothing deeper than
    :data:`MAX_CHUNK_DEPTH` is emitted (D43).
    """
    if isinstance(item, BaseModel):
        data = item.model_dump_json().encode()
        decode_chunk(data)
    elif isinstance(item, (dict, list)):
        if _too_deep(item):
            raise ChunkError("chunk is nested too deeply")
        try:
            text = json.dumps(
                item, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError):
            raise ChunkError("chunk is not JSON-serialisable") from None
        data = text.encode()
    elif isinstance(item, (bytes, bytearray, memoryview)):
        data = bytes(item)
        decode_chunk(data)
    else:
        raise ChunkError(f"chunk of type {type(item).__name__} is not supported")
    if b"\n" in data or b"\r" in data:
        raise ChunkError("chunk contains a line break")
    return data


def decode_chunk(data: bytes) -> Any:
    """Parse one chunk's ``data`` (validator side): a JSON object or array.

    Raises :class:`ChunkError` for invalid UTF-8, invalid JSON, NaN /
    infinity, nesting deeper than :data:`MAX_CHUNK_DEPTH`, or any other
    top-level value.
    """
    try:
        value = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ChunkError("chunk is not valid JSON") from None
    if not isinstance(value, (dict, list)):
        raise ChunkError("chunk must be a JSON object or array")
    if _too_deep(value):
        raise ChunkError("chunk is nested too deeply")
    return value


class StreamDigest:
    """Running sha256 over the chunks' ``data`` bytes, and their count."""

    def __init__(self) -> None:
        self._hash = hashlib.sha256()
        self.count = 0

    def update(self, data: bytes) -> None:
        """Add one chunk's exact ``data`` bytes."""
        self._hash.update(data)
        self.count += 1

    def hexdigest(self) -> str:
        """The digest so far, lowercase hex."""
        return self._hash.hexdigest()


# ---------------------------------------------------------------- trailer


@dataclass(frozen=True, slots=True)
class Trailer:
    """The ``tw-end`` event's data."""

    digest: str
    count: int
    signature: str | None
    """``0x`` + hex; ``None`` when the miner does not sign responses."""


def encode_trailer(trailer: Trailer) -> bytes:
    """The ``tw-end`` data bytes (compact JSON)."""
    body: dict[str, Any] = {"digest": trailer.digest, "count": trailer.count}
    if trailer.signature is not None:
        body["signature"] = trailer.signature
    return json.dumps(body, separators=(",", ":")).encode()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        for text in (key, value):
            if isinstance(text, str) and _lone_surrogate(text):
                raise TrailerError("tw-end holds a lone surrogate escape")
        if key in out:
            raise TrailerError(f"duplicate key {key!r} in tw-end")
        out[key] = value
    return out


def _lone_surrogate(text: str) -> bool:
    # json.loads joins a valid escaped pair into one code point, so any
    # surrogate code point left over came from a lone escape.
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


def _plain_count(literal: str) -> int:
    # The trailer's only number is ``count``: no sign, so no ``-0``.
    if literal.startswith("-"):
        raise TrailerError("tw-end count must be an integer >= 0")
    # 20 digits hold any u64; the bound also keeps int() away from very
    # long literals (CPython refuses more than 4,300 digits with ValueError).
    if len(literal) > len(str(_U64_MAX)) or int(literal) > _U64_MAX:
        raise TrailerError("tw-end count is out of range")
    return int(literal)


def _no_float(_literal: str) -> Any:
    raise TrailerError("tw-end count must be an integer >= 0")


def parse_trailer(data: bytes) -> Trailer:
    """Parse ``tw-end`` data strictly. Raises :class:`TrailerError`.

    It must be a JSON object with ``digest`` (64 lowercase hex), ``count``
    (an integer literal >= 0 that fits a u64: no sign, fraction or exponent)
    and optionally ``signature`` (a string), nothing else, with no key twice
    and no lone surrogate escape in any string (D43).
    """
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
            parse_int=_plain_count,
            parse_float=_no_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ChunkError, RecursionError):
        raise TrailerError("tw-end data is not valid JSON") from None
    if not isinstance(value, dict):
        raise TrailerError("tw-end data must be a JSON object")
    if not set(value) <= _TRAILER_KEYS or not {"digest", "count"} <= set(value):
        raise TrailerError("tw-end needs digest and count, and nothing but signature")
    digest, count = value["digest"], value["count"]
    signature = value.get("signature")
    if not isinstance(digest, str) or not _HEX_DIGEST.fullmatch(digest):
        raise TrailerError("tw-end digest must be 64 lowercase hex characters")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise TrailerError("tw-end count must be an integer >= 0")
    if "signature" in value and not isinstance(signature, str):
        raise TrailerError("tw-end signature must be a string")
    return Trailer(digest=digest, count=count, signature=signature)


# ---------------------------------------------------------------- SSE


def encode_event(event: str, data: bytes) -> bytes:
    """One SSE frame: ``event: <event>``, one ``data:`` line, a blank line."""
    if "\n" in event or "\r" in event or b"\n" in data or b"\r" in data:
        raise ValueError("SSE event names and data must not contain line breaks")
    return b"event: " + event.encode() + b"\ndata: " + data + b"\n\n"


@dataclass(frozen=True, slots=True)
class SSEEvent:
    """One dispatched event: its type and its data bytes (lines joined by LF)."""

    event: str
    data: bytes


class SSEParser:
    """Incremental SSE parser over raw bytes (WHATWG "event stream" rules).

    Lines end with CRLF, LF or CR. A line starting with ``:`` is a comment.
    Otherwise ``field[: value]`` (one leading space of the value removed); a
    line with no colon is a field with an empty value. ``data`` lines are
    joined with LF; ``event`` sets the type (default ``message``); ``id``,
    ``retry`` and unknown fields are ignored. A blank line dispatches the
    event if it has data. A UTF-8 BOM at the very start is skipped. Data stays
    bytes, so the digest covers exactly what was sent.

    :meth:`feed` never raises, whatever the input; an incomplete event at the
    end of the stream is dropped by :meth:`finish`.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._scanned = 0  # no line end before this offset of the buffer
        self._started = False
        self._event: str | None = None
        self._data: list[bytes] = []
        self._has_data = False

    def feed(self, chunk: bytes) -> list[SSEEvent]:
        """Add bytes; return the events completed by them, in order."""
        self._buffer += chunk
        if not self._started:
            if len(self._buffer) < len(_BOM) and _BOM.startswith(bytes(self._buffer)):
                return []
            if self._buffer.startswith(_BOM):
                del self._buffer[: len(_BOM)]
            self._started = True
        return list(self._lines(final=False))

    def finish(self) -> list[SSEEvent]:
        """End of stream: a final CR ends its line; an unfinished event is dropped."""
        events = list(self._lines(final=True))
        self._buffer.clear()
        self._scanned = 0
        self._reset()
        return events

    def _lines(self, *, final: bool) -> Iterator[SSEEvent]:
        buffer = self._buffer
        start = 0
        for match in _LINE_END.finditer(buffer, self._scanned):
            if match.group() == b"\r" and match.end() == len(buffer) and not final:
                break  # may be the first half of a CRLF split across feeds
            event = self._line(bytes(buffer[start : match.start()]))
            start = match.end()
            if event is not None:
                yield event
        del buffer[:start]
        # Scan only new bytes next time (a long line arriving in small pieces
        # stays linear); a trailing CR is looked at again.
        self._scanned = len(buffer) - 1 if buffer.endswith(b"\r") else len(buffer)

    def _line(self, line: bytes) -> SSEEvent | None:
        if not line:
            return self._dispatch()
        if line.startswith(b":"):
            return None
        name, colon, value = line.partition(b":")
        if colon and value.startswith(b" "):
            value = value[1:]
        if name == b"data":
            self._data.append(value)
            self._has_data = True
        elif name == b"event":
            self._event = value.decode("utf-8", errors="replace")
        return None

    def _dispatch(self) -> SSEEvent | None:
        if not self._has_data:
            self._reset()
            return None
        event = SSEEvent(self._event or "message", b"\n".join(self._data))
        self._reset()
        return event

    def _reset(self) -> None:
        self._event = None
        self._data = []
        self._has_data = False


#: Bytes the miner keeps free under ``max_bytes`` for the ``tw-end`` frame:
#: the largest possible one (a 20-digit count, a 64-byte signature), so a
#: stream the miner finishes always fits a validator using the same limit.
TRAILER_RESERVE: Final = len(
    encode_event(
        EVENT_END,
        encode_trailer(
            Trailer(digest="0" * 64, count=2**64 - 1, signature="0x" + "0" * 128)
        ),
    )
)
