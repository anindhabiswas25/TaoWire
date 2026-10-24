"""The miner's HTTP/1.1 protocol: httptools with request limits (spec 8.6.1, 13.6).

uvicorn's protocols leave three gaps a public miner must close:

- **Slowloris.** Idle keep-alive connections time out only *after* a
  response; a client that connects and sends nothing, or sends a request
  one byte at a time, holds its connection forever, and at
  ``limit_concurrency`` connections every new request gets 503. This
  protocol closes a connection whose request has not fully arrived
  (request line, headers and body) within ``read_timeout_s`` of its first
  byte, or of the connection opening.
- **Header size.** httptools has no limit, and h11's
  ``h11_max_incomplete_event_size`` only applies while a request head is
  still incomplete: a 64 KiB header that arrives in one read passes. Here
  the request line plus headers may hold at most ``max_header_bytes`` and
  ``max_headers`` fields, counted as they are parsed, and a head that is
  still incomplete after that many bytes is refused too. The answer is
  uvicorn's ``400 Invalid HTTP request received.``, and the connection
  closes.
- **Speed.** A flood is answered by this protocol and the per-IP limiter;
  httptools (C) parses a request in a fraction of h11's time.

The miner sets ``read_timeout_s`` to ``TW_AUTH_MAX_AGE_S +
TW_AUTH_ALLOWED_SKEW_S``: a request that takes longer to arrive would be
refused as stale anyway.
"""

from __future__ import annotations

import asyncio
import functools
from typing import Any

from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

__all__ = [
    "MAX_HEADERS",
    "MAX_HEADER_BYTES",
    "GuardedHttpToolsProtocol",
    "guarded_protocol",
]

#: Request line plus header bytes (names, values and separators), spec 8.6.1.
MAX_HEADER_BYTES = 16 * 1024
#: Header fields per request.
MAX_HEADERS = 100


class _HeadTooLarge(Exception):
    """Raised in a parser callback; httptools turns it into a parse error (400)."""


class GuardedHttpToolsProtocol(HttpToolsProtocol):
    """``HttpToolsProtocol`` plus a request-read deadline and header limits."""

    def __init__(
        self,
        *args: Any,
        read_timeout_s: float,
        max_header_bytes: int = MAX_HEADER_BYTES,
        max_headers: int = MAX_HEADERS,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        if read_timeout_s <= 0 or max_header_bytes < 1 or max_headers < 1:
            raise ValueError("read_timeout_s and the header limits must be > 0")
        self.read_timeout_s = read_timeout_s
        self.max_header_bytes = max_header_bytes
        self.max_headers = max_headers
        self._read_deadline: asyncio.TimerHandle | None = None
        self._in_head = False
        self._head_bytes = 0  # parsed: request line and complete headers
        self._raw_head_bytes = 0  # received while the head is incomplete
        self._header_count = 0

    # ------------------------------------------------------------ deadline

    def _arm(self) -> None:
        if self._read_deadline is None:
            self._read_deadline = self.loop.call_later(
                self.read_timeout_s, self._read_timed_out
            )

    def _disarm(self) -> None:
        if self._read_deadline is not None:
            self._read_deadline.cancel()
            self._read_deadline = None

    def _read_timed_out(self) -> None:
        self._read_deadline = None
        if not self.transport.is_closing():
            self.transport.close()

    # ------------------------------------------------------------ connection

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        self._arm()  # a connection that never sends a request is closed too

    def connection_lost(self, exc: Exception | None) -> None:
        self._disarm()
        super().connection_lost(exc)

    def data_received(self, data: bytes) -> None:
        was_in_head = self._in_head
        super().data_received(data)
        if was_in_head and self._in_head and not self.transport.is_closing():
            # The whole read belongs to a head that is still incomplete (a
            # header value httptools is still buffering): bound it. A read
            # in which a request starts is not counted, so the bound is one
            # read plus max_header_bytes.
            self._raw_head_bytes += len(data)
            if self._raw_head_bytes > self.max_header_bytes:
                self._refuse_head()

    def _refuse_head(self) -> None:
        msg = "Invalid HTTP request received."
        self.logger.warning(msg)
        self.send_400_response(msg)

    # ------------------------------------------------------------ parser callbacks

    def on_message_begin(self) -> None:
        super().on_message_begin()
        self._in_head = True
        self._head_bytes = self._raw_head_bytes = self._header_count = 0
        self._arm()

    def on_url(self, url: bytes) -> None:
        self._count(len(url))
        super().on_url(url)

    def on_header(self, name: bytes, value: bytes) -> None:
        self._header_count += 1
        if self._header_count > self.max_headers:
            raise _HeadTooLarge
        self._count(len(name) + len(value) + 4)  # ": " and CRLF
        super().on_header(name, value)

    def on_headers_complete(self) -> None:
        self._in_head = False
        super().on_headers_complete()

    def on_message_complete(self) -> None:
        super().on_message_complete()
        self._disarm()

    def _count(self, n: int) -> None:
        self._head_bytes += n
        if self._head_bytes > self.max_header_bytes:
            raise _HeadTooLarge


def guarded_protocol(read_timeout_s: float) -> Any:
    """The ``http=`` value for uvicorn (a picklable factory, so workers get it too)."""
    return functools.partial(GuardedHttpToolsProtocol, read_timeout_s=read_timeout_s)
