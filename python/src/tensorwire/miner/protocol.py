"""The miner's HTTP/1.1 protocol: h11 with a request-read deadline (spec 8.6.1, 13.6).

uvicorn's own protocols time out idle keep-alive connections only *after* a
response; a client that connects and sends nothing, or sends a request one
byte at a time (slowloris), holds its connection forever, and at
``limit_concurrency`` connections every new request gets 503. This protocol
closes a connection whose next request has not fully arrived (headers and
body) within ``read_timeout_s`` of its first byte, or of the connection
opening. Once a request is fully received the deadline is off: the
handler timeout and uvicorn's keep-alive timeout take over.

The miner sets ``read_timeout_s`` to ``TW_AUTH_MAX_AGE_S +
TW_AUTH_ALLOWED_SKEW_S``: a request that takes longer to arrive would be
refused as stale anyway.

h11 (not httptools) is used on purpose: the header size limit
(``h11_max_incomplete_event_size``, 16 KiB) only exists for h11.
"""

from __future__ import annotations

import asyncio
import functools
from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol

__all__ = ["GuardedH11Protocol", "guarded_protocol"]


class GuardedH11Protocol(H11Protocol):
    """``H11Protocol`` plus a deadline for receiving each request."""

    def __init__(self, *args: Any, read_timeout_s: float, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if read_timeout_s <= 0:
            raise ValueError("read_timeout_s must be > 0")
        self.read_timeout_s = read_timeout_s
        self._read_deadline: asyncio.TimerHandle | None = None

    def _arm(self) -> None:
        self._disarm()
        self._read_deadline = self.loop.call_later(
            self.read_timeout_s, self._read_timed_out
        )

    def _disarm(self) -> None:
        if self._read_deadline is not None:
            self._read_deadline.cancel()
            self._read_deadline = None

    def _between_requests(self) -> bool:
        return self.cycle is None or self.cycle.response_complete

    def _request_received(self) -> bool:
        return self.cycle is not None and not self.cycle.more_body

    def _read_timed_out(self) -> None:
        self._read_deadline = None
        if not self.transport.is_closing():
            self.transport.close()

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        self._arm()  # a connection that never sends a request is closed too

    def data_received(self, data: bytes) -> None:
        if self._read_deadline is None and self._between_requests():
            self._arm()  # first byte of the next request on a kept-alive connection
        super().data_received(data)
        if self._request_received() and not self._between_requests():
            self._disarm()

    def connection_lost(self, exc: Exception | None) -> None:
        self._disarm()
        super().connection_lost(exc)


def guarded_protocol(read_timeout_s: float) -> Any:
    """The ``http=`` value for uvicorn (a picklable factory, so workers get it too)."""
    return functools.partial(GuardedH11Protocol, read_timeout_s=read_timeout_s)
