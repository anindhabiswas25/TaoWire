"""Controllable time for tests (spec 8.13).

One :class:`FakeClock` drives both kinds of time the kit reads:

- wall-clock nanoseconds (:meth:`FakeClock.now_ns`), used for btauth/1
  nonces and freshness: pass it to ``RequestVerifier(now_ns=...)`` and
  ``MonotonicNonce(clock_ns=...)``;
- monotonic seconds (:meth:`FakeClock.monotonic`), used for snapshot ages,
  rate limits and nonce-store expiry.

Time only moves when the test says so.
"""

from __future__ import annotations

import time

__all__ = ["FakeClock"]


class FakeClock:
    """Frozen time that moves with :meth:`advance`.

    ``start_ns`` defaults to the real wall clock at construction, so
    signatures made with it look current to anything outside the test.
    """

    def __init__(
        self, start_ns: int | None = None, *, monotonic_start: float = 1_000.0
    ) -> None:
        self._wall_ns = time.time_ns() if start_ns is None else start_ns
        self._mono = monotonic_start

    def now_ns(self) -> int:
        """Wall-clock time in nanoseconds since the Unix epoch."""
        return self._wall_ns

    def time(self) -> float:
        """Wall-clock time in seconds since the Unix epoch."""
        return self._wall_ns / 1e9

    def monotonic(self) -> float:
        """Monotonic time in seconds."""
        return self._mono

    def advance(self, seconds: float) -> None:
        """Move both clocks forward by ``seconds``."""
        if seconds < 0:
            raise ValueError(
                "time only moves forward; use step_wall() for a clock step"
            )
        self._wall_ns += round(seconds * 1e9)
        self._mono += seconds

    def step_wall(self, seconds: float) -> None:
        """Step only the wall clock (by ``seconds``, may be negative), as NTP would."""
        self._wall_ns += round(seconds * 1e9)
