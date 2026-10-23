"""Clock guard: is the local wall clock close enough to NTP? (spec 8.4.4)

btauth/1 freshness compares the request nonce with the receiver's wall
clock, so a drifting clock turns every request into ``tw.auth_stale``. The
guard measures the offset at startup and every 10 minutes:

- ``|offset| > 0.5 s``: WARNING, and ``tw_clock_offset_seconds`` shows it.
- ``|offset| > allowed_skew``: ERROR. The miner keeps serving (refusing would
  only make things worse) but ``/readyz`` reports ``clock_skew``.
- No NTP server answers, or ``ntplib`` is not installed: the offset is
  "unknown". That never fails anything.

:class:`ClockStepGuard` watches for **backwards wall-clock steps** (spec
8.4.3-8.4.4, D21). Freshness is judged on the wall clock, so after a step
back a nonce the replay store has already forgotten could look fresh again.
A step larger than the store's margin opens a fail-closed window of
``retention`` seconds (503 ``tw.replay_store_unavailable``, ``/readyz``
``clock_step``) instead of reopening nonces.
"""

from __future__ import annotations

import enum
import math
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import anyio
import anyio.to_thread
import structlog

__all__ = [
    "CHECK_INTERVAL_S",
    "WARN_OFFSET_S",
    "ClockGuard",
    "ClockReading",
    "ClockStatus",
    "ClockStepGuard",
    "NtpQuery",
    "ntplib_query",
]

#: Seconds between two checks.
CHECK_INTERVAL_S = 600.0
#: Offsets above this are logged as a warning.
WARN_OFFSET_S = 0.5

NtpQuery = Callable[[str, float], float]
"""``query(server, timeout_s) -> offset_s``; raises ``OSError`` (or ``ntplib``'s
error) when the server does not answer."""

_log = structlog.stdlib.get_logger(__name__)


class ClockStatus(enum.Enum):
    """Outcome of one clock check."""

    OK = "ok"
    WARN = "warn"
    SKEWED = "skewed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ClockReading:
    """One measurement. ``offset_s`` is ``None`` when it is unknown."""

    status: ClockStatus
    offset_s: float | None = None
    server: str | None = None


def ntplib_query() -> NtpQuery | None:
    """An NTP query using the optional ``ntplib`` package, or ``None``."""
    try:
        import ntplib  # noqa: PLC0415 - optional extra (tensorwire[ntp])
    except ImportError:
        return None
    client = ntplib.NTPClient()

    def query(server: str, timeout_s: float) -> float:
        return float(client.request(server, version=3, timeout=timeout_s).offset)

    return query


class ClockGuard:
    """Measures the wall-clock offset against ``servers`` (first answer wins).

    ``query`` defaults to :func:`ntplib_query`; pass a function for tests.
    An empty ``servers`` list disables the check (status stays unknown).
    ``on_reading`` runs after each check (the miner updates its gauge there).
    """

    def __init__(
        self,
        servers: Sequence[str],
        *,
        allowed_skew_s: float,
        query: NtpQuery | None = None,
        timeout_s: float = 2.0,
        on_reading: Callable[[ClockReading], None] | None = None,
    ) -> None:
        if not math.isfinite(allowed_skew_s) or allowed_skew_s <= 0:
            raise ValueError("allowed_skew_s must be a positive number of seconds")
        self._servers = tuple(servers)
        self._skew = allowed_skew_s
        self._query = ntplib_query() if query is None else query
        self._timeout = timeout_s
        self._on_reading = on_reading
        self._last = ClockReading(ClockStatus.UNKNOWN)

    @property
    def last(self) -> ClockReading:
        """The latest reading (unknown before the first check)."""
        return self._last

    @property
    def skewed(self) -> bool:
        """Whether the latest known offset is beyond the allowed skew."""
        return self._last.status is ClockStatus.SKEWED

    def classify(self, offset_s: float) -> ClockStatus:
        """The status for a measured offset."""
        magnitude = abs(offset_s)
        if magnitude > self._skew:
            return ClockStatus.SKEWED
        if magnitude > WARN_OFFSET_S:
            return ClockStatus.WARN
        return ClockStatus.OK

    def check(self) -> ClockReading:
        """Measure now (blocking network I/O). Never raises for NTP failures."""
        reading = ClockReading(ClockStatus.UNKNOWN)
        if self._query is not None:
            for server in self._servers:
                try:
                    offset = self._query(server, self._timeout)
                except Exception as exc:  # noqa: BLE001 - ntplib raises its own types; any failure = try the next server
                    _log.debug(
                        "ntp_query_failed", server=server, error=type(exc).__name__
                    )
                    continue
                if math.isfinite(offset):
                    reading = ClockReading(self.classify(offset), offset, server)
                    break
        self._record(reading)
        return reading

    async def check_async(self) -> ClockReading:
        """:meth:`check` in a worker thread."""
        return await anyio.to_thread.run_sync(self.check)

    async def run(self, interval_s: float = CHECK_INTERVAL_S) -> None:
        """Check every ``interval_s`` seconds until cancelled.

        A check that fails unexpectedly is logged and the schedule goes on:
        the guard must not stop watching the clock because of one bad reading.
        """
        while True:
            await anyio.sleep(interval_s)
            try:
                await self.check_async()
            except Exception:  # noqa: BLE001 - keep the schedule alive
                _log.exception("clock_check_failed")

    def _record(self, reading: ClockReading) -> None:
        self._last = reading
        if reading.status is ClockStatus.SKEWED:
            _log.error(
                "clock_skew",
                offset_s=reading.offset_s,
                allowed_skew_s=self._skew,
                server=reading.server,
                hint="requests will fail as tw.auth_stale; fix time sync (chrony)",
            )
        elif reading.status is ClockStatus.WARN:
            _log.warning(
                "clock_offset", offset_s=reading.offset_s, server=reading.server
            )
        elif reading.status is ClockStatus.UNKNOWN and self._servers:
            _log.info("clock_offset_unknown", servers=list(self._servers))
        if self._on_reading is not None:
            self._on_reading(reading)


class ClockStepGuard:
    """Detects backwards wall-clock steps and fails closed after one (D21).

    Each :meth:`check` compares ``wall - monotonic`` with its previous value.
    When it dropped by more than ``margin_s`` (the replay store's margin,
    ``retention - (max_age + allowed_skew)``), the guard logs
    ``clock_step_detected`` at ERROR and stays :attr:`failing_closed` for
    ``hold_s`` seconds (the store's ``retention``) on the monotonic clock: by
    then every nonce that could look fresh again has expired from freshness.
    A forward step, or a smaller backwards one, only moves the baseline.

    ``wall_ns`` and ``monotonic`` are injectable for tests. ``on_step``
    receives the size of each detected step in seconds (the miner sets
    ``tw_clock_step_seconds`` there). Thread-safe: the request path calls
    :meth:`check` from verification threads.
    """

    def __init__(
        self,
        *,
        margin_s: float,
        hold_s: float,
        wall_ns: Callable[[], int] = time.time_ns,
        monotonic: Callable[[], float] = time.monotonic,
        on_step: Callable[[float], None] | None = None,
    ) -> None:
        for name, value in (("margin_s", margin_s), ("hold_s", hold_s)):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a positive number of seconds")
        self._margin = float(margin_s)
        self._hold = float(hold_s)
        self._wall_ns = wall_ns
        self._monotonic = monotonic
        self._on_step = on_step
        self._lock = threading.Lock()
        self._until: float | None = None
        self._last_step_s = 0.0
        self._offset = self._read()[0]

    @property
    def margin_s(self) -> float:
        """A backwards step larger than this opens the fail-closed window."""
        return self._margin

    @property
    def last_step_s(self) -> float:
        """Size of the last detected backwards step (0 before the first)."""
        return self._last_step_s

    def _read(self) -> tuple[float, float]:
        mono = self._monotonic()
        return self._wall_ns() / 1e9 - mono, mono

    def check(self) -> bool:
        """Measure now; return whether the guard is failing closed."""
        with self._lock:
            offset, mono = self._read()
            step = self._offset - offset
            self._offset = offset
            if step > self._margin:
                self._until = mono + self._hold
                self._last_step_s = step
                detected = True
            else:
                detected = False
            closed = self._until is not None and mono < self._until
        if detected:
            _log.error(
                "clock_step_detected",
                step_s=round(step, 3),
                margin_s=self._margin,
                fail_closed_s=self._hold,
                hint="authenticated requests get 503 until the window ends",
            )
            if self._on_step is not None:
                self._on_step(step)
        return closed

    @property
    def failing_closed(self) -> bool:
        """Whether the fail-closed window is open (runs a :meth:`check`)."""
        return self.check()
