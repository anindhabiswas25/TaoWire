"""Replay-protection stores for btauth/1 (spec 8.4.3).

A store remembers accepted ``(hotkey, nonce)`` pairs for ``retention`` seconds.
``bittensor.http_auth.verify`` calls ``check_and_store`` only after the
signature verifies (fact A4), and synchronously (fact A1), so both stores here
are synchronous.

- :class:`MemoryNonceStore`: one process only.
- :class:`RedisNonceStore`: shared across processes and hosts. Required when
  more than one worker or instance serves the same hotkey.

Every store exposes ``retention`` so the verifier can refuse a store whose
memory is too short: at least **twice** the freshness window
``max_age + allowed_skew`` (fact A3, D21; :func:`check_retention_margin`).
The difference is the margin a backwards wall-clock step may use before
:class:`~taowire.auth.clock.ClockStepGuard` fails closed
(:class:`StepGuardedNonceStore`).
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from taowire.errors import ReplayStoreUnavailable

if TYPE_CHECKING:
    import redis

    from taowire.auth.clock import ClockStepGuard

__all__ = [
    "RETENTION_FACTOR",
    "MemoryNonceStore",
    "NonceStore",
    "RedisNonceStore",
    "StepGuardedNonceStore",
    "check_retention_margin",
]

#: A store must remember pairs for at least this many freshness windows (D21).
RETENTION_FACTOR = 2


@runtime_checkable
class NonceStore(Protocol):
    """``bittensor.http_auth.NonceStore`` plus the ``retention`` the kit requires."""

    @property
    def retention(self) -> float:
        """Seconds an accepted pair is remembered."""
        ...

    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        """True = never seen (and now recorded). False = replay."""
        ...


def _check_retention(retention: float) -> float:
    if not math.isfinite(retention) or retention <= 0:
        raise ValueError("retention must be a positive number of seconds")
    return float(retention)


def check_retention_margin(
    retention: float, max_age: float, allowed_skew: float
) -> float:
    """Return the store's margin, ``retention - (max_age + allowed_skew)``.

    Raises ``ValueError`` when ``retention < 2 x (max_age + allowed_skew)``
    (spec 8.4.3, D21): with less, a small backwards wall-clock step could
    reopen a nonce the store has already forgotten.
    """
    window = max_age + allowed_skew
    if not retention >= RETENTION_FACTOR * window:
        raise ValueError(
            "nonce store retention too short: it must be at least "
            f"{RETENTION_FACTOR} x (max_age + allowed_skew) = "
            f"{RETENTION_FACTOR * window:g} s"
        )
    return retention - window


class MemoryNonceStore:
    """Single-process store with time-based expiry.

    Same semantics as ``bittensor.http_auth.InMemoryNonceStore``, with
    injectable clocks for tests. Memory is bounded by the number of
    *verified* requests per retention window, because the verifier only
    stores after the signature checks out.

    A pair is forgotten only when ``retention`` has passed on the monotonic
    ``clock`` **and** its nonce is more than ``retention`` old on the wall
    clock (``wall_ns``), spec 8.4.3 / D21. Freshness is judged on the wall
    clock, so a backwards step (NTP) could otherwise make a forgotten nonce
    fresh again.
    """

    def __init__(
        self,
        retention: float = 60.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        self._retention = _check_retention(retention)
        self._retention_ns = int(self._retention * 1e9)
        self._clock = clock
        self._wall_ns = wall_ns
        self._seen: set[tuple[str, int]] = set()
        self._expiry: deque[tuple[float, tuple[str, int]]] = deque()
        self._lock = threading.Lock()

    @property
    def retention(self) -> float:
        """Seconds an accepted pair is remembered."""
        return self._retention

    def __len__(self) -> int:
        with self._lock:
            self._expire(self._clock())
            return len(self._seen)

    def _expire(self, now: float) -> None:
        wall = self._wall_ns()
        while (
            self._expiry
            and self._expiry[0][0] <= now
            and wall - self._expiry[0][1][1] > self._retention_ns
        ):
            self._seen.discard(self._expiry.popleft()[1])

    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        """True = never seen (and now recorded). False = replay."""
        key = (hotkey_ss58, nonce_ns)
        with self._lock:
            now = self._clock()
            self._expire(now)
            if key in self._seen:
                return False
            self._seen.add(key)
            self._expiry.append((now + self._retention, key))
            return True


class RedisNonceStore:
    """Store shared across processes and hosts, backed by Redis ``SET NX PX``.

    Uses a **sync** client (verify is synchronous, fact A1) with short socket
    timeouts. Any Redis failure raises :class:`ReplayStoreUnavailable` (503):
    the store fails closed and never falls back to memory.
    """

    def __init__(
        self,
        url: str,
        *,
        retention: float = 60.0,
        prefix: str = "tw:n:",
        client: redis.Redis | None = None,
    ) -> None:
        try:
            import redis  # noqa: PLC0415 - optional extra
        except ImportError:
            raise RuntimeError(
                "RedisNonceStore needs the redis extra: pip install 'taowire[redis]'"
            ) from None
        self._retention = _check_retention(retention)
        self._px = math.ceil(self._retention * 1000)
        self._prefix = prefix
        self._redis_error = redis.RedisError
        self._r = (
            redis.Redis.from_url(url, socket_timeout=0.25, socket_connect_timeout=0.5)
            if client is None
            else client
        )

    @property
    def retention(self) -> float:
        """Seconds an accepted pair is remembered."""
        return self._retention

    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        """True = never seen (and now recorded). False = replay.

        Raises :class:`ReplayStoreUnavailable` if Redis cannot be reached.
        """
        key = f"{self._prefix}{hotkey_ss58}:{nonce_ns}"
        try:
            return bool(self._r.set(key, b"1", nx=True, px=self._px))
        except self._redis_error as exc:
            raise ReplayStoreUnavailable() from exc

    def ping(self) -> bool:
        """Readiness probe: True when Redis answers."""
        try:
            return bool(self._r.ping())
        except self._redis_error:
            return False

    def close(self) -> None:
        """Close the connection pool."""
        self._r.close()


class StepGuardedNonceStore:
    """A store that fails closed while a :class:`ClockStepGuard` window is open.

    Every ``check_and_store`` first runs ``guard.check()``. During the
    window after a backwards wall-clock step it raises
    :class:`ReplayStoreUnavailable` (503) instead of consulting ``inner``:
    the store may have forgotten nonces that look fresh again (D21). The
    store is only consulted after the signature verifies, so only
    authenticated requests see the 503. ``ping`` and ``close`` reach
    ``inner`` when it has them.
    """

    def __init__(self, inner: NonceStore, guard: ClockStepGuard) -> None:
        self._inner = inner
        self._guard = guard

    @property
    def inner(self) -> NonceStore:
        """The wrapped store."""
        return self._inner

    @property
    def guard(self) -> ClockStepGuard:
        """The clock-step guard."""
        return self._guard

    @property
    def retention(self) -> float:
        """Seconds an accepted pair is remembered (the inner store's)."""
        return self._inner.retention

    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        """The inner store's answer; :class:`ReplayStoreUnavailable` in the window."""
        if self._guard.check():
            raise ReplayStoreUnavailable()
        return self._inner.check_and_store(hotkey_ss58, nonce_ns)

    def ping(self) -> bool:
        """Readiness: the inner store's ``ping`` (True when it has none)."""
        ping = getattr(self._inner, "ping", None)
        return True if ping is None else bool(ping())

    def close(self) -> None:
        """Close the inner store when it can be closed."""
        close = getattr(self._inner, "close", None)
        if close is not None:
            close()
