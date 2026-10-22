"""Replay-protection stores for btauth/1 (spec 8.4.3).

A store remembers accepted ``(hotkey, nonce)`` pairs for ``retention`` seconds.
``bittensor.http_auth.verify`` calls ``check_and_store`` only after the
signature verifies (fact A4), and synchronously (fact A1), so both stores here
are synchronous.

- :class:`MemoryNonceStore`: one process only.
- :class:`RedisNonceStore`: shared across processes and hosts. Required when
  more than one worker or instance serves the same hotkey.

Every store exposes ``retention`` so the verifier can refuse a store whose
memory is shorter than the freshness window (fact A3).
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from tensorwire.errors import ReplayStoreUnavailable

if TYPE_CHECKING:
    import redis

__all__ = ["MemoryNonceStore", "NonceStore", "RedisNonceStore"]


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


class MemoryNonceStore:
    """Single-process store with time-based expiry.

    Same semantics as ``bittensor.http_auth.InMemoryNonceStore``, with an
    injectable monotonic clock for tests. Memory is bounded by the number of
    *verified* requests per retention window, because the verifier only
    stores after the signature checks out.
    """

    def __init__(
        self, retention: float = 60.0, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._retention = _check_retention(retention)
        self._clock = clock
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
        while self._expiry and self._expiry[0][0] <= now:
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
                "RedisNonceStore needs the redis extra: pip install 'tensorwire[redis]'"
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
