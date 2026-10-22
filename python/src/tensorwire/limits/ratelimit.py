"""Token-bucket rate limiting (spec 8.6.2), memory backend.

Two layers use this module:

1. **Pre-auth, per client IP** (default 50 req/s, burst 100). The key comes
   from :func:`client_ip`.
2. **Post-auth, per hotkey and route** (default 20 req/s, burst 40).

A bucket holds up to ``burst`` tokens and refills at ``rate`` tokens per
second. Each request takes one token; an empty bucket rejects with 429 and a
``Retry-After`` of the seconds until one token is back.

:class:`MemoryRateLimiter` is per process. With more than one worker or
instance the same fail-closed rule as the nonce store applies: use the Redis
backend (spec 8.6.2, Phase 3).
"""

from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from tensorwire.errors import RateLimited

__all__ = [
    "MemoryRateLimiter",
    "RateDecision",
    "RateLimiter",
    "TokenBucket",
    "client_ip",
]

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class RateDecision:
    """Outcome of taking one token."""

    allowed: bool
    #: Seconds until a token is available; 0.0 when allowed.
    retry_after_s: float

    def raise_if_denied(self, layer: Literal["ip", "hotkey"]) -> None:
        """Raise :class:`RateLimited` (429, ``Retry-After``) if denied."""
        if not self.allowed:
            raise RateLimited(retry_after_s=self.retry_after_s, layer=layer)


class RateLimiter(Protocol):
    """A keyed token-bucket limiter (memory or Redis backend)."""

    async def acquire(self, key: str) -> RateDecision:
        """Take one token from ``key``'s bucket."""
        ...


class TokenBucket:
    """One token bucket.

    Not thread-safe on its own; :class:`MemoryRateLimiter` holds the lock.
    """

    __slots__ = ("burst", "rate", "tokens", "updated")

    def __init__(self, *, rate: float, burst: int, now: float) -> None:
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.updated = now

    def _refill(self, now: float) -> None:
        # A clock that does not move forward never adds tokens.
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(float(self.burst), self.tokens + elapsed * self.rate)
        self.updated = max(self.updated, now)

    def take(self, now: float) -> RateDecision:
        """Take one token at time ``now`` (seconds, monotonic)."""
        self._refill(now)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return RateDecision(allowed=True, retry_after_s=0.0)
        return RateDecision(
            allowed=False, retry_after_s=(1.0 - self.tokens) / self.rate
        )


def _check_rate(rate: float, burst: int) -> None:
    if not math.isfinite(rate) or rate <= 0:
        raise ValueError("rate must be a positive number of tokens per second")
    if burst < 1:
        raise ValueError("burst must be at least 1")


class MemoryRateLimiter:
    """Per-process keyed token buckets.

    Memory is bounded: at most ``max_keys`` buckets are kept. When the table
    is full the least recently used bucket is dropped (O(1)), which hands that
    key a fresh bucket next time. A key that is actively sending is never the
    least recently used one.
    """

    def __init__(
        self,
        *,
        rate: float,
        burst: int,
        max_keys: int = 100_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        _check_rate(rate, burst)
        if max_keys < 1:
            raise ValueError("max_keys must be at least 1")
        self.rate = rate
        self.burst = burst
        self.max_keys = max_keys
        self._clock = clock
        self._buckets: OrderedDict[str, TokenBucket] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._buckets)

    def take(self, key: str) -> RateDecision:
        """Take one token from ``key``'s bucket (synchronous)."""
        with self._lock:
            now = self._clock()
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    self._buckets.popitem(last=False)
                bucket = TokenBucket(rate=self.rate, burst=self.burst, now=now)
                self._buckets[key] = bucket
            else:
                self._buckets.move_to_end(key)
            return bucket.take(now)

    async def acquire(self, key: str) -> RateDecision:
        """Take one token from ``key``'s bucket."""
        return self.take(key)


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _trusted(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
    proxies: Sequence[IPNetwork],
) -> bool:
    return ip is not None and any(ip in net for net in proxies)


def client_ip(
    peer: str | None,
    forwarded_for: Sequence[str],
    trusted_proxies: Sequence[IPNetwork],
) -> str:
    """The rate-limit key for a request's client.

    ``peer`` is the socket peer address; ``forwarded_for`` holds every
    ``X-Forwarded-For`` header value in order. Without trusted proxies, or
    when the peer is not one of them, the peer is the client: a header from
    an untrusted sender is ignored. Otherwise the result is the right-most
    ``X-Forwarded-For`` entry that is not a trusted proxy (entries further
    left are written by the client and cannot be trusted).
    """
    peer_ip = _parse_ip(peer) if peer else None
    peer_key = str(peer_ip) if peer_ip is not None else (peer or "unknown")
    if not trusted_proxies or not _trusted(peer_ip, trusted_proxies):
        return peer_key
    hops = [h.strip() for value in forwarded_for for h in value.split(",") if h.strip()]
    for hop in reversed(hops):
        ip = _parse_ip(hop)
        if not _trusted(ip, trusted_proxies):
            # An unparseable hop is kept verbatim: it still separates clients.
            return str(ip) if ip is not None else hop
    # Every hop is a trusted proxy: the left-most is the closest we get to the client.
    return str(_parse_ip(hops[0])) if hops else peer_key
