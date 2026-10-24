"""Token-bucket rate limiting (spec 8.6.2), memory and Redis backends.

Two layers use this module:

1. **Pre-auth, per client IP** (default 50 req/s, burst 100). The key comes
   from :func:`client_ip`.
2. **Post-auth, per hotkey and route** (default 20 req/s, burst 40).

:class:`PreAuthRateLimit` is the ASGI middleware for layer 1; the miner
pipeline applies layer 2 after authentication.

A bucket holds up to ``burst`` tokens and refills at ``rate`` tokens per
second. Each request takes one token; an empty bucket rejects with 429 and a
``Retry-After`` of the seconds until one token is back.

:class:`MemoryRateLimiter` is per process. :class:`RedisRateLimiter` keeps
the buckets in Redis, updated by one atomic Lua script on Redis's own clock,
so every worker and instance shares them. With more than one worker or
instance the same rule as the nonce store applies: the memory backend is
refused at startup, and a Redis failure fails closed (503
``tw.replay_store_unavailable``), never open.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, MutableMapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol

import structlog

from taowire.errors import RateLimited, ReplayStoreUnavailable, TWError
from taowire.limits.body import send_error
from taowire.observability.logging import new_request_id
from taowire.observability.middleware import UNMATCHED_ROUTE

if TYPE_CHECKING:
    import redis.asyncio

    from taowire.observability.metrics import Metrics

__all__ = [
    "MemoryRateLimiter",
    "PreAuthRateLimit",
    "RateDecision",
    "RateLimiter",
    "RedisRateLimiter",
    "TokenBucket",
    "client_ip",
]

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_log = structlog.stdlib.get_logger("taowire.limits")


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


#: Atomic token-bucket update. KEYS[1] = bucket; ARGV = rate, burst, ttl_ms.
#: Time comes from Redis (``TIME``), so workers on hosts with different clocks
#: share one timeline. Returns ``{allowed (0/1), retry_after_s (string)}``.
_BUCKET_SCRIPT = """
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil or ts == nil then
  tokens = burst
  ts = now
end
local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
tokens = math.min(burst, tokens + elapsed * rate)
if now > ts then ts = now end
local allowed = 0
local retry = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry = (1 - tokens) / rate
end
redis.call('HSET', KEYS[1], 'tokens', string.format('%.17g', tokens),
           'ts', string.format('%.17g', ts))
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]))
return {allowed, string.format('%.17g', retry)}
"""

#: Keys longer than this are hashed (an unparseable X-Forwarded-For hop is
#: kept verbatim and can be up to the header limit).
_MAX_RAW_KEY = 128


class RedisRateLimiter:
    """Keyed token buckets shared through Redis (spec 8.6.2).

    One ``EVALSHA`` per request updates the bucket atomically. A bucket
    expires once it would be full again, so Redis memory stays bounded.

    A denied key is also remembered locally until its ``Retry-After`` has
    passed: nobody can add tokens to a bucket before that, so the local
    answer is the one Redis would give, and a flood from one key costs one
    Redis call per refill instead of one per request. The local table is
    bounded (``max_local_keys``, least recently used dropped).

    Any Redis error raises :class:`ReplayStoreUnavailable` (503): the
    limiter fails closed, as the nonce store does.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        rate: float,
        burst: int,
        prefix: str = "tw:rl:",
        client: redis.asyncio.Redis | None = None,
        max_connections: int = 64,
        max_local_keys: int = 100_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        try:
            import redis  # noqa: PLC0415 - optional extra
            import redis.asyncio  # noqa: PLC0415
        except ImportError:
            raise RuntimeError(
                "RedisRateLimiter needs the redis extra: pip install 'taowire[redis]'"
            ) from None
        _check_rate(rate, burst)
        self.rate = rate
        self.burst = burst
        self._prefix = prefix
        # Expire once the bucket would be full again (plus a second).
        self._ttl_ms = math.ceil(burst / rate * 1000) + 1000
        self._redis_error = redis.RedisError
        if client is None:
            if url is None:
                raise ValueError("pass a Redis url or a client")
            pool = redis.asyncio.BlockingConnectionPool.from_url(
                url,
                max_connections=max_connections,
                timeout=0.25,
                socket_timeout=0.25,
                socket_connect_timeout=0.5,
            )
            client = redis.asyncio.Redis.from_pool(pool)  # closes the pool too
        self._r = client
        self._script = client.register_script(_BUCKET_SCRIPT)
        self._clock = clock
        self._max_local = max_local_keys
        self._denied_until: OrderedDict[str, float] = OrderedDict()

    def _key(self, key: str) -> str:
        if len(key) > _MAX_RAW_KEY:
            key = "h:" + hashlib.sha256(key.encode()).hexdigest()
        return self._prefix + key

    def _locally_denied(self, key: str, now: float) -> float | None:
        until = self._denied_until.get(key)
        if until is None:
            return None
        if now >= until:
            del self._denied_until[key]
            return None
        return until - now

    def _remember_denial(self, key: str, until: float) -> None:
        self._denied_until[key] = until
        self._denied_until.move_to_end(key)
        while len(self._denied_until) > self._max_local:
            self._denied_until.popitem(last=False)

    async def acquire(self, key: str) -> RateDecision:
        """Take one token from ``key``'s bucket.

        Raises :class:`ReplayStoreUnavailable` if Redis cannot be reached.
        """
        now = self._clock()
        wait = self._locally_denied(key, now)
        if wait is not None:
            return RateDecision(allowed=False, retry_after_s=wait)
        try:
            allowed, retry = await self._script(
                keys=[self._key(key)], args=[self.rate, self.burst, self._ttl_ms]
            )
        except self._redis_error as exc:
            raise ReplayStoreUnavailable() from exc
        if int(allowed) == 1:
            return RateDecision(allowed=True, retry_after_s=0.0)
        retry_after = float(retry)
        self._remember_denial(key, now + retry_after)
        return RateDecision(allowed=False, retry_after_s=retry_after)

    async def ping(self) -> bool:
        """Readiness probe: True when Redis answers."""
        try:
            return bool(await self._r.ping())
        except self._redis_error:
            return False

    async def aclose(self) -> None:
        """Close the connection pool."""
        await self._r.aclose()


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


Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def _scope_client_ip(scope: Scope, trusted_proxies: Sequence[IPNetwork]) -> str:
    client = scope.get("client")
    peer = client[0] if client else None
    forwarded = [
        v.decode("latin-1")
        for k, v in scope.get("headers", [])
        if k.lower() == b"x-forwarded-for"
    ]
    return client_ip(peer, forwarded, trusted_proxies)


class PreAuthRateLimit:
    """Layer 1: per-client-IP token bucket, before anything else is read.

    Rejections are 429 ``tw.rate_limited`` with ``Retry-After``, unsigned
    (spec Appendix A), with a request ID in the body and ``X-TW-Request-Id``.
    A shared (Redis) limiter that cannot be reached answers 503
    ``tw.replay_store_unavailable``, except on ``passthrough_on_failure``
    paths (the health endpoints: a Redis outage must not fail liveness).

    The miner installs it outermost, so a flood is refused before any other
    layer runs. With ``metrics`` it counts its own refusals
    (``tw_requests_total{route="unmatched"}``, ``tw_rate_limited_total{layer="ip"}``,
    ``tw_nonce_store_errors_total``) and, instead of one access-log line per
    refused request, logs ``ip_rate_limited`` at WARNING at most once per
    client per ``log_interval_s`` with the number refused since.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        limiter: RateLimiter,
        trusted_proxies: Sequence[IPNetwork] = (),
        passthrough_on_failure: frozenset[str] = frozenset(),
        metrics: Metrics | None = None,
        log_interval_s: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.app = app
        self._limiter = limiter
        self._proxies = tuple(trusted_proxies)
        self._passthrough = passthrough_on_failure
        self._log = _RefusalLog(log_interval_s, clock)
        # Label lookups done once: a flood is counted at a few hundred ns each.
        self._counters: dict[str, tuple[Any, ...]] = {}
        if metrics is not None:
            self._counters = {
                RateLimited.code: (
                    metrics.requests.labels(
                        route=UNMATCHED_ROUTE, status="429", code=RateLimited.code
                    ),
                    metrics.rate_limited.labels(layer="ip"),
                ),
                ReplayStoreUnavailable.code: (
                    metrics.requests.labels(
                        route=UNMATCHED_ROUTE,
                        status="503",
                        code=ReplayStoreUnavailable.code,
                    ),
                    metrics.nonce_store_errors.labels(backend="redis"),
                ),
            }

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        error: TWError
        client = _scope_client_ip(scope, self._proxies)
        try:
            decision = await self._limiter.acquire(client)
        except ReplayStoreUnavailable as exc:  # shared limiter down: fail closed
            if scope.get("path") in self._passthrough:
                await self.app(scope, receive, send)
                return
            error = exc
        else:
            if decision.allowed:
                await self.app(scope, receive, send)
                return
            error = RateLimited(retry_after_s=decision.retry_after_s, layer="ip")
        for counter in self._counters.get(error.code, ()):
            counter.inc()
        self._log.refused(client, error.code)
        await send_error(send, error, request_id=new_request_id())


class _RefusalLog:
    """At most one WARNING per client per interval, with the count since."""

    _MAX_CLIENTS = 10_000

    def __init__(self, interval_s: float, clock: Callable[[], float]) -> None:
        self._interval = interval_s
        self._clock = clock
        self._seen: OrderedDict[str, list[float]] = OrderedDict()  # [last_log, n]

    def refused(self, client: str, code: str) -> None:
        now = self._clock()
        entry = self._seen.get(client)
        if entry is not None and now - entry[0] < self._interval:
            entry[1] += 1
            return
        refused = 1 if entry is None else int(entry[1]) + 1
        self._seen[client] = [now, 0]
        self._seen.move_to_end(client)
        while len(self._seen) > self._MAX_CLIENTS:
            self._seen.popitem(last=False)
        _log.warning("ip_rate_limited", client_ip=client, code=code, refused=refused)
