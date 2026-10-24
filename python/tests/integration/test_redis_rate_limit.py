"""Shared rate limits through Redis (spec 8.6.2) and the multi-worker rules.

Tests marked ``redis`` need a real Redis at ``TAOWIRE_TEST_REDIS_URL``
(Engineer B's ``tw-redis``, e.g. ``redis://127.0.0.1:6379/15``); each test
uses its own key prefix. The fail-closed tests use a closed port and always run.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import redis
from pydantic import BaseModel, SecretStr

from taowire.auth.nonce_store import MemoryNonceStore, RedisNonceStore
from taowire.errors import StartupError
from taowire.limits.ratelimit import RedisRateLimiter
from taowire.miner.app import Miner
from taowire.miner.routes import RouteContext
from taowire.testing.client import SignedClient
from taowire.testing.clock import FakeClock
from taowire.testing.keys import dev_key
from taowire.testing.pytest_plugin import MINER_KEY

URL = os.environ.get("TAOWIRE_TEST_REDIS_URL")
DEAD = "redis://127.0.0.1:1/0"  # nothing listens on port 1

needs_redis = pytest.mark.skipif(not URL, reason="TAOWIRE_TEST_REDIS_URL not set")


class Echo(BaseModel):
    text: str


def prefix() -> str:
    return f"tw:test:{uuid.uuid4().hex}:"


def miner(
    kwargs: dict[str, Any], *, settings: dict[str, Any] | None = None, **parts: Any
) -> Miner:
    m = Miner(
        **{
            **kwargs,
            "settings": kwargs["settings"].model_copy(update=settings or {}),
            **parts,
        }
    )

    @m.route("/v1/echo", request=Echo, response=Echo)
    async def echo(req: Echo, ctx: RouteContext) -> Echo:
        return req

    return m


def client(app: Any, clock: FakeClock) -> SignedClient:
    return SignedClient(
        app, receiver_ss58=dev_key(MINER_KEY).ss58, key="alice", clock_ns=clock.now_ns
    )


# ---------------------------------------------------------------- the Lua bucket


@pytest.fixture
async def limiter() -> AsyncIterator[RedisRateLimiter]:
    assert URL is not None
    lim = RedisRateLimiter(URL, rate=10.0, burst=3, prefix=prefix())
    yield lim
    await lim.aclose()


@pytest.mark.redis
@needs_redis
async def test_burst_refill_and_expiry(limiter: RedisRateLimiter) -> None:
    decisions = [await limiter.acquire("1.2.3.4") for _ in range(4)]
    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert 0.05 < decisions[3].retry_after_s <= 0.1
    await asyncio.sleep(0.12)
    assert (await limiter.acquire("1.2.3.4")).allowed  # one token back
    assert URL is not None
    raw = redis.Redis.from_url(URL)
    key = limiter._key("1.2.3.4")
    ttl_ms: int = raw.pttl(key)  # type: ignore[assignment]
    assert 0 < ttl_ms <= 3 / 10 * 1000 + 1000  # expires once full again
    raw.close()


@pytest.mark.redis
@needs_redis
async def test_one_bucket_across_workers_is_atomic() -> None:
    # Four "workers" (separate clients and pools) hammer one key at once.
    assert URL is not None
    shared = prefix()
    workers = [
        RedisRateLimiter(URL, rate=0.001, burst=25, prefix=shared) for _ in range(4)
    ]
    results = await asyncio.gather(
        *(workers[i % 4].acquire("10.0.0.1") for i in range(200))
    )
    assert sum(r.allowed for r in results) == 25
    for w in workers:
        await w.aclose()


@pytest.mark.redis
@needs_redis
async def test_redis_clock_not_worker_clock() -> None:
    # A worker whose monotonic clock jumps ahead gets no extra tokens:
    # refill is computed from Redis TIME inside the script.
    assert URL is not None
    shared = prefix()
    now = [0.0]
    jumpy = RedisRateLimiter(
        URL, rate=0.001, burst=1, prefix=shared, clock=lambda: now[0]
    )
    assert (await jumpy.acquire("k")).allowed
    now[0] += 10_000.0
    assert not (await jumpy.acquire("k")).allowed
    await jumpy.aclose()


# ---------------------------------------------------------------- two miner workers


@pytest.mark.redis
@needs_redis
async def test_two_workers_share_both_layers(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    assert URL is not None
    shared = prefix()
    store = RedisNonceStore(URL, prefix=shared + "n:")

    def worker() -> Miner:
        return miner(
            tw_miner_kwargs,
            settings={"workers": 2},
            nonce_store=store,
            ip_limiter=RedisRateLimiter(
                URL, rate=0.001, burst=6, prefix=shared + "ip:"
            ),
            hotkey_limiter=RedisRateLimiter(
                URL, rate=0.001, burst=3, prefix=shared + "hk:"
            ),
        )

    one, two = worker(), worker()
    async with one.running() as app1, two.running() as app2:
        assert one.lifecycle.runtime.limiter_backend == "redis"
        c1, c2 = client(app1, tw_clock), client(app2, tw_clock)
        # Hotkey layer (alice on /v1/echo): burst 3 in total, not per worker.
        statuses = []
        for i in range(4):
            tw_clock.advance(0.001)  # two signers on one frozen clock: distinct nonces
            r = await (c1 if i % 2 == 0 else c2).post("/v1/echo", json={"text": "x"})
            statuses.append(r.status_code)
        assert statuses == [200, 200, 200, 429]
        assert r.json()["error"]["code"] == "tw.rate_limited"
        # IP layer: 6 tokens per IP in total; 4 used above (all reached the
        # middleware), so the 7th request overall is refused before auth.
        later = []
        for c in (c2, c1, c2):
            tw_clock.advance(0.001)
            later.append(await c.post("/v1/echo", json={"text": "x"}))
        _, r6, r7 = later
        assert [r.status_code for r in later] == [429, 429, 429]
        assert "x-tw-resp-signature" in r6.headers  # hotkey layer: signed
        assert "x-tw-resp-signature" not in r7.headers  # IP layer: unsigned
        assert "retry-after" in r7.headers
        rate_limited = one.metrics.registry.get_sample_value(
            "tw_rate_limited_total", {"layer": "hotkey"}
        )
        assert rate_limited == 1.0  # r6, refused by this worker's hotkey layer
        await c1.aclose()
        await c2.aclose()
    store.close()


# ---------------------------------------------------------------- fail closed


async def test_redis_outage_fails_closed_but_health_answers(
    tw_miner_kwargs: dict[str, Any], tw_clock: FakeClock
) -> None:
    m = miner(
        tw_miner_kwargs,
        ip_limiter=RedisRateLimiter(DEAD, rate=50, burst=100),
        hotkey_limiter=RedisRateLimiter(DEAD, rate=20, burst=40),
    )
    async with m.running() as app:
        c = client(app, tw_clock)
        started = time.perf_counter()
        r = await c.post("/v1/echo", json={"text": "x"})
        assert time.perf_counter() - started < 2.0
        assert r.status_code == 503
        assert r.json()["error"]["code"] == "tw.replay_store_unavailable"
        assert (await c.http.get("/healthz")).status_code == 200
        ready = await c.http.get("/readyz")
        assert ready.status_code == 503
        assert "rate_limiter_unreachable" in ready.text
        errors = m.metrics.registry.get_sample_value(
            "tw_nonce_store_errors_total", {"backend": "redis"}
        )
        assert errors == 1.0
        await c.aclose()


async def test_multiworker_refuses_per_process_rate_limits(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    # A shared replay store alone is not enough: the limits must be shared too.
    shared_store = RedisNonceStore(DEAD)
    m = miner(tw_miner_kwargs, settings={"workers": 4}, nonce_store=shared_store)
    with pytest.raises(StartupError, match="per-process rate limits"):
        await m.lifecycle.start()


async def test_unsafe_override_allows_per_process_limits(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    m = miner(
        tw_miner_kwargs,
        settings={"instance_count": 2, "unsafe_allow_memory_nonce_multiworker": True},
        nonce_store=MemoryNonceStore(),
    )
    async with m.running():
        assert m.lifecycle.runtime.limiter_backend == "memory"


async def test_redis_url_gives_shared_limits_for_both_layers(
    tw_miner_kwargs: dict[str, Any],
) -> None:
    m = miner(
        tw_miner_kwargs, settings={"redis_url": SecretStr(DEAD), "instance_count": 3}
    )
    async with m.running():
        rt = m.lifecycle.runtime
        assert (rt.store_backend, rt.limiter_backend) == ("redis", "redis")
