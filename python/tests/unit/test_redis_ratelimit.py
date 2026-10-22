"""RedisRateLimiter without a server: fail-closed mapping, local deny cache, keys.

The Lua script itself runs against real Redis in
``tests/integration/test_redis_rate_limit.py``.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest
import redis

from tensorwire.errors import ReplayStoreUnavailable
from tensorwire.limits.ratelimit import PreAuthRateLimit, RateDecision, RedisRateLimiter


class FakeScript:
    """Stands in for ``redis.asyncio`` ``Script``: replays scripted answers."""

    def __init__(self, answers: list[Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[list[str], list[Any]]] = []

    async def __call__(self, *, keys: list[str], args: list[Any]) -> Any:
        self.calls.append((keys, args))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


class FakeRedis:
    def __init__(self, answers: list[Any], *, up: bool = True) -> None:
        self.script = FakeScript(answers)
        self.up = up
        self.closed = False

    def register_script(self, source: str) -> FakeScript:
        assert "redis.call('TIME')" in source  # Redis's clock, not the worker's
        return self.script

    async def ping(self) -> bool:
        if not self.up:
            raise redis.ConnectionError("down")
        return True

    async def aclose(self) -> None:
        self.closed = True


class Clock:
    def __init__(self) -> None:
        self.now = 50.0

    def __call__(self) -> float:
        return self.now


def limiter(answers: list[Any], **kw: Any) -> tuple[RedisRateLimiter, FakeRedis, Clock]:
    client = FakeRedis(answers, up=kw.pop("up", True))
    clock = Clock()
    lim = RedisRateLimiter(
        rate=2.0,
        burst=4,
        prefix="p:",
        client=client,  # type: ignore[arg-type]
        clock=clock,
        **kw,
    )
    return lim, client, clock


async def test_allowed_and_denied_answers() -> None:
    lim, client, _ = limiter([[1, "0"], [0, "0.375"]])
    assert await lim.acquire("1.2.3.4") == RateDecision(True, 0.0)
    assert await lim.acquire("1.2.3.4") == RateDecision(False, 0.375)
    keys, args = client.script.calls[0]
    assert keys == ["p:1.2.3.4"]
    assert args == [2.0, 4, 3000]  # ttl = burst / rate + 1 s, in ms


async def test_a_denied_key_is_answered_locally_until_retry_after() -> None:
    lim, client, clock = limiter([[0, "0.5"], [1, "0"]])
    assert not (await lim.acquire("k")).allowed
    clock.now += 0.2
    local = await lim.acquire("k")
    assert not local.allowed
    assert local.retry_after_s == pytest.approx(0.3)
    assert len(client.script.calls) == 1  # no Redis call during the wait
    clock.now += 0.3
    assert (await lim.acquire("k")).allowed
    assert len(client.script.calls) == 2


async def test_local_deny_table_is_bounded() -> None:
    lim, _, _ = limiter([[0, "10"]] * 5, max_local_keys=2)
    for key in "abc":
        await lim.acquire(key)
    assert list(lim._denied_until) == ["b", "c"]


async def test_long_keys_are_hashed() -> None:
    lim, client, _ = limiter([[1, "0"]])
    await lim.acquire("x" * 500)
    (key,), _ = client.script.calls[0]
    assert key.startswith("p:h:")
    assert len(key) == len("p:h:") + 64


async def test_redis_errors_fail_closed() -> None:
    lim, _, _ = limiter([redis.TimeoutError("slow")], up=False)
    with pytest.raises(ReplayStoreUnavailable):
        await lim.acquire("k")
    assert not await lim.ping()


async def test_ping_and_close() -> None:
    lim, client, _ = limiter([])
    assert await lim.ping()
    await lim.aclose()
    assert client.closed


def test_arguments() -> None:
    with pytest.raises(ValueError, match="url or a client"):
        RedisRateLimiter(rate=1, burst=1)
    with pytest.raises(ValueError, match="rate"):
        RedisRateLimiter("redis://x", rate=0, burst=1)
    built = RedisRateLimiter("redis://127.0.0.1:1/0", rate=1, burst=1)
    assert built.rate == 1


def test_needs_the_redis_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "redis", None)
    with pytest.raises(RuntimeError, match=r"tensorwire\[redis\]"):
        RedisRateLimiter("redis://x", rate=1, burst=1)


# ---------------------------------------------------------------- middleware


async def call(mw: PreAuthRateLimit, path: str) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Any) -> None:
        sent.append(message)

    scope = {"type": "http", "path": path, "client": ("9.9.9.9", 1), "headers": []}
    await mw(scope, receive, send)
    return sent


async def ok_app(scope: Any, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def test_middleware_fails_closed_except_on_health_paths() -> None:
    lim, _, _ = limiter([redis.ConnectionError("down")] * 2)
    mw = PreAuthRateLimit(
        ok_app, limiter=lim, passthrough_on_failure=frozenset({"/healthz"})
    )
    blocked = await call(mw, "/v1/x")
    assert blocked[0]["status"] == 503
    assert b"tw.replay_store_unavailable" in blocked[1]["body"]
    passed = await call(mw, "/healthz")
    assert passed[0]["status"] == 200
