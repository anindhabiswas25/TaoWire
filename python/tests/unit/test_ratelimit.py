"""limits/ratelimit.py: refill math, Retry-After, key bounds, client IP (13.2)."""

from __future__ import annotations

import ipaddress
from typing import Any

import pytest
import structlog

from tensorwire.errors import RateLimited
from tensorwire.limits.ratelimit import (
    MemoryRateLimiter,
    PreAuthRateLimit,
    RateDecision,
    TokenBucket,
    client_ip,
)
from tensorwire.observability.metrics import Metrics


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_burst_then_reject() -> None:
    b = TokenBucket(rate=2.0, burst=3, now=0.0)
    assert [b.take(0.0).allowed for _ in range(4)] == [True, True, True, False]


def test_refill_math() -> None:
    b = TokenBucket(rate=2.0, burst=3, now=0.0)
    for _ in range(3):
        b.take(0.0)
    denied = b.take(0.0)
    assert denied == RateDecision(allowed=False, retry_after_s=0.5)  # 1 token / 2 per s
    assert not b.take(0.25).allowed  # half a token back
    assert b.take(0.25 + 0.25).allowed  # exactly one token at t=0.5
    assert b.take(0.75).retry_after_s == pytest.approx(
        0.25
    )  # 0.5 token back, 0.5 missing


def test_refill_is_capped_at_burst() -> None:
    b = TokenBucket(rate=10.0, burst=2, now=0.0)
    results = [b.take(1_000.0).allowed for _ in range(3)]
    assert results == [True, True, False]


def test_clock_going_backwards_adds_nothing() -> None:
    b = TokenBucket(rate=1.0, burst=1, now=10.0)
    assert b.take(10.0).allowed
    assert not b.take(5.0).allowed
    assert not b.take(10.5).allowed  # no credit for the backwards step
    assert b.take(11.0).allowed


def test_limiter_keys_are_independent() -> None:
    clock = FakeClock()
    lim = MemoryRateLimiter(rate=1.0, burst=1, clock=clock)
    assert lim.take("a").allowed
    assert not lim.take("a").allowed
    assert lim.take("b").allowed
    clock.now += 1.0
    assert lim.take("a").allowed


async def test_acquire_is_async_take() -> None:
    lim = MemoryRateLimiter(rate=1.0, burst=1, clock=FakeClock())
    assert (await lim.acquire("k")).allowed
    assert not (await lim.acquire("k")).allowed


def test_retry_after_header() -> None:
    clock = FakeClock()
    lim = MemoryRateLimiter(rate=0.4, burst=1, clock=clock)
    lim.take("k")
    decision = lim.take("k")
    assert decision.retry_after_s == pytest.approx(2.5)
    with pytest.raises(RateLimited) as info:
        decision.raise_if_denied("hotkey")
    assert info.value.response_headers() == {"Retry-After": "3"}
    assert info.value.layer == "hotkey"
    RateDecision(allowed=True, retry_after_s=0.0).raise_if_denied("ip")  # no raise


def test_key_table_is_bounded_lru() -> None:
    clock = FakeClock()
    lim = MemoryRateLimiter(rate=1.0, burst=1, max_keys=2, clock=clock)
    lim.take("a")
    lim.take("b")
    lim.take("a")  # a is now most recent
    lim.take("c")  # evicts b
    assert len(lim) == 2
    assert not lim.take("a").allowed  # a kept its (empty) bucket
    assert lim.take("b").allowed  # b was evicted: fresh bucket


@pytest.mark.parametrize(
    ("rate", "burst", "max_keys", "match"),
    [
        (0, 1, 1, "rate"),
        (-1, 1, 1, "rate"),
        (float("inf"), 1, 1, "rate"),
        (1, 0, 1, "burst"),
        (1, 1, 0, "max_keys"),
    ],
)
def test_limiter_arguments(rate: float, burst: int, max_keys: int, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        MemoryRateLimiter(rate=rate, burst=burst, max_keys=max_keys)


# --------------------------------------------------------------- client_ip

PROXIES = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("2001:db8::/32")]


@pytest.mark.parametrize(
    ("peer", "xff", "proxies", "expected"),
    [
        ("203.0.113.9", [], [], "203.0.113.9"),
        (
            "203.0.113.9",
            ["1.2.3.4"],
            [],
            "203.0.113.9",
        ),  # no trusted proxies: header ignored
        (
            "203.0.113.9",
            ["1.2.3.4"],
            PROXIES,
            "203.0.113.9",
        ),  # peer not a proxy: header ignored
        ("10.0.0.1", ["1.2.3.4"], PROXIES, "1.2.3.4"),
        (
            "10.0.0.1",
            ["6.6.6.6, 1.2.3.4"],
            PROXIES,
            "1.2.3.4",
        ),  # spoofed left entry ignored
        ("10.0.0.1", ["6.6.6.6, 1.2.3.4, 10.0.0.2"], PROXIES, "1.2.3.4"),  # proxy chain
        ("10.0.0.1", ["6.6.6.6", "1.2.3.4"], PROXIES, "1.2.3.4"),  # multiple headers
        (
            "10.0.0.1",
            ["10.0.0.3, 10.0.0.2"],
            PROXIES,
            "10.0.0.3",
        ),  # all trusted: left-most
        ("10.0.0.1", [], PROXIES, "10.0.0.1"),
        ("10.0.0.1", [" , "], PROXIES, "10.0.0.1"),
        ("10.0.0.1", ["garbage"], PROXIES, "garbage"),
        ("2001:db8::5", ["2001:DB8:0:0:0:0:0:1, 2a00::1"], PROXIES, "2a00::1"),
        ("2001:db8::5", ["2a00:0::1"], PROXIES, "2a00::1"),  # normalised
        (None, ["1.2.3.4"], PROXIES, "unknown"),
        ("unix-socket", [], [], "unix-socket"),
    ],
)
def test_client_ip(
    peer: str | None,
    xff: list[str],
    proxies: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    expected: str,
) -> None:
    assert client_ip(peer, xff, proxies) == expected


# ---------------------------------------------------------------- PreAuthRateLimit


async def _call(
    mw: Any, *, client: tuple[str, int] | None, headers: list[tuple[bytes, bytes]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sent: list[dict[str, Any]] = []
    scope: dict[str, Any] = {"type": "http", "client": client, "headers": headers}

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b""}

    async def send(message: Any) -> None:
        sent.append(message)

    await mw(scope, receive, send)
    return sent, scope


async def _ok(scope: Any, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b""})


async def test_pre_auth_limit_keys_by_client_ip() -> None:
    limiter = MemoryRateLimiter(rate=0.001, burst=1)
    mw = PreAuthRateLimit(_ok, limiter=limiter)
    sent, _ = await _call(mw, client=("1.1.1.1", 5), headers=[])
    assert sent[0]["status"] == 200
    sent, _ = await _call(mw, client=("1.1.1.1", 6), headers=[])
    assert sent[0]["status"] == 429
    headers = dict(sent[0]["headers"])
    assert int(headers[b"retry-after"]) >= 1
    assert b'"tw.rate_limited"' in sent[1]["body"]
    assert len(headers[b"x-tw-request-id"]) == 26  # a ULID, also in the body
    assert headers[b"x-tw-request-id"] in sent[1]["body"]
    sent, _ = await _call(mw, client=("2.2.2.2", 5), headers=[])
    assert sent[0]["status"] == 200


async def test_pre_auth_refusals_are_counted_and_logged_sparingly() -> None:
    clock = FakeClock()
    metrics = Metrics()
    mw = PreAuthRateLimit(
        _ok,
        limiter=MemoryRateLimiter(rate=0.001, burst=1, clock=clock),
        metrics=metrics,
        log_interval_s=10,
        clock=clock,
    )
    with structlog.testing.capture_logs() as logs:
        for _ in range(6):  # 1 served, 5 refused
            await _call(mw, client=("1.1.1.1", 5), headers=[])
        clock.now += 10
        await _call(mw, client=("1.1.1.1", 5), headers=[])  # next window
        await _call(mw, client=("2.2.2.2", 5), headers=[])  # another client: served
    refusals = [e for e in logs if e["event"] == "ip_rate_limited"]
    assert [(e["client_ip"], e["refused"]) for e in refusals] == [
        ("1.1.1.1", 1),
        ("1.1.1.1", 5),  # 4 more in the first window + the one that logged
    ]
    text = metrics.render().decode()
    assert (
        'tw_requests_total{code="tw.rate_limited",route="unmatched",status="429"} 6.0'
        in text
    )
    assert 'tw_rate_limited_total{layer="ip"} 6.0' in text


async def test_pre_auth_limit_uses_trusted_proxy_header() -> None:
    limiter = MemoryRateLimiter(rate=0.001, burst=1)
    proxies = [ipaddress.ip_network("10.0.0.0/8")]
    mw = PreAuthRateLimit(_ok, limiter=limiter, trusted_proxies=proxies)
    for client_ip_ in ("7.7.7.7", "8.8.8.8"):
        xff = [(b"x-forwarded-for", f"6.6.6.6, {client_ip_}".encode())]
        sent, _ = await _call(mw, client=("10.0.0.1", 1), headers=xff)
        assert sent[0]["status"] == 200  # two distinct clients behind one proxy
    # an untrusted peer cannot choose its key with the header
    xff = [(b"x-forwarded-for", b"9.9.9.9")]
    assert (await _call(mw, client=("3.3.3.3", 1), headers=xff))[0][0]["status"] == 200
    assert (await _call(mw, client=("3.3.3.3", 1), headers=[]))[0][0]["status"] == 429


async def test_pre_auth_limit_passes_non_http_through() -> None:
    seen: list[str] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    mw = PreAuthRateLimit(app, limiter=MemoryRateLimiter(rate=1, burst=1))
    await mw({"type": "lifespan"}, None, None)  # type: ignore[arg-type]
    assert seen == ["lifespan"]
