"""limits/ratelimit.py: bucket refill math, Retry-After, key bounds, client IP (13.2)."""

from __future__ import annotations

import ipaddress

import pytest

from tensorwire.errors import RateLimited
from tensorwire.limits.ratelimit import MemoryRateLimiter, RateDecision, TokenBucket, client_ip


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
    assert b.take(0.75).retry_after_s == pytest.approx(0.25)  # 0.5 token back, 0.5 missing


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
        ("203.0.113.9", ["1.2.3.4"], [], "203.0.113.9"),  # no trusted proxies: header ignored
        ("203.0.113.9", ["1.2.3.4"], PROXIES, "203.0.113.9"),  # peer not a proxy: header ignored
        ("10.0.0.1", ["1.2.3.4"], PROXIES, "1.2.3.4"),
        ("10.0.0.1", ["6.6.6.6, 1.2.3.4"], PROXIES, "1.2.3.4"),  # spoofed left entry ignored
        ("10.0.0.1", ["6.6.6.6, 1.2.3.4, 10.0.0.2"], PROXIES, "1.2.3.4"),  # proxy chain
        ("10.0.0.1", ["6.6.6.6", "1.2.3.4"], PROXIES, "1.2.3.4"),  # multiple headers
        ("10.0.0.1", ["10.0.0.3, 10.0.0.2"], PROXIES, "10.0.0.3"),  # all trusted: left-most
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
