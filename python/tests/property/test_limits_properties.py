"""Property tests for the limits package (hypothesis)."""

from __future__ import annotations

import math

from hypothesis import given
from hypothesis import strategies as st

from tensorwire.limits.body import _content_length
from tensorwire.limits.ratelimit import TokenBucket

steps = st.lists(st.floats(min_value=0, max_value=5, allow_nan=False), min_size=1, max_size=200)


@given(
    rate=st.floats(min_value=0.01, max_value=1000, allow_nan=False),
    burst=st.integers(min_value=1, max_value=500),
    gaps=steps,
)
def test_bucket_never_admits_more_than_burst_plus_refill(
    rate: float, burst: int, gaps: list[float]
) -> None:
    bucket = TokenBucket(rate=rate, burst=burst, now=0.0)
    now = 0.0
    admitted = 0
    for gap in gaps:
        now += gap
        decision = bucket.take(now)
        admitted += decision.allowed
        if not decision.allowed:
            assert decision.retry_after_s > 0
            assert decision.retry_after_s <= 1 / rate + 1e-9
    assert admitted <= burst + math.floor(now * rate + 1e-6)


@given(gaps=steps)
def test_bucket_admits_when_waiting_retry_after(gaps: list[float]) -> None:
    bucket = TokenBucket(rate=3.0, burst=2, now=0.0)
    now = 0.0
    for gap in gaps:
        now += gap
        decision = bucket.take(now)
        if not decision.allowed:
            assert bucket.take(now + decision.retry_after_s + 1e-9).allowed
            now += decision.retry_after_s + 1e-9


@given(st.lists(st.tuples(st.binary(max_size=20), st.binary(max_size=20)), max_size=6))
def test_content_length_parser_never_raises(headers: list[tuple[bytes, bytes]]) -> None:
    value = _content_length(headers)
    assert value is None or value >= 0
