"""``migrate status`` metrics-text parser (DoD 5): exact numbers or a clean error."""

from __future__ import annotations

import datetime as dt

from hypothesis import given
from hypothesis import strategies as st

from tensorwire.migrate import status as rollout
from tensorwire.observability.metrics import Metrics

RESULTS = ["ok", "tw.legacy_auth_failed", "tw.handler_error", "tw.timeout"]
TODAY_NS = int(dt.datetime(2026, 10, 23, tzinfo=dt.timezone.utc).timestamp() * 1e9)

counts = st.dictionaries(st.sampled_from(RESULTS), st.integers(0, 10**9), max_size=4)
days = st.none() | st.integers(0, 180)


@st.composite
def node(draw: st.DrawFn) -> tuple[str, dict[str, int]]:
    """Real ``Metrics`` text with random values, and what it must parse to."""
    m = Metrics()
    btauth, v10 = draw(st.integers(0, 4096)), draw(st.integers(0, 4096))
    if draw(st.booleans()):  # a validator
        m.validator_miners_by_protocol.labels(protocol="btauth/1").set(btauth)
        m.validator_miners_by_protocol.labels(protocol="v10").set(v10)
    else:
        btauth = v10 = 0
    want = {"btauth": btauth, "v10": v10}
    for direction in ("inbound", "outbound"):
        by_result = draw(counts)
        for result, n in by_result.items():
            m.legacy_v10_requests.labels(direction=direction, result=result).inc(n)
        want[direction] = sum(by_result.values())
        left = draw(days)
        if left is not None:
            until = dt.date(2026, 10, 23) + dt.timedelta(days=left)
            m.track_legacy_v10_end(direction, until, clock_ns=lambda: TODAY_NS)
        want[f"days_{direction}"] = -1 if left is None else left
    return m.render().decode(), want


@given(node())
def test_real_metrics_text_parses_to_exact_numbers(
    case: tuple[str, dict[str, int]],
) -> None:
    text, want = case
    s = rollout.parse_metrics_text(text, "n")
    assert s.miners_btauth == want["btauth"]
    assert s.miners_v10 == want["v10"]
    assert s.inbound_v10_total == want["inbound"]
    assert s.outbound_v10_total == want["outbound"]
    for direction in ("inbound", "outbound"):
        expected = want[f"days_{direction}"]
        assert s.days_remaining[direction] == (None if expected < 0 else expected)


@given(st.lists(node(), max_size=5), st.none() | st.floats(0, 1))
def test_report_is_the_sum_and_share_is_a_fraction(
    cases: list[tuple[str, dict[str, int]]], minimum: float | None
) -> None:
    parsed = [rollout.parse_metrics_text(t, str(i)) for i, (t, _) in enumerate(cases)]
    r = rollout.build_report(parsed, min_btauth_share=minimum)
    assert r.miners_btauth == sum(w["btauth"] for _, w in cases)
    assert r.inbound_v10_total == sum(w["inbound"] for _, w in cases)
    if r.btauth_share is None:
        assert r.miners_btauth + r.miners_v10 == 0
    else:
        assert 0 <= r.btauth_share <= 1
    assert r.exit_code in (0, 1)
    assert (r.exit_code == 1) == (r.share_met is False)
    for direction in ("inbound", "outbound"):
        known = [
            w[f"days_{direction}"] for _, w in cases if w[f"days_{direction}"] >= 0
        ]
        assert r.days_remaining[direction] == (min(known) if known else None)


@given(st.text(max_size=300))
def test_any_text_parses_or_raises_metrics_text_error(text: str) -> None:
    try:
        s = rollout.parse_metrics_text(text, "x")
    except rollout.MetricsTextError:
        return
    assert s.miners_btauth >= 0
    assert s.miners_v10 >= 0
    assert s.inbound_v10_total >= 0
    assert s.outbound_v10_total >= 0


metric_lines = st.lists(
    st.tuples(
        st.sampled_from(
            [
                "tw_validator_miners_by_protocol",
                "tw_legacy_v10_requests_total",
                "tw_legacy_v10_days_remaining",
            ]
        ),
        st.sampled_from(['protocol="v10"', 'direction="inbound"', 'result="ok"', ""]),
        st.sampled_from(["1", "-1", "NaN", "+Inf", "1e400", "0x10", "", "7.5"]),
    ),
    max_size=8,
)


@given(metric_lines)
def test_near_valid_lines_parse_or_raise_metrics_text_error(
    lines: list[tuple[str, str, str]],
) -> None:
    text = "".join(f"{n}{{{label}}} {v}\n" for n, label, v in lines)
    try:
        s = rollout.parse_metrics_text(text, "x")
    except rollout.MetricsTextError:
        return
    for value in (s.inbound_v10_total, s.outbound_v10_total):
        assert value >= 0
        assert value != float("inf")
