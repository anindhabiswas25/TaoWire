"""``tensorwire bench --miner-cpus`` parsing: a CPU list or a clean error, always."""

from __future__ import annotations

import typer
from hypothesis import given
from hypothesis import strategies as st

from tensorwire.cli.bench_cmd import parse_cpus

ranges = st.lists(
    st.tuples(st.integers(0, 64), st.integers(0, 8)), min_size=1, max_size=6
)


@given(st.text(max_size=40))
def test_any_text_parses_or_raises_bad_parameter(spec: str) -> None:
    try:
        cpus = parse_cpus(spec)
    except typer.BadParameter:
        return
    if cpus is not None:
        assert cpus == sorted(set(cpus))
        assert all(c >= 0 for c in cpus)


@given(ranges)
def test_ranges_round_trip(parts: list[tuple[int, int]]) -> None:
    spec = ",".join(f"{a}-{a + n}" if n else str(a) for a, n in parts)
    expected = sorted({c for a, n in parts for c in range(a, a + n + 1)})
    assert parse_cpus(spec) == expected
