from __future__ import annotations

import pytest

from tensorwire.chain.metagraph_cache import (
    DEFAULT_SOFT_AGE_S,
    StalenessStage,
    StalenessThresholds,
    default_max_age_s,
)


def test_default_max_age_is_two_tempos() -> None:
    assert default_max_age_s(360) == 8640.0
    assert default_max_age_s(100, block_time_s=0.25) == 50.0


@pytest.mark.parametrize(("tempo", "block_time"), [(0, 12.0), (-1, 12.0), (360, 0.0)])
def test_default_max_age_rejects_non_positive(tempo: int, block_time: float) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        default_max_age_s(tempo, block_time_s=block_time)


def test_for_tempo_defaults() -> None:
    thresholds = StalenessThresholds.for_tempo(360)
    assert thresholds == StalenessThresholds(
        soft_age_s=DEFAULT_SOFT_AGE_S, max_age_s=8640.0
    )


def test_for_tempo_overrides() -> None:
    thresholds = StalenessThresholds.for_tempo(360, soft_age_s=120, max_age_s=300)
    assert thresholds == StalenessThresholds(soft_age_s=120, max_age_s=300)


@pytest.mark.parametrize(("soft", "max_"), [(0, 10), (10, 10), (20, 10), (-1, 10)])
def test_thresholds_must_be_ordered(soft: float, max_: float) -> None:
    with pytest.raises(ValueError, match="thresholds must satisfy"):
        StalenessThresholds(soft_age_s=soft, max_age_s=max_)


@pytest.mark.parametrize(
    ("age", "stage"),
    [
        (0.0, StalenessStage.FRESH),
        (119.999, StalenessStage.FRESH),
        (120.0, StalenessStage.DEGRADED),
        (300.0, StalenessStage.DEGRADED),
        (300.001, StalenessStage.KNOWN_CALLERS_ONLY),
        (1e9, StalenessStage.KNOWN_CALLERS_ONLY),
        (None, StalenessStage.KNOWN_CALLERS_ONLY),
    ],
)
def test_stage_boundaries(age: float | None, stage: StalenessStage) -> None:
    assert StalenessThresholds(soft_age_s=120, max_age_s=300).stage_for(age) is stage


def test_stage_values_match_degraded_gauge() -> None:
    assert [int(s) for s in StalenessStage] == [0, 1, 2]
