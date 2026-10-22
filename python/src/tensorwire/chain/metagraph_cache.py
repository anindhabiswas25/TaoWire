"""Metagraph cache interface and staged staleness (spec 8.5.1).

The cache refreshes a subnet snapshot in the background and reports how old
it is as one of three stages. The caller policy (``policy/``) decides what
each stage means for a request; the cache only measures. The background
refresh implementation lands in Phase 1; this module fixes the interface
and the stage arithmetic so the policy can be built against it.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from tensorwire.chain.gateway import MetagraphView, NeuronView

__all__ = [
    "BLOCK_TIME_S",
    "DEFAULT_SOFT_AGE_S",
    "MetagraphSource",
    "RefreshListener",
    "StalenessStage",
    "StalenessThresholds",
    "default_max_age_s",
]

BLOCK_TIME_S = 12.0
"""Mainnet and testnet block time, used to turn a tempo into seconds."""

DEFAULT_SOFT_AGE_S = 900.0
"""Default ``TW_METAGRAPH_SOFT_AGE_S``."""


class StalenessStage(enum.IntEnum):
    """How usable the current snapshot is.

    The integer value is what the ``tw_metagraph_degraded`` gauge reports
    (Appendix B).
    """

    FRESH = 0
    """Younger than the soft age: normal operation."""

    DEGRADED = 1
    """Between soft and max age: normal policy on the last snapshot, warn."""

    KNOWN_CALLERS_ONLY = 2
    """Older than max age, or no snapshot yet: only previously accepted callers."""


def default_max_age_s(tempo: int, *, block_time_s: float = BLOCK_TIME_S) -> float:
    """Default ``TW_METAGRAPH_MAX_AGE_S``: two tempos, in seconds.

    8,640 s at the default tempo of 360 blocks.
    """
    if tempo <= 0:
        raise ValueError("tempo must be positive")
    if block_time_s <= 0:
        raise ValueError("block_time_s must be positive")
    return 2 * tempo * block_time_s


@dataclass(frozen=True, slots=True)
class StalenessThresholds:
    """Snapshot age limits, in seconds. ``soft_age_s < max_age_s``."""

    soft_age_s: float
    max_age_s: float

    def __post_init__(self) -> None:
        if not 0 < self.soft_age_s < self.max_age_s:
            raise ValueError("thresholds must satisfy 0 < soft_age_s < max_age_s")

    @classmethod
    def for_tempo(
        cls,
        tempo: int,
        *,
        soft_age_s: float | None = None,
        max_age_s: float | None = None,
    ) -> StalenessThresholds:
        """Build thresholds from operator settings, filling the defaults from ``tempo``.

        ``None`` means "not set by the operator". ``max_age_s`` defaults to two
        tempos. ``soft_age_s`` defaults to :data:`DEFAULT_SOFT_AGE_S`, capped at
        half the max age so a short tempo (localnet: tempo 10 gives 240 s)
        still yields a valid degraded stage. Values the operator set are used
        as given and must satisfy ``soft_age_s < max_age_s``.
        """
        max_age = default_max_age_s(tempo) if max_age_s is None else max_age_s
        if soft_age_s is None:
            soft_age_s = min(DEFAULT_SOFT_AGE_S, max_age / 2)
        return cls(soft_age_s=soft_age_s, max_age_s=max_age)

    def stage_for(self, age_s: float | None) -> StalenessStage:
        """Return the stage for a snapshot of ``age_s`` seconds.

        ``None`` (no snapshot yet) is :attr:`StalenessStage.KNOWN_CALLERS_ONLY`,
        so a cache that never loaded fails closed. As in the spec table, fresh
        is ``age < soft_age_s`` and known-callers-only is ``age > max_age_s``;
        both boundary values are degraded.
        """
        if age_s is None or age_s > self.max_age_s:
            return StalenessStage.KNOWN_CALLERS_ONLY
        if age_s >= self.soft_age_s:
            return StalenessStage.DEGRADED
        return StalenessStage.FRESH


RefreshListener = Callable[[MetagraphView], None]
"""Called synchronously with each new snapshot, right after it is stored."""


@runtime_checkable
class MetagraphSource(Protocol):
    """What the miner, policy and sidecar read from the metagraph cache.

    The policy's known-callers set (spec 8.5.1) is cleared from a refresh
    listener: a listener runs on every successful refresh, and a new snapshot
    is always :attr:`StalenessStage.FRESH` when it arrives.
    """

    @property
    def netuid(self) -> int:
        """The subnet this cache follows."""
        ...

    @property
    def thresholds(self) -> StalenessThresholds:
        """The age limits in force."""
        ...

    def snapshot(self) -> MetagraphView | None:
        """The latest snapshot, or ``None`` before the first successful fetch."""
        ...

    def age_s(self) -> float | None:
        """Seconds since the latest snapshot was fetched, or ``None``."""
        ...

    def stage(self) -> StalenessStage:
        """The current stage: ``thresholds.stage_for(age_s())``."""
        ...

    def by_hotkey(self, hotkey: str) -> NeuronView | None:
        """Look ``hotkey`` up in the latest snapshot; ``None`` if absent."""
        ...

    def add_refresh_listener(self, listener: RefreshListener) -> None:
        """Register ``listener`` to run after every successful refresh."""
        ...

    async def start(self) -> None:
        """Fetch the first snapshot (blocking), then refresh in the background.

        Raises if no snapshot arrives within the startup timeout.
        """
        ...

    async def stop(self) -> None:
        """Stop the background refresh. Safe to call more than once."""
        ...

    async def refresh_now(self) -> MetagraphView:
        """Fetch a snapshot immediately, store it and notify listeners."""
        ...
