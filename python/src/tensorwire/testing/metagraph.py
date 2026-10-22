"""A :class:`~tensorwire.chain.metagraph_cache.MetagraphSource` for tests.

:class:`FakeMetagraphSource` reads snapshots from any ``ChainGateway``
(usually ``FakeChain``) only when the test calls :meth:`refresh_now` (or
:meth:`start`); there is no background task. Ages come from an injected
monotonic clock, so a test can walk through the staleness stages of spec
8.5.1 deterministically::

    clock = FakeClock()
    source = FakeMetagraphSource(chain, netuid=1, clock=clock.monotonic)
    await source.start()
    clock.advance(10_000)          # past the max age
    assert source.stage() is StalenessStage.KNOWN_CALLERS_ONLY
"""

from __future__ import annotations

import time
from collections.abc import Callable

from tensorwire.chain.gateway import ChainGateway, MetagraphView, NeuronView
from tensorwire.chain.metagraph_cache import (
    RefreshListener,
    StalenessStage,
    StalenessThresholds,
)

__all__ = ["FakeMetagraphSource"]


class FakeMetagraphSource:
    """Snapshots on demand from ``gateway``; thresholds from the subnet's tempo.

    ``soft_age_s`` / ``max_age_s`` are the operator settings (``None`` =
    unset), resolved with ``StalenessThresholds.for_tempo`` on every
    snapshot, as the real cache does. Before the first snapshot the tempo is
    taken as 360.
    """

    def __init__(
        self,
        gateway: ChainGateway,
        netuid: int,
        *,
        soft_age_s: float | None = None,
        max_age_s: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._gateway = gateway
        self._netuid = netuid
        self._soft = soft_age_s
        self._max = max_age_s
        self._clock = clock
        self._snapshot: MetagraphView | None = None
        self._thresholds = StalenessThresholds.for_tempo(
            360, soft_age_s=soft_age_s, max_age_s=max_age_s
        )
        self._listeners: list[RefreshListener] = []
        self.started = False
        self.stopped = False

    @property
    def netuid(self) -> int:
        """The subnet this source follows."""
        return self._netuid

    @property
    def thresholds(self) -> StalenessThresholds:
        """The age limits in force."""
        return self._thresholds

    def snapshot(self) -> MetagraphView | None:
        """The latest snapshot, or ``None``."""
        return self._snapshot

    def age_s(self) -> float | None:
        """Seconds since the latest snapshot was fetched, or ``None``."""
        if self._snapshot is None:
            return None
        return max(0.0, self._clock() - self._snapshot.fetched_at_monotonic)

    def stage(self) -> StalenessStage:
        """The current stage."""
        return self._thresholds.stage_for(self.age_s())

    def by_hotkey(self, hotkey: str) -> NeuronView | None:
        """Look ``hotkey`` up in the latest snapshot."""
        return None if self._snapshot is None else self._snapshot.by_hotkey(hotkey)

    def add_refresh_listener(self, listener: RefreshListener) -> None:
        """Run ``listener`` after every successful refresh."""
        self._listeners.append(listener)

    async def start(self) -> None:
        """Fetch the first snapshot."""
        await self.refresh_now()
        self.started = True

    async def stop(self) -> None:
        """Nothing runs in the background; only records the call."""
        self.stopped = True

    async def refresh_now(self) -> MetagraphView:
        """Fetch a snapshot, store it and notify listeners."""
        mg = await self._gateway.metagraph(self._netuid)
        self._thresholds = StalenessThresholds.for_tempo(
            mg.tempo, soft_age_s=self._soft, max_age_s=self._max
        )
        self._snapshot = mg
        for listener in self._listeners:
            listener(mg)
        return mg
