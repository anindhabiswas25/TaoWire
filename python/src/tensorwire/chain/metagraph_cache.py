"""Metagraph cache interface and staged staleness (spec 8.5.1).

The cache refreshes a subnet snapshot in the background and reports how old
it is as one of three stages. The caller policy (``policy/``) decides what
each stage means for a request; the cache only measures.
:class:`MetagraphCache` is the implementation of :class:`MetagraphSource`.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from tensorwire.chain.gateway import (
    ChainGateway,
    ChainUnavailable,
    GatewayError,
    MetagraphView,
    NeuronView,
    SubnetNotFound,
)

__all__ = [
    "BLOCK_TIME_S",
    "DEFAULT_SOFT_AGE_S",
    "DEFAULT_TEMPO",
    "FailureListener",
    "MetagraphCache",
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


# ---------------------------------------------------------------------------
# MetagraphCache: the background implementation.

_log = logging.getLogger("tensorwire.chain")

DEFAULT_TEMPO = 360
"""Tempo assumed for the thresholds until the first snapshot reports the real one."""

DEFAULT_REFRESH_S = 120.0
"""Default ``TW_METAGRAPH_REFRESH_S``."""

REFRESH_JITTER = 0.1
"""Refresh intervals vary by +/-10% so miners do not hit endpoints in step."""

FAILURE_BACKOFF_BASE_S = 5.0
"""First retry delay after a failed refresh; doubles up to the refresh interval."""

DEGRADED_WARNING_EVERY_S = 300.0
"""A stale snapshot is logged at WARNING at most this often (spec 8.5.1)."""

FailureListener = Callable[[BaseException], None]
"""Called synchronously with the error of each failed refresh."""


class MetagraphCache:
    """Keeps a fresh :class:`MetagraphView` of one subnet (spec 8.5.1).

    ``start()`` blocks until the first snapshot arrives (or raises after
    ``startup_timeout_s``), then a background task refreshes every
    ``refresh_s`` seconds, +/-10% jitter. A failed refresh keeps the old
    snapshot, counts the failure, notifies the failure listeners and retries
    with backoff (5 s doubling up to ``refresh_s``); the gateway itself
    rotates through its fallback endpoints. A snapshot from an earlier block
    than the current one (a lagging endpoint) is not stored and counts as a
    failure.

    ``soft_age_s`` / ``max_age_s`` are the operator's settings; ``None``
    means "not set" and derives the default from the subnet's tempo (see
    :meth:`StalenessThresholds.for_tempo`). Thresholds are recomputed when the
    tempo changes.

    Staleness is measured from ``MetagraphView.fetched_at_monotonic`` with
    ``monotonic``, so the gateway and the cache must use the same clock
    (both default to ``time.monotonic``).
    """

    def __init__(
        self,
        gateway: ChainGateway,
        netuid: int,
        *,
        refresh_s: float = DEFAULT_REFRESH_S,
        soft_age_s: float | None = None,
        max_age_s: float | None = None,
        startup_timeout_s: float = 120.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        if refresh_s <= 0 or startup_timeout_s <= 0:
            raise ValueError("refresh_s and startup_timeout_s must be positive")
        self._gateway = gateway
        self._netuid = netuid
        self._refresh_s = refresh_s
        self._soft_age_s = soft_age_s
        self._max_age_s = max_age_s
        self._startup_timeout_s = startup_timeout_s
        self._monotonic = monotonic
        self._sleep = sleep
        self._jitter = jitter
        self._thresholds = StalenessThresholds.for_tempo(
            DEFAULT_TEMPO, soft_age_s=soft_age_s, max_age_s=max_age_s
        )
        self._snapshot: MetagraphView | None = None
        self._listeners: list[RefreshListener] = []
        self._failure_listeners: list[FailureListener] = []
        self._task: asyncio.Task[None] | None = None
        self._refresh_lock = asyncio.Lock()
        self._last_warning: float | None = None
        self.refresh_failures_total = 0
        """Failed refreshes since creation (``tw_metagraph_refresh_failures_total``)."""
        self.consecutive_failures = 0
        """Failed refreshes since the last success."""
        self.last_error: str | None = None
        """Type and message of the latest failure, or ``None`` after a success."""

    @classmethod
    def from_settings(
        cls,
        gateway: ChainGateway,
        settings: Any,
        *,
        on_refresh_failure: Callable[[], None] | None = None,
    ) -> MetagraphCache:
        """Build a cache from ``tensorwire.config.CommonSettings`` (or a subclass).

        Reads ``netuid``, ``metagraph_refresh_s``, ``metagraph_soft_age_s``
        and ``metagraph_max_age_s`` (``None`` = unset, derived from the tempo)
        and ``startup_timeout_s``. ``on_refresh_failure`` is called once per
        failed refresh (for ``tw_metagraph_refresh_failures_total``).
        """
        cache = cls(
            gateway,
            int(settings.netuid),
            refresh_s=float(settings.metagraph_refresh_s),
            soft_age_s=settings.metagraph_soft_age_s,
            max_age_s=settings.metagraph_max_age_s,
            startup_timeout_s=float(settings.startup_timeout_s),
        )
        if on_refresh_failure is not None:
            callback = on_refresh_failure
            cache.add_failure_listener(lambda _error: callback())
        return cache

    # -- MetagraphSource -------------------------------------------------------

    @property
    def netuid(self) -> int:
        """The subnet this cache follows."""
        return self._netuid

    @property
    def thresholds(self) -> StalenessThresholds:
        """The age limits in force (derived from the latest snapshot's tempo)."""
        return self._thresholds

    @property
    def running(self) -> bool:
        """Whether the background refresh task is running."""
        return self._task is not None and not self._task.done()

    def snapshot(self) -> MetagraphView | None:
        """The latest snapshot, or ``None`` before the first successful fetch."""
        return self._snapshot

    def age_s(self) -> float | None:
        """Seconds since the latest snapshot was fetched (>= 0), or ``None``."""
        if self._snapshot is None:
            return None
        return max(0.0, self._monotonic() - self._snapshot.fetched_at_monotonic)

    def stage(self) -> StalenessStage:
        """The current stage: ``thresholds.stage_for(age_s())``."""
        return self._thresholds.stage_for(self.age_s())

    def by_hotkey(self, hotkey: str) -> NeuronView | None:
        """Look ``hotkey`` up in the latest snapshot (O(1)); ``None`` if absent."""
        snap = self._snapshot
        return None if snap is None else snap.by_hotkey(hotkey)

    def add_refresh_listener(self, listener: RefreshListener) -> None:
        """Run ``listener(snapshot)`` after every successful refresh.

        Listeners run in registration order; an exception in one is logged and
        does not stop the others or the refresh.
        """
        self._listeners.append(listener)

    def add_failure_listener(self, listener: FailureListener) -> None:
        """Run ``listener(error)`` after every failed refresh (e.g. for metrics)."""
        self._failure_listeners.append(listener)

    async def start(self) -> None:
        """Fetch the first snapshot, then refresh in the background.

        Retries with backoff until ``startup_timeout_s`` has passed, then
        raises :class:`ChainUnavailable`. :class:`SubnetNotFound` is raised at
        once: retrying cannot fix a wrong netuid. Calling ``start`` again while
        running does nothing.
        """
        if self.running:
            return
        if self._snapshot is None:
            await self._first_fetch()
        self._task = asyncio.create_task(
            self._run(), name=f"tensorwire-metagraph-{self._netuid}"
        )

    async def stop(self) -> None:
        """Stop the background refresh. Safe to call more than once."""
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def refresh_now(self) -> MetagraphView:
        """Fetch a snapshot now, store it and notify listeners.

        Raises the gateway's error (the old snapshot is kept); failures are
        counted the same way as in the background loop.
        """
        async with self._refresh_lock:
            try:
                snap = await self._gateway.metagraph(self._netuid)
                self._check(snap)
            except Exception as e:
                self._record_failure(e)
                raise
            self._store(snap)
            return snap

    # -- internals -------------------------------------------------------------

    async def _first_fetch(self) -> None:
        deadline = self._monotonic() + self._startup_timeout_s
        failures = 0
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise ChainUnavailable(
                    f"no metagraph for subnet {self._netuid} within "
                    f"{self._startup_timeout_s:g}s ({self.last_error})"
                )
            try:
                await asyncio.wait_for(self.refresh_now(), remaining)
                return
            except SubnetNotFound:
                raise
            except (GatewayError, TimeoutError, asyncio.TimeoutError) as e:
                if isinstance(e, (TimeoutError, asyncio.TimeoutError)):
                    self._record_failure(e)
                failures += 1
                delay = min(self._failure_delay(failures), max(0.0, remaining))
                await self._sleep(delay)

    async def _run(self) -> None:
        failures = 0
        while True:
            delay = (
                self._failure_delay(failures)
                if failures
                else self._refresh_s * (1 + REFRESH_JITTER * (2 * self._jitter() - 1))
            )
            await self._sleep(delay)
            try:
                await self.refresh_now()
                failures = 0
            except Exception:  # noqa: BLE001 - counted and logged; the loop must survive
                failures += 1
            self._warn_if_stale()

    def _failure_delay(self, failures: int) -> float:
        base = min(self._refresh_s, FAILURE_BACKOFF_BASE_S * 2 ** (failures - 1))
        return float(base * (1 + REFRESH_JITTER * (2 * self._jitter() - 1)))

    def _check(self, snap: MetagraphView) -> None:
        if snap.netuid != self._netuid:
            raise ChainUnavailable(
                f"gateway returned subnet {snap.netuid}, expected {self._netuid}"
            )
        current = self._snapshot
        if current is not None and snap.block < current.block:
            raise ChainUnavailable(
                f"endpoint is behind: block {snap.block} < cached {current.block}"
            )

    def _store(self, snap: MetagraphView) -> None:
        if self._snapshot is None or snap.tempo != self._snapshot.tempo:
            self._thresholds = StalenessThresholds.for_tempo(
                snap.tempo, soft_age_s=self._soft_age_s, max_age_s=self._max_age_s
            )
        self._snapshot = snap
        self.consecutive_failures = 0
        self.last_error = None
        self._last_warning = None
        for listener in list(self._listeners):
            try:
                listener(snap)
            except Exception:  # noqa: BLE001 - one bad listener must not stop refreshes
                _log.exception("metagraph refresh listener failed")

    def _record_failure(self, error: BaseException) -> None:
        self.refresh_failures_total += 1
        self.consecutive_failures += 1
        self.last_error = f"{type(error).__name__}: {error}"
        _log.warning(
            "metagraph refresh failed",
            extra={
                "netuid": self._netuid,
                "consecutive_failures": self.consecutive_failures,
                "error": type(error).__name__,
            },
        )
        for listener in list(self._failure_listeners):
            try:
                listener(error)
            except Exception:  # noqa: BLE001 - one bad listener must not stop refreshes
                _log.exception("metagraph failure listener failed")

    def _warn_if_stale(self) -> None:
        stage = self.stage()
        if stage is StalenessStage.FRESH:
            return
        now = self._monotonic()
        if (
            self._last_warning is not None
            and now - self._last_warning < DEGRADED_WARNING_EVERY_S
        ):
            return
        self._last_warning = now
        _log.warning(
            "metagraph snapshot is stale",
            extra={
                "netuid": self._netuid,
                "stage": stage.name.lower(),
                "age_s": self.age_s(),
                "last_error": self.last_error,
            },
        )
