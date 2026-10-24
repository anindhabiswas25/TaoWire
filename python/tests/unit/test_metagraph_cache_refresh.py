"""MetagraphCache (spec 8.5.1): startup, background refresh, staleness, failures.

Runs against FakeChain with injected faults. Time is a fake clock shared by
FakeChain (snapshot stamps) and the cache (ages); the cache's sleeps are
released one at a time by the test, so the refresh loop is deterministic.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
from typing import Any

import pytest

from taowire.chain.gateway import ChainUnavailable, MetagraphView, SubnetNotFound
from taowire.chain.metagraph_cache import (
    DEFAULT_TEMPO,
    MetagraphCache,
    MetagraphSource,
    StalenessStage,
    StalenessThresholds,
)
from taowire.testing.fake_chain import FakeChain

NETUID = 2
VALIDATOR = "5Validator"
MINER = "5Miner"
STALE_MESSAGE = "metagraph snapshot is stale"


class Clock:
    """A monotonic clock plus a sleep that waits until the test releases it.

    With ``auto=True`` every sleep returns at once and just advances time.
    """

    def __init__(self, *, auto: bool = False) -> None:
        self.now = 1000.0
        self.auto = auto
        self.delays: list[float] = []
        self._pending: list[tuple[float, asyncio.Future[None]]] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        self.delays.append(delay)
        if self.auto:
            self.now += delay
            await asyncio.sleep(0)
            return
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._pending.append((delay, future))
        await future

    async def release(self) -> float:
        """Let the oldest pending sleep finish (advancing time), then settle."""
        for _ in range(100):
            if self._pending:
                break
            await asyncio.sleep(0)
        delay, future = self._pending.pop(0)
        self.now += delay
        future.set_result(None)
        for _ in range(20):
            await asyncio.sleep(0)
        return delay


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def chain(clock: Clock) -> FakeChain:
    chain = FakeChain(monotonic=clock)
    chain.add_subnet(NETUID, tempo=10)
    chain.register(NETUID, VALIDATOR, validator_permit=True, stake_tao=1000)
    chain.register(NETUID, MINER)
    return chain


def _cache(chain: FakeChain, clock: Clock, **kwargs: Any) -> MetagraphCache:
    kwargs.setdefault("refresh_s", 100.0)
    return MetagraphCache(
        chain, NETUID, monotonic=clock, sleep=clock.sleep, jitter=lambda: 0.5, **kwargs
    )


async def _started(chain: FakeChain, clock: Clock, **kwargs: Any) -> MetagraphCache:
    await chain.connect()
    cache = _cache(chain, clock, **kwargs)
    await cache.start()
    return cache


def test_implements_source(chain: FakeChain, clock: Clock) -> None:
    assert isinstance(_cache(chain, clock), MetagraphSource)


@pytest.mark.parametrize("kwargs", [{"refresh_s": 0}, {"startup_timeout_s": 0}])
def test_rejects_bad_settings(
    chain: FakeChain, clock: Clock, kwargs: dict[str, Any]
) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        _cache(chain, clock, **kwargs)


def test_before_start_fails_closed(chain: FakeChain, clock: Clock) -> None:
    cache = _cache(chain, clock)
    assert cache.snapshot() is None
    assert cache.age_s() is None
    assert cache.stage() is StalenessStage.KNOWN_CALLERS_ONLY
    assert cache.by_hotkey(VALIDATOR) is None
    assert cache.thresholds == StalenessThresholds.for_tempo(DEFAULT_TEMPO)
    assert cache.netuid == NETUID
    assert not cache.running


async def test_start_loads_snapshot_and_index(chain: FakeChain, clock: Clock) -> None:
    cache = await _started(chain, clock)
    try:
        snap = cache.snapshot()
        assert snap is not None
        assert snap.netuid == NETUID
        assert cache.age_s() == 0.0
        assert cache.stage() is StalenessStage.FRESH
        validator = cache.by_hotkey(VALIDATOR)
        assert validator is not None
        assert validator.validator_permit
        assert cache.by_hotkey("5Nobody") is None
        # tempo 10 on a 12 s block chain: max 240 s, soft 120 s
        assert cache.thresholds == StalenessThresholds(120.0, 240.0)
        assert cache.running
        await cache.start()  # idempotent
    finally:
        await cache.stop()
        await cache.stop()
    assert not cache.running


async def test_operator_thresholds(chain: FakeChain, clock: Clock) -> None:
    cache = await _started(chain, clock, soft_age_s=30.0, max_age_s=60.0)
    await cache.stop()
    assert cache.thresholds == StalenessThresholds(30.0, 60.0)


async def test_explicit_soft_age_too_large_for_tempo(
    chain: FakeChain, clock: Clock
) -> None:
    await chain.connect()
    cache = _cache(chain, clock, soft_age_s=900.0)
    with pytest.raises(ValueError, match="thresholds must satisfy"):
        await cache.start()


async def test_startup_retries_until_chain_answers(
    chain: FakeChain, clock: Clock
) -> None:
    clock.auto = True
    chain.fail_next("metagraph", times=3)
    cache = await _started(chain, clock)
    await cache.stop()
    assert cache.snapshot() is not None
    assert cache.refresh_failures_total == 3
    assert cache.consecutive_failures == 0
    assert cache.last_error is None
    assert clock.delays[:3] == [5.0, 10.0, 20.0]


async def test_startup_timeout(chain: FakeChain, clock: Clock) -> None:
    clock.auto = True
    chain.fail_next("metagraph", times=1000)
    await chain.connect()
    cache = _cache(chain, clock, startup_timeout_s=60.0)
    with pytest.raises(ChainUnavailable, match="no metagraph for subnet 2 within 60s"):
        await cache.start()
    assert not cache.running
    assert cache.snapshot() is None
    assert sum(clock.delays) == pytest.approx(60.0)


async def test_startup_attempt_that_hangs_is_bounded(chain: FakeChain) -> None:
    class HangingChain(FakeChain):
        async def metagraph(self, netuid: int) -> MetagraphView:
            await asyncio.Event().wait()
            raise AssertionError

    hanging = HangingChain()
    await hanging.connect()
    cache = MetagraphCache(hanging, NETUID, startup_timeout_s=0.05)
    with pytest.raises(ChainUnavailable, match="TimeoutError"):
        await cache.start()
    assert cache.refresh_failures_total >= 1


async def test_startup_unknown_subnet_fails_at_once(clock: Clock) -> None:
    chain = FakeChain(monotonic=clock)
    await chain.connect()
    cache = _cache(chain, clock)
    with pytest.raises(SubnetNotFound):
        await cache.start()
    assert clock.delays == []


async def test_background_refresh_with_jitter(chain: FakeChain, clock: Clock) -> None:
    jitters = iter([0.0, 1.0, 0.5])
    await chain.connect()
    cache = MetagraphCache(
        chain,
        NETUID,
        refresh_s=100.0,
        monotonic=clock,
        sleep=clock.sleep,
        jitter=lambda: next(jitters),
    )
    seen: list[int] = []
    cache.add_refresh_listener(lambda snap: seen.append(snap.block))
    await cache.start()
    try:
        chain.advance(5)
        assert await clock.release() == pytest.approx(90.0)  # -10%
        chain.advance(5)
        assert await clock.release() == pytest.approx(110.0)  # +10%
        assert seen == [1, 6, 11]  # startup snapshot, then two refreshes
        snap = cache.snapshot()
        assert snap is not None
        assert snap.block == 11
        assert cache.age_s() == 0.0
    finally:
        await cache.stop()


async def test_listener_sees_every_refresh_including_first(
    chain: FakeChain, clock: Clock
) -> None:
    await chain.connect()
    cache = _cache(chain, clock)
    snaps: list[MetagraphView] = []
    cache.add_refresh_listener(snaps.append)
    await cache.start()
    await cache.refresh_now()
    await cache.stop()
    assert len(snaps) == 2
    assert snaps[-1] is cache.snapshot()


async def test_failing_listener_does_not_stop_others(
    chain: FakeChain, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    await chain.connect()
    cache = _cache(chain, clock)
    calls: list[str] = []

    def bad(_: MetagraphView) -> None:
        raise RuntimeError("listener bug")

    cache.add_refresh_listener(bad)
    cache.add_refresh_listener(lambda _: calls.append("ok"))
    with caplog.at_level(logging.ERROR, logger="taowire.chain"):
        await cache.refresh_now()
    assert calls == ["ok"]
    assert cache.snapshot() is not None
    assert "metagraph refresh listener failed" in caplog.text


async def test_staleness_stages_during_an_outage(
    chain: FakeChain, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    cache = await _started(chain, clock)  # soft 120 s, max 240 s
    failures: list[BaseException] = []
    cache.add_failure_listener(failures.append)
    chain.fail_next("metagraph", times=1000)
    try:
        with caplog.at_level(logging.WARNING, logger="taowire.chain"):
            assert await clock.release() == 100.0  # refresh fails at t=100
            assert cache.stage() is StalenessStage.FRESH
            assert await clock.release() == 5.0
            assert await clock.release() == 10.0  # t=115
            assert cache.stage() is StalenessStage.FRESH
            assert await clock.release() == 20.0  # t=135
            assert cache.stage() is StalenessStage.DEGRADED
            for _ in range(3):
                await clock.release()  # 40, 80, 100(capped) -> t=355
            assert cache.age_s() == pytest.approx(355.0)
            assert cache.stage() is StalenessStage.KNOWN_CALLERS_ONLY
    finally:
        await cache.stop()
    # the old snapshot is kept for the policy to use
    assert cache.by_hotkey(VALIDATOR) is not None
    assert cache.refresh_failures_total == 7
    assert cache.consecutive_failures == 7
    assert len(failures) == 7
    assert isinstance(failures[0], ChainUnavailable)
    assert cache.last_error is not None
    assert cache.last_error.startswith("ChainUnavailable")
    stale = [
        r for r in caplog.records if r.getMessage() == "metagraph snapshot is stale"
    ]
    # degraded at t=135, then rate-limited to one per 300 s
    assert [r.stage for r in stale] == ["degraded"]  # type: ignore[attr-defined]


async def test_recovery_after_outage(chain: FakeChain, clock: Clock) -> None:
    cache = await _started(chain, clock)
    chain.fail_next("metagraph", times=2)
    try:
        await clock.release()
        await clock.release()
        assert cache.consecutive_failures == 2
        chain.advance(3)
        assert await clock.release() == 10.0
        assert cache.consecutive_failures == 0
        assert cache.last_error is None
        assert cache.stage() is StalenessStage.FRESH
        assert await clock.release() == 100.0  # back on the normal schedule
    finally:
        await cache.stop()


async def test_stale_warning_repeats_every_five_minutes(
    chain: FakeChain, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    cache = await _started(chain, clock, refresh_s=200.0)
    chain.fail_next("metagraph", times=1000)
    try:
        with caplog.at_level(logging.WARNING, logger="taowire.chain"):
            for _ in range(8):
                await clock.release()
    finally:
        await cache.stop()
    stale = [
        r for r in caplog.records if r.getMessage() == "metagraph snapshot is stale"
    ]
    times = [r.age_s for r in stale]  # type: ignore[attr-defined]
    assert len(times) >= 2
    assert all(b - a >= 300 for a, b in itertools.pairwise(times))


async def test_unexpected_error_does_not_kill_the_loop(
    chain: FakeChain, clock: Clock
) -> None:
    cache = await _started(chain, clock)
    chain.fail_next("metagraph", error=KeyError("sdk bug"))
    try:
        await clock.release()
        assert cache.running
        assert cache.last_error is not None
        assert cache.last_error.startswith("KeyError")
        await clock.release()
        assert cache.consecutive_failures == 0
    finally:
        await cache.stop()


async def test_failing_failure_listener_is_contained(
    chain: FakeChain, clock: Clock
) -> None:
    await chain.connect()
    cache = _cache(chain, clock)

    def bad(_: BaseException) -> None:
        raise RuntimeError("metrics bug")

    cache.add_failure_listener(bad)
    chain.fail_next("metagraph")
    with pytest.raises(ChainUnavailable):
        await cache.refresh_now()
    assert cache.refresh_failures_total == 1


async def test_lagging_endpoint_is_not_stored(chain: FakeChain, clock: Clock) -> None:
    cache = await _started(chain, clock)
    await cache.stop()
    chain.advance(10)
    newer = await cache.refresh_now()
    chain._state.block -= 5  # an endpoint that is behind
    with pytest.raises(ChainUnavailable, match="endpoint is behind"):
        await cache.refresh_now()
    assert cache.snapshot() is newer
    assert cache.refresh_failures_total == 1


async def test_wrong_netuid_is_rejected(chain: FakeChain, clock: Clock) -> None:
    class WrongSubnet(FakeChain):
        async def metagraph(self, netuid: int) -> MetagraphView:
            view = await super().metagraph(netuid)
            return MetagraphView(
                netuid=netuid + 1,
                block=view.block,
                fetched_at_monotonic=view.fetched_at_monotonic,
                neurons=view.neurons,
                tempo=view.tempo,
            )

    wrong = WrongSubnet(monotonic=clock)
    wrong.add_subnet(NETUID)
    await wrong.connect()
    cache = _cache(wrong, clock)
    with pytest.raises(ChainUnavailable, match="expected 2"):
        await cache.refresh_now()


async def test_tempo_change_updates_thresholds(chain: FakeChain, clock: Clock) -> None:
    cache = await _started(chain, clock)
    await cache.stop()
    chain.set_hyperparameters(NETUID, tempo=360)
    await cache.refresh_now()
    assert cache.thresholds == StalenessThresholds(900.0, 8640.0)


async def test_snapshot_from_the_future_has_age_zero(
    chain: FakeChain, clock: Clock
) -> None:
    cache = await _started(chain, clock)
    await cache.stop()
    clock.now -= 50
    assert cache.age_s() == 0.0


async def test_known_callers_cleared_by_listener(
    chain: FakeChain, clock: Clock
) -> None:
    """The pattern policy/ uses: a fresh snapshot clears the known-callers set."""
    cache = await _started(chain, clock)
    await cache.stop()
    known = {VALIDATOR: 1.0}
    cache.add_refresh_listener(lambda _: known.clear())
    await cache.refresh_now()
    assert known == {}


async def test_from_settings(chain: FakeChain, clock: Clock) -> None:
    from types import SimpleNamespace

    settings = SimpleNamespace(
        netuid=NETUID,
        metagraph_refresh_s=60,
        metagraph_soft_age_s=None,
        metagraph_max_age_s=None,
        startup_timeout_s=30,
    )
    failures: list[None] = []
    await chain.connect()
    cache = MetagraphCache.from_settings(
        chain, settings, on_refresh_failure=lambda: failures.append(None)
    )
    assert (cache.netuid, cache._refresh_s, cache._startup_timeout_s) == (
        NETUID,
        60,
        30,
    )
    chain.fail_next("metagraph")
    with pytest.raises(ChainUnavailable):
        await cache.refresh_now()
    assert failures == [None]
    await cache.refresh_now()
    assert cache.thresholds == StalenessThresholds(120.0, 240.0)
    assert MetagraphCache.from_settings(chain, settings)._failure_listeners == []
