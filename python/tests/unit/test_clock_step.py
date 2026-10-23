"""Clock-step guard and the 2x retention rule (spec 8.4.3-8.4.4, D21, G4-3).

Every clock is injected: the wall clock and the monotonic clock move
independently, as they do when NTP steps the wall clock.
"""

from __future__ import annotations

from typing import Any

import fakeredis
import pytest
import structlog.testing

from tensorwire.auth.clock import ClockStepGuard
from tensorwire.auth.nonce_store import (
    MemoryNonceStore,
    NonceStore,
    RedisNonceStore,
    StepGuardedNonceStore,
    check_retention_margin,
)
from tensorwire.errors import ReplayStoreUnavailable

S = 10**9
RETENTION = 60.0
MARGIN = RETENTION - 12.0  # defaults: max_age 10 + allowed_skew 2


class Clocks:
    """A wall clock (ns) and a monotonic clock (s), stepped independently."""

    def __init__(self) -> None:
        self.wall = 1_700_000_000 * S
        self.mono = 1_000.0

    def wall_ns(self) -> int:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall += int(seconds * S)
        self.mono += seconds

    def step_wall(self, seconds: float) -> None:
        self.wall += int(seconds * S)


@pytest.fixture
def clocks() -> Clocks:
    return Clocks()


def guard(clocks: Clocks, **kwargs: Any) -> ClockStepGuard:
    return ClockStepGuard(
        margin_s=MARGIN,
        hold_s=RETENTION,
        wall_ns=clocks.wall_ns,
        monotonic=clocks.monotonic,
        **kwargs,
    )


# ---------------------------------------------------------------- 2x rule


@pytest.mark.parametrize(
    ("retention", "ok"), [(23.9, False), (12.0, False), (24.0, True), (60.0, True)]
)
def test_retention_must_cover_twice_the_window(retention: float, ok: bool) -> None:
    if ok:
        assert check_retention_margin(retention, 10, 2) == retention - 12
    else:
        with pytest.raises(ValueError, match=r"at least 2 x .* = 24 s"):
            check_retention_margin(retention, 10, 2)


def test_nan_retention_is_refused() -> None:
    with pytest.raises(ValueError, match="retention too short"):
        check_retention_margin(float("nan"), 10, 2)


# ---------------------------------------------------------------- the guard


def test_steady_clock_never_fails_closed(clocks: Clocks) -> None:
    g = guard(clocks)
    for _ in range(5):
        clocks.advance(30)
        assert not g.check()
    assert g.last_step_s == 0.0
    assert g.margin_s == MARGIN


@pytest.mark.parametrize("step", [3600.0, 1.0, -MARGIN, -0.5])
def test_forward_or_small_steps_only_move_the_baseline(
    clocks: Clocks, step: float
) -> None:
    g = guard(clocks)
    clocks.step_wall(step)
    assert not g.check()
    # The baseline moved: a further small step back is measured from here.
    clocks.step_wall(-1)
    assert not g.check()


def test_backwards_step_fails_closed_for_retention(clocks: Clocks) -> None:
    seen: list[float] = []
    g = guard(clocks, on_step=seen.append)
    with structlog.testing.capture_logs() as logs:
        clocks.step_wall(-(MARGIN + 1))
        assert g.check()
    assert seen == [pytest.approx(MARGIN + 1)]
    assert g.last_step_s == pytest.approx(MARGIN + 1)
    [event] = [e for e in logs if e["event"] == "clock_step_detected"]
    assert event["log_level"] == "error"
    assert event["step_s"] == pytest.approx(MARGIN + 1)
    clocks.advance(RETENTION - 0.1)
    assert g.failing_closed
    clocks.advance(0.1)
    assert not g.failing_closed  # normal service resumes after `retention`
    assert seen == [pytest.approx(MARGIN + 1)]  # logged and reported once


def test_a_second_step_extends_the_window(clocks: Clocks) -> None:
    g = guard(clocks)
    clocks.step_wall(-100)
    assert g.check()
    clocks.advance(50)
    clocks.step_wall(-100)
    assert g.check()
    clocks.advance(RETENTION - 1)
    assert g.check()
    clocks.advance(1)
    assert not g.check()


@pytest.mark.parametrize(
    ("margin", "hold"), [(0, 60), (-1, 60), (48, 0), (float("inf"), 60)]
)
def test_guard_arguments_are_checked(margin: float, hold: float) -> None:
    with pytest.raises(ValueError, match="positive number of seconds"):
        ClockStepGuard(margin_s=margin, hold_s=hold)


# ---------------------------------------------------------------- guarded stores


def memory_store(clocks: Clocks) -> MemoryNonceStore:
    return MemoryNonceStore(RETENTION, clock=clocks.monotonic, wall_ns=clocks.wall_ns)


class ClockedRedis:
    """fakeredis whose key expiry follows the injected monotonic clock.

    Redis expires ``PX`` keys on its own clock, which a step on the miner's
    wall clock does not move. Expiry is simulated by deleting keys whose
    deadline has passed before every command.
    """

    def __init__(self, clocks: Clocks) -> None:
        self._clocks = clocks
        self._r = fakeredis.FakeRedis()
        self._deadline: dict[str, float] = {}

    def set(self, key: str, value: bytes, *, nx: bool, px: int) -> bool | None:
        now = self._clocks.mono
        for k, deadline in list(self._deadline.items()):
            if deadline <= now:
                self._r.delete(k)
                del self._deadline[k]
        ok = self._r.set(key, value, nx=nx)
        if ok:
            self._deadline[key] = now + px / 1000
        return ok

    def ping(self) -> bool:
        return bool(self._r.ping())

    def close(self) -> None:
        self._r.close()


def redis_store(clocks: Clocks) -> RedisNonceStore:
    return RedisNonceStore(
        "redis://unused",
        retention=RETENTION,
        client=ClockedRedis(clocks),  # type: ignore[arg-type]
    )


STORES = {"memory": memory_store, "redis": redis_store}


@pytest.mark.parametrize("kind", sorted(STORES))
def test_unguarded_store_reopens_a_nonce_after_a_step_back(
    clocks: Clocks, kind: str
) -> None:
    """Why the guard exists, on the Redis store (the memory store is safe alone)."""
    store: NonceStore = STORES[kind](clocks)
    nonce = clocks.wall
    assert store.check_and_store("hk", nonce)
    clocks.advance(RETENTION + 1)  # Redis forgot the key on its own clock
    clocks.step_wall(-(RETENTION - 5))  # NTP steps the miner back: nonce is 6 s old
    reopened = store.check_and_store("hk", nonce)
    # The memory store keeps the pair until the wall clock agrees (D21);
    # Redis cannot know about the miner's step.
    assert reopened is (kind == "redis")


@pytest.mark.parametrize("kind", sorted(STORES))
def test_guarded_store_fails_closed_after_a_step_back(
    clocks: Clocks, kind: str
) -> None:
    inner = STORES[kind](clocks)
    store = StepGuardedNonceStore(inner, guard(clocks))
    assert store.retention == RETENTION
    assert store.inner is inner
    nonce = clocks.wall
    assert store.check_and_store("hk", nonce)
    assert not store.check_and_store("hk", nonce)
    clocks.advance(RETENTION + 1)
    clocks.step_wall(-(RETENTION - 5))
    with pytest.raises(ReplayStoreUnavailable):
        store.check_and_store("hk", nonce)  # the replay is not served
    with pytest.raises(ReplayStoreUnavailable):
        store.check_and_store("hk", clocks.wall)  # nor is anything else
    clocks.advance(RETENTION)
    # Window over: the old nonce is now far outside freshness anyway, and
    # new nonces are accepted again.
    assert store.check_and_store("hk", clocks.wall)
    assert store.ping()
    store.close()


def test_guarded_store_without_ping_or_close(clocks: Clocks) -> None:
    class Bare:
        retention = RETENTION

        def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
            return True

    store = StepGuardedNonceStore(Bare(), guard(clocks))
    assert store.guard.margin_s == MARGIN
    assert store.ping()
    store.close()


# ---------------------------------------------------------------- memory store


def test_memory_store_survives_a_wall_clock_step_back() -> None:
    """A backwards wall-clock step must not make a forgotten nonce fresh again.

    Freshness is judged on the wall clock; the pair stays until its nonce is
    older than the retention there too (from eng-b/lang bbcfa78; Go/Rust do
    the same).
    """
    mono, wall = [0.0], [1_000 * S]
    nonce = wall[0]
    store = MemoryNonceStore(24, clock=lambda: mono[0], wall_ns=lambda: wall[0])
    assert store.check_and_store("hk", nonce)
    mono[0], wall[0] = 30.0, nonce + 5 * S  # 30 s passed, wall stepped back 25 s
    assert not store.check_and_store("hk", nonce)
    mono[0], wall[0] = 31.0, nonce + 25 * S
    assert store.check_and_store("hk", nonce)
