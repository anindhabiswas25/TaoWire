"""Score store, miner selection, weight scheduler and hotkey lock (spec 8.9, 8.4.1)."""

from __future__ import annotations

import multiprocessing
import random
from pathlib import Path
from typing import Any

import pytest
import structlog

from taowire.chain.gateway import ChainUnavailable, MetagraphView, SubnetNotFound
from taowire.observability.metrics import Metrics
from taowire.testing.fake_chain import FakeChain
from taowire.validator.lock import HotkeyLock, HotkeyLockHeld
from taowire.validator.scores import RoundRecord, ScoreStore, WeightRecord
from taowire.validator.selection import eligible_miners, select_miners
from taowire.validator.weights import (
    MAX_REPLANS,
    WeightScheduler,
    blocks_from_remediation,
)

NETUID = 7
VALI = "5Vali"


# ---------------------------------------------------------------- scores


def store(tmp_path: Path, alpha: float = 0.5) -> ScoreStore:
    return ScoreStore(tmp_path / "state" / "scores.db", NETUID, alpha=alpha)


def test_ema_and_persistence(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.update({1: 1.0, 2: 0.0}, {1: "a", 2: "b"}, block=10)
    s.update({1: 1.0}, {1: "a"}, block=11)
    assert s.scores() == {1: 0.75, 2: 0.0}
    s.close()
    s.close()  # idempotent
    again = store(tmp_path)
    assert again.scores() == {1: 0.75, 2: 0.0}
    assert again.hotkeys() == {1: "a", 2: "b"}
    assert (tmp_path / "state").stat().st_mode & 0o777 == 0o700


def test_hotkey_change_resets_the_uid(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.update({1: 1.0}, {1: "old"}, block=1)
    s.update({1: 1.0}, {1: "new"}, block=2)  # new owner starts from 0
    assert s.scores() == {1: 0.5}


def test_sync_hotkeys_drops_changed_and_departed(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.update({1: 1.0, 2: 1.0, 3: 1.0}, {1: "a", 2: "b", 3: "c"}, block=1)
    gone = s.sync_hotkeys({1: "a", 2: "B"})
    assert gone == {2: "b", 3: "c"}
    assert s.scores() == {1: 0.5}


@pytest.mark.parametrize(
    ("value", "expected"),
    [(2.0, 0.5), (-1.0, 0.0), (float("nan"), 0.0), (float("inf"), 0.5)],
)
def test_values_are_clamped(tmp_path: Path, value: float, expected: float) -> None:
    s = store(tmp_path)
    s.update({1: value}, {1: "a"}, block=1)
    assert s.scores() == {1: expected}


def test_update_needs_hotkeys(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no hotkey"):
        store(tmp_path).update({9: 1.0}, {}, block=1)


def test_bad_alpha() -> None:
    with pytest.raises(ValueError, match="alpha"):
        ScoreStore(":memory:", NETUID, alpha=0)


def test_history(tmp_path: Path) -> None:
    s = store(tmp_path)
    assert s.next_round_id() == 1
    s.record_round(RoundRecord(1.0, 3, 2, 10.0, 20.0))
    s.record_round(RoundRecord(2.0, 3, 3, None, None))
    assert s.next_round_id() == 3
    assert [r.started_at for r in s.last_rounds()] == [2.0, 1.0]
    s.record_weights(WeightRecord(100, True, None, 2, "0xabc"))
    s.record_weights(WeightRecord(200, False, "rate_limited", 2, None))
    assert s.last_weights(1) == [WeightRecord(200, False, "rate_limited", 2, None)]


def test_subnets_are_separate(tmp_path: Path) -> None:
    shared = tmp_path / "scores.db"
    a = ScoreStore(shared, 1, alpha=1)
    a.update({1: 1.0}, {1: "a"}, block=1)
    assert ScoreStore(shared, 2, alpha=1).scores() == {}


# ---------------------------------------------------------------- selection


async def metagraph(chain: FakeChain) -> MetagraphView:
    await chain.connect()
    return await chain.metagraph(NETUID)


def fleet(n: int = 6) -> FakeChain:
    chain = FakeChain(signer_hotkey=VALI)
    chain.add_subnet(NETUID, tempo=10, weights_rate_limit=5)
    chain.register(NETUID, VALI, validator_permit=True, axon="44.9.9.9:1")
    for i in range(n):
        chain.register(NETUID, f"5Miner{i}", axon=f"44.0.0.{i + 1}:8091")
    chain.register(NETUID, "5NoAxon")
    chain.register(NETUID, "5OtherVali", validator_permit=True, axon="44.8.8.8:1")
    return chain


async def test_selection_defaults() -> None:
    mg = await metagraph(fleet())
    picked = eligible_miners(mg, exclude_hotkeys={VALI})
    assert [n.hotkey for n in picked] == [f"5Miner{i}" for i in range(6)]
    with_vali = eligible_miners(mg, include_validators=True, exclude_hotkeys={VALI})
    assert "5OtherVali" in {n.hotkey for n in with_vali}


async def test_selection_samples_in_uid_order() -> None:
    mg = await metagraph(fleet())
    picked = select_miners(mg, sample_size=3, rng=random.Random(1))
    assert len(picked) == 3
    assert [n.uid for n in picked] == sorted(n.uid for n in picked)
    assert len(select_miners(mg, sample_size=100)) == 6
    with pytest.raises(ValueError, match="sample_size"):
        select_miners(mg, sample_size=0)


# ---------------------------------------------------------------- weights


@pytest.mark.parametrize(
    ("text", "blocks"),
    [("retry in 37 blocks", 37), ("wait 1 block", 1), ("later", None), (None, None)],
)
def test_blocks_from_remediation(text: str | None, blocks: int | None) -> None:
    assert blocks_from_remediation(text) == blocks


def scheduler(chain: FakeChain, **kw: Any) -> WeightScheduler:
    options: dict[str, Any] = {"min_interval_blocks": 10}
    options.update(kw)
    return WeightScheduler(chain, NETUID, VALI, **options)


async def test_weights_follow_the_chain_schedule(tmp_path: Path) -> None:
    chain = fleet(2)
    metrics = Metrics()
    s = store(tmp_path)
    sched = scheduler(chain, store=s, metrics=metrics, version_key=3)
    mg = await metagraph(chain)
    scores = {1: 0.5, 2: 0.0, 99: 1.0}
    assert (await sched.maybe_submit(scores, mg)).reason == "not_due"  # rate limit
    chain.advance(5)
    decision = await sched.maybe_submit(scores, mg)
    assert decision.submitted
    assert decision.n_uids == 1  # zero and unknown UIDs dropped
    (sub,) = chain.weight_submissions()
    assert sub.weights == {1: 0.5}
    assert sub.version_key == 3
    chain.advance(5)  # chain allows it, min interval (10) does not
    assert (await sched.maybe_submit(scores, mg)).reason == "not_due"
    chain.advance(5)
    assert (await sched.maybe_submit(scores, mg)).submitted
    assert s.last_weights(1)[0].ok
    assert metrics.validator_last_weights_block._value.get() == chain.current_block


async def test_all_zero_scores_are_not_submitted() -> None:
    chain = fleet(2)
    chain.advance(10)
    with structlog.testing.capture_logs() as logs:
        d = await scheduler(chain).maybe_submit({1: 0.0}, await metagraph(chain))
    assert d.reason == "no_scores"
    assert any(e["event"] == "tw.no_scores" for e in logs)
    assert chain.weight_submissions() == ()


async def test_rate_limited_waits_the_named_blocks() -> None:
    chain = fleet(2)
    chain.advance(10)
    chain.reject_next("set_weights", "rate_limited", remediation="retry in 4 blocks")
    sched = scheduler(chain)
    mg = await metagraph(chain)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "failed"
    chain.advance(3)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "waiting"
    chain.advance(1)
    assert (await sched.maybe_submit({1: 1.0}, mg)).submitted


async def test_rate_limited_without_count_waits_a_tempo() -> None:
    chain = fleet(2)
    chain.advance(10)
    chain.reject_next("set_weights", "rate_limited", remediation="slow down")
    sched = scheduler(chain)
    mg = await metagraph(chain)
    await sched.maybe_submit({1: 1.0}, mg)
    chain.advance(9)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "waiting"


async def test_not_authorized_stops_until_a_permit_appears() -> None:
    chain = fleet(2)
    chain.advance(10)
    chain.set_permit(NETUID, VALI, False)
    sched = scheduler(chain)
    mg = await metagraph(chain)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "failed"
    assert sched.stopped == "not_authorized"
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "stopped"
    chain.set_permit(NETUID, VALI, True)
    assert (await sched.maybe_submit({1: 1.0}, await metagraph(chain))).submitted
    assert sched.stopped is None


async def test_unregistered_validator_stops_and_resumes() -> None:
    chain = fleet(2)
    sched = scheduler(chain)
    chain.deregister(NETUID, VALI)
    assert (
        await sched.maybe_submit({1: 1.0}, await metagraph(chain))
    ).reason == "stopped"
    assert (
        await sched.maybe_submit({1: 1.0}, await metagraph(chain))
    ).reason == "stopped"
    chain.register(NETUID, VALI, validator_permit=True)
    chain.advance(10)
    assert (await sched.maybe_submit({1: 1.0}, await metagraph(chain))).submitted


async def test_other_rejections_back_off() -> None:
    chain = fleet(2)
    chain.advance(10)
    chain.reject_next("set_weights", "invalid_argument")
    sched = scheduler(chain)
    mg = await metagraph(chain)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "failed"
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "waiting"
    assert sched.stopped is None


# ---------------------------------------------------------------- re-plans
# D32, G5-2: timelocked commits that missed their drand reveal round.

REVEAL = {"expired": "InvalidRevealRound", "too_early": "RevealTooEarly"}


def reject_reveal(chain: FakeChain, code: str = "expired", times: int = 1) -> None:
    chain.reject_next("set_weights", code, times, error_name=REVEAL[code])


def submissions(metrics: Metrics, ok: str, code: str) -> float | None:
    return metrics.registry.get_sample_value(
        "tw_validator_weight_submissions_total", {"ok": ok, "code": code}
    )


@pytest.mark.parametrize("code", ["expired", "too_early"])
async def test_a_missed_reveal_round_is_replanned_from_the_next_block(
    code: str,
) -> None:
    chain = fleet(2)
    chain.advance(10)
    reject_reveal(chain, code)
    metrics = Metrics()
    sched = scheduler(chain, metrics=metrics)
    mg = await metagraph(chain)
    with structlog.testing.capture_logs() as logs:
        d = await sched.maybe_submit({1: 1.0}, mg)
    assert (d.reason, d.replans) == ("replanning", 1)
    (event,) = [e for e in logs if e["event"] == "weights_commit_replanned"]
    assert (event["code"], event["error_name"]) == (code, REVEAL[code])
    assert event["log_level"] == "warning"
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "waiting"  # same block
    chain.advance(1)
    d = await sched.maybe_submit({1: 1.0}, mg)
    assert (d.reason, d.replans) == ("submitted", 1)
    assert chain.calls["set_weights"] == 2  # a new plan and a new extrinsic
    assert len(chain.weight_submissions()) == 1
    assert submissions(metrics, "false", code) == 1
    assert submissions(metrics, "true", "ok") == 1


async def test_replans_are_bounded_per_window_logged_metered_and_stored(
    tmp_path: Path,
) -> None:
    chain = fleet(2)
    chain.advance(10)
    reject_reveal(chain, times=1 + MAX_REPLANS)
    metrics = Metrics()
    s = store(tmp_path)
    sched = scheduler(chain, metrics=metrics, store=s)
    mg = await metagraph(chain)
    start = chain.current_block
    with structlog.testing.capture_logs() as logs:
        for _ in range(MAX_REPLANS):
            assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "replanning"
            chain.advance(1)
        d = await sched.maybe_submit({1: 1.0}, mg)
    assert (d.reason, d.replans) == ("failed", MAX_REPLANS)
    events = [e["event"] for e in logs]
    assert events.count("weights_commit_replanned") == MAX_REPLANS
    (exhausted,) = [e for e in logs if e["event"] == "weights_commit_replan_exhausted"]
    window_end = start + max(5, 10)  # max(weights_rate_limit, tempo)
    assert (exhausted["log_level"], exhausted["wait_until_block"]) == (
        "error",
        window_end,
    )
    assert "weights_rejected" not in events
    assert chain.calls["set_weights"] == 1 + MAX_REPLANS
    assert submissions(metrics, "false", "expired") == 1 + MAX_REPLANS
    rows = s.last_weights(10)
    assert sorted(r.block for r in rows) == [start + i for i in range(1 + MAX_REPLANS)]
    assert all(not r.ok and r.code == "expired" for r in rows)
    chain.advance(window_end - chain.current_block - 1)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "waiting"
    chain.advance(1)
    d = await sched.maybe_submit({1: 1.0}, mg)  # the next window
    assert (d.reason, d.replans) == ("submitted", 0)


async def test_another_error_does_not_reset_the_window_budget() -> None:
    chain = fleet(2)
    chain.advance(10)
    sched = scheduler(chain, min_interval_blocks=0)
    mg = await metagraph(chain)
    reject_reveal(chain)
    assert (await sched.maybe_submit({1: 1.0}, mg)).replans == 1
    chain.advance(1)
    chain.reject_next("set_weights", "invalid_argument")
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "failed"
    chain.advance(1)  # back-off: max(1, min(min_interval 0, tempo))
    reject_reveal(chain, times=MAX_REPLANS)
    reasons = []
    for _ in range(MAX_REPLANS):
        reasons.append((await sched.maybe_submit({1: 1.0}, mg)).reason)
        chain.advance(1)
    assert reasons == ["replanning"] * (MAX_REPLANS - 1) + ["failed"]


async def test_a_commit_that_landed_meanwhile_is_noticed() -> None:
    chain = fleet(2)
    chain.advance(10)
    reject_reveal(chain)
    sched = scheduler(chain)
    mg = await metagraph(chain)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "replanning"
    other = chain.with_signer(VALI)  # e.g. a commit from a second process landed
    await other.connect()
    assert (await other.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)).ok
    chain.advance(1)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "not_due"


@pytest.mark.parametrize(
    ("code", "error_name"),
    [
        ("expired", "Stale"),  # pool nonce: the gateway already re-signed it
        ("too_early", "Future"),
        ("too_early", "MultiBlockMigrationsOngoing"),  # a new plan cannot help
        ("expired", None),
    ],
)
async def test_other_errors_with_those_codes_are_not_replanned(
    code: str, error_name: str | None
) -> None:
    chain = fleet(2)
    chain.advance(10)
    chain.reject_next("set_weights", code, error_name=error_name)
    with structlog.testing.capture_logs() as logs:
        d = await scheduler(chain).maybe_submit({1: 1.0}, await metagraph(chain))
    assert (d.reason, d.replans) == ("failed", 0)
    assert any(e["event"] == "weights_rejected" for e in logs)


async def test_chain_failures_never_raise() -> None:
    chain = fleet(2)
    chain.advance(10)
    sched = scheduler(chain)
    mg = await metagraph(chain)
    chain.fail_next("block")
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "failed"
    chain.fail_next("set_weights", error=ChainUnavailable("down"))
    d = await sched.maybe_submit({1: 1.0}, mg)
    assert d.reason == "failed"
    assert d.outcome is not None
    assert d.outcome.code == "unknown"


async def test_a_stale_version_key_is_never_committed(tmp_path: Path) -> None:
    """D38: below the subnet's WeightsVersionKey nothing is committed."""
    chain = fleet(2)  # tempo 10, weights rate limit 5
    chain.set_hyperparameters(NETUID, weights_version_key=7)
    chain.advance(10)
    metrics = Metrics()
    s = store(tmp_path)
    sched = scheduler(chain, metrics=metrics, store=s, version_key=6)
    mg = await metagraph(chain)
    with structlog.testing.capture_logs() as logs:
        d = await sched.maybe_submit({1: 1.0}, mg)
    assert d.reason == "version_key_stale"
    assert d.outcome is not None
    assert d.outcome.code == "version_key_stale"
    assert chain.calls["set_weights"] == 0
    (event,) = [e for e in logs if e["event"] == "weights_version_key_stale"]
    assert event["log_level"] == "error"
    assert (event["version_key"], event["chain_version_key"]) == (6, 7)
    assert submissions(metrics, "false", "version_key_stale") == 1
    assert s.last_weights(1)[0].code == "version_key_stale"
    # The next window, not before (max(rate limit, tempo) = 10 blocks).
    chain.advance(9)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "waiting"
    chain.advance(1)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "version_key_stale"
    assert chain.calls["weights_version_key"] == 2  # read again for the new window
    # An upgraded validator commits.
    upgraded = scheduler(chain, metrics=metrics, version_key=7)
    assert (await upgraded.maybe_submit({1: 1.0}, mg)).submitted
    assert chain.weight_submissions()[-1].version_key == 7


async def test_the_version_key_is_read_once_per_tempo() -> None:
    chain = fleet(2)
    chain.set_hyperparameters(NETUID, weights_version_key=2)
    chain.advance(10)
    sched = scheduler(chain, version_key=2, min_interval_blocks=0)
    mg = await metagraph(chain)
    assert (await sched.maybe_submit({1: 1.0}, mg)).submitted
    chain.advance(5)
    assert (await sched.maybe_submit({1: 1.0}, mg)).submitted
    assert chain.calls["weights_version_key"] == 1  # cached inside the tempo
    chain.advance(5)
    assert (await sched.maybe_submit({1: 1.0}, mg)).submitted
    assert chain.calls["weights_version_key"] == 2
    # The chain raises its key: the next read (next tempo) stops the commits.
    chain.set_hyperparameters(NETUID, weights_version_key=3)
    chain.advance(10)
    assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "version_key_stale"


async def test_an_unreadable_version_key_is_a_failed_check() -> None:
    chain = fleet(2)
    chain.advance(10)
    sched = scheduler(chain)
    mg = await metagraph(chain)
    chain.fail_next("weights_version_key")
    with structlog.testing.capture_logs() as logs:
        assert (await sched.maybe_submit({1: 1.0}, mg)).reason == "failed"
    assert any(e["event"] == "weights_check_failed" for e in logs)
    assert chain.calls["set_weights"] == 0
    assert (await sched.maybe_submit({1: 1.0}, mg)).submitted


async def test_fake_chain_version_key_parity() -> None:
    chain = fleet(1)
    await chain.connect()
    assert await chain.weights_version_key(NETUID) == 0
    chain.set_hyperparameters(NETUID, weights_version_key=12)
    assert await chain.weights_version_key(NETUID) == 12
    with pytest.raises(SubnetNotFound):
        await chain.weights_version_key(99)


def test_negative_interval() -> None:
    with pytest.raises(ValueError, match="negative"):
        WeightScheduler(FakeChain(), NETUID, VALI, min_interval_blocks=-1)


# ---------------------------------------------------------------- lock


def _try_lock(state_dir: str, queue: Any) -> None:
    try:
        HotkeyLock(Path(state_dir), VALI).acquire()
    except HotkeyLockHeld:
        queue.put("held")
    else:
        queue.put("acquired")


def test_lock_is_exclusive_across_processes(tmp_path: Path) -> None:
    lock = HotkeyLock(tmp_path, VALI)
    assert not lock.is_held_elsewhere()
    lock.acquire()
    lock.acquire()  # idempotent
    assert lock.held
    queue: Any = multiprocessing.get_context("fork").Queue()
    child = multiprocessing.get_context("fork").Process(
        target=_try_lock, args=(str(tmp_path), queue)
    )
    child.start()
    child.join(10)
    assert queue.get(timeout=5) == "held"
    other = HotkeyLock(tmp_path, VALI)
    assert other.is_held_elsewhere()
    with pytest.raises(HotkeyLockHeld, match="one validator process"):
        other.acquire()
    lock.release()
    lock.release()
    assert not other.is_held_elsewhere()
    other.acquire()
    other.release()
    assert lock.path.read_text().isdigit()
