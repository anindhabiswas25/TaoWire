"""policy/caller.py: rule order (13.2) and the staged staleness rule (8.5.1)."""

from __future__ import annotations

import pytest

from taowire.chain.gateway import MetagraphView, NeuronView
from taowire.chain.metagraph_cache import StalenessStage
from taowire.config import MinerSettings
from taowire.errors import Forbidden, MetagraphStale
from taowire.policy.caller import CallerGate, CallerPolicy, KnownCallers
from taowire.testing.clock import FakeClock
from taowire.testing.fake_chain import FakeChain
from taowire.testing.keys import dev_key
from taowire.testing.metagraph import FakeMetagraphSource
from taowire.testing.pytest_plugin import TWEnv

V = dev_key("alice").ss58  # validator, 1000 stake
N = dev_key("charlie").ss58  # registered, no permit, 5 stake
U = dev_key("dave").ss58  # unregistered


def neuron(uid: int, hotkey: str, *, permit: bool, stake: float) -> NeuronView:
    return NeuronView(
        uid=uid, hotkey=hotkey, coldkey=hotkey, validator_permit=permit, active=True,
        total_stake_tao=stake, alpha_stake=stake, tao_stake=0.0, axon=None,
        last_update=0, incentive=0.0, dividends=0.0,
    )  # fmt: skip


MG = MetagraphView(
    netuid=1,
    block=10,
    fetched_at_monotonic=0.0,
    neurons=(
        neuron(0, V, permit=True, stake=1000),
        neuron(1, N, permit=False, stake=5),
    ),
    tempo=360,
)


def denial(policy: CallerPolicy, hotkey: str) -> str | None:
    try:
        policy.check(hotkey, MG)
    except Forbidden as exc:
        return f"{exc.code}" if exc.http_status == 403 else "wrong status"
    return None


# ---------------------------------------------------------------- CallerPolicy


def test_strict_default() -> None:
    p = CallerPolicy()
    assert denial(p, V) is None
    assert denial(p, N) == "tw.forbidden_not_validator"
    assert denial(p, U) == "tw.forbidden_not_registered"
    assert p.check(V, MG) == MG.by_hotkey(V)


@pytest.mark.parametrize(
    ("policy", "hotkey", "expected"),
    [
        # deny beats allow and everything else
        (CallerPolicy(deny_hotkeys=frozenset({V})), V, "tw.forbidden_denied"),
        # allow beats registered / permit / stake
        (CallerPolicy(allow_hotkeys=frozenset({U}), min_stake_tao=1e9), U, None),
        (CallerPolicy(allow_hotkeys=frozenset({N}), min_stake_tao=1e9), N, None),
        # registered beats permit
        (CallerPolicy(), U, "tw.forbidden_not_registered"),
        # permit beats stake
        (CallerPolicy(min_stake_tao=1e9), N, "tw.forbidden_not_validator"),
        # stake last
        (CallerPolicy(min_stake_tao=1000.01), V, "tw.forbidden_low_stake"),
        (CallerPolicy(min_stake_tao=1000), V, None),
        # each check can be relaxed on its own
        (CallerPolicy(require_validator_permit=False), N, None),
        (CallerPolicy(require_validator_permit=False, min_stake_tao=10), N,
         "tw.forbidden_low_stake"),
        (CallerPolicy(require_registered=False), U, "tw.forbidden_not_validator"),
        (CallerPolicy(require_registered=False, require_validator_permit=False), U,
         None),
        (CallerPolicy(require_registered=False, require_validator_permit=False,
                      min_stake_tao=1), U, "tw.forbidden_low_stake"),
    ],
)  # fmt: skip
def test_order_deny_allow_registered_permit_stake(
    policy: CallerPolicy, hotkey: str, expected: str | None
) -> None:
    assert denial(policy, hotkey) == expected


def test_allow_listed_unregistered_caller_has_no_neuron() -> None:
    assert CallerPolicy(allow_hotkeys=frozenset({U})).check(U, MG) is None


def test_invalid_policies() -> None:
    with pytest.raises(ValueError, match="min_stake_tao"):
        CallerPolicy(min_stake_tao=-1)
    with pytest.raises(ValueError, match="min_stake_tao"):
        CallerPolicy(min_stake_tao=float("nan"))
    with pytest.raises(ValueError, match="both allowed and denied"):
        CallerPolicy(allow_hotkeys=frozenset({V}), deny_hotkeys=frozenset({V}))


def test_with_denied_wins_over_allow() -> None:
    p = CallerPolicy(allow_hotkeys=frozenset({U, N})).with_denied([U])
    assert p.deny_hotkeys == frozenset({U})
    assert p.allow_hotkeys == frozenset({N})
    assert denial(p, U) == "tw.forbidden_denied"


def test_from_settings(tw_env: TWEnv) -> None:
    tw_env.set(
        netuid=1, wallet_name="m", external_ip="44.1.2.3", require_permit=False,
        min_caller_stake_tao=7, allow_hotkeys=U, deny_hotkeys=N,
    )  # fmt: skip
    p = CallerPolicy.from_settings(MinerSettings.from_env())
    assert p == CallerPolicy(
        require_registered=True,
        require_validator_permit=False,
        min_stake_tao=7,
        allow_hotkeys=frozenset({U}),
        deny_hotkeys=frozenset({N}),
    )


# ---------------------------------------------------------------- KnownCallers


def test_known_callers_are_bounded() -> None:
    k = KnownCallers(max_entries=2)
    k.add("/a", V, 1.0)
    k.add("/a", N, 2.0)
    k.add("/a", V, 3.0)  # refreshes V
    k.add("/a", U, 4.0)  # evicts N, the oldest
    assert (("/a", V) in k, ("/a", N) in k, ("/a", U) in k) == (True, False, True)
    with pytest.raises(ValueError, match="max_entries"):
        KnownCallers(max_entries=0)


def test_known_callers() -> None:
    k = KnownCallers()
    k.add("/a", V, 5.0)
    assert ("/a", V) in k
    assert ("/b", V) not in k
    assert k.last_accepted("/a", V) == 5.0
    assert k.last_accepted("/b", V) is None
    assert len(k) == 1
    k.clear()
    assert len(k) == 0


# ---------------------------------------------------------------- CallerGate


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
async def source(clock: FakeClock) -> FakeMetagraphSource:
    chain = FakeChain(monotonic=clock.monotonic)
    chain.add_subnet(1)
    chain.register(1, V, validator_permit=True, stake_tao=1000)
    chain.register(1, N)
    await chain.connect()
    src = FakeMetagraphSource(chain, 1, clock=clock.monotonic)
    await src.start()
    return src


async def test_gate_fresh_and_degraded_apply_policy_and_remember(
    source: FakeMetagraphSource, clock: FakeClock
) -> None:
    gate = CallerGate(source, clock=clock.monotonic)
    policy = CallerPolicy()
    assert gate.precheck() is StalenessStage.FRESH
    assert gate.admit("/r", policy, V) is not None
    assert gate.known.last_accepted("/r", V) == clock.monotonic()
    with pytest.raises(Forbidden):
        gate.admit("/r", policy, N)
    assert ("/r", N) not in gate.known  # only callers that pass are remembered
    clock.advance(source.thresholds.soft_age_s)
    assert gate.precheck() is StalenessStage.DEGRADED
    with pytest.raises(Forbidden):
        gate.admit("/r", policy, N)  # degraded: normal policy on the last snapshot


async def test_gate_known_callers_only(
    source: FakeMetagraphSource, clock: FakeClock
) -> None:
    gate = CallerGate(source, clock=clock.monotonic)
    relaxed = CallerPolicy(require_validator_permit=False)
    gate.admit("/r", CallerPolicy(), V)
    gate.admit("/open", relaxed, N)
    clock.advance(source.thresholds.max_age_s + 1)
    assert (
        gate.precheck() is StalenessStage.KNOWN_CALLERS_ONLY
    )  # not strict: no 503 yet
    assert gate.admit("/r", CallerPolicy(), V) == source.by_hotkey(V)
    with pytest.raises(MetagraphStale):
        gate.admit("/r", CallerPolicy(), N)  # known on /open only, not on /r
    assert gate.admit("/open", relaxed, N) is not None
    with pytest.raises(MetagraphStale):
        gate.admit("/r", CallerPolicy(), U)
    with pytest.raises(Forbidden):  # the deny list still applies first
        gate.admit("/r", CallerPolicy(deny_hotkeys=frozenset({V})), V)
    await source.refresh_now()  # a fresh snapshot clears the set
    assert len(gate.known) == 0


async def test_gate_strict(source: FakeMetagraphSource, clock: FakeClock) -> None:
    gate = CallerGate(source, strict=True, clock=clock.monotonic)
    assert gate.strict
    gate.admit("/r", CallerPolicy(), V)
    clock.advance(source.thresholds.max_age_s + 1)
    with pytest.raises(MetagraphStale):
        gate.precheck()
    with pytest.raises(MetagraphStale):
        gate.admit("/r", CallerPolicy(), V)


async def test_gate_without_snapshot_fails_closed(clock: FakeClock) -> None:
    chain = FakeChain(monotonic=clock.monotonic)
    source = FakeMetagraphSource(chain, 1, clock=clock.monotonic)
    gate = CallerGate(source)
    assert source.stage() is StalenessStage.KNOWN_CALLERS_ONLY
    with pytest.raises(MetagraphStale):
        gate.admit("/r", CallerPolicy(), V)
    gate.known.add("/r", V, 0.0)
    assert gate.admit("/r", CallerPolicy(), V) is None
