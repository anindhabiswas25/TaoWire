from __future__ import annotations

import pytest
import pytest_asyncio

from taowire.chain.axon import Endpoint
from taowire.chain.gateway import ChainUnavailable, SubnetNotFound, TxOutcome
from taowire.testing.fake_chain import FakeChain

VALIDATOR = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
MINER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
OTHER = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest_asyncio.fixture
async def chain(clock: Clock) -> FakeChain:
    chain = FakeChain(signer_hotkey=MINER, monotonic=clock)
    chain.add_subnet(2, tempo=100, weights_rate_limit=10, serving_rate_limit=5)
    chain.register(2, VALIDATOR, validator_permit=True, stake_tao=1000.0)
    chain.register(2, MINER, axon="203.0.113.7:8091")
    await chain.connect()
    return chain


@pytest.mark.asyncio
async def test_requires_connect() -> None:
    chain = FakeChain()
    chain.add_subnet(2)
    with pytest.raises(RuntimeError, match="not connected"):
        await chain.metagraph(2)
    await chain.connect()
    assert chain.connected
    await chain.close()
    await chain.close()
    assert not chain.connected


@pytest.mark.asyncio
async def test_metagraph_snapshot(chain: FakeChain, clock: Clock) -> None:
    chain.advance(7)
    mg = await chain.metagraph(2)
    assert mg.netuid == 2
    assert mg.block == 8
    assert mg.tempo == 100
    assert mg.fetched_at_monotonic == clock.now
    assert [n.hotkey for n in mg.neurons] == [VALIDATOR, MINER]
    validator = mg.by_hotkey(VALIDATOR)
    assert validator is not None
    assert validator.validator_permit
    assert validator.total_stake_tao == 1000.0
    assert validator.axon is None
    assert validator.axon_protocol is None
    miner = mg.by_hotkey(MINER)
    assert miner is not None
    assert miner.axon == Endpoint(host="203.0.113.7", port=8091, is_ipv6=False)
    assert miner.axon_protocol == 4


@pytest.mark.asyncio
async def test_snapshot_uses_injected_clock(chain: FakeChain, clock: Clock) -> None:
    first = await chain.metagraph(2)
    clock.now += 60
    second = await chain.metagraph(2)
    assert second.fetched_at_monotonic - first.fetched_at_monotonic == 60


@pytest.mark.asyncio
async def test_private_axons_follow_setting(clock: Clock) -> None:
    chain = FakeChain(monotonic=clock, allow_private_axons=False)
    chain.add_subnet(2)
    chain.register(2, MINER, axon="127.0.0.1:8091")
    await chain.connect()
    neuron = (await chain.metagraph(2)).by_hotkey(MINER)
    assert neuron is not None
    assert neuron.axon is None


@pytest.mark.asyncio
async def test_unknown_subnet(chain: FakeChain) -> None:
    with pytest.raises(SubnetNotFound):
        await chain.metagraph(9)
    with pytest.raises(SubnetNotFound):
        await chain.uid_for_hotkey(9, MINER)


@pytest.mark.asyncio
async def test_reads(chain: FakeChain) -> None:
    assert await chain.block() == 1
    assert await chain.uid_for_hotkey(2, MINER) == 1
    assert await chain.uid_for_hotkey(2, OTHER) is None
    assert await chain.weights_rate_limit(2) == 10
    chain.advance(4)
    assert await chain.blocks_since_last_update(2, 0) == 4
    assert await chain.blocks_since_last_update(2, 200) is None


@pytest.mark.asyncio
async def test_fail_next_raises_then_recovers(chain: FakeChain) -> None:
    chain.fail_next("metagraph", times=2)
    for _ in range(2):
        with pytest.raises(ChainUnavailable):
            await chain.metagraph(2)
    await chain.metagraph(2)
    assert chain.calls["metagraph"] == 3


@pytest.mark.asyncio
async def test_fail_next_custom_error_and_order(chain: FakeChain) -> None:
    chain.fail_next("block", error=TimeoutError("slow"))
    chain.fail_next("block")
    with pytest.raises(TimeoutError):
        await chain.block()
    with pytest.raises(ChainUnavailable):
        await chain.block()
    assert await chain.block() == 1


@pytest.mark.asyncio
async def test_fail_next_on_connect() -> None:
    chain = FakeChain()
    chain.fail_next("connect")
    with pytest.raises(ChainUnavailable):
        await chain.connect()
    assert not chain.connected


def test_fault_validation() -> None:
    chain = FakeChain()
    with pytest.raises(ValueError, match="unknown operation"):
        chain.fail_next("metagraf")
    with pytest.raises(ValueError, match="times"):
        chain.fail_next("block", times=0)
    with pytest.raises(ValueError, match="writes"):
        chain.reject_next("block", "rate_limited")


@pytest.mark.asyncio
async def test_serve_axon(chain: FakeChain) -> None:
    outcome = await chain.serve_axon(
        2, "198.51.100.4", 9000, tls_cert_hex=None, protocol_tag=87
    )
    assert outcome.ok
    assert outcome.code is None
    assert outcome.block_hash is not None
    miner = (await chain.metagraph(2)).by_hotkey(MINER)
    assert miner is not None
    assert miner.axon == Endpoint(host="198.51.100.4", port=9000, is_ipv6=False)
    assert miner.axon_protocol == 87
    (publication,) = chain.axon_publications(2)
    assert (publication.hotkey, publication.ip, publication.port) == (
        MINER,
        "198.51.100.4",
        9000,
    )


@pytest.mark.asyncio
async def test_serve_axon_ipv6(chain: FakeChain) -> None:
    outcome = await chain.serve_axon(
        2, "2001:db8::5", 9000, tls_cert_hex="0x01ab", protocol_tag=4
    )
    assert outcome.ok
    miner = (await chain.metagraph(2)).by_hotkey(MINER)
    assert miner is not None
    assert miner.axon == Endpoint(host="2001:db8::5", port=9000, is_ipv6=True)
    assert chain.axon_publications()[0].tls_cert_hex == "0x01ab"


@pytest.mark.asyncio
async def test_serve_axon_rate_limited(chain: FakeChain) -> None:
    assert (
        await chain.serve_axon(
            2, "198.51.100.4", 9000, tls_cert_hex=None, protocol_tag=4
        )
    ).ok
    chain.advance(4)
    limited = await chain.serve_axon(
        2, "198.51.100.4", 9001, tls_cert_hex=None, protocol_tag=4
    )
    assert limited == TxOutcome(
        ok=False,
        code="rate_limited",
        remediation="wait for the rate-limit window to pass, then retry",
        block_hash=None,
    )
    chain.advance(1)
    assert (
        await chain.serve_axon(
            2, "198.51.100.4", 9001, tls_cert_hex=None, protocol_tag=4
        )
    ).ok


@pytest.mark.parametrize(
    ("ip", "port", "tag"),
    [
        ("198.51.100.4", 0, 4),
        ("not-an-ip", 80, 4),
        ("198.51.100.4", 70000, 4),
        ("198.51.100.4", 80, 256),
        ("198.51.100.4", 80, -1),
    ],
)
@pytest.mark.asyncio
async def test_serve_axon_invalid_arguments(
    chain: FakeChain, ip: str, port: int, tag: int
) -> None:
    outcome = await chain.serve_axon(2, ip, port, tls_cert_hex=None, protocol_tag=tag)
    assert outcome.code == "invalid_argument"
    assert not chain.axon_publications()


@pytest.mark.asyncio
async def test_serve_axon_unregistered_and_unknown_subnet(chain: FakeChain) -> None:
    other = chain.with_signer(OTHER)
    await other.connect()
    assert (
        await other.serve_axon(2, "198.51.100.4", 80, tls_cert_hex=None, protocol_tag=4)
    ).code == "not_registered"
    assert (
        await other.serve_axon(9, "198.51.100.4", 80, tls_cert_hex=None, protocol_tag=4)
    ).code == "subnet_not_exists"


@pytest.mark.asyncio
async def test_writes_need_a_signer() -> None:
    chain = FakeChain()
    chain.add_subnet(2)
    await chain.connect()
    with pytest.raises(RuntimeError, match="signer_hotkey"):
        await chain.set_weights(2, {0: 1.0}, mechid=0, version_key=0)


@pytest.mark.asyncio
async def test_set_weights(chain: FakeChain) -> None:
    validator = chain.with_signer(VALIDATOR)
    await validator.connect()
    early = await validator.set_weights(2, {1: 1.0}, mechid=0, version_key=0)
    assert early.code == "rate_limited"
    chain.advance(10)
    outcome = await validator.set_weights(2, {1: 0.7, 0: 0.3}, mechid=0, version_key=3)
    assert outcome.ok
    (submission,) = chain.weight_submissions(2)
    assert submission.hotkey == VALIDATOR
    assert submission.uid == 0
    assert submission.weights == {1: 0.7, 0: 0.3}
    assert submission.version_key == 3
    assert submission.block == 11
    assert await chain.blocks_since_last_update(2, 0) == 0
    again = await validator.set_weights(2, {1: 1.0}, mechid=0, version_key=3)
    assert again.code == "rate_limited"


@pytest.mark.asyncio
async def test_set_weights_rules(chain: FakeChain) -> None:
    chain.advance(10)
    chain.set_hyperparameters(2, weights_version_key=5)
    validator = chain.with_signer(VALIDATOR)
    await validator.connect()
    assert (
        await chain.set_weights(2, {0: 1.0}, mechid=0, version_key=5)
    ).code == "not_authorized"
    assert (
        await validator.set_weights(2, {0: 1.0}, mechid=0, version_key=4)
    ).code == "invalid_argument"
    assert (
        await validator.set_weights(2, {}, mechid=0, version_key=5)
    ).code == "invalid_argument"
    assert (
        await validator.set_weights(2, {7: 1.0}, mechid=0, version_key=5)
    ).code == "invalid_argument"
    assert (
        await validator.set_weights(2, {1: -1.0}, mechid=0, version_key=5)
    ).code == "invalid_argument"
    assert (
        await validator.set_weights(2, {1: float("nan")}, mechid=0, version_key=5)
    ).code == "invalid_argument"
    assert (
        await validator.set_weights(9, {1: 1.0}, mechid=0, version_key=5)
    ).code == "subnet_not_exists"
    stranger = chain.with_signer(OTHER)
    await stranger.connect()
    assert (
        await stranger.set_weights(2, {1: 1.0}, mechid=0, version_key=5)
    ).code == "not_registered"
    assert not chain.weight_submissions()


@pytest.mark.asyncio
async def test_reject_next(chain: FakeChain) -> None:
    chain.reject_next("serve_axon", "rate_limited", remediation="wait 12 blocks")
    outcome = await chain.serve_axon(
        2, "198.51.100.4", 80, tls_cert_hex=None, protocol_tag=4
    )
    assert outcome == TxOutcome(
        ok=False, code="rate_limited", remediation="wait 12 blocks", block_hash=None
    )
    assert (
        await chain.serve_axon(2, "198.51.100.4", 80, tls_cert_hex=None, protocol_tag=4)
    ).ok


@pytest.mark.asyncio
async def test_shared_state_between_signers(chain: FakeChain) -> None:
    validator = chain.with_signer(VALIDATOR)
    assert validator.signer_hotkey == VALIDATOR
    assert not validator.connected
    await validator.connect()
    chain.advance(3)
    assert await validator.block() == 4
    chain.set_permit(2, MINER, True)
    miner = (await validator.metagraph(2)).by_hotkey(MINER)
    assert miner is not None
    assert miner.validator_permit
    assert chain.calls is validator.calls


@pytest.mark.asyncio
async def test_setup_helpers(chain: FakeChain) -> None:
    chain.set_stake(2, MINER, stake_tao=12.5, alpha_stake=100.0, tao_stake=2.0)
    chain.set_axon(2, MINER, "[2001:db8::9]:7000", protocol=87)
    chain.set_scores(2, MINER, incentive=0.25, dividends=0.0)
    miner = (await chain.metagraph(2)).by_hotkey(MINER)
    assert miner is not None
    assert (miner.total_stake_tao, miner.alpha_stake, miner.tao_stake) == (
        12.5,
        100.0,
        2.0,
    )
    assert miner.axon == Endpoint(host="2001:db8::9", port=7000, is_ipv6=True)
    assert miner.axon_protocol == 87
    assert miner.incentive == 0.25
    chain.set_axon(2, MINER, None)
    miner = (await chain.metagraph(2)).by_hotkey(MINER)
    assert miner is not None
    assert miner.axon is None
    assert miner.axon_protocol is None


@pytest.mark.asyncio
async def test_uid_replacement_changes_hotkey(chain: FakeChain) -> None:
    assert chain.register(2, OTHER, uid=1) == 1
    mg = await chain.metagraph(2)
    assert mg.neurons[1].hotkey == OTHER
    assert mg.by_hotkey(MINER) is None


@pytest.mark.asyncio
async def test_deregister_frees_lowest_uid(chain: FakeChain) -> None:
    chain.deregister(2, VALIDATOR)
    assert chain.register(2, OTHER) == 0


def test_setup_validation() -> None:
    chain = FakeChain()
    chain.add_subnet(2, max_uids=1)
    with pytest.raises(ValueError, match="already exists"):
        chain.add_subnet(2)
    with pytest.raises(ValueError, match="positive"):
        chain.add_subnet(3, tempo=0)
    with pytest.raises(ValueError, match="positive"):
        chain.set_hyperparameters(2, tempo=0)
    chain.register(2, MINER)
    with pytest.raises(ValueError, match="already registered"):
        chain.register(2, MINER, uid=0)
    with pytest.raises(ValueError, match="full"):
        chain.register(2, OTHER)
    with pytest.raises(ValueError, match="out of range"):
        chain.register(2, OTHER, uid=1)
    with pytest.raises(ValueError, match="not registered"):
        chain.set_permit(2, OTHER, True)
    with pytest.raises(SubnetNotFound):
        chain.register(5, OTHER)
    with pytest.raises(ValueError, match="negative"):
        chain.advance(-1)
    assert chain.current_block == 1


@pytest.mark.asyncio
async def test_set_hyperparameters(chain: FakeChain) -> None:
    chain.set_hyperparameters(
        2, tempo=50, weights_rate_limit=3, serving_rate_limit=1, weights_version_key=2
    )
    assert (await chain.metagraph(2)).tempo == 50
    assert await chain.weights_rate_limit(2) == 3


@pytest.mark.asyncio
async def test_reject_next_set_weights(chain: FakeChain) -> None:
    chain.advance(10)
    validator = chain.with_signer(VALIDATOR)
    await validator.connect()
    validator.reject_next("set_weights", "not_authorized", times=2)
    for _ in range(2):
        outcome = await validator.set_weights(2, {1: 1.0}, mechid=0, version_key=0)
        assert outcome.code == "not_authorized"
        assert (
            outcome.remediation == "this hotkey lacks a validator permit on the subnet"
        )
    assert (await validator.set_weights(2, {1: 1.0}, mechid=0, version_key=0)).ok


@pytest.mark.asyncio
async def test_serving_rate_limit(chain: FakeChain) -> None:
    assert await chain.serving_rate_limit(2) == 5
    chain.set_hyperparameters(2, serving_rate_limit=50)
    assert await chain.serving_rate_limit(2) == 50
    assert chain.calls["serving_rate_limit"] == 2
    with pytest.raises(SubnetNotFound):
        await chain.serving_rate_limit(9)
    chain.fail_next("serving_rate_limit")
    with pytest.raises(ChainUnavailable):
        await chain.serving_rate_limit(2)
