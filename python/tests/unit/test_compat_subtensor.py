"""compat.Subtensor: v10 ``bt.subtensor`` calls on the gateway (spec 10b.2.6, D34)."""

from __future__ import annotations

import asyncio
import multiprocessing
import sys
import threading
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from taowire.compat import Metagraph, Subtensor
from taowire.compat.subtensor import V10_WRITES
from taowire.testing.fake_chain import FakeChain
from taowire.testing.keys import dev_key

NETUID = 3
BOB = dev_key("bob")
ALICE = dev_key("alice")


@pytest.fixture
def chain() -> FakeChain:
    c = FakeChain(block=50)
    c.add_subnet(NETUID)
    c.register(NETUID, BOB.ss58, axon="44.1.2.3:8091")
    c.register(NETUID, ALICE.ss58, validator_permit=True, stake_tao=100)
    return c


@pytest.fixture
def subtensor(chain: FakeChain) -> Iterator[Subtensor]:
    def factory(hotkey: Any) -> FakeChain:
        return chain if hotkey is None else chain.with_signer(hotkey.ss58_address)

    s = Subtensor("ws://127.0.0.1:9944", gateway_factory=factory)
    try:
        yield s
    finally:
        s.close()


def wallet(name: str) -> Any:
    """A v10-shaped wallet whose coldkey must never be touched."""

    class Wallet:
        hotkey = dev_key(name).keypair

        @property
        def coldkey(self) -> Any:
            raise AssertionError("the coldkey was read")

    return Wallet()


def test_reads(subtensor: Subtensor, chain: FakeChain) -> None:
    mg = subtensor.metagraph(NETUID)
    assert isinstance(mg, Metagraph)
    assert mg.hotkeys == [BOB.ss58, ALICE.ss58]
    assert subtensor.block == subtensor.get_current_block() == 50
    assert subtensor.get_block_hash(7) == f"0x{7:064x}"
    assert subtensor.get_block_hash() == f"0x{50:064x}"
    assert subtensor.get_block_hash(51) is None
    assert (
        subtensor.get_uid_for_hotkey_on_subnet(hotkey_ss58=ALICE.ss58, netuid=NETUID)
        == 1
    )
    assert subtensor.get_uid_for_hotkey_on_subnet(dev_key("dave").ss58, NETUID) is None
    assert subtensor.is_hotkey_registered(netuid=NETUID, hotkey_ss58=BOB.ss58)
    assert not subtensor.is_hotkey_registered(dev_key("dave").ss58, NETUID)
    chain.set_storage("SubnetOwnerHotkey", [NETUID], ALICE.ss58)
    assert subtensor.query_subtensor("SubnetOwnerHotkey", params=[NETUID]) == ALICE.ss58
    assert subtensor.query_subtensor("SubnetOwnerHotkey", params=[9]) is None


def test_commitments_round_trip(subtensor: Subtensor) -> None:
    assert subtensor.get_commitment(netuid=NETUID, uid=1) == ""
    assert subtensor.set_commitment(wallet=wallet("alice"), netuid=NETUID, data="abc")
    assert subtensor.get_commitment(netuid=NETUID, uid=1) == "abc"
    assert subtensor.commit(wallet("bob"), NETUID, "x" * 128)
    assert subtensor.get_commitment(NETUID, 0) == "x" * 128
    assert subtensor.get_commitment(NETUID, 99) == ""  # no such UID
    assert not subtensor.commit(wallet("bob"), NETUID, "x" * 129)  # too long
    assert not subtensor.commit(wallet("dave"), NETUID, "y")  # not registered


def test_set_weights_and_serve_axon(subtensor: Subtensor, chain: FakeChain) -> None:
    chain.advance(1000)  # past the weights rate limit
    ok, message = subtensor.set_weights(
        wallet=wallet("alice"),
        netuid=NETUID,
        uids=[0, 1],
        weights=[0.25, 0.75],
        wait_for_finalization=False,
        version_key=0,
    )
    assert (ok, message) == (True, "Successfully set weights.")
    (submission,) = chain.weight_submissions(NETUID)
    assert submission.hotkey == ALICE.ss58
    ok, message = subtensor.set_weights(wallet("bob"), NETUID, [0], [1.0])
    assert not ok  # bob has no validator permit
    assert message
    assert subtensor.serve_axon(netuid=NETUID, axon=object()) is True
    assert len(chain.axon_publications()) == 0  # the kit's lifecycle publishes


@pytest.mark.parametrize("name", sorted(V10_WRITES))
def test_unsupported_writes_name_the_replacement(
    subtensor: Subtensor, name: str
) -> None:
    with pytest.raises(NotImplementedError, match="v11: "):
        getattr(subtensor, name)(wallet=wallet("bob"), netuid=NETUID)


def test_unknown_attributes_and_history(subtensor: Subtensor) -> None:
    with pytest.raises(AttributeError, match=r"bt\.Subtensor"):
        _ = subtensor.get_stake_info
    with pytest.raises(NotImplementedError, match="latest block"):
        subtensor.metagraph(NETUID, block=3)
    with pytest.raises(NotImplementedError, match="netuid"):
        subtensor.is_hotkey_registered(BOB.ss58)
    with pytest.raises(TypeError, match="hotkey"):
        subtensor.commit(SimpleNamespace(), NETUID, "x")


def test_network_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SimpleNamespace(subtensor=SimpleNamespace(chain_endpoint="ws://x:1"))
    monkeypatch.delenv("TW_NETWORK", raising=False)
    cases = [
        (Subtensor("test"), "test"),
        (Subtensor(config=config), "ws://x:1"),
        (Subtensor(), "finney"),
    ]
    monkeypatch.setenv("TW_NETWORK", "local")
    cases.append((Subtensor(config=SimpleNamespace()), "local"))
    for s, expected in cases:
        assert s.network == s.chain_endpoint == expected
        assert repr(s) == f"compat.Subtensor({expected})"
        s.close()


def test_context_manager_closes(chain: FakeChain) -> None:
    with Subtensor("x", gateway_factory=lambda hk: chain) as s:
        s.get_current_block()
        assert chain.connected
    assert not chain.connected


def test_get_commitment_reads_the_uid_s_hotkey_only(
    subtensor: Subtensor, chain: FakeChain
) -> None:
    assert subtensor.set_commitment(wallet("bob"), NETUID, "abc")
    before = chain.calls["metagraph"]
    assert subtensor.get_commitment(NETUID, 0) == "abc"
    assert subtensor.get_commitment(NETUID, -1) == ""
    assert chain.calls["metagraph"] == before  # one storage read, not a metagraph


def test_a_call_that_times_out_is_cancelled(chain: FakeChain) -> None:
    started, cancelled = threading.Event(), threading.Event()

    async def hang() -> int:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return 0  # pragma: no cover

    chain.block = hang  # type: ignore[method-assign]
    with Subtensor("x", gateway_factory=lambda hk: chain, timeout_s=0.2) as s:
        with pytest.raises(TimeoutError, match=r"0\.2 s"):
            s.get_current_block()
        assert started.is_set()
        assert cancelled.wait(5)


def test_calls_after_close_are_refused(chain: FakeChain) -> None:
    s = Subtensor("x", gateway_factory=lambda hk: chain)
    s.close()
    s.close()  # idempotent
    with pytest.raises(RuntimeError, match="closed"):
        s.get_current_block()


@pytest.mark.skipif(sys.platform == "win32", reason="needs fork")
def test_works_in_a_forked_child(chain: FakeChain) -> None:
    """v10 subnets run chain calls in ``fork`` workers (data-universe does)."""
    with Subtensor("x", gateway_factory=lambda hk: chain, timeout_s=5) as s:
        assert s.get_current_block() == 50  # the parent's loop and connection
        ctx = multiprocessing.get_context("fork")
        queue = ctx.Queue()
        child = ctx.Process(target=_child_block, args=(s, queue))
        child.start()
        child.join(30)
        assert child.exitcode == 0
        assert queue.get(timeout=5) == 50
        assert s.get_current_block() == 50  # the parent is unaffected


def _child_block(s: Subtensor, queue: Any) -> None:
    queue.put(s.get_current_block())
