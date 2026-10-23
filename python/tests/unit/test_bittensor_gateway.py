"""BittensorGateway (spec 8.3) against a scripted stand-in for the SDK client.

The stand-in records every call and replays queued faults, so the retry,
timeout, endpoint-rotation and re-sign rules are checked without a chain.
The same gateway runs against a real localnet in tests/localnet.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import bittensor as bt
import pytest
from bittensor.result import ExtrinsicResult

from tensorwire.chain import gateway as gateway_module
from tensorwire.chain.axon import Endpoint
from tensorwire.chain.gateway import (
    BACKOFF_MAX_S,
    RESIGN_ERROR_NAMES,
    BittensorGateway,
    ChainGateway,
    ChainUnavailable,
    SdkSurfaceError,
    SubnetNotFound,
    TimelockMalformed,
    TimelockNotReady,
    TimelockUnavailable,
    check_sdk_surface,
    metagraph_view,
)

NETUID = 2
HOTKEY = SimpleNamespace(ss58_address="5Hotkey")

HANG = object()
"""Queued in place of an error: the call never returns (to hit timeouts)."""


def _balance(amount: float, netuid: int) -> bt.Balance:
    return bt.Balance.from_rao(round(amount * 1e9), netuid)


def _sdk_neuron(
    uid: int,
    *,
    alpha: float = 0.0,
    tao: float = 0.0,
    permit: bool = False,
    axon: str | None = None,
) -> bt.MetagraphNeuron:
    zero = _balance(0, NETUID)
    return bt.MetagraphNeuron(
        uid=uid,
        hotkey=f"hk{uid}",
        coldkey=f"ck{uid}",
        active=True,
        validator_permit=permit,
        last_update=10 + uid,
        block_at_registration=1,
        rank=0.0,
        trust=0.0,
        consensus=0.0,
        incentive=0.25,
        dividends=0.5,
        pruning_score=0.0,
        emission=zero,
        alpha_stake=_balance(alpha, NETUID),
        tao_stake=_balance(tao, 0),
        total_stake=_balance(alpha, NETUID),
        axon=axon,
        identity=None,
        commitment=None,
    )


def _sdk_metagraph(
    neurons: list[bt.MetagraphNeuron],
    *,
    netuid: int = NETUID,
    price: float | None = 2.0,
    axons: Any = None,
    block: int = 100,
    tempo: int = 10,
) -> bt.Metagraph:
    return bt.Metagraph(
        netuid=netuid,
        mechid=0,
        name="sn",
        symbol="b",
        block=block,
        tempo=tempo,
        last_step=0,
        blocks_since_last_step=0,
        owner_hotkey="hk0",
        owner_coldkey="ck0",
        network_registered_at=1,
        num_uids=len(neurons),
        max_uids=256,
        price=price,
        moving_price=None,
        identity=None,
        neurons=neurons,
        commitments={},
        unregistered_commitments={},
        raw={"axons": axons} if axons is not None else {},
    )


def _failed(name: str, message: str = "rejected") -> ExtrinsicResult:
    error = bt.ChainError(message, name=name)
    return ExtrinsicResult(success=False, message=message, error=error)


def _ok(block_hash: str = "0xabc") -> ExtrinsicResult:
    return ExtrinsicResult(success=True, message="Success", block_hash=block_hash)


@dataclass
class World:
    """Shared state of every stand-in client the gateway builds."""

    metagraph: bt.Metagraph | None = None
    subnets: set[int] = field(default_factory=lambda: {NETUID})
    uid: int | None = 1
    weights_rate_limit: int = 100
    blocks_since: int | None = 7
    serving: int | None = 50
    planned: list[Any] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    faults: dict[str, list[Any]] = field(default_factory=lambda: defaultdict(list))
    results: list[ExtrinsicResult | BaseException | object] = field(
        default_factory=list
    )
    clients: list[FakeSdkClient] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    executed: list[tuple[Any, Any, dict[str, Any]]] = field(default_factory=list)
    finalized: int = 50

    def fail(self, op: str, *errors: Any) -> None:
        self.faults[op].extend(errors)

    async def run(self, op: str, value: Any) -> Any:
        self.calls.append(op)
        queue = self.faults.get(op)
        if queue:
            fault = queue.pop(0)
            if fault is HANG:
                await asyncio.Event().wait()
            raise fault
        return value


class FakeSdkClient:
    """Duck-typed ``bt.Client``: only what the gateway uses."""

    def __init__(self, world: World, endpoint: str, fallbacks: list[str] | None):
        self.world = world
        self.endpoint = endpoint
        self.fallbacks = fallbacks
        self.closed = False
        world.clients.append(self)
        self.subnets = SimpleNamespace(metagraph=self._metagraph)
        self.neurons = SimpleNamespace(uid=self._uid)
        self.hyperparameters = SimpleNamespace(
            weights_rate_limit=self._weights_rate_limit
        )
        self.epochs = SimpleNamespace(
            blocks_since_last_update=self._blocks_since_last_update
        )

    async def connect(self) -> None:
        await self.world.run("connect", None)

    async def close(self) -> None:
        self.closed = True
        await self.world.run("close", None)

    async def block(self) -> int:
        return int(await self.world.run("block", 123))

    async def finalized_block(self) -> int:
        self.world.finalized += 1
        return self.world.finalized

    async def block_time(self) -> float:
        return 0.0

    async def query(self, item: tuple[str, str], params: list[int]) -> Any:
        if item == ("SubtensorModule", "ServingRateLimit"):
            return await self.world.run("serving_rate_limit", self.world.serving)
        assert item == ("SubtensorModule", "NetworksAdded")
        return bool(await self.world.run("query", params[0] in self.world.subnets))

    async def _metagraph(self, netuid: int, *, commitments: bool) -> Any:
        assert commitments is False
        value = self.world.metagraph if netuid in self.world.subnets else None
        return await self.world.run("metagraph", value)

    async def _uid(self, *, hotkey_ss58: str, netuid: int) -> int | None:
        value = self.world.uid if netuid in self.world.subnets else None
        return await self.world.run("uid", value)  # type: ignore[no-any-return]

    async def _weights_rate_limit(self, *, netuid: int) -> int:
        return int(
            await self.world.run("weights_rate_limit", self.world.weights_rate_limit)
        )

    async def _blocks_since_last_update(self, *, netuid: int, uid: int) -> int | None:
        value = self.world.blocks_since if netuid in self.world.subnets else None
        return await self.world.run("blocks_since", value)  # type: ignore[no-any-return]

    async def plan(self, intent: Any, signer: Any) -> Any:
        self.world.planned.append(intent)
        return await self.world.run(
            "plan",
            SimpleNamespace(
                ok=not self.world.violations, violations=self.world.violations
            ),
        )

    async def execute(self, intent: Any, signer: Any, **kwargs: Any) -> Any:
        self.world.executed.append((intent, signer, kwargs))
        self.world.calls.append("execute")
        outcome = self.world.results.pop(0) if self.world.results else _ok()
        if outcome is HANG:
            await asyncio.Event().wait()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture
def world() -> World:
    return World(metagraph=_sdk_metagraph([_sdk_neuron(0), _sdk_neuron(1)]))


@pytest.fixture
def sleeps() -> list[float]:
    return []


def _gateway(
    world: World,
    sleeps: list[float],
    *,
    fallbacks: tuple[str, ...] = (),
    timeout_s: float = 5.0,
    **kwargs: Any,
) -> BittensorGateway:
    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    return BittensorGateway(
        "ws://primary:9944",
        hotkey=HOTKEY,
        fallback_endpoints=fallbacks,
        timeout_s=timeout_s,
        sleep=sleep,
        jitter=lambda: 0.5,
        monotonic=lambda: 1000.0,
        client_factory=lambda net, fb: FakeSdkClient(world, net, fb),
        **kwargs,
    )


async def _connected(
    world: World, sleeps: list[float], **kwargs: Any
) -> BittensorGateway:
    gw = _gateway(world, sleeps, **kwargs)
    await gw.connect()
    return gw


# -- construction and connection ------------------------------------------------


def test_implements_protocol(world: World, sleeps: list[float]) -> None:
    assert isinstance(_gateway(world, sleeps), ChainGateway)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_s": 0},
        {"write_timeout_s": -1},
        {"read_attempts": 0},
        {"write_attempts": 0},
    ],
)
def test_rejects_bad_settings(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="must be"):
        BittensorGateway("local", **kwargs)


def test_from_settings() -> None:
    settings = SimpleNamespace(
        network="local",
        chain_fallbacks=("ws://a:9944",),
        chain_timeout_s=12,
        allow_private_axons=True,
    )
    gw = BittensorGateway.from_settings(settings, hotkey=HOTKEY)
    assert gw.endpoint == "local"
    assert gw._endpoints == ["local", "ws://a:9944"]
    assert gw._timeout_s == 12.0
    assert gw._write_timeout_s == 48.0
    assert gw._allow_private is True
    # the miner lifecycle passes the hotkey by position
    assert BittensorGateway.from_settings(settings, HOTKEY)._hotkey is HOTKEY


def test_default_client_is_async_sdk_client() -> None:
    gw = BittensorGateway("ws://127.0.0.1:9944")
    client = gw._factory("ws://127.0.0.1:9944", None)
    assert isinstance(client, bt.Client)


async def test_reads_need_connect(world: World, sleeps: list[float]) -> None:
    gw = _gateway(world, sleeps)
    with pytest.raises(RuntimeError, match="not connected"):
        await gw.block()


async def test_connect_and_close(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    assert len(world.clients) == 1
    assert world.clients[0].endpoint == "ws://primary:9944"
    assert world.clients[0].fallbacks is None  # the SDK's own public pool
    await gw.close()
    await gw.close()
    assert world.clients[0].closed


async def test_custom_fallbacks_are_passed_in_order(
    world: World, sleeps: list[float]
) -> None:
    await _connected(world, sleeps, fallbacks=("ws://b:1", "ws://c:1"))
    assert world.clients[0].fallbacks == ["ws://b:1", "ws://c:1"]


async def test_connect_rotates_endpoints_then_gives_up(
    world: World, sleeps: list[float]
) -> None:
    world.fail("connect", *[OSError("refused")] * 5)
    gw = _gateway(world, sleeps, fallbacks=("ws://b:1",))
    with pytest.raises(ChainUnavailable, match="connect failed after 5 attempts"):
        await gw.connect()
    assert [c.endpoint for c in world.clients] == [
        "ws://primary:9944",
        "ws://b:1",
        "ws://primary:9944",
        "ws://b:1",
        "ws://primary:9944",
    ]
    assert all(c.closed for c in world.clients)
    with pytest.raises(RuntimeError, match="not connected"):
        await gw.block()


async def test_connect_recovers_on_fallback(world: World, sleeps: list[float]) -> None:
    world.fail("connect", OSError("refused"))
    gw = await _connected(world, sleeps, fallbacks=("ws://b:1",))
    assert gw.endpoint == "ws://b:1"
    assert world.clients[-1].fallbacks == ["ws://primary:9944"]
    assert await gw.block() == 123


# -- read retries -----------------------------------------------------------------


async def test_read_backoff_schedule(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    world.fail("block", *[bt.ChainError("busy")] * 4)
    assert await gw.block() == 123
    # jitter 0.5 -> exactly the base delay: 0.5, 1, 2, 4
    assert sleeps == [0.5, 1.0, 2.0, 4.0]


async def test_backoff_is_capped_and_jittered(
    world: World, sleeps: list[float]
) -> None:
    gw = _gateway(world, sleeps)
    assert gw._backoff(10) == BACKOFF_MAX_S
    gw._jitter = lambda: 0.0
    assert gw._backoff(1) == 0.25
    gw._jitter = lambda: 0.999
    assert gw._backoff(1) == pytest.approx(0.7495)


async def test_read_exhaustion_raises_chain_unavailable(
    world: World, sleeps: list[float]
) -> None:
    gw = await _connected(world, sleeps)
    world.fail("block", *[bt.RpcConnectionError("gone")] * 5)
    with pytest.raises(ChainUnavailable, match="block failed after 5 attempts") as info:
        await gw.block()
    assert isinstance(info.value.__cause__, bt.RpcConnectionError)
    assert len(sleeps) == 4


async def test_connection_error_rebuilds_client_on_next_endpoint(
    world: World, sleeps: list[float]
) -> None:
    gw = await _connected(world, sleeps, fallbacks=("ws://b:1",))
    world.fail("metagraph", bt.ConnectionNotReady("closed"))
    mg = await gw.metagraph(NETUID)
    assert mg.netuid == NETUID
    assert world.clients[0].closed
    assert world.clients[1].endpoint == "ws://b:1"


async def test_chain_error_keeps_client(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    world.fail("block", bt.ChainError("node busy"))
    assert await gw.block() == 123
    assert len(world.clients) == 1


async def test_read_timeout_is_retried(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps, timeout_s=0.05)
    world.fail("block", HANG)
    assert await gw.block() == 123
    assert len(world.clients) == 2  # a hung connection is replaced


async def test_unexpected_errors_propagate(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    world.fail("block", KeyError("bug"))
    with pytest.raises(KeyError):
        await gw.block()
    assert sleeps == []


async def test_close_errors_are_ignored(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    world.fail("close", OSError("already gone"))
    await gw.close()


# -- reads ------------------------------------------------------------------------


async def test_metagraph_view(world: World, sleeps: list[float]) -> None:
    world.metagraph = _sdk_metagraph(
        [
            _sdk_neuron(0, alpha=100.0, tao=10.0, permit=True, axon="10.0.0.1:8091"),
            _sdk_neuron(1, alpha=4.0, axon="203.0.113.7:8091"),
            _sdk_neuron(2),
        ],
        price=2.5,
        axons=[{"protocol": 87}, {"protocol": 4}, {"protocol": 0}],
    )
    gw = await _connected(world, sleeps, allow_private_axons=True)
    mg = await gw.metagraph(NETUID)
    assert (mg.netuid, mg.block, mg.tempo, mg.fetched_at_monotonic) == (
        NETUID,
        100,
        10,
        1000.0,
    )
    v, m, empty = mg.neurons
    assert v.total_stake_tao == pytest.approx(100.0 * 2.5 + 10.0)
    assert (v.alpha_stake, v.tao_stake) == (100.0, 10.0)
    assert v.validator_permit
    assert v.active
    assert v.axon == Endpoint("10.0.0.1", 8091, is_ipv6=False)
    assert v.axon_protocol == 87
    assert (v.last_update, v.incentive, v.dividends) == (10, 0.25, 0.5)
    assert m.total_stake_tao == pytest.approx(10.0)
    assert m.axon_protocol == 4
    assert empty.axon is None
    assert empty.axon_protocol is None
    assert mg.by_hotkey("hk1") is m


async def test_private_axons_rejected_by_default(
    world: World, sleeps: list[float]
) -> None:
    world.metagraph = _sdk_metagraph(
        [_sdk_neuron(0, axon="10.0.0.1:8091")], axons=[{"protocol": 87}]
    )
    gw = await _connected(world, sleeps)
    (n,) = (await gw.metagraph(NETUID)).neurons
    assert n.axon is None
    assert n.axon_protocol == 87  # published, just not usable


@pytest.mark.parametrize("price", [None, 0.0, -1.0, float("nan"), float("inf")])
def test_no_usable_price_counts_alpha_as_zero(price: float | None) -> None:
    mg = _sdk_metagraph([_sdk_neuron(0, alpha=1000.0, tao=3.0)], price=price)
    (n,) = metagraph_view(mg, fetched_at_monotonic=0, allow_private_axons=False).neurons
    assert n.total_stake_tao == 3.0
    assert n.alpha_stake == 1000.0


def test_root_subnet_alpha_is_tao() -> None:
    neuron = _sdk_neuron(0)
    neuron.alpha_stake = _balance(5.0, 0)
    mg = _sdk_metagraph([neuron], netuid=0, price=None)
    (n,) = metagraph_view(mg, fetched_at_monotonic=0, allow_private_axons=False).neurons
    assert n.total_stake_tao == 5.0


@pytest.mark.parametrize(
    "axons",
    [
        None,
        "not a list",
        [],
        [{"protocol": 256}],
        [{"protocol": -1}],
        [{"protocol": True}],
        [{"protocol": "87"}],
        [{}],
        ["junk"],
    ],
)
def test_bad_raw_axon_records_give_no_protocol(axons: Any) -> None:
    mg = _sdk_metagraph([_sdk_neuron(0, axon="203.0.113.7:1")], axons=axons)
    (n,) = metagraph_view(mg, fetched_at_monotonic=0, allow_private_axons=False).neurons
    assert n.axon_protocol is None


def test_raw_not_a_dict() -> None:
    mg = _sdk_metagraph([_sdk_neuron(0, axon="203.0.113.7:1")])
    mg.raw = None  # type: ignore[assignment]
    (n,) = metagraph_view(mg, fetched_at_monotonic=0, allow_private_axons=False).neurons
    assert n.axon_protocol is None


async def test_metagraph_unknown_subnet(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    with pytest.raises(SubnetNotFound):
        await gw.metagraph(99)
    assert sleeps == []  # not retried


async def test_uid_for_hotkey(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    assert await gw.uid_for_hotkey(NETUID, "hk1") == 1
    world.uid = None
    assert await gw.uid_for_hotkey(NETUID, "nobody") is None
    with pytest.raises(SubnetNotFound):
        await gw.uid_for_hotkey(99, "hk1")


async def test_weights_rate_limit(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    assert await gw.weights_rate_limit(NETUID) == 100
    with pytest.raises(SubnetNotFound):
        await gw.weights_rate_limit(99)
    assert "weights_rate_limit" not in world.calls[-1:]


async def test_blocks_since_last_update(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    assert await gw.blocks_since_last_update(NETUID, 1) == 7
    world.blocks_since = None
    assert await gw.blocks_since_last_update(NETUID, 9) is None
    with pytest.raises(SubnetNotFound):
        await gw.blocks_since_last_update(99, 1)


# -- writes -----------------------------------------------------------------------


async def test_serve_axon_success_and_log(
    world: World, sleeps: list[float], caplog: pytest.LogCaptureFixture
) -> None:
    gw = await _connected(world, sleeps)
    with caplog.at_level(logging.INFO, logger="tensorwire.chain"):
        outcome = await gw.serve_axon(
            NETUID, "203.0.113.7", 8091, tls_cert_hex=None, protocol_tag=87
        )
    assert outcome.ok
    assert outcome.block_hash == "0xabc"
    assert outcome.code is None
    (intent, signer, kwargs) = world.executed[0]
    assert isinstance(intent, bt.ServeAxon)
    assert (intent.netuid, intent.ip, intent.port, intent.protocol) == (
        NETUID,
        "203.0.113.7",
        8091,
        87,
    )
    assert signer is HOTKEY
    assert kwargs == {"wait_for_inclusion": True, "wait_for_finalization": True}
    (record,) = [r for r in caplog.records if r.getMessage() == "chain write"]
    assert record.op == "serve_axon"  # type: ignore[attr-defined]
    assert record.axon == "203.0.113.7:8091"  # type: ignore[attr-defined]
    assert record.block_hash == "0xabc"  # type: ignore[attr-defined]


async def test_serve_axon_tls_and_ipv6(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps, wait_for_finalization=False)
    cert = "0x01" + "ab" * 32
    await gw.serve_axon(NETUID, "2001:db8::1", 443, tls_cert_hex=cert, protocol_tag=0)
    (intent, _, kwargs) = world.executed[0]
    assert isinstance(intent, bt.ServeAxonTls)
    assert intent.certificate == cert
    assert kwargs["wait_for_finalization"] is False


@pytest.mark.parametrize(("tag", "port"), [(256, 1), (-1, 1), (87, 0), (87, 65536)])
async def test_serve_axon_rejects_bad_arguments_without_submitting(
    world: World, sleeps: list[float], tag: int, port: int
) -> None:
    gw = await _connected(world, sleeps)
    outcome = await gw.serve_axon(
        NETUID, "1.2.3.4", port, tls_cert_hex=None, protocol_tag=tag
    )
    assert (outcome.ok, outcome.code) == (False, "invalid_argument")
    assert world.executed == []


async def test_set_weights(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 0.25, 2: 0.75}, mechid=0, version_key=3)
    assert outcome.ok
    (intent, _, _) = world.executed[0]
    assert isinstance(intent, bt.SetWeights)
    assert intent.version_key == 3


@pytest.mark.parametrize(
    "weights", [{}, {1: -0.1}, {1: float("nan")}, {1: float("inf")}]
)
async def test_set_weights_rejects_bad_weights(
    world: World, sleeps: list[float], weights: dict[int, float]
) -> None:
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, weights, mechid=0, version_key=0)
    assert outcome.code == "invalid_argument"
    assert world.executed == []


async def test_writes_need_a_hotkey(world: World, sleeps: list[float]) -> None:
    gw = BittensorGateway(
        "ws://primary:9944",
        client_factory=lambda net, fb: FakeSdkClient(world, net, fb),
    )
    await gw.connect()
    with pytest.raises(RuntimeError, match="no hotkey"):
        await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)


async def test_chain_rejection_is_mapped_not_retried(
    world: World, sleeps: list[float]
) -> None:
    world.results = [_failed("SettingWeightsTooFast", "rate limited")]
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert (outcome.ok, outcome.code) == (False, "rate_limited")
    assert outcome.remediation
    assert len(world.executed) == 1


@pytest.mark.parametrize(
    ("name", "code"),
    [("InvalidRevealRound", "expired"), ("RevealTooEarly", "too_early")],
)
async def test_reveal_round_rejection_is_returned_not_resent(
    world: World, sleeps: list[float], name: str, code: str
) -> None:
    """D32: `expired` comes back after one submission; the scheduler re-plans."""
    world.results = [_failed(name), _ok()]
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert (outcome.ok, outcome.code, outcome.error_name) == (False, code, name)
    assert outcome.replannable
    assert len(world.planned) == 1
    assert len(world.executed) == 1


@pytest.mark.parametrize("name", sorted(RESIGN_ERROR_NAMES))
async def test_pool_rejections_are_resigned(
    world: World, sleeps: list[float], name: str
) -> None:
    world.results = [_failed(name), _ok("0xdef")]
    gw = await _connected(world, sleeps)
    before = world.finalized
    outcome = await gw.serve_axon(
        NETUID, "1.2.3.4", 1, tls_cert_hex=None, protocol_tag=87
    )
    assert outcome.ok
    assert outcome.block_hash == "0xdef"
    assert len(world.executed) == 2
    assert world.finalized > before + 1  # waited for a new finalized block


async def test_resign_is_bounded(world: World, sleeps: list[float]) -> None:
    world.results = [_failed("BadProof")] * 5
    gw = await _connected(world, sleeps, write_attempts=3)
    outcome = await gw.serve_axon(
        NETUID, "1.2.3.4", 1, tls_cert_hex=None, protocol_tag=87
    )
    assert (outcome.ok, outcome.code) == (False, "invalid_argument")
    assert len(world.executed) == 3


@pytest.mark.parametrize("name", ["Retracted", "FinalityTimeout", None])
async def test_maybe_included_is_not_resent(
    world: World, sleeps: list[float], name: str | None
) -> None:
    world.results = [_failed(name) if name else ExtrinsicResult(success=False)]
    gw = await _connected(world, sleeps)
    outcome = await gw.serve_axon(
        NETUID, "1.2.3.4", 1, tls_cert_hex=None, protocol_tag=87
    )
    assert not outcome.ok
    assert len(world.executed) == 1
    if name is None:
        assert outcome.code == "unknown"


@pytest.mark.parametrize(
    "error", [bt.RpcConnectionError("drop"), OSError("reset"), bt.ChainError("x")]
)
async def test_exception_after_submit_is_unknown_fate(
    world: World, sleeps: list[float], error: BaseException
) -> None:
    world.results = [error, _ok()]
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert (outcome.ok, outcome.code) == (False, "unknown")
    assert "may still be included" in (outcome.remediation or "")
    assert len(world.executed) == 1


async def test_write_timeout_is_unknown_fate(world: World, sleeps: list[float]) -> None:
    world.results = [HANG]
    gw = await _connected(world, sleeps, write_timeout_s=0.05)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert outcome.code == "unknown"
    assert len(world.executed) == 1


async def test_policy_error(world: World, sleeps: list[float]) -> None:
    world.results = [bt.PolicyError(["fee too high", "blocked"])]
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert (outcome.code, outcome.remediation) == (
        "policy_violation",
        "fee too high; blocked",
    )


async def test_write_when_chain_unreachable(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    world.fail("metagraph", bt.ConnectionNotReady("x"))  # drops the client
    world.fail("connect", *[OSError("down")] * 100)
    with pytest.raises(ChainUnavailable):
        await gw.metagraph(NETUID)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert outcome.code == "unknown"
    assert "nothing was submitted" in (outcome.remediation or "")
    assert world.executed == []


async def test_finality_wait_is_bounded(world: World, sleeps: list[float]) -> None:
    world.results = [_failed("AncientBirthBlock"), _ok()]
    gw = await _connected(world, sleeps, timeout_s=0.05)

    async def stuck() -> int:
        return 1

    for client in world.clients:
        client.finalized_block = stuck  # type: ignore[method-assign]
    gw._sleep = asyncio.sleep  # real sleep so the timeout can fire
    outcome = await gw.serve_axon(
        NETUID, "1.2.3.4", 1, tls_cert_hex=None, protocol_tag=87
    )
    assert outcome.ok
    assert len(world.executed) == 2


# -- serving rate limit and SDK surface -------------------------------------------


async def test_serving_rate_limit(world: World, sleeps: list[float]) -> None:
    gw = await _connected(world, sleeps)
    assert await gw.serving_rate_limit(NETUID) == 50
    world.serving = None
    assert await gw.serving_rate_limit(NETUID) == 0
    with pytest.raises(SubnetNotFound):
        await gw.serving_rate_limit(99)


def test_installed_sdk_has_the_surface() -> None:
    assert check_sdk_surface() == []
    assert check_sdk_surface(bt.Client("ws://127.0.0.1:9944")) == []


async def test_connect_refuses_sdk_without_a_symbol(
    world: World, sleeps: list[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(bt, "ServeAxonTls")
    gw = _gateway(world, sleeps)
    with pytest.raises(
        SdkSurfaceError, match=r"bittensor\.ServeAxonTls.*>=11\.3\.0,<12"
    ):
        await gw.connect()
    assert world.clients == []


async def test_connect_refuses_client_without_a_read(
    world: World, sleeps: list[float]
) -> None:
    gw = _gateway(world, sleeps)

    def factory(net: str, fb: list[str] | None) -> FakeSdkClient:
        client = FakeSdkClient(world, net, fb)
        client.epochs = SimpleNamespace()
        return client

    gw._factory = factory
    expected = r"Client\.epochs\.blocks_since_last_update"
    with pytest.raises(SdkSurfaceError, match=expected):
        await gw.connect()
    assert world.clients[0].closed
    with pytest.raises(RuntimeError, match="not connected"):
        await gw.block()


def test_missing_exception_class_never_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(bt, "PolicyError")
    error_type = gateway_module._sdk_error("PolicyError")
    assert error_type is gateway_module._MissingSdkError
    assert gateway_module._sdk_error("Client") is gateway_module._MissingSdkError


async def test_policy_error_without_violations(
    world: World, sleeps: list[float]
) -> None:
    error = bt.PolicyError([])
    world.results = [error]
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert outcome.code == "policy_violation"


# -- planning before submission ---------------------------------------------------


async def test_failed_preflight_is_definite_and_not_submitted(
    world: World, sleeps: list[float]
) -> None:
    error = bt.ChainError(
        "Weights on netuid 2 were last set 30 blocks ago; retry in ~70 blocks",
        code=bt.ErrorCode.RATE_LIMITED,
    )
    world.fail("plan", error)
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert (outcome.ok, outcome.code) == (False, "rate_limited")
    assert "retry in ~70 blocks" in (outcome.remediation or "")
    assert world.executed == []
    assert len(world.planned) == 1


async def test_preflight_error_name_is_kept(world: World, sleeps: list[float]) -> None:
    world.fail(
        "plan",
        bt.ChainError(
            "migrations",
            code=bt.ErrorCode.TOO_EARLY,
            name="MultiBlockMigrationsOngoing",
        ),
    )
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert (outcome.code, outcome.error_name) == (
        "too_early",
        "MultiBlockMigrationsOngoing",
    )
    assert world.executed == []


@pytest.mark.parametrize(
    "error", [bt.ChainError("node hiccup"), bt.RpcConnectionError("drop"), HANG]
)
async def test_plan_failure_without_a_code_is_retried(
    world: World, sleeps: list[float], error: Any
) -> None:
    world.fail("plan", error)
    gw = await _connected(world, sleeps, timeout_s=0.05)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert outcome.ok
    assert len(world.planned) == 2
    assert len(world.executed) == 1


async def test_plan_keeps_failing_nothing_submitted(
    world: World, sleeps: list[float]
) -> None:
    world.fail("plan", *[bt.ChainError("down")] * 3)
    gw = await _connected(world, sleeps, write_attempts=3)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert outcome.code == "unknown"
    assert "nothing was submitted" in (outcome.remediation or "")
    assert world.executed == []


async def test_plan_violations(world: World, sleeps: list[float]) -> None:
    world.violations = ["fee above max_fee_tao"]
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert (outcome.code, outcome.remediation) == (
        "policy_violation",
        "fee above max_fee_tao",
    )
    assert world.executed == []


async def test_plan_policy_error(world: World, sleeps: list[float]) -> None:
    world.fail("plan", bt.PolicyError(["blocked"]))
    gw = await _connected(world, sleeps)
    outcome = await gw.set_weights(NETUID, {1: 1.0}, mechid=0, version_key=0)
    assert (outcome.code, outcome.remediation) == ("policy_violation", "blocked")
    assert world.executed == []


# -- timelock (spec 3.7, 8.10, D30) -----------------------------------------------


def _envelope(round_: int) -> str:
    """A parseable envelope naming ``round_`` (decryption is patched)."""
    import struct

    return (b"\x00" * 16 + b"AES_GCM_" + struct.pack("<Q", round_)).hex()


async def test_timelock_seal_is_local_and_parseable() -> None:
    gw = BittensorGateway("local")  # no connection needed
    sealed = await gw.timelock_seal(b"answer", reveal_in_s=30)
    assert gw.timelock_parse(sealed.hex) == sealed
    assert sealed.reveal_at_s >= time.time() + 29
    with pytest.raises(ValueError, match="positive"):
        await gw.timelock_seal(b"x", reveal_in_s=0)


@pytest.mark.parametrize(
    "junk", ["", "zz", "00" * 4, "ab" * 40, _envelope(2**63), _envelope(2**64 - 1)]
)
def test_timelock_junk_is_malformed(junk: str) -> None:
    gw = BittensorGateway("local")
    with pytest.raises(TimelockMalformed):  # incl. a round too large for a date
        gw.timelock_parse(junk)
    with pytest.raises(TimelockMalformed):
        gw.timelock_decrypt(junk, "00" * 48)


async def test_timelock_signature_before_the_round_makes_no_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(gateway_module._core, "get_signature_for_round", calls.append)
    future = bt.timelock.current_round() + 20
    with pytest.raises(TimelockNotReady) as early:
        await BittensorGateway("local").timelock_signature(future, timeout_s=5)
    assert 55 < early.value.remaining_s <= 63
    assert calls == []


async def test_timelock_signature_is_fetched_in_a_thread_and_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading

    core = gateway_module._core
    past = bt.timelock.current_round() - 5
    seen: dict[str, Any] = {}

    def fetch(round_: int) -> str:
        seen.update(round=round_, thread=threading.current_thread())
        return "ab" * 48

    monkeypatch.setattr(core, "get_signature_for_round", fetch)
    plaintext = gateway_module._PROBE
    monkeypatch.setattr(core, "decrypt_with_signature", lambda ct, sig: plaintext)
    gw = BittensorGateway("local")
    assert await gw.timelock_signature(past, timeout_s=5) == "ab" * 48
    assert seen["round"] == past
    assert seen["thread"] is not threading.main_thread()
    # a relay answer that does not open its own round is never used
    monkeypatch.setattr(core, "decrypt_with_signature", lambda probe, sig: b"other")
    with pytest.raises(TimelockUnavailable):
        await gw.timelock_signature(past, timeout_s=5)


@pytest.mark.parametrize(
    "error", [ValueError("Failed to get Drand round: connection error"), OSError("x")]
)
async def test_timelock_drand_failures_are_unavailable(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    def fetch(_round: int) -> str:
        raise error

    monkeypatch.setattr(gateway_module._core, "get_signature_for_round", fetch)
    past = bt.timelock.current_round() - 5
    with pytest.raises(TimelockUnavailable):
        await BittensorGateway("local").timelock_signature(past, timeout_s=1)


async def test_timelock_a_hanging_fetch_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fetch(_round: int) -> str:
        time.sleep(2)  # a drand call that hangs; the thread is abandoned
        return "ab" * 48

    monkeypatch.setattr(gateway_module._core, "get_signature_for_round", fetch)
    started = time.monotonic()
    with pytest.raises(TimelockUnavailable):
        await BittensorGateway("local").timelock_signature(
            bt.timelock.current_round() - 5, timeout_s=0.3
        )
    assert time.monotonic() - started < 1.5


def test_timelock_decrypt_maps_core_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(_data: bytes, _sig: str) -> bytes:
        raise ValueError("Error decrypting ciphertext: InvalidSignature")

    monkeypatch.setattr(gateway_module._core, "decrypt_with_signature", refuse)
    with pytest.raises(TimelockMalformed):
        BittensorGateway("local").timelock_decrypt(_envelope(5), "ab" * 48)
    monkeypatch.setattr(
        gateway_module._core, "decrypt_with_signature", lambda d, s: b"ok"
    )
    assert BittensorGateway("local").timelock_decrypt(_envelope(5), "ab" * 48) == b"ok"


def test_timelock_round_trip_locally() -> None:
    """Real crypto, no network: seal at a past round, open with its signature."""
    core = gateway_module._core
    ciphertext, round_ = core.encrypt_at_round(b"secret", 1000)
    sealed_hex = bt.timelock.Timelocked(
        ciphertext=ciphertext, reveal_round=round_
    ).hex()
    gw = BittensorGateway("local")
    assert gw.timelock_parse(sealed_hex).reveal_round == 1000
    with pytest.raises(TimelockMalformed):  # a signature of no round at all
        gw.timelock_decrypt(sealed_hex, "ab" * 48)
