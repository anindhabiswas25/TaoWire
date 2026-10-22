"""compat: priority gate, Axon rules, weights, Metagraph view, Dendrite helpers."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from tensorwire.chain.axon import parse_axon
from tensorwire.chain.gateway import MetagraphView, NeuronView
from tensorwire.compat import Axon, AxonInfo, Dendrite, Metagraph, Synapse, weights
from tensorwire.compat.axon import PriorityGate
from tensorwire.compat.dendrite import axons_from, status_code_for
from tensorwire.errors import RateLimited
from tensorwire.miner.app import Miner
from tensorwire.testing.keys import dev_key
from tensorwire.validator.client import MinerResult, ValidatorClient


class Ping(Synapse):
    value: int = 0


def neuron(uid: int, axon: str | None = "44.0.0.1:8091", **kw: Any) -> NeuronView:
    options: dict[str, Any] = {
        "uid": uid,
        "hotkey": f"hk{uid}",
        "coldkey": f"ck{uid}",
        "validator_permit": False,
        "active": True,
        "total_stake_tao": float(uid),
        "alpha_stake": 0.0,
        "tao_stake": 0.0,
        "axon": parse_axon(axon, allow_private=True) if axon else None,
        "last_update": uid,
        "incentive": 0.1,
        "dividends": 0.2,
    }
    options.update(kw)
    return NeuronView(**options)


def view(*neurons: NeuronView) -> MetagraphView:
    return MetagraphView(
        netuid=1, block=10, fetched_at_monotonic=0.0, neurons=neurons, tempo=360
    )


# ---------------------------------------------------------------- priority gate


async def test_gate_admits_up_to_the_limit_then_by_priority() -> None:
    gate = PriorityGate(limit=1, max_queue=3)
    await gate.acquire(0)
    order: list[float] = []

    async def wait(p: float) -> None:
        await gate.acquire(p)
        order.append(p)
        gate.release()

    tasks = [asyncio.create_task(wait(p)) for p in (1.0, 5.0, 3.0)]
    await asyncio.sleep(0)
    assert gate.queued == 3
    with pytest.raises(RateLimited):
        await gate.acquire(9.0)  # queue full
    gate.release()
    await asyncio.gather(*tasks)
    assert order == [5.0, 3.0, 1.0]
    assert gate.active == 0


async def test_gate_skips_cancelled_waiters() -> None:
    gate = PriorityGate(limit=1, max_queue=2)
    await gate.acquire(0)
    waiter = asyncio.create_task(gate.acquire(1))
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert gate.queued == 0
    gate.release()
    assert gate.active == 0


def test_gate_bounds() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        PriorityGate(0, 1)


# ---------------------------------------------------------------- Axon rules


@pytest.fixture
def axon(tw_miner_kwargs: dict[str, Any]) -> Axon:
    return Axon(miner=Miner(**tw_miner_kwargs))


async def forward(synapse: Ping) -> Ping:
    return synapse


def test_attach_registers_the_synapse_path(axon: Axon) -> None:
    assert axon.attach(forward_fn=forward) is axon
    route = axon.miner.routes.get("/Ping")
    assert route is not None
    assert route.legacy_synapse is Ping
    assert axon.app is axon.miner.app
    assert axon.serve() is axon


def test_custom_verify_fn_is_refused(axon: Axon) -> None:
    with pytest.raises(ValueError, match="verify_fn is not supported"):
        axon.attach(forward_fn=forward, verify_fn=lambda s: None)


def test_forward_must_be_annotated(axon: Axon) -> None:
    async def untyped(synapse):  # type: ignore[no-untyped-def]
        return synapse

    with pytest.raises(TypeError, match="annotate forward_fn"):
        axon.attach(forward_fn=untyped)
    with pytest.raises(TypeError, match="first argument"):
        axon.attach(forward_fn=lambda: None)


def test_attach_twice_is_refused(axon: Axon) -> None:
    axon.attach(forward_fn=forward)
    with pytest.raises(ValueError, match="already attached"):
        axon.attach(forward_fn=forward)


def test_v10_constructor_arguments_are_refused(tw_miner_kwargs: dict[str, Any]) -> None:
    with pytest.raises(TypeError, match="config, wallet"):
        Axon(miner=Miner(**tw_miner_kwargs), wallet=object(), config=object())


def test_serve_checks_the_netuid(axon: Axon) -> None:
    with pytest.raises(ValueError, match="TW_NETUID"):
        axon.serve(netuid=999)


# ---------------------------------------------------------------- weights


def test_to_mapping() -> None:
    assert weights.to_mapping([0, 3], [0.5, 0.0]) == {0: 0.5, 3: 0.0}

    class Arr:
        def __init__(self, v: list[Any]) -> None:
            self.v = v

        def tolist(self) -> list[Any]:
            return self.v

    assert weights.to_mapping(Arr([1]), Arr([2])) == {1: 2.0}


@pytest.mark.parametrize(
    ("uids", "values", "match"),
    [
        ([0, 1], [1.0], "must match"),
        ([0, 0], [1.0, 1.0], "twice"),
        ([-1], [1.0], "invalid uid"),
        ([1.5], [1.0], "invalid uid"),
        ([0], [-1.0], "invalid weight"),
        ([0], [float("nan")], "invalid weight"),
    ],
)
def test_to_mapping_rejects(uids: list[Any], values: list[Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        weights.to_mapping(uids, values)


def test_to_mapping_needs_sequences() -> None:
    with pytest.raises(TypeError):
        weights.to_mapping("01", [1, 2])
    with pytest.raises(TypeError):
        weights.to_mapping(5, [1])


# ---------------------------------------------------------------- Metagraph view


def test_metagraph_view_attributes() -> None:
    mg = Metagraph(view(neuron(1, axon=None), neuron(0, validator_permit=True)))
    assert mg.n == 2
    assert (mg.netuid, mg.block) == (1, 10)
    assert mg.uids == [0, 1]
    assert mg.hotkeys == ["hk0", "hk1"]
    assert mg.coldkeys == ["ck0", "ck1"]
    assert mg.S == [0.0, 1.0]
    assert mg.validator_permit == [True, False]
    assert mg.last_update == [0, 1]
    assert mg.I == [0.1, 0.1]
    assert mg.D == [0.2, 0.2]
    assert [a.is_serving for a in mg.axons] == [True, False]
    assert mg.axons[1].ip == "0.0.0.0"
    mg.sync(subtensor=None)


def test_metagraph_view_over_a_source() -> None:
    class Source:
        snap: MetagraphView | None = None

        def snapshot(self) -> MetagraphView | None:
            return self.snap

    source = Source()
    mg = Metagraph(source)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="no metagraph"):
        _ = mg.hotkeys
    source.snap = view(neuron(0), neuron(2))
    with pytest.raises(RuntimeError, match="contiguous"):
        _ = mg.hotkeys


# ---------------------------------------------------------------- Dendrite helpers


def test_axons_from() -> None:
    mg = view(neuron(0), neuron(1, axon=None))
    assert [a.uid for a in axons_from(mg)] == [0, 1]
    assert [a.hotkey for a in axons_from(mg, uids=[1, 0])] == ["hk1", "hk0"]
    with pytest.raises(KeyError):
        axons_from(mg, uids=[7])


def result(**kw: Any) -> MinerResult:
    options: dict[str, Any] = {
        "uid": 0,
        "hotkey": "hk",
        "ok": False,
        "status": None,
        "latency_ms": None,
        "data": None,
        "error_code": None,
        "attempts": 1,
    }
    options.update(kw)
    return MinerResult(**options)


@pytest.mark.parametrize(
    ("kw", "code"),
    [
        ({"ok": True, "status": 200}, 200),
        ({"error_code": "tw.timeout"}, 408),
        ({"error_code": "tw.connect_error"}, 503),
        ({"error_code": "tw.forbidden_denied", "status": 403}, 403),
        ({"error_code": "tw.bad_response_signature", "status": 200}, 500),
        ({"error_code": "tw.invalid_response"}, 500),
    ],
)
def test_status_code_for(kw: dict[str, Any], code: int) -> None:
    assert status_code_for(result(**kw)) == code


async def test_dendrite_construction() -> None:
    signer = dev_key("alice").signer()
    with pytest.raises(TypeError, match="signer= or client="):
        Dendrite()
    client = ValidatorClient(signer)
    with pytest.raises(TypeError, match="not both"):
        Dendrite(signer, client=client)
    d = Dendrite(signer, timeout_s=3.0)
    assert d.hotkey == dev_key("alice").ss58
    assert d.client.timeout_s == 3.0
    with pytest.raises(NotImplementedError):
        await d.forward([], Ping(), streaming=True)
    await d.aclose()
    await client.aclose()


async def test_dendrite_without_neuron_info() -> None:
    d = Dendrite(dev_key("alice").signer())
    bare = AxonInfo(ip="1.2.3.4", port=1, hotkey="hk")
    (item,) = await d([bare], Ping(value=1), deserialize=False)
    assert item.dendrite.status_code == 503
    assert item.dendrite.status_message == "tw.no_axon"
    await d.aclose()
