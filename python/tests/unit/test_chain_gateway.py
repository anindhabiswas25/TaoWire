from __future__ import annotations

import dataclasses

import pytest

from taowire.chain.axon import Endpoint
from taowire.chain.gateway import (
    ChainGateway,
    ChainUnavailable,
    GatewayError,
    MetagraphView,
    NeuronView,
    SubnetNotFound,
    TxOutcome,
)
from taowire.testing.fake_chain import FakeChain


def _neuron(uid: int, hotkey: str, *, permit: bool = False) -> NeuronView:
    return NeuronView(
        uid=uid,
        hotkey=hotkey,
        coldkey=f"cold-{hotkey}",
        validator_permit=permit,
        active=True,
        total_stake_tao=10.0 * uid,
        alpha_stake=1.0,
        tao_stake=0.5,
        axon=Endpoint(host="203.0.113.7", port=8090 + uid, is_ipv6=False),
        last_update=5,
        incentive=0.0,
        dividends=0.0,
    )


def _view(*neurons: NeuronView) -> MetagraphView:
    return MetagraphView(
        netuid=2, block=100, fetched_at_monotonic=12.5, neurons=neurons, tempo=360
    )


def test_by_hotkey() -> None:
    a, b = _neuron(0, "hk-a"), _neuron(1, "hk-b")
    view = _view(a, b)
    assert view.by_hotkey("hk-b") is b
    assert view.by_hotkey("hk-c") is None


def test_validators_in_uid_order() -> None:
    view = _view(
        _neuron(0, "a", permit=True), _neuron(1, "b"), _neuron(2, "c", permit=True)
    )
    assert [n.uid for n in view.validators()] == [0, 2]


def test_views_are_immutable() -> None:
    view = _view(_neuron(0, "a"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        view.block = 1  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        view.neurons[0].validator_permit = True  # type: ignore[misc]


def test_view_equality_ignores_index() -> None:
    assert _view(_neuron(0, "a")) == _view(_neuron(0, "a"))
    assert "_by_hotkey" not in repr(_view(_neuron(0, "a")))


def test_axon_protocol_defaults_to_none() -> None:
    assert _neuron(0, "a").axon_protocol is None


def test_tx_outcome_fields() -> None:
    outcome = TxOutcome(
        ok=False, code="rate_limited", remediation="wait", block_hash=None
    )
    assert not outcome.ok
    assert outcome.code == "rate_limited"


def test_error_hierarchy() -> None:
    assert issubclass(ChainUnavailable, GatewayError)
    assert issubclass(SubnetNotFound, GatewayError)


def test_fake_chain_implements_protocol() -> None:
    assert isinstance(FakeChain(), ChainGateway)
