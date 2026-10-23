"""compat.neuron: the template's neuron surface on the kit (10b.2.4, D18)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tensorwire.chain.gateway import MetagraphView, NeuronView
from tensorwire.compat import Metagraph
from tensorwire.compat.neuron import (
    HotkeyWallet,
    SubtensorView,
    TemplateNeuronSurface,
    interrupt,
)
from tensorwire.config import ValidatorSettings
from tensorwire.crypto import verify
from tensorwire.testing.keys import dev_key

ALICE = dev_key("alice")
BOB = dev_key("bob")


def wallet() -> HotkeyWallet:
    return HotkeyWallet(ALICE.keypair, name="w", hotkey_name="h", path="/p")


def test_wallet_has_the_hotkey_only() -> None:
    w = wallet()
    assert w.hotkey.ss58_address == ALICE.ss58
    assert w.hotkey.public_key == bytes(ALICE.keypair.public_key)
    for message in ("text", b"bytes"):
        signature = w.hotkey.sign(message)
        data = message.encode() if isinstance(message, str) else message
        assert verify(data, signature, ALICE.ss58, ALICE.keypair.crypto_type)
    with pytest.raises(AttributeError, match="never loads the coldkey"):
        _ = w.coldkey
    with pytest.raises(AttributeError, match="never loads the coldkey"):
        _ = w.coldkeypub
    assert str(w) == "wallet(w, h, /p)"
    assert ALICE.ss58 in repr(w.hotkey)


def neuron(uid: int, hotkey: str) -> NeuronView:
    return NeuronView(
        uid=uid,
        hotkey=hotkey,
        coldkey=hotkey,
        validator_permit=False,
        active=True,
        total_stake_tao=0.0,
        alpha_stake=0.0,
        tao_stake=0.0,
        axon=None,
        last_update=0,
        incentive=0.0,
        dividends=0.0,
    )


SNAPSHOT = MetagraphView(
    netuid=4,
    block=123,
    fetched_at_monotonic=0.0,
    neurons=(neuron(0, ALICE.ss58), neuron(1, BOB.ss58)),
    tempo=10,
)


def view(tmp_path: Path) -> SubtensorView:
    s = ValidatorSettings(
        netuid=4, wallet_name="v", wallet_path=tmp_path, network="local"
    )
    return SubtensorView(s, lambda: SNAPSHOT, lambda: Metagraph(SNAPSHOT))


def test_subtensor_view_answers_template_reads(tmp_path: Path) -> None:
    st = view(tmp_path)
    assert (st.network, st.chain_endpoint) == ("local", "local")
    assert st.block == st.get_current_block() == 123
    assert st.metagraph(4).hotkeys == [ALICE.ss58, BOB.ss58]
    assert st.metagraph().n == 2
    assert st.is_hotkey_registered(netuid=4, hotkey_ss58=BOB.ss58)
    assert not st.is_hotkey_registered(hotkey_ss58=dev_key("eve").ss58)
    assert repr(st) == "subtensor(local)"


def test_subtensor_view_refuses_other_subnets_and_writes(tmp_path: Path) -> None:
    st = view(tmp_path)
    with pytest.raises(ValueError, match="TW_NETUID=4"):
        st.metagraph(5)
    with pytest.raises(TypeError, match="hotkey_ss58"):
        st.is_hotkey_registered(netuid=4)
    with pytest.raises(AttributeError, match="sets weights itself"):
        st.set_weights  # noqa: B018 - the attribute access is the test
    with pytest.raises(AttributeError):
        st._private  # noqa: B018


def test_sync_keeps_the_template_order() -> None:
    calls: list[str] = []

    class Neuron(TemplateNeuronSurface):
        def check_registered(self) -> None:
            calls.append("registered")

        def resync_metagraph(self) -> None:
            calls.append("resync")

        def should_set_weights(self) -> bool:
            return True

        def set_weights(self) -> None:
            calls.append("weights")

        def save_state(self) -> None:
            calls.append("save")

    Neuron().sync()
    assert calls == ["registered", "resync", "weights", "save"]


def test_surface_defaults() -> None:
    n = TemplateNeuronSurface()
    n.check_registered()
    n.serve_axon()
    n.resync_metagraph()
    n.set_weights()
    n.load_state()
    assert n.should_sync_metagraph() is True
    assert n.should_set_weights() is False
    n.sync()


def test_interrupt_raises_keyboard_interrupt() -> None:
    with pytest.raises(KeyboardInterrupt):
        interrupt(15, None)
