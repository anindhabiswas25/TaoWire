"""compat.config: v10's ``bt.config`` and option groups on the kit (10b.2.4, D18)."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

from tensorwire.compat.config import (
    V10_GROUPS,
    Config,
    add_v10_args,
    config,
    fill_defaults,
    fill_v10_groups,
)
from tensorwire.config import MinerSettings, ValidatorSettings
from tensorwire.testing.pytest_plugin import TWEnv


def parser_with(*groups: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    for group in groups:
        add_v10_args(parser, group)
    parser.add_argument("--neuron.name", default="miner")
    return parser


def test_every_group_parses_with_kit_defaults(tw_env: TWEnv) -> None:
    tw_env.set(wallet_name="w1", wallet_hotkey="h1", network="local", state_dir="/s")
    c = config(parser_with(*V10_GROUPS), [])
    assert (c.wallet.name, c.wallet.hotkey) == ("w1", "h1")
    assert c.subtensor.network == "local"
    assert c.logging.logging_dir == "/s"
    assert c.logging.debug is False
    assert c.axon.port == 8091
    assert c.neuron.name == "miner"


def test_unknown_options_are_ignored_unless_strict() -> None:
    p = parser_with("wallet")
    c = config(p, ["--neuron.name", "x", "--subtensor.network", "finney"])
    assert c.neuron.name == "x"
    assert not hasattr(c, "subtensor")
    with pytest.raises(SystemExit):
        config(p, ["--subtensor.network", "finney"], strict=True)


def test_adding_a_group_twice_or_over_own_options_is_harmless() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--wallet.name", default="mine")
    add_v10_args(p, "wallet")
    add_v10_args(p, "wallet")
    assert config(p, []).wallet.name == "mine"


def test_unknown_group() -> None:
    with pytest.raises(ValueError, match="unknown v10 option group"):
        add_v10_args(argparse.ArgumentParser(), "dendrite")


def test_merge_keeps_own_values_and_adds_missing_ones() -> None:
    mine = config(parser_with("wallet"), ["--wallet.name", "a"])
    other = Config(wallet=Config(name="b", path="/p"), extra=SimpleNamespace(x=1))
    merged = mine.merge(other)
    assert merged is mine
    assert (mine.wallet.name, mine.wallet.path) != ("b", "/p")
    assert mine.wallet.name == "a"
    assert mine.extra.x == 1
    other.extra.x = 2
    assert mine.extra.x == 1  # deep-copied
    assert "wallet" in mine
    assert 3 not in mine
    assert mine.get("missing", 5) == 5
    copy = mine.copy()
    copy.wallet.name = "c"
    assert mine.wallet.name == "a"


def test_merge_into_a_plain_value_does_not_recurse() -> None:
    mine = Config(wallet="flat")
    mine.merge(Config(wallet=Config(name="b")))
    assert mine.wallet == "flat"


def test_fill_v10_groups_reports_what_the_kit_uses(tmp_path: Path) -> None:
    s = MinerSettings(
        netuid=7,
        wallet_name="m",
        wallet_path=tmp_path,
        external_ip="44.1.2.3",
        external_port=9000,
        network="local",
        state_dir=tmp_path / "state",
    )
    c = config(parser_with(*V10_GROUPS), ["--wallet.name", "typo", "--logging.debug"])
    fill_v10_groups(c, s)
    assert c.netuid == 7
    assert c.wallet.name == "m"
    assert c.axon.port == 9000
    assert c.axon.external_ip == "44.1.2.3"
    assert c.logging.logging_dir == str(tmp_path / "state")
    assert c.logging.debug is True  # the subnet's own flag is kept


def test_fill_v10_groups_on_an_empty_validator_config(tmp_path: Path) -> None:
    s = ValidatorSettings(netuid=3, wallet_name="v", wallet_path=tmp_path)
    c = SimpleNamespace()
    fill_v10_groups(c, s)
    assert c.netuid == 3
    assert c.wallet.name == "v"
    assert c.logging.trace is False
    assert not hasattr(c, "axon")


def test_fill_defaults_fills_only_missing_values() -> None:
    target = SimpleNamespace(neuron=SimpleNamespace(name="mine", device=None))
    fill_defaults(
        target,
        SimpleNamespace(
            neuron=SimpleNamespace(name="x", device="cpu", epoch_length=100),
            blacklist=SimpleNamespace(force_validator_permit=False),
        ),
    )
    assert target.neuron.name == "mine"
    assert target.neuron.device == "cpu"
    assert target.neuron.epoch_length == 100
    assert target.blacklist.force_validator_permit is False
