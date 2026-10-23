"""v10's command-line config on the kit (spec 10b.2.4, D18).

A template-derived subnet builds its config with ``argparse`` plus the SDK's
option groups and ``bt.config``::

    parser = argparse.ArgumentParser()
    bt.wallet.add_args(parser)
    bt.subtensor.add_args(parser)
    bt.logging.add_args(parser)
    bt.axon.add_args(parser)
    cls.add_args(parser)
    return bt.config(parser)

``tensorwire migrate apply`` rewrites those calls to :func:`add_v10_args`
and :func:`config` (TWM032). The v10 option names stay (``--wallet.name``,
``--subtensor.network``, ``--logging.logging_dir``, ``--axon.port``, ...) so
the subnet's own code that reads ``config.wallet.name`` keeps working, but
their defaults come from the kit's ``TW_*`` variables, and the kit never
reads them back: wallet, chain and axon settings are ``TW_*`` settings
(spec Section 12). :func:`fill_v10_groups` writes the values the kit really
uses into an existing config.
"""

from __future__ import annotations

import argparse
import copy
import os
from collections.abc import Iterable, Sequence
from types import SimpleNamespace
from typing import Any

from tensorwire.config import CommonSettings, MinerSettings

__all__ = [
    "V10_GROUPS",
    "Config",
    "add_v10_args",
    "config",
    "fill_defaults",
    "fill_v10_groups",
]

#: The SDK option groups :func:`add_v10_args` knows.
V10_GROUPS = ("wallet", "subtensor", "logging", "axon")


class Config(SimpleNamespace):
    """v10's ``bt.config``: nested attributes (``config.neuron.name``), ``merge``.

    Like v10's (a ``DefaultMunch``), a missing option reads as ``None``:
    template code tests ``config.neuron.disable_set_weights`` on miners,
    where only validators define it.
    """

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        return None

    def merge(self, other: Any) -> Config:
        """Copy every value of ``other`` that this config lacks (v10 semantics)."""
        for name, value in vars(other).items():
            mine = getattr(self, name, None)
            if mine is None:
                setattr(self, name, copy.deepcopy(value))
            elif isinstance(mine, SimpleNamespace) and isinstance(
                value, SimpleNamespace
            ):
                Config.merge(mine, value)  # type: ignore[arg-type]
        return self

    def copy(self) -> Config:
        """A deep copy."""
        return copy.deepcopy(self)

    def get(self, name: str, default: Any = None) -> Any:
        """The option's value, or ``default`` when it is not set."""
        return self.__dict__.get(name, default)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self.__dict__


def _env(name: str, default: str) -> str:
    return os.environ.get(name) or default


def _v10_options(group: str) -> list[tuple[str, dict[str, Any]]]:
    """``(flag, argparse kwargs)`` per option of a v10 group, kit defaults."""
    state = _env("TW_STATE_DIR", "~/.tensorwire")
    port = int(_env("TW_EXTERNAL_PORT", _env("TW_BIND_PORT", "8091")))
    options: dict[str, list[tuple[str, dict[str, Any]]]] = {
        "wallet": [
            ("--wallet.name", {"default": _env("TW_WALLET_NAME", "default")}),
            ("--wallet.hotkey", {"default": _env("TW_WALLET_HOTKEY", "default")}),
            (
                "--wallet.path",
                {"default": _env("TW_WALLET_PATH", "~/.bittensor/wallets")},
            ),
        ],
        "subtensor": [
            ("--subtensor.network", {"default": _env("TW_NETWORK", "test")}),
            ("--subtensor.chain_endpoint", {"default": _env("TW_NETWORK", "test")}),
        ],
        "logging": [
            ("--logging.logging_dir", {"default": state}),
            ("--logging.debug", {"action": "store_true", "default": False}),
            ("--logging.trace", {"action": "store_true", "default": False}),
            ("--logging.info", {"action": "store_true", "default": False}),
            ("--logging.record_log", {"action": "store_true", "default": False}),
        ],
        "axon": [
            ("--axon.port", {"type": int, "default": port}),
            ("--axon.ip", {"default": _env("TW_BIND_HOST", "0.0.0.0")}),  # noqa: S104 - v10's default
            ("--axon.external_ip", {"default": _env("TW_EXTERNAL_IP", "") or None}),
            ("--axon.external_port", {"type": int, "default": port}),
            ("--axon.max_workers", {"type": int, "default": 10}),
        ],
    }
    if group not in options:
        raise ValueError(f"unknown v10 option group {group!r}; known: {V10_GROUPS}")
    return options[group]


def add_v10_args(parser: argparse.ArgumentParser, group: str) -> None:
    """Add v10's ``--<group>.*`` options (what ``bt.<group>.add_args`` did).

    Defaults come from ``TW_*`` variables. An option the parser already has
    is left alone, so calling this twice, or after the subnet's own
    ``--wallet.name``, is harmless.
    """
    known = {flag for action in parser._actions for flag in action.option_strings}
    for flag, kwargs in _v10_options(group):
        if flag not in known:
            parser.add_argument(flag, **kwargs)


def _nest(values: dict[str, Any]) -> Config:
    """``{"neuron.sample_size": 5}`` -> ``config.neuron.sample_size == 5``."""
    root = Config()
    for key, value in values.items():
        *parents, leaf = key.split(".")
        node: SimpleNamespace = root
        for part in parents:
            child = node.__dict__.get(part)
            if not isinstance(child, SimpleNamespace):
                child = Config()
                setattr(node, part, child)
            node = child
        setattr(node, leaf, value)
    return root


def config(
    parser: argparse.ArgumentParser | None = None,
    args: Sequence[str] | None = None,
    *,
    strict: bool = False,
) -> Config:
    """v10's ``bt.config(parser)``: parse the command line into a :class:`Config`.

    Unknown options are ignored (``strict=False``), as v10 did, so running a
    neuron with the old ``--wallet.*`` flags does not fail.
    """
    parser = argparse.ArgumentParser() if parser is None else parser
    if strict:
        namespace = parser.parse_args(args)
    else:
        namespace, _unknown = parser.parse_known_args(args)
    return _nest(vars(namespace))


def _set(node: Any, path: Iterable[str], value: Any) -> None:
    *parents, leaf = path
    for part in parents:
        child = getattr(node, part, None)
        if not isinstance(child, SimpleNamespace):
            child = Config()
            setattr(node, part, child)
        node = child
    setattr(node, leaf, value)


def fill_v10_groups(target: Any, settings: CommonSettings) -> None:
    """Write the values the kit uses into ``target``'s v10 option groups.

    ``config.wallet.name``, ``config.subtensor.network``,
    ``config.logging.logging_dir``, ``config.axon.port`` (miners) and
    ``config.netuid`` then say what the kit really runs with, so subnet code
    that builds paths or log lines from them stays correct.
    """
    values: dict[str, Any] = {
        "netuid": settings.netuid,
        "wallet.name": settings.wallet_name,
        "wallet.hotkey": settings.wallet_hotkey,
        "wallet.path": str(settings.wallet_path),
        "subtensor.network": settings.network,
        "subtensor.chain_endpoint": settings.network,
        "logging.logging_dir": str(settings.state_dir),
    }
    for flag in ("debug", "trace", "info", "record_log"):
        if getattr(getattr(target, "logging", None), flag, None) is None:
            values[f"logging.{flag}"] = False
    if isinstance(settings, MinerSettings):
        values |= {
            "axon.port": settings.effective_external_port,
            "axon.external_port": settings.effective_external_port,
            "axon.ip": settings.bind_host,
            "axon.external_ip": settings.external_ip,
        }
    for key, value in values.items():
        _set(target, key.split("."), value)


def fill_defaults(target: Any, defaults: SimpleNamespace) -> None:
    """Set every attribute of ``defaults`` that ``target`` lacks (recursively)."""
    for name, value in vars(defaults).items():
        current = getattr(target, name, None)
        if current is None:
            setattr(target, name, value)
        elif isinstance(value, SimpleNamespace):
            fill_defaults(current, value)
