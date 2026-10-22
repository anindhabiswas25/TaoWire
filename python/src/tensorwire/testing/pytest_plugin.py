"""pytest fixtures shipped with TensorWire (registered through the ``pytest11`` entry point).

Kept import-light: pytest loads this module in every project that has
``tensorwire`` installed.
"""

from __future__ import annotations

import os

import pytest

__all__ = ["TWEnv", "tw_env"]


class TWEnv:
    """Sets ``TW_*`` variables for one test; everything is undone afterwards."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._mp = monkeypatch

    def set(self, **values: object) -> None:
        """Set ``TW_<NAME>`` for each keyword; booleans become ``1``/``0``.

        ``set(netuid=1, metagraph_strict=True)`` sets ``TW_NETUID=1`` and
        ``TW_METAGRAPH_STRICT=1``.
        """
        for name, value in values.items():
            text = ("1" if value else "0") if isinstance(value, bool) else str(value)
            self._mp.setenv(f"TW_{name.upper()}", text)

    def unset(self, *names: str) -> None:
        """Remove ``TW_<NAME>`` for each name, if set."""
        for name in names:
            self._mp.delenv(f"TW_{name.upper()}", raising=False)


@pytest.fixture
def tw_env(monkeypatch: pytest.MonkeyPatch) -> TWEnv:
    """A clean ``TW_*`` environment: every inherited ``TW_*`` variable is removed."""
    for name in list(os.environ):
        if name.upper().startswith("TW_"):
            monkeypatch.delenv(name)
    return TWEnv(monkeypatch)
