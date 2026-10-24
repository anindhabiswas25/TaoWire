"""Shared types for the localnet tests (see conftest.py)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import bittensor as bt
from bittensor.keyfiles import Keypair

#: ``$LOCALNET_DIR`` (``localnet_up.sh``); a second chain has its own.
STATE_DIR = Path(os.environ.get("LOCALNET_DIR", "~/.taowire/localnet")).expanduser()


def _endpoint() -> str:
    """The chain ``localnet_up.sh`` set up (``localnet.json``), else the default."""
    try:
        info = json.loads((STATE_DIR / "localnet.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "ws://127.0.0.1:9944"
    return str(info.get("endpoint", "ws://127.0.0.1:9944"))


ENDPOINT = _endpoint()
#: ``(host, port)`` of :data:`ENDPOINT`.
ENDPOINT_ADDR = (
    urlsplit(ENDPOINT).hostname or "127.0.0.1",
    urlsplit(ENDPOINT).port or 9944,
)


@dataclass(frozen=True)
class Localnet:
    """What ``localnet_up.sh`` prepared (``localnet.json``)."""

    netuid: int
    wallet_path: Path
    wallets: dict[str, dict[str, Any]]
    block_time_s: float

    def wait_s(self, blocks: int, floor_s: float) -> float:
        """A timeout for something that takes ``blocks`` blocks on this chain.

        The same tests run on fast blocks (0.25 s) and on real 12 s blocks
        (spec 14.2): a rate limit of 100 blocks is 25 s on one and 20 min on
        the other. Never less than ``floor_s``; 50% headroom plus 30 s.
        """
        return max(floor_s, blocks * self.block_time_s * 1.5 + 30.0)

    def hotkey(self, wallet: str) -> Keypair:
        """The ``default`` hotkey of a dev wallet (never the coldkey)."""
        hotkey: Keypair = bt.Wallet(
            name=wallet, hotkey="default", path=str(self.wallet_path)
        ).hotkey
        return hotkey
