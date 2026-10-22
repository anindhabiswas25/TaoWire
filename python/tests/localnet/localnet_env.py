"""Shared types for the localnet tests (see conftest.py)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import bittensor as bt
from bittensor.keyfiles import Keypair

ENDPOINT = "ws://127.0.0.1:9944"


@dataclass(frozen=True)
class Localnet:
    """What ``localnet_up.sh`` prepared (``localnet.json``)."""

    netuid: int
    wallet_path: Path
    wallets: dict[str, dict[str, Any]]
    block_time_s: float

    def hotkey(self, wallet: str) -> Keypair:
        """The ``default`` hotkey of a dev wallet (never the coldkey)."""
        hotkey: Keypair = bt.Wallet(
            name=wallet, hotkey="default", path=str(self.wallet_path)
        ).hotkey
        return hotkey
