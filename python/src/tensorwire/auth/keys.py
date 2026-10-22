"""Hotkey loading and the coldkey guard (spec 8.7.3 step 2, trap 13).

A miner signs with its **hotkey** only. This module reads the hotkey file
directly (``<wallet_path>/<wallet>/hotkeys/<hotkey>``) and never builds a
``bittensor.Wallet``, so no code path can reach the coldkey's private key.

The coldkey guard looks at ``<wallet_path>/<wallet>/coldkey`` without
decrypting it: an unencrypted coldkey on a server means a compromise of the
server is a compromise of the funds, so the miner refuses to start (unless
``TW_REFUSE_IF_COLDKEY_PRESENT=0``). An encrypted one only gets a warning.
"""

from __future__ import annotations

import enum
import os
from pathlib import Path

from bittensor import sp_core
from bittensor.signing import WalletLike

from tensorwire.errors import StartupError

__all__ = [
    "ColdkeyState",
    "WalletLike",
    "coldkey_path",
    "coldkey_state",
    "hotkey_path",
    "load_hotkey",
]


class ColdkeyState(enum.Enum):
    """What sits at the wallet's coldkey path."""

    ABSENT = "absent"
    UNREADABLE = "unreadable"
    ENCRYPTED = "encrypted"
    UNENCRYPTED = "unencrypted"


def hotkey_path(wallet_path: Path, wallet_name: str, hotkey: str) -> Path:
    """Where the SDK keeps a wallet's hotkey file."""
    return wallet_path.expanduser() / wallet_name / "hotkeys" / hotkey


def coldkey_path(wallet_path: Path, wallet_name: str) -> Path:
    """Where the SDK keeps a wallet's coldkey file."""
    return wallet_path.expanduser() / wallet_name / "coldkey"


def coldkey_state(wallet_path: Path, wallet_name: str) -> ColdkeyState:
    """Classify the coldkey file. Reads it only to test for encryption."""
    path = coldkey_path(wallet_path, wallet_name)
    if not path.exists():
        return ColdkeyState.ABSENT
    if not path.is_file() or not os.access(path, os.R_OK):
        return ColdkeyState.UNREADABLE
    try:
        encrypted = bool(sp_core.keyfile_data_is_encrypted(path.read_bytes()))
    except OSError:
        return ColdkeyState.UNREADABLE
    return ColdkeyState.ENCRYPTED if encrypted else ColdkeyState.UNENCRYPTED


def load_hotkey(wallet_path: Path, wallet_name: str, hotkey: str) -> sp_core.Keypair:
    """Load an unencrypted hotkey keypair, or raise :class:`StartupError`.

    The returned ``Keypair`` can be used anywhere the SDK expects a wallet.
    Error messages name the file, never its contents.
    """
    path = hotkey_path(wallet_path, wallet_name, hotkey)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise StartupError(
            f"hotkey file not found: {path} (check TW_WALLET_PATH, "
            "TW_WALLET_NAME and TW_WALLET_HOTKEY)"
        ) from None
    except OSError as exc:
        raise StartupError(f"cannot read hotkey file {path}: {exc.strerror}") from None
    if sp_core.keyfile_data_is_encrypted(data):
        raise StartupError(
            f"hotkey file {path} is encrypted; a server needs an unencrypted "
            "hotkey (btcli creates hotkeys unencrypted by default)"
        )
    try:
        return sp_core.deserialize_keypair_from_keyfile_data(data)
    except sp_core.KeyfileError:
        raise StartupError(f"hotkey file {path} is not a valid keyfile") from None
