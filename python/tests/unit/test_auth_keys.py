"""auth/keys.py: hotkey-only loading and the coldkey guard (8.7.3 step 2, trap 13)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from bittensor import sp_core

from tensorwire.auth.keys import (
    ColdkeyState,
    coldkey_path,
    coldkey_state,
    hotkey_path,
    load_hotkey,
)
from tensorwire.errors import StartupError
from tensorwire.testing.keys import dev_key

ALICE = dev_key("alice").keypair


def keyfile(path: Path, *, password: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = sp_core.serialized_keypair_to_keyfile_data(ALICE)
    if password is not None:
        data = sp_core.encrypt_keyfile_data(data, password)
    path.write_bytes(data)


def test_paths(tmp_path: Path) -> None:
    assert hotkey_path(tmp_path, "w", "h") == tmp_path / "w" / "hotkeys" / "h"
    assert coldkey_path(tmp_path, "w") == tmp_path / "w" / "coldkey"


def test_coldkey_states(tmp_path: Path) -> None:
    assert coldkey_state(tmp_path, "w") is ColdkeyState.ABSENT
    keyfile(coldkey_path(tmp_path, "w"))
    assert coldkey_state(tmp_path, "w") is ColdkeyState.UNENCRYPTED
    keyfile(coldkey_path(tmp_path, "w"), password="pw")
    assert coldkey_state(tmp_path, "w") is ColdkeyState.ENCRYPTED


def test_unreadable_coldkey(tmp_path: Path) -> None:
    coldkey_path(tmp_path, "d").mkdir(parents=True)  # a directory, not a keyfile
    assert coldkey_state(tmp_path, "d") is ColdkeyState.UNREADABLE
    if os.geteuid() != 0:  # root can read anything
        keyfile(coldkey_path(tmp_path, "w"))
        coldkey_path(tmp_path, "w").chmod(0)
        assert coldkey_state(tmp_path, "w") is ColdkeyState.UNREADABLE


def test_coldkey_read_error_counts_as_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keyfile(coldkey_path(tmp_path, "w"))

    def fail(self: Path) -> bytes:
        raise PermissionError

    monkeypatch.setattr(Path, "read_bytes", fail)
    assert coldkey_state(tmp_path, "w") is ColdkeyState.UNREADABLE


def test_load_hotkey(tmp_path: Path) -> None:
    keyfile(hotkey_path(tmp_path, "w", "default"))
    assert load_hotkey(tmp_path, "w", "default").ss58_address == ALICE.ss58_address


def test_load_hotkey_missing(tmp_path: Path) -> None:
    with pytest.raises(StartupError, match="hotkey file not found"):
        load_hotkey(tmp_path, "w", "default")


def test_load_hotkey_encrypted(tmp_path: Path) -> None:
    keyfile(hotkey_path(tmp_path, "w", "default"), password="pw")
    with pytest.raises(StartupError, match="is encrypted"):
        load_hotkey(tmp_path, "w", "default")


def test_load_hotkey_invalid_content(tmp_path: Path) -> None:
    path = hotkey_path(tmp_path, "w", "default")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"s3cr3t-l00king bytes")
    with pytest.raises(StartupError, match="not a valid keyfile") as info:
        load_hotkey(tmp_path, "w", "default")
    assert "s3cr3t" not in str(info.value)


def test_load_hotkey_unreadable(tmp_path: Path) -> None:
    hotkey_path(tmp_path, "w", "default").mkdir(parents=True)
    with pytest.raises(StartupError, match="cannot read hotkey file"):
        load_hotkey(tmp_path, "w", "default")
