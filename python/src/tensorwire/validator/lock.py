"""One signing process per validator hotkey (spec 8.4.1).

Two processes signing with one hotkey can produce the same nonce, and
miners then reject the second request as a replay. The validator holds an
exclusive ``flock`` on ``TW_STATE_DIR/locks/<hotkey>.lock`` while it runs;
a second validator with the same hotkey refuses to start, and
``tensorwire doctor`` reports a running holder.

The lock is advisory and per host: it cannot see a process on another
machine using the same hotkey.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path

__all__ = ["HotkeyLock", "HotkeyLockHeld", "lock_path"]


class HotkeyLockHeld(Exception):
    """Another process on this host signs with the same hotkey."""


def lock_path(state_dir: Path, hotkey_ss58: str) -> Path:
    """Where the lock for ``hotkey_ss58`` lives."""
    return state_dir / "locks" / f"{hotkey_ss58}.lock"


class HotkeyLock:
    """An exclusive, non-blocking ``flock`` on the hotkey's lock file."""

    def __init__(self, state_dir: Path, hotkey_ss58: str) -> None:
        self.path = lock_path(state_dir, hotkey_ss58)
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        """Whether this object holds the lock."""
        return self._fd is not None

    def acquire(self) -> None:
        """Take the lock, or raise :class:`HotkeyLockHeld`."""
        if self._fd is not None:
            return
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise HotkeyLockHeld(
                f"another process on this host signs as this hotkey ({self.path}); "
                "run one validator process per hotkey"
            ) from None
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        self._fd = fd

    def release(self) -> None:
        """Release the lock. Safe to call more than once."""
        fd, self._fd = self._fd, None
        if fd is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def is_held_elsewhere(self) -> bool:
        """Whether another process holds the lock now (for ``doctor``)."""
        if self._fd is not None or not self.path.exists():
            return False
        fd = os.open(self.path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        finally:
            os.close(fd)
        return False
