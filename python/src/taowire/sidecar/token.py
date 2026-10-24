"""The sidecar's bearer token (spec 11.6, 12.4).

The token lives in ``TW_SIDECAR_TOKEN_FILE`` (default
``$TW_STATE_DIR/sidecar.token``). The first run generates it (32 random bytes,
URL-safe base64) and writes it with mode 0600; later runs read it and refuse a
file that is not a regular file or that group or others can read or write
(the TLS key rule). The token is never logged; errors name the file only.
Requests are compared in constant time.
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Final

from taowire.errors import StartupError

__all__ = ["TOKEN_LENGTH", "load_or_create_token", "token_matches"]

#: Shortest and longest accepted token.
TOKEN_LENGTH: Final = (16, 1024)

_PRINTABLE = re.compile(r"[\x21-\x7e]+")
_BEARER = "Bearer "


def _check(token: str, path: Path) -> str:
    low, high = TOKEN_LENGTH
    if not (low <= len(token) <= high and _PRINTABLE.fullmatch(token)):
        raise StartupError(
            f"sidecar token file {path} must hold {low}-{high} printable ASCII "
            "characters"
        )
    return token


def _read(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise StartupError(
            f"cannot open sidecar token file {path} ({exc.strerror}; a symbolic "
            "link is refused)"
        ) from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise StartupError(f"sidecar token file {path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        if st.st_mode & 0o077:
            raise StartupError(
                f"sidecar token file {path} must not be readable or writable by "
                "group or others (chmod 600)"
            )
        data = f.read(TOKEN_LENGTH[1] + 3)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        text = ""
    text = text.removesuffix("\n").removesuffix("\r")
    return _check(text, path)


def load_or_create_token(path: Path) -> tuple[str, bool]:
    """Return ``(token, created)``: read the token file, or create it.

    Raises :class:`StartupError` for a file that is unsafe or malformed.
    """
    if not os.path.lexists(path):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        token = secrets.token_urlsafe(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            return _read(path), False  # another process created it first
        except OSError as exc:
            raise StartupError(
                f"cannot create sidecar token file {path} ({exc.strerror})"
            ) from None
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(token + "\n")
        return token, True
    return _read(path), False


def token_matches(authorization: str | None, token: str) -> bool:
    """Whether the ``Authorization`` header is exactly ``Bearer <token>``.

    Constant time in the token (``hmac.compare_digest``); a header that is not
    ASCII never matches.
    """
    if authorization is None or not authorization.startswith(_BEARER):
        return False
    given = authorization[len(_BEARER) :]
    try:
        return hmac.compare_digest(given.encode("ascii"), token.encode("ascii"))
    except UnicodeEncodeError:
        return False
