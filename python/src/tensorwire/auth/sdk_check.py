"""Startup check of the installed ``bittensor`` SDK (spec 8.7.3 step 1).

A light version of ``scripts/check_sdk_surface.py``: before anything else
runs, confirm that the SDK symbols this layer depends on exist and that the
installed version is inside the supported range. A missing symbol stops the
process with a message naming the symbol and the supported versions. A
version inside the range that has not been tested yet (spec 18.2) only logs a
WARNING.

Only the modules ``auth/`` may import are checked here (ADR-0001). The chain
symbols (``Subtensor``, intents) are checked by the chain gateway.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import ModuleType

from tensorwire.errors import StartupError

__all__ = [
    "REQUIRED_SYMBOLS",
    "SUPPORTED_RANGE",
    "TESTED_VERSIONS",
    "SdkReport",
    "check_sdk",
]

#: The range the kit declares in ``pyproject.toml`` (spec 3, 8.1).
SUPPORTED_RANGE = ">=11.3.0,<12"
_LOWEST = (11, 3, 0)
_BELOW = (12, 0, 0)

#: Releases the full test suite has passed on (compatibility matrix, spec 18.2).
TESTED_VERSIONS: tuple[str, ...] = ("11.3.0",)

#: Symbols used by ``auth/`` and ``crypto.py``, per SDK module.
REQUIRED_SYMBOLS: Mapping[str, tuple[str, ...]] = {
    "bittensor.http_auth": (
        "AuthError",
        "BadSignature",
        "Caller",
        "DEFAULT_ALLOWED_SKEW",
        "DEFAULT_MAX_AGE",
        "HEADER_HOTKEY",
        "HEADER_NONCE",
        "MalformedAuth",
        "ReplayedRequest",
        "StaleRequest",
        "WrongReceiver",
        "build_payload",
        "sign",
        "verify",
    ),
    "bittensor.signing": ("Signer", "resolve_signer"),
    "bittensor.sp_core": (
        "CRYPTO_ED25519",
        "CRYPTO_SR25519",
        "KeyfileError",
        "Keypair",
        "deserialize_keypair_from_keyfile_data",
        "keyfile_data_is_encrypted",
        "ss58_decode",
        "ss58_encode",
        "verify",
    ),
}

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(.*)")


@dataclass(frozen=True, slots=True)
class SdkReport:
    """Result of a passing check."""

    version: str
    tested: bool


def _in_range(version: str) -> bool:
    match = _VERSION_RE.fullmatch(version)
    if match is None:
        return False
    release = (int(match[1]), int(match[2]), int(match[3]))
    if match[4] and release == _LOWEST:
        return False  # a pre-release of 11.3.0 sorts below 11.3.0
    return _LOWEST <= release < _BELOW


def check_sdk(
    *,
    version_of: Callable[[str], str] = importlib.metadata.version,
    import_module: Callable[[str], ModuleType] = importlib.import_module,
) -> SdkReport:
    """Check the installed SDK; raise :class:`StartupError` if it is unusable."""
    supported = f"bittensor{SUPPORTED_RANGE} (tested: {', '.join(TESTED_VERSIONS)})"
    try:
        version = version_of("bittensor")
    except importlib.metadata.PackageNotFoundError:
        raise StartupError(f"bittensor is not installed; install {supported}") from None
    if not _in_range(version):
        raise StartupError(f"bittensor {version} is not supported; install {supported}")
    for module_name, names in REQUIRED_SYMBOLS.items():
        try:
            module = import_module(module_name)
        except ImportError:
            raise StartupError(
                f"bittensor {version} has no module {module_name}; install {supported}"
            ) from None
        for name in names:
            if not hasattr(module, name):
                raise StartupError(
                    f"bittensor {version} lacks {module_name}.{name}; "
                    f"install {supported}"
                )
    return SdkReport(version=version, tested=version in TESTED_VERSIONS)
