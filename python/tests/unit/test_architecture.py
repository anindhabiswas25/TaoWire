"""ADR-0001: which kit modules may import which parts of bittensor.

import-linter (``just lint``) enforces that only ``chain.gateway``, ``crypto``
and ``auth/*`` import ``bittensor`` at all, and only ``chain.gateway``
imports ``bittensor_core`` (the SDK's compiled core, used for the drand round
signatures, D30). It cannot see submodules of an external package, so this
test adds the finer rule:

- ``auth/*`` may only use ``http_auth``, ``signing`` and ``sp_core``;
- ``crypto.py`` may also use ``keyfiles`` (``Keypair``) and ``wallet``
  (``Wallet``) (ADR-0001).

Function-level imports are checked too.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import taowire

PACKAGE = Path(taowire.__file__).parent
GATEWAY = Path("chain/gateway.py")
AUTH_ALLOWED = frozenset({"http_auth", "signing", "sp_core"})
CRYPTO_ALLOWED = AUTH_ALLOWED | {"keyfiles", "wallet"}
#: ``bittensor_core`` has no allowed submodules outside the gateway.
_SDK_ROOTS = frozenset({"bittensor", "bittensor_core"})


def _allowed_submodules(rel: Path) -> frozenset[str]:
    if rel == Path("crypto.py"):
        return CRYPTO_ALLOWED
    if rel.parts[0] == "auth":
        return AUTH_ALLOWED
    return frozenset()


def bittensor_imports(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """Yield ``(line, dotted name)`` for every bittensor module or member imported."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _SDK_ROOTS:
                    yield node.lineno, alias.name
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.level == 0
            and node.module.split(".")[0] in _SDK_ROOTS
        ):
            for alias in node.names:
                yield node.lineno, f"{node.module}.{alias.name}"


def violations(rel: Path, source: str) -> list[str]:
    if rel == GATEWAY:
        return []
    found = []
    for line, name in bittensor_imports(ast.parse(source)):
        parts = name.split(".")
        if len(parts) >= 2 and parts[1] in _allowed_submodules(rel):
            continue
        found.append(f"{rel}:{line} imports {name}")
    return found


def test_package_respects_adr_0001() -> None:
    problems = []
    for path in sorted(PACKAGE.rglob("*.py")):
        rel = path.relative_to(PACKAGE)
        problems += violations(rel, path.read_text(encoding="utf-8"))
    assert problems == []


@pytest.mark.parametrize(
    ("rel", "source", "bad"),
    [
        ("chain/gateway.py", "import bittensor as bt", False),
        ("auth/signer.py", "from bittensor import http_auth", False),
        ("auth/verifier.py", "import bittensor.http_auth", False),
        ("crypto.py", "from bittensor.sp_core import verify", False),
        ("crypto.py", "from bittensor.keyfiles import Keypair", False),
        ("crypto.py", "from bittensor.wallet import Wallet", False),
        ("auth/signer.py", "from bittensor.keyfiles import Keypair", True),
        ("crypto.py", "from bittensor import Subtensor", True),
        ("auth/signer.py", "import bittensor", True),
        ("auth/signer.py", "import bittensor as bt", True),
        ("auth/signer.py", "from bittensor import Subtensor", True),
        ("auth/signer.py", "from bittensor.wallets import CRYPTO_TYPE_NAMES", True),
        ("policy/caller.py", "from bittensor import http_auth", True),
        ("miner/app.py", "def f():\n    import bittensor\n", True),
        ("chain/gateway.py", "import bittensor_core as _core", False),
        ("extensions/timelock.py", "import bittensor_core", True),
        ("crypto.py", "from bittensor_core import decrypt", True),
        ("miner/app.py", "import bittensorx", False),
        ("miner/app.py", "from . import bittensor", False),
    ],
)
def test_rule_examples(rel: str, source: str, bad: bool) -> None:
    assert bool(violations(Path(rel), source)) is bad
