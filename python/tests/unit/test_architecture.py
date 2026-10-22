"""ADR-0001: which kit modules may import which parts of bittensor.

import-linter (``just lint``) enforces that only ``chain.gateway``, ``crypto``
and ``auth/*`` import ``bittensor`` at all. It cannot see submodules of an
external package, so this test adds the finer rule: ``auth/*`` and
``crypto.py`` may only use ``http_auth``, ``signing`` and ``sp_core``.
Function-level imports are checked too.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import tensorwire

PACKAGE = Path(tensorwire.__file__).parent
GATEWAY = Path("chain/gateway.py")
NARROW = {"http_auth", "signing", "sp_core"}


def _narrow_allowed(rel: Path) -> bool:
    return rel == Path("crypto.py") or rel.parts[0] == "auth"


def bittensor_imports(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """Yield ``(line, dotted name)`` for every bittensor module or member imported."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "bittensor":
                    yield node.lineno, alias.name
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.level == 0
            and node.module.split(".")[0] == "bittensor"
        ):
            for alias in node.names:
                yield node.lineno, f"{node.module}.{alias.name}"


def violations(rel: Path, source: str) -> list[str]:
    if rel == GATEWAY:
        return []
    found = []
    for line, name in bittensor_imports(ast.parse(source)):
        parts = name.split(".")
        if _narrow_allowed(rel) and len(parts) >= 2 and parts[1] in NARROW:
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
        ("auth/signer.py", "import bittensor", True),
        ("auth/signer.py", "import bittensor as bt", True),
        ("auth/signer.py", "from bittensor import Subtensor", True),
        ("auth/signer.py", "from bittensor.wallets import CRYPTO_TYPE_NAMES", True),
        ("policy/caller.py", "from bittensor import http_auth", True),
        ("miner/app.py", "def f():\n    import bittensor\n", True),
        ("miner/app.py", "import bittensorx", False),
        ("miner/app.py", "from . import bittensor", False),
    ],
)
def test_rule_examples(rel: str, source: str, bad: bool) -> None:
    assert bool(violations(Path(rel), source)) is bad
