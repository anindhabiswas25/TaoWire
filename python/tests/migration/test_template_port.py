"""The archived v10 template, ported to ``tensorwire.compat`` (10b.6).

``examples/migrations/template-v10-to-v11/after/`` must run: its own test
starts the template's miner and validator in process on FakeChain, queries,
scores and sets weights. The port also has to fix the security findings
``migrate scan`` reports on ``before/``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tensorwire.migrate.scan import scan_repo

PORT = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "migrations"
    / "template-v10-to-v11"
)


def test_after_runs_on_compat() -> None:
    run = subprocess.run(  # our interpreter, our files
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"],
        cwd=PORT / "after",
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "1 passed" in run.stdout


def test_port_removes_the_core_findings() -> None:
    before = {(f.path, f.rule) for f in scan_repo(PORT / "before").findings}
    core = ("neurons/", "template/")
    left = [f for f in scan_repo(PORT / "after").findings if f.path.startswith(core)]
    assert ("template/protocol.py", "TWM100") in before
    # Left: only the template's own permit flag, which no longer matters: the
    # kit enforces the permit (TW_REQUIRE_PERMIT=1) before blacklist_fn.
    assert {f.rule for f in left} == {"TWM103"}
