"""Golden test (spec 13.8): ``migrate apply`` on the template's ``before/``,
plus the committed hand fixes, gives ``after/`` exactly; and S6 (spec 1.5)."""

from __future__ import annotations

import filecmp
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tensorwire.migrate.apply import plan_repo

EXAMPLE = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "migrations"
    / "template-v10-to-v11"
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def golden() -> ModuleType:
    spec = importlib.util.spec_from_file_location("golden", EXAMPLE / "golden.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["golden"] = module
    spec.loader.exec_module(module)
    return module


def tree(root: Path) -> dict[str, Path]:
    return {
        p.relative_to(root).as_posix(): p
        for p in root.rglob("*")
        if p.is_file()
        and not {".git", "__pycache__", ".pytest_cache"}
        & set(p.relative_to(root).parts)
    }


def test_before_plus_apply_plus_hand_fixes_is_after(tmp_path: Path) -> None:
    g = golden()
    repo = g.applied_copy(tmp_path / "repo")
    subprocess.run(  # noqa: S603
        ["git", "apply", "--whitespace=nowarn", str(g.PATCH)],  # noqa: S607
        cwd=repo,
        check=True,
    )
    got, want = tree(repo), tree(EXAMPLE / "after")
    assert sorted(got) == sorted(want)
    different = [p for p in got if not filecmp.cmp(got[p], want[p], shallow=False)]
    assert different == []


def test_apply_is_idempotent_on_its_own_output(tmp_path: Path) -> None:
    repo = golden().applied_copy(tmp_path / "repo")
    again = plan_repo(repo)
    assert again.changed == []
    assert again.parse_errors == []


def test_s6_subnet_code_within_50_lines() -> None:
    g = golden()
    s6 = g.count(g.PATCH.read_text(encoding="utf-8"))
    assert s6.subnet_lines() <= 50, s6.subnet_lines()
    assert s6.subnet_lines() == 19  # docs/migrations/template.md quotes this number
    # Every file the patch touches is in exactly one reported area.
    areas = [g.SUBNET, g.FRAMEWORK, g.TESTS]
    for f in s6.files:
        assert sum(bool(a.match(f.path)) for a in areas) <= 1, f.path


def test_count_rules() -> None:
    g = golden()
    patch = (
        "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,3 +1,3 @@\n"
        "-import bittensor as bt\n+import logging\n"
        "-# TW-MIGRATE: TWM100 fix it\n+    from x import y\n-a = 1\n+a = 2\n"
    )
    (f,) = g.count(patch).files
    assert (f.added, f.removed, f.imports, f.markers, f.counted) == (3, 3, 3, 1, 2)
