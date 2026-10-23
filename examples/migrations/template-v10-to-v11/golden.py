"""The template port's golden data (spec 13.8) and its S6 count (spec 1.5).

``after/`` is exactly: ``tensorwire migrate apply`` run on ``before/``, then
``hand-fixes.patch`` (the changes a person made by hand). This script:

- ``python golden.py write``: rebuild ``hand-fixes.patch`` from the current
  ``apply`` output and ``after/`` (after changing ``apply`` or ``after/``);
- ``python golden.py s6``: print the S6 count: the hand fixes per file,
  subnet code only, without import lines and without removed
  ``# TW-MIGRATE:`` markers (``apply`` wrote those, D15).

``python/tests/migration/test_template_golden.py`` checks that ``before/``
+ ``apply`` + ``hand-fixes.patch`` == ``after/`` and that S6 holds.
Needs ``git`` on PATH and ``tensorwire[migrate]``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
BEFORE = HERE / "before"
AFTER = HERE / "after"
PATCH = HERE / "hand-fixes.patch"
_IGNORE = shutil.ignore_patterns("__pycache__", ".git", ".pytest_cache")

#: What S6 calls "subnet code": the code a team wrote on top of the
#: template. The template's own framework (``template/base``, its config and
#: mock helpers) is reported separately; so are tests and docs.
SUBNET = re.compile(
    r"^(neurons/|template/protocol\.py|template/validator/|template/utils/uids\.py"
    r"|template/__init__\.py|requirements\.txt|setup\.py)"
)
FRAMEWORK = re.compile(
    r"^template/(base/|mock\.py|api/|utils/(config|misc|logging)\.py)"
)
TESTS = re.compile(r"^tests/")


def _git(cwd: Path, *args: str) -> str:
    run = subprocess.run(  # noqa: S603 - fixed argv
        ["git", *args],  # noqa: S607 - git from PATH
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return run.stdout


def applied_copy(dest: Path) -> Path:
    """``before/`` copied to ``dest`` (a git repository), with ``apply`` run on it."""
    shutil.copytree(BEFORE, dest, ignore=_IGNORE)
    _git(dest, "init", "-q")
    _git(dest, "add", "-A")
    _git(dest, "-c", "user.name=golden", "-c", "user.email=golden@localhost",
         "commit", "-qm", "before")  # fmt: skip
    from tensorwire.migrate.apply import plan_repo, write_changes  # noqa: PLC0415

    write_changes(plan_repo(dest))
    _git(dest, "add", "-A")
    _git(dest, "-c", "user.name=golden", "-c", "user.email=golden@localhost",
         "commit", "-qm", "apply")  # fmt: skip
    return dest


def hand_fixes(applied: Path) -> str:
    """The diff from ``applied`` (the apply output) to ``after/``."""
    for item in applied.iterdir():
        if item.name != ".git":
            shutil.rmtree(item) if item.is_dir() else item.unlink()
    shutil.copytree(AFTER, applied, ignore=_IGNORE, dirs_exist_ok=True)
    _git(applied, "add", "-A")
    return _git(applied, "diff", "--cached", "--no-renames", "--no-color")


@dataclass
class FileCount:
    """Changed lines in one file of the hand-fix patch."""

    path: str
    added: int = 0
    removed: int = 0
    imports: int = 0
    markers: int = 0

    @property
    def counted(self) -> int:
        """Added + removed lines, without import lines and removed markers."""
        return self.added + self.removed - self.imports - self.markers


@dataclass
class S6:
    """The hand-fix patch, counted per area."""

    files: list[FileCount] = field(default_factory=list)

    def area(self, pattern: re.Pattern[str]) -> list[FileCount]:
        """The files whose path matches ``pattern``."""
        return [f for f in self.files if pattern.match(f.path)]

    def subnet_lines(self) -> int:
        """The S6 number."""
        return sum(f.counted for f in self.area(SUBNET))


_IMPORT = re.compile(r"^\s*(import\s+\S|from\s+\S+\s+import\s)")


def count(patch: str) -> S6:
    """Count ``patch`` (``git diff`` output) per file."""
    result = S6()
    current: FileCount | None = None
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            path = line.split(" b/", 1)[1]
            current = FileCount(path)
            result.files.append(current)
            continue
        if current is None or line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            body = line[1:]
            if line.startswith("+"):
                current.added += 1
            else:
                current.removed += 1
                if body.strip().startswith("# TW-MIGRATE:"):
                    current.markers += 1
                    continue
            if _IMPORT.match(body):
                current.imports += 1
    return result


def _table(title: str, files: list[FileCount]) -> list[str]:
    lines = [f"{title}:"]
    for f in files:
        lines.append(
            f"  {f.path}: +{f.added} -{f.removed} "
            f"(imports {f.imports}, markers {f.markers}) -> {f.counted}"
        )
    lines.append(f"  total: {sum(f.counted for f in files)}")
    return lines


def main(argv: list[str]) -> int:
    """``write`` or ``s6``."""
    command = argv[1] if len(argv) > 1 else "s6"
    with tempfile.TemporaryDirectory() as tmp:
        patch = hand_fixes(applied_copy(Path(tmp) / "repo"))
    if command == "write":
        PATCH.write_text(patch, encoding="utf-8")
        sys.stdout.write(f"wrote {PATCH.name} ({len(patch.splitlines())} lines)\n")
        return 0
    s6 = count(patch)
    report = [
        *_table("subnet code (S6)", s6.area(SUBNET)),
        *_table("template framework", s6.area(FRAMEWORK)),
        *_table("tests", s6.area(TESTS)),
    ]
    rest = [
        f
        for f in s6.files
        if not any(p.match(f.path) for p in (SUBNET, FRAMEWORK, TESTS))
    ]
    if rest:
        report += _table("other", rest)
    report.append(f"S6 = {s6.subnet_lines()} changed lines (target <= 50)")
    sys.stdout.write("\n".join(report) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
