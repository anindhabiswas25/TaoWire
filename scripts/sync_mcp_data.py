#!/usr/bin/env python3
"""Copy the docs and .env.example into the MCP server's package data.

`taowire mcp` serves them from the installed package, so an agent can read
the docs offline and they always match the installed version. Run this after
editing docs/ or .env.example; tests/unit/test_mcp_knowledge.py fails while
the copies differ. docs/team/ is internal and never copied.

    python scripts/sync_mcp_data.py [--check]
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "python/src/taowire/mcp_server/data"
EXCLUDE = {"team"}


def wanted() -> dict[Path, Path]:
    """Map each bundled path (relative to DATA) to its source."""
    out = {Path("env.example"): ROOT / ".env.example"}
    for src in sorted((ROOT / "docs").rglob("*.md")):
        rel = src.relative_to(ROOT / "docs")
        if rel.parts[0] in EXCLUDE:
            continue
        out[Path("docs") / rel] = src
    return out


def main() -> int:
    check = "--check" in sys.argv[1:]
    want = wanted()
    have = {p.relative_to(DATA) for p in DATA.rglob("*") if p.is_file()} if DATA.exists() else set()
    stale = sorted(have - set(want))
    differ = sorted(
        rel for rel, src in want.items()
        if not (DATA / rel).exists() or (DATA / rel).read_bytes() != src.read_bytes()
    )
    if check:
        for rel in differ:
            print(f"out of date: {rel}")
        for rel in stale:
            print(f"not in docs/: {rel}")
        return 1 if differ or stale else 0
    for rel in stale:
        (DATA / rel).unlink()
    for rel in differ:
        (DATA / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(want[rel], DATA / rel)
    print(f"{len(want)} files in {DATA.relative_to(ROOT)} ({len(differ)} updated, {len(stale)} removed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
