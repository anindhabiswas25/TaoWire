"""The source distribution holds only its include list (G6-1, spec 18.4 item 3).

hatchling's sdist used to sweep in any git-ignored virtualenv under ``python/``
not named ``.venv`` (the ``.venv-py310`` of the Python 3.10 check), and
``uv build`` then failed. ``[tool.hatch.build.targets.sdist] only-include``
fixes the list; this test builds an sdist from a copy of the project with
such a virtualenv in it and checks every member, then builds the wheel from
that sdist (what ``uv build`` does).
"""

from __future__ import annotations

import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

PYTHON_DIR = Path(__file__).resolve().parents[2]


def _uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        pytest.fail("uv is not on PATH (the project is built with uv)")
    return uv


def test_include_list_is_the_documented_one() -> None:
    text = (PYTHON_DIR / "pyproject.toml").read_text()
    section = text.split("[tool.hatch.build.targets.sdist]", 1)[1].split("\n[", 1)[0]
    assert (
        'only-include = ["src/taowire", "pyproject.toml", "README.md", "LICENSE"]'
        in section
    )


def test_sdist_holds_only_the_include_list(tmp_path: Path) -> None:
    project = tmp_path / "python"
    shutil.copytree(
        PYTHON_DIR / "src",
        project / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy(PYTHON_DIR / name, project / name)
    # What broke G6-1: a git-ignored virtualenv with another name, and tests.
    stray = project / ".venv-py310" / "lib" / "python3.10" / "site-packages"
    stray.mkdir(parents=True)
    (stray / "huge.py").write_text("x = 1\n")
    (project / ".venv-py310" / ".gitignore").write_text("*\n")
    (project / "tests").mkdir()
    (project / "tests" / "test_x.py").write_text("")
    cache = project / "src" / "taowire" / "__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "x.cpython-312.pyc").write_bytes(b"")
    out = tmp_path / "dist"
    run = subprocess.run(  # noqa: S603 - fixed argv
        [_uv(), "build", "--offline", "--out-dir", str(out), str(project)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert run.returncode == 0, run.stderr[-2000:]
    (sdist,) = out.glob("*.tar.gz")
    assert len(list(out.glob("*.whl"))) == 1
    with tarfile.open(sdist) as tar:
        names = tar.getnames()
    root = names[0].split("/", 1)[0]
    allowed_files = {"PKG-INFO", "pyproject.toml", "README.md", "LICENSE", ".gitignore"}
    for name in names:
        rel = name.removeprefix(root + "/")
        if rel in {root, ""} or rel in allowed_files:
            continue
        assert rel.startswith("src/taowire"), rel
        assert "__pycache__" not in rel, rel
        assert not rel.endswith(".pyc"), rel
    assert any(n.endswith("src/taowire/py.typed") for n in names)
    assert any("cli/templates" in n for n in names)
    assert f"{root}/LICENSE" in names


def test_every_package_ships_the_repository_license() -> None:
    """Each package directory holds an exact copy of the root LICENSE (Apache-2.0)."""
    want = (PYTHON_DIR.parent / "LICENSE").read_bytes()
    for package in ("python", "typescript", "rust"):
        assert (PYTHON_DIR.parent / package / "LICENSE").read_bytes() == want, package
