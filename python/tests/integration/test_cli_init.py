"""``tensorwire init`` (spec 8.14; Phase 2 exit: the project passes its own tests)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tensorwire.cli.init_cmd import package_name, render_project
from tensorwire.cli.main import app

EXAMPLE = Path(__file__).resolve().parents[3] / "examples" / "text-ops-subnet"


def test_example_is_the_scaffold() -> None:
    # examples/text-ops-subnet is `tensorwire init` output plus its own README.
    files = render_project("text-ops-subnet", package="text_ops")
    for rel, content in files.items():
        if rel == "README.md":
            continue
        assert (EXAMPLE / rel).read_text(encoding="utf-8") == content, rel


def test_dot_files_are_rendered() -> None:
    files = render_project("x-subnet")
    assert {".env.example", ".gitignore"} <= set(files)
    assert "TW_EXTERNAL_IP=127.0.0.2" in files[".env.example"]


def test_rendering_renames_project_and_package() -> None:
    files = render_project("My.Subnet-2")
    assert "my_subnet_2/miner.py" in files
    assert "tests/test_my_subnet_2.py" in files
    assert 'name = "My.Subnet-2"' in files["pyproject.toml"]
    assert "from my_subnet_2.protocol import" in files["my_subnet_2/miner.py"]
    assert not any("text_ops" in c or "text-ops-subnet" in c for c in files.values())


@pytest.mark.parametrize(
    "bad", ["1abc", "a b", "", "x" * 65, "tensorwire", "class", "-a"]
)
def test_bad_names(bad: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - several messages
        package_name(bad)


@pytest.mark.parametrize("bad", ["Pkg", "my-pkg", "def", "bittensor"])
def test_bad_packages(bad: str) -> None:
    with pytest.raises(ValueError, match="not a usable package"):
        render_project("ok", package=bad)


def test_unknown_template() -> None:
    with pytest.raises(ValueError, match="unknown template"):
        render_project("ok", "nope")


def test_scaffolded_project_passes_its_own_tests(tmp_path: Path) -> None:
    target = tmp_path / "my-subnet"
    result = CliRunner().invoke(app, ["init", str(target)])
    assert result.exit_code == 0, result.output
    assert "created my-subnet" in result.output
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        cwd=target,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "9 passed" in run.stdout


def test_refuses_a_non_empty_directory(tmp_path: Path) -> None:
    (tmp_path / "keep.txt").write_text("mine")
    result = CliRunner().invoke(app, ["init", str(tmp_path), "--name", "ok"])
    assert result.exit_code == 1
    assert (tmp_path / "keep.txt").read_text() == "mine"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keep.txt"]


def test_cli_rejects_a_bad_name(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["init", str(tmp_path / "x"), "--name", "9x"])
    assert result.exit_code == 2
    assert not (tmp_path / "x").exists()
