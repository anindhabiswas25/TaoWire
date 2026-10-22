"""cli/main.py: the command exists and reports its version."""

from __future__ import annotations

from typer.testing import CliRunner

from tensorwire import __version__
from tensorwire.cli.main import app


def test_version() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"tensorwire {__version__}"


def test_no_args_shows_help() -> None:
    result = CliRunner().invoke(app, [])
    assert "Usage" in result.output
