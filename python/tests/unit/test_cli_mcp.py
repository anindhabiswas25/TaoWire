"""`taowire mcp`: starts the stdio server, or says which extra is missing."""

from __future__ import annotations

import builtins
from typing import Any

import pytest
from typer.testing import CliRunner

from taowire.cli.main import app
from taowire.mcp_server import server


def test_runs_the_stdio_server(monkeypatch: pytest.MonkeyPatch) -> None:
    ran: list[str] = []

    class Fake:
        def run(self, transport: str) -> None:
            ran.append(transport)

    monkeypatch.setattr(server, "build_server", Fake)
    result = CliRunner().invoke(app, ["mcp"])
    assert result.exit_code == 0, result.output
    assert ran == ["stdio"]
    assert result.stdout == ""  # stdout belongs to the protocol


def test_missing_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def fail(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "taowire.mcp_server.server":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail)
    result = CliRunner().invoke(app, ["mcp"])
    assert result.exit_code == 2
    assert "pip install 'taowire[mcp]'" in result.output
