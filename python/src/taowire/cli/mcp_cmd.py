"""``taowire mcp``: run the MCP server for AI coding agents over stdio.

The protocol uses stdout, so logging goes to stderr. Needs the ``mcp`` extra.
"""

from __future__ import annotations

import sys

import typer

from taowire.observability.logging import configure_logging

__all__ = ["mcp"]


def mcp() -> None:
    """Run the TaoWire MCP server (stdio) for AI agents (Claude Code, Cursor, ...)."""
    try:
        from taowire.mcp_server.server import build_server  # noqa: PLC0415 - optional extra
    except ImportError:
        typer.echo(
            "taowire mcp needs the mcp extra: pip install 'taowire[mcp]'", err=True
        )
        raise typer.Exit(2) from None
    configure_logging("WARNING", stream=sys.stderr)  # stdout carries the protocol
    build_server().run("stdio")
