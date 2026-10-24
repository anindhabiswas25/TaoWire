"""``taowire mcp``: an MCP server that lets AI coding agents use the kit.

The server speaks the Model Context Protocol over stdio. It gives an agent
the kit's own knowledge (error codes, settings, the bundled docs) and a few
safe actions (scaffold a project, scan or port a v10 subnet, check a setup,
inspect a signed request or response, read a metagraph).

Safety rules, enforced by what the tools are able to do:

- no tool reads, prints or signs with a private key;
- no tool writes to any chain (no weights, no ``ServeAxon``, no stake);
- tools that write files say so (``read_only_hint=False``) and refuse to
  overwrite: ``scaffold_project`` needs an empty directory and
  ``migrate_apply`` writes only into a clean git tree, unless the caller
  explicitly allows a dirty one.

Install with ``pip install "taowire[mcp]"``; run with ``taowire mcp``.
The server is :func:`taowire.mcp_server.server.build_server`.
"""

from __future__ import annotations

__all__: list[str] = []
