"""The TaoWire MCP server (see the package docstring for the safety rules)."""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import Field

from taowire.mcp_server import actions, knowledge
from taowire.version import __version__

__all__ = ["INSTRUCTIONS", "build_server"]

REPO = "https://github.com/anindhabiswas25/TaoWire"

INSTRUCTIONS = f"""\
TaoWire {__version__} is the networking kit for Bittensor v11 subnets. It is an
alpha, not security-reviewed: localnet and testnet only, never mainnet value.

Facts an agent must get right:
- Bittensor v11 has NO Axon, Dendrite, Synapse, StreamingSynapse or SubnetsAPI.
  Do not write v10 code. Miners use `taowire.Miner` (`@miner.route(...)`,
  `Miner.from_env().run()`); validators subclass `taowire.SubnetValidator`
  (`make_task`, `score`) and run
  `ValidatorRunner(validator, ValidatorSettings.from_env()).run()`.
- Requests are signed with btauth/1 (X-Bittensor-* headers); miners sign
  answers with twresp/1. Settings are TW_* environment variables; an unknown
  TW_* name is a startup error.
- Several miner workers need TW_REDIS_URL (a shared replay store).
- For a v10 subnet: migrate_scan, then migrate_apply (diff first), then fix the
  `# TW-MIGRATE:` comments by hand.

Use read_doc / search_docs for anything else (start with read_doc("quickstart")),
explain_error for any tw.* code, list_settings for TW_* variables, and
inspect_request / inspect_response to debug signatures. These tools never read
private keys and never write to a chain: the user runs chain writes
(registration, staking) themselves with btcli.
"""

_READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
_READ_NET = ToolAnnotations(read_only_hint=True, open_world_hint=True)
_WRITE_FILES = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=False,
)


def _arg(description: str, **limits: Any) -> Any:
    """A tool argument's description (and numeric limits) for the JSON schema."""
    return Field(description=description, **limits)


BodyEncoding = Annotated[
    Literal["utf-8", "base64"],
    _arg("How `body` is encoded: utf-8 text or base64 of the raw bytes."),
]
RepoPath = Annotated[str, _arg("Path of the v10 subnet repository.")]


@contextlib.contextmanager
def _user_errors() -> Iterator[None]:
    """Expected failures reach the agent with their message (``ToolError``).

    Bad input, a missing or non-empty directory, a refused write, an unreachable
    chain: the agent can fix those. Anything else stays a crash, whose text the
    SDK keeps on the server.
    """
    try:
        yield
    except (ValueError, KeyError, OSError, RuntimeError) as exc:
        raise ToolError(str(exc)) from exc


def build_server() -> MCPServer:
    """The MCP server with every TaoWire tool and prompt registered."""
    server: MCPServer = MCPServer(
        "taowire",
        title="TaoWire",
        description="Networking kit for Bittensor v11 subnets",
        instructions=INSTRUCTIONS,
        website_url=REPO,
        version=__version__,
    )
    _knowledge_tools(server)
    _debug_tools(server)
    _project_tools(server)
    _prompts(server)
    return server


def _knowledge_tools(server: MCPServer) -> None:
    @server.tool(annotations=_READ)
    def taowire_info() -> dict[str, Any]:
        """Version, status, supported bittensor range, packages and links."""
        return {
            "taowire": __version__,
            "status": "alpha: not security-reviewed; localnet and testnet only",
            "bittensor": ">=11.3.0,<12",
            "python": "3.10-3.14",
            "packages": {
                "python": f'pip install "taowire[all]=={__version__}"',
                "typescript": "npm install @taowire/btauth@alpha",
                "go": "go get github.com/anindhabiswas25/TaoWire/go@v0.1.0-alpha.1",
                "rust": "cargo add taowire-btauth@0.1.0-alpha.1",
            },
            "repository": REPO,
            "issues": f"{REPO}/issues",
        }

    @server.tool(annotations=_READ)
    def explain_error(
        code: Annotated[str, _arg("A TaoWire error code, e.g. tw.auth_stale.")],
    ) -> dict[str, Any]:
        """Explain a tw.* error code: where it comes from, its cause and the fix."""
        return asdict(knowledge.explain_error(code))

    @server.tool(annotations=_READ)
    def list_error_codes() -> list[dict[str, Any]]:
        """Every tw.* error code the kit uses, with HTTP status and its cause."""
        return [
            {
                "code": e.code,
                "raised_by": e.raised_by,
                "http_status": e.http_status,
                "cause": e.cause,
            }
            for e in map(knowledge.explain_error, knowledge.all_error_codes())
        ]

    @server.tool(annotations=_READ)
    def list_settings(
        role: Annotated[
            Literal["all", "common", "miner", "validator", "sidecar"],
            _arg("Which process type's settings to list."),
        ] = "all",
    ) -> list[dict[str, Any]]:
        """Every TW_* setting: default, limits, who reads it and what it does."""
        return [asdict(s) for s in knowledge.list_settings(role)]

    @server.tool(annotations=_READ)
    def list_docs() -> list[dict[str, Any]]:
        """The TaoWire docs bundled with this version (name, title, size)."""
        return [asdict(d) for d in knowledge.doc_names()]

    @server.tool(annotations=_READ)
    def read_doc(
        name: Annotated[
            str, _arg("Doc name from list_docs, e.g. quickstart or protocol/twresp-1.")
        ],
    ) -> str:
        """The full Markdown text of one bundled doc."""
        try:
            return knowledge.read_doc(name)
        except KeyError:
            names = ", ".join(d.name for d in knowledge.doc_names())
            raise ToolError(f"no doc named {name!r}; available: {names}") from None

    @server.tool(annotations=_READ)
    def search_docs(
        query: Annotated[str, _arg("Words that must all appear on one line.")],
        limit: Annotated[int, _arg("Most lines to return.", ge=1, le=100)] = 20,
    ) -> list[dict[str, Any]]:
        """Search the bundled docs: doc name, line number, section and the line."""
        return knowledge.search_docs(query, limit)


def _debug_tools(server: MCPServer) -> None:
    @server.tool(annotations=_READ)
    def inspect_request(  # noqa: PLR0917 - MCP passes tool arguments by name
        method: Annotated[str, _arg("HTTP method, e.g. POST.")],
        target: Annotated[
            str, _arg("Request target as sent: path plus ?query, e.g. /v1/transform.")
        ],
        headers: Annotated[
            dict[str, str], _arg("The request headers (X-Bittensor-* at least).")
        ],
        body: Annotated[str, _arg("The raw request body.")] = "",
        body_encoding: BodyEncoding = "utf-8",
        receiver: Annotated[
            str | None,
            _arg("Miner hotkey to check against; default X-Bittensor-Receiver."),
        ] = None,
        check_freshness: Annotated[
            bool, _arg("False checks an old capture as if it had just arrived.")
        ] = True,
    ) -> dict[str, Any]:
        """Decode a btauth/1 request, show the exact signed payload, and verify it.

        Explains any failure (tw.auth_* code, cause, fix). It uses an empty replay
        store, so replay is not checked. Needs no keys: only public data.
        """
        with _user_errors():
            return actions.inspect_request(
                method=method,
                target=target,
                headers=headers,
                body=actions.decode_body(body, body_encoding),
                receiver=receiver,
                check_freshness=check_freshness,
            )

    @server.tool(annotations=_READ)
    def inspect_response(  # noqa: PLR0917 - MCP passes tool arguments by name
        headers: Annotated[
            dict[str, str], _arg("The response headers (X-TW-Resp-* at least).")
        ],
        status: Annotated[int, _arg("The HTTP status.", ge=100, le=599)],
        expected_responder: Annotated[str, _arg("The miner hotkey queried.")],
        request_nonce: Annotated[int, _arg("X-Bittensor-Nonce of the request.", ge=0)],
        sender: Annotated[str, _arg("The validator hotkey that sent the request.")],
        body: Annotated[str, _arg("The raw response body.")] = "",
        body_encoding: BodyEncoding = "utf-8",
    ) -> dict[str, Any]:
        """Check a miner's twresp/1 response signature and show what it covers."""
        with _user_errors():
            return actions.inspect_response(
                headers=headers,
                body=actions.decode_body(body, body_encoding),
                status=status,
                expected_responder=expected_responder,
                request_nonce=request_nonce,
                sender=sender,
            )


def _project_tools(server: MCPServer) -> None:
    @server.tool(annotations=_WRITE_FILES)
    def scaffold_project(
        directory: Annotated[str, _arg("New or empty directory for the project.")],
        name: Annotated[str | None, _arg("Project name (default: the directory).")] = (
            None
        ),
        package: Annotated[str | None, _arg("Python package name.")] = None,
    ) -> dict[str, Any]:
        """Create a working example subnet (miner, validator, scoring, tests).

        Same as `taowire init`. Writes files; refuses a non-empty directory.
        """
        with _user_errors():
            return actions.scaffold_project(Path(directory), name=name, package=package)

    @server.tool(annotations=_READ)
    def migrate_scan(repo: RepoPath) -> dict[str, Any]:
        """List every v10 symbol and risky pattern in a subnet, with its v11 fix."""
        with _user_errors():
            return actions.migrate_scan(Path(repo))

    @server.tool(annotations=_WRITE_FILES)
    def migrate_apply(
        repo: RepoPath,
        write: Annotated[
            bool, _arg("False (default) only returns the diff; True rewrites files.")
        ] = False,
        allow_dirty: Annotated[
            bool, _arg("Write even with uncommitted changes (not recommended).")
        ] = False,
    ) -> dict[str, Any]:
        """Port a v10 subnet: safe rewrites plus `# TW-MIGRATE:` comments.

        Show the diff first (write=false). With write=true it refuses a git tree
        with uncommitted changes unless allow_dirty is true.
        """
        with _user_errors():
            return actions.migrate_apply(
                Path(repo), write=write, allow_dirty=allow_dirty
            )

    @server.tool(annotations=_READ_NET)
    async def doctor(
        role: Annotated[Literal["miner", "validator"], _arg("The process to check.")],
        env_file: Annotated[
            str | None, _arg("A .env file with the process's TW_* settings.")
        ] = None,
    ) -> dict[str, Any]:
        """Check a miner's or validator's setup: keys, clock, chain, Redis, axon.

        Reads the chain and probes ports; prints no key material and no Redis URL.
        """
        path = None if env_file is None else Path(env_file)
        with _user_errors():
            return await actions.doctor(role, path)

    @server.tool(annotations=_READ_NET)
    async def read_metagraph(
        network: Annotated[str, _arg("local, test, finney, or a ws(s):// endpoint.")],
        netuid: Annotated[int, _arg("The subnet number.", ge=0, le=65535)],
        limit: Annotated[int, _arg("Most neurons to return.", ge=1, le=1024)] = 64,
    ) -> dict[str, Any]:
        """Read one subnet: UIDs, hotkeys, validator permits, stake and axons.

        Read-only; no wallet needed.
        """
        with _user_errors():
            return await actions.read_metagraph(network, netuid, limit=limit)


def _prompts(server: MCPServer) -> None:
    @server.prompt(title="Start a new TaoWire subnet")
    def new_subnet(task: str = "the subnet's task") -> str:
        """Guide the agent from an empty directory to a subnet on localnet."""
        return (
            f"Build a Bittensor v11 subnet with TaoWire for: {task}.\n"
            "1. Call read_doc('quickstart') and follow it.\n"
            "2. Call scaffold_project, then adapt protocol.py (request and "
            "response models), miner.py (the route handler) and scoring.py.\n"
            "3. Keep the tests passing (pytest -q) after every change.\n"
            "4. Use list_settings for TW_* variables and explain_error for any "
            "tw.* code.\n"
            "Never write v10 code (Axon/Dendrite/Synapse) and never handle "
            "private keys."
        )

    @server.prompt(title="Port a v10 subnet to TaoWire")
    def port_v10_subnet(repo: str = ".") -> str:
        """Guide the agent through migrate_scan, migrate_apply and manual fixes."""
        return (
            f"Port the Bittensor v10 subnet in {repo} to v11 with TaoWire.\n"
            "1. Call read_doc('migration-from-v10').\n"
            f"2. Call migrate_scan(repo='{repo}') and summarise what is automatic "
            "and what is not.\n"
            f"3. Call migrate_apply(repo='{repo}', write=false) and show the diff. "
            "Only with the user's approval call it again with write=true (it "
            "needs a clean git tree).\n"
            "4. Resolve every `# TW-MIGRATE:` comment by hand, then run the "
            "subnet's tests.\n"
            "5. For a live subnet, read_doc('migration-rollout') before switching "
            "nodes."
        )
