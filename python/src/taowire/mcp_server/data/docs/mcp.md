# Using TaoWire from an AI agent (MCP)

> **Alpha.** Not security-reviewed; APIs may change. For localnet and testnet,
> **not for mainnet value**.

`taowire mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server.
It lets an AI coding agent (Claude Code, Claude Desktop, Cursor, VS Code, or any MCP
client) use the kit directly: read the right docs, create a subnet project, port a v10
subnet, check a setup and debug signatures.

Agents trained before Bittensor v11 tend to write v10 code (`Axon`, `Dendrite`,
`Synapse`), which no longer exists. The server's instructions and docs keep the agent on
the v11 kit.

## Install

```bash
pip install "taowire[mcp]==0.1.0a2"
taowire mcp --help
```

Or let your agent start it with [`uvx`](https://docs.astral.sh/uv/), with nothing to
install first: the configs below use `uvx --from "taowire[mcp]==0.1.0a2" taowire mcp`.
If you installed TaoWire yourself, use `taowire` with the argument `mcp` instead.

## Connect your agent

**Claude Code**

```bash
claude mcp add taowire -- uvx --from "taowire[mcp]==0.1.0a2" taowire mcp
```

**Claude Desktop** (`claude_desktop_config.json`), **Cursor** (`.cursor/mcp.json`) and
most other clients:

```json
{
  "mcpServers": {
    "taowire": {
      "command": "uvx",
      "args": ["--from", "taowire[mcp]==0.1.0a2", "taowire", "mcp"]
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`):

```json
{
  "servers": {
    "taowire": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "taowire[mcp]==0.1.0a2", "taowire", "mcp"]
    }
  }
}
```

Then ask the agent, for example: *"Use TaoWire to build a subnet where miners caption
images"*, or *"Port the v10 subnet in this repository to v11 with TaoWire."*

## Tools

| Tool | What it does | Changes anything? |
|---|---|---|
| `taowire_info` | Version, status, packages, links | no |
| `explain_error` | Cause and fix for any `tw.*` error code | no |
| `list_error_codes` | Every error code with its HTTP status | no |
| `list_settings` | Every `TW_*` setting: default, limits, meaning (per process type) | no |
| `list_docs`, `read_doc`, `search_docs` | The TaoWire docs for the installed version (offline) | no |
| `inspect_request` | Decode a btauth/1 request, show the 8 signed lines, verify it, explain any failure | no |
| `inspect_response` | Verify a miner's `twresp/1` answer signature | no |
| `migrate_scan` | List every v10 symbol in a subnet with its v11 replacement | no |
| `doctor` | `taowire doctor` for a miner or validator: keys present, clock, chain, Redis, axon | no (reads the chain, probes ports) |
| `read_metagraph` | One subnet's UIDs, hotkeys, permits, stake and axons | no (reads the chain) |
| `scaffold_project` | `taowire init`: a working example subnet | writes files into an **empty** directory only |
| `migrate_apply` | Port a v10 subnet: returns the diff; with `write=true`, rewrites the files | writes only into a **clean git tree** (unless `allow_dirty`) |

Prompts: `new_subnet` (from nothing to a subnet on localnet) and `port_v10_subnet`
(scan, diff, approve, apply, finish by hand).

## Safety

- **No keys.** No tool reads, prints or signs with a private key. `doctor` reads the
  hotkey's public address only and never prints a Redis URL.
- **No chain writes.** No tool registers, stakes, sets weights or publishes an axon.
  Those stay with you and `btcli`; the agent is told so.
- **File writes are marked and guarded.** `scaffold_project` and `migrate_apply` carry
  MCP's `readOnlyHint: false`, so your client can ask before running them. `migrate_apply`
  returns a diff unless you pass `write=true`.
- The server runs locally over stdio, as your user, and opens no network port.

## Example: debugging a 401

Paste the failing request's headers and body to the agent. It calls `inspect_request`,
which shows the exact eight lines the signature covers and the step that failed:

```text
result: {"ok": false, "code": "tw.auth_bad_signature",
         "cause": "... the body, method or target changed after signing ...",
         "fix": "Sign the exact bytes you send, with the exact path and query ..."}
signed_payload_lines: ["btauth/1", "sr25519", "POST", "/v1/transform",
                       "20466721ba23...041d", "1761300000123456789",
                       "5Grwva...utQY", "5FHneW...94ty"]
```

An old capture fails freshness first (`tw.auth_stale`); pass `check_freshness=false` to
check its signature anyway.
