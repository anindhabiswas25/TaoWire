"""The MCP server through a real MCP client: in process and over stdio."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from taowire.auth.signer import RequestSigner
from taowire.crypto import keypair_from_uri
from taowire.mcp_server.server import INSTRUCTIONS, build_server
from taowire.version import __version__

READ_ONLY = {
    "taowire_info",
    "explain_error",
    "list_error_codes",
    "list_settings",
    "list_docs",
    "read_doc",
    "search_docs",
    "inspect_request",
    "inspect_response",
    "migrate_scan",
    "doctor",
    "read_metagraph",
}
WRITES_FILES = {"scaffold_project", "migrate_apply"}


def _data(result: Any) -> Any:
    assert not result.is_error, result.content
    data = result.structured_content
    # Non-object returns (lists, strings) come wrapped as {"result": ...}.
    if isinstance(data, dict) and set(data) == {"result"}:
        return data["result"]
    return data


async def test_tools_prompts_and_safety_hints() -> None:
    async with Client(build_server()) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert set(tools) == READ_ONLY | WRITES_FILES
        for name in READ_ONLY:
            assert tools[name].annotations.read_only_hint is True, name
        for name in WRITES_FILES:
            hints = tools[name].annotations
            assert hints.read_only_hint is False, name
            assert hints.destructive_hint is False, name
        assert all(t.description for t in tools.values())
        prompts = {p.name for p in (await client.list_prompts()).prompts}
        assert prompts == {"new_subnet", "port_v10_subnet"}


def test_instructions_warn_against_v10_code() -> None:
    assert "NO Axon, Dendrite, Synapse" in INSTRUCTIONS
    assert "never write to" in INSTRUCTIONS.replace("\n", " ")
    assert __version__ in INSTRUCTIONS


async def test_knowledge_tools() -> None:
    async with Client(build_server()) as client:
        info = _data(await client.call_tool("taowire_info", {}))
        assert info["taowire"] == __version__
        err = _data(
            await client.call_tool("explain_error", {"code": "tw.auth_replayed"})
        )
        assert err["http_status"] == 401
        assert "TW_REDIS_URL" in err["fix"]
        codes = _data(await client.call_tool("list_error_codes", {}))
        assert len(codes) > 25
        settings = _data(await client.call_tool("list_settings", {"role": "sidecar"}))
        assert any(s["name"] == "TW_SIDECAR_PORT" for s in settings)
        docs = _data(await client.call_tool("list_docs", {}))
        assert any(d["name"] == "quickstart" for d in docs)
        text = _data(await client.call_tool("read_doc", {"name": "quickstart"}))
        assert text.startswith("# Quickstart")
        hits = _data(
            await client.call_tool("search_docs", {"query": "ServeAxon", "limit": 2})
        )
        assert len(hits) == 2


async def test_inspect_request_tool() -> None:
    body = '{"text":"hello","op":"upper"}'
    bob = keypair_from_uri("//Bob").ss58_address
    headers = RequestSigner(keypair_from_uri("//Alice")).sign(
        method="POST", target="/v1/transform", body=body.encode(), receiver_ss58=bob
    )
    args = {"method": "POST", "target": "/v1/transform", "headers": headers}
    async with Client(build_server()) as client:
        ok = _data(await client.call_tool("inspect_request", {**args, "body": body}))
        assert ok["result"]["ok"] is True
        bad = _data(await client.call_tool("inspect_request", {**args, "body": "{}"}))
        assert bad["result"]["code"] == "tw.auth_bad_signature"


async def test_expected_errors_reach_the_agent(tmp_path: Path) -> None:
    (tmp_path / "taken").mkdir()
    (tmp_path / "taken/file").write_text("x")
    async with Client(build_server()) as client:
        missing = await client.call_tool("read_doc", {"name": "nope"})
        assert missing.is_error
        assert "available:" in missing.content[0].text
        taken = await client.call_tool(
            "scaffold_project", {"directory": str(tmp_path / "taken")}
        )
        assert taken.is_error
        assert "not empty" in taken.content[0].text
        bad_b64 = await client.call_tool(
            "inspect_request",
            {
                "method": "POST",
                "target": "/",
                "headers": {},
                "body": "!!",
                "body_encoding": "base64",
            },
        )
        assert bad_b64.is_error
        assert "base64" in bad_b64.content[0].text


async def test_stdio_server_keeps_stdout_clean(tmp_path: Path) -> None:
    """`taowire mcp` as a subprocess: stdout carries only the protocol."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from taowire.cli.main import app; app(['mcp'])"],
        cwd=str(tmp_path),
    )
    async with Client(params) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert names == READ_ONLY | WRITES_FILES
        done = _data(
            await client.call_tool(
                "scaffold_project", {"directory": str(tmp_path / "sub")}
            )
        )
        assert (tmp_path / "sub" / done["package"] / "miner.py").is_file()


@pytest.mark.parametrize("bad", [{"role": "nope"}, {}])
async def test_doctor_argument_validation(bad: dict[str, str]) -> None:
    async with Client(build_server()) as client:
        result = await client.call_tool("doctor", bad)
        assert result.is_error


async def test_prompts_render() -> None:
    async with Client(build_server()) as client:
        new = await client.get_prompt("new_subnet", {"task": "image captioning"})
        text = new.messages[0].content.text
        assert "image captioning" in text
        assert "scaffold_project" in text
        port = await client.get_prompt("port_v10_subnet", {"repo": "/x"})
        assert "migrate_scan(repo='/x')" in port.messages[0].content.text


REPO = Path(__file__).resolve().parents[3]
BEFORE = REPO / "examples/migrations/template-v10-to-v11/before"


@pytest.mark.skipif(not BEFORE.is_dir(), reason="needs the repository")
async def test_migrate_tools(tmp_path: Path) -> None:
    async with Client(build_server()) as client:
        scan = _data(await client.call_tool("migrate_scan", {"repo": str(BEFORE)}))
        assert scan["findings"]
        dry = _data(await client.call_tool("migrate_apply", {"repo": str(BEFORE)}))
        assert dry["written"] is False
        assert dry["diff"]
        refused = await client.call_tool(
            "migrate_apply", {"repo": str(tmp_path), "write": True}
        )
        assert refused.is_error
        assert "git" in refused.content[0].text


async def test_inspect_response_tool() -> None:
    from taowire.crypto import HotkeySigner
    from taowire.extensions.response_sig import sign_response

    alice = keypair_from_uri("//Alice").ss58_address
    bob = keypair_from_uri("//Bob")
    body = '{"result":"HELLO"}'
    headers = sign_response(
        HotkeySigner(bob),
        request_nonce=7,
        sender_ss58=alice,
        status=200,
        body=body.encode(),
    )
    args = {
        "headers": headers,
        "status": 200,
        "expected_responder": bob.ss58_address,
        "request_nonce": 7,
        "sender": alice,
    }
    async with Client(build_server()) as client:
        ok = _data(await client.call_tool("inspect_response", {**args, "body": body}))
        assert ok["result"]["ok"] is True


async def test_chain_tools_report_an_unreachable_chain(tmp_path: Path) -> None:
    async with Client(build_server()) as client:
        mg = await client.call_tool(
            "read_metagraph", {"network": "ws://127.0.0.1:1", "netuid": 2}
        )
        assert mg.is_error
        assert "chain read failed" in mg.content[0].text
        doc = await client.call_tool(
            "doctor", {"role": "miner", "env_file": str(tmp_path / "none.env")}
        )
        assert doc.is_error
        assert "no such env file" in doc.content[0].text
