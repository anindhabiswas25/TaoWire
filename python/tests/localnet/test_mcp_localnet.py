"""The MCP server's chain tools against the localnet chain (read-only)."""

from __future__ import annotations

from pathlib import Path

import pytest
from localnet_env import ENDPOINT, Localnet
from mcp import Client

from taowire.mcp_server.server import build_server

pytestmark = pytest.mark.localnet


async def test_read_metagraph_and_doctor(localnet: Localnet, tmp_path: Path) -> None:
    env = tmp_path / "validator.env"
    env.write_text(
        f"TW_NETWORK={ENDPOINT}\n"
        f"TW_NETUID={localnet.netuid}\n"
        f"TW_WALLET_PATH={localnet.wallet_path}\n"
        "TW_WALLET_NAME=validator\n"
        "TW_ALLOW_PRIVATE_AXONS=1\n"
        "TW_REFUSE_IF_COLDKEY_PRESENT=0\n"
        "TW_METRICS_BIND=127.0.0.1:9199\n",
        encoding="utf-8",
    )
    async with Client(build_server()) as client:
        mg = await client.call_tool(
            "read_metagraph", {"network": ENDPOINT, "netuid": localnet.netuid}
        )
        assert not mg.is_error, mg.content
        snap = mg.structured_content
        assert snap["netuid"] == localnet.netuid
        assert snap["n_neurons"] >= 2
        assert snap["n_validator_permits"] >= 1
        assert {"uid", "hotkey", "validator_permit", "axon"} <= set(snap["neurons"][0])

        doc = await client.call_tool(
            "doctor", {"role": "validator", "env_file": str(env)}
        )
        assert not doc.is_error, doc.content
        report = doc.structured_content
        by_name = {c["name"]: c for c in report["checks"]}
        assert "chain" in by_name, report["checks"]
        assert by_name["chain"]["status"] == "ok"
        assert by_name["registered"]["status"] == "ok"
        text = str(report).lower()
        assert "mnemonic" not in text
        assert "private" not in text.replace("allow_private", "")
