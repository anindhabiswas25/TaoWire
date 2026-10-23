"""Fixtures for tests against the Docker localnet (``just localnet-up``).

The chain and dev wallets come from ``scripts/localnet_up.sh``; its state
directory is ``$LOCALNET_DIR`` (default ``~/.tensorwire/localnet``). Every
test here is marked ``localnet`` and is skipped when that state or the chain
is missing. Only public dev keys are used; never point this at a real network.
"""

from __future__ import annotations

import json
import socket
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from localnet_env import ENDPOINT, ENDPOINT_ADDR, STATE_DIR, Localnet

from tensorwire.chain.gateway import BittensorGateway


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    here = Path(__file__).parent
    for item in items:
        if here in Path(str(item.fspath)).parents:
            item.add_marker(pytest.mark.localnet)


def _chain_reachable() -> bool:
    try:
        with socket.create_connection(ENDPOINT_ADDR, timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def localnet() -> Localnet:
    info_file = STATE_DIR / "localnet.json"
    if not info_file.is_file():
        pytest.skip(f"no localnet state at {STATE_DIR}; run `just localnet-up`")
    if not _chain_reachable():
        pytest.skip(f"localnet chain is not running at {ENDPOINT}")
    info = json.loads(info_file.read_text(encoding="utf-8"))
    return Localnet(
        netuid=int(info["netuid"]),
        wallet_path=Path(info["wallet_path"]),
        wallets=info["wallets"],
        block_time_s=float(info.get("block_time_s", 0.25)),
    )


@pytest_asyncio.fixture
async def gateway_for(
    localnet: Localnet,
) -> AsyncIterator[Any]:
    """Factory: ``await gateway_for("miner_py")`` gives a connected gateway."""
    opened: list[BittensorGateway] = []

    async def make(wallet: str | None = None) -> BittensorGateway:
        gw = BittensorGateway(
            ENDPOINT,
            hotkey=localnet.hotkey(wallet) if wallet else None,
            allow_private_axons=True,
            timeout_s=30.0,
        )
        await gw.connect()
        opened.append(gw)
        return gw

    yield make
    for gw in opened:
        await gw.close()
