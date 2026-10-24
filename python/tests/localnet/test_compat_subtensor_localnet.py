"""compat.Subtensor against a real localnet chain (spec 10b.2.6, D34).

Needs ``just localnet-up``. The commitment is written with the dev ``miner_ts``
hotkey (never a coldkey) and read back through the v10-shaped calls a subnet
like data-universe makes.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from localnet_env import ENDPOINT, Localnet

from taowire.compat import Metagraph, Subtensor


@pytest.fixture
def subtensor() -> Iterator[Subtensor]:
    with Subtensor(network=ENDPOINT, timeout_s=60.0) as s:
        yield s


def test_reads(subtensor: Subtensor, localnet: Localnet) -> None:
    netuid = localnet.netuid
    mg = subtensor.metagraph(netuid=netuid)
    assert isinstance(mg, Metagraph)
    assert mg.n == len(localnet.wallets)
    validator = localnet.hotkey("validator").ss58_address
    uid = subtensor.get_uid_for_hotkey_on_subnet(hotkey_ss58=validator, netuid=netuid)
    assert uid == localnet.wallets["validator"]["uid"]
    assert mg.hotkeys[uid] == validator
    assert subtensor.is_hotkey_registered(hotkey_ss58=validator, netuid=netuid)
    block = subtensor.get_current_block()
    assert block > 0
    assert subtensor.block >= block
    block_hash = subtensor.get_block_hash(block)
    assert isinstance(block_hash, str)
    assert block_hash.startswith("0x")
    assert len(block_hash) == 66
    assert subtensor.get_block_hash(10**9) is None
    owner = subtensor.query_subtensor("SubnetOwnerHotkey", params=[netuid])
    assert owner == localnet.hotkey("owner").ss58_address


def test_commitment_written_with_a_dev_hotkey_and_read_back(
    subtensor: Subtensor, localnet: Localnet
) -> None:
    netuid = localnet.netuid
    wallet = SimpleNamespace(hotkey=localnet.hotkey("miner_ts"))
    uid = localnet.wallets["miner_ts"]["uid"]
    data = f"tw-compat-{time.time_ns()}"
    assert subtensor.set_commitment(wallet=wallet, netuid=netuid, data=data)
    assert subtensor.get_commitment(netuid=netuid, uid=uid) == data
