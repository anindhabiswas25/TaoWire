"""Timing-sensitive chain limits on real 12-second blocks (spec 14.2).

On fast blocks (0.25 s) the serving and weights rate limits pass 48x faster
than wall-clock, so the tests elsewhere cannot tell a schedule that counts
blocks from one that counts seconds. These run only on a 12 s chain:

    LOCALNET_FAST_BLOCKS=0 LOCALNET_RPC_PORT=9954 LOCALNET_CONTAINER=local_chain_12s \\
      LOCALNET_DIR=~/.taowire/localnet-12s scripts/localnet_up.sh
    LOCALNET_DIR=~/.taowire/localnet-12s uv run pytest -m localnet tests/localnet

They use the chain's default limits (ServingRateLimit 50, WeightsSetRateLimit
100), so they take about 10 and 25 minutes. Dev wallets only: ``miner_rs``
publishes its axon; ``validator`` sets weights through the kit's validator.
"""

from __future__ import annotations

import itertools
import json
import time
from pathlib import Path
from typing import Any

import bittensor as bt
import pytest
from drand_guard import DrandWatch
from localnet_env import ENDPOINT, Localnet
from test_gateway_localnet import (
    TW_PROTOCOL_TAG,
    GatewayFor,
    serve_with_rate_limit,
    wait_blocks,
)
from test_validator_e2e_localnet import (
    EXTERNAL_IP,
    MINER_WALLET,
    REVEAL_BLOCKS,
    WEIGHTS_TIMEOUT_S,
    Process,
    _stop,
    _until,
    _validator,
    evidence_dir,
    miner,
)

from taowire.chain.axon import Endpoint
from taowire.chain.gateway import BittensorGateway

__all__ = ["evidence_dir", "miner"]  # pytest fixtures used below

#: Below this, the chain runs fast blocks and these tests prove nothing.
MIN_BLOCK_TIME_S = 6.0


@pytest.fixture(autouse=True)
def _needs_12s_blocks(localnet: Localnet) -> None:
    if localnet.block_time_s < MIN_BLOCK_TIME_S:
        pytest.skip(
            f"needs 12 s blocks (this chain: {localnet.block_time_s} s); "
            "start one with LOCALNET_FAST_BLOCKS=0 scripts/localnet_up.sh"
        )


async def test_serving_rate_limit_holds_in_wall_clock(
    localnet: Localnet, gateway_for: GatewayFor
) -> None:
    """A second ``ServeAxon`` within ServingRateLimit blocks is refused as
    ``rate_limited``, and goes through once that many 12 s blocks have passed."""
    gw = await gateway_for("miner_rs")
    netuid = localnet.netuid
    limit = await gw.serving_rate_limit(netuid)
    assert limit > 0, "ServingRateLimit is 0: nothing to test"
    first_port = 20_000 + (await gw.block()) % 20_000
    first = await serve_with_rate_limit(gw, localnet, "127.0.0.2", first_port)
    assert first.ok, first
    served_at = await gw.block()
    started = time.monotonic()

    again = await gw.serve_axon(
        netuid,
        "127.0.0.2",
        first_port + 1,
        tls_cert_hex=None,
        protocol_tag=TW_PROTOCOL_TAG,
    )
    assert not again.ok
    assert again.code == "rate_limited", again
    assert again.remediation

    await wait_blocks(
        gw, served_at + limit + 1 - await gw.block(), localnet.block_time_s
    )
    later = await gw.serve_axon(
        netuid,
        "127.0.0.2",
        first_port + 1,
        tls_cert_hex=None,
        protocol_tag=TW_PROTOCOL_TAG,
    )
    elapsed = time.monotonic() - started
    assert later.ok, later
    mg = await gw.metagraph(netuid)
    neuron = mg.by_hotkey(localnet.wallets["miner_rs"]["hotkey"])
    assert neuron is not None
    assert neuron.axon == Endpoint("127.0.0.2", first_port + 1, is_ipv6=False)
    # the limit is counted in blocks, which are 12 s of wall-clock here
    assert elapsed >= 0.9 * limit * localnet.block_time_s, elapsed


async def test_weight_schedule_waits_for_the_chain_rate_limit(
    localnet: Localnet,
    miner: tuple[int, Process],
    tmp_path: Path,
    evidence_dir: Path,
) -> None:
    """The kit's validator (TW_MIN_WEIGHT_INTERVAL_BLOCKS=10) submits weights
    at most once per WeightsSetRateLimit blocks, is never refused by the chain
    for submitting too early, and its commit is revealed on chain."""
    port, miner_process = miner
    netuid = localnet.netuid
    gw = BittensorGateway(ENDPOINT, allow_private_axons=True)
    await gw.connect()
    client = await bt.Subtensor(ENDPOINT)
    try:
        limit = await gw.weights_rate_limit(netuid)
        serving = await gw.serving_rate_limit(netuid)
        want = Endpoint(EXTERNAL_IP, port, is_ipv6=False)
        miner_hotkey = localnet.wallets[MINER_WALLET]["hotkey"]

        async def published() -> bool:
            neuron = (await gw.metagraph(netuid)).by_hotkey(miner_hotkey)
            return neuron is not None and neuron.axon == want

        await _until(
            "the miner's axon on chain",
            published,
            localnet.wait_s(serving, 180.0),
            miner_process,
        )
        miner_uid = localnet.wallets[MINER_WALLET]["uid"]
        validator_uid = localnet.wallets["validator"]["uid"]

        validator = _validator(localnet, tmp_path, evidence_dir)
        try:

            def submissions() -> list[dict[str, Any]]:
                return [
                    e
                    for e in validator.events()
                    if e.get("event") == "weights submitted" and e.get("block_hash")
                ]

            async def two_submissions() -> list[dict[str, Any]] | None:
                subs = submissions()
                return subs if len(subs) >= 2 else None

            subs = await _until(
                "two weight submissions",
                two_submissions,
                localnet.wait_s(2 * limit + 20, 600.0),
                validator,
            )

            async def revealed() -> dict[int, float] | None:
                row = (await client.weights.weights(netuid)).get(validator_uid) or {}
                return row if row.get(miner_uid, 0.0) > 0 else None

            row = await _until(
                "weights revealed on chain",
                revealed,
                localnet.wait_s(REVEAL_BLOCKS, WEIGHTS_TIMEOUT_S),
                validator,
                DrandWatch(client),
            )
            rejected = [
                e for e in validator.events() if e.get("event") == "weights_rejected"
            ]
        finally:
            _stop(validator)
    finally:
        await client.close()
        await gw.close()

    blocks = [int(e["block"]) for e in subs]
    spacing = [b - a for a, b in itertools.pairwise(blocks)]
    (evidence_dir / "schedule.json").write_text(
        json.dumps(
            {
                "weights_rate_limit": limit,
                "min_weight_interval_blocks": 10,
                "block_time_s": localnet.block_time_s,
                "submissions": subs,
                "spacing_blocks": spacing,
                "rejected": rejected,
                "revealed_row": {str(k): v for k, v in row.items()},
            },
            indent=2,
        )
        + "\n"
    )
    assert all(gap >= limit for gap in spacing), spacing
    assert not rejected, rejected
    assert row[miner_uid] > 0
