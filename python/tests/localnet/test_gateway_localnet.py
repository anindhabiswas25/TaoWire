"""BittensorGateway and MetagraphCache against a real localnet chain (spec 8.3, 8.5.1).

Needs ``just localnet-up``. Writes use the localnet dev wallets only:
``miner_rs`` publishes its axon, ``validator`` sets weights.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable
from typing import Any

import bittensor as bt
import pytest
from localnet_env import ENDPOINT, Localnet

from tensorwire.chain.axon import Endpoint
from tensorwire.chain.gateway import (
    BittensorGateway,
    ChainGateway,
    SubnetNotFound,
    TxOutcome,
)
from tensorwire.chain.metagraph_cache import MetagraphCache, StalenessStage

GatewayFor = Callable[..., Awaitable[BittensorGateway]]

TW_PROTOCOL_TAG = 87
"""Decision D1: the default ``TW_PROTOCOL_TAG``."""


async def wait_blocks(gw: ChainGateway, n: int, block_time_s: float) -> int:
    target = await gw.block() + n
    for _ in range(n * 40 + 40):  # bounded: a stalled chain fails the test
        block = await gw.block()
        if block >= target:
            return block
        await asyncio.sleep(max(block_time_s / 2, 0.1))
    raise AssertionError(f"chain did not reach block {target}")


async def test_reads(localnet: Localnet, gateway_for: GatewayFor) -> None:
    gw = await gateway_for()
    assert isinstance(gw, ChainGateway)
    block = await gw.block()
    assert block > 0

    mg = await gw.metagraph(localnet.netuid)
    assert mg.netuid == localnet.netuid
    assert mg.block >= block
    assert mg.tempo > 0
    validator_hotkey = localnet.wallets["validator"]["hotkey"]
    validator = mg.by_hotkey(validator_hotkey)
    assert validator is not None
    assert validator.validator_permit
    assert validator.total_stake_tao > 0
    assert validator in mg.validators()

    uid = await gw.uid_for_hotkey(localnet.netuid, validator_hotkey)
    assert uid == validator.uid
    assert (
        await gw.uid_for_hotkey(
            localnet.netuid, "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )
        is None
    )
    assert await gw.weights_rate_limit(localnet.netuid) >= 0
    assert await gw.serving_rate_limit(localnet.netuid) >= 0
    assert await gw.blocks_since_last_update(localnet.netuid, validator.uid) is not None

    for read in (
        lambda: gw.metagraph(999),
        lambda: gw.weights_rate_limit(999),
        lambda: gw.serving_rate_limit(999),
        lambda: gw.uid_for_hotkey(999, validator_hotkey),
    ):
        with pytest.raises(SubnetNotFound):
            await read()


async def test_total_stake_tao_matches_decision_d2(
    localnet: Localnet, gateway_for: GatewayFor
) -> None:
    """total_stake_tao = alpha_stake x spot price + tao_stake (ADR-0001)."""
    gw = await gateway_for()
    async with bt.Subtensor(ENDPOINT, fallback_endpoints=[]) as client:
        raw = await client.subnets.metagraph(localnet.netuid, commitments=False)
    view = await gw.metagraph(localnet.netuid)
    assert raw is not None
    assert raw.price is not None
    assert raw.price > 0
    by_uid = {n.uid: n for n in view.neurons}
    for n in raw.neurons:
        mine = by_uid[n.uid]
        assert mine.alpha_stake == pytest.approx(n.alpha_stake.amount)
        assert mine.tao_stake == pytest.approx(n.tao_stake.amount)
        # the spot price moves between the two reads only if a block changed
        # the pool; allow for that
        expected = n.alpha_stake.amount * raw.price + n.tao_stake.amount
        assert math.isclose(mine.total_stake_tao, expected, rel_tol=0.05)


async def test_serve_axon_publishes_endpoint_and_protocol(
    localnet: Localnet, gateway_for: GatewayFor
) -> None:
    gw = await gateway_for("miner_rs")
    hotkey = localnet.wallets["miner_rs"]["hotkey"]
    port = 20_000 + (await gw.block()) % 20_000  # differs on every run
    outcome = await serve_with_rate_limit(gw, localnet, "127.0.0.2", port)
    assert outcome.ok, outcome
    assert outcome.block_hash is not None
    assert outcome.block_hash.startswith("0x")

    mg = await gw.metagraph(localnet.netuid)
    neuron = mg.by_hotkey(hotkey)
    assert neuron is not None
    assert neuron.axon == Endpoint("127.0.0.2", port, is_ipv6=False)
    assert neuron.axon_protocol == TW_PROTOCOL_TAG

    # validators with TW_ALLOW_PRIVATE_AXONS=0 see the axon as unusable
    strict = BittensorGateway(ENDPOINT, allow_private_axons=False)
    await strict.connect()
    try:
        strict_view = (await strict.metagraph(localnet.netuid)).by_hotkey(hotkey)
    finally:
        await strict.close()
    assert strict_view is not None
    assert strict_view.axon is None
    assert strict_view.axon_protocol == TW_PROTOCOL_TAG


async def test_serve_axon_rejections(
    localnet: Localnet, gateway_for: GatewayFor
) -> None:
    gw = await gateway_for("miner_rs")
    # the chain rejects 127.0.0.1 (spec 3.5); wait out the serving rate limit
    # first so the rejection is about the address
    await wait_blocks(
        gw, await gw.serving_rate_limit(localnet.netuid) + 1, localnet.block_time_s
    )
    outcome = await gw.serve_axon(
        localnet.netuid, "127.0.0.1", 8091, tls_cert_hex=None, protocol_tag=87
    )
    assert not outcome.ok
    assert outcome.code == "invalid_argument"
    assert outcome.remediation
    # u8 protocol: refused before anything is signed
    too_big = await gw.serve_axon(
        localnet.netuid, "127.0.0.2", 8091, tls_cert_hex=None, protocol_tag=21591
    )
    assert too_big == TxOutcome(
        ok=False,
        code="invalid_argument",
        remediation="protocol_tag must be 0..255, port 1..65535",
        block_hash=None,
    )


async def test_serve_axon_not_registered(
    localnet: Localnet, gateway_for: GatewayFor
) -> None:
    gw = await gateway_for("alice")
    outcome = await gw.serve_axon(
        localnet.netuid, "127.0.0.2", 8099, tls_cert_hex=None, protocol_tag=87
    )
    assert not outcome.ok
    assert outcome.code == "not_registered"


async def wait_for_weights_window(
    gw: BittensorGateway, localnet: Localnet, uid: int
) -> int:
    """Wait until ``uid`` may set weights again; return the rate limit."""
    limit = await gw.weights_rate_limit(localnet.netuid)
    since = await gw.blocks_since_last_update(localnet.netuid, uid)
    assert since is not None
    if since < limit:
        await wait_blocks(gw, limit - since + 1, localnet.block_time_s)
    return limit


async def test_set_weights(localnet: Localnet, gateway_for: GatewayFor) -> None:
    gw = await gateway_for("validator")
    netuid = localnet.netuid
    uid = localnet.wallets["validator"]["uid"]
    limit = await wait_for_weights_window(gw, localnet, uid)

    miners = [localnet.wallets[m]["uid"] for m in ("miner_py", "miner_ts")]
    outcome = await gw.set_weights(
        netuid, {miners[0]: 0.25, miners[1]: 0.75}, mechid=0, version_key=0
    )
    assert outcome.ok, outcome
    assert outcome.block_hash is not None

    after = await gw.blocks_since_last_update(netuid, uid)
    assert after is not None
    assert after < limit

    # immediately again: refused by the SDK's preflight, nothing submitted
    again = await gw.set_weights(netuid, {miners[0]: 1.0}, mechid=0, version_key=0)
    assert not again.ok
    assert again.code == "rate_limited"
    assert again.block_hash is None
    assert "rate limit" in (again.remediation or "")


async def test_set_weights_commit_without_permit_is_accepted(
    localnet: Localnet, gateway_for: GatewayFor
) -> None:
    """Pins observed chain behaviour (Phase 1 finding, ADR-0001).

    With commit-reveal enabled (localnet default), ``SetWeights`` is a
    timelocked commit and the chain accepts it from a hotkey without a
    validator permit. ``ok`` means "commit included", not "weights applied";
    FakeChain's ``not_authorized`` models the plain (no commit-reveal) path.
    """
    gw = await gateway_for("miner_go")
    uid = localnet.wallets["miner_go"]["uid"]
    me = (await gw.metagraph(localnet.netuid)).by_hotkey(
        localnet.wallets["miner_go"]["hotkey"]
    )
    assert me is not None
    assert not me.validator_permit, "miner_go gained a permit; rerun localnet"
    await wait_for_weights_window(gw, localnet, uid)
    miner_py = localnet.wallets["miner_py"]["uid"]
    outcome = await gw.set_weights(
        localnet.netuid, {miner_py: 1.0}, mechid=0, version_key=0
    )
    assert outcome.ok, outcome


async def test_metagraph_cache_on_localnet(
    localnet: Localnet, gateway_for: GatewayFor
) -> None:
    gw = await gateway_for()
    cache = MetagraphCache(gw, localnet.netuid, refresh_s=10.0, startup_timeout_s=60)
    seen: list[int] = []
    cache.add_refresh_listener(lambda snap: seen.append(snap.block))
    await cache.start()
    try:
        assert cache.stage() is StalenessStage.FRESH
        assert cache.by_hotkey(localnet.wallets["validator"]["hotkey"]) is not None
        await wait_blocks(gw, 2, localnet.block_time_s)
        newer = await cache.refresh_now()
        assert newer.block > seen[0]
        assert cache.refresh_failures_total == 0
    finally:
        await cache.stop()
    assert seen[-1] == newer.block


async def serve_with_rate_limit(
    gw: BittensorGateway, localnet: Localnet, ip: str, port: int
) -> Any:
    """``serve_axon``, waiting out the serving rate limit once if needed."""
    outcome = await gw.serve_axon(
        localnet.netuid, ip, port, tls_cert_hex=None, protocol_tag=TW_PROTOCOL_TAG
    )
    if outcome.code == "rate_limited":
        await wait_blocks(
            gw, await gw.serving_rate_limit(localnet.netuid) + 1, localnet.block_time_s
        )
        outcome = await gw.serve_axon(
            localnet.netuid, ip, port, tls_cert_hex=None, protocol_tag=TW_PROTOCOL_TAG
        )
    return outcome
