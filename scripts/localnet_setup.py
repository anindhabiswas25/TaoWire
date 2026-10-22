#!/usr/bin/env python3
"""Prepare a running localnet for TensorWire development (spec Section 14).

Creates dev wallets, funds them from Alice, registers and starts a subnet,
registers a validator and four miners, stakes the validator and waits until
it holds a validator permit. Every step checks the chain first, so running
it again on a prepared chain changes nothing.

Fast-block localnets (0.25 s blocks) finalize 3 to 8 blocks behind the head,
and the SDK anchors a transaction's mortal era at the finalized head. A
MEV-shielded call (``BurnedRegister``) lives for only 8 blocks, so it often
expires before inclusion; short forks also invalidate signatures. Every
attempt is therefore a new extrinsic, built and signed right after a new
block is finalized, and attempts are spaced by blocks, not seconds. When the
retries run out on transient errors only, the script exits with
``EXIT_TRANSIENT`` so ``localnet_up.sh`` can restart the chain with 12 s blocks.

LOCALNET ONLY. Every key below is derived from a public seed printed in
this file. Anyone can recompute them. Never fund them on a real network.
Wallets are written to ``<state-dir>/wallets``, never ``~/.bittensor``.

Usage (normally through ``scripts/localnet_up.sh``):
    python scripts/localnet_setup.py --state-dir DIR [--endpoint ws://127.0.0.1:9944]
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import hashlib
import json
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import bittensor as bt
from bittensor.keyfiles import Keypair
from bittensor.result import BittensorError

ALICE_SEED = "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"
"""//Alice's public dev seed (spec 14.3). Pre-funded on every localnet."""

ALICE_SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

MARKER = ".tensorwire-localnet"
"""Marks a state directory created by this script (localnet_down.sh checks it)."""

LOCAL_ENDPOINTS = ("ws://127.0.0.1:", "ws://localhost:", "ws://[::1]:")


@dataclass(frozen=True)
class Role:
    wallet: str
    fund_tao: float


ROLES = (
    Role("owner", 2000.0),
    Role("validator", 1000.0),
    Role("miner_py", 50.0),
    Role("miner_ts", 50.0),
    Role("miner_go", 50.0),
    Role("miner_rs", 50.0),
)
VALIDATOR_STAKE_TAO = 500.0

ATTEMPTS = 10
"""Submissions per step before giving up."""

RETRY_SPACING_BLOCKS = 2
"""Blocks to wait after failed attempt ``n``: ``n`` times this."""

FINALITY_WAIT_BLOCKS = 60
"""Give up waiting for a new finalized block after this many block times."""

EXIT_TRANSIENT = 75
"""Exit code (EX_TEMPFAIL) when a step failed on transient errors only."""

PERMANENT_CODES = frozenset(
    {
        "insufficient_balance",
        "insufficient_liquidity",
        "not_authorized",
        "subnet_not_exists",
        "unit_mismatch",
        "policy_violation",
        "disabled",
    }
)
"""Failures that a new attempt cannot fix. Everything else is retried."""


class TransientFailure(Exception):
    """A step kept failing on errors that a later attempt could fix."""


def dev_seed(wallet: str, role: str) -> str:
    """The public, deterministic seed of a localnet key."""
    digest = hashlib.sha256(f"tensorwire-localnet:{wallet}:{role}".encode()).hexdigest()
    return "0x" + digest


def log(message: str) -> None:
    print(f"[localnet] {message}", flush=True)


def make_wallet(
    path: Path, name: str, coldkey_seed: str, hotkey_seed: str
) -> bt.Wallet:
    """Create (or check) an unencrypted dev wallet with one hotkey, ``default``."""
    wallet = bt.Wallet(name=name, hotkey="default", path=str(path))
    if not (path / name / "coldkey").exists():
        wallet.regenerate_coldkey(
            seed=coldkey_seed, use_password=False, overwrite=False, suppress=True
        )
    if not (path / name / "hotkeys" / "default").exists():
        wallet.regenerate_hotkey(
            seed=hotkey_seed, use_password=False, overwrite=False, suppress=True
        )
    return bt.Wallet(name=name, hotkey="default", path=str(path))


def check_wallet(wallet: bt.Wallet, coldkey_seed: str, hotkey_seed: str) -> None:
    """Refuse to continue if an existing wallet is not the expected dev wallet."""
    want_cold = Keypair.create_from_seed(bytes.fromhex(coldkey_seed[2:])).ss58_address
    want_hot = Keypair.create_from_seed(bytes.fromhex(hotkey_seed[2:])).ss58_address
    if (
        wallet.coldkeypub.ss58_address != want_cold
        or wallet.hotkey.ss58_address != want_hot
    ):
        raise SystemExit(
            f"wallet {wallet.name!r} in the state directory is not the expected dev "
            "wallet; remove the state directory (localnet_down.sh --purge) and retry"
        )


async def ensure(
    client: Any,
    what: str,
    done: Callable[[], Awaitable[bool]],
    intent: Any,
    wallet: bt.Wallet,
    *,
    attempts: int,
) -> None:
    """Submit ``intent`` unless ``done()`` already holds, retrying failed submissions.

    ``done()`` is re-checked before every attempt, so a submission whose outcome
    was unknown is never applied twice. Each attempt is a new extrinsic (fresh
    nonce, fresh era) signed right after a new block is finalized, which gives
    the mortal era the most blocks left (see the module docstring). Failed
    attempts are spaced by a growing number of blocks. A permanent failure
    (for example ``insufficient_balance``) stops at once.
    """
    block_time = await client.block_time()
    for attempt in range(1, attempts + 1):
        if await done():
            log(f"{what}: done" if attempt > 1 else f"{what}: already done")
            return
        try:
            await wait_for_new_finalized(client, block_time)
            result = await client.execute(
                intent, wallet, wait_for_inclusion=True, wait_for_finalization=True
            )
        except (BittensorError, OSError, TimeoutError) as e:
            # Raised instead of returned: RPC drops, a missing MEV-shield key.
            code, message = "error", f"{type(e).__name__}: {e}"
        else:
            if result.success:
                log(f"{what}: ok (block {result.block_hash})")
                if not await done():
                    raise SystemExit(
                        f"{what}: included, but the chain does not show it"
                    )
                return
            error = result.error
            code = getattr(getattr(error, "code", None), "value", "unknown")
            message = getattr(error, "message", None) or result.message
        log(f"{what}: attempt {attempt}/{attempts} failed ({code}: {message})")
        if code in PERMANENT_CODES:
            raise SystemExit(f"{what}: failed permanently ({code})")
        if attempt < attempts:
            head = await client.block()
            await client.wait_for_block(head + RETRY_SPACING_BLOCKS * attempt)
    if await done():
        log(f"{what}: done")
        return
    raise TransientFailure(f"{what}: failed after {attempts} attempts")


async def wait_for_new_finalized(client: Any, block_time: float) -> None:
    """Return as soon as the finalized head moves past its current value."""
    start = await client.finalized_block()
    deadline = time.monotonic() + max(10.0, FINALITY_WAIT_BLOCKS * block_time)
    while time.monotonic() < deadline:
        await asyncio.sleep(block_time / 4)
        if await client.finalized_block() > start:
            return
    raise TransientFailure(f"finality stalled at block {start}")


async def wait_for_chain(endpoint: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            async with bt.Subtensor(endpoint, fallback_endpoints=[]) as client:
                first = await client.block()
                await asyncio.sleep(1.0)
                if await client.block() > first:
                    return
        except Exception as e:  # noqa: BLE001 - the node is still starting
            last_error = e
        await asyncio.sleep(1.0)
    raise SystemExit(f"chain at {endpoint} not producing blocks: {last_error}")


async def find_owned_subnet(client: Any, owner_coldkey: str) -> int | None:
    for info in await client.subnets.subnets():
        if info.netuid == 0:
            continue
        mg = await client.subnets.metagraph(info.netuid, commitments=False)
        if mg is not None and mg.owner_coldkey == owner_coldkey:
            return int(info.netuid)
    return None


def prepare_wallets(state_dir: Path) -> tuple[bt.Wallet, dict[str, bt.Wallet]]:
    """Create (or check) the Alice wallet and one wallet per role."""
    wallets_dir = state_dir / "wallets"
    wallets_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / MARKER).touch()
    state_dir.chmod(0o700)

    alice = make_wallet(wallets_dir, "alice", ALICE_SEED, ALICE_SEED)
    check_wallet(alice, ALICE_SEED, ALICE_SEED)
    if alice.coldkeypub.ss58_address != ALICE_SS58:
        raise SystemExit("the Alice seed does not derive //Alice")
    wallets: dict[str, bt.Wallet] = {}
    for role in ROLES:
        cold, hot = dev_seed(role.wallet, "coldkey"), dev_seed(role.wallet, "hotkey")
        wallet = make_wallet(wallets_dir, role.wallet, cold, hot)
        check_wallet(wallet, cold, hot)
        wallets[role.wallet] = wallet
    log(f"wallets ready in {wallets_dir}")
    return alice, wallets


async def setup(
    endpoint: str,
    alice: bt.Wallet,
    wallets: dict[str, bt.Wallet],
    permit_timeout_s: float,
    attempts: int,
) -> dict[str, Any]:
    async with bt.Subtensor(endpoint, fallback_endpoints=[]) as client:
        for role in ROLES:
            await fund(client, alice, wallets[role.wallet], role, attempts)

        owner = wallets["owner"]
        owner_cold = owner.coldkeypub.ss58_address

        async def subnet_registered() -> bool:
            return await find_owned_subnet(client, owner_cold) is not None

        await ensure(
            client,
            "register subnet",
            subnet_registered,
            bt.RegisterSubnet(hotkey_ss58=owner.hotkey.ss58_address),
            owner,
            attempts=attempts,
        )
        netuid = await find_owned_subnet(client, owner_cold)
        assert netuid is not None

        schedule = await client.subnets.subnet_start_schedule(netuid)
        await client.wait_for_block(int(schedule.get("earliest_start_block") or 0))
        await ensure(
            client,
            f"start subnet {netuid}",
            functools.partial(subnet_started, client, netuid),
            bt.StartCall(netuid=netuid),
            owner,
            attempts=attempts,
        )

        for name in ("validator", "miner_py", "miner_ts", "miner_go", "miner_rs"):
            wallet = wallets[name]
            await ensure(
                client,
                f"register {name} on {netuid}",
                functools.partial(
                    registered, client, netuid, wallet.hotkey.ss58_address
                ),
                bt.BurnedRegister(
                    netuid=netuid, hotkey_ss58=wallet.hotkey.ss58_address
                ),
                wallet,
                attempts=attempts,
            )

        validator = wallets["validator"]

        async def staked() -> bool:
            stake = await client.staking.stake(
                coldkey_ss58=validator.coldkeypub.ss58_address,
                hotkey_ss58=validator.hotkey.ss58_address,
                netuid=netuid,
            )
            return bool(stake.rao > 0)

        await ensure(
            client,
            f"stake {VALIDATOR_STAKE_TAO:g} TAO to validator on {netuid}",
            staked,
            # A new subnet's pool is shallow: 500 TAO moves the price far past
            # the default 5% tolerance. Dev funds only, so accept the slippage.
            bt.AddStake(
                hotkey_ss58=validator.hotkey.ss58_address,
                netuid=netuid,
                amount_tao=VALIDATOR_STAKE_TAO,
                slippage_protection=False,
            ),
            validator,
            attempts=attempts,
        )

        mg = await wait_for_permit(
            client, netuid, validator.hotkey.ss58_address, permit_timeout_s
        )
        info = summary(netuid, mg, alice, wallets, await client.block())
        info["block_time_s"] = await client.block_time()
        return info


async def fund(
    client: Any, alice: bt.Wallet, wallet: bt.Wallet, role: Role, attempts: int
) -> None:
    coldkey = wallet.coldkeypub.ss58_address

    async def funded() -> bool:
        # A tenth of the target: the owner spends most of its funds on the
        # subnet lock, and must not be topped up again on the next run.
        balance = await client.balances.balance(coldkey)
        return bool(balance >= bt.tao(role.fund_tao / 10))

    await ensure(
        client,
        f"fund {role.wallet} with {role.fund_tao:g} TAO",
        funded,
        bt.Transfer(dest_ss58=coldkey, amount_tao=role.fund_tao),
        alice,
        attempts=attempts,
    )


async def registered(client: Any, netuid: int, hotkey: str) -> bool:
    return await client.neurons.uid(hotkey_ss58=hotkey, netuid=netuid) is not None


async def subnet_started(client: Any, netuid: int) -> bool:
    """A subnet is started once ``start_call`` has set its first emission block."""
    first = await client.query(
        ("SubtensorModule", "FirstEmissionBlockNumber"), [netuid]
    )
    return first is not None


async def wait_for_permit(
    client: Any, netuid: int, hotkey: str, timeout_s: float
) -> Any:
    """Wait for ``hotkey``'s validator permit: ``timeout_s`` or three tempos."""
    mg = await client.subnets.metagraph(netuid, commitments=False)
    tempo_s = (mg.tempo if mg is not None else 0) * await client.block_time()
    deadline = time.monotonic() + max(timeout_s, 3 * tempo_s)
    while True:
        mg = await client.subnets.metagraph(netuid, commitments=False)
        neuron = mg.by_hotkey(hotkey) if mg is not None else None
        if neuron is not None and neuron.validator_permit:
            log(f"validator permit: yes (uid {neuron.uid}, block {mg.block})")
            return mg
        if time.monotonic() > deadline:
            raise SystemExit(
                f"validator has no permit after {timeout_s:g}s; permits update once "
                "per tempo, check the stake and retry"
            )
        await asyncio.sleep(2.0)


def summary(
    netuid: int,
    mg: Any,
    alice: bt.Wallet,
    wallets: dict[str, bt.Wallet],
    block: int,
) -> dict[str, Any]:
    neurons = {}
    for name, wallet in wallets.items():
        neuron = mg.by_hotkey(wallet.hotkey.ss58_address)
        neurons[name] = {
            "coldkey": wallet.coldkeypub.ss58_address,
            "hotkey": wallet.hotkey.ss58_address,
            "uid": None if neuron is None else neuron.uid,
            "validator_permit": None if neuron is None else neuron.validator_permit,
        }
    return {
        "netuid": netuid,
        "block": block,
        "tempo": mg.tempo,
        "alice": alice.coldkeypub.ss58_address,
        "wallets": neurons,
    }


def write_outputs(state_dir: Path, endpoint: str, info: dict[str, Any]) -> None:
    info = {**info, "endpoint": endpoint, "wallet_path": str(state_dir / "wallets")}
    (state_dir / "localnet.json").write_text(json.dumps(info, indent=2) + "\n")
    env = [
        "# Written by scripts/localnet_setup.py. Localnet only.",
        "TW_NETWORK=local",
        f"TW_NETUID={info['netuid']}",
        f"TW_WALLET_PATH={info['wallet_path']}",
        "TW_ALLOW_PRIVATE_AXONS=1",
    ]
    (state_dir / "localnet.env").write_text("\n".join(env) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--endpoint", default="ws://127.0.0.1:9944")
    parser.add_argument("--chain-timeout", type=float, default=120.0)
    parser.add_argument("--permit-timeout", type=float, default=300.0)
    parser.add_argument(
        "--attempts",
        type=int,
        default=ATTEMPTS,
        help="submissions per step before giving up on transient errors",
    )
    args = parser.parse_args(argv)
    if args.attempts < 1:
        parser.error("--attempts must be at least 1")
    if not args.endpoint.startswith(LOCAL_ENDPOINTS):
        parser.error("refusing to run against a non-local endpoint")
    state_dir = args.state_dir.expanduser().resolve()
    if (
        state_dir == (Path.home() / ".bittensor").resolve()
        or (Path.home() / ".bittensor").resolve() in state_dir.parents
    ):
        parser.error("refusing to use ~/.bittensor as the localnet state directory")

    asyncio.run(wait_for_chain(args.endpoint, args.chain_timeout))
    alice, wallets = prepare_wallets(state_dir)
    try:
        info = asyncio.run(
            setup(args.endpoint, alice, wallets, args.permit_timeout, args.attempts)
        )
    except TransientFailure as e:
        log(f"giving up on transient errors: {e}")
        return EXIT_TRANSIENT
    write_outputs(state_dir, args.endpoint, info)
    log(f"done: netuid {info['netuid']} at block {info['block']}")
    print(json.dumps(info, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
