#!/usr/bin/env python3
"""Answer two Phase 0 questions on a localnet prepared by localnet_up.sh.

1. Spec 8.3: what unit is ``MetagraphNeuron.total_stake``, and how do alpha
   and root (TAO) stake combine in it?
2. Spec 8.11.3: is the on-chain axon ``protocol`` field readable through the
   v11 metagraph, and which values can ``ServeAxon`` store?

It also reports the chain's drand feed (``drand``: last stored pulse vs the
wall clock, and HTTP 429 / deadline errors in the chain log; see
``drand_feed.py``). Without a working feed, timelocked weight commits are never
revealed (spec 14.2). ``--drand-only`` reports just that, read-only.

LOCALNET ONLY: it starts the root subnet with Alice (sudo on localnet), adds
root stake to the validator hotkey and publishes axons for the four miners.
Writes a JSON report to ``--out``.

Usage:
    python scripts/localnet_probe.py --out REPORT.json [--state-dir DIR]
    python scripts/localnet_probe.py --drand-only [--out REPORT.json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import bittensor as bt

from drand_feed import drand_feed

ROOT_STAKE_TAO = 100.0
U64_SCALE = 2**64
# (wallet, ip, port, protocol tag). 21591 is the spec's TW_PROTOCOL_TAG
# default; 256 is the first value outside u8. Loopback is rejected by the
# chain (see IP_CASES), so these use private addresses.
SERVE_CASES = (
    ("miner_py", "10.0.0.5", 8091, 87),
    ("miner_ts", "192.168.1.10", 8092, 255),
    ("miner_rs", "172.17.0.1", 8094, 21591),
    ("miner_rs", "172.17.0.1", 8094, 256),
    ("miner_rs", "172.17.0.1", 8094, 0),
)
# Addresses tried in order with one wallet until one is accepted. Failed
# publications do not count against the serving rate limit.
IP_CASES = ("127.0.0.1", "127.0.0.2", "::1", "0.0.0.0")  # noqa: S104


def log(message: str) -> None:
    print(f"[probe] {message}", flush=True)


async def execute(
    client: Any, intent: Any, wallet: bt.Wallet, attempts: int = 8
) -> Any:
    """Execute, retrying transient fast-block failures; return the last result."""
    result = None
    for _ in range(attempts):
        result = await client.execute(
            intent, wallet, wait_for_inclusion=True, wait_for_finalization=True
        )
        if result.success:
            return result
        code = getattr(getattr(result.error, "code", None), "value", None)
        if code in ("invalid_argument", "rate_limited", "not_authorized", "disabled"):
            message = result.message or ""
            if (
                "signature does not match" not in message
                and "pool marked" not in message
            ):
                return result
        await asyncio.sleep(2.0)
    return result


async def stake_units(
    client: Any, wallets: dict[str, bt.Wallet], netuid: int
) -> dict[str, Any]:
    validator = wallets["validator"]
    hotkey = validator.hotkey.ss58_address

    async def snapshot() -> dict[str, Any]:
        mg = await client.subnets.metagraph(netuid, commitments=False)
        n = mg.by_hotkey(hotkey)
        tao_weight = await client.query(("SubtensorModule", "TaoWeight"), [])
        return {
            "block": mg.block,
            "price_tao_per_alpha": mg.price,
            "alpha_stake_rao": n.alpha_stake.rao,
            "alpha_stake_netuid": n.alpha_stake.netuid,
            "tao_stake_rao": n.tao_stake.rao,
            "tao_stake_netuid": n.tao_stake.netuid,
            "total_stake_rao": n.total_stake.rao,
            "total_stake_netuid": n.total_stake.netuid,
            "total_stake_repr": repr(n.total_stake),
            "tao_weight_raw": tao_weight,
            "tao_weight": tao_weight / U64_SCALE,
            "alpha_plus_weighted_tao_rao": n.alpha_stake.rao
            + tao_weight / U64_SCALE * n.tao_stake.rao,
            "validator_permit": n.validator_permit,
        }

    before = await snapshot()
    if not await client.query(("SubtensorModule", "SubtokenEnabled"), [0]):
        alice = wallets["alice"]
        result = await execute(client, bt.StartCall(netuid=0), alice)
        log(f"start root subnet: {result.success} {result.message}")
    if before["tao_stake_rao"] == 0:
        result = await execute(
            client,
            bt.AddStake(
                hotkey_ss58=hotkey,
                netuid=0,
                amount_tao=ROOT_STAKE_TAO,
                slippage_protection=False,
            ),
            validator,
        )
        log(f"root stake {ROOT_STAKE_TAO:g} TAO: {result.success} {result.message}")
    await client.wait_for_block(await client.block() + 2)
    after = await snapshot()
    total = after["total_stake_rao"]
    predicted = after["alpha_plus_weighted_tao_rao"]
    return {
        "before_root_stake": before,
        "after_root_stake": after,
        "total_equals_alpha_plus_tao_weight_times_tao": abs(total - predicted)
        <= 1 + 1e-9 * total,
        "total_stake_sdk_unit": "alpha of the subnet (Balance tagged with netuid)",
        "total_stake_tao_property_raises": _tao_raises(netuid),
    }


def _tao_raises(netuid: int) -> str:
    try:
        _ = bt.Balance.from_rao(1, netuid).tao
    except bt.UnitMismatchError as e:
        return f"UnitMismatchError: {e}"
    return "no error"


async def ip_acceptance(
    client: Any, wallets: dict[str, bt.Wallet], netuid: int
) -> list[dict[str, Any]]:
    wallet = wallets["miner_go"]
    cases = []
    for ip in IP_CASES:
        result = await execute(
            client, bt.ServeAxon(netuid=netuid, ip=ip, port=8093), wallet
        )
        cases.append({"ip": ip, "accepted": result.success, "message": result.message})
        log(f"ServeAxon ip={ip}: {result.success} {result.message}")
        if result.success:
            break
    return cases


async def axon_protocol(
    client: Any, wallets: dict[str, bt.Wallet], netuid: int
) -> list[dict[str, Any]]:
    cases = []
    for name, ip, port, tag in SERVE_CASES:
        wallet = wallets[name]
        case: dict[str, Any] = {"wallet": name, "ip": ip, "port": port, "protocol": tag}
        try:
            intent = bt.ServeAxon(netuid=netuid, ip=ip, port=port, protocol=tag)
            result = await execute(client, intent, wallet)
            case["success"] = result.success
            case["code"] = getattr(getattr(result.error, "code", None), "value", None)
            case["message"] = result.message
        except Exception as e:  # noqa: BLE001 - encoding errors surface as exceptions
            case["success"] = False
            case["exception"] = f"{type(e).__name__}: {e}"
        mg = await client.subnets.metagraph(netuid, commitments=False)
        neuron = mg.by_hotkey(wallet.hotkey.ss58_address)
        case["read_back"] = {
            "axon": neuron.axon,
            "raw": mg.raw["axons"][neuron.uid],
        }
        log(
            f"ServeAxon protocol={tag}: {case.get('success')} "
            f"-> {case['read_back']['raw']}"
        )
        cases.append(case)
    return cases


async def probe(endpoint: str, state_dir: Path) -> dict[str, Any]:
    info = json.loads((state_dir / "localnet.json").read_text())
    netuid = int(info["netuid"])
    path = str(state_dir / "wallets")
    names = ["alice", "validator", "miner_py", "miner_ts", "miner_go", "miner_rs"]
    wallets = {n: bt.Wallet(name=n, hotkey="default", path=path) for n in names}
    async with bt.Subtensor(endpoint, fallback_endpoints=[]) as client:
        return {
            "bittensor": bt.__version__,
            "endpoint": endpoint,
            "netuid": netuid,
            "spec_version": await client.spec_version(),
            "stake_units": await stake_units(client, wallets, netuid),
            "serve_axon_ip_acceptance": await ip_acceptance(client, wallets, netuid),
            "axon_protocol": await axon_protocol(client, wallets, netuid),
            "drand": (await drand_feed(client)).as_dict(),
        }


async def probe_drand(endpoint: str) -> dict[str, Any]:
    """Read-only: just the drand feed."""
    async with bt.Subtensor(endpoint, fallback_endpoints=[]) as client:
        return {"endpoint": endpoint, "drand": (await drand_feed(client)).as_dict()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--state-dir", type=Path, default=Path("~/.tensorwire/localnet")
    )
    parser.add_argument("--endpoint", default="ws://127.0.0.1:9944")
    parser.add_argument("--out", type=Path)
    parser.add_argument(
        "--drand-only",
        action="store_true",
        help="read-only: report the chain's drand feed; exit 1 when it is failing",
    )
    args = parser.parse_args(argv)
    if not args.endpoint.startswith(("ws://127.0.0.1:", "ws://localhost:")):
        parser.error("refusing to run against a non-local endpoint")
    if args.drand_only:
        report = asyncio.run(probe_drand(args.endpoint))
    elif args.out is None:
        parser.error("--out is required (it writes to the chain; see the docstring)")
    else:
        report = asyncio.run(probe(args.endpoint, args.state_dir.expanduser()))
    if args.out is not None:
        args.out.write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps(report, indent=2, default=str))
    return 0 if report["drand"]["healthy"] else 1


if __name__ == "__main__":
    sys.exit(main())
