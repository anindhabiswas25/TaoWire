#!/usr/bin/env python3
"""Count subnets running TensorWire: product metric M1 (spec 1.6).

Reads every subnet's metagraph and counts the served axons whose on-chain
``protocol`` byte equals the TensorWire tag (spec 8.7.2). A subnet counts
toward M1 when at least ``--min-axons`` of its axons advertise the tag. The
tag is advisory and any team can publish the same byte, so cross-check the
result against public repositories that depend on ``tensorwire``.

Read-only: it never signs or submits anything and needs no wallet. Public
endpoints are rate-limited (about 1 request per second), so it pauses
``--delay`` seconds between subnets on non-local networks.

Usage:
    python scripts/count_m1.py --network local --tag 87 [--json REPORT.json]
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import sys
from collections import Counter
from typing import Any

import bittensor as bt

LOCAL_PREFIXES = ("local", "ws://127.0.0.1:", "ws://localhost:")


def served_protocols(metagraph: Any) -> list[int]:
    """The protocol byte of every neuron with a served axon (non-zero IP)."""
    out = []
    for axon in metagraph.raw.get("axons") or []:
        if isinstance(axon, dict) and int(axon.get("ip") or 0) != 0:
            out.append(int(axon.get("protocol") or 0))
    return out


async def count(
    network: str, tag: int, min_axons: int, delay_s: float
) -> dict[str, Any]:
    async with bt.Subtensor(network) as client:
        block = await client.block()
        subnets = sorted(int(s.netuid) for s in await client.subnets.subnets())
        rows = []
        histogram: Counter[int] = Counter()
        for i, netuid in enumerate(subnets):
            if i and delay_s:
                await asyncio.sleep(delay_s)
            mg = await client.subnets.metagraph(netuid, commitments=False)
            if mg is None:
                continue
            protocols = served_protocols(mg)
            histogram.update(protocols)
            tagged = sum(1 for p in protocols if p == tag)
            rows.append(
                {
                    "netuid": netuid,
                    "neurons": len(mg.neurons),
                    "served_axons": len(protocols),
                    "tagged_axons": tagged,
                    "counts": tagged >= min_axons,
                }
            )
    return {
        "metric": "M1",
        "network": network,
        "block": block,
        "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "tag": tag,
        "min_axons": min_axons,
        "subnets_scanned": len(rows),
        "m1": sum(1 for r in rows if r["counts"]),
        "subnets": rows,
        "protocol_histogram": {str(k): v for k, v in sorted(histogram.items())},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--network", default="local", help="finney | test | local | ws://..."
    )
    parser.add_argument(
        "--tag", type=int, required=True, help="TW_PROTOCOL_TAG (0-255)"
    )
    parser.add_argument("--min-axons", type=int, default=1)
    parser.add_argument(
        "--delay", type=float, default=None, help="seconds between subnets"
    )
    parser.add_argument("--json", metavar="PATH", help="also write the report as JSON")
    args = parser.parse_args(argv)
    if not 0 <= args.tag <= 255:
        parser.error("--tag must be 0-255: the on-chain protocol field is a u8")
    if args.min_axons < 1:
        parser.error("--min-axons must be at least 1")
    delay = args.delay
    if delay is None:
        delay = 0.0 if args.network.startswith(LOCAL_PREFIXES) else 1.0

    report = asyncio.run(count(args.network, args.tag, args.min_axons, delay))
    print(
        f"M1 = {report['m1']} subnet(s) with >= {args.min_axons} axon(s) advertising "
        f"protocol {args.tag} ({report['network']}, block {report['block']}, "
        f"{report['subnets_scanned']} subnets scanned)"
    )
    for row in report["subnets"]:
        print(
            f"  netuid {row['netuid']:>3}: {row['tagged_axons']}/{row['served_axons']} "
            f"served axons tagged, {row['neurons']} neurons"
        )
    print(f"  protocol values in use: {report['protocol_histogram']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
