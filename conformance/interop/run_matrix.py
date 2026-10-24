#!/usr/bin/env python3
"""The cross-language interop matrix on localnet (spec 13.5, 15.7 shape).

    just localnet-up
    cd python && uv run python ../conformance/interop/run_matrix.py \\
        --out ../dist/interop-matrix [--count 200]

On the localnet subnet of ``scripts/localnet_up.sh`` (dev wallets only), it
starts the four text-ops miners, each on its own address and port and with
its own registered hotkey:

- Python: ``python -m text_ops.miner`` (wallet ``miner_py``), publishing its
  axon itself;
- TypeScript, Go, Rust: the example miners (wallets ``miner_ts``,
  ``miner_go``, ``miner_rs``), each with its own ``taowire sidecar``
  through which it publishes its axon and gets its caller policy.

Then:

1. the Python validator (``ValidatorClient``, the wallet that holds a
   validator permit, read from the chain) sends ``--count`` requests to each
   miner's ``POST /v1/transform`` and ``--count`` to its streaming route, at
   the addresses the chain shows: every one must be ok, twresp/1 verified and
   correct (``text_ops.protocol``);
2. the TypeScript, Go and Rust client signers (the same validator hotkey) send
   ``--count`` requests to the Python miner: every one 200 with a verified
   twresp/1 signature;
3. weights: a marker row is committed and revealed first, then the text-ops
   validator runs until the chain shows a revealed row that weights all four
   miners (so the reveal belongs to this run).

Evidence: ``results.json``, ``results.md`` and one log per process in
``--out``. Refuses any chain that is not on 127.0.0.1.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
from live_check import REPO, free_port, spawn, wait_http

from taowire.auth.signer import RequestSigner
from taowire.chain.gateway import BittensorGateway, NeuronView
from taowire.validator.client import ValidatorClient
from taowire.validator.weights import WeightScheduler

sys.path.insert(0, str(REPO / "examples" / "text-ops-subnet"))
sys.path.insert(0, str(REPO / "python" / "tests" / "localnet"))
from drand_guard import DrandWatch, require_drand_feed
from localnet_env import ENDPOINT, STATE_DIR
from text_ops.protocol import (
    ROUTE,
    STREAM_ROUTE,
    TransformPiece,
    TransformResponse,
    expected,
    pieces,
    random_request,
)

EXAMPLE = REPO / "examples" / "text-ops-subnet"
#: Miner wallet, address (127.0.0.x, never .1: the chain refuses it).
MINERS = {
    "python": ("miner_py", "127.0.0.2"),
    "typescript": ("miner_ts", "127.0.0.3"),
    "go": ("miner_go", "127.0.0.4"),
    "rust": ("miner_rs", "127.0.0.5"),
}
VALIDATOR_CANDIDATES = ("validator", "owner")


def note(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def build(out: Path) -> dict[str, list[str]]:
    """The miners and the interop signers; their command prefixes."""
    tmp = Path(tempfile.mkdtemp(prefix="tw-matrix-"))
    go_miner, go_interop = tmp / "textops-miner", tmp / "btauth-interop"
    features = ["--features", "axum,client,sidecar,redis"]
    steps = [
        (["go", "build", "-o", str(go_miner), "./examples/textops-miner"], REPO / "go"),
        (["go", "build", "-o", str(go_interop), "./cmd/btauth-interop"], REPO / "go"),
        (
            ["cargo", "build", "-j", "2", "--example", "textops_miner", *features],
            REPO / "rust",
        ),
        (
            ["cargo", "build", "-j", "2", "--example", "interop", *features],
            REPO / "rust",
        ),
        (["npm", "run", "build:examples"], REPO / "typescript"),
    ]
    env = {**os.environ, "GOTOOLCHAIN": "local"}
    with (out / "build.txt").open("w", encoding="utf-8") as log:
        for cmd, cwd in steps:
            subprocess.run(  # noqa: S603 - fixed argv
                cmd, cwd=cwd, env=env, check=True, stdout=log, stderr=subprocess.STDOUT
            )
    target = REPO / "rust" / "target" / "debug" / "examples"
    ts = REPO / "typescript" / "build" / "examples"
    return {
        "miner:go": [str(go_miner)],
        "miner:rust": [str(target / "textops_miner")],
        "miner:typescript": ["node", str(ts / "textops-miner.js")],
        "sign:go": [str(go_interop)],
        "sign:rust": [str(target / "interop")],
        "sign:typescript": ["node", str(ts / "interop.js")],
    }


class Fleet:
    """The processes of one run; every one is stopped at the end."""

    def __init__(self, out: Path, info: dict[str, Any]) -> None:
        self.out = out
        self.info = info
        self.procs: list[tuple[str, subprocess.Popen[bytes], Path]] = []
        self.tmp = Path(tempfile.mkdtemp(prefix="tw-matrix-state-"))

    def env(self, wallet: str, extra: dict[str, str]) -> dict[str, str]:
        base = {k: v for k, v in os.environ.items() if not k.upper().startswith("TW_")}
        state = self.tmp / wallet
        state.mkdir(parents=True, exist_ok=True)
        return {
            **base,
            "TW_NETWORK": ENDPOINT,
            "TW_NETUID": str(self.info["netuid"]),
            "TW_WALLET_PATH": str(STATE_DIR / "wallets"),
            "TW_WALLET_NAME": wallet,
            "TW_REFUSE_IF_COLDKEY_PRESENT": "0",  # localnet dev wallets hold coldkeys
            "TW_ALLOW_PRIVATE_AXONS": "1",
            "TW_STATE_DIR": str(state),
            "TW_METRICS_BIND": f"127.0.0.1:{free_port('127.0.0.1')}",
            "TW_NTP_SERVERS": "",
            "TW_METAGRAPH_REFRESH_S": "10",
            **extra,
        }

    def start(
        self, name: str, cmd: list[str], env: dict[str, str], cwd: Path | None = None
    ) -> Path:
        log = self.out / f"{name}.log"
        self.procs.append((name, spawn(cmd, log, env=env, cwd=cwd), log))
        note(f"started {name}")
        return log

    def alive(self, name: str) -> bool:
        return next(p for n, p, _ in self.procs if n == name).poll() is None

    def stop_all(self) -> None:
        for name, p, _ in reversed(self.procs):
            p.terminate()
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()
            note(f"stopped {name}")


async def until(what: str, check: Any, timeout_s: float, poll_s: float = 1.0) -> Any:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = await check()
        if value:
            return value
        await asyncio.sleep(poll_s)
    raise SystemExit(f"timed out waiting for {what}")


def start_miners(fleet: Fleet, programs: dict[str, list[str]]) -> dict[str, int]:
    ports: dict[str, int] = {}
    # 400 back-to-back requests from one validator exceed the default buckets,
    # which are not what this matrix tests.
    names = ("TW_RATE_HOTKEY_PER_S", "TW_RATE_HOTKEY_BURST")
    names += ("TW_RATE_IP_PER_S", "TW_RATE_IP_BURST")
    fast = dict.fromkeys(names, "1000")
    for lang, (wallet, ip) in MINERS.items():
        port = free_port(ip)
        ports[lang] = port
        miner_env = {
            "TW_BIND_HOST": ip,
            "TW_BIND_PORT": str(port),
            "TW_EXTERNAL_IP": ip,
            **fast,
        }
        if lang == "python":
            env = fleet.env(wallet, {**miner_env, "PYTHONPATH": str(EXAMPLE)})
            fleet.start(
                f"{lang}-miner",
                [sys.executable, "-m", "text_ops.miner"],
                env,
                cwd=EXAMPLE,
            )
            continue
        sc_port = free_port("127.0.0.1")
        token = fleet.tmp / wallet / "sidecar.token"
        sc_env = fleet.env(
            wallet,
            {"TW_SIDECAR_PORT": str(sc_port), "TW_SIDECAR_TOKEN_FILE": str(token)},
        )
        cli = str(Path(sys.executable).parent / "taowire")
        fleet.start(f"{lang}-sidecar", [cli, "sidecar"], sc_env)
        deadline = time.monotonic() + 120
        while not token.exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        wait_sidecar(sc_port, token, fleet, f"{lang}-sidecar")
        env = {**sc_env, **miner_env}
        fleet.start(f"{lang}-miner", programs[f"miner:{lang}"], env)
    for lang, (_, ip) in MINERS.items():
        name = f"{lang}-miner"
        log = fleet.out / f"{name}.log"
        proc = next(p for n, p, _ in fleet.procs if n == name)
        wait_http(f"http://{ip}:{ports[lang]}/healthz", proc, log)
    return ports


def wait_sidecar(port: int, token: Path, fleet: Fleet, name: str) -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if not fleet.alive(name):
            raise SystemExit(f"{name} exited, see {fleet.out / (name + '.log')}")
        try:
            headers = {"Authorization": f"Bearer {token.read_text().strip()}"}
            r = httpx.get(
                f"http://127.0.0.1:{port}/v1/health", headers=headers, timeout=1
            )
            if r.status_code == 200 and r.json().get("ok"):
                return
        except (httpx.TransportError, OSError, ValueError):
            pass
        time.sleep(0.5)
    raise SystemExit(f"{name} not ready")


async def published_axons(
    gw: BittensorGateway, netuid: int, hotkeys: dict[str, str], ports: dict[str, int]
) -> dict[str, NeuronView]:
    async def check() -> dict[str, NeuronView] | None:
        mg = await gw.metagraph(netuid)
        found: dict[str, NeuronView] = {}
        for lang, (_, ip) in MINERS.items():
            n = mg.by_hotkey(hotkeys[lang])
            if (
                n is None
                or n.axon is None
                or (n.axon.host, n.axon.port) != (ip, ports[lang])
            ):
                return None
            found[lang] = n
        return found

    result: dict[str, NeuronView] = await until(
        "the four axons on chain", check, 300, 2.0
    )
    return result


async def python_validator_cells(
    signer: RequestSigner, neurons: dict[str, NeuronView], count: int
) -> list[dict[str, Any]]:
    cells = []
    async with ValidatorClient(
        signer, timeout_s=10, max_attempts=1, max_concurrency=8
    ) as vc:
        for lang, n in neurons.items():
            rng = random.Random(n.uid)  # noqa: S311 - tasks, not secrets
            reqs = [random_request(rng) for _ in range(count)]
            plain = await asyncio.gather(
                *(
                    vc.query(
                        n,
                        ROUTE,
                        r.model_dump_json().encode(),
                        response_model=TransformResponse,
                    )
                    for r in reqs
                )
            )
            ok = sum(
                1
                for r, res in zip(reqs, plain, strict=True)
                if res.ok
                and res.response_verified
                and res.data == TransformResponse(result=expected(r))
            )
            streams = await asyncio.gather(
                *(
                    vc.query_stream(
                        n,
                        STREAM_ROUTE,
                        r.model_dump_json().encode(),
                        chunk_model=TransformPiece,
                    )
                    for r in reqs
                )
            )
            sok = sum(
                1
                for r, res in zip(reqs, streams, strict=True)
                if res.ok
                and res.response_verified
                and list(res.data or ()) == pieces(r)
            )
            errors: dict[str, int] = {}
            for res in (*plain, *streams):
                if not res.ok:
                    errors[str(res.error_code)] = errors.get(str(res.error_code), 0) + 1
            p50 = sorted(r.latency_ms for r in plain)[len(plain) // 2]
            cells.append(
                {
                    "cell": f"python validator -> {lang} miner",
                    "uid": n.uid,
                    "axon": str(n.axon),
                    "transform_ok": ok,
                    "stream_ok": sok,
                    "count": count,
                    "errors": errors,
                    "p50_ms": round(p50, 2),
                    "pass": ok == sok == count,
                }
            )
            note(f"{cells[-1]['cell']}: {ok}/{count} transform, {sok}/{count} stream")
    return cells


def signer_cells(
    programs: dict[str, list[str]], seed: str, receiver: str, url: str, count: int
) -> list[dict[str, Any]]:
    body = json.dumps({"text": "hello world", "op": "upper"}, separators=(",", ":"))
    cells = []
    for lang in ("typescript", "go", "rust"):
        prog = programs[f"sign:{lang}"]
        if lang == "rust":
            args = ["sign", url, seed, receiver, "sr25519", str(count), body]
        else:
            args = [
                "sign",
                "--url",
                url,
                "--seed",
                seed,
                "--receiver",
                receiver,
                "--count",
                str(count),
                "--body",
                body,
            ]
        run = subprocess.run(  # noqa: S603 - the matrix's own binaries
            [*prog, *args], capture_output=True, text=True, timeout=900, check=False
        )
        lines = run.stdout.strip().splitlines()
        summary = (
            json.loads(lines[-1]) if lines else {"ok": 0, "error": run.stderr[-500:]}
        )
        cells.append(
            {
                "cell": f"{lang} client signer -> python miner",
                **summary,
                "pass": summary.get("ok") == count,
            }
        )
        note(f"{cells[-1]['cell']}: {summary.get('ok')}/{count}")
    return cells


async def weights_cell(
    fleet: Fleet, info: dict[str, Any], validator: str, neurons: dict[str, NeuronView]
) -> dict[str, Any]:
    netuid = info["netuid"]
    wallet = bt.Wallet(
        name=validator, hotkey="default", path=str(STATE_DIR / "wallets")
    )
    gw = BittensorGateway(ENDPOINT, hotkey=wallet.hotkey, allow_private_axons=True)
    await gw.connect()
    client = await bt.Subtensor(network=ENDPOINT)
    try:
        await require_drand_feed(client)
        mg = await gw.metagraph(netuid)
        me = mg.by_hotkey(wallet.hotkey.ss58_address)
        if me is None:
            raise SystemExit(f"{validator} is not registered")
        miner_uids = sorted(n.uid for n in neurons.values())
        marker = next(
            n.uid for n in mg.neurons if n.uid not in miner_uids and n.uid != me.uid
        )
        # 1. A marker row first: a row that later weights all four miners was
        #    revealed in this run.
        scheduler = WeightScheduler(
            gw, netuid, wallet.hotkey.ss58_address, min_interval_blocks=0
        )

        async def committed() -> Any:
            d = await scheduler.maybe_submit({marker: 1.0}, mg)
            return d if d.reason not in ("replanning", "waiting", "not_due") else None

        decision = await until("the marker commit", committed, 600, 2.0)
        if not decision.submitted:
            return {
                "cell": "weights set and revealed",
                "pass": False,
                "marker_decision": decision.reason,
            }

        async def marker_row() -> Any:
            row = (await client.weights.weights(netuid)).get(me.uid)
            return row if row == {marker: 1.0} else None

        watch = DrandWatch(client)

        async def marker_watched() -> Any:
            await watch.check()
            return await marker_row()

        await until("the marker reveal", marker_watched, 900, 2.0)
        note(f"marker row revealed (uid {me.uid} -> {marker})")
        # 2. The text-ops validator scores the four miners and sets weights.
        env = fleet.env(
            validator,
            {
                "PYTHONPATH": str(EXAMPLE),
                "TW_ROUND_INTERVAL_S": "3",
                "TW_QUERY_VALIDATORS": "1",
                "TW_MIN_WEIGHT_INTERVAL_BLOCKS": "10",
                "TW_QUERY_TIMEOUT_S": "5",
            },
        )
        fleet.start(
            "python-validator",
            [sys.executable, "-m", "text_ops.validator"],
            env,
            cwd=EXAMPLE,
        )
        started_block = await gw.block()

        async def full_row() -> Any:
            await watch.check()
            row = (await client.weights.weights(netuid)).get(me.uid) or {}
            return row if all(row.get(u, 0) > 0 for u in miner_uids) else None

        row = await until(
            "a revealed row weighting the four miners", full_row, 1200, 3.0
        )
        return {
            "cell": "weights set and revealed (text-ops validator)",
            "validator_uid": me.uid,
            "marker_uid": marker,
            "miner_uids": miner_uids,
            "revealed_row": {str(k): v for k, v in row.items()},
            "validator_started_block": started_block,
            "revealed_by_block": await gw.block(),
            "pass": True,
        }
    finally:
        await gw.close()
        await client.close()


async def run(args: argparse.Namespace, out: Path) -> list[dict[str, Any]]:
    if "127.0.0.1" not in ENDPOINT:
        raise SystemExit(f"refusing {ENDPOINT}: localnet only")
    info = json.loads((STATE_DIR / "localnet.json").read_text())
    hotkeys = {lang: info["wallets"][w]["hotkey"] for lang, (w, _) in MINERS.items()}
    gw = BittensorGateway(ENDPOINT, allow_private_axons=True)
    await gw.connect()
    mg = await gw.metagraph(info["netuid"])
    permit = [
        w
        for w in VALIDATOR_CANDIDATES
        if (n := mg.by_hotkey(info["wallets"][w]["hotkey"])) and n.validator_permit
    ]
    if not permit:
        raise SystemExit("no candidate validator wallet holds a permit right now")
    validator = permit[0]
    note(f"validator wallet: {validator} (holds a permit on block {mg.block})")
    programs = build(out)
    fleet = Fleet(out, info)
    cells: list[dict[str, Any]] = []
    try:
        ports = start_miners(fleet, programs)
        neurons = await published_axons(gw, info["netuid"], hotkeys, ports)
        note("all four axons are on chain")
        wallet = bt.Wallet(
            name=validator, hotkey="default", path=str(STATE_DIR / "wallets")
        )
        cells += await python_validator_cells(
            RequestSigner(wallet.hotkey), neurons, args.count
        )
        seed = json.loads(
            (STATE_DIR / "wallets" / validator / "hotkeys" / "default").read_text()
        )["secretSeed"]
        py_url = f"http://{MINERS['python'][1]}:{ports['python']}{ROUTE}"
        cells += signer_cells(
            programs, seed.removeprefix("0x"), hotkeys["python"], py_url, args.count
        )
        cells.append(await weights_cell(fleet, info, validator, neurons))
    finally:
        fleet.stop_all()
        await gw.close()
    return cells


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--count", type=int, default=200)
    args = parser.parse_args()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    started = time.time()
    cells = asyncio.run(run(args, out))
    ok = len(cells) == 8 and all(c["pass"] for c in cells)
    (out / "results.json").write_text(
        json.dumps(
            {
                "endpoint": ENDPOINT,
                "duration_s": round(time.time() - started),
                "pass": ok,
                "cells": cells,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    lines = ["| cell | pass | detail |", "|---|---|---|"]
    for c in cells:
        detail = {k: v for k, v in c.items() if k not in ("cell", "pass")}
        lines.append(f"| {c['cell']} | {c['pass']} | {json.dumps(detail)[:300]} |")
    (out / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
