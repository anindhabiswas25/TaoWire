#!/usr/bin/env python3
"""Walk the rollout runbook (spec 10b.5) with rollbacks on the localnet mixed fleet.

    PY=<tree>/python/.venv/bin/python
    "$PY" scripts/rollout_walkthrough.py --tree <tree> --out dist/rollout

``<tree>`` is a checkout of this repository (``taowire migrate status`` and
the ported template in ``examples/migrations/template-v10-to-v11/after/``).
Run this script with that tree's interpreter. The fleet, on the localnet from
``scripts/localnet_up.sh`` (netuid 2, dev wallets):

- ``validator`` (uid 1): v10 validator (sets weights, key 0), then
  ``after/neurons/validator.py`` with metrics on :9102.
- ``owner`` (uid 0): the v10 straggler validator, then ``after/`` on :9104.
- ``miner_py`` (uid 2): v10 Axon on 127.0.0.2:8092, then ``after/neurons/miner.py``
  on the same address, metrics :9101.
- ``miner_go`` (uid 4): the same on 127.0.0.3:8093, metrics :9103.

The archived template's own ``before/`` neurons do not run on bittensor 10.x
(they use ``bt.wallet`` / ``bt.subtensor`` / ``bt.metagraph`` / ``bt.axon``,
which 10.3.0 and 10.5.0 do not have), so the v10 nodes are
``scripts/v10_peer.py``: the template's ``Dummy`` Synapse on the real 10.5.0
Axon, Dendrite, ``serve_axon`` and ``set_weights`` (template ``version_key`` 0
and ``epoch_length`` 100).

"Weights land on chain" means a ``TimelockedWeightsRevealed`` event for the
validator's hotkey after the check started (``LastUpdate`` moves at commit
time already, so it proves nothing). Every check is written to
``<out>/walkthrough.json`` and ``<out>/walkthrough.md``; every ``migrate
status`` read keeps its raw scrapes in ``<out>/scrapes/``. The run stops at the
first failing check, stops every node and exits 1.

Localnet dev keys only: refuses any endpoint that is not on 127.0.0.1.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import bittensor as bt

REPO = Path(__file__).resolve().parents[1]
V10_PEER = REPO / "scripts" / "v10_peer.py"
LEGACY_PY = Path.home() / ".taowire" / "venvs" / "bittensor-10.5.0" / "bin" / "python"
ENDPOINT = "ws://127.0.0.1:9944"
NETUID = 2
SM = "SubtensorModule"
#: Kit protocol tag on chain (TW_PROTOCOL_TAG default); v10 ``serve_axon`` writes 4.
TW_PROTOCOL = 87
V10_PROTOCOL = 4

MINERS: dict[str, dict[str, Any]] = {
    "miner_py": {"ip": "127.0.0.2", "port": 8092, "metrics": 9101},
    "miner_go": {"ip": "127.0.0.3", "port": 8093, "metrics": 9103},
}
VALIDATORS: dict[str, dict[str, Any]] = {
    "validator": {"metrics": 9102},
    "owner": {"metrics": 9104},
}
#: TW_METAGRAPH_REFRESH_S for the TaoWire nodes (the config minimum).
REFRESH_S = 10
#: Validator log event of spec 8.11.3 step 5 (D16).
TAG_CHANGED = "legacy_v10_protocol_tag_changed"
#: Weights version key the stage 1 release sends (template sends 0).
NEW_KEY = 1
V_PORTS = [int(v["metrics"]) for v in VALIDATORS.values()]
M_PORTS = [int(m["metrics"]) for m in MINERS.values()]


def today_plus(days: int) -> str:
    return (
        dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=days)
    ).isoformat()


#: The legacy end date of the stage 1 and 2 releases.
UNTIL28 = today_plus(28)


# --------------------------------------------------------------------------- nodes


@dataclass
class Node:
    name: str  # e.g. "tw-validator@validator"
    proc: subprocess.Popen[bytes]
    log: Path
    metrics: int | None = None

    def lines(self) -> list[str]:
        return self.log.read_text(encoding="utf-8", errors="replace").splitlines()


@dataclass
class Fleet:
    tree: Path
    out: Path
    wallets: Path
    nodes: dict[str, Node] = field(default_factory=dict)  # by hotkey
    seq: int = 0

    @property
    def after(self) -> Path:
        return self.tree / "examples" / "migrations" / "template-v10-to-v11" / "after"

    def _log(self, name: str) -> Path:
        self.seq += 1
        path = self.out / "logs" / f"{self.seq:02d}-{name.replace('@', '-')}.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _spawn(
        self, hotkey: str, name: str, cmd: list[str], env: dict[str, str], **kw: Any
    ) -> Node:
        if hotkey in self.nodes:
            raise RuntimeError(f"{hotkey} already runs {self.nodes[hotkey].name}")
        log = self._log(name)
        with log.open("wb") as fh:
            proc = subprocess.Popen(
                cmd, stdout=fh, stderr=subprocess.STDOUT, env=env, **kw
            )
        node = Node(name, proc, log)
        self.nodes[hotkey] = node
        note(f"started {name} (pid {proc.pid}, log {log.name})")
        return node

    def _tw_env(self, hotkey: str, extra: dict[str, str]) -> dict[str, str]:
        state = self.out / "state" / hotkey
        state.mkdir(parents=True, exist_ok=True)
        return {
            "HOME": str(Path.home()),
            "PATH": os.environ["PATH"],
            "PYTHONPATH": str(self.after),
            "TW_NETWORK": ENDPOINT,
            "TW_NETUID": str(NETUID),
            "TW_WALLET_PATH": str(self.wallets),
            "TW_WALLET_NAME": hotkey,
            "TW_STATE_DIR": str(state),
            "TW_ALLOW_PRIVATE_AXONS": "1",
            "TW_REFUSE_IF_COLDKEY_PRESENT": "0",  # localnet dev wallets hold coldkeys
            "TW_METAGRAPH_REFRESH_S": str(REFRESH_S),  # localnet: see switches fast
            **extra,
        }

    def tw_miner(self, hotkey: str, legacy_until: str | None) -> Node:
        m = MINERS[hotkey]
        extra = {
            "TW_BIND_HOST": m["ip"],
            "TW_BIND_PORT": str(m["port"]),
            "TW_EXTERNAL_IP": m["ip"],
            "TW_METRICS_BIND": f"127.0.0.1:{m['metrics']}",
        }
        if legacy_until:
            extra["TW_LEGACY_V10_UNTIL"] = legacy_until
        cmd = [sys.executable, str(self.after / "neurons" / "miner.py")]
        node = self._spawn(
            hotkey, f"tw-miner@{hotkey}", cmd, self._tw_env(hotkey, extra)
        )
        node.metrics = int(m["metrics"])
        return node

    def tw_validator(
        self,
        hotkey: str,
        legacy_client: str,
        until: str | None,
        *,
        version_key: int = NEW_KEY,
    ) -> Node:
        extra = {
            "TW_METRICS_BIND": f"127.0.0.1:{VALIDATORS[hotkey]['metrics']}",
            "TW_WEIGHTS_VERSION_KEY": str(version_key),
            "TW_LEGACY_V10_CLIENT": legacy_client,
            "TW_ROUND_INTERVAL_S": "3",
            "TW_MIN_WEIGHT_INTERVAL_BLOCKS": "10",
        }
        if until:
            extra["TW_LEGACY_V10_CLIENT_UNTIL"] = until
        # On localnet, miners that get weights hold permits and alpha stake far
        # above the template's vpermit_tao_limit (4096) within minutes, and the
        # template's get_random_uids then skips them as "validators".
        cmd = [
            sys.executable,
            str(self.after / "neurons" / "validator.py"),
            "--neuron.vpermit_tao_limit",
            "1000000000",
        ]
        node = self._spawn(
            hotkey, f"tw-validator@{hotkey}", cmd, self._tw_env(hotkey, extra)
        )
        node.metrics = int(VALIDATORS[hotkey]["metrics"])
        return node

    def v10_miner(self, hotkey: str) -> Node:
        m = MINERS[hotkey]
        cmd = [
            str(LEGACY_PY), "-I", str(V10_PEER), "axon", "--ip", m["ip"],
            "--port", str(m["port"]), "--chain", ENDPOINT, "--netuid", str(NETUID),
            "--wallet-name", hotkey, "--wallet-path", str(self.wallets),
        ]  # fmt: skip
        env = {"HOME": str(Path.home()), "PATH": os.environ["PATH"]}
        return self._spawn(
            hotkey, f"v10-miner@{hotkey}", cmd, env, stdin=subprocess.PIPE
        )

    def v10_validator(self, hotkey: str, uids: list[int], block_time: float) -> Node:
        cmd = [
            str(LEGACY_PY), "-I", str(V10_PEER), "validator", "--chain", ENDPOINT,
            "--netuid", str(NETUID), "--wallet-name", hotkey,
            "--wallet-path", str(self.wallets), "--uids", *map(str, uids),
            "--count", "2", "--rounds", "0", "--interval", "3", "--set-weights",
            "--version-key", "0", "--block-time", str(block_time),
        ]  # fmt: skip
        env = {"HOME": str(Path.home()), "PATH": os.environ["PATH"]}
        return self._spawn(hotkey, f"v10-validator@{hotkey}", cmd, env)

    def stop(self, hotkey: str) -> None:
        node = self.nodes.pop(hotkey)
        node.proc.send_signal(signal.SIGTERM)
        try:
            node.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            node.proc.kill()
            node.proc.wait()
        if node.proc.stdin:
            node.proc.stdin.close()
        note(f"stopped {node.name} (exit {node.proc.returncode})")

    def stop_all(self) -> None:
        for hotkey in list(self.nodes):
            self.stop(hotkey)


# --------------------------------------------------------------------------- report

REPORT: list[dict[str, Any]] = []


def note(msg: str) -> None:
    print(f"[{dt.datetime.now(dt.timezone.utc):%H:%M:%S}] {msg}", flush=True)


class CheckFailedError(Exception):
    pass


def record(stage: str, check: str, ok: bool, detail: dict[str, Any]) -> None:
    REPORT.append({"stage": stage, "check": check, "ok": ok, **detail})
    note(f"{'PASS' if ok else 'FAIL'} [{stage}] {check}: {json.dumps(detail)[:300]}")
    if not ok:
        raise CheckFailedError(f"[{stage}] {check}")


def write_report(out: Path, meta: dict[str, Any]) -> None:
    (out / "walkthrough.json").write_text(
        json.dumps({"meta": meta, "checks": REPORT}, indent=2) + "\n", encoding="utf-8"
    )
    rows = [
        f"| {r['stage']} | {r['check']} | {'✅' if r['ok'] else '❌'} | "
        + ", ".join(
            f"{k}={v}" for k, v in r.items() if k not in ("stage", "check", "ok")
        )
        + " |"
        for r in REPORT
    ]
    md = [
        "# Rollout walk-through (spec 10b.5)",
        "",
        "Generated by `scripts/rollout_walkthrough.py`.",
        "",
        *(f"- {k}: {v}" for k, v in meta.items()),
        "",
        "| stage | check | ok | detail |",
        "|---|---|---|---|",
        *rows,
        "",
    ]
    (out / "walkthrough.md").write_text("\n".join(md), encoding="utf-8")


# --------------------------------------------------------------------------- chain


class Chain:
    """Chain reads plus a scanner that keeps every weight commit/reveal event.

    The node keeps state for a few hundred blocks only (fast blocks: about a
    minute), so the scanner runs all the time (:meth:`start`) instead of only
    when a check asks.
    """

    def __init__(self, client: Any) -> None:
        self.c = client
        self.cursor: int = 0
        self.events: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None

    async def block(self) -> int:
        return int(await self.c.query(("System", "Number"), []))

    async def axon(self, hotkey_ss58: str) -> dict[str, Any]:
        return dict(await self.c.query((SM, "Axons"), [NETUID, hotkey_ss58]) or {})

    async def weights_version(self) -> int:
        return int(await self.c.query((SM, "WeightsVersionKey"), [NETUID]))

    async def weight_row(self, uid: int) -> list[Any]:
        return list(await self.c.query((SM, "Weights"), [NETUID, uid]) or [])

    def start(self) -> None:
        async def loop() -> None:
            while True:
                await self.scan()
                await asyncio.sleep(0.5)

        self._task = asyncio.create_task(loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def scan(self) -> None:
        """Collect weight commit/reveal events from blocks not scanned yet."""
        async with self._lock:
            head = await self.block()
            while self.cursor < head:
                block = self.cursor + 1
                events = await self.c.query(("System", "Events"), [], block=block)
                for e in events or []:
                    event = e.get("event", e)
                    name = event.get("event_id", "")
                    if event.get("module_id") == SM and "Weight" in name:
                        self.events.append(
                            {
                                "block": block,
                                "event": name,
                                "attributes": event.get("attributes"),
                            }
                        )
                self.cursor = block

    async def revealed_since(
        self, hotkey_ss58: str, block: int
    ) -> dict[str, Any] | None:
        await self.scan()
        for e in self.events:
            if (
                e["block"] > block
                and e["event"] == "TimelockedWeightsRevealed"
                and hotkey_ss58 in json.dumps(e["attributes"])
            ):
                return e
        return None


async def until(
    what: str,
    check: Callable[[], Awaitable[Any]],
    timeout_s: float,
    every_s: float = 2.0,
) -> Any:
    """Poll ``check`` until it returns something truthy; ``None`` after the timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        value = await check()
        if value:
            return value
        if time.monotonic() > deadline:
            note(f"timed out after {timeout_s:.0f} s waiting for {what}")
            return None
        await asyncio.sleep(every_s)


# --------------------------------------------------------------------------- reads

ROUND = re.compile(r'"event": "round ok"')


def last_round(node: Node) -> dict[str, Any] | None:
    for line in reversed(node.lines()):
        if ROUND.search(line):
            try:
                return dict(json.loads(line[line.index("{") :]))
            except ValueError:
                continue
    return None


def v10_results(node: Node) -> list[dict[str, Any]]:
    return [json.loads(x[7:]) for x in node.lines() if x.startswith("RESULT ")]


def v10_weights(node: Node) -> list[dict[str, Any]]:
    return [json.loads(x[8:]) for x in node.lines() if x.startswith("WEIGHTS ")]


def scrape(out: Path, label: str, ports: list[int]) -> list[Path]:
    files = []
    for port in ports:
        path = out / "scrapes" / f"{label}-{port}.prom"
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as r:
            path.write_bytes(r.read())
        files.append(path)
    return files


def migrate_status(
    tree: Path, out: Path, label: str, ports: list[int], min_share: float | None = None
) -> tuple[int, dict[str, Any]]:
    files = scrape(out, label, ports)
    cmd = [str(tree / "python" / ".venv" / "bin" / "taowire"), "migrate", "status"]
    for f in files:
        cmd += ["--metrics-file", str(f)]
    text = subprocess.run(
        [*cmd, "--format", "text"], capture_output=True, text=True, check=False
    )
    js = subprocess.run(
        [*cmd, "--format", "json"], capture_output=True, text=True, check=False
    )
    if min_share is not None:
        gated = subprocess.run(
            [*cmd, "--min-btauth-share", str(min_share)],
            capture_output=True,
            text=True,
            check=False,
        )
        code = gated.returncode
    else:
        code = js.returncode
    (out / "scrapes" / f"{label}.status.txt").write_text(
        f"$ {' '.join(cmd)}\n{text.stdout}{text.stderr}exit {text.returncode}\n"
        + (f"with --min-btauth-share {min_share}: exit {code}\n" if min_share else ""),
        encoding="utf-8",
    )
    return code, json.loads(js.stdout)


def summary(status: dict[str, Any]) -> dict[str, Any]:
    keys = ("miners_btauth", "miners_v10", "btauth_share", "inbound_v10_total")
    picked = {k: status.get(k) for k in keys}
    picked["outbound_v10_total"] = status.get("outbound_v10_total")
    picked["days_remaining"] = status.get("days_remaining")
    picked["unreachable"] = len(status.get("unreachable", []))
    return picked


# --------------------------------------------------------------------------- walk


class Walk:
    def __init__(
        self, fleet: Fleet, chain: Chain, ss58: dict[str, str], uid: dict[str, int]
    ):
        self.f = fleet
        self.chain = chain
        self.ss58 = ss58
        self.uid = uid
        self.block_time = 0.25

    # -- helpers ------------------------------------------------------------

    async def axon_is(self, hotkey: str, protocol: int, timeout_s: float = 180) -> None:
        m = MINERS[hotkey]
        want = (int(m["port"]), protocol)

        async def ok() -> dict[str, Any] | None:
            ax = await self.chain.axon(self.ss58[hotkey])
            return ax if (ax.get("port"), ax.get("protocol")) == want else None

        ax = await until(f"axon {hotkey}", ok, timeout_s)
        record(
            self.stage,
            f"{hotkey} axon on chain: port {want[0]}, protocol {protocol}",
            ax is not None,
            {"axon": ax or await self.chain.axon(self.ss58[hotkey])},
        )

    async def weights_land(self, hotkeys: list[str], timeout_s: float = 240) -> None:
        start = await self.chain.block()
        for hotkey in hotkeys:
            ss58 = self.ss58[hotkey]

            async def revealed(ss58: str = ss58) -> dict[str, Any] | None:
                return await self.chain.revealed_since(ss58, start)

            event = await until(f"reveal {hotkey}", revealed, timeout_s)
            row = await self.chain.weight_row(self.uid[hotkey])
            record(
                self.stage,
                f"weights land on chain for {hotkey} ({self.f.nodes[hotkey].name})",
                event is not None,
                {"since_block": start, "reveal": event, "weight_row": row},
            )

    async def no_reveal(self, hotkey: str, settle_s: float, window_s: float) -> None:
        # A commit made just before the key went up may still reveal: let it pass.
        await asyncio.sleep(settle_s)
        start = await self.chain.block()
        await asyncio.sleep(window_s)
        event = await self.chain.revealed_since(self.ss58[hotkey], start)
        tries = [
            w for w in v10_weights(self.f.nodes[hotkey]) if w.get("block", 0) > start
        ]
        record(
            self.stage,
            f"{hotkey} ({self.f.nodes[hotkey].name}, key 0) gets no weights on chain",
            event is None,
            {
                "settle_s": settle_s,
                "window_blocks": [start, await self.chain.block()],
                "v10_attempts": tries,
            },
        )

    async def tw_round(
        self,
        hotkey: str,
        want: dict[str, int],
        timeout_s: float = 120,
        label: str | None = None,
    ) -> None:
        node = self.f.nodes[hotkey]

        async def ok() -> dict[str, Any] | None:
            r = last_round(node)
            if r and all(r.get(k) == v for k, v in want.items()):
                return r
            return None

        r = await until(f"round {hotkey}", ok, timeout_s)
        got = r or last_round(node) or {}
        record(
            self.stage,
            f"{node.name} round: "
            + ", ".join(f"{k}={v}" for k, v in want.items())
            + (f" ({label})" if label else ""),
            r is not None,
            {
                k: got.get(k)
                for k in ("round_id", "n_queried", "n_ok", "n_btauth", "n_v10")
            },
        )

    def log_event(self, hotkey: str, event: str, needle: str, since: Node) -> None:
        """``event`` was logged by ``since`` (the running node) for ``needle``."""
        marker = f'"event": "{event}"'
        hits = [x for x in since.lines() if marker in x and needle in x]
        record(
            self.stage,
            f"{since.name} logged {event} for {needle}",
            bool(hits) and self.f.nodes.get(hotkey) is since,
            {"lines": hits[-2:]},
        )

    async def v10_round(
        self, hotkey: str, want_ok: int, timeout_s: float = 120
    ) -> None:
        node = self.f.nodes[hotkey]
        uids = [self.uid[m] for m in MINERS]

        async def ok() -> list[dict[str, Any]] | None:
            res = v10_results(node)
            last = {r["uid"]: r for r in res}
            if (
                all(u in last for u in uids)
                and sum(last[u]["ok"] > 0 for u in uids) == want_ok
            ):
                return [last[u] for u in uids]
            return None

        got = await until(f"v10 round {hotkey}", ok, timeout_s)
        record(
            self.stage,
            f"{node.name}: {want_ok} of {len(uids)} miners answer correctly",
            got is not None,
            {"last_results": got or v10_results(node)[-len(uids) :]},
        )

    async def status(
        self,
        label: str,
        ports: list[int],
        want: dict[str, Any],
        min_share: float | None = None,
        want_exit: int = 0,
    ) -> dict[str, Any]:
        async def ok() -> tuple[int, dict[str, Any]] | None:
            code, st = migrate_status(self.f.tree, self.f.out, label, ports, min_share)
            s = summary(st)
            good = code == want_exit and all(
                _matches(s.get(k), v) for k, v in want.items()
            )
            return (code, st) if good else None

        got = await until(f"status {label}", ok, 90, every_s=5)
        code, st = got or migrate_status(
            self.f.tree, self.f.out, label, ports, min_share
        )
        record(
            self.stage,
            f"migrate status ({label}): "
            + ", ".join(f"{k}={v}" for k, v in want.items())
            + (
                f"; --min-btauth-share {min_share} exit {want_exit}"
                if min_share
                else ""
            ),
            got is not None,
            {"exit": code, **summary(st), "raw": f"scrapes/{label}.status.txt"},
        )
        return st

    async def set_weights_version(self, value: int, owner: bt.Wallet) -> None:
        tries = 0

        async def done() -> bool:
            return await self.chain.weights_version() == value

        while not await done() and tries < 20:
            tries += 1
            try:
                result = await self.chain.c.execute(
                    bt.SetHyperparameter(
                        netuid=NETUID, name="weights_version", value=value
                    ),
                    owner,
                    wait_for_inclusion=True,
                    wait_for_finalization=True,
                )
                msg = getattr(result, "message", None)
            except Exception as e:  # noqa: BLE001 - recorded, retried
                msg = f"{type(e).__name__}: {e}"
            if not await done():
                note(f"weights_version={value}: attempt {tries} not applied ({msg})")
                await asyncio.sleep(1.5)
        record(
            self.stage,
            f"owner sets weights_version={value} (read back)",
            await done(),
            {
                "attempts": tries,
                "WeightsVersionKey": await self.chain.weights_version(),
            },
        )

    async def v10_dendrite_probe(self, hotkey: str, want_ok: bool) -> None:
        m = MINERS[hotkey]
        cmd = [
            str(LEGACY_PY), "-I", str(V10_PEER), "dendrite", "--ip", m["ip"],
            "--port", str(m["port"]), "--axon-hotkey", self.ss58[hotkey],
            "--wallet-name", "validator", "--wallet-path", str(self.f.wallets),
            "--count", "3", "--timeout", "5",
        ]  # fmt: skip
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, check=False
        )
        lines = [json.loads(x) for x in out.stdout.splitlines() if x.startswith("{")]
        codes = sorted({x["status_code"] for x in lines})
        ok = all(x["ok"] for x in lines) and len(lines) == 3
        record(
            self.stage,
            f"v10 Dendrite -> TaoWire miner {hotkey}: "
            + ("answered" if want_ok else "refused"),
            ok == want_ok,
            {"status_codes": codes, "summary": out.stdout.strip().splitlines()[-1:]},
        )

    # -- stages ---------------------------------------------------------------

    stage = "setup"

    async def run(self, owner: bt.Wallet, through: int = 4) -> None:
        """Every stage up to ``through`` in order; the first failing check raises."""
        await self.pre(owner)
        await self.stage1()
        if through >= 2:
            await self.stage2()
        if through >= 3:
            await self.stage3(owner)
        if through >= 4:
            await self.stage4()

    @property
    def miner_uids(self) -> list[int]:
        return [self.uid[m] for m in MINERS]

    async def pre(self, owner: bt.Wallet) -> None:
        """Before stage 1: an all-v10 subnet, both validators setting weights."""
        f = self.f
        self.stage = "pre"
        await self.set_weights_version(0, owner)
        for m in MINERS:
            f.v10_miner(m)
        for m in MINERS:
            await self.axon_is(m, V10_PROTOCOL)
        for v in VALIDATORS:
            f.v10_validator(v, self.miner_uids, self.block_time)
        for v in VALIDATORS:
            await self.v10_round(v, 2)
        await self.weights_land(list(VALIDATORS))

    async def stage1(self) -> None:
        """Validators first: ``validator`` upgrades with TW_LEGACY_V10_CLIENT=auto."""
        f = self.f
        self.stage = "1"
        f.stop("validator")
        f.tw_validator("validator", "auto", UNTIL28)
        await self.tw_round("validator", {"n_ok": 2, "n_v10": 2, "n_btauth": 0})
        await self.status(
            "stage1-validator",
            [VALIDATORS["validator"]["metrics"]],
            {
                "miners_btauth": 0,
                "miners_v10": 2,
                "outbound_v10_total": ">0",
                "days_remaining": {"inbound": None, "outbound": 28},
            },
        )
        await self.weights_land(["validator", "owner"])

        self.stage = "1-rollback"
        f.stop("validator")
        f.v10_validator("validator", self.miner_uids, self.block_time)
        await self.v10_round("validator", 2)
        await self.weights_land(["validator"])
        self.stage = "1-undo"
        f.stop("validator")
        f.tw_validator("validator", "auto", UNTIL28)
        await self.tw_round("validator", {"n_ok": 2, "n_v10": 2})
        await self.weights_land(["validator"])

    async def stage2(self) -> None:
        """Miners upgrade with TW_LEGACY_V10_UNTIL, one at a time."""
        f = self.f
        v_port = [VALIDATORS["validator"]["metrics"]]
        self.stage = "2"
        f.stop("miner_py")
        f.tw_miner("miner_py", UNTIL28)
        await self.axon_is("miner_py", TW_PROTOCOL)
        await self.tw_round("validator", {"n_ok": 2, "n_btauth": 1, "n_v10": 1})
        await self.status(
            "stage2a-validator",
            v_port,
            {"miners_btauth": 1, "miners_v10": 1, "btauth_share": 0.5},
            min_share=0.95,
            want_exit=1,
        )
        f.stop("miner_go")
        f.tw_miner("miner_go", UNTIL28)
        await self.axon_is("miner_go", TW_PROTOCOL)
        await self.tw_round("validator", {"n_ok": 2, "n_btauth": 2, "n_v10": 0})
        await self.v10_round("owner", 2)  # the v10 validator still reaches both
        await self.status(
            "stage2-validator",
            v_port,
            {"miners_btauth": 2, "miners_v10": 0, "btauth_share": 1.0},
            min_share=0.95,
        )
        await self.status(
            "stage2-miners",
            M_PORTS,
            {
                "inbound_v10_total": ">0",
                "days_remaining": {"inbound": 28, "outbound": None},
            },
        )
        await self.weights_land(["validator", "owner"])

        self.stage = "2-rollback"
        f.stop("miner_go")
        f.v10_miner("miner_go")
        await self.axon_is("miner_go", V10_PROTOCOL)
        await self.v10_round("owner", 2)
        # Spec 8.11.3 step 5 (D16): the v10 release re-published the axon without
        # the kit's tag, so the running validator forgets miner_go at its next
        # metagraph refresh and reaches it over v10 again. No restart.
        validator = f.nodes["validator"]
        await self.tw_round(
            "validator",
            {"n_ok": 2, "n_btauth": 1, "n_v10": 1},
            timeout_s=REFRESH_S + 90,
            label="D16: v10 miner reached again after the next metagraph refresh",
        )
        self.log_event(
            "validator", TAG_CHANGED, self.ss58["miner_go"][:8], since=validator
        )
        record(
            self.stage,
            "validator was not restarted (same process, still running)",
            f.nodes["validator"] is validator and validator.proc.poll() is None,
            {"pid": validator.proc.pid, "node": validator.name},
        )
        await self.weights_land(["validator", "owner"])
        self.stage = "2-undo"
        f.stop("miner_go")
        f.tw_miner("miner_go", UNTIL28)
        await self.axon_is("miner_go", TW_PROTOCOL)
        await self.tw_round("validator", {"n_ok": 2, "n_btauth": 2, "n_v10": 0})
        await self.status(
            "stage2-undo-validator", v_port, {"btauth_share": 1.0}, min_share=0.95
        )
        await self.weights_land(["validator"])

    async def inbound_over(self, label: str, wait_s: float) -> tuple[float, float]:
        """``inbound_v10_total`` on the miners, read twice ``wait_s`` apart."""
        first = await self.status(f"{label}-t0", M_PORTS, {})
        await asyncio.sleep(wait_s)
        second = await self.status(f"{label}-t1", M_PORTS, {})
        return first["inbound_v10_total"], second["inbound_v10_total"]

    async def stage3(self, owner: bt.Wallet) -> None:
        """Push stragglers: the owner raises weights_version to the stage 1 key."""
        f = self.f
        tempo_wait = max(30.0, 10 * self.block_time)
        self.stage = "3"
        await self.set_weights_version(NEW_KEY, owner)
        await self.weights_land(["validator"])
        await self.no_reveal(
            "owner", settle_s=20.0, window_s=max(40.0, 160 * self.block_time)
        )
        t0, t1 = await self.inbound_over("stage3-miners-blocked", tempo_wait)
        record(
            self.stage,
            "while the blocked v10 validator still runs, inbound v10 is not flat "
            "(exit check not met yet, as expected)",
            t1 > t0,
            {"inbound_t0": t0, "inbound_t1": t1},
        )
        f.stop("owner")  # the straggler upgrades, first with its old key (D38)
        await self.stale_key_is_stopped_at_commit("owner")
        f.stop("owner")
        f.tw_validator("owner", "auto", UNTIL28)
        await self.tw_round("owner", {"n_ok": 2, "n_btauth": 2})
        t0, t1 = await self.inbound_over("stage3-miners-upgraded", tempo_wait)
        record(
            self.stage,
            "exit: inbound v10 flat over one tempo (and >= 30 s) after the straggler "
            "upgraded",
            t1 == t0,
            {"inbound_t0": t0, "inbound_t1": t1, "tempo_blocks": 10},
        )
        await self.weights_land(["validator", "owner"])

        self.stage = "3-rollback"
        await self.set_weights_version(0, owner)
        f.stop("owner")
        f.v10_validator("owner", self.miner_uids, self.block_time)
        await self.v10_round("owner", 2)
        await self.weights_land(["owner", "validator"])
        self.stage = "3-undo"
        await self.set_weights_version(NEW_KEY, owner)
        f.stop("owner")
        f.tw_validator("owner", "auto", UNTIL28)
        await self.tw_round("owner", {"n_ok": 2, "n_btauth": 2})
        await self.weights_land(["owner", "validator"])

    async def stale_key_is_stopped_at_commit(self, hotkey: str) -> None:
        """D38: a TaoWire validator with key 0 refuses to commit, says why."""
        node = self.f.tw_validator(hotkey, "auto", UNTIL28, version_key=0)
        start = await self.chain.block()
        marker = '"event": "weights_version_key_stale"'

        async def logged() -> list[str] | None:
            return [x for x in node.lines() if marker in x] or None

        await until(f"{hotkey} stale key", logged, 240)
        self.log_event(
            hotkey, "weights_version_key_stale", f'"chain_version_key": {NEW_KEY}', node
        )
        event = await self.chain.revealed_since(self.ss58[hotkey], start)
        record(
            self.stage,
            f"{node.name} (key 0) committed nothing: no reveal since it started",
            event is None,
            {"since_block": start, "reveal": event},
        )

    def restart_all(
        self, miner_until: str | None, client: str, until: str | None
    ) -> None:
        for m in MINERS:
            self.f.stop(m)
            self.f.tw_miner(m, miner_until)
        for v in VALIDATORS:
            self.f.stop(v)
            self.f.tw_validator(v, client, until)

    async def stage4(self) -> None:
        """End the transition: no TW_LEGACY_V10_UNTIL, TW_LEGACY_V10_CLIENT=off."""
        all_ports = V_PORTS + M_PORTS
        zero = {
            "inbound_v10_total": 0,
            "outbound_v10_total": 0,
            "days_remaining": {"inbound": None, "outbound": None},
        }
        self.stage = "4"
        self.restart_all(None, "off", None)
        for v in VALIDATORS:
            await self.tw_round(v, {"n_ok": 2, "n_btauth": 2, "n_v10": 0})
        await self.status(
            "stage4-all",
            all_ports,
            {"miners_btauth": 4, "miners_v10": 0, **zero},
            min_share=0.95,
        )
        await self.v10_dendrite_probe("miner_py", want_ok=False)
        await self.weights_land(list(VALIDATORS))

        self.stage = "4-rollback"
        until14 = today_plus(14)
        self.restart_all(until14, "auto", until14)
        for v in VALIDATORS:
            await self.tw_round(v, {"n_ok": 2, "n_btauth": 2})
        await self.v10_dendrite_probe("miner_py", want_ok=True)
        await self.status(
            "stage4-rollback-all",
            all_ports,
            {
                "inbound_v10_total": ">0",
                "days_remaining": {"inbound": 14, "outbound": 14},
            },
        )
        await self.weights_land(list(VALIDATORS))
        self.stage = "4-undo"
        self.restart_all(None, "off", None)
        for v in VALIDATORS:
            await self.tw_round(v, {"n_ok": 2, "n_btauth": 2, "n_v10": 0})
        await self.status("stage4-undo-all", all_ports, zero)
        await self.weights_land(list(VALIDATORS))


def _matches(got: Any, want: Any) -> bool:
    if want == ">0":
        return isinstance(got, (int, float)) and got > 0
    if isinstance(want, dict):
        return isinstance(got, dict) and all(
            _matches(got.get(k), v) for k, v in want.items()
        )
    return bool(got == want)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, default=Path("~/.taowire/localnet"))
    parser.add_argument(
        "--through",
        type=int,
        choices=[1, 2, 3, 4],
        default=4,
        help="last stage to walk (the earlier ones set it up); default 4",
    )
    args = parser.parse_args()
    state = args.state_dir.expanduser()
    info = json.loads((state / "localnet.json").read_text(encoding="utf-8"))
    if info["endpoint"] != ENDPOINT or int(info["netuid"]) != NETUID:
        raise SystemExit(f"expected {ENDPOINT} netuid {NETUID}, got {info['endpoint']}")
    wallets = Path(info["wallet_path"])
    ss58 = {w: info["wallets"][w]["hotkey"] for w in [*MINERS, *VALIDATORS]}
    uid = {w: int(info["wallets"][w]["uid"]) for w in [*MINERS, *VALIDATORS]}
    args.out.mkdir(parents=True, exist_ok=True)
    meta = {
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "tree": str(args.tree),
        "tree_head": subprocess.run(
            ["git", "-C", str(args.tree), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip(),
        "endpoint": ENDPOINT,
        "netuid": NETUID,
        "through_stage": args.through,
        "uids": uid,
    }
    owner = bt.Wallet(name="owner", hotkey="default", path=str(wallets))
    fleet = Fleet(args.tree, args.out, wallets)
    code = 0
    async with bt.Subtensor(ENDPOINT, fallback_endpoints=[]) as client:
        chain = Chain(client)
        chain.cursor = await chain.block()
        meta["start_block"] = chain.cursor
        chain.start()
        walk = Walk(fleet, chain, ss58, uid)
        walk.block_time = float(info.get("block_time_s", 0.25))
        try:
            await walk.run(owner, args.through)
        except CheckFailedError as e:
            note(f"stopped at the first failing check: {e}")
            code = 1
        except Exception as e:  # noqa: BLE001 - recorded in the report
            REPORT.append(
                {
                    "stage": walk.stage,
                    "check": "driver error",
                    "ok": False,
                    "error": f"{type(e).__name__}: {e}",
                }
            )
            note(f"driver error: {type(e).__name__}: {e}")
            code = 2
        finally:
            await chain.stop()
            fleet.stop_all()
            meta["end_block"] = await chain.block()
            meta["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(
                timespec="seconds"
            )
            meta["result"] = "PASS" if code == 0 else "FAIL"
            (args.out / "chain-events.json").write_text(
                json.dumps(chain.events, indent=1) + "\n", encoding="utf-8"
            )
            write_report(args.out, meta)
    return code


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
