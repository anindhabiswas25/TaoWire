"""Phase 2 exit criterion (spec 17): on localnet the validator queries the miner,
scores it, sets weights, and the weights are visible on chain after the reveal.

Both processes are the text-ops example (``examples/text-ops-subnet``), started
as an operator would: ``python -m text_ops.miner`` / ``python -m text_ops.validator``
configured only by ``TW_*`` variables. The test then reads the chain like any
observer: the miner's published axon, the validator's timelocked commit, and
finally the revealed weight row (``client.weights.weights``).

Permits move on a tempo-10 localnet (spec 14.2), so the validator runs with
``TW_QUERY_VALIDATORS=1``: the miner is queried whether or not it holds a permit.

Reveals need the chain's drand feed: the test checks it before committing and
while waiting, and fails fast with ``environment: drand feed failing (...)``
when the feed is down (``drand_guard``, G3-8).
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
import pytest
from drand_guard import DrandWatch, require_drand_feed
from localnet_env import ENDPOINT, Localnet

from taowire.chain.axon import Endpoint
from taowire.chain.gateway import BittensorGateway
from taowire.validator.weights import WeightDecision, WeightScheduler

EXAMPLE = Path(__file__).resolve().parents[3] / "examples" / "text-ops-subnet"
MINER_WALLET = "miner_py"
VALIDATOR_WALLET = "validator"
EXTERNAL_IP = "127.0.0.2"
#: Floors; the waits scale with the chain's block time (``Localnet.wait_s``).
PUBLISH_TIMEOUT_S = 180.0
WEIGHTS_TIMEOUT_S = 600.0
#: Blocks a timelocked commit needs to reveal: RevealPeriodEpochs (1) + slack, x tempo.
REVEAL_BLOCKS = 3 * 10 + 10


def _free_port(host: str) -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        port: int = s.getsockname()[1]
        return port


@dataclass
class Process:
    proc: subprocess.Popen[bytes]
    log: Path
    out: Any

    def events(self) -> list[dict[str, Any]]:
        out = []
        for line in self.log.read_text(errors="replace").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                out.append(record)
        return out

    def tail(self) -> str:
        return self.log.read_text(errors="replace")[-4000:]


def _base_env(localnet: Localnet, wallet: str, state: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("TW_")}
    env.update(
        {
            "TW_NETWORK": ENDPOINT,
            "TW_NETUID": str(localnet.netuid),
            "TW_WALLET_NAME": wallet,
            "TW_WALLET_PATH": str(localnet.wallet_path),
            "TW_REFUSE_IF_COLDKEY_PRESENT": "0",  # localnet dev wallets only
            "TW_ALLOW_PRIVATE_AXONS": "1",
            "TW_STATE_DIR": str(state),
            "TW_METRICS_BIND": f"127.0.0.1:{_free_port('127.0.0.1')}",
            "TW_NTP_SERVERS": "",
            "TW_METAGRAPH_REFRESH_S": "10",
            "TW_LOG_LEVEL": "INFO",
            "PYTHONPATH": str(EXAMPLE),
        }
    )
    return env


def _start(module: str, env: dict[str, str], log: Path) -> Process:
    out = log.open("wb")
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, the repo's own example
        [sys.executable, "-m", module],
        env=env,
        cwd=EXAMPLE,
        stdout=out,
        stderr=subprocess.STDOUT,
    )
    return Process(proc, log, out)


def _stop(process: Process) -> None:
    process.proc.terminate()
    try:
        process.proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.proc.kill()
        process.proc.wait()
    process.out.close()


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    target = os.environ.get("TAOWIRE_E2E_EVIDENCE_DIR")
    path = Path(target) if target else tmp_path / "evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture
def miner(
    localnet: Localnet, tmp_path: Path, evidence_dir: Path
) -> Iterator[tuple[int, Process]]:
    port = _free_port(EXTERNAL_IP)
    env = _base_env(localnet, MINER_WALLET, tmp_path / "miner-state")
    env.update(
        {
            "TW_BIND_HOST": EXTERNAL_IP,
            "TW_BIND_PORT": str(port),
            "TW_EXTERNAL_IP": EXTERNAL_IP,
        }
    )
    process = _start("text_ops.miner", env, evidence_dir / "miner.log")
    try:
        yield port, process
    finally:
        _stop(process)


def _validator(localnet: Localnet, tmp_path: Path, evidence_dir: Path) -> Process:
    env = _base_env(localnet, VALIDATOR_WALLET, tmp_path / "validator-state")
    env.update(
        {
            "TW_ROUND_INTERVAL_S": "3",
            "TW_QUERY_VALIDATORS": "1",
            "TW_MIN_WEIGHT_INTERVAL_BLOCKS": "10",
            "TW_QUERY_TIMEOUT_S": "5",
        }
    )
    return _start("text_ops.validator", env, evidence_dir / "validator.log")


async def _until(
    what: str,
    check: Any,
    timeout_s: float,
    process: Process,
    watch: DrandWatch | None = None,
) -> Any:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        if process.proc.poll() is not None:
            raise AssertionError(
                f"process exited while waiting for {what}:\n{process.tail()}"
            )
        if watch is not None:
            await watch.check()
        value = await check()
        if value:
            return value
        await asyncio.sleep(1.0)
    raise AssertionError(f"timed out waiting for {what}; log:\n{process.tail()}")


async def _marker_row(
    localnet: Localnet,
    client: Any,
    validator_uid: int,
    marker_uid: int,
    process: Process,
) -> tuple[dict[int, float], int]:
    """Put a known row on chain (validator -> marker uid) and wait for its reveal."""
    gw = BittensorGateway(
        ENDPOINT, hotkey=localnet.hotkey(VALIDATOR_WALLET), allow_private_axons=True
    )
    await gw.connect()
    try:
        limit = await gw.weights_rate_limit(localnet.netuid)

        async def window_open() -> bool:
            since = await gw.blocks_since_last_update(localnet.netuid, validator_uid)
            return since is not None and since >= limit

        await _until(
            "the weights rate limit",
            window_open,
            localnet.wait_s(limit, 300.0),
            process,
        )
        await require_drand_feed(client)
        # Through the scheduler, as the validator does: a commit whose reveal round
        # the chain's drand feed already passed (``expired``) is re-planned (D32).
        scheduler = WeightScheduler(
            gw,
            localnet.netuid,
            localnet.wallets[VALIDATOR_WALLET]["hotkey"],
            min_interval_blocks=0,
        )
        mg = await gw.metagraph(localnet.netuid)

        async def committed() -> WeightDecision | None:
            decision = await scheduler.maybe_submit({marker_uid: 1.0}, mg)
            if decision.reason in ("replanning", "waiting"):
                return None
            return decision

        decision = await _until(
            "the marker commit", committed, localnet.wait_s(10, 60.0), process
        )
        assert decision.submitted, decision

        async def marker_revealed() -> dict[int, float] | None:
            row = (await client.weights.weights(localnet.netuid)).get(validator_uid)
            return row if row == {marker_uid: 1.0} else None

        row: dict[int, float] = await _until(
            "the marker row",
            marker_revealed,
            localnet.wait_s(REVEAL_BLOCKS, WEIGHTS_TIMEOUT_S),
            process,
            DrandWatch(client),
        )
        return row, decision.replans
    finally:
        await gw.close()


async def test_validator_scores_miner_and_weights_reveal(
    localnet: Localnet, miner: tuple[int, Process], tmp_path: Path, evidence_dir: Path
) -> None:
    port, miner_process = miner
    netuid = localnet.netuid
    miner_hotkey = localnet.wallets[MINER_WALLET]["hotkey"]
    validator_hotkey = localnet.wallets[VALIDATOR_WALLET]["hotkey"]
    want = Endpoint(EXTERNAL_IP, port, is_ipv6=False)
    gw = BittensorGateway(ENDPOINT, allow_private_axons=True)
    await gw.connect()
    client = await bt.Subtensor(ENDPOINT)
    results: dict[str, Any] = {"netuid": netuid}
    try:

        async def published() -> bool:
            neuron = (await gw.metagraph(netuid)).by_hotkey(miner_hotkey)
            return neuron is not None and neuron.axon == want

        # A publish less than ServingRateLimit blocks after the last one waits.
        publish_s = localnet.wait_s(
            await gw.serving_rate_limit(netuid), PUBLISH_TIMEOUT_S
        )
        await _until("the miner's axon on chain", published, publish_s, miner_process)

        async def ready() -> bool:
            async with httpx.AsyncClient(timeout=2.0) as http:
                try:
                    r = await http.get(want.base_url("http") + "/readyz")
                except httpx.TransportError:
                    return False
                return r.status_code == 200

        await _until("miner /readyz", ready, publish_s, miner_process)
        mg = await gw.metagraph(netuid)
        miner_uid = mg.by_hotkey(miner_hotkey).uid  # type: ignore[union-attr]
        validator_uid = mg.by_hotkey(validator_hotkey).uid  # type: ignore[union-attr]
        results.update(miner_uid=miner_uid, validator_uid=validator_uid, axon=str(want))
        marker_uid = next(
            n.uid for n in mg.neurons if n.uid not in (miner_uid, validator_uid)
        )
        results["marker_row"], results["marker_replans"] = await _marker_row(
            localnet, client, validator_uid, marker_uid, miner_process
        )
        results["start_block"] = await gw.block()

        validator = _validator(localnet, tmp_path, evidence_dir)
        try:

            async def scored() -> dict[str, Any] | None:
                for e in validator.events():
                    if e.get("event") == "round ok" and e.get("n_ok", 0) >= 1:
                        return e
                return None

            round_ok = await _until("a round with n_ok >= 1", scored, 120.0, validator)
            results["round_ok"] = round_ok

            async def submitted() -> dict[str, Any] | None:
                for e in validator.events():
                    if e.get("event") == "weights submitted" and e.get("block_hash"):
                        return e
                return None

            # The marker row just used the window: the validator waits a full one.
            limit = await gw.weights_rate_limit(netuid)
            submission = await _until(
                "weights submitted", submitted, localnet.wait_s(limit, 300.0), validator
            )
            results["weights_submitted"] = submission

            async def revealed() -> dict[int, float] | None:
                # The marker row was on chain before the validator started, so
                # the row can only hold the miner once this run's commit revealed.
                rows = await client.weights.weights(netuid)
                row = rows.get(validator_uid) or {}
                return row if row.get(miner_uid, 0.0) > 0 else None

            row = await _until(
                "weights revealed on chain",
                revealed,
                localnet.wait_s(REVEAL_BLOCKS, WEIGHTS_TIMEOUT_S),
                validator,
                DrandWatch(client),
            )
            results["revealed_row"] = {str(k): v for k, v in row.items()}
            results["revealed_at_block"] = await gw.block()
        finally:
            _stop(validator)
    finally:
        await client.close()
        await gw.close()
        (evidence_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    assert row[miner_uid] > 0
    assert marker_uid not in row
