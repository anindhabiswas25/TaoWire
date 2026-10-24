"""Phase 4 exit criterion (spec 17): streaming on localnet with compat.

A compat ``StreamingSynapse`` miner process (the archived template's
``StreamPrompting``, ``stream_miner_app.py``) and a compat streaming validator
process (``stream_validator_app.py``) on the localnet subnet: the validator's
streams verify (signed ``tw-end``), it scores from the final item only, and
its weights are committed **and revealed** in the same run.

To be sure the revealed row comes from this run, the validator's row is first
moved to a marker UID (committed and revealed, as in the reveal e2e test),
then the streaming validator must reveal ``{miner_uid: 1.0}`` over it.
Commit-reveal stays on; the drand feed is checked first and while waiting.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import bittensor as bt
import httpx
import pytest
from drand_guard import DrandWatch, require_drand_feed
from localnet_env import ENDPOINT, Localnet
from test_validator_e2e_localnet import (
    EXTERNAL_IP,
    MINER_WALLET,
    PUBLISH_TIMEOUT_S,
    REVEAL_BLOCKS,
    VALIDATOR_WALLET,
    WEIGHTS_TIMEOUT_S,
    Process,
    _base_env,
    _free_port,
    _marker_row,
    _stop,
    _until,
)

from taowire.chain.axon import Endpoint
from taowire.chain.gateway import BittensorGateway

HERE = Path(__file__).resolve().parent


def _start_script(script: str, env: dict[str, str], log: Path, *args: str) -> Process:
    out = log.open("wb")
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, this test's own scripts
        [sys.executable, str(HERE / script), *args],
        env={**env, "PYTHONPATH": str(HERE)},
        cwd=HERE,
        stdout=out,
        stderr=subprocess.STDOUT,
    )
    return Process(proc, log, out)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    target = os.environ.get("TAOWIRE_E2E_EVIDENCE_DIR")
    path = Path(target) if target else tmp_path / "evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.mark.localnet
async def test_compat_streaming_miner_and_validator_with_revealed_weights(
    localnet: Localnet, tmp_path: Path, evidence_dir: Path
) -> None:
    netuid = localnet.netuid
    miner_hotkey = localnet.wallets[MINER_WALLET]["hotkey"]
    validator_hotkey = localnet.wallets[VALIDATOR_WALLET]["hotkey"]
    port = _free_port(EXTERNAL_IP)
    want = Endpoint(EXTERNAL_IP, port, is_ipv6=False)
    miner_env = _base_env(localnet, MINER_WALLET, tmp_path / "miner-state")
    miner_env.update(
        {
            "TW_BIND_HOST": EXTERNAL_IP,
            "TW_BIND_PORT": str(port),
            "TW_EXTERNAL_IP": EXTERNAL_IP,
        }
    )
    miner = _start_script("stream_miner_app.py", miner_env, evidence_dir / "miner.log")
    gw = BittensorGateway(ENDPOINT, allow_private_axons=True)
    await gw.connect()
    client = await bt.Subtensor(ENDPOINT)
    results: dict[str, Any] = {"netuid": netuid}
    validator: Process | None = None
    try:

        async def published() -> bool:
            neuron = (await gw.metagraph(netuid)).by_hotkey(miner_hotkey)
            if neuron is None or neuron.axon != want:
                return False
            async with httpx.AsyncClient(timeout=2) as http:
                try:
                    r = await http.get(want.base_url("http") + "/readyz")
                except httpx.TransportError:
                    return False
            return r.status_code == 200

        await _until(
            "the streaming miner",
            published,
            localnet.wait_s(40, PUBLISH_TIMEOUT_S),
            miner,
        )
        mg = await gw.metagraph(netuid)
        miner_uid = mg.by_hotkey(miner_hotkey).uid  # type: ignore[union-attr]
        validator_uid = mg.by_hotkey(validator_hotkey).uid  # type: ignore[union-attr]
        marker_uid = next(
            n.uid for n in mg.neurons if n.uid not in (miner_uid, validator_uid)
        )
        results.update(miner_uid=miner_uid, validator_uid=validator_uid)
        results["marker_row"], results["marker_replans"] = await _marker_row(
            localnet, client, validator_uid, marker_uid, miner
        )
        validator_env = _base_env(
            localnet, VALIDATOR_WALLET, tmp_path / "validator-state"
        )
        validator_env.update(
            {"TW_MIN_WEIGHT_INTERVAL_BLOCKS": "10", "TW_QUERY_TIMEOUT_S": "10"}
        )
        await require_drand_feed(client)
        validator = _start_script(
            "stream_validator_app.py",
            validator_env,
            evidence_dir / "validator.log",
            miner_hotkey,
        )

        def lines(event: str) -> list[dict[str, Any]]:
            assert validator is not None
            return [e for e in validator.events() if e.get("event") == event]

        async def streamed_and_committed() -> bool:
            rounds = lines("stream_round")
            submitted = [w for w in lines("weights") if w["reason"] == "submitted"]
            return any(r["ok"] for r in rounds) and bool(submitted)

        await _until(
            "a verified stream and a committed weight",
            streamed_and_committed,
            localnet.wait_s(60, 180.0),
            validator,
        )

        async def revealed() -> dict[int, float] | None:
            row = (await client.weights.weights(netuid)).get(validator_uid)
            return row if row == {miner_uid: 1.0} else None

        row: dict[int, float] = await _until(
            "the streaming validator's revealed row",
            revealed,
            localnet.wait_s(REVEAL_BLOCKS, WEIGHTS_TIMEOUT_S),
            validator,
            DrandWatch(client),
        )
        rounds = lines("stream_round")
        results.update(
            revealed_row={str(k): v for k, v in row.items()},
            revealed_at_block=await gw.block(),
            stream_rounds=len(rounds),
            stream_rounds_ok=sum(r["ok"] for r in rounds),
            first_round=rounds[0],
            weights=lines("weights"),
        )
        assert all(r["ok"] for r in rounds), rounds
        assert rounds[0]["chunks"] > 1  # it really streamed in pieces
    finally:
        if validator is not None:
            _stop(validator)
        _stop(miner)
        await gw.close()
        await client.close()
        (evidence_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
