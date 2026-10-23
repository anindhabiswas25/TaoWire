"""Phase 4 exit criterion (spec 17): sealed challenge and sealed response on localnet.

A kit miner process (``sealed_miner_app.py``) on the localnet subnet; the
validator side runs here with the real chain gateway and the real drand
beacon: it seals a challenge (reveal 6 s), queries the miner over btauth/1,
the miner opens the challenge at the reveal and answers sealed (reveal 3 s),
and the validator opens the signed sealed answer and scores it.

Uses the public drand API twice (one open on each side); marked ``drand`` as
well as ``localnet`` so it can be left out when drand is rate-limiting.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from localnet_env import ENDPOINT, Localnet
from sealed_miner_app import Answer, Question
from test_validator_e2e_localnet import (
    EXTERNAL_IP,
    MINER_WALLET,
    PUBLISH_TIMEOUT_S,
    VALIDATOR_WALLET,
    Process,
    _base_env,
    _free_port,
    _stop,
    _until,
)

from tensorwire.auth.signer import RequestSigner
from tensorwire.chain.axon import Endpoint
from tensorwire.chain.gateway import BittensorGateway
from tensorwire.extensions.timelock import SealedResponse, Timelock
from tensorwire.observability.metrics import Metrics
from tensorwire.validator.client import ValidatorClient

HERE = Path(__file__).resolve().parent


def _start(env: dict[str, str], log: Path) -> Process:
    out = log.open("wb")
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, this test's own script
        [sys.executable, str(HERE / "sealed_miner_app.py")],
        env=env,
        cwd=HERE,
        stdout=out,
        stderr=subprocess.STDOUT,
    )
    return Process(proc, log, out)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    target = os.environ.get("TENSORWIRE_E2E_EVIDENCE_DIR")
    path = Path(target) if target else tmp_path / "evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.mark.localnet
@pytest.mark.drand
async def test_sealed_challenge_and_sealed_response_on_localnet(
    localnet: Localnet, tmp_path: Path, evidence_dir: Path
) -> None:
    netuid = localnet.netuid
    miner_hotkey = localnet.wallets[MINER_WALLET]["hotkey"]
    port = _free_port(EXTERNAL_IP)
    want = Endpoint(EXTERNAL_IP, port, is_ipv6=False)
    env = _base_env(localnet, MINER_WALLET, tmp_path / "miner-state")
    env.update(
        {
            "TW_BIND_HOST": EXTERNAL_IP,
            "TW_BIND_PORT": str(port),
            "TW_EXTERNAL_IP": EXTERNAL_IP,
            "PYTHONPATH": str(HERE),
        }
    )
    miner = _start(env, evidence_dir / "miner.log")
    gw = BittensorGateway(ENDPOINT, allow_private_axons=True)
    await gw.connect()
    results: dict[str, Any] = {"netuid": netuid}
    try:

        async def ready() -> bool:
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
            "the sealed miner", ready, localnet.wait_s(40, PUBLISH_TIMEOUT_S), miner
        )
        neuron = (await gw.metagraph(netuid)).by_hotkey(miner_hotkey)
        assert neuron is not None
        metrics = Metrics()
        timelock = Timelock(gw, retries=2, timeout_s=60, metrics=metrics)
        challenge = await timelock.seal_challenge(Question(a=19, b=23), reveal_in=6)
        signer = RequestSigner(localnet.hotkey(VALIDATOR_WALLET))
        async with ValidatorClient(signer, timeout_s=60, max_attempts=1) as client:
            answered = await client.query(
                neuron,
                "/v1/sealed",
                challenge.model_dump_json().encode(),
                response_model=SealedResponse,
            )
        results["query"] = {
            "ok": answered.ok,
            "error_code": answered.error_code,
            "verified": answered.response_verified,
            "latency_ms": answered.latency_ms,
            "reveal_round": getattr(answered.data, "reveal_round", None),
        }
        assert answered.ok, answered
        assert answered.response_verified
        opened = await timelock.open_results({neuron.uid: answered}, Answer)
        result = opened[neuron.uid]
        results["opened"] = {
            "ok": result.ok,
            "error_code": result.error_code,
            "data": result.data.model_dump() if result.data is not None else None,
        }
        assert result.ok, result
        assert result.data == Answer(total=42)
        assert (
            metrics.registry.get_sample_value(
                "tw_timelock_open_total", {"result": "ok"}
            )
            == 1
        )
    finally:
        _stop(miner)
        await gw.close()
        (evidence_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
