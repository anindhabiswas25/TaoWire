#!/usr/bin/env python3
"""The TS, Go and Rust text-ops miners against the real sidecar, without a chain.

    cd python
    uv run python ../conformance/interop/miners_check.py \\
        --out ../reports/phase-5/miners-smoke [--only go]

For each example miner (spec 10, 11.1, P4): a FakeChain-backed
``taowire sidecar`` (//Bob is the miner and the sidecar's hotkey, //Alice a
validator with a permit, //Charlie registered without one), the miner with a
hotkey file of //Bob and the sidecar's token, then the Python side checks:

- 30 random tasks on ``POST /v1/transform`` through ``ValidatorClient``: ok,
  twresp/1 verified, the result equal to ``text_ops.protocol.expected``, and
  the raw body byte-identical to the Python miner's (``model_dump_json``);
- the same tasks on ``POST /v1/transform/stream``: verified streams whose
  chunks are exactly ``text_ops.protocol.pieces``;
- //Charlie gets the signed 403 ``tw.forbidden_not_validator`` (the sidecar
  policy), a bad body the signed 422, an unsigned request 401;
- the miner published its axon through the sidecar at startup.

Public dev keys only.
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

import httpx
from live_check import REPO, free_port, spawn, wait_http

from taowire.chain.axon import Endpoint
from taowire.chain.gateway import NeuronView
from taowire.extensions.response_sig import ResponseSignatureError, verify_response
from taowire.testing.keys import dev_key
from taowire.validator.client import ValidatorClient

sys.path.insert(0, str(REPO / "examples" / "text-ops-subnet"))
from text_ops.protocol import (
    ROUTE,
    STREAM_ROUTE,
    TransformPiece,
    TransformRequest,
    TransformResponse,
    expected,
    pieces,
    random_request,
)

BOB = dev_key("bob")
SEEDS = json.loads((REPO / "conformance" / "vectors" / "payload.json").read_text())[
    "keys"
]

SIDECAR_SCRIPT = """
import sys
from taowire.config import SidecarSettings
from taowire.sidecar import Sidecar
from taowire.testing.fake_chain import FakeChain
from taowire.testing.keys import dev_key
from taowire.testing.metagraph import FakeMetagraphSource

bob = dev_key("bob")
chain = FakeChain(signer_hotkey=bob.ss58)
chain.add_subnet(1)
chain.set_hyperparameters(1, serving_rate_limit=0)
chain.register(1, bob.ss58)
chain.register(1, dev_key("alice").ss58, validator_permit=True, stake_tao=1000)
chain.register(1, dev_key("charlie").ss58)
Sidecar(SidecarSettings.from_env(), port=int(sys.argv[1]), gateway=chain,
        metagraph=FakeMetagraphSource(chain, 1), hotkey=bob.keypair).run()
"""


def build(out: Path, langs: list[str]) -> dict[str, list[str]]:
    """Build the chosen miners; their command lines."""
    go_bin = Path(tempfile.mkdtemp(prefix="tw-textops-go-")) / "textops-miner"
    steps = {
        "go": (
            ["go", "build", "-o", str(go_bin), "./examples/textops-miner"],
            REPO / "go",
        ),
        "rust": (
            [
                *("cargo", "build", "-j", "2", "--example", "textops_miner"),
                *("--features", "axum,client,sidecar,redis"),
            ],
            REPO / "rust",
        ),
        "typescript": (["npm", "run", "build:examples"], REPO / "typescript"),
    }
    env = {**os.environ, "GOTOOLCHAIN": "local"}
    with (out / "build.txt").open("w", encoding="utf-8") as log:
        for lang in langs:
            cmd, cwd = steps[lang]
            subprocess.run(  # noqa: S603 - fixed argv
                cmd, cwd=cwd, env=env, check=True, stdout=log, stderr=subprocess.STDOUT
            )
    commands = {
        "go": [str(go_bin)],
        "rust": [
            str(REPO / "rust" / "target" / "debug" / "examples" / "textops_miner")
        ],
        "typescript": [
            "node",
            str(REPO / "typescript" / "build" / "examples" / "textops-miner.js"),
        ],
    }
    return {lang: commands[lang] for lang in langs}


def neuron(port: int) -> NeuronView:
    return NeuronView(
        uid=0,
        hotkey=BOB.ss58,
        coldkey=BOB.ss58,
        validator_permit=False,
        active=True,
        total_stake_tao=0.0,
        alpha_stake=0.0,
        tao_stake=0.0,
        axon=Endpoint("127.0.0.3", port, is_ipv6=False),
        last_update=0,
        incentive=0.0,
        dividends=0.0,
    )


def signed_post(
    url: str, path: str, body: bytes, who: str
) -> tuple[httpx.Response, int, str]:
    key = dev_key(who)
    headers = key.signer().sign(
        method="POST", target=path, body=body, receiver_ss58=BOB.ss58
    )
    headers["Content-Type"] = "application/json"
    r = httpx.post(url + path, content=body, headers=headers, timeout=10)
    return r, int(headers["X-Bittensor-Nonce"]), key.ss58


def signed_ok(r: httpx.Response, nonce: int, sender: str) -> bool:
    try:
        verify_response(
            list(r.headers.multi_items()),
            expected_responder=BOB.ss58,
            request_nonce=nonce,
            sender_ss58=sender,
            status=r.status_code,
            body=r.content,
        )
    except ResponseSignatureError:
        return False
    return True


async def tasks(port: int, n: int) -> dict[str, Any]:
    rng = random.Random(port)  # noqa: S311 - test tasks, not secrets
    reqs = [random_request(rng) for _ in range(n)]
    plain = stream = 0
    problems: list[str] = []
    async with ValidatorClient(
        dev_key("alice").signer(), timeout_s=10, max_attempts=1
    ) as vc:
        for req in reqs:
            body = req.model_dump_json().encode()
            r = await vc.query(
                neuron(port), ROUTE, body, response_model=TransformResponse
            )
            if (
                r.ok
                and r.response_verified
                and r.data == TransformResponse(result=expected(req))
            ):
                plain += 1
            else:
                problems.append(f"transform {req.op}: {r.error_code} {r.data!r}"[:200])
            s = await vc.query_stream(
                neuron(port), STREAM_ROUTE, body, chunk_model=TransformPiece
            )
            if s.ok and s.response_verified and list(s.data or ()) == pieces(req):
                stream += 1
            else:
                problems.append(f"stream {req.op}: {s.error_code}"[:200])
    return {
        "transform_ok": plain,
        "stream_ok": stream,
        "tasks": n,
        "problems": problems[:5],
    }


def check(lang: str, url: str, port: int) -> dict[str, Any]:
    out: dict[str, Any] = {"miner": lang, **asyncio.run(tasks(port, 30))}
    req = TransformRequest(text="Hello World 42", op="reverse")
    body = req.model_dump_json().encode()
    r, nonce, sender = signed_post(url, ROUTE, body, "alice")
    want = TransformResponse(result=expected(req)).model_dump_json().encode()
    out["byte_identical"] = r.status_code == 200 and r.content == want
    out["signed_200"] = signed_ok(r, nonce, sender)
    r, nonce, sender = signed_post(url, ROUTE, body, "charlie")
    out["charlie"] = (
        r.status_code,
        r.json().get("error", {}).get("code"),
        signed_ok(r, nonce, sender),
    )
    bad = json.dumps({"text": "", "op": "upper"}).encode()
    r, nonce, sender = signed_post(url, ROUTE, bad, "alice")
    out["bad_body"] = (
        r.status_code,
        r.json().get("error", {}).get("code"),
        signed_ok(r, nonce, sender),
    )
    r = httpx.post(url + ROUTE, content=body, timeout=10)
    out["unsigned"] = (r.status_code, r.json().get("error", {}).get("code"))
    return out


def passed(c: dict[str, Any]) -> bool:
    return (
        c["transform_ok"] == c["stream_ok"] == c["tasks"]
        and c["byte_identical"]
        and c["signed_200"]
        and c["charlie"] == (403, "tw.forbidden_not_validator", True)
        and c["bad_body"] == (422, "tw.invalid_request", True)
        and c["unsigned"] == (401, "tw.auth_malformed")
        and c["axon_published"]
    )


def run_one(lang: str, program: list[str], out: Path) -> dict[str, Any]:
    tmp = Path(tempfile.mkdtemp(prefix=f"tw-miners-{lang}-"))
    (tmp / "sidecar.py").write_text(SIDECAR_SCRIPT, encoding="utf-8")
    hotkeys = tmp / "wallets" / "miner" / "hotkeys"
    hotkeys.mkdir(parents=True)
    hotkey = hotkeys / "default"
    hotkey.write_text(
        json.dumps(
            {
                "secretSeed": "0x" + SEEDS["bob_sr25519"]["secret_seed_hex"],
                "ss58Address": BOB.ss58,
            }
        )
    )
    hotkey.chmod(0o600)
    token = tmp / "state" / "sidecar.token"
    sc_port, port = free_port("127.0.0.1"), free_port("127.0.0.3")
    base = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp),
        "TW_NETUID": "1",
        "TW_WALLET_NAME": "miner",
    }
    sidecar_env = {
        **base,
        "TW_WALLET_PATH": str(tmp / "empty"),
        "TW_STATE_DIR": str(tmp / "state"),
        "TW_SIDECAR_TOKEN_FILE": str(token),
        "TW_ALLOW_PRIVATE_AXONS": "1",
        "TW_METRICS_BIND": f"127.0.0.1:{free_port('127.0.0.1')}",
        "TW_NTP_SERVERS": "",
    }
    sc_log = out / f"{lang}-sidecar.log"
    procs = [
        spawn(
            [sys.executable, "sidecar.py", str(sc_port)],
            sc_log,
            cwd=tmp,
            env=sidecar_env,
        )
    ]
    try:
        deadline = time.monotonic() + 60
        while not token.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        time.sleep(0.5)
        miner_env = {
            **base,
            "TW_WALLET_PATH": str(tmp / "wallets"),
            "TW_BIND_HOST": "127.0.0.3",
            "TW_BIND_PORT": str(port),
            "TW_EXTERNAL_IP": "127.0.0.3",
            "TW_SIDECAR_PORT": str(sc_port),
            "TW_SIDECAR_TOKEN_FILE": str(token),
            **dict.fromkeys(
                (
                    "TW_RATE_HOTKEY_PER_S",
                    "TW_RATE_HOTKEY_BURST",
                    "TW_RATE_IP_PER_S",
                    "TW_RATE_IP_BURST",
                ),
                "1000",
            ),
        }
        log = out / f"{lang}-miner.log"
        procs.append(spawn(program, log, env=miner_env))
        url = f"http://127.0.0.3:{port}"
        wait_http(f"{url}/healthz", procs[-1], log)
        result = check(lang, url, port)
        result["axon_published"] = (
            sc_log.read_text(encoding="utf-8").count("sidecar_axon_published") == 1
        )
    finally:
        for p in reversed(procs):
            p.terminate()
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                p.kill()
    result["pass"] = passed(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--only", choices=["go", "rust", "typescript"])
    args = parser.parse_args()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    programs = build(out, [args.only] if args.only else ["go", "rust", "typescript"])
    cells = []
    for lang, program in programs.items():
        cells.append(run_one(lang, program, out))
        print(cells[-1], flush=True)
    (out / "results.json").write_text(
        json.dumps(cells, indent=1) + "\n", encoding="utf-8"
    )
    head = ["miner", "pass", "transform", "stream", "byte-identical"]
    head += ["charlie", "bad body", "unsigned", "axon"]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for c in cells:
        row = [c["miner"], c["pass"], f"{c['transform_ok']}/{c['tasks']}"]
        row += [f"{c['stream_ok']}/{c['tasks']}", c["byte_identical"], c["charlie"]]
        row += [c["bad_body"], c["unsigned"], c["axon_published"]]
        lines.append("| " + " | ".join(str(x) for x in row) + " |")
    (out / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    ok = all(c["pass"] for c in cells)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
