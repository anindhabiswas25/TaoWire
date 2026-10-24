#!/usr/bin/env python3
"""Live interop without a chain (Phase 5): Go, Rust and TypeScript against Python.

    cd python
    uv run python ../conformance/interop/live_check.py --out ../reports/phase-5/interop

Six directions, ``--count`` requests each (default 200), every one with a
fresh signature:

1. Go signer (sr25519 and ed25519) -> the Python miner.
2. Rust signer (sr25519 and ed25519) -> the Python miner.
3. TypeScript signer (sr25519 and ed25519) -> the Python miner.
4. Python signer -> the Go middleware.
5. Python signer -> the Rust middleware.
6. Python signer -> the TypeScript Fastify adapter.

A cell passes when every answer is 200 and its ``twresp/1`` signature
verifies (checked by the Go/Rust/TypeScript client, or here with
``tensorwire.extensions.response_sig``). The Python miner is the real kit
(``tensorwire.Miner`` under uvicorn) on 127.0.0.2 with a FakeChain inside the
process; Go, Rust and TypeScript serve on 127.0.0.3. Public dev keys only:
//Bob is every miner, //Alice the caller. The localnet matrix of spec 13.5 is
``run_matrix.py`` (later in Phase 5).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Literal

import httpx

from tensorwire.extensions.response_sig import ResponseSignatureError, verify_response
from tensorwire.testing.keys import dev_key

REPO = Path(__file__).resolve().parents[2]
VECTOR_KEYS = json.loads(
    (REPO / "conformance" / "vectors" / "payload.json").read_text(encoding="utf-8")
)["keys"]
SEEDS = {name: k["secret_seed_hex"] for name, k in VECTOR_KEYS.items()}
BOB = VECTOR_KEYS["bob_sr25519"]["ss58"]

MINER_SCRIPT = """
from pydantic import BaseModel
from tensorwire import Miner, RouteContext
from tensorwire.config import MinerSettings
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource

bob = dev_key("bob")
chain = FakeChain(signer_hotkey=bob.ss58)
chain.add_subnet(1)
chain.register(1, bob.ss58)
for scheme in ("sr25519", "ed25519"):
    alice = dev_key("alice", scheme)
    chain.register(1, alice.ss58, validator_permit=True, stake_tao=1000)

class Req(BaseModel):
    text: str

class Resp(BaseModel):
    result: str

miner = Miner(MinerSettings.from_env(), gateway=chain,
              metagraph=FakeMetagraphSource(chain, 1), hotkey=bob.keypair)

@miner.route("/v1/upper", request=Req, response=Resp)
async def upper(req: Req, ctx: RouteContext) -> Resp:
    return Resp(result=req.text.upper())

miner.run()
"""


def free_port(host: str) -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def wait_http(url: str, proc: subprocess.Popen[bytes], log: Path) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"{url}: process exited early, see {log}")
        try:
            if httpx.get(url, timeout=0.5).status_code == 200:
                return
        except httpx.TransportError:
            time.sleep(0.2)
    raise SystemExit(f"{url} not ready, see {log}")


def spawn(cmd: list[str], log: Path, **kw: Any) -> subprocess.Popen[bytes]:
    fh = log.open("wb")
    return subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, **kw)  # noqa: S603


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit(f"{name} is not on PATH")
    return path


def build(out: Path) -> dict[str, list[str]]:
    """Build the Go, Rust and TypeScript interop programs (build log in ``out``).

    Returns each language's command prefix.
    """
    go_bin = Path(tempfile.mkdtemp(prefix="tw-interop-go-")) / "btauth-interop"
    go = [_tool("go"), "build", "-o", str(go_bin), "./cmd/btauth-interop"]
    cargo = [_tool("cargo"), "build", "-j", "2", "--example", "interop"]
    cargo += ["--features", "axum,client,sidecar"]
    npm = [_tool("npm"), "run", "build:examples"]
    env = {**os.environ, "GOTOOLCHAIN": "local"}
    with (out / "build.txt").open("w", encoding="utf-8") as log:
        steps = [(go, REPO / "go"), (cargo, REPO / "rust")]
        if not (REPO / "typescript" / "node_modules").is_dir():
            steps.append(([_tool("npm"), "ci", "--no-fund"], REPO / "typescript"))
        steps.append((npm, REPO / "typescript"))
        for cmd, cwd in steps:
            subprocess.run(  # noqa: S603 - fixed argv
                cmd, cwd=cwd, env=env, check=True, stdout=log, stderr=subprocess.STDOUT
            )
    ts_entry = REPO / "typescript" / "build" / "examples" / "interop.js"
    return {
        "go": [str(go_bin)],
        "rust": [str(REPO / "rust" / "target" / "debug" / "examples" / "interop")],
        "typescript": [_tool("node"), str(ts_entry)],
    }


def serve_args(lang: str, addr: str, seed: str) -> list[str]:
    if lang in {"go", "typescript"}:
        return ["serve", "--addr", addr, "--seed", seed]
    return ["serve", addr, seed]


def sign_args(lang: str, url: str, seed: str, scheme: str, count: int) -> list[str]:
    if lang in {"go", "typescript"}:
        flags = ["--url", url, "--seed", seed, "--receiver", BOB, "--scheme", scheme]
        return ["sign", *flags, "--count", str(count)]
    return ["sign", url, seed, BOB, scheme, str(count)]


def python_signer(
    url: str, count: int, scheme: Literal["sr25519", "ed25519"]
) -> dict[str, Any]:
    """The Python signer against a Go/Rust miner, verifying every answer."""
    alice = dev_key("alice", scheme)
    signer = alice.signer()
    target = httpx.URL(url).raw_path.decode()
    statuses: dict[int, int] = {}
    errors: dict[str, int] = {}
    ok = 0
    body = b'{"text":"hello"}'
    with httpx.Client(timeout=10) as client:
        for _ in range(count):
            headers = signer.sign(
                method="POST", target=target, body=body, receiver_ss58=BOB
            )
            r = client.post(url, content=body, headers=headers)
            statuses[r.status_code] = statuses.get(r.status_code, 0) + 1
            try:
                verify_response(
                    list(r.headers.multi_items()),
                    expected_responder=BOB,
                    request_nonce=int(headers["X-Bittensor-Nonce"]),
                    sender_ss58=alice.ss58,
                    status=r.status_code,
                    body=r.content,
                )
            except ResponseSignatureError as exc:
                errors[exc.code] = errors.get(exc.code, 0) + 1
                continue
            ok += r.status_code == 200 and r.json() == {"result": "HELLO"}
    return {
        "language": "python",
        "signer": alice.ss58,
        "scheme": scheme,
        "count": count,
        "ok": ok,
        "statuses": statuses,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--count", type=int, default=200)
    args = parser.parse_args()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    programs = build(out)
    procs: list[subprocess.Popen[bytes]] = []
    cells: list[dict[str, Any]] = []
    try:
        tmp = Path(tempfile.mkdtemp(prefix="tw-interop-"))
        (tmp / "miner.py").write_text(MINER_SCRIPT, encoding="utf-8")
        py_port = free_port("127.0.0.2")
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(tmp),
            "TW_NETUID": "1",
            "TW_WALLET_NAME": "miner",
            "TW_WALLET_PATH": str(tmp / "empty"),
            "TW_EXTERNAL_IP": "127.0.0.2",
            "TW_ALLOW_PRIVATE_AXONS": "1",
            "TW_BIND_HOST": "127.0.0.2",
            "TW_BIND_PORT": str(py_port),
            "TW_METRICS_BIND": f"127.0.0.1:{free_port('127.0.0.1')}",
            "TW_NTP_SERVERS": "",
            "TW_DRAIN_S": "1",
            # 200 back-to-back requests from one caller: above the default
            # per-hotkey bucket (20/s, burst 40), which is not what is tested.
            **dict.fromkeys(("TW_RATE_HOTKEY_PER_S", "TW_RATE_HOTKEY_BURST"), "1000"),
            **dict.fromkeys(("TW_RATE_IP_PER_S", "TW_RATE_IP_BURST"), "1000"),
        }
        procs.append(
            spawn(
                [sys.executable, "miner.py"], out / "python-miner.log", cwd=tmp, env=env
            )
        )
        py_url = f"http://127.0.0.2:{py_port}"
        wait_http(f"{py_url}/readyz", procs[-1], out / "python-miner.log")
        servers = {}
        for lang, program in programs.items():
            port = free_port("127.0.0.3")
            cmd = [
                *program,
                *serve_args(lang, f"127.0.0.3:{port}", SEEDS["bob_sr25519"]),
            ]
            procs.append(spawn(cmd, out / f"{lang}-miner.log"))
            servers[lang] = f"http://127.0.0.3:{port}"
            wait_http(f"{servers[lang]}/healthz", procs[-1], out / f"{lang}-miner.log")

        for lang, program in programs.items():
            for scheme in ("sr25519", "ed25519"):
                seed = SEEDS[f"alice_{scheme}"]
                url = f"{py_url}/v1/upper"
                cmd = [*program, *sign_args(lang, url, seed, scheme, args.count)]
                run = subprocess.run(  # noqa: S603 - fixed argv
                    cmd, capture_output=True, text=True, timeout=600, check=False
                )
                summary = json.loads(run.stdout.strip().splitlines()[-1])
                cell = f"{lang} signer ({scheme}) -> python miner"
                cells.append({"cell": cell, "exit": run.returncode, **summary})
        for lang, base in servers.items():
            for py_scheme in ("sr25519", "ed25519"):
                summary = python_signer(f"{base}/v1/upper", args.count, py_scheme)
                cells.append(
                    {"cell": f"python signer ({py_scheme}) -> {lang} miner", **summary}
                )
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                p.kill()
    expected_cells = 4 * len(programs)
    passed = all(c["ok"] == c["count"] == args.count for c in cells)
    passed = passed and len(cells) == expected_cells
    lines = ["| cell | ok / count | statuses | errors |", "|---|---|---|---|"]
    lines += [
        f"| {c['cell']} | {c['ok']}/{c['count']} | {c['statuses']} | {c['errors']} |"
        for c in cells
    ]
    (out / "results.json").write_text(
        json.dumps(cells, indent=1) + "\n", encoding="utf-8"
    )
    (out / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print("PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
