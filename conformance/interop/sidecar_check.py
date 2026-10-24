#!/usr/bin/env python3
"""The sidecar clients against the real sidecar, without a chain (spec 11.6, S1).

    cd python
    uv run python ../conformance/interop/sidecar_check.py \\
        --out ../reports/phase-5/sidecar-interop

Starts ``taowire.sidecar.Sidecar`` (uvicorn on 127.0.0.1, the token file
generated on disk, a FakeChain inside the process: //Bob is the miner and the
sidecar's hotkey, //Alice a validator with a permit, //Charlie registered
without one, //Dave not registered) and runs the ``sidecar`` mode of the Go,
Rust and TypeScript interop programs against it. Each program starts its
client (health, netuid and hotkey check, first snapshot), runs the local
policy and ``/v1/caller`` for the four hotkeys, publishes an axon and calls
once with a wrong token. A cell passes when every answer is the expected one
and the sidecar published one axon per client. Public dev keys only.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from live_check import build, free_port, spawn

from taowire.testing.keys import dev_key

ALICE, BOB, CHARLIE, DAVE = (
    dev_key(n).ss58 for n in ("alice", "bob", "charlie", "dave")
)
PROBES = [ALICE, CHARLIE, DAVE]

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
chain.register(1, bob.ss58)
chain.register(1, dev_key("alice").ss58, validator_permit=True, stake_tao=1000)
chain.register(1, dev_key("charlie").ss58)
# every client publishes once in a row: no serving rate limit on this fake subnet
chain.set_hyperparameters(1, serving_rate_limit=0)
settings = SidecarSettings.from_env()
Sidecar(settings, port=int(sys.argv[1]), gateway=chain,
        metagraph=FakeMetagraphSource(chain, 1), hotkey=bob.keypair).run()
"""

EXPECTED = {
    "start": "ok",
    "neurons": 3,
    "check": {
        ALICE: "ok",
        CHARLIE: "tw.forbidden_not_validator",
        DAVE: "tw.forbidden_not_registered",
    },
    "caller": {
        ALICE: "allowed",
        CHARLIE: "tw.forbidden_not_validator",
        DAVE: "tw.forbidden_not_registered",
    },
    "serve_axon": "ok",
    "block_hash_ok": True,
    "wrong_token": "tw.sidecar_unauthorized",
}


def sidecar_args(lang: str, url: str, token: Path) -> list[str]:
    probes = ",".join(PROBES)
    if lang in {"go", "typescript"}:
        flags = ["--url", url, "--token-file", str(token), "--netuid", "1"]
        return ["sidecar", *flags, "--receiver", BOB, "--probes", probes]
    return ["sidecar", url, str(token), "1", BOB, probes]


def judge(summary: dict[str, Any]) -> list[str]:
    """The differences from the expected answers (empty: pass)."""
    problems = [
        f"{k}: {summary.get(k)!r} != {v!r}"
        for k, v in EXPECTED.items()
        if summary.get(k) != v
    ]
    health = summary.get("health", {})
    if health.get("hotkey") != BOB or health.get("ok") is not True:
        problems.append(f"health: {health!r}")
    if str(summary.get("stage", "")).lower() != "fresh":
        problems.append(f"stage: {summary.get('stage')!r}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    programs = build(out)
    tmp = Path(tempfile.mkdtemp(prefix="tw-sidecar-interop-"))
    (tmp / "sidecar.py").write_text(SIDECAR_SCRIPT, encoding="utf-8")
    token = tmp / "state" / "sidecar.token"
    port = free_port("127.0.0.1")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp),
        "TW_NETUID": "1",
        "TW_WALLET_NAME": "miner",
        "TW_WALLET_PATH": str(tmp / "empty"),
        "TW_STATE_DIR": str(tmp / "state"),
        "TW_SIDECAR_TOKEN_FILE": str(token),
        "TW_ALLOW_PRIVATE_AXONS": "1",
        "TW_METRICS_BIND": f"127.0.0.1:{free_port('127.0.0.1')}",
        "TW_NTP_SERVERS": "",
    }
    log = out / "sidecar.log"
    proc = spawn([sys.executable, "sidecar.py", str(port)], log, cwd=tmp, env=env)
    cells: list[dict[str, Any]] = []
    try:
        url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 60
        while not token.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        wait_http_authorized(url, token, proc, log)
        if token.stat().st_mode & 0o777 != 0o600:
            raise SystemExit(f"token file mode {token.stat().st_mode & 0o777:o}")
        for lang, program in programs.items():
            run = subprocess.run(  # noqa: S603 - fixed argv
                [*program, *sidecar_args(lang, url, token)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            lines = run.stdout.strip().splitlines()
            summary = json.loads(lines[-1]) if lines else {"error": run.stderr[-500:]}
            problems = judge(summary)
            cells.append(
                {
                    "cell": f"{lang} client -> python sidecar",
                    "pass": not problems,
                    "problems": problems,
                    **summary,
                }
            )
            print(cells[-1], flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    published = log.read_text(encoding="utf-8").count("sidecar_axon_published")
    passed = all(c["pass"] for c in cells) and len(cells) == len(programs)
    passed = passed and published == len(programs)
    lines = ["| cell | pass | problems |", "|---|---|---|"]
    lines += [f"| {c['cell']} | {c['pass']} | {c['problems']} |" for c in cells]
    lines.append(f"\nAxons published through the sidecar (FakeChain): {published}")
    (out / "results.json").write_text(
        json.dumps({"cells": cells, "published": published}, indent=1) + "\n",
        encoding="utf-8",
    )
    (out / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print("PASS" if passed else "FAIL")
    return 0 if passed else 1


def wait_http_authorized(
    url: str, token: Path, proc: subprocess.Popen[bytes], log: Path
) -> None:
    """Wait for the sidecar's /v1/health (with the token)."""
    import httpx  # noqa: PLC0415 - only needed here

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"sidecar exited early, see {log}")
        try:
            headers = {"Authorization": f"Bearer {token.read_text().strip()}"}
            if (
                httpx.get(f"{url}/v1/health", headers=headers, timeout=0.5).status_code
                == 200
            ):
                return
        except (httpx.TransportError, OSError):
            pass
        time.sleep(0.2)
    raise SystemExit(f"sidecar not ready, see {log}")


if __name__ == "__main__":
    raise SystemExit(main())
