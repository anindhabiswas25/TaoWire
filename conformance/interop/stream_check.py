#!/usr/bin/env python3
"""Stream interop without a chain (Phase 5, spec 9.2, 11.1, 13.4 test 11 shape).

    cd python
    uv run python ../conformance/interop/stream_check.py \
        --out ../reports/phase-5/stream-interop

Cells: the Go, Rust and TypeScript stream clients against the Python
streaming miner, and the Python client (``ValidatorClient.query_stream``)
against the Go, Rust and TypeScript streaming miners, plus Python against
Python as the baseline. Every miner is reached through a tampering relay (a
small HTTP proxy in this process) that applies one case per run:

- ``none``: the stream as sent; it must verify with the five expected chunks;
- ``tamper_chunk``, ``reorder``, ``drop_chunk``, ``extra_chunk``,
  ``tamper_trailer`` (digest), ``tamper_signature``, ``duplicate_trailer``,
  ``event_after_trailer``, ``missing_trailer``: each must be refused as
  ``tw.bad_response_signature`` for the whole stream.

The Python miner is the real kit (``stream=True`` route) with a FakeChain;
the other miners are the interop programs' ``/v1/stream`` route. //Bob is
every miner, //Alice every client. Public dev keys only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
from live_check import (
    BOB,
    MINER_SCRIPT,
    SEEDS,
    build,
    free_port,
    serve_args,
    spawn,
    wait_http,
)

from tensorwire.chain.axon import Endpoint
from tensorwire.chain.gateway import NeuronView
from tensorwire.testing.keys import dev_key
from tensorwire.validator.client import ValidatorClient

STREAM_MINER = (
    MINER_SCRIPT.replace("miner.run()", "")
    + """
@miner.route("/v1/stream", request=Req, stream=True)
async def stream(req: Req, ctx: RouteContext):
    for i in range(5):
        yield {"i": i, "text": req.text.upper()}

miner.run()
"""
)

BODY = b'{"text":"hello"}'
EXPECTED = [{"i": i, "text": "HELLO"} for i in range(5)]
REFUSED = "tw.bad_response_signature"

Frames = list[bytes]


def _chunks(f: Frames) -> list[int]:
    return [i for i, x in enumerate(f) if x.startswith(b"event: chunk")]


def _end(f: Frames) -> int:
    return next(i for i, x in enumerate(f) if x.startswith(b"event: tw-end"))


def _flip_hex(frame: bytes, key: bytes) -> bytes:
    at = frame.index(key) + len(key)
    if frame[at : at + 2] == b"0x":
        at += 2
    new = b"1" if frame[at : at + 1] != b"1" else b"2"
    return frame[:at] + new + frame[at + 1 :]


def _swap(f: Frames, a: int, b: int) -> Frames:
    f[a], f[b] = f[b], f[a]
    return f


EDITS: dict[str, Callable[[Frames], Frames]] = {
    "none": lambda f: f,
    "tamper_chunk": lambda f: [
        x.replace(b"HELLO", b"HELLP") if i == _chunks(f)[1] else x
        for i, x in enumerate(f)
    ],
    "reorder": lambda f: _swap(f, _chunks(f)[0], _chunks(f)[1]),
    "drop_chunk": lambda f: [x for i, x in enumerate(f) if i != _chunks(f)[1]],
    "extra_chunk": lambda f: [*f[: _end(f)], f[_chunks(f)[0]], *f[_end(f) :]],
    "tamper_trailer": lambda f: [
        _flip_hex(x, b'"digest":"') if i == _end(f) else x for i, x in enumerate(f)
    ],
    "tamper_signature": lambda f: [
        _flip_hex(x, b'"signature":"') if i == _end(f) else x for i, x in enumerate(f)
    ],
    "duplicate_trailer": lambda f: [*f, f[_end(f)]],
    "event_after_trailer": lambda f: [*f, b"event: chunk\ndata: {}"],
    "missing_trailer": lambda f: [*f[: _end(f)], *f[_end(f) + 1 :]],
}

_FORWARD = ("x-bittensor-", "content-type", "accept")
_DROP = {"content-length", "transfer-encoding", "connection", "date", "server"}


class Relay(ThreadingHTTPServer):
    """An HTTP proxy to one miner that rewrites the SSE body per ``case``."""

    daemon_threads = True

    def __init__(self, upstream: str) -> None:
        super().__init__(("127.0.0.1", 0), _RelayHandler)
        self.upstream = upstream
        self.case = "none"

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class _RelayHandler(BaseHTTPRequestHandler):
    server: Relay

    def log_message(self, *_args: Any) -> None:
        """Quiet: the harness writes its own evidence."""

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        headers = {
            k: v for k, v in self.headers.items() if k.lower().startswith(_FORWARD)
        }
        headers["accept-encoding"] = "identity"
        r = httpx.post(
            self.server.upstream + self.path, content=body, headers=headers, timeout=30
        )
        data = r.content
        if r.headers.get("content-type", "").startswith("text/event-stream"):
            frames = [f for f in data.split(b"\n\n") if f]
            frames = EDITS[self.server.case](frames)
            data = b"".join(f + b"\n\n" for f in frames)
        self.send_response(r.status_code)
        for k, v in r.headers.multi_items():
            if k.lower() not in _DROP:
                self.send_header(k, v)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start_relay(upstream: str) -> Relay:
    relay = Relay(upstream)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    return relay


def stream_args(lang: str, url: str) -> list[str]:
    seed = SEEDS["alice_sr25519"]
    if lang in {"go", "typescript"}:
        flags = ["--url", url, "--seed", seed, "--receiver", BOB]
        return ["stream", *flags, "--count", "1"]
    return ["stream", url, seed, BOB, "sr25519", "1"]


def run_lang_client(program: list[str], lang: str, url: str) -> tuple[str, Any]:
    run = subprocess.run(  # noqa: S603 - fixed argv
        [*program, *stream_args(lang, url)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    lines = run.stdout.strip().splitlines()
    if not lines:
        return f"no output (exit {run.returncode}): {run.stderr[-300:]}", None
    summary = json.loads(lines[-1])
    if summary["ok"] == 1:
        return "ok", summary["chunks"]
    return next(iter(summary["errors"]), "unknown"), None


def run_python_client(relay: Relay) -> tuple[str, Any]:
    port = relay.server_address[1]
    neuron = NeuronView(
        uid=1,
        hotkey=BOB,
        coldkey=BOB,
        validator_permit=False,
        active=True,
        total_stake_tao=0.0,
        alpha_stake=0.0,
        tao_stake=0.0,
        axon=Endpoint("127.0.0.1", int(port), is_ipv6=False),
        last_update=0,
        incentive=0.0,
        dividends=0.0,
    )

    async def query() -> tuple[str, Any]:
        vc = ValidatorClient(dev_key("alice").signer(), max_attempts=1)
        try:
            result = await vc.query_stream(neuron, "/v1/stream", BODY)
        finally:
            await vc.aclose()
        if result.ok and result.response_verified:
            return "ok", list(result.data or ())
        return str(result.error_code), None

    return asyncio.run(query())


def main() -> int:  # noqa: PLR0915 - one linear script
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    programs = build(out)
    procs: list[subprocess.Popen[bytes]] = []
    cells: list[dict[str, Any]] = []
    try:
        tmp = Path(tempfile.mkdtemp(prefix="tw-stream-interop-"))
        (tmp / "miner.py").write_text(STREAM_MINER, encoding="utf-8")
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
        }
        procs.append(
            spawn(
                [sys.executable, "miner.py"], out / "python-miner.log", cwd=tmp, env=env
            )
        )
        miners = {"python": f"http://127.0.0.2:{py_port}"}
        wait_http(f"{miners['python']}/readyz", procs[-1], out / "python-miner.log")
        for lang, program in programs.items():
            port = free_port("127.0.0.3")
            addr = f"127.0.0.3:{port}"
            cmd = [*program, *serve_args(lang, addr, SEEDS["bob_sr25519"])]
            procs.append(spawn(cmd, out / f"{lang}-miner.log"))
            miners[lang] = f"http://127.0.0.3:{port}"
            wait_http(f"{miners[lang]}/healthz", procs[-1], out / f"{lang}-miner.log")
        relays = {lang: start_relay(url) for lang, url in miners.items()}

        pairs: list[tuple[str, str]] = [("python", "python")]
        pairs += [(lang, "python") for lang in programs]
        pairs += [("python", lang) for lang in programs]
        for client, miner in pairs:
            relay = relays[miner]
            results: dict[str, str] = {}
            for case in EDITS:
                relay.case = case
                if client == "python":
                    got, chunks = run_python_client(relay)
                else:
                    url = f"{relay.url}/v1/stream"
                    got, chunks = run_lang_client(programs[client], client, url)
                if case == "none" and got == "ok" and chunks != EXPECTED:
                    got = f"wrong chunks: {chunks}"
                results[case] = got
            passed = all(
                got == ("ok" if case == "none" else REFUSED)
                for case, got in results.items()
            )
            cells.append(
                {"cell": f"{client} client -> {miner} miner", "pass": passed, **results}
            )
            print(cells[-1], flush=True)
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                p.kill()
    passed = all(c["pass"] for c in cells) and len(cells) == 1 + 2 * len(programs)
    head = ["cell", "pass", *EDITS]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join(str(c[h]) for h in head) + " |" for c in cells]
    (out / "results.json").write_text(
        json.dumps(cells, indent=1) + "\n", encoding="utf-8"
    )
    (out / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print("PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
