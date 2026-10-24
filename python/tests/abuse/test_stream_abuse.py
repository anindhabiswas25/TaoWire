"""Stream abuse tests (spec 13.6, D29) against real processes.

1. A hostile miner process sends a slow-drip stream (one byte at a time,
   each byte inside the idle limit, no event ever complete) and an endless
   stream: the real ``ValidatorClient`` cuts both at its limits, over TCP.
2. A permitted validator opens many streams on a real kit miner and never
   reads them: past ``MAX_STREAMS_PER_CALLER`` per worker they are refused
   (429), the ones accepted are cut at ``TW_STREAM_MAX_S``, and the miner
   keeps serving ``alice`` (plain and streaming queries) all along.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from abuse_tools import free_port, legit_validator, start_miner, write_evidence

from tensorwire.auth.signer import RequestSigner
from tensorwire.chain.axon import Endpoint
from tensorwire.chain.gateway import NeuronView
from tensorwire.extensions.streaming import StreamLimits
from tensorwire.miner.streaming import MAX_STREAMS_PER_CALLER
from tensorwire.testing import bench as tb
from tensorwire.testing.keys import dev_key
from tensorwire.validator.client import ValidatorClient

pytestmark = pytest.mark.abuse

HERE = Path(__file__).resolve().parent
REDIS = os.environ.get("TENSORWIRE_TEST_REDIS_URL")


def neuron(port: int) -> NeuronView:
    bob = dev_key("bob").ss58
    return NeuronView(
        uid=1,
        hotkey=bob,
        coldkey=bob,
        validator_permit=False,
        active=True,
        total_stake_tao=0.0,
        alpha_stake=0.0,
        tao_stake=0.0,
        axon=Endpoint("127.0.0.1", port, is_ipv6=False),
        last_update=0,
        incentive=0.0,
        dividends=0.0,
    )


def start_hostile(tmp: Path) -> tuple[subprocess.Popen[bytes], int]:
    port = free_port()
    argv = [sys.executable, "-m", "uvicorn", "hostile_stream_miner:app"]
    with (tmp / "hostile.log").open("wb") as log:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, this test's own server
            [*argv, "--port", str(port)],
            cwd=HERE,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return proc, port
        time.sleep(0.1)
    proc.kill()
    raise AssertionError("hostile server did not start")


async def test_slow_drip_and_endless_streams_are_cut_by_the_validator(
    tmp_path: Path,
) -> None:
    proc, port = start_hostile(tmp_path)
    limits = StreamLimits(max_s=3, idle_s=1, max_bytes=64 * 1024 * 1024)
    results = {}
    try:
        async with ValidatorClient(
            dev_key("alice").signer(), timeout_s=30, stream_limits=limits
        ) as vc:
            for route in ("/drip", "/endless"):
                started = time.monotonic()
                r = await vc.query_stream(neuron(port), route, b"{}")
                results[route] = (r.error_code, time.monotonic() - started)
    finally:
        proc.kill()
        proc.wait()
    write_evidence(
        "stream_drip_endless",
        {k: {"code": c, "seconds": round(s, 2)} for k, (c, s) in results.items()},
    )
    drip_code, drip_s = results["/drip"]
    assert drip_code == "tw.timeout"
    assert drip_s < 2.5  # idle_s = 1: cut long before max_s, although bytes kept coming
    endless_code, endless_s = results["/endless"]
    assert endless_code == "tw.timeout"
    assert 2.9 < endless_s < 5  # max_s = 3


def _open_unread(port: int, count: int, body: bytes) -> list[socket.socket]:
    """``count`` signed stream requests from validator #1, never read."""
    signer = RequestSigner(tb.bench_validator(1))
    sockets = []
    for _ in range(count):
        headers = signer.sign(
            method="POST",
            target=tb.BENCH_STREAM_ROUTE,
            body=body,
            receiver_ss58=dev_key("bob").ss58,
        )
        lines = [
            f"POST {tb.BENCH_STREAM_ROUTE} HTTP/1.1",
            "Host: miner",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            *(f"{k}: {v}" for k, v in headers.items()),
        ]
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.bind(("127.0.0.4", 0))
        s.connect(("127.0.0.1", port))
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
        sockets.append(s)
    return sockets


def _statuses(sockets: list[socket.socket]) -> dict[str, int]:
    """What each attacker connection got (read now, then closed).

    The status, and for a 503 also its ``tw.*`` code (``"503
    tw.replay_store_unavailable"``): D42 allows only that 503.
    """
    counts: dict[str, int] = {}
    for s in sockets:
        s.settimeout(2)
        try:
            head = s.recv(4096)
        except OSError:
            head = b""
        finally:
            s.close()
        status = head[9:12].decode() if head.startswith(b"HTTP/1.1 ") else "none"
        if status == "503":
            body = head.split(b"\r\n\r\n", 1)[-1]
            try:
                status += " " + json.loads(body)["error"]["code"]
            except (ValueError, KeyError, TypeError):
                status += " ?"
        counts[status] = counts.get(status, 0) + 1
    return counts


def _aborts(metrics_port: int) -> dict[str, float]:
    text = httpx.get(f"http://127.0.0.1:{metrics_port}/metrics", timeout=5).text
    out: dict[str, float] = {}
    for line in text.splitlines():
        if line.startswith("tw_stream_aborted_total{"):
            labels, value = line.rsplit(" ", 1)
            out[labels.split('reason="', 1)[1].split('"', 1)[0]] = float(value)
    return out


async def test_unread_streams_do_not_stall_the_miner(tmp_path: Path) -> None:
    metrics_port = free_port()
    fleet = {"workers": "2", "redis_url": REDIS} if REDIS else {"workers": "1"}
    miner = start_miner(
        tmp_path, stream_max_s="5", metrics_bind=f"127.0.0.1:{metrics_port}", **fleet
    )
    body = json.dumps({"chunks": 3000, "size": 1000}).encode()  # ~3 MB each
    streams = 40
    workers = int(fleet["workers"])
    try:
        sockets = _open_unread(miner.port, streams, body)
        await asyncio.sleep(1.0)  # the miner is now blocked on 30 full sockets
        cpu0 = miner.cpu_seconds()
        legit_task = asyncio.create_task(
            legit_validator(miner.port, rate=20, duration_s=3)
        )
        async with ValidatorClient(dev_key("alice").signer(), timeout_s=10) as vc:
            small = json.dumps({"chunks": 20, "size": 10}).encode()
            streamed = await vc.query_stream(
                neuron(miner.port), tb.BENCH_STREAM_ROUTE, small
            )
        legit = await legit_task
        cpu = miner.cpu_seconds() - cpu0
        await asyncio.sleep(3.0)  # past TW_STREAM_MAX_S = 5 for the unread ones
        aborts = _aborts(metrics_port)
        statuses = _statuses(sockets)
    finally:
        log = miner.stop()
    write_evidence(
        "unread_streams",
        {
            "unread_streams": streams,
            "attacker_statuses": statuses,
            "legit": dict(legit.statuses),
            "legit_p99_ms": round(legit.p99_ms(), 1),
            "alice_stream_ok": streamed.ok,
            "miner_cpu_s_during": round(cpu, 2),
            "miner_aborts": aborts,
            "workers": fleet["workers"],
        },
    )
    assert streamed.ok, (streamed, log[-2000:])
    assert streamed.response_verified
    assert dict(legit.statuses) == {"200": legit.total}, legit.statuses
    assert legit.total >= 50
    assert legit.p99_ms() < 200, legit.p99_ms()
    # Pass rule of 13.6 (D42): the attacker's requests may be 200, 429 or 503
    # tw.replay_store_unavailable (the shared limiter failing closed on its
    # 250 ms Redis timeout under load), nothing else.
    allowed = {"200", "429", "503 tw.replay_store_unavailable"}
    assert set(statuses) <= allowed, statuses
    assert sum(statuses.values()) == streams, statuses
    accepted = statuses.get("200", 0)
    refused_early = statuses.get("503 tw.replay_store_unavailable", 0)
    # D36: never more open streams than the slots; a 503 was refused before it
    # reached them, so it does not count against the slots either way.
    assert accepted <= MAX_STREAMS_PER_CALLER * workers, statuses
    assert accepted + refused_early >= MAX_STREAMS_PER_CALLER, statuses
    assert aborts.get("max_duration", 0) == accepted, aborts
