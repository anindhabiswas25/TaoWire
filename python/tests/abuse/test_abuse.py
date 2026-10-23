"""Abuse tests against a real miner process (spec 13.6, 16.1 rows 1 and 8).

Every test runs an attack on loopback while ``alice`` (a permitted
validator, another source address) keeps querying, and asserts she is
still served. With ``TENSORWIRE_TEST_REDIS_URL`` set the miner runs two
workers on Redis (shared replay store and limits); otherwise one worker.

Set ``TENSORWIRE_ABUSE_REPORT=<file>`` to record the measured numbers.
"""

from __future__ import annotations

import asyncio
import contextlib
import multiprocessing
import os
import socket
import time
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
import pytest
from abuse_tools import (
    BODY,
    ROUTE,
    flood_process,
    forged_headers,
    legit_validator,
    raw_request,
    start_miner,
    write_evidence,
)

from tensorwire.testing.keys import dev_key

pytestmark = pytest.mark.abuse

REDIS = os.environ.get("TENSORWIRE_TEST_REDIS_URL")


def fleet() -> dict[str, str]:
    return {"workers": "2", "redis_url": REDIS} if REDIS else {"workers": "1"}


def run_flood(
    port: int, payloads: list[bytes], *, rate: float, processes: int, seconds: float
) -> list[Any]:
    """Start attacker processes; returns them with their result queue."""
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    procs = [
        ctx.Process(
            target=flood_process,
            args=(queue, port, payloads, rate / processes, 8, seconds),
        )
        for _ in range(processes)
    ]
    for p in procs:
        p.start()
    return [queue, procs]


def collect(queue: Any, procs: list[Any]) -> Counter[str]:
    total: Counter[str] = Counter()
    for _ in procs:
        total.update(queue.get(timeout=120))
    for p in procs:
        p.join(timeout=30)
    return total


def assert_served(legit: Any, minimum: int) -> None:
    assert dict(legit.statuses) == {"200": legit.total}, legit.statuses
    assert legit.total >= minimum
    assert legit.p99_ms() < 200, legit.p99_ms()


# ------------------------------------------------------------ 1. invalid signatures


async def test_invalid_signature_flood(tmp_path: Path) -> None:
    """10,000 req/s with bad signatures from one IP.

    The IP limiter answers them, the miner stays under 2 cores, and alice is
    served with p99 < 200 ms.
    """
    miner = start_miner(tmp_path, **fleet())
    base_nonce = time.time_ns()
    payloads = [raw_request(forged_headers(base_nonce + i)) for i in range(500)]
    try:
        queue, procs = run_flood(
            miner.port, payloads, rate=10_000, processes=4, seconds=10
        )
        await asyncio.sleep(2.5)  # attackers are up and sending
        cpu0, t0 = miner.cpu_seconds(), time.monotonic()
        legit = await legit_validator(miner.port, rate=10, duration_s=6)
        cores = (miner.cpu_seconds() - cpu0) / (time.monotonic() - t0)
        rss = miner.rss_mib()
        flood = collect(queue, procs)
    finally:
        miner.stop()
    answered = sum(v for k, v in flood.items() if k.isdigit())
    offered = flood["sent"] / 10
    write_evidence(
        "invalid_signature_flood",
        {
            "offered_rps": round(offered),
            "answered_rps": round(answered / 10),
            "statuses": {k: v for k, v in flood.items() if k.isdigit()},
            "miner_cores": round(cores, 2),
            "miner_rss_mib": round(rss, 1),
            "legit": dict(legit.statuses),
            "legit_p99_ms": round(legit.p99_ms(), 1),
            "workers": fleet()["workers"],
        },
    )
    assert offered >= 9_000, offered  # the attack really was ~10k/s
    assert flood["429"] / answered >= 0.95, flood  # the IP limiter took it
    assert cores < 2.0, cores
    assert_served(legit, minimum=50)


# ------------------------------------------------------------------ 2. slowloris


async def _slow_client(port: int, mode: str) -> float:
    """Seconds until the miner closes a slow connection (inf if it never does)."""
    started = time.monotonic()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    head = f"POST {ROUTE} HTTP/1.1\r\nHost: miner\r\nContent-Length: 1000\r\n"
    drip = {
        "headers": (b"", ("X-Slow: " + "a" * 200).encode()),
        "body": ((head + "\r\n").encode(), b"x" * 999),
        "idle": (b"", b""),
    }[mode]
    first, rest = drip
    try:
        if mode == "headers":
            writer.write(head.encode())
        elif first:
            writer.write(first)
        for byte in rest:
            writer.write(bytes([byte]))
            await writer.drain()
            await asyncio.sleep(0.5)
            if reader.at_eof():
                break
        if not rest:
            await asyncio.wait_for(reader.read(), timeout=30)
        else:
            await asyncio.wait_for(reader.read(), timeout=1)
    except (ConnectionError, OSError):
        pass
    except TimeoutError:
        return float("inf")
    finally:
        writer.close()
    return time.monotonic() - started


async def test_slowloris_connections_are_closed(tmp_path: Path) -> None:
    """Slow headers, slow bodies and silent connections are closed once a
    request has taken longer to arrive than it could stay fresh (2.5 s here)."""
    miner = start_miner(
        tmp_path, auth_max_age_s="2", auth_allowed_skew_s="0.5", **fleet()
    )
    try:
        attack = asyncio.gather(
            *(
                _slow_client(miner.port, mode)
                for mode in ["headers"] * 120 + ["body"] * 60 + ["idle"] * 60
            )
        )
        await asyncio.sleep(0.3)
        legit = await legit_validator(miner.port, rate=10, duration_s=4)
        closed_after = await attack
    finally:
        miner.stop()
    worst = max(closed_after)
    write_evidence(
        "slowloris",
        {
            "connections": len(closed_after),
            "closed_after_max_s": round(worst, 2),
            "legit": dict(legit.statuses),
            "legit_p99_ms": round(legit.p99_ms(), 1),
        },
    )
    assert worst < 2.5 + 1.5, sorted(closed_after)[-5:]
    assert_served(legit, minimum=30)


# ------------------------------------------------------------------ 3. 100 MB bodies


def _send_huge(port: int, *, chunked: bool) -> tuple[bytes, int]:
    """Send a 100 MB body; returns (answer, bytes the socket accepted)."""
    total = 100 * 1024 * 1024
    head = f"POST {ROUTE} HTTP/1.1\r\nHost: miner\r\n" + (
        "Transfer-Encoding: chunked\r\n\r\n"
        if chunked
        else f"Content-Length: {total}\r\n\r\n"
    )
    piece = b"x" * 65536
    frame = (b"10000\r\n" + piece + b"\r\n") if chunked else piece
    sent = 0
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(head.encode())
        try:
            while sent < total:
                s.sendall(frame)
                sent += len(piece)
        except OSError:
            pass  # the miner answered and closed: exactly what we want
        s.settimeout(5)
        answer = b""
        try:
            while chunk := s.recv(65536):
                answer += chunk
        except OSError:
            pass
    return answer, sent


async def test_100_mb_body_is_refused_without_buffering(tmp_path: Path) -> None:
    miner = start_miner(tmp_path, **fleet())
    try:
        before = miner.rss_mib()
        declared = await asyncio.to_thread(_send_huge, miner.port, chunked=False)
        streamed = await asyncio.to_thread(_send_huge, miner.port, chunked=True)
        after = miner.rss_mib()
        legit = await legit_validator(miner.port, rate=10, duration_s=2)
    finally:
        miner.stop()
    write_evidence(
        "body_100mb",
        {
            "declared_sent_mib": round(declared[1] / 2**20, 1),
            "chunked_sent_mib": round(streamed[1] / 2**20, 1),
            "rss_growth_mib": round(after - before, 1),
            "legit": dict(legit.statuses),
        },
    )
    assert declared[0].startswith(b"HTTP/1.1 413"), declared[0][:80]
    assert streamed[0].startswith(b"HTTP/1.1 413"), streamed[0][:80]
    assert b"tw.payload_too_large" in streamed[0]
    assert streamed[1] < 100 * 2**20  # the miner stopped reading long before
    assert after - before < 32, (before, after)  # never held the body
    assert_served(legit, minimum=15)


# ------------------------------------------------------------------ 4. header floods


def _raw(port: int, data: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        with contextlib.suppress(OSError):
            s.sendall(data)
        answer = b""
        try:
            while chunk := s.recv(65536):
                answer += chunk
        except OSError:
            pass
        return answer


async def test_header_floods(tmp_path: Path) -> None:
    """Oversized headers get 400 before any work; many large-header requests
    are rate limited; alice is served throughout."""
    miner = start_miner(tmp_path, **fleet())
    try:
        one_huge = raw_request({"X-Pad": "a" * 64 * 1024})
        many = raw_request({f"X-H{i}": "v" * 10 for i in range(2000)})
        answers = [
            await asyncio.to_thread(_raw, miner.port, r) for r in (one_huge, many)
        ]
        before = miner.rss_mib()
        near_limit = raw_request(
            {**forged_headers(time.time_ns()), "X-Pad": "a" * 15_000}
        )
        queue, procs = run_flood(
            miner.port, [near_limit], rate=2_000, processes=2, seconds=5
        )
        await asyncio.sleep(1.5)
        legit = await legit_validator(miner.port, rate=10, duration_s=3)
        flood = collect(queue, procs)
        after = miner.rss_mib()
    finally:
        miner.stop()
    write_evidence(
        "header_flood",
        {
            "oversized_answers": [a[:12].decode() for a in answers],
            "flood_statuses": {k: v for k, v in flood.items() if k.isdigit()},
            "rss_growth_mib": round(after - before, 1),
            "legit": dict(legit.statuses),
            "legit_p99_ms": round(legit.p99_ms(), 1),
        },
    )
    for answer in answers:
        assert answer.startswith(b"HTTP/1.1 400"), answer[:80]
    assert flood["200"] == 0
    assert flood["429"] > flood["401"]
    assert after - before < 64
    assert_served(legit, minimum=25)


# ------------------------------------------------------------------ 5. replay storm


async def test_replay_storm(tmp_path: Path) -> None:
    """One captured valid request replayed thousands of times (across workers
    when Redis is used): never served twice, and alice herself, whose request
    it was, keeps being served."""
    miner = start_miner(tmp_path, **fleet())
    signer = dev_key("alice").signer()
    headers = signer.sign(
        method="POST", target=ROUTE, body=BODY, receiver_ss58=dev_key("bob").ss58
    )
    headers["Content-Type"] = "application/json"
    url = f"http://127.0.0.1:{miner.port}{ROUTE}"
    try:
        async with httpx.AsyncClient() as http:
            first = await http.post(url, content=BODY, headers=headers)
            again = [
                await http.post(url, content=BODY, headers=headers) for _ in range(5)
            ]
        captured = raw_request(headers)
        queue, procs = run_flood(
            miner.port, [captured], rate=3_000, processes=2, seconds=4
        )
        await asyncio.sleep(1.5)
        legit = await legit_validator(miner.port, rate=10, duration_s=3)
        storm = collect(queue, procs)
    finally:
        miner.stop()
    write_evidence(
        "replay_storm",
        {
            "replays_sent": storm["sent"],
            "statuses": {k: v for k, v in storm.items() if k.isdigit()},
            "legit": dict(legit.statuses),
            "workers": fleet()["workers"],
        },
    )
    assert first.status_code == 200
    for r in again:
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "tw.auth_replayed"
    assert storm["200"] == 0  # never served a second time, on any worker
    assert storm["sent"] >= 6_000
    assert_served(legit, minimum=25)
