"""Attackers and a legitimate validator for the abuse tests (spec 13.6).

Attackers speak raw HTTP/1.1 over asyncio streams (cheap enough to offer
10,000 requests/s from Python); the legitimate validator signs real
btauth/1 requests from another source address.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from tensorwire.testing import bench as tb
from tensorwire.testing.keys import dev_key

ROUTE = tb.BENCH_ROUTE
BODY = tb.bench_body(256)
_STATUS = re.compile(rb"HTTP/1\.1 (\d{3}) ")


# ------------------------------------------------------------------ the miner


@dataclass
class MinerProcess:
    proc: subprocess.Popen[bytes]
    port: int
    log: Path

    def pids(self) -> list[int]:
        """The supervisor and its workers."""
        children = Path(f"/proc/{self.proc.pid}/task/{self.proc.pid}/children")
        kids = (
            [int(p) for p in children.read_text().split()] if children.exists() else []
        )
        return [self.proc.pid, *kids]

    def cpu_seconds(self) -> float:
        """User + system CPU time of the supervisor and its workers."""
        tick = os.sysconf("SC_CLK_TCK")
        total = 0.0
        for pid in self.pids():
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            except OSError:
                continue
            total += (int(fields[11]) + int(fields[12])) / tick
        return total

    def rss_mib(self) -> float:
        """Resident memory of the supervisor and its workers, MiB."""
        total = 0
        for pid in self.pids():
            try:
                for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
            except OSError:
                continue
        return total / 1024

    def stop(self) -> str:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return self.log.read_text(errors="replace")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def start_miner(tmp: Path, **settings: str) -> MinerProcess:
    """The bench miner (``bob``) with the kit's default limits, plus ``settings``."""
    port = free_port()
    env = {
        k: v for k, v in os.environ.items() if not k.startswith(("TW_", "PROMETHEUS"))
    }
    env.update(
        {
            "TW_NETUID": str(tb.BENCH_NETUID),
            "TW_WALLET_NAME": "bench",
            "TW_WALLET_PATH": str(tmp),
            "TW_EXTERNAL_IP": "127.0.0.2",
            "TW_ALLOW_PRIVATE_AXONS": "1",
            "TW_BIND_HOST": "127.0.0.1",
            "TW_BIND_PORT": str(port),
            "TW_METRICS_BIND": f"127.0.0.1:{free_port()}",
            "TW_NTP_SERVERS": "",
            "TW_LOG_LEVEL": "WARNING",
        }
    )
    env.update({f"TW_{k.upper()}": v for k, v in settings.items()})
    log = tmp / f"miner-{port}.log"
    with log.open("wb") as out:
        proc = subprocess.Popen(
            [sys.executable, "-m", "tensorwire.testing.bench"],
            env=env,
            stdout=out,
            stderr=subprocess.STDOUT,
        )
    miner = MinerProcess(proc, port, log)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"miner exited: {log.read_text()}")
        try:
            if (
                httpx.get(f"http://127.0.0.1:{port}/readyz", timeout=1).status_code
                == 200
            ):
                return miner
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    miner.stop()
    raise AssertionError("miner did not become ready")


# ------------------------------------------------------------------ legitimate traffic


@dataclass
class LegitStats:
    statuses: Counter[str] = field(default_factory=Counter)
    latencies: list[float] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.statuses.values())

    def p99_ms(self) -> float:
        return tb.percentile(self.latencies, 0.99) * 1000


async def legit_validator(
    port: int, *, rate: float, duration_s: float, source: str = "127.0.0.3"
) -> LegitStats:
    """``alice`` querying the miner at ``rate`` per second from ``source``."""
    signer = dev_key("alice").signer()
    stats = LegitStats()
    url = f"http://127.0.0.1:{port}{ROUTE}"
    transport = httpx.AsyncHTTPTransport(retries=0, local_address=source)
    async with httpx.AsyncClient(transport=transport, timeout=10) as http:
        ends = time.monotonic() + duration_s
        while time.monotonic() < ends:
            tick = time.monotonic()
            headers = signer.sign(
                method="POST",
                target=ROUTE,
                body=BODY,
                receiver_ss58=dev_key("bob").ss58,
            )
            headers["Content-Type"] = "application/json"
            started = time.perf_counter()
            try:
                r = await http.post(url, content=BODY, headers=headers)
                stats.statuses[str(r.status_code)] += 1
                if r.status_code == 200:
                    stats.latencies.append(time.perf_counter() - started)
            except httpx.HTTPError as exc:
                stats.statuses[type(exc).__name__] += 1
            await asyncio.sleep(max(0.0, 1 / rate - (time.monotonic() - tick)))
    return stats


# ------------------------------------------------------------------ attackers


def raw_request(headers: dict[str, str], body: bytes = BODY) -> bytes:
    """One HTTP/1.1 request to the bench route, byte for byte."""
    lines = [f"POST {ROUTE} HTTP/1.1", "Host: miner", f"Content-Length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def forged_headers(nonce: int) -> dict[str, str]:
    """btauth/1 headers with a well-formed but wrong signature."""
    return {
        "Content-Type": "application/json",
        "X-Bittensor-Hotkey": dev_key("alice").ss58,
        "X-Bittensor-Receiver": dev_key("bob").ss58,
        "X-Bittensor-Nonce": str(nonce),
        "X-Bittensor-Signature": "0x" + "ab" * 64,
    }


async def _flood_connection(
    port: int, payloads: list[bytes], rate: float, ends: float, counts: Counter[str]
) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    async def read() -> None:
        tail = b""
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            data = tail + chunk
            for status in _STATUS.findall(data):
                counts[status.decode()] += 1
            tail = data[-32:]

    reading = asyncio.get_running_loop().create_task(read())
    i = 0
    batch = max(1, int(rate / 50))  # send in 20 ms slices
    try:
        while time.monotonic() < ends:
            tick = time.monotonic()
            writer.write(
                b"".join(payloads[(i + k) % len(payloads)] for k in range(batch))
            )
            counts["sent"] += batch
            i += batch
            await writer.drain()
            await asyncio.sleep(max(0.0, batch / rate - (time.monotonic() - tick)))
        await asyncio.sleep(1.0)  # collect the last answers
    except (ConnectionError, OSError):
        counts["connection_errors"] += 1
    finally:
        reading.cancel()
        writer.close()


def flood_process(
    queue: Any,
    port: int,
    payloads: list[bytes],
    rate: float,
    connections: int,
    duration_s: float,
) -> None:
    """One attacker process: ``rate`` requests/s over ``connections`` (open loop)."""

    async def run() -> Counter[str]:
        counts: Counter[str] = Counter()
        ends = time.monotonic() + duration_s
        await asyncio.gather(
            *(
                _flood_connection(port, payloads, rate / connections, ends, counts)
                for _ in range(connections)
            )
        )
        return counts

    queue.put(dict(asyncio.run(run())))


def write_evidence(name: str, data: dict[str, Any]) -> None:
    """Append one result to ``$TENSORWIRE_ABUSE_REPORT`` (JSON lines), if set."""
    path = os.environ.get("TENSORWIRE_ABUSE_REPORT")
    if path:
        with Path(path).open("a", encoding="utf-8") as out:
            out.write(json.dumps({"test": name, **data}) + "\n")
