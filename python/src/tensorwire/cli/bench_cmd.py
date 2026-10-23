"""``tensorwire bench``: the 13.7 benchmark targets on this machine.

Three measurements, each against real HTTP, signatures, replay store and
rate limiters, with a FakeChain in place of the chain:

1. **Throughput.** A real uvicorn miner (``--workers``, Redis from
   ``--redis-url``) with a trivial handler; ``--clients`` load processes
   (one validator hotkey each) keep ``--concurrency`` signed 1 KB requests in
   flight for ``--duration`` seconds. Counts 200s per second.
2. **Auth + policy overhead.** What the kit adds before the handler (IP
   limit, staleness precheck, btauth/1 verification with the replay store,
   caller policy, hotkey limit), per request, p50 / p99.
3. **Fan-out.** One validator queries ``--fanout-miners`` local miners
   (served by ``--fanout-hosts`` processes) at once, twresp/1 checked; the
   slowest of ``--fanout-rounds`` rounds counts.

On a machine with at least 8 CPUs the miner side is pinned to the first 4
(``--miner-cpus``) and the load generators to the others
(``--client-cpus``), which approximates the 4 vCPU target host. Redis runs
wherever it runs (not pinned). The report says what was used.

**Redis path (spec 13.7, D17).** "Met" means Redis reached directly: host
networking, a Unix socket or the container's own IP, not Docker's userland
port proxy (``docker-proxy``), which adds latency a production deployment
does not have. Without ``--redis-url`` the bench finds Redis itself: a
running container that publishes port 6379 is reached at its own IP (when
that answers), otherwise a Redis on 127.0.0.1:6379 is used. An explicit
``--redis-url`` is used as given. Either way the report prints the path, and
a run through ``docker-proxy`` is marked as extra information, not the
13.7 result.

The rate limits stay on but are raised far above the load (one IP and a few
hotkeys send everything), so they cost their Redis round trip without
capping throughput.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import multiprocessing
import os
import platform
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

import httpx
import typer
from pydantic import SecretStr

from tensorwire.config import MinerSettings
from tensorwire.observability.logging import configure_logging
from tensorwire.testing import bench as tb
from tensorwire.testing.keys import dev_key
from tensorwire.version import __version__

__all__ = [
    "BenchReport",
    "DockerRedis",
    "RedisPath",
    "Targets",
    "bench",
    "docker_redis_containers",
    "parse_cpus",
    "resolve_redis_path",
]

_MAX_CPU = 4096


@dataclass(frozen=True)
class Targets:
    """Spec 13.7."""

    rps: float = 500.0
    auth_p50_ms: float = 2.0
    auth_p99_ms: float = 5.0
    fanout_s: float = 2.0


@dataclass
class BenchReport:
    """Everything one run measured, with the environment it ran in."""

    environment: dict[str, Any] = field(default_factory=dict)
    throughput: dict[str, Any] = field(default_factory=dict)
    auth: dict[str, Any] = field(default_factory=dict)
    fanout: dict[str, Any] = field(default_factory=dict)
    verdict: dict[str, bool | None] = field(default_factory=dict)


def parse_cpus(spec: str | None) -> list[int] | None:
    """``"0-3,6"`` -> ``[0, 1, 2, 3, 6]``; empty or ``"none"`` -> ``None``."""
    if spec is None or spec.strip().lower() in ("", "none"):
        return None
    cpus: set[int] = set()
    try:
        for raw in spec.split(","):
            low, _, high = raw.strip().partition("-")
            first = int(low)
            last = int(high) if high else first
            if not 0 <= first <= last < _MAX_CPU:
                raise ValueError(raw)
            cpus.update(range(first, last + 1))
    except ValueError:
        raise typer.BadParameter(f"not a CPU list: {spec!r}") from None
    return sorted(cpus)


def _auto_cpus() -> tuple[list[int] | None, list[int] | None]:
    available = sorted(os.sched_getaffinity(0))
    if len(available) < 8:
        return None, None
    return available[:4], available[4:]


def _free_port(host: str = "127.0.0.1") -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def _ms(seconds: float) -> float:
    return round(seconds * 1000, 3)


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


# ------------------------------------------------------------------ redis path

#: The database the bench uses on a Redis it found itself.
BENCH_REDIS_DB = 14
_REDIS_PORT = 6379
#: Host addresses a published port is reached on (loopback and wildcard).
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "0.0.0.0", "::"})  # noqa: S104


@dataclass(frozen=True)
class DockerRedis:
    """A running container that serves Redis (publishes or exposes 6379)."""

    name: str
    ip: str | None
    """The container's own address (``None`` on host networking)."""
    published: tuple[tuple[str, int], ...]
    """``(host_ip, host_port)`` pairs mapped to its 6379 by ``docker-proxy``."""
    host_network: bool = False


@dataclass(frozen=True)
class RedisPath:
    """Which Redis the bench uses and how it is reached (D17)."""

    url: str | None
    kind: str
    """``direct`` (container IP, host network, Unix socket, non-Docker host
    Redis), ``docker-proxy``, or ``none`` (no Redis: one worker, memory)."""
    detail: str

    @property
    def counts(self) -> bool:
        """Whether a run on this path can be the 13.7 result."""
        return self.kind != "docker-proxy"

    def describe(self) -> str:
        """One line for the report."""
        note = "" if self.counts else " (extra information only, not the 13.7 result)"
        return f"redis path: {self.kind}{note}: {self.detail}"


def docker_redis_containers(
    run: Callable[[list[str]], str] | None = None,
) -> list[DockerRedis]:
    """Running Docker containers serving Redis on 6379 (empty without Docker).

    ``run`` executes a ``docker`` command and returns its stdout (tests pass
    a fake).
    """
    run = _docker if run is None else run
    try:
        ids = run(["docker", "ps", "-q"]).split()
        if not ids:
            return []
        raw = run(["docker", "inspect", *ids])
        containers = json.loads(raw)
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    found: list[DockerRedis] = []
    for c in containers if isinstance(containers, list) else []:
        try:
            net = c.get("NetworkSettings") or {}
            ports = net.get("Ports") or {}
            mode = str((c.get("HostConfig") or {}).get("NetworkMode", ""))
            image = str((c.get("Config") or {}).get("Image", ""))
            if f"{_REDIS_PORT}/tcp" not in ports and not (
                mode == "host" and "redis" in image
            ):
                continue
            published = tuple(
                (str(b.get("HostIp") or "*"), int(b["HostPort"]))
                for b in ports.get(f"{_REDIS_PORT}/tcp") or ()
            )
            ips = [
                str(n.get("IPAddress"))
                for n in (net.get("Networks") or {}).values()
                if n.get("IPAddress")
            ]
            found.append(
                DockerRedis(
                    name=str(c.get("Name", "")).lstrip("/"),
                    ip=ips[0] if ips else None,
                    published=published,
                    host_network=mode == "host",
                )
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
    return found


def _docker(cmd: list[str]) -> str:
    return subprocess.run(  # noqa: S603 - fixed docker command, no shell
        cmd, capture_output=True, check=True, text=True, timeout=10
    ).stdout


def _redis_answers(url: str) -> bool:
    try:
        import redis  # noqa: PLC0415 - optional extra

        client = redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)
        try:
            return bool(client.ping())
        finally:
            client.close()
    except Exception:  # noqa: BLE001 - unreachable for any reason
        return False


def resolve_redis_path(
    url: str | None,
    *,
    containers: Callable[[], list[DockerRedis]] = docker_redis_containers,
    answers: Callable[[str], bool] = _redis_answers,
) -> RedisPath:
    """Find Redis for the bench, preferring the direct path (13.7, D17).

    With ``url``: use it as given and say how it is reached. Without: a
    container's own IP when it answers, else ``127.0.0.1:6379``. Returns
    kind ``none`` when no Redis answers.
    """
    if url is not None:
        return _classify(url, containers())
    found = containers()
    for c in found:
        if c.host_network:
            candidate = f"redis://127.0.0.1:{_REDIS_PORT}/{BENCH_REDIS_DB}"
            if answers(candidate):
                return RedisPath(
                    candidate, "direct", f"container {c.name}, host network"
                )
        elif c.ip:
            candidate = f"redis://{c.ip}:{_REDIS_PORT}/{BENCH_REDIS_DB}"
            if answers(candidate):
                return RedisPath(
                    candidate, "direct", f"container {c.name} at its own IP"
                )
    local = f"redis://127.0.0.1:{_REDIS_PORT}/{BENCH_REDIS_DB}"
    if answers(local):
        return _classify(local, found)
    return RedisPath(None, "none", "no Redis found (one worker, memory stores)")


def _classify(url: str, containers: list[DockerRedis]) -> RedisPath:
    parts = urlsplit(url)
    if parts.scheme == "unix":
        return RedisPath(url, "direct", "Unix socket")
    host = parts.hostname or "127.0.0.1"
    port = parts.port or _REDIS_PORT
    for c in containers:
        if c.ip is not None and host == c.ip:
            return RedisPath(url, "direct", f"container {c.name} at its own IP")
        if host in _LOOPBACK and any(p == port for _, p in c.published):
            better = (
                f"; direct: redis://{c.ip}:{_REDIS_PORT}{parts.path or ''}"
                if c.ip
                else ""
            )
            return RedisPath(
                url,
                "docker-proxy",
                f"{host}:{port} is Docker's port mapping of container {c.name}{better}",
            )
        if c.host_network and host in _LOOPBACK and port == _REDIS_PORT:
            return RedisPath(url, "direct", f"container {c.name}, host network")
    return RedisPath(url, "direct", f"{host}:{port} (not a Docker port mapping)")


def _redis_version(url: str | None) -> str | None:
    if url is None:
        return None
    try:
        import redis  # noqa: PLC0415 - optional extra

        client = redis.Redis.from_url(url, socket_timeout=1)
        info: Any = client.info("server")
        client.close()
        return str(info.get("redis_version"))
    except Exception as exc:  # noqa: BLE001 - only for the report
        return f"unreachable ({type(exc).__name__})"


def _environment(
    redis: RedisPath, miner_cpus: list[int] | None, client_cpus: list[int] | None
) -> dict[str, Any]:
    redis_url = redis.url

    mem_kb = 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal"):
                mem_kb = int(line.split()[1])
    except OSError:
        pass
    return {
        "date_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "cpu": _cpu_model(),
        "cpus_total": os.cpu_count(),
        "memory_gib": round(mem_kb / 1024 / 1024, 1),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "tensorwire": __version__,
        "bittensor": _version("bittensor"),
        "uvicorn": _version("uvicorn"),
        "redis": _redis_version(redis_url),
        "redis_path": asdict(redis),
        "miner_cpus": miner_cpus,
        "client_cpus": client_cpus,
    }


# ------------------------------------------------------------------ throughput


def _miner_env(
    *, port: int, metrics_port: int, workers: int, redis_url: str | None, log: str
) -> dict[str, str]:
    env = {
        k: v for k, v in os.environ.items() if not k.startswith(("TW_", "PROMETHEUS"))
    }
    env.update(
        {
            "TW_NETUID": str(tb.BENCH_NETUID),
            "TW_WALLET_NAME": "bench",
            "TW_WALLET_PATH": tempfile.gettempdir(),
            "TW_EXTERNAL_IP": "127.0.0.2",
            "TW_ALLOW_PRIVATE_AXONS": "1",
            "TW_BIND_HOST": "127.0.0.1",
            "TW_BIND_PORT": str(port),
            "TW_METRICS_BIND": f"127.0.0.1:{metrics_port}",
            "TW_NTP_SERVERS": "",
            "TW_WORKERS": str(workers),
            "TW_LOG_LEVEL": log,
            "TW_RATE_IP_PER_S": "1000000",
            "TW_RATE_IP_BURST": "1000000",
            "TW_RATE_HOTKEY_PER_S": "1000000",
            "TW_RATE_HOTKEY_BURST": "1000000",
        }
    )
    if redis_url is not None:
        env["TW_REDIS_URL"] = redis_url
    return env


def _wait_ready(port: int, proc: subprocess.Popen[bytes], timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"the bench miner exited with {proc.returncode}")
        try:
            if (
                httpx.get(f"http://127.0.0.1:{port}/readyz", timeout=1).status_code
                == 200
            ):
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    raise RuntimeError("the bench miner did not become ready")


def _scrape_verify(metrics_port: int) -> dict[str, float]:
    text = httpx.get(f"http://127.0.0.1:{metrics_port}/metrics", timeout=5).text
    values: dict[str, float] = {}
    for line in text.splitlines():
        for name in ("tw_auth_verify_duration_seconds_sum",
                     "tw_auth_verify_duration_seconds_count"):  # fmt: skip
            if line.startswith(name + " "):
                values[name] = float(line.split()[1])
    return values


def run_throughput(
    *,
    duration_s: float,
    warmup_s: float,
    workers: int,
    clients: int,
    concurrency: int,
    body: bytes,
    redis_url: str | None,
    miner_cpus: list[int] | None,
    client_cpus: list[int] | None,
    log_level: str,
    workdir: Path,
) -> dict[str, Any]:
    """Measurement 1: verified requests per second through a real miner."""
    port, metrics_port = _free_port(), _free_port()
    env = _miner_env(
        port=port,
        metrics_port=metrics_port,
        workers=workers,
        redis_url=redis_url,
        log=log_level,
    )
    log_path = workdir / "bench-miner.log"
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            [sys.executable, "-m", "tensorwire.testing.bench"],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            preexec_fn=(lambda: os.sched_setaffinity(0, miner_cpus))  # noqa: PLW1509
            if miner_cpus
            else None,
        )
        try:
            _wait_ready(port, proc, timeout_s=60)
            ctx = multiprocessing.get_context("spawn")
            queue = ctx.Queue()
            per_client = max(1, concurrency // clients)
            procs = [
                ctx.Process(
                    target=tb.load_process,
                    args=(queue,),
                    kwargs={
                        "url": f"http://127.0.0.1:{port}{tb.BENCH_ROUTE}",
                        "validator": i,
                        "miner_hotkey": dev_key("bob").ss58,
                        "body": body,
                        "concurrency": per_client,
                        "duration_s": duration_s,
                        "warmup_s": warmup_s,
                        "cpus": client_cpus,
                    },
                )
                for i in range(clients)
            ]
            for p in procs:
                p.start()
            results = [queue.get(timeout=duration_s + warmup_s + 120) for _ in procs]
            for p in procs:
                p.join(timeout=30)
            verify = _scrape_verify(metrics_port)
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
    ok = sum(r["ok"] for r in results)
    failed = sum(r["failed"] for r in results)
    latencies = [x for r in results for x in r["latencies"]]
    statuses: dict[str, int] = {}
    for r in results:
        for k, v in r["statuses"].items():
            statuses[k] = statuses.get(k, 0) + v
    window = max(r["elapsed_s"] for r in results) or duration_s
    count = verify.get("tw_auth_verify_duration_seconds_count", 0.0)
    return {
        "workers": workers,
        "clients": clients,
        "concurrency": per_client * clients,
        "duration_s": duration_s,
        "body_bytes": len(body),
        "backend": "redis" if redis_url else "memory",
        "ok": ok,
        "failed": failed,
        "statuses": statuses,
        "rps": round(ok / window, 1),
        "latency_ms": {
            "p50": _ms(tb.percentile(latencies, 0.50)),
            "p99": _ms(tb.percentile(latencies, 0.99)),
        },
        "server_verify_mean_ms": _ms(
            verify.get("tw_auth_verify_duration_seconds_sum", 0.0) / count
        )
        if count
        else None,
        "miner_log": str(log_path),
    }


# ------------------------------------------------------------------ auth overhead


def run_auth(
    *, requests: int, body: bytes, redis_url: str | None, cpus: list[int] | None
) -> dict[str, Any]:
    """Measurement 2: the kit's work before the handler, per request."""
    before = os.sched_getaffinity(0)
    if cpus:
        os.sched_setaffinity(0, cpus)

    async def measure() -> list[float]:
        settings = MinerSettings(
            netuid=tb.BENCH_NETUID,
            wallet_name="bench",
            wallet_path=Path(tempfile.gettempdir()),
            external_ip="127.0.0.2",
            allow_private_axons=True,
            ntp_servers=(),
            redis_url=None if redis_url is None else SecretStr(redis_url),
            rate_ip_per_s=1_000_000,
            rate_ip_burst=1_000_000,
            rate_hotkey_per_s=1_000_000,
            rate_hotkey_burst=1_000_000,
        )
        miner = tb.bench_miner(settings)
        async with miner.running():
            await tb.auth_overhead(miner, min(500, requests), body=body)  # warm-up
            return await tb.auth_overhead(miner, requests, body=body)

    try:
        timings = asyncio.run(measure())
    finally:
        os.sched_setaffinity(0, before)
    return {
        "requests": requests,
        "backend": "redis" if redis_url else "memory",
        "p50_ms": _ms(tb.percentile(timings, 0.50)),
        "p99_ms": _ms(tb.percentile(timings, 0.99)),
        "mean_ms": _ms(sum(timings) / len(timings)),
    }


# ------------------------------------------------------------------ fan-out


def run_fanout(
    *,
    miners: int,
    hosts: int,
    rounds: int,
    max_concurrency: int,
    body: bytes,
    miner_cpus: list[int] | None,
    client_cpus: list[int] | None,
) -> dict[str, Any]:
    """Measurement 3: one validator round over ``miners`` local miners."""
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    stop = ctx.Event()
    groups = [list(range(i, miners, hosts)) for i in range(min(hosts, miners))]
    procs = [
        ctx.Process(
            target=tb.fanout_host_process, args=(group, queue, stop, miner_cpus)
        )
        for group in groups
    ]
    for p in procs:
        p.start()
    before = os.sched_getaffinity(0)
    try:
        ports: dict[int, int] = {}
        for _ in procs:
            ports.update(queue.get(timeout=120))
        if client_cpus:
            os.sched_setaffinity(0, client_cpus)
        neurons = tb.fanout_neurons(ports)
        results = asyncio.run(
            tb.fanout(
                neurons, body=body, rounds=rounds, max_concurrency=max_concurrency
            )
        )
    finally:
        os.sched_setaffinity(0, before)
        stop.set()
        for p in procs:
            p.join(timeout=30)
            if p.is_alive():
                p.kill()
    times = [t for t, _ in results]
    return {
        "miners": miners,
        "hosts": hosts,
        "max_concurrency": max_concurrency,
        "rounds": rounds,
        "round_s": [round(t, 3) for t in times],
        "first_round_s": round(times[0], 3),
        "slowest_round_s": round(max(times), 3),
        "n_ok_verified": [n for _, n in results],
    }


# ------------------------------------------------------------------ command


def _verdict(report: BenchReport, targets: Targets) -> dict[str, bool | None]:
    t, a, f = report.throughput, report.auth, report.fanout
    return {
        "rps": None if not t else t["rps"] >= targets.rps,
        "auth_p50": None if not a else a["p50_ms"] <= targets.auth_p50_ms,
        "auth_p99": None if not a else a["p99_ms"] <= targets.auth_p99_ms,
        "fanout": None
        if not f
        else f["slowest_round_s"] <= targets.fanout_s
        and all(n == f["miners"] for n in f["n_ok_verified"]),
    }


def _mark(ok: bool | None) -> str:
    return {True: "PASS", False: "MISS", None: "skipped"}[ok]


def render(report: BenchReport, targets: Targets) -> str:
    """The human-readable report."""
    e, t, a, f, v = (
        report.environment,
        report.throughput,
        report.auth,
        report.fanout,
        report.verdict,
    )
    lines = [
        f"tensorwire bench {e.get('tensorwire')} — {e.get('date_utc')} UTC",
        f"  host: {e.get('cpu')}, {e.get('cpus_total')} CPUs, "
        f"{e.get('memory_gib')} GiB, {e.get('os')}",
        f"  python {e.get('python')}, bittensor {e.get('bittensor')}, "
        f"uvicorn {e.get('uvicorn')}, redis {e.get('redis')}",
        f"  miner CPUs {e.get('miner_cpus') or 'unpinned'}, "
        f"client CPUs {e.get('client_cpus') or 'unpinned'}",
    ]
    path = e.get("redis_path")
    if path:
        lines.append("  " + RedisPath(**path).describe())
    lines.append("")
    if t:
        lines += [
            f"[{_mark(v['rps'])}] verified requests/s: {t['rps']} "
            f"(target >= {targets.rps:g}; {t['workers']} workers, {t['backend']}, "
            f"{t['concurrency']} in flight, {t['body_bytes']} B, "
            f"{t['duration_s']:g} s)",
            f"       end-to-end latency p50 {t['latency_ms']['p50']} ms, "
            f"p99 {t['latency_ms']['p99']} ms; ok {t['ok']}, failed {t['failed']} "
            f"{t['statuses']}; server verify mean {t['server_verify_mean_ms']} ms",
        ]
    if a:
        lines += [
            f"[{_mark(v['auth_p50'])}] auth + policy p50: {a['p50_ms']} ms "
            f"(target <= {targets.auth_p50_ms:g} ms)",
            f"[{_mark(v['auth_p99'])}] auth + policy p99: {a['p99_ms']} ms "
            f"(target <= {targets.auth_p99_ms:g} ms; {a['requests']} requests, "
            f"{a['backend']})",
        ]
    if f:
        lines += [
            f"[{_mark(v['fanout'])}] fan-out to {f['miners']} miners: slowest round "
            f"{f['slowest_round_s']} s, first {f['first_round_s']} s "
            f"(target <= {targets.fanout_s:g} s; concurrency {f['max_concurrency']}, "
            f"verified answers per round {sorted(set(f['n_ok_verified']))})",
        ]
    return "\n".join(lines)


def bench(
    *,
    duration: Annotated[
        float, typer.Option("--duration", help="Seconds of measured load.")
    ] = 60.0,
    warmup: Annotated[float, typer.Option(help="Seconds before counting.")] = 3.0,
    workers: Annotated[int, typer.Option(help="uvicorn workers (miner).")] = 4,
    clients: Annotated[
        int | None,
        typer.Option(
            min=1,
            max=tb.MAX_LOAD_PROCESSES,
            help="Load processes, one hotkey each (default: one per client CPU, "
            "at most 12).",
        ),
    ] = None,
    concurrency: Annotated[int, typer.Option(help="Requests in flight.")] = 96,
    body_bytes: Annotated[int, typer.Option(help="Request body size.")] = 1024,
    redis_url: Annotated[
        str | None,
        typer.Option(
            envvar="TENSORWIRE_BENCH_REDIS_URL",
            help="Redis for the replay store and limiters (needed for workers > 1). "
            "Default: found automatically, reached directly (13.7, D17).",
        ),
    ] = None,
    miner_cpus: Annotated[
        str, typer.Option(help='CPUs for the miner side, "auto" or "none".')
    ] = "auto",
    client_cpus: Annotated[
        str, typer.Option(help='CPUs for the load side, "auto" or "none".')
    ] = "auto",
    auth_requests: Annotated[int, typer.Option(help="Requests timed.")] = 5000,
    fanout_miners: Annotated[int, typer.Option(help="Local miners.")] = 256,
    fanout_hosts: Annotated[int, typer.Option(help="Processes serving them.")] = 8,
    fanout_rounds: Annotated[int, typer.Option(help="Rounds; the slowest counts.")] = 5,
    fanout_concurrency: Annotated[
        int, typer.Option(help="Validator max concurrency (TW_MAX_CONCURRENCY).")
    ] = 64,
    skip: Annotated[
        list[str] | None,
        typer.Option(help="Skip a measurement: throughput, auth, fanout."),
    ] = None,
    log_level: Annotated[str, typer.Option(help="Miner TW_LOG_LEVEL.")] = "INFO",
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Also write the report as JSON.")
    ] = None,
) -> None:
    """Load-test a local miner and validator against the spec 13.7 targets."""
    configure_logging("WARNING")
    skipped = set(skip or ())
    unknown = skipped - {"throughput", "auth", "fanout"}
    if unknown:
        raise typer.BadParameter(f"unknown measurement(s): {sorted(unknown)}")
    path = resolve_redis_path(redis_url)
    typer.echo(path.describe(), err=True)
    redis_url = path.url
    if workers > 1 and redis_url is None:
        raise typer.BadParameter(
            "workers > 1 needs Redis: none found; pass --redis-url (or "
            "TENSORWIRE_BENCH_REDIS_URL). The miner refuses per-process replay "
            "stores and limits"
        )
    body = tb.bench_body(body_bytes)
    auto_miner, auto_client = _auto_cpus()
    m_cpus = auto_miner if miner_cpus == "auto" else parse_cpus(miner_cpus)
    c_cpus = auto_client if client_cpus == "auto" else parse_cpus(client_cpus)
    n_clients = clients or min(12, len(c_cpus) if c_cpus else 4)
    targets = Targets()
    report = BenchReport(environment=_environment(path, m_cpus, c_cpus))
    with tempfile.TemporaryDirectory(prefix="tensorwire-bench-") as tmp:
        if "throughput" not in skipped:
            typer.echo("throughput ...", err=True)
            report.throughput = run_throughput(
                duration_s=duration,
                warmup_s=warmup,
                workers=workers,
                clients=n_clients,
                concurrency=concurrency,
                body=body,
                redis_url=redis_url,
                miner_cpus=m_cpus,
                client_cpus=c_cpus,
                log_level=log_level,
                workdir=Path(tmp),
            )
            report.throughput.pop("miner_log")
    if "auth" not in skipped:
        typer.echo("auth + policy overhead ...", err=True)
        report.auth = run_auth(
            requests=auth_requests, body=body, redis_url=redis_url, cpus=m_cpus
        )
    if "fanout" not in skipped:
        typer.echo("fan-out ...", err=True)
        report.fanout = run_fanout(
            miners=fanout_miners,
            hosts=fanout_hosts,
            rounds=fanout_rounds,
            max_concurrency=fanout_concurrency,
            body=body,
            miner_cpus=m_cpus,
            client_cpus=c_cpus,
        )
    report.verdict = _verdict(report, targets)
    typer.echo(render(report, targets))
    if json_out is not None:
        json_out.write_text(json.dumps(asdict(report), indent=2) + "\n")
