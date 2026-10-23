"""Building blocks of ``tensorwire bench`` (spec 13.7).

Everything here runs against a :class:`~tensorwire.testing.fake_chain.FakeChain`
inside the process; HTTP, signatures, the replay store and the rate limiters
are real. The CLI (:mod:`tensorwire.cli.bench_cmd`) starts these pieces in
separate processes and pins them to CPUs; tests call them in-process.

- :func:`bench_miner`: the benchmark miner (``bob``), one trivial route.
  :data:`worker_app` is its app for ``TW_WORKERS > 1`` (built from ``TW_*``
  variables in each worker).
- :func:`run_load`: one load generator (one validator hotkey, ``concurrency``
  requests in flight) for a fixed time.
- :func:`auth_overhead`: the time the kit adds before the handler (IP limit,
  staleness precheck, btauth/1 verification with the replay store, caller
  policy, hotkey limit), measured per request without HTTP.
- :func:`serve_miners` and :func:`fanout`: many miners in one process, and one
  validator querying all of them at once.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import os
import socket
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio.to_thread
import httpx
import uvicorn
from pydantic import BaseModel, Field

from tensorwire.auth.signer import RequestSigner
from tensorwire.chain.axon import parse_axon
from tensorwire.chain.gateway import NeuronView
from tensorwire.config import MinerSettings
from tensorwire.crypto import keypair_from_uri
from tensorwire.miner.app import Miner, NoSignalServer
from tensorwire.miner.routes import RouteContext
from tensorwire.observability.logging import configure_logging
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.metagraph import FakeMetagraphSource
from tensorwire.validator.client import ValidatorClient

__all__ = [
    "BENCH_NETUID",
    "BENCH_ROUTE",
    "BENCH_STREAM_ROUTE",
    "MAX_LOAD_PROCESSES",
    "BenchRequest",
    "BenchResponse",
    "BenchStreamRequest",
    "LoadStats",
    "auth_overhead",
    "bench_body",
    "bench_chain",
    "bench_miner",
    "bench_validator",
    "fanout",
    "fanout_host_process",
    "fanout_key",
    "fanout_neurons",
    "load_process",
    "main",
    "percentile",
    "run_load",
    "serve_miners",
]

BENCH_NETUID = 1
BENCH_ROUTE = "/v1/bench"
#: A streaming route (spec 9.2) for the stream abuse tests (13.6).
BENCH_STREAM_ROUTE = "/v1/bench/stream"
#: Load generators that can run at once. Each signs with its own permitted
#: validator hotkey (:func:`bench_validator`), so no two processes ever sign
#: the same nonce.
MAX_LOAD_PROCESSES = 32


class BenchRequest(BaseModel):
    """The benchmark request: a payload of the chosen size."""

    payload: str


class BenchResponse(BaseModel):
    """The benchmark answer: the payload length."""

    n: int


class BenchStreamRequest(BaseModel):
    """A stream of ``chunks`` chunks of about ``size`` bytes each."""

    chunks: int = Field(ge=0, le=100_000)
    size: int = Field(ge=0, le=65_536)


def bench_body(size: int) -> bytes:
    """A JSON body of exactly ``size`` bytes (at least 15)."""
    overhead = len(BenchRequest(payload="").model_dump_json())
    if size < overhead:
        raise ValueError(f"body size must be at least {overhead} bytes")
    return BenchRequest(payload="x" * (size - overhead)).model_dump_json().encode()


def percentile(values: Sequence[float], q: float) -> float:
    """The ``q`` quantile (0-1) of ``values``, nearest rank; NaN when empty."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    rank = min(len(ordered) - 1, max(0, round(q * len(ordered)) - 1))
    return ordered[rank]


def bench_validator(index: int) -> Any:
    """Validator keypair ``index``: ``//Alice`` (0) or ``//TensorWireBenchV<index>``."""
    if not 0 <= index < MAX_LOAD_PROCESSES:
        raise ValueError(f"validator index must be 0-{MAX_LOAD_PROCESSES - 1}")
    if index == 0:
        return dev_key("alice").keypair
    return keypair_from_uri(f"//TensorWireBenchV{index}")


def bench_chain(miner_hotkeys: Sequence[str] = ()) -> FakeChain:
    """A subnet: ``bob`` (or ``miner_hotkeys``) as miners, permitted validators."""
    chain = FakeChain()
    chain.add_subnet(BENCH_NETUID)
    for hotkey in miner_hotkeys or (dev_key("bob").ss58,):
        chain.register(BENCH_NETUID, hotkey)
    for index in range(MAX_LOAD_PROCESSES):
        chain.register(
            BENCH_NETUID,
            bench_validator(index).ss58_address,
            validator_permit=True,
            stake_tao=1000,
        )
    return chain


def bench_miner(
    settings: MinerSettings,
    *,
    chain: FakeChain | None = None,
    hotkey: Any = None,
) -> Miner:
    """The benchmark miner: one route that returns the payload length."""
    keypair = dev_key("bob").keypair if hotkey is None else hotkey
    chain = bench_chain() if chain is None else chain
    gateway = chain.with_signer(keypair.ss58_address)
    miner = Miner(
        settings,
        gateway=gateway,
        metagraph=FakeMetagraphSource(gateway, BENCH_NETUID),
        hotkey=keypair,
        check_sdk=False,
    )

    @miner.route(BENCH_ROUTE, request=BenchRequest, response=BenchResponse)
    async def bench(req: BenchRequest, ctx: RouteContext) -> BenchResponse:  # noqa: ARG001
        return BenchResponse(n=len(req.payload))

    @miner.route(BENCH_STREAM_ROUTE, request=BenchStreamRequest, stream=True)
    async def stream(req: BenchStreamRequest, ctx: RouteContext) -> AsyncIterator[Any]:  # noqa: ARG001
        pad = "x" * req.size
        for i in range(req.chunks):
            yield {"i": i, "pad": pad}

    return miner


def __getattr__(name: str) -> Any:
    # ``worker_app``: what each TW_WORKERS > 1 worker imports
    # ("tensorwire.testing.bench:worker_app"); built from TW_* variables.
    if name == "worker_app":
        app = bench_miner(MinerSettings.from_env()).app
        globals()["worker_app"] = app
        return app
    raise AttributeError(name)


# ------------------------------------------------------------------ load


@dataclass
class LoadStats:
    """One load generator's results (latencies in seconds, 200s only)."""

    ok: int = 0
    failed: int = 0
    statuses: dict[str, int] = field(default_factory=dict)
    latencies: list[float] = field(default_factory=list)
    elapsed_s: float = 0.0


async def run_load(
    url: str,
    *,
    validator: int,
    miner_hotkey: str,
    body: bytes,
    concurrency: int,
    duration_s: float,
    warmup_s: float = 0.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> LoadStats:
    """Send signed requests to ``url`` for ``warmup_s + duration_s`` seconds.

    ``concurrency`` requests are in flight at all times. Only the
    ``duration_s`` window after the warm-up is counted.
    """
    signer = RequestSigner(bench_validator(validator))
    target = httpx.URL(url).raw_path.decode("ascii")
    stats = LoadStats()
    limits = httpx.Limits(
        max_connections=concurrency, max_keepalive_connections=concurrency
    )
    started = time.perf_counter()
    counting_from = started + warmup_s
    ends = counting_from + duration_s

    async def worker(http: httpx.AsyncClient) -> None:
        while (now := time.perf_counter()) < ends:
            headers = signer.sign(
                method="POST", target=target, body=body, receiver_ss58=miner_hotkey
            )
            headers["Content-Type"] = "application/json"
            sent = time.perf_counter()
            try:
                r = await http.post(url, content=body, headers=headers)
                status = str(r.status_code)
            except httpx.HTTPError as exc:
                status = type(exc).__name__
            done = time.perf_counter()
            if now < counting_from:
                continue
            stats.statuses[status] = stats.statuses.get(status, 0) + 1
            if status == "200":
                stats.ok += 1
                stats.latencies.append(done - sent)
            else:
                stats.failed += 1

    async with httpx.AsyncClient(
        transport=transport or httpx.AsyncHTTPTransport(retries=0),
        limits=limits,
        timeout=httpx.Timeout(30.0),
    ) as http:
        await asyncio.gather(*(worker(http) for _ in range(concurrency)))
    stats.elapsed_s = min(duration_s, max(0.0, time.perf_counter() - counting_from))
    return stats


# ------------------------------------------------------------------ auth overhead


async def auth_overhead(miner: Miner, requests: int, *, body: bytes) -> list[float]:
    """Seconds the kit spends before the handler, per request (spec 13.7 row 2).

    ``miner`` must be started (``miner.running()``). Each request is signed
    by ``alice`` (signing is the validator's cost and is not timed), then the
    miner's own pipeline pieces run on it in order: per-IP limit, staleness
    precheck, btauth/1 verification (thread offload and replay store
    included), caller policy and the per-hotkey limit.
    """
    rt = miner.lifecycle.runtime
    route = miner.routes.get(BENCH_ROUTE)
    if route is None:
        raise ValueError("not a bench miner")
    signer = dev_key("alice").signer()
    timings: list[float] = []
    for _ in range(requests):
        headers = signer.sign(
            method="POST", target=BENCH_ROUTE, body=body, receiver_ss58=rt.hotkey_ss58
        )
        started = time.perf_counter()
        await rt.ip_limiter.acquire("203.0.113.7")
        rt.gate.precheck()
        caller = await rt.verifier.verify(
            list(headers.items()), body, method="POST", target=BENCH_ROUTE
        )
        rt.gate.admit(route.path, route.policy, caller.hotkey_ss58)
        await rt.hotkey_limiter.acquire(f"{route.path} {caller.hotkey_ss58}")
        timings.append(time.perf_counter() - started)
    return timings


# ------------------------------------------------------------------ fan-out


def fanout_key(index: int) -> Any:
    """The keypair of fan-out miner ``index`` (``//TensorWireBench<index>``)."""
    return keypair_from_uri(f"//TensorWireBench{index}")


def _miner_settings(host: str, port: int, **extra: Any) -> MinerSettings:
    return MinerSettings(
        netuid=BENCH_NETUID,
        wallet_name="bench",
        wallet_path=Path(tempfile.gettempdir()),  # no wallet: the hotkey is passed in
        external_ip=host,
        bind_host=host,
        bind_port=port,
        allow_private_axons=True,
        ntp_servers=(),
        rate_ip_per_s=1_000_000,
        rate_ip_burst=1_000_000,
        **extra,
    )


@contextlib.asynccontextmanager
async def serve_miners(
    indexes: Sequence[int], *, host: str = "127.0.0.2"
) -> AsyncIterator[dict[int, int]]:
    """Run fan-out miners ``indexes`` in this process; yields ``{index: port}``.

    Every miner has its own hotkey (:func:`fanout_key`), port and uvicorn
    server; all share one event loop.
    """
    keys = {i: fanout_key(i) for i in indexes}
    chain = bench_chain([k.ss58_address for k in keys.values()])
    ports: dict[int, int] = {}
    servers: list[tuple[uvicorn.Server, asyncio.Task[None]]] = []
    async with contextlib.AsyncExitStack() as stack:
        for index, key in keys.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, 0))
            port = int(sock.getsockname()[1])
            stack.callback(sock.close)
            miner = bench_miner(_miner_settings(host, port), chain=chain, hotkey=key)
            app = await stack.enter_async_context(miner.running())
            options = {
                k: v
                for k, v in miner.uvicorn_options().items()
                if k not in ("host", "port")
            }
            server = NoSignalServer(uvicorn.Config(app, lifespan="off", **options))
            task = asyncio.get_running_loop().create_task(server.serve([sock]))
            servers.append((server, task))
            ports[index] = port
        # uvicorn has no "started" event to wait on.
        while not all(s.started for s, _ in servers):  # noqa: ASYNC110
            await asyncio.sleep(0.01)
        try:
            yield ports
        finally:
            for running, _ in servers:
                running.should_exit = True
            await asyncio.gather(*(t for _, t in servers), return_exceptions=True)


def fanout_neurons(ports: dict[int, int], host: str = "127.0.0.2") -> list[NeuronView]:
    """Neuron views for the fan-out miners (as a validator reads the metagraph)."""
    neurons = []
    for index, port in sorted(ports.items()):
        hotkey = fanout_key(index).ss58_address
        neurons.append(
            NeuronView(
                uid=index,
                hotkey=hotkey,
                coldkey=hotkey,
                validator_permit=False,
                active=True,
                total_stake_tao=0.0,
                alpha_stake=0.0,
                tao_stake=0.0,
                axon=parse_axon(f"{host}:{port}", allow_private=True),
                last_update=0,
                incentive=0.0,
                dividends=0.0,
                axon_protocol=87,
            )
        )
    return neurons


async def fanout(
    neurons: Sequence[NeuronView],
    *,
    body: bytes,
    rounds: int,
    max_concurrency: int,
    on_round: Callable[[int, float, int], None] | None = None,
) -> list[tuple[float, int]]:
    """``rounds`` rounds of one validator (``alice``) querying all ``neurons``.

    Responses are checked (twresp/1), as a validator does. Returns
    ``(seconds, n_ok)`` per round.
    """
    results: list[tuple[float, int]] = []
    async with ValidatorClient(
        dev_key("alice").signer(), max_concurrency=max_concurrency
    ) as client:
        for i in range(rounds):
            started = time.perf_counter()
            answers = await client.query_many(neurons, BENCH_ROUTE, body)
            elapsed = time.perf_counter() - started
            n_ok = sum(1 for r in answers.values() if r.ok and r.response_verified)
            results.append((elapsed, n_ok))
            if on_round is not None:
                on_round(i, elapsed, n_ok)
    return results


# ------------------------------------------------------------------ processes


def _pin(cpus: Sequence[int] | None) -> None:
    configure_logging("WARNING")  # a spawned process: quiet, JSON
    if cpus:
        os.sched_setaffinity(0, cpus)


def load_process(
    queue: Any,
    *,
    url: str,
    validator: int,
    miner_hotkey: str,
    body: bytes,
    concurrency: int,
    duration_s: float,
    warmup_s: float,
    cpus: Sequence[int] | None,
) -> None:
    """One load-generator process: :func:`run_load`, result put on ``queue``."""
    _pin(cpus)
    stats = asyncio.run(
        run_load(
            url,
            validator=validator,
            miner_hotkey=miner_hotkey,
            body=body,
            concurrency=concurrency,
            duration_s=duration_s,
            warmup_s=warmup_s,
        )
    )
    queue.put(dataclasses.asdict(stats))


def fanout_host_process(
    indexes: Sequence[int], queue: Any, stop: Any, cpus: Sequence[int] | None
) -> None:
    """One fan-out host: serves miners ``indexes`` until ``stop`` is set."""
    _pin(cpus)

    async def serve() -> None:
        async with serve_miners(indexes) as ports:
            queue.put(ports)
            await anyio.to_thread.run_sync(stop.wait)

    asyncio.run(serve())


def main() -> None:
    """The throughput miner (``python -m tensorwire.testing.bench``), from ``TW_*``."""
    bench_miner(MinerSettings.from_env()).run(
        app_import="tensorwire.testing.bench:worker_app"
    )


if __name__ == "__main__":
    main()
