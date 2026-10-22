"""The validator loop: query, score, persist, set weights (spec 8.9).

Users subclass :class:`SubnetValidator` and the kit runs the schedule::

    class MyValidator(SubnetValidator):
        async def make_task(self, round_id: int) -> Task:
            return Task(route="/v1/transform", body=b'{"text":"hi","op":"upper"}',
                        response_model=TransformResponse)

        async def score(self, task, results):  # -> {uid: score in [0, 1]}
            return {uid: 1.0 if r.ok else 0.0 for uid, r in results.items()}

    ValidatorRunner(MyValidator(), ValidatorSettings.from_env()).run()

Each round (every ``TW_ROUND_INTERVAL_S``):

1. read the metagraph snapshot; reset the scores of UIDs whose hotkey changed;
2. select miners (default: non-permit neurons with an axon, a random sample
   of ``TW_SAMPLE_SIZE``), build the task, query them all, score;
3. fold the scores into the EMA store (``TW_STATE_DIR/scores.db``);
4. let the weight scheduler submit weights if they are due (``weights.py``).

Once per tempo the client re-probes miners remembered as v10 (8.11.3).
Health endpoints and Prometheus metrics are served on ``TW_METRICS_BIND``.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import math
import signal
import statistics
import sys
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import anyio.to_thread
import structlog
import uvicorn
from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from tensorwire.auth.keys import ColdkeyState, WalletLike, coldkey_state, load_hotkey
from tensorwire.auth.sdk_check import check_sdk
from tensorwire.auth.signer import MonotonicNonce, RequestSigner
from tensorwire.chain.gateway import (
    BittensorGateway,
    ChainGateway,
    GatewayError,
    MetagraphView,
    NeuronView,
)
from tensorwire.chain.metagraph_cache import (
    MetagraphCache,
    MetagraphSource,
    StalenessStage,
)
from tensorwire.config import ValidatorSettings
from tensorwire.crypto import HotkeySigner
from tensorwire.errors import ConfigError, StartupError
from tensorwire.miner.app import NoSignalServer
from tensorwire.observability.logging import configure_logging
from tensorwire.observability.metrics import Metrics
from tensorwire.validator.client import (
    LegacyClientLike,
    MinerResult,
    ProtocolSelectorLike,
    ValidatorClient,
)
from tensorwire.validator.lock import HotkeyLock, HotkeyLockHeld
from tensorwire.validator.scores import RoundRecord, ScoreStore
from tensorwire.validator.selection import select_miners
from tensorwire.validator.weights import WeightDecision, WeightScheduler

__all__ = ["RoundReport", "SubnetValidator", "Task", "ValidatorRunner"]

_log = structlog.stdlib.get_logger("tensorwire.validator")


@dataclass(frozen=True)
class Task:
    """One round's request: where, what, and how to read the answer."""

    route: str
    body: bytes
    response_model: type[BaseModel] | None = None
    legacy_synapse: BaseModel | None = None
    """The same request as a v10 Synapse, to reach v10 miners (8.11.3)."""
    method: str = "POST"
    idempotent: bool = True
    expected: Any = None
    """Anything ``score`` needs to judge the answers (the right result)."""


class SubnetValidator(ABC):
    """Subclass this: the subnet's tasks and scoring. The kit runs the schedule."""

    #: Set by the runner from ``TW_SAMPLE_SIZE`` / ``TW_QUERY_VALIDATORS``.
    sample_size: int = 64
    query_validators: bool = False
    #: This validator's hotkey (never queried). Set by the runner.
    own_hotkey: str | None = None

    @abstractmethod
    async def make_task(self, round_id: int) -> Task:
        """The request for this round."""

    @abstractmethod
    async def score(
        self, task: Task, results: dict[int, MinerResult]
    ) -> dict[int, float]:
        """A score in [0, 1] per UID. Failed results (``ok=False``) should score 0.

        v10 answers (``protocol="v10"``) are never signed; they count by
        default, and ``result.response_verified`` says which answers were.
        """

    def select_miners(self, mg: MetagraphView) -> Sequence[NeuronView]:
        """The miners to query this round (default: spec 8.9 step 1)."""
        exclude = () if self.own_hotkey is None else (self.own_hotkey,)
        return select_miners(
            mg,
            sample_size=self.sample_size,
            include_validators=self.query_validators,
            exclude_hotkeys=exclude,
        )


@dataclass(frozen=True)
class RoundReport:
    """What one round did."""

    round_id: int
    n_queried: int
    n_ok: int
    n_btauth: int
    n_v10: int
    p50_ms: float | None
    p95_ms: float | None
    scores: dict[int, float] = field(default_factory=dict)
    weights: WeightDecision | None = None


LegacyFactory = Callable[[ValidatorSettings, HotkeySigner], tuple[Any, Any]]


class ValidatorRunner:
    """Runs a :class:`SubnetValidator` against the chain.

    Everything after ``settings`` is optional (tests pass ``FakeChain``,
    a test metagraph source, a dev keypair and an in-process transport).
    """

    def __init__(
        self,
        validator: SubnetValidator,
        settings: ValidatorSettings,
        *,
        gateway: ChainGateway | None = None,
        metagraph: MetagraphSource | None = None,
        hotkey: WalletLike | None = None,
        transport: Any = None,
        metrics: Metrics | None = None,
        store_path: Path | str | None = None,
        clock_ns: Callable[[], int] | None = None,
        legacy: LegacyFactory | None = None,
        check_sdk: bool = True,
    ) -> None:
        self.validator = validator
        self.settings = settings
        self.metrics = Metrics() if metrics is None else metrics
        self._gateway = gateway
        self._metagraph = metagraph
        self._hotkey = hotkey
        self._transport = transport
        self._store_path = store_path
        self._clock_ns = clock_ns
        self._legacy_factory = legacy
        self._check_sdk = check_sdk
        self._lock: HotkeyLock | None = None
        self._started = False
        self._last_round_at: float | None = None
        self._last_reprobe_block: int | None = None
        self.client: ValidatorClient | None = None
        self.store: ScoreStore | None = None
        self.weights: WeightScheduler | None = None
        self.hotkey_ss58: str | None = None

    @classmethod
    def from_env(
        cls,
        validator: SubnetValidator,
        env_file: str | Path | None = None,
        **kwargs: Any,
    ) -> ValidatorRunner:
        """Build a runner from ``TW_*`` variables (and ``env_file``)."""
        return cls(validator, ValidatorSettings.from_env(env_file), **kwargs)

    # ------------------------------------------------------------ startup

    @property
    def gateway(self) -> ChainGateway:
        """The chain gateway (after :meth:`start`)."""
        if self._gateway is None:
            raise RuntimeError("the validator has not started")
        return self._gateway

    @property
    def metagraph(self) -> MetagraphSource:
        """The metagraph source (after :meth:`start`)."""
        if self._metagraph is None:
            raise RuntimeError("the validator has not started")
        return self._metagraph

    async def start(self) -> None:
        """Load the hotkey, connect, check registration, open the store."""
        s = self.settings
        if self._check_sdk:
            report = check_sdk()
            if not report.tested:
                _log.warning("sdk_version_untested", version=report.version)
        for name in s.weakened_settings():
            _log.warning("unsafe_setting_active", setting=name)
        self.metrics.set_unsafe_settings(s.weakened_settings())
        hotkey = self._load_hotkey()
        nonce = None if self._clock_ns is None else MonotonicNonce(self._clock_ns)
        signer = RequestSigner(hotkey, nonce=nonce)
        raw = HotkeySigner(hotkey)
        if s.legacy_v10_client == "auto" and raw.scheme != "sr25519":
            # Spec 8.11.3: v10 Axons verify sr25519 only.
            raise StartupError(
                "TW_LEGACY_V10_CLIENT=auto needs an sr25519 validator hotkey "
                f"(this one is {raw.scheme}): v10 Axons verify sr25519 "
                "signatures only. Set TW_LEGACY_V10_CLIENT=off and unset "
                "TW_LEGACY_V10_CLIENT_UNTIL, or use an sr25519 hotkey"
            )
        self.hotkey_ss58 = signer.hotkey_ss58
        self._lock = HotkeyLock(s.state_dir, signer.hotkey_ss58)
        try:
            self._lock.acquire()
        except HotkeyLockHeld as exc:
            raise StartupError(str(exc)) from None
        try:
            await self._connect(hotkey)
            mg = self.metagraph.snapshot()
            if mg is None or mg.by_hotkey(signer.hotkey_ss58) is None:
                raise StartupError(
                    f"hotkey {signer.hotkey_ss58} is not registered on netuid "
                    f"{s.netuid}; register first: btcli tx burned-register --netuid "
                    f"{s.netuid} -w {s.wallet_name} -H {s.wallet_hotkey}",
                    exit_code=3,
                )
            self.client = self._build_client(signer, raw)
            path = self._store_path or (s.state_dir / "scores.db")
            self.store = ScoreStore(path, s.netuid, alpha=s.score_alpha)
            self.weights = WeightScheduler(
                self.gateway,
                s.netuid,
                signer.hotkey_ss58,
                min_interval_blocks=s.min_weight_interval_blocks,
                version_key=s.weights_version_key,
                mechid=s.mechid,
                store=self.store,
                metrics=self.metrics,
            )
        except BaseException:
            await self.stop()
            raise
        v = self.validator
        v.sample_size = s.sample_size
        v.query_validators = s.query_validators
        v.own_hotkey = signer.hotkey_ss58
        self._started = True
        _log.info("validator_ready", netuid=s.netuid, hotkey=signer.hotkey_ss58)

    def _load_hotkey(self) -> WalletLike:
        s = self.settings
        state = coldkey_state(s.wallet_path, s.wallet_name)
        if state is ColdkeyState.UNENCRYPTED and s.refuse_if_coldkey_present:
            raise StartupError(
                "an unencrypted coldkey is readable in "
                f"{s.wallet_path / s.wallet_name}; move it off this server "
                "(validators need the hotkey only), or set "
                "TW_REFUSE_IF_COLDKEY_PRESENT=0 (not recommended)"
            )
        if state is ColdkeyState.UNENCRYPTED:
            _log.warning("unencrypted_coldkey_present", wallet=s.wallet_name)
        if self._hotkey is not None:
            return self._hotkey
        keypair: WalletLike = load_hotkey(s.wallet_path, s.wallet_name, s.wallet_hotkey)
        return keypair

    async def _connect(self, hotkey: WalletLike) -> None:
        s = self.settings
        if self._gateway is None:
            self._gateway = BittensorGateway.from_settings(s, hotkey)
        if self._metagraph is None:
            self._metagraph = MetagraphCache.from_settings(
                self._gateway,
                s,
                on_refresh_failure=self.metrics.metagraph_refresh_failures.inc,
            )
        try:
            with anyio.fail_after(s.startup_timeout_s):
                await self._gateway.connect()
                await self._metagraph.start()
        except TimeoutError:
            raise StartupError(
                f"no metagraph within TW_STARTUP_TIMEOUT_S={s.startup_timeout_s:g}s"
            ) from None
        except GatewayError as exc:
            raise StartupError(f"chain unavailable at startup: {exc}") from None

    def _build_client(
        self, signer: RequestSigner, raw: HotkeySigner
    ) -> ValidatorClient:
        s = self.settings
        legacy: LegacyClientLike | None = None
        selector: ProtocolSelectorLike | None = None
        if s.legacy_v10_client == "auto":
            factory = self._legacy_factory or _bridge_client
            legacy, selector = factory(s, raw)
            _log.warning(
                "legacy_v10_outbound_enabled",
                until=str(s.legacy_v10_client_until),
                hint="v10 miners are reached until this date",
            )
        return ValidatorClient(
            signer,
            timeout_s=s.query_timeout_s,
            max_concurrency=s.max_concurrency,
            max_attempts=s.max_attempts,
            verify_responses=s.verify_responses,
            scheme_policy=s.scheme_policy,
            max_response_bytes=s.max_response_bytes,
            legacy=legacy,
            selector=selector,
            metrics=self.metrics,
            transport=self._transport,
        )

    async def stop(self) -> None:
        """Close the client, the store and the chain. Safe to call more than once."""
        self._started = False
        if self.client is not None:
            await self.client.aclose()
            self.client = None
        if self.store is not None:
            self.store.close()
            self.store = None
        if self._metagraph is not None:
            with contextlib.suppress(Exception):
                await self._metagraph.stop()
        if self._gateway is not None:
            with contextlib.suppress(Exception):
                await self._gateway.close()
        if self._lock is not None:
            self._lock.release()

    @contextlib.asynccontextmanager
    async def running(self) -> Any:
        """Start and stop around a block (tests, custom loops)."""
        await self.start()
        try:
            yield self
        finally:
            await self.stop()

    # ------------------------------------------------------------ rounds

    async def run_round(self, round_id: int | None = None) -> RoundReport | None:
        """Run one round. Returns ``None`` when there is no metagraph yet."""
        client, store, weights = self.client, self.store, self.weights
        if client is None or store is None or weights is None:
            raise RuntimeError("the validator has not started")
        mg = self.metagraph.snapshot()
        if mg is None:
            _log.warning("round_skipped", reason="no metagraph snapshot")
            return None
        started = time.perf_counter()
        hotkeys = {n.uid: n.hotkey for n in mg.neurons}
        for old in (
            await anyio.to_thread.run_sync(store.sync_hotkeys, hotkeys)
        ).values():
            client.forget(old)
        self._maybe_reprobe(mg)
        rid = (
            round_id
            if round_id is not None
            else await anyio.to_thread.run_sync(store.next_round_id)
        )
        miners = list(self.validator.select_miners(mg))
        task = await self.validator.make_task(rid)
        results = await client.query_many(
            miners,
            task.route,
            task.body,
            method="GET" if task.method == "GET" else "POST",
            idempotent=task.idempotent,
            response_model=task.response_model,
            legacy_synapse=task.legacy_synapse,
        )
        raw_scores = await self.validator.score(task, results) if results else {}
        scores = {
            uid: float(v)
            for uid, v in raw_scores.items()
            if uid in hotkeys and math.isfinite(float(v))
        }
        await anyio.to_thread.run_sync(store.update, scores, hotkeys, mg.block)
        report = self._report(rid, results, scores)
        await anyio.to_thread.run_sync(
            store.record_round,
            RoundRecord(
                time.time(), report.n_queried, report.n_ok, report.p50_ms, report.p95_ms
            ),
        )
        decision = await weights.maybe_submit(store.scores(), mg)
        self.metrics.validator_round_duration.observe(time.perf_counter() - started)
        self.metrics.validator_miners_by_protocol.labels(protocol="btauth/1").set(
            report.n_btauth
        )
        self.metrics.validator_miners_by_protocol.labels(protocol="v10").set(
            report.n_v10
        )
        self._last_round_at = time.monotonic()
        _log.info(
            "round ok",
            round_id=rid,
            n_queried=report.n_queried,
            n_ok=report.n_ok,
            n_btauth=report.n_btauth,
            n_v10=report.n_v10,
            p50_ms=report.p50_ms,
            p95_ms=report.p95_ms,
            weights=decision.reason,
        )
        return RoundReport(
            rid,
            report.n_queried,
            report.n_ok,
            report.n_btauth,
            report.n_v10,
            report.p50_ms,
            report.p95_ms,
            scores,
            decision,
        )

    def _maybe_reprobe(self, mg: MetagraphView) -> None:
        if self.client is None:
            return
        last = self._last_reprobe_block
        if last is None:
            self._last_reprobe_block = mg.block
        elif mg.block - last >= mg.tempo:
            self.client.reprobe()
            self._last_reprobe_block = mg.block

    @staticmethod
    def _report(
        rid: int, results: dict[int, MinerResult], scores: dict[int, float]
    ) -> RoundReport:
        latencies = sorted(
            r.latency_ms for r in results.values() if r.ok and r.latency_ms
        )
        p50 = statistics.median(latencies) if latencies else None
        p95 = (
            latencies[min(len(latencies) - 1, math.ceil(0.95 * len(latencies)) - 1)]
            if latencies
            else None
        )
        ok = [r for r in results.values() if r.ok]
        return RoundReport(
            rid,
            n_queried=len(results),
            n_ok=len(ok),
            n_btauth=sum(1 for r in ok if r.protocol == "btauth/1"),
            n_v10=sum(1 for r in ok if r.protocol == "v10"),
            p50_ms=p50,
            p95_ms=p95,
            scores=scores,
        )

    async def run_forever(self) -> None:
        """Run rounds every ``TW_ROUND_INTERVAL_S`` until cancelled."""
        interval = self.settings.round_interval_s
        while True:
            started = time.monotonic()
            try:
                await self.run_round()
            except Exception:  # noqa: BLE001 - a bad round must not stop the validator
                _log.exception("round_failed")
            await anyio.sleep(max(0.0, interval - (time.monotonic() - started)))

    # ------------------------------------------------------------ health

    def readiness(self) -> tuple[bool, list[str]]:
        """Ready, or the reasons it is not (fixed words, no configuration)."""
        if not self._started or self._metagraph is None:
            return False, ["starting"]
        reasons = []
        if self._metagraph.stage() is StalenessStage.KNOWN_CALLERS_ONLY:
            reasons.append("metagraph_stale")
        last = self._last_round_at
        if (
            last is not None
            and time.monotonic() - last > 3 * self.settings.round_interval_s
        ):
            reasons.append("rounds_stalled")
        if self.weights is not None and self.weights.stopped is not None:
            reasons.append("weights_stopped")
        return not reasons, reasons

    def health_app(self) -> Starlette:
        """``/healthz``, ``/readyz`` and ``/metrics`` for ``TW_METRICS_BIND``."""

        async def healthz(_: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})

        async def readyz(_: Request) -> JSONResponse:
            ready, reasons = self.readiness()
            if ready:
                return JSONResponse({"status": "ready"})
            return JSONResponse(
                {"status": "not_ready", "reasons": reasons}, status_code=503
            )

        async def metrics(_: Request) -> Response:
            return Response(
                self.metrics.render(), media_type="text/plain; version=0.0.4"
            )

        return Starlette(
            routes=[
                Route("/healthz", healthz),
                Route("/readyz", readyz),
                Route("/metrics", metrics),
            ]
        )

    # ------------------------------------------------------------ run

    def run(self) -> None:
        """Run until SIGINT/SIGTERM. Exit 3 when the hotkey is not registered."""
        configure_logging(self.settings.log_level)
        try:
            asyncio.run(self._serve())
        except KeyboardInterrupt:
            sys.exit(130)
        except StartupError as exc:
            _log.critical("startup_refused", reason=str(exc))
            sys.exit(exc.exit_code)
        except ConfigError as exc:
            _log.critical("config_invalid", reason=str(exc))
            sys.exit(2)

    async def _serve(self) -> None:
        await self.start()
        bind = self.settings.metrics_bind
        server = NoSignalServer(
            uvicorn.Config(
                self.health_app(),
                host=bind.host,
                port=bind.port,
                lifespan="off",
                log_config=None,
                access_log=False,
                server_header=False,
            )
        )
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        tasks = [
            loop.create_task(server.serve(), name="tensorwire-health"),
            loop.create_task(self.run_forever(), name="tensorwire-rounds"),
        ]
        try:
            await stop.wait()
        finally:
            server.should_exit = True
            tasks[1].cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await tasks[1]
            with contextlib.suppress(Exception):
                await tasks[0]
            await self.stop()
            _log.info("validator_stopped")


def _bridge_client(
    settings: ValidatorSettings, signer: HotkeySigner
) -> tuple[LegacyClientLike, ProtocolSelectorLike]:
    """The bridge's ``LegacyClient`` and ``ProtocolSelector`` (v10 ``auto``)."""
    try:
        module: Any = importlib.import_module("tensorwire.extensions.legacy_v10.client")
    except ImportError:
        module = None
    client_cls = getattr(module, "LegacyClient", None)
    selector_cls = getattr(module, "ProtocolSelector", None)
    if client_cls is None or selector_cls is None:
        raise StartupError(
            "TW_LEGACY_V10_CLIENT=auto but the legacy v10 bridge is not in this build"
        )
    until = settings.legacy_v10_client_until
    return client_cls(signer), selector_cls(settings.protocol_tag, until=until)
