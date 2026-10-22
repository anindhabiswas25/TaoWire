"""Miner startup, background tasks, readiness and shutdown (spec 8.7.3).

Startup, in order:

1. Settings are already validated (``MinerSettings``). Check the installed
   SDK; log every active weakening setting at WARNING and export
   ``tw_unsafe_settings_active``.
2. Refuse to start if an unencrypted coldkey is readable in the wallet
   directory (``TW_REFUSE_IF_COLDKEY_PRESENT=1``); warn if an encrypted one
   is there. Load the hotkey only.
3. Connect the chain gateway and fetch the first metagraph (blocking, at
   most ``TW_STARTUP_TIMEOUT_S``).
4. Exit with code 3 if our hotkey is not registered on ``TW_NETUID``.
5. Build the nonce store, verifier, caller gate and per-hotkey limiter; refuse
   a per-process nonce store when several workers or instances run.
6. Check the clock against NTP.
7. Publish the axon if the on-chain one differs from
   ``TW_EXTERNAL_IP:TW_EXTERNAL_PORT`` (only when ``TW_AUTO_SERVE_AXON=1`` and
   ``TW_AXON_PUBLISHER=1``). ``rate_limited`` is retried after the serving
   rate limit.
8. Start background tasks: clock check (10 min), axon drift check (30 min),
   metagraph gauges.
9. Mark ready.

Shutdown cancels the background tasks and closes the metagraph source, the
gateway and the nonce store. Draining in-flight requests is the server's job
(``Miner.run`` gives uvicorn ``TW_DRAIN_S`` for it).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

import anyio
import anyio.to_thread
import structlog

from tensorwire.auth.clock import ClockGuard, ClockReading, NtpQuery
from tensorwire.auth.keys import (
    ColdkeyState,
    WalletLike,
    coldkey_state,
    load_hotkey,
)
from tensorwire.auth.nonce_store import MemoryNonceStore, NonceStore, RedisNonceStore
from tensorwire.auth.sdk_check import check_sdk
from tensorwire.auth.verifier import RequestVerifier
from tensorwire.chain import gateway as gateway_module
from tensorwire.chain import metagraph_cache as cache_module
from tensorwire.chain.axon import Endpoint
from tensorwire.chain.gateway import ChainGateway, GatewayError
from tensorwire.chain.metagraph_cache import MetagraphSource, StalenessStage
from tensorwire.config import MinerSettings
from tensorwire.crypto import HotkeySigner
from tensorwire.errors import StartupError
from tensorwire.limits.ratelimit import MemoryRateLimiter, RateLimiter
from tensorwire.observability.metrics import Metrics
from tensorwire.policy.caller import CallerGate

__all__ = [
    "AXON_DRIFT_INTERVAL_S",
    "DEGRADED_WARN_INTERVAL_S",
    "SERVING_RATE_LIMIT_BLOCKS",
    "Lifecycle",
    "MinerParts",
    "Readiness",
    "Runtime",
]

#: Axon drift check period (spec 8.7.3 step 8).
AXON_DRIFT_INTERVAL_S = 1800.0
#: Blocks to wait after a ``rate_limited`` ServeAxon (mainnet ``serving_rate_limit``).
SERVING_RATE_LIMIT_BLOCKS = 50
#: Seconds between two "metagraph degraded" warnings (spec 8.5.1).
DEGRADED_WARN_INTERVAL_S = 300.0
_GAUGE_INTERVAL_S = 5.0

_log = structlog.stdlib.get_logger(__name__)


@dataclass
class MinerParts:
    """Injectable dependencies. ``None`` = build the production default.

    Tests pass ``FakeChain``, a test ``MetagraphSource``, a dev ``Keypair``
    and a ``FakeClock``.
    """

    gateway: ChainGateway | None = None
    metagraph: MetagraphSource | None = None
    hotkey: WalletLike | None = None
    nonce_store: NonceStore | None = None
    clock_ns: Callable[[], int] | None = None
    monotonic: Callable[[], float] = time.monotonic
    ntp_query: NtpQuery | None = None
    check_sdk: bool = True
    axon_retry_poll_s: float = 12.0


@dataclass(frozen=True, slots=True)
class Readiness:
    """``/readyz``: ready, or the reasons it is not; soft problems in ``degraded``."""

    ready: bool
    reasons: tuple[str, ...] = ()
    degraded: tuple[str, ...] = ()


@dataclass
class Runtime:
    """What the request path needs, available once startup reached step 5."""

    hotkey_ss58: str
    gateway: ChainGateway
    metagraph: MetagraphSource
    store: NonceStore
    store_backend: str
    verifier: RequestVerifier
    gate: CallerGate
    hotkey_limiter: RateLimiter
    clock: ClockGuard
    axon_in_sync: bool | None = None
    tasks: list[asyncio.Task[None]] = field(default_factory=list)


def _same_host(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a == b


def _real_chain(
    settings: MinerSettings,
    hotkey: WalletLike,
    metrics: Metrics,
    gateway: ChainGateway | None,
) -> tuple[ChainGateway, MetagraphSource]:
    """Build the production ``BittensorGateway`` / ``MetagraphCache`` from settings.

    Both classes are Engineer B's (``chain/``); a given ``gateway`` is reused.
    """
    gateway_cls: Any = getattr(gateway_module, "BittensorGateway", None)
    cache_cls: Any = getattr(cache_module, "MetagraphCache", None)
    if (gateway is None and gateway_cls is None) or cache_cls is None:
        raise StartupError(
            "the real chain gateway is not in this build; pass gateway= and "
            "metagraph= to Miner"
        )
    if gateway is None:
        gateway = gateway_cls.from_settings(settings, hotkey)
    cache: MetagraphSource = cache_cls.from_settings(
        gateway, settings, on_refresh_failure=metrics.metagraph_refresh_failures.inc
    )
    return gateway, cache


class Lifecycle:
    """Runs startup and shutdown for one miner process and reports readiness."""

    def __init__(
        self, settings: MinerSettings, metrics: Metrics, parts: MinerParts
    ) -> None:
        self.settings = settings
        self.metrics = metrics
        self.parts = parts
        self._runtime: Runtime | None = None
        self._ready = False
        self._stopping = False
        self._last_degraded_warning: float | None = None

    @property
    def runtime(self) -> Runtime:
        """The running parts. ``RuntimeError`` before startup."""
        if self._runtime is None:
            raise RuntimeError("the miner has not started")
        return self._runtime

    @property
    def ready(self) -> bool:
        """Whether startup completed and shutdown has not begun."""
        return self._ready and not self._stopping

    # ------------------------------------------------------------ startup

    async def start(self) -> None:
        """Run startup steps 1-9. Raises :class:`StartupError` on refusal."""
        s = self.settings
        self._check_sdk_and_settings()
        hotkey = self._load_keys()
        signer = HotkeySigner(hotkey)
        if self.parts.metagraph is None:
            gateway, metagraph = _real_chain(
                s, hotkey, self.metrics, self.parts.gateway
            )
        elif self.parts.gateway is None:
            raise StartupError("a metagraph source was given without its gateway")
        else:
            gateway, metagraph = self.parts.gateway, self.parts.metagraph
        await self._connect(gateway, metagraph)
        mg = metagraph.snapshot()
        if mg is None or mg.by_hotkey(signer.ss58_address) is None:
            await self._close_chain(gateway, metagraph)
            raise StartupError(
                f"hotkey {signer.ss58_address} is not registered on netuid "
                f"{s.netuid}; register first: btcli tx burned-register --netuid "
                f"{s.netuid} -w {s.wallet_name} -H {s.wallet_hotkey}",
                exit_code=3,
            )
        try:
            runtime = self._build_runtime(signer.ss58_address, gateway, metagraph)
        except BaseException:
            await self._close_chain(gateway, metagraph)
            raise
        self._runtime = runtime
        await runtime.clock.check_async()
        await self.sync_axon()
        self._update_gauges()
        runtime.tasks += [
            self._spawn(runtime.clock.run(), "clock"),
            self._spawn(self._axon_drift_loop(), "axon_drift"),
            self._spawn(self._gauge_loop(), "gauges"),
        ]
        self._ready = True
        _log.info(
            "miner_ready",
            netuid=s.netuid,
            hotkey=signer.ss58_address,
            external=f"{s.external_ip}:{s.effective_external_port}",
        )

    def _check_sdk_and_settings(self) -> None:
        if self.parts.check_sdk:
            report = check_sdk()
            if not report.tested:
                _log.warning(
                    "sdk_version_untested",
                    version=report.version,
                    hint="inside the supported range but not in the tested list",
                )
        weakened = self.settings.weakened_settings()
        for name in weakened:
            _log.warning("unsafe_setting_active", setting=name)
        self.metrics.set_unsafe_settings(weakened)

    def _load_keys(self) -> WalletLike:
        s = self.settings
        state = coldkey_state(s.wallet_path, s.wallet_name)
        if state is ColdkeyState.UNENCRYPTED and s.refuse_if_coldkey_present:
            raise StartupError(
                "an unencrypted coldkey is readable in "
                f"{s.wallet_path / s.wallet_name}; "
                "move the coldkey off this server (miners need the hotkey only), "
                "or set TW_REFUSE_IF_COLDKEY_PRESENT=0 (not recommended)"
            )
        if state is ColdkeyState.UNENCRYPTED:
            _log.warning("unencrypted_coldkey_present", wallet=s.wallet_name)
        elif state is ColdkeyState.ENCRYPTED:
            _log.warning(
                "coldkey_present",
                wallet=s.wallet_name,
                hint="encrypted; still better kept off servers",
            )
        if self.parts.hotkey is not None:
            return self.parts.hotkey
        keypair: WalletLike = load_hotkey(s.wallet_path, s.wallet_name, s.wallet_hotkey)
        return keypair

    async def _connect(self, gateway: ChainGateway, metagraph: MetagraphSource) -> None:
        timeout = self.settings.startup_timeout_s
        try:
            with anyio.fail_after(timeout):
                await gateway.connect()
                await metagraph.start()
        except TimeoutError:
            await self._close_chain(gateway, metagraph)
            raise StartupError(
                f"no metagraph within TW_STARTUP_TIMEOUT_S={timeout:g}s; "
                "check TW_NETWORK and TW_CHAIN_FALLBACKS"
            ) from None
        except GatewayError as exc:
            await self._close_chain(gateway, metagraph)
            raise StartupError(f"chain unavailable at startup: {exc}") from None

    @staticmethod
    async def _close_chain(gateway: ChainGateway, metagraph: MetagraphSource) -> None:
        with contextlib.suppress(Exception):
            await metagraph.stop()
        with contextlib.suppress(Exception):
            await gateway.close()

    def _build_runtime(
        self, hotkey_ss58: str, gateway: ChainGateway, metagraph: MetagraphSource
    ) -> Runtime:
        s = self.settings
        store = self.parts.nonce_store
        if store is None:
            store = (
                RedisNonceStore(
                    s.redis_url.get_secret_value(), retention=s.nonce_retention_s
                )
                if s.redis_url is not None
                else MemoryNonceStore(s.nonce_retention_s, clock=self.parts.monotonic)
            )
        backend = "memory" if isinstance(store, MemoryNonceStore) else "redis"
        multi = s.workers > 1 or s.instance_count > 1
        if backend == "memory" and multi:
            if not s.unsafe_allow_memory_nonce_multiworker:
                raise StartupError(
                    "a per-process nonce store with TW_WORKERS > 1 or "
                    "TW_INSTANCE_COUNT > 1 lets replays through; set TW_REDIS_URL "
                    "(spec 8.4.3)"
                )
            _log.warning(
                "memory_nonce_store_multiworker",
                hint="replays across workers/instances are NOT detected",
            )
        if multi:
            _log.warning(
                "per_process_rate_limits",
                hint="rate limits apply per worker/instance until the Redis "
                "limiter is configured",
            )
        verifier = RequestVerifier(
            hotkey_ss58,
            store,
            max_age=s.auth_max_age_s,
            allowed_skew=s.auth_allowed_skew_s,
            now_ns=self.parts.clock_ns,
        )
        clock = ClockGuard(
            s.ntp_servers,
            allowed_skew_s=s.auth_allowed_skew_s,
            query=self.parts.ntp_query,
            on_reading=self._on_clock_reading,
        )
        return Runtime(
            hotkey_ss58=hotkey_ss58,
            gateway=gateway,
            metagraph=metagraph,
            store=store,
            store_backend=backend,
            verifier=verifier,
            gate=CallerGate(
                metagraph, strict=s.metagraph_strict, clock=self.parts.monotonic
            ),
            hotkey_limiter=MemoryRateLimiter(
                rate=s.rate_hotkey_per_s,
                burst=s.rate_hotkey_burst,
                clock=self.parts.monotonic,
            ),
            clock=clock,
        )

    def _on_clock_reading(self, reading: ClockReading) -> None:
        offset = reading.offset_s
        self.metrics.clock_offset.set(float("nan") if offset is None else offset)

    @staticmethod
    def _spawn(coro: Coroutine[Any, Any, None], name: str) -> asyncio.Task[None]:
        return asyncio.get_running_loop().create_task(coro, name=f"tensorwire-{name}")

    # ------------------------------------------------------------ axon

    def _axon_matches(self) -> bool:
        rt = self.runtime
        s = self.settings
        mg = rt.metagraph.snapshot()
        me = None if mg is None else mg.by_hotkey(rt.hotkey_ss58)
        axon: Endpoint | None = None if me is None else me.axon
        return (
            me is not None
            and axon is not None
            and _same_host(axon.host, s.external_ip)
            and axon.port == s.effective_external_port
            and me.axon_protocol == s.protocol_tag
        )

    async def sync_axon(self) -> bool:
        """Publish our axon if the chain shows something else. Returns in-sync."""
        rt = self.runtime
        s = self.settings
        if self._axon_matches():
            rt.axon_in_sync = True
            return True
        if not (s.auto_serve_axon and s.axon_publisher):
            _log.warning(
                "axon_differs_from_config",
                external=f"{s.external_ip}:{s.effective_external_port}",
                hint="publishing is off (TW_AUTO_SERVE_AXON / TW_AXON_PUBLISHER)",
            )
            rt.axon_in_sync = False
            return False
        try:
            outcome = await rt.gateway.serve_axon(
                s.netuid,
                s.external_ip,
                s.effective_external_port,
                tls_cert_hex=None,
                protocol_tag=s.protocol_tag,
            )
        except GatewayError as exc:
            _log.error("serve_axon_failed", error=str(exc))
            rt.axon_in_sync = False
            return False
        if outcome.ok:
            _log.info(
                "axon_published",
                external=f"{s.external_ip}:{s.effective_external_port}",
                protocol=s.protocol_tag,
                block_hash=outcome.block_hash,
            )
            rt.axon_in_sync = True
            with contextlib.suppress(GatewayError):
                await rt.metagraph.refresh_now()
            return True
        rt.axon_in_sync = False
        if outcome.code == "rate_limited":
            _log.warning(
                "serve_axon_rate_limited",
                remediation=outcome.remediation,
                retry_after_blocks=SERVING_RATE_LIMIT_BLOCKS,
            )
            rt.tasks.append(self._spawn(self._retry_axon_later(), "axon_retry"))
        else:
            _log.error(
                "serve_axon_rejected",
                code=outcome.code,
                remediation=outcome.remediation,
            )
        return False

    async def _retry_axon_later(self) -> None:
        rt = self.runtime
        try:
            target = await rt.gateway.block() + SERVING_RATE_LIMIT_BLOCKS
            # Polls a remote value (the block height); there is no event to wait on.
            while await rt.gateway.block() < target:  # noqa: ASYNC110
                await anyio.sleep(self.parts.axon_retry_poll_s)
        except GatewayError as exc:
            _log.warning("axon_retry_deferred", error=str(exc))
            return  # the drift check tries again later
        await self.sync_axon()

    async def _axon_drift_loop(self) -> None:
        while True:
            await anyio.sleep(AXON_DRIFT_INTERVAL_S)
            await self.sync_axon()

    # ------------------------------------------------------------ readiness

    def _update_gauges(self) -> None:
        source = self.runtime.metagraph
        age = source.age_s()
        stage = source.stage()
        self.metrics.metagraph_age.set(float("nan") if age is None else age)
        self.metrics.metagraph_degraded.set(int(stage))
        if stage is StalenessStage.DEGRADED:
            now = self.parts.monotonic()
            last = self._last_degraded_warning
            if last is None or now - last >= DEGRADED_WARN_INTERVAL_S:
                self._last_degraded_warning = now
                _log.warning(
                    "metagraph_degraded",
                    age_s=age,
                    max_age_s=source.thresholds.max_age_s,
                    hint="serving on the last snapshot; check TW_CHAIN_FALLBACKS",
                )

    async def _gauge_loop(self) -> None:
        while True:
            await anyio.sleep(_GAUGE_INTERVAL_S)
            self._update_gauges()

    async def readiness(self) -> Readiness:
        """The ``/readyz`` verdict (spec 8.7.4). Reasons never reveal configuration."""
        if self._runtime is None or not self._ready:
            return Readiness(False, ("starting",))
        if self._stopping:
            return Readiness(False, ("stopping",))
        rt = self._runtime
        self._update_gauges()
        reasons: list[str] = []
        degraded: list[str] = []
        mg = rt.metagraph.snapshot()
        if mg is not None and mg.by_hotkey(rt.hotkey_ss58) is None:
            reasons.append("not_registered")
        stage = rt.metagraph.stage()
        if stage is StalenessStage.KNOWN_CALLERS_ONLY:
            reasons.append("metagraph_stale")
        elif stage is StalenessStage.DEGRADED:
            degraded.append("metagraph_stale")
        ping = getattr(rt.store, "ping", None)
        if ping is not None and not await anyio.to_thread.run_sync(ping):
            reasons.append("nonce_store_unreachable")
        if rt.clock.skewed:
            reasons.append("clock_skew")
        if rt.axon_in_sync is False:
            degraded.append("axon_not_published")
        return Readiness(not reasons, tuple(reasons), tuple(degraded))

    # ------------------------------------------------------------ shutdown

    async def stop(self) -> None:
        """Stop background tasks and close the chain and the nonce store.

        Safe to call more than once.
        """
        if self._stopping:
            return
        self._stopping = True
        rt = self._runtime
        if rt is None:
            return
        for task in rt.tasks:
            task.cancel()
        for task in rt.tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        rt.tasks.clear()
        await self._close_chain(rt.gateway, rt.metagraph)
        close = getattr(rt.store, "close", None)
        if close is not None:
            with contextlib.suppress(Exception):
                close()
        _log.info("miner_stopped")
