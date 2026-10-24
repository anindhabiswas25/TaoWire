"""The sidecar process (spec 11.6): ``tensorwire sidecar``.

:class:`Sidecar` loads the miner's hotkey (``TW_WALLET_*``, with the miner's
coldkey rule), the bearer token, the chain gateway and the metagraph cache
(ADR-0001: every chain call goes through ``chain/gateway.py``), then serves the
app of :mod:`tensorwire.sidecar.app` on ``host:TW_SIDECAR_PORT``. The host
must be ``127.0.0.1`` or ``::1``; anything else is refused unless
``TW_SIDECAR_UNSAFE_BIND=1`` (logged at WARNING and exported in
``tw_unsafe_settings_active``). Metrics are served on ``TW_METRICS_BIND``.

Tests and the cross-language checks pass ``gateway`` / ``metagraph`` /
``hotkey`` (a ``FakeChain``) to run without a chain.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable, Iterator

import anyio
import structlog
import uvicorn
from starlette.types import ASGIApp

from tensorwire.auth.keys import ColdkeyState, WalletLike, coldkey_state, load_hotkey
from tensorwire.chain.gateway import BittensorGateway, ChainGateway, GatewayError
from tensorwire.chain.metagraph_cache import MetagraphCache, MetagraphSource
from tensorwire.config import SidecarSettings
from tensorwire.crypto import HotkeySigner
from tensorwire.errors import StartupError
from tensorwire.observability.metrics import Metrics
from tensorwire.policy.caller import CallerGate, CallerPolicy
from tensorwire.sidecar.app import create_app
from tensorwire.sidecar.token import load_or_create_token

__all__ = ["LOOPBACK_HOSTS", "Sidecar"]

#: The only addresses the sidecar binds to without ``TW_SIDECAR_UNSAFE_BIND``.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})

_log = structlog.stdlib.get_logger("tensorwire.sidecar")


class _MetricsServer(uvicorn.Server):
    """The metrics server runs beside the main one: it leaves signals to it."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        """No signal handling: the sidecar's main server owns it."""
        yield


class Sidecar:
    """The sidecar: settings, hotkey, token, chain, app (see the module docstring)."""

    def __init__(
        self,
        settings: SidecarSettings | None = None,
        *,
        host: str = "127.0.0.1",
        port: int | None = None,
        gateway: ChainGateway | None = None,
        metagraph: MetagraphSource | None = None,
        hotkey: WalletLike | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        self.settings = SidecarSettings.from_env() if settings is None else settings
        self.host = host
        self.port = self.settings.sidecar_port if port is None else port
        self.metrics = Metrics() if metrics is None else metrics
        self._gateway = gateway
        self._metagraph = metagraph
        self._hotkey = hotkey
        self._app: ASGIApp | None = None
        self.token_created = False

    # ------------------------------------------------------------ startup

    def check_bind(self) -> None:
        """Refuse a non-loopback host unless ``TW_SIDECAR_UNSAFE_BIND=1``."""
        if self.host in LOOPBACK_HOSTS:
            return
        if not self.settings.sidecar_unsafe_bind:
            raise StartupError(
                f"the sidecar binds to loopback only (127.0.0.1 or ::1), not "
                f"{self.host!r}; set TW_SIDECAR_UNSAFE_BIND=1 to override (unsafe: "
                "the token and the chain writes are then reachable from the network)"
            )
        _log.warning("sidecar_unsafe_bind", host=self.host)

    def _report_unsafe(self) -> None:
        weakened = self.settings.weakened_settings()
        for name in weakened:
            _log.warning("unsafe_setting_active", setting=name)
        self.metrics.set_unsafe_settings(weakened)

    def _load_hotkey(self) -> WalletLike:
        s = self.settings
        state = coldkey_state(s.wallet_path, s.wallet_name)
        if state is ColdkeyState.UNENCRYPTED and s.refuse_if_coldkey_present:
            raise StartupError(
                "an unencrypted coldkey is readable in "
                f"{s.wallet_path / s.wallet_name}; move it off this server (the "
                "sidecar needs the hotkey only), or set TW_REFUSE_IF_COLDKEY_PRESENT=0"
            )
        if state is ColdkeyState.UNENCRYPTED:
            _log.warning("unencrypted_coldkey_present", wallet=s.wallet_name)
        if self._hotkey is not None:
            return self._hotkey
        hotkey: WalletLike = load_hotkey(s.wallet_path, s.wallet_name, s.wallet_hotkey)
        return hotkey

    async def start(self) -> None:
        """Run every startup check, connect, and build the app.

        Raises :class:`StartupError` (bind, coldkey, hotkey, token, chain).
        """
        self.check_bind()
        self._report_unsafe()
        s = self.settings
        hotkey = self._load_hotkey()
        path = s.effective_token_file
        token, self.token_created = load_or_create_token(path)
        if self.token_created:
            _log.info("sidecar_token_created", path=str(path))
        gateway = self._gateway
        if gateway is None:
            gateway = BittensorGateway.from_settings(s, hotkey)
        metagraph = self._metagraph
        if metagraph is None:
            metagraph = MetagraphCache.from_settings(
                gateway,
                s,
                on_refresh_failure=self.metrics.metagraph_refresh_failures.inc,
            )
        try:
            with anyio.fail_after(s.startup_timeout_s):
                await gateway.connect()
                await metagraph.start()
        except TimeoutError:
            raise StartupError(
                f"no metagraph within TW_STARTUP_TIMEOUT_S={s.startup_timeout_s:g}s; "
                "check TW_NETWORK and TW_CHAIN_FALLBACKS"
            ) from None
        except GatewayError as exc:
            raise StartupError(f"chain unavailable at startup: {exc}") from None
        self._gateway, self._metagraph = gateway, metagraph
        gate = CallerGate(metagraph, strict=s.metagraph_strict)
        hotkey_ss58 = HotkeySigner(hotkey).ss58_address
        self._app = create_app(
            settings=s,
            gateway=gateway,
            metagraph=metagraph,
            gate=gate,
            policy=CallerPolicy.from_settings(s),
            hotkey_ss58=hotkey_ss58,
            token=token,
        )
        _log.info(
            "sidecar_started",
            host=self.host,
            port=self.port,
            netuid=s.netuid,
            hotkey=hotkey_ss58,
            token_file=str(path),
        )

    async def stop(self) -> None:
        """Stop the metagraph refresh and close the gateway (safe to repeat)."""
        if self._metagraph is not None:
            with contextlib.suppress(Exception):
                await self._metagraph.stop()
        if self._gateway is not None:
            with contextlib.suppress(Exception):
                await self._gateway.close()

    @property
    def app(self) -> ASGIApp:
        """The ASGI app (after :meth:`start`)."""
        if self._app is None:
            raise RuntimeError("call start() first")
        return self._app

    # ------------------------------------------------------------ serving

    def uvicorn_config(self, app: ASGIApp | None = None) -> uvicorn.Config:
        """uvicorn: the bind, keep-alive 5 s, 16 KiB headers, 64 connections."""
        return uvicorn.Config(
            self.app if app is None else app,
            host=self.host,
            port=self.port,
            lifespan="off",
            log_config=None,
            access_log=False,
            server_header=False,
            timeout_keep_alive=5,
            h11_max_incomplete_event_size=16 * 1024,
            limit_concurrency=64,
        )

    async def serve(
        self, *, on_server: Callable[[uvicorn.Server], None] | None = None
    ) -> None:
        """Start, serve the app and the metrics until stopped, then stop.

        ``on_server`` receives the main server (tests set ``should_exit``).
        """
        await self.start()
        bind = self.settings.metrics_bind
        metrics = _MetricsServer(
            uvicorn.Config(
                self.metrics.asgi_app(),
                host=bind.host,
                port=bind.port,
                lifespan="off",
                log_config=None,
                access_log=False,
                server_header=False,
            )
        )
        server = uvicorn.Server(self.uvicorn_config())
        if on_server is not None:
            on_server(server)
        metrics_task = asyncio.get_running_loop().create_task(metrics.serve())
        try:
            await server.serve()
        finally:
            metrics.should_exit = True
            await metrics_task
            await self.stop()

    def run(self) -> None:
        """Blocking ``serve()`` (the CLI)."""
        asyncio.run(self.serve())
