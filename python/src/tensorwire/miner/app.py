"""The ``Miner``: route registration, the FastAPI app, and running it (spec 8.7.1).

Example::

    from pydantic import BaseModel
    from tensorwire import Miner, RouteContext

    class TransformRequest(BaseModel):
        text: str

    class TransformResponse(BaseModel):
        result: str

    miner = Miner.from_env()

    @miner.route("/v1/transform", request=TransformRequest,
                 response=TransformResponse, timeout_s=5.0, max_body_bytes=64_000)
    async def transform(req: TransformRequest, ctx: RouteContext) -> TransformResponse:
        return TransformResponse(result=req.text.upper())

    if __name__ == "__main__":
        miner.run()

Every route registered with :meth:`Miner.route` is protected: btauth/1,
caller policy, size and rate limits, in the order of spec 5.3. ``miner.app``
is a normal FastAPI app; routes added to it directly are **not** protected
by the kit.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any, Literal, TypeVar

import structlog
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from tensorwire.auth.clock import NtpQuery
from tensorwire.auth.keys import WalletLike
from tensorwire.auth.nonce_store import NonceStore
from tensorwire.chain.gateway import ChainGateway
from tensorwire.chain.metagraph_cache import MetagraphSource
from tensorwire.config import MinerSettings
from tensorwire.errors import ConfigError, StartupError
from tensorwire.limits.body import BodySizeLimit
from tensorwire.limits.ratelimit import PreAuthRateLimit, RateDecision, RateLimiter
from tensorwire.miner.health import health_routes
from tensorwire.miner.legacy import LegacyServerFactory
from tensorwire.miner.lifecycle import Lifecycle, MinerParts
from tensorwire.miner.pipeline import RouteEndpoint
from tensorwire.miner.protocol import MAX_HEADER_BYTES, guarded_protocol
from tensorwire.miner.routes import Handler, Route, RouteRegistry
from tensorwire.observability.logging import configure_logging
from tensorwire.observability.metrics import MULTIPROC_ENV, Metrics, serve_multiprocess
from tensorwire.observability.middleware import RequestContext
from tensorwire.policy.caller import CallerPolicy

__all__ = ["DEFAULT_LIMIT_CONCURRENCY", "MAX_HEADER_BYTES", "Miner", "NoSignalServer"]

#: uvicorn ``--limit-concurrency``: connections beyond this get 503 at once.
DEFAULT_LIMIT_CONCURRENCY = 1024
_KEEP_ALIVE_S = 5

_H = TypeVar("_H", bound=Handler)


class NoSignalServer(uvicorn.Server):
    """A uvicorn server that leaves signal handling to its owner (side listeners)."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


_log = structlog.stdlib.get_logger(__name__)


class _LifecycleIpLimiter:
    """The pre-auth limiter the lifecycle builds at startup (memory or Redis)."""

    def __init__(self, lifecycle: Lifecycle) -> None:
        self._lifecycle = lifecycle

    async def acquire(self, key: str) -> RateDecision:
        return await self._lifecycle.acquire_ip(key)


class Miner:
    """A TensorWire miner: protected routes plus the startup lifecycle.

    Everything after ``settings`` is optional and only needed in tests or
    special deployments; by default the miner loads its hotkey from the
    wallet directory and talks to the chain set in ``TW_NETWORK``.
    """

    def __init__(
        self,
        settings: MinerSettings,
        *,
        gateway: ChainGateway | None = None,
        metagraph: MetagraphSource | None = None,
        hotkey: WalletLike | None = None,
        nonce_store: NonceStore | None = None,
        clock_ns: Callable[[], int] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        ntp_query: NtpQuery | None = None,
        metrics: Metrics | None = None,
        check_sdk: bool = True,
        legacy_server: LegacyServerFactory | None = None,
        ip_limiter: RateLimiter | None = None,
        hotkey_limiter: RateLimiter | None = None,
    ) -> None:
        self.settings = settings
        self.metrics = Metrics() if metrics is None else metrics
        self.routes = RouteRegistry()
        self.default_policy = CallerPolicy.from_settings(settings)
        self._monotonic = monotonic
        self.lifecycle = Lifecycle(
            settings,
            self.metrics,
            MinerParts(
                gateway=gateway,
                metagraph=metagraph,
                hotkey=hotkey,
                nonce_store=nonce_store,
                clock_ns=clock_ns,
                monotonic=monotonic,
                ntp_query=ntp_query,
                check_sdk=check_sdk,
                legacy_server=legacy_server,
                ip_limiter=ip_limiter,
                hotkey_limiter=hotkey_limiter,
            ),
        )
        self._app: FastAPI | None = None

    @classmethod
    def from_env(cls, env_file: str | Path | None = None, **kwargs: Any) -> Miner:
        """Build a miner from ``TW_*`` variables (and ``env_file``)."""
        return cls(MinerSettings.from_env(env_file), **kwargs)

    # ------------------------------------------------------------ routes

    def route(
        self,
        path: str,
        *,
        request: type[BaseModel] | None = None,
        response: type[BaseModel] | None = None,
        method: Literal["POST", "GET"] = "POST",
        timeout_s: float | None = None,
        max_body_bytes: int | None = None,
        policy: CallerPolicy | None = None,
        legacy_synapse: type[BaseModel] | None = None,
        legacy_body_hash: Callable[[bytes], str] | None = None,
        encode: Callable[[Any], bytes] | None = None,
    ) -> Callable[[_H], _H]:
        """Register a protected route (decorator).

        ``timeout_s`` and ``max_body_bytes`` default to ``TW_HANDLER_TIMEOUT_S``
        and ``TW_MAX_BODY_BYTES``. ``policy`` defaults to the strict policy
        from settings; ``TW_DENY_HOTKEYS`` applies to every route either way.

        While ``TW_LEGACY_V10_UNTIL`` is set, a route with ``legacy_synapse``
        (a ``tensorwire.compat.Synapse`` subclass) or ``legacy_body_hash``
        also accepts v10 Dendrite requests (spec 8.11.2). They arrive at
        ``/<SynapseName>``; that path is mounted for them when it differs
        from ``path``. ``encode`` replaces the default response encoding.
        """
        chosen = self.default_policy if policy is None else policy

        def register(handler: _H) -> _H:
            self.routes.add(
                path,
                handler,
                method=method,
                request=request,
                response=response,
                timeout_s=self.settings.handler_timeout_s
                if timeout_s is None
                else timeout_s,
                max_body_bytes=self.settings.max_body_bytes
                if max_body_bytes is None
                else max_body_bytes,
                policy=chosen.with_denied(self.settings.deny_hotkeys),
                legacy_synapse=legacy_synapse,
                legacy_body_hash=legacy_body_hash,
                encode=encode,
            )
            return handler

        return register

    # ------------------------------------------------------------ app

    @property
    def app(self) -> FastAPI:
        """The FastAPI app. Built on first access; register routes before that."""
        if self._app is None:
            self._app = self._build_app()
        return self._app

    def _build_app(self) -> FastAPI:
        self.routes.freeze()
        app = FastAPI(
            lifespan=self._lifespan,
            openapi_url=None,
            docs_url=None,
            redoc_url=None,
        )
        for route in health_routes(self.lifecycle):
            app.router.routes.append(route)
        for kit_route in self.routes:
            self._mount(app, kit_route)
        s = self.settings
        largest = max([s.max_body_bytes, *(r.max_body_bytes for r in self.routes)])
        # add_middleware wraps: the last one added runs first (spec 5.3 steps
        # 1-3). The per-IP limit is outermost, so a flood is refused before
        # anything else runs; it counts and logs its own refusals.
        app.add_middleware(BodySizeLimit, max_bytes=largest)
        app.add_middleware(
            RequestContext,
            metrics=self.metrics,
            log_full_hotkeys=lambda: s.log_level == "DEBUG",
        )
        app.add_middleware(
            PreAuthRateLimit,
            limiter=_LifecycleIpLimiter(self.lifecycle),
            trusted_proxies=s.trusted_proxies,
            passthrough_on_failure=frozenset({"/healthz", "/readyz"}),
            metrics=self.metrics,
        )
        return app

    def _mount(self, app: FastAPI, route: Route) -> None:
        endpoint = RouteEndpoint(route, self.lifecycle, self.metrics)
        app.router.add_route(
            route.path,
            endpoint.endpoint,
            methods=[route.method],
            include_in_schema=False,
        )
        if route.legacy_synapse is None:
            return
        alias = "/" + route.legacy_synapse.__name__
        if alias == route.path:
            return
        if self.routes.get(alias) is not None:
            raise ValueError(
                f"{alias} is both a route and the v10 path of {route.path}"
            )
        legacy = RouteEndpoint(route, self.lifecycle, self.metrics, legacy_only=True)
        app.router.add_route(
            alias, legacy.endpoint, methods=["POST"], include_in_schema=False
        )

    @contextlib.asynccontextmanager
    async def _lifespan(self, _app: FastAPI) -> AsyncIterator[None]:
        # Miner.run() starts the lifecycle before the server opens its port
        # (so a refusal keeps its exit code); an external server
        # (``uvicorn my_miner:miner.app``) and each TW_WORKERS > 1 worker
        # start it here. Either way it stops
        # here: uvicorn runs the lifespan shutdown after draining requests and
        # before it re-raises the signal that stopped it.
        if not self.lifecycle.ready:
            # A TW_WORKERS > 1 worker or an external server: nothing has set up
            # the kit's JSON logs in this process yet (spec 8.12).
            configure_logging(self.settings.log_level)
            await self.lifecycle.start()
        try:
            yield
        finally:
            await self.lifecycle.stop()

    @contextlib.asynccontextmanager
    async def running(self) -> AsyncIterator[FastAPI]:
        """Start and stop the miner around a block, without a server (tests)."""
        app = self.app
        await self.lifecycle.start()
        try:
            yield app
        finally:
            await self.lifecycle.stop()

    # ------------------------------------------------------------ run

    def uvicorn_options(self) -> dict[str, Any]:
        """The kit's uvicorn settings for the public port (spec 8.6.1)."""
        s = self.settings
        options: dict[str, Any] = {
            "host": s.bind_host,
            "port": s.bind_port,
            "log_config": None,
            "access_log": False,
            "server_header": False,
            "proxy_headers": False,  # the kit reads X-Forwarded-For itself
            "timeout_keep_alive": _KEEP_ALIVE_S,
            # httptools with a request-read deadline (slowloris) and header
            # limits (MAX_HEADER_BYTES); see miner/protocol.py.
            "http": guarded_protocol(s.auth_max_age_s + s.auth_allowed_skew_s),
            "limit_concurrency": DEFAULT_LIMIT_CONCURRENCY,
            "timeout_graceful_shutdown": max(1, round(s.drain_s)),
        }
        if s.tls_cert_file is not None and s.tls_key_file is not None:
            options["ssl_certfile"] = str(s.tls_cert_file)
            options["ssl_keyfile"] = str(s.tls_key_file)
        return options

    def run(self, *, app_import: str | None = None) -> None:
        """Serve until SIGINT/SIGTERM, with metrics on ``TW_METRICS_BIND``.

        Startup runs before the server opens its port; if it is refused the
        process exits with the :class:`StartupError` exit code (3 = hotkey
        not registered). On shutdown the server stops accepting, gives
        in-flight requests ``TW_DRAIN_S`` to finish, then the chain
        connection and the nonce store are closed.

        With ``TW_WORKERS > 1`` uvicorn imports the app in each worker: pass
        ``app_import="my_miner:miner.app"``.
        """
        configure_logging(self.settings.log_level)
        try:
            if self.settings.workers > 1:
                self._run_workers(app_import)
            else:
                asyncio.run(self._serve())
        except KeyboardInterrupt:
            # Ctrl-C: uvicorn drained and the lifecycle stopped ("miner_stopped");
            # it re-raises SIGINT afterwards. Exit like a shell does, no traceback.
            sys.exit(130)
        except StartupError as exc:
            _log.critical("startup_refused", reason=str(exc))
            sys.exit(exc.exit_code)
        except ConfigError as exc:
            _log.critical("config_invalid", reason=str(exc))
            sys.exit(2)

    def _metrics_server(self) -> uvicorn.Server:
        bind = self.settings.metrics_bind
        config = uvicorn.Config(
            self.metrics.asgi_app(),
            host=bind.host,
            port=bind.port,
            lifespan="off",
            log_config=None,
            access_log=False,
            server_header=False,
        )
        return NoSignalServer(config)

    async def _serve(self) -> None:
        app = self.app
        await self.lifecycle.start()
        metrics_server = self._metrics_server()
        metrics_task = asyncio.get_running_loop().create_task(metrics_server.serve())
        server = uvicorn.Server(
            uvicorn.Config(app, lifespan="on", **self.uvicorn_options())
        )
        try:
            await server.serve()
        finally:
            metrics_server.should_exit = True
            await metrics_task
            await self.lifecycle.stop()

    async def _preflight(self) -> None:
        await self.lifecycle.start()
        await self.lifecycle.stop()
        _log.info("startup_checks_passed", workers=self.settings.workers)

    def _run_workers(self, app_import: str | None) -> None:
        if app_import is None:
            raise ConfigError(
                "TW_WORKERS > 1 needs the app's import path: "
                "miner.run(app_import='my_miner:miner.app')"
            )
        s = self.settings
        # Run the startup checks once here, so a refusal (exit 3 = not
        # registered, ...) ends this process with its exit code; a worker
        # that fails its lifespan only makes uvicorn stop with status 0.
        asyncio.run(self._preflight())
        # Workers write their metrics here (prometheus_client multiprocess
        # mode); this process serves the aggregate on TW_METRICS_BIND.
        metrics_dir = tempfile.mkdtemp(prefix="tensorwire-metrics-")
        os.environ[MULTIPROC_ENV] = metrics_dir
        stop_metrics = serve_multiprocess(
            metrics_dir,
            s.metrics_bind.host,
            s.metrics_bind.port,
            legacy_until=s.legacy_v10_until,
        )
        try:
            # Every worker runs the full startup. The axon is published by the
            # first worker that sees the chain differ; the others find it in sync.
            uvicorn.run(
                app_import,
                lifespan="on",
                workers=s.workers,
                **self.uvicorn_options(),
            )
        finally:
            stop_metrics()
            os.environ.pop(MULTIPROC_ENV, None)
            shutil.rmtree(metrics_dir, ignore_errors=True)
