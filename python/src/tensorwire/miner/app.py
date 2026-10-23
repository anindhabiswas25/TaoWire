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
import threading
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
from tensorwire.extensions.streaming import StreamLimits
from tensorwire.extensions.timelock import Timelock
from tensorwire.limits.body import BodySizeLimit
from tensorwire.limits.ratelimit import PreAuthRateLimit, RateDecision, RateLimiter
from tensorwire.miner.health import health_routes
from tensorwire.miner.legacy import LegacyServerFactory
from tensorwire.miner.lifecycle import Lifecycle, MinerParts
from tensorwire.miner.pipeline import RouteEndpoint
from tensorwire.miner.protocol import MAX_HEADER_BYTES, guarded_protocol
from tensorwire.miner.routes import Handler, Route, RouteRegistry
from tensorwire.miner.streaming import StreamSlots
from tensorwire.observability.logging import configure_logging
from tensorwire.observability.metrics import MULTIPROC_ENV, Metrics, serve_multiprocess
from tensorwire.observability.middleware import RequestContext
from tensorwire.policy.caller import CallerPolicy

__all__ = [
    "DEFAULT_LIMIT_CONCURRENCY",
    "MAX_HEADER_BYTES",
    "BackgroundServer",
    "Miner",
    "NoSignalServer",
]

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
        self._stream_slots = StreamSlots()  # open streams per caller, all routes
        self._timelock: Timelock | None = None

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
        stream: bool = False,
        stream_max_s: float | None = None,
        stream_max_bytes: int | None = None,
        stream_idle_s: float | None = None,
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

        ``stream=True`` makes it a streaming route (spec 9.2): the handler
        returns an async iterable of chunks (JSON objects or arrays: models,
        dicts, lists) or a ``StreamingReply``, and ``response`` is the chunk
        model. ``stream_max_s`` / ``stream_max_bytes`` / ``stream_idle_s``
        override ``TW_STREAM_MAX_S`` / ``_MAX_BYTES`` / ``_IDLE_S`` (same
        ranges). ``timeout_s`` bounds the time to the first chunk.
        """
        chosen = self.default_policy if policy is None else policy
        limits: StreamLimits | None = None
        if stream:
            s = self.settings
            limits = StreamLimits.from_settings(s).override(
                max_s=stream_max_s, max_bytes=stream_max_bytes, idle_s=stream_idle_s
            )
        elif (stream_max_s, stream_max_bytes, stream_idle_s) != (None, None, None):
            raise ValueError("stream_* limits need stream=True")

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
                stream_limits=limits,
            )
            return handler

        return register

    @property
    def timelock(self) -> Timelock:
        """This miner's :class:`~tensorwire.extensions.timelock.Timelock` (spec 8.10).

        For sealed challenges and sealed responses in route handlers; built
        on first use, after startup, with the kit's defaults.
        """
        if self._timelock is None:
            self._timelock = Timelock(
                self.lifecycle.runtime.gateway, metrics=self.metrics
            )
        return self._timelock

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
        endpoint = RouteEndpoint(
            route, self.lifecycle, self.metrics, stream_slots=self._stream_slots
        )
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
        legacy = RouteEndpoint(
            route,
            self.lifecycle,
            self.metrics,
            legacy_only=True,
            stream_slots=self._stream_slots,
        )
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

    def serve_in_background(
        self, *, ready_timeout_s: float | None = None
    ) -> BackgroundServer:
        """Serve from a daemon thread, without touching signal handlers.

        For v10's ``with Miner() as miner:`` form (compat): returns once the
        miner is ready, or raises what startup raised (``StartupError``, ...).
        Single worker only. Stop it with :meth:`BackgroundServer.stop`.
        """
        if self.settings.workers > 1:
            raise ConfigError("serve_in_background() runs one worker (TW_WORKERS=1)")
        handle = BackgroundServer(self)
        handle.start(
            self.settings.startup_timeout_s + 30
            if ready_timeout_s is None
            else ready_timeout_s
        )
        return handle

    async def _serve(
        self,
        *,
        signals: bool = True,
        on_server: Callable[[uvicorn.Server], None] | None = None,
    ) -> None:
        app = self.app
        await self.lifecycle.start()
        metrics_server = self._metrics_server()
        metrics_task = asyncio.get_running_loop().create_task(metrics_server.serve())
        server_cls = uvicorn.Server if signals else NoSignalServer
        server = server_cls(
            uvicorn.Config(app, lifespan="on", **self.uvicorn_options())
        )
        if on_server is not None:
            on_server(server)
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


class BackgroundServer:
    """A :class:`Miner` served from a daemon thread (``Miner.serve_in_background``)."""

    def __init__(self, miner: Miner) -> None:
        self._miner = miner
        self._server: uvicorn.Server | None = None
        self._error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._main, name="tensorwire-miner", daemon=True
        )

    def _main(self) -> None:
        try:
            asyncio.run(self._miner._serve(signals=False, on_server=self._keep))
        except BaseException as exc:  # noqa: BLE001 - reported to the owner thread
            self._error = exc

    def _keep(self, server: uvicorn.Server) -> None:
        self._server = server

    def start(self, timeout_s: float) -> None:
        """Start the thread; return once the miner is ready (or raise)."""
        self._thread.start()
        deadline = time.monotonic() + timeout_s
        while not (self._miner.lifecycle.ready and self.started):
            if not self._thread.is_alive():
                raise self._error or RuntimeError("the miner stopped during startup")
            if time.monotonic() > deadline:
                self.stop()
                raise StartupError("the miner did not become ready in time")
            time.sleep(0.05)

    @property
    def started(self) -> bool:
        """Whether the HTTP server is listening."""
        return self._server is not None and self._server.started

    @property
    def running(self) -> bool:
        """Whether the serving thread is alive."""
        return self._thread.is_alive()

    def stop(self, timeout_s: float = 60.0) -> None:
        """Ask the server to drain and stop, and wait for the thread."""
        if self._server is not None:
            self._server.should_exit = True
        self._thread.join(timeout=timeout_s)
