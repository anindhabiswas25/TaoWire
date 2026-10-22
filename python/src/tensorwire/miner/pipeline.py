"""The miner request path, in the exact order of spec 5.3.

Steps 1-3 run as ASGI middleware in front of every request (installed by
``miner.app``): pre-auth per-IP rate limit, then the body-size cap over the
largest route limit. Step 4 is the router. :class:`RouteEndpoint` runs the
rest for one route:

[2/3] the route's own body limit (declared length, then a running count)
[5]   metagraph usable? (strict mode past the max age: 503 for everyone)
[6]   btauth/1 verification in a worker thread (401 ``tw.auth_*``)
[7]   caller policy, or known callers only past the max age (403 / 503)
[8]   per-hotkey, per-route rate limit (429)
[9]   parse the verified raw body into the request model (422)
[10]  the handler, with a timeout (504 / 500)
[11]  serialize, sign the response (``twresp/1``, spec 9.1) and send

Cheap rejects come first; the signature check runs only after the size and
IP limits, and the replay store is written only after the signature
verifies (fact A4). Handlers never see bytes that were not verified.

Responses are signed when ``TW_SIGN_RESPONSES=1`` (the default): every 200,
and every error raised after the caller was authenticated (Appendix A,
"Response signed?"). Errors before that are never signed.

Legacy v10 requests (spec 8.11.2) take the same path with the bridge's
verifier at step [6] and are answered in v10 shape; they are not signed
with ``twresp/1`` (v10 Dendrites do not read it).
"""

from __future__ import annotations

import functools
import time
from collections.abc import MutableMapping
from typing import Any
from urllib.parse import quote

import anyio
import anyio.to_thread
import structlog
from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.responses import Response

from tensorwire.auth.verifier import Caller
from tensorwire.errors import (
    HandlerError,
    HandlerTimeout,
    InvalidRequest,
    LegacyAuthFailed,
    PayloadTooLarge,
    RateLimited,
    ReplayStoreUnavailable,
    TWError,
)
from tensorwire.extensions.response_sig import sign_response
from tensorwire.miner.legacy import LegacyRequestLike, LegacyServerLike
from tensorwire.miner.lifecycle import Lifecycle, Runtime
from tensorwire.miner.routes import Route, RouteContext
from tensorwire.observability.metrics import Metrics
from tensorwire.observability.middleware import state_of

__all__ = ["RouteEndpoint", "raw_target"]

_log = structlog.stdlib.get_logger("tensorwire.miner")


def raw_target(scope: MutableMapping[str, Any]) -> str:
    """The request target exactly as received: percent-encoded path + ``?query``.

    Uses the ASGI ``raw_path``. A server that does not provide it gets the
    decoded path re-encoded, which can differ from what the client signed;
    such requests then fail as ``tw.auth_bad_signature`` (fail closed).
    """
    raw = scope.get("raw_path")
    path = (
        raw.decode("latin-1")
        if raw
        else quote(scope["path"], safe="/:@!$&'()*+,;=-._~")
    )
    query = scope.get("query_string", b"")
    return f"{path}?{query.decode('latin-1')}" if query else path


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.strip().isdigit() and int(declared) > limit:
        raise PayloadTooLarge()
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise PayloadTooLarge()
        chunks.append(chunk)
    return b"".join(chunks)


def _serialize(route: Route, result: Any) -> tuple[bytes, str]:
    if route.encode is not None and not isinstance(result, (bytes, bytearray)):
        return route.encode(result), "application/json"
    if isinstance(result, (bytes, bytearray, memoryview)):
        return bytes(result), "application/octet-stream"
    model = route.response_model
    if isinstance(result, BaseModel) and (model is None or isinstance(result, model)):
        return result.model_dump_json().encode(), "application/json"
    expected = "bytes" if model is None else f"{model.__name__} or bytes"
    _log.error(
        "handler_bad_return",
        route=route.path,
        returned=type(result).__name__,
        expected=expected,
    )
    raise HandlerError()


class RouteEndpoint:
    """Runs steps 2-11 of the request path for one route.

    ``legacy_only`` marks the extra ``/<SynapseName>`` path mounted for a
    native route that also accepts v10 requests: btauth/1 requests there are
    answered 404.
    """

    def __init__(
        self,
        route: Route,
        lifecycle: Lifecycle,
        metrics: Metrics,
        *,
        legacy_only: bool = False,
    ) -> None:
        self.route = route
        self._lifecycle = lifecycle
        self._metrics = metrics
        self._legacy_only = legacy_only

    async def endpoint(self, request: Request) -> Response:
        """The Starlette endpoint (a bound method: Starlette passes a ``Request``)."""
        state = state_of(request.scope)
        state["tw_route"] = self.route.path
        request_id: str | None = state.get("request_id")
        started = time.perf_counter()
        legacy = self._legacy_server(request)
        if legacy is None and self._legacy_only:
            return Response(status_code=404)
        try:
            if legacy is not None:
                return await self._handle_legacy(request, state, request_id, legacy)
            return await self._handle(request, state, request_id)
        except TWError as err:
            state["tw_code"] = err.code
            if legacy is not None:
                self._lifecycle.legacy_traffic.record(state.get("tw_caller"), err.code)
                return _legacy_response(
                    legacy,
                    request,
                    status=err.http_status,
                    synapse=None,
                    error=err,
                    started=started,
                )
            headers = err.response_headers()
            content = err.response_body(request_id)
            caller: Caller | None = state.get("tw_caller_obj")
            if err.signed and caller is not None:
                headers.update(self._sign(caller, err.http_status, content))
            return Response(
                content=content,
                status_code=err.http_status,
                headers=headers,
                media_type="application/json",
            )

    def _legacy_server(self, request: Request) -> LegacyServerLike | None:
        """The bridge when this is a v10 request and the bridge is on, else ``None``."""
        if not self._lifecycle.ready:
            return None
        legacy = self._lifecycle.runtime.legacy
        if legacy is None or not legacy.is_legacy(request.headers):
            return None
        return legacy

    def _sign(self, caller: Caller, status: int, content: bytes) -> dict[str, str]:
        rt = self._lifecycle.runtime
        if not self._lifecycle.settings.sign_responses:
            return {}
        return sign_response(
            rt.signer,
            request_nonce=caller.nonce_ns,
            sender_ss58=caller.hotkey_ss58,
            status=status,
            body=content,
        )

    async def _handle(
        self, request: Request, state: MutableMapping[str, Any], request_id: str | None
    ) -> Response:
        route = self.route
        body = await _read_body(request, route.max_body_bytes)  # [2/3]
        rt = self._lifecycle.runtime
        rt.gate.precheck()  # [5]
        started = time.perf_counter()
        try:  # [6]
            caller = await rt.verifier.verify(
                request.headers.items(),
                body,
                method=request.method,
                target=raw_target(request.scope),
            )
        except ReplayStoreUnavailable:
            state["tw_store_backend"] = rt.store_backend
            raise
        finally:
            self._metrics.auth_verify_duration.observe(time.perf_counter() - started)
        ctx = await self._admit(rt, state, caller, request_id)  # [7] [8]
        argument = route.parse(body)  # [9]
        result = await self._invoke(argument, ctx)  # [10]
        content, media_type = _serialize(route, result)  # [11]
        return Response(
            content=content,
            status_code=200,
            media_type=media_type,
            headers=self._sign(caller, 200, content),
        )

    async def _admit(
        self,
        rt: Runtime,
        state: MutableMapping[str, Any],
        caller: Caller,
        request_id: str | None,
    ) -> RouteContext:
        route = self.route
        state["tw_caller"] = caller.hotkey_ss58
        state["tw_caller_obj"] = caller
        neuron = rt.gate.admit(route.path, route.policy, caller.hotkey_ss58)  # [7]
        decision = await rt.hotkey_limiter.acquire(f"{route.path} {caller.hotkey_ss58}")
        if not decision.allowed:  # [8]
            state["tw_rate_layer"] = "hotkey"
            raise RateLimited(retry_after_s=decision.retry_after_s, layer="hotkey")
        return RouteContext(
            caller=caller, caller_neuron=neuron, request_id=request_id, route=route.path
        )

    async def _handle_legacy(
        self,
        request: Request,
        state: MutableMapping[str, Any],
        request_id: str | None,
        legacy: LegacyServerLike,
    ) -> Response:
        route = self.route
        started = time.perf_counter()
        state["tw_protocol"] = "v10"
        if not route.accepts_legacy:
            raise LegacyAuthFailed("this route does not accept v10 requests")
        body = await _read_body(request, route.max_body_bytes)  # [2/3]
        rt = self._lifecycle.runtime
        rt.gate.precheck()  # [5]
        verify_started = time.perf_counter()
        try:  # [6] v10 signature + the kit's freshness window and replay store
            verified = await legacy.verify(
                list(request.headers.items()),
                body,
                synapse_cls=route.legacy_synapse,
                body_hash=route.legacy_body_hash,
            )
        except ReplayStoreUnavailable:
            state["tw_store_backend"] = rt.store_backend
            raise
        finally:
            self._metrics.auth_verify_duration.observe(
                time.perf_counter() - verify_started
            )
        ctx = await self._admit(rt, state, verified.caller, request_id)  # [7] [8]
        argument = self._legacy_argument(verified, body)  # [9]
        result = await self._invoke(argument, ctx)  # [10]
        synapse = self._legacy_result(verified, result)  # [11]
        self._lifecycle.legacy_traffic.record(verified.caller.hotkey_ss58, "ok")
        return _legacy_response(
            legacy, request, status=200, synapse=synapse, error=None, started=started
        )

    def _legacy_argument(self, verified: LegacyRequestLike, body: bytes) -> Any:
        route = self.route
        synapse = verified.synapse
        if synapse is None:
            return route.parse(body)
        model = route.request_model
        if model is None or isinstance(synapse, model):
            return synapse
        try:
            return model.model_validate(_user_fields(synapse))
        except ValidationError:
            raise InvalidRequest() from None

    def _legacy_result(self, verified: LegacyRequestLike, result: Any) -> BaseModel:
        synapse = verified.synapse
        if synapse is not None and isinstance(result, type(synapse)):
            return result
        if synapse is not None and isinstance(result, BaseModel):
            return synapse.model_copy(update=result.model_dump())
        _log.error(
            "legacy_bad_return",
            route=self.route.path,
            returned=type(result).__name__,
            hint="a route serving v10 requests must return its Synapse or a model",
        )
        raise HandlerError()

    async def _invoke(self, argument: Any, ctx: RouteContext) -> Any:
        route = self.route
        result: Any = None
        try:
            with anyio.move_on_after(route.timeout_s) as scope:
                if route.is_async:
                    result = await route.handler(argument, ctx)
                else:
                    call = functools.partial(route.handler, argument, ctx)
                    result = await anyio.to_thread.run_sync(
                        call, abandon_on_cancel=True
                    )
        except TWError:
            raise  # kit errors carry their own safe public message
        except Exception:  # noqa: BLE001 - any handler bug becomes a 500, never a crash
            _log.exception("handler_error", route=route.path, request_id=ctx.request_id)
            raise HandlerError() from None
        if scope.cancelled_caught:
            _log.warning(
                "handler_timeout",
                route=route.path,
                request_id=ctx.request_id,
                timeout_s=route.timeout_s,
            )
            raise HandlerTimeout()
        return result


def _user_fields(synapse: BaseModel) -> dict[str, Any]:
    fields = getattr(synapse, "user_fields", None)
    if callable(fields):
        values: dict[str, Any] = fields()
        return values
    return synapse.model_dump()


def _legacy_response(
    legacy: LegacyServerLike,
    request: Request,
    *,
    status: int,
    synapse: BaseModel | None,
    error: TWError | None,
    started: float,
) -> Response:
    content, headers = legacy.respond(
        request.headers,
        status=status,
        synapse=synapse,
        error=error,
        process_time_s=time.perf_counter() - started,
    )
    response = Response(content=content, status_code=status)
    for name, value in headers:
        if name.lower() != "content-length":  # Starlette sets it from the content
            response.headers.append(name, value)
    return response
