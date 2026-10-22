"""Per-request ID, access log line and request metrics, as pure ASGI middleware.

Installed outermost on the miner. For every HTTP request it:

1. creates a ULID request ID, stores it in ``scope["state"]["request_id"]``
   (inner layers put it in error bodies) and returns it in ``X-TW-Request-Id``;
2. after the response, logs one line (spec 8.12) and updates
   ``tw_requests_total`` / ``tw_request_duration_seconds``, plus the
   rejection counters derived from the error code (auth failures, policy
   denials, rate limits, oversized bodies, replay-store errors), so every
   layer is counted the same way.

Inner layers describe the outcome through ``scope["state"]``: ``tw_route``
(the registered route path, used as the metric label), ``tw_code`` (the
``tw.*`` code of an error response), ``tw_caller`` (the verified hotkey),
``tw_rate_layer`` (``ip``/``hotkey``) and ``tw_store_backend``.
Requests to paths that are not kit routes are labelled ``unmatched``, so
arbitrary paths never become label values.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

import structlog

from tensorwire.observability.logging import new_request_id, short_hotkey
from tensorwire.observability.metrics import Metrics

__all__ = ["UNMATCHED_ROUTE", "RequestContext", "state_of"]

UNMATCHED_ROUTE = "unmatched"

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_log = structlog.stdlib.get_logger("tensorwire.request")


def state_of(scope: Scope) -> MutableMapping[str, Any]:
    """The request's ``scope["state"]`` dict, created if missing."""
    state = scope.setdefault("state", {})
    if not isinstance(
        state, MutableMapping
    ):  # pragma: no cover - ASGI servers use a dict
        raise TypeError("scope['state'] is not a mapping")
    return state


class RequestContext:
    """Request ID, access log and request metrics for every HTTP request."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        metrics: Metrics,
        log_full_hotkeys: Callable[[], bool] = lambda: False,
    ) -> None:
        self.app = app
        self._metrics = metrics
        self._full = log_full_hotkeys

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        request_id = new_request_id()
        state = state_of(scope)
        state["request_id"] = request_id
        status = 500

        async def send_with_id(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() != b"x-tw-request-id"
                ]
                headers.append((b"x-tw-request-id", request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            elapsed = time.perf_counter() - started
            route = state.get("tw_route", UNMATCHED_ROUTE)
            code = state.get("tw_code") or ("ok" if status < 400 else f"http_{status}")
            self._metrics.requests.labels(
                route=route, status=str(status), code=code
            ).inc()
            self._metrics.request_duration.labels(route=route).observe(elapsed)
            self._count_rejection(code, state)
            _log.info(
                "request",
                request_id=request_id,
                route=route,
                caller_hotkey=short_hotkey(state.get("tw_caller"), full=self._full()),
                status=status,
                latency_ms=round(elapsed * 1000, 3),
                code=code,
            )

    def _count_rejection(self, code: str, state: MutableMapping[str, Any]) -> None:
        m = self._metrics
        if code.startswith("tw.auth_"):
            m.auth_failures.labels(code=code).inc()
        elif code.startswith("tw.forbidden_") or code == "tw.metagraph_stale":
            m.policy_denials.labels(code=code).inc()
        elif code == "tw.rate_limited":
            m.rate_limited.labels(layer=state.get("tw_rate_layer", "ip")).inc()
        elif code == "tw.payload_too_large":
            m.payload_too_large.inc()
        elif code == "tw.replay_store_unavailable":
            backend = state.get("tw_store_backend", "unknown")
            m.nonce_store_errors.labels(backend=backend).inc()
