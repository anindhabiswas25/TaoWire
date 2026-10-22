"""Health endpoints on the public port (spec 8.7.4).

- ``GET /healthz``: ``200 {"status":"ok"}`` while the process is alive.
- ``GET /readyz``: ``200 {"status":"ready","degraded":[...]}``, or
  ``503 {"status":"not_ready","reasons":[...]}``.

Neither needs authentication and neither reveals a hotkey, a version or any
configuration: reasons are fixed words (``starting``, ``stopping``,
``not_registered``, ``metagraph_stale``, ``nonce_store_unreachable``,
``clock_skew``; degraded: ``metagraph_stale``, ``axon_not_published``).
``/metrics`` is served on ``TW_METRICS_BIND``, never here.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tensorwire.miner.lifecycle import Lifecycle

__all__ = ["health_routes"]


def health_routes(lifecycle: Lifecycle) -> list[Route]:
    """The ``/healthz`` and ``/readyz`` routes for one miner."""

    async def healthz(request: Request) -> JSONResponse:
        request.state.tw_route = "/healthz"
        return JSONResponse({"status": "ok"})

    async def readyz(request: Request) -> JSONResponse:
        request.state.tw_route = "/readyz"
        verdict = await lifecycle.readiness()
        if verdict.ready:
            return JSONResponse({"status": "ready", "degraded": list(verdict.degraded)})
        return JSONResponse(
            {"status": "not_ready", "reasons": list(verdict.reasons)}, status_code=503
        )

    return [
        Route("/healthz", healthz, methods=["GET"], include_in_schema=False),
        Route("/readyz", readyz, methods=["GET"], include_in_schema=False),
    ]
