"""The sidecar's HTTP app (spec 11.6): the contract of ``docs/multi-language.md``.

Four endpoints, every one behind the bearer token:

- ``GET /v1/health``: the sidecar's hotkey, netuid and snapshot state;
- ``GET /v1/metagraph?netuid=N``: the cached snapshot, with its age and tempo,
  so a client can apply the staleness stages of spec 8.5.1 itself;
- ``GET /v1/caller/{hotkey}?netuid=N``: the sidecar's own caller decision
  (``CallerPolicy`` + ``CallerGate``, scope ``sidecar``);
- ``POST /v1/serve-axon``: publish an axon for the sidecar's hotkey, on the
  configured netuid only, sent once through the gateway.

Every refusal is the Appendix A JSON body. Parameters and bodies are parsed
by hand and strictly (so nothing answers with FastAPI's own validation body).
No weight setting.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Awaitable, Callable
from typing import Any

import anyio
import structlog
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from tensorwire.chain.axon import parse_axon
from tensorwire.chain.gateway import ChainGateway, GatewayError, NeuronView
from tensorwire.chain.metagraph_cache import MetagraphSource, StalenessStage
from tensorwire.config import SidecarSettings
from tensorwire.crypto import public_key_from_ss58
from tensorwire.errors import (
    Forbidden,
    InvalidRequest,
    MetagraphStale,
    SidecarUnauthorized,
    TWError,
)
from tensorwire.limits.body import BodySizeLimit
from tensorwire.policy.caller import CallerGate, CallerPolicy
from tensorwire.sidecar.token import token_matches

__all__ = ["MAX_BODY_BYTES", "SCOPE", "create_app"]

#: Request body cap (spec 11.6 bodies are tiny).
MAX_BODY_BYTES = 64 * 1024
#: The known-callers scope of ``/v1/caller``.
SCOPE = "sidecar"

_log = structlog.stdlib.get_logger("tensorwire.sidecar")
_NETUID = re.compile(r"[0-9]{1,5}")
_CERT_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2}){2,65}")
_SERVE_KEYS = frozenset({"netuid", "ip", "port", "tls_cert_hex"})
_STAGE_NAMES = {
    StalenessStage.FRESH: "fresh",
    StalenessStage.DEGRADED: "degraded",
    StalenessStage.KNOWN_CALLERS_ONLY: "known_callers_only",
}


def _error(err: TWError) -> Response:
    return Response(
        err.response_body(),
        status_code=err.http_status,
        media_type="application/json",
    )


class _Auth:
    """Pure ASGI: every request needs the bearer token, before routing."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self._token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        auth: str | None = None
        for name, value in scope["headers"]:
            if name == b"authorization":
                if auth is not None:  # a repeated header never matches
                    auth = None
                    break
                auth = value.decode("latin-1")
        if not token_matches(auth, self._token):
            _log.info("sidecar_request", path=scope["path"], status=401)
            await _error(SidecarUnauthorized())(scope, receive, send)
            return
        await self.app(scope, receive, _status_recorder(send, scope))


def _status_recorder(send: Send, scope: Scope) -> Send:
    async def recorder(message: Any) -> None:
        if message["type"] == "http.response.start":
            _log.info(
                "sidecar_request",
                method=scope["method"],
                path=scope["path"],
                status=message["status"],
            )
        await send(message)

    return recorder


def _invalid(detail: str) -> InvalidRequest:
    """``422 tw.invalid_request`` with the fixed public message; detail to the log."""
    _log.info("sidecar_invalid_request", detail=detail)
    return InvalidRequest()


def _netuid(request: Request, configured: int) -> None:
    raw = request.query_params.getlist("netuid")
    if len(raw) != 1 or not _NETUID.fullmatch(raw[0]) or int(raw[0]) != configured:
        raise _invalid(f"netuid must be {configured}")


def _is_ss58(value: str) -> bool:
    try:
        public_key_from_ss58(value)  # 48 characters checked before decoding (D19)
    except ValueError:
        return False
    return True


def _stake(n: NeuronView) -> float:
    # Not finite or negative counts as 0: a stake threshold fails closed.
    v = n.total_stake_tao
    return v if math.isfinite(v) and v >= 0 else 0.0


def _neuron(n: NeuronView) -> dict[str, Any]:
    return {
        "uid": n.uid,
        "hotkey": n.hotkey,
        "validator_permit": n.validator_permit,
        "total_stake_tao": _stake(n),
        "axon": None if n.axon is None else str(n.axon),
    }


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _invalid("duplicate key")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise _invalid(f"{name} is not JSON")


def parse_serve_axon(body: bytes, netuid: int) -> tuple[str, int, str | None]:
    """Parse a ``/v1/serve-axon`` body: ``(ip, port, tls_cert_hex)``.

    Exactly ``netuid`` (the configured one), ``ip`` (string), ``port``
    (1-65535) and optionally ``tls_cert_hex`` (``0x`` + 2-65 bytes, or null);
    no other key, no key twice. Raises :class:`InvalidRequest`.
    """
    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise _invalid("body is not JSON") from None
    if not isinstance(value, dict) or not {"netuid", "ip", "port"} <= set(value):
        raise _invalid("expected {netuid, ip, port[, tls_cert_hex]}")
    if not set(value) <= _SERVE_KEYS:
        raise _invalid("unknown key")
    n, ip, port = value["netuid"], value["ip"], value["port"]
    if isinstance(n, bool) or n != netuid or not isinstance(n, int):
        raise _invalid(f"netuid must be {netuid}")
    if not isinstance(ip, str) or not 1 <= len(ip) <= 64:
        raise _invalid("ip must be a string")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise _invalid("port must be 1-65535")
    cert = value.get("tls_cert_hex")
    bad_cert = not isinstance(cert, str) or not _CERT_HEX.fullmatch(cert)
    if cert is not None and bad_cert:
        raise _invalid("tls_cert_hex must be 0x + 2-65 bytes of hex")
    return ip, port, None if cert is None else cert.lower()


def create_app(
    *,
    settings: SidecarSettings,
    gateway: ChainGateway,
    metagraph: MetagraphSource,
    gate: CallerGate,
    policy: CallerPolicy,
    hotkey_ss58: str,
    token: str,
) -> ASGIApp:
    """The sidecar ASGI app (see the module docstring)."""
    netuid = settings.netuid
    write_lock = anyio.Lock()
    api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @api.exception_handler(TWError)
    async def _tw(_request: Request, exc: TWError) -> Response:
        return _error(exc)

    def route(
        method: str, path: str
    ) -> Callable[[Callable[[Request], Awaitable[Response]]], Any]:
        def register(handler: Callable[[Request], Awaitable[Response]]) -> Any:
            api.add_api_route(path, handler, methods=[method])
            return handler

        return register

    @route("GET", "/v1/health")
    async def health(_request: Request) -> Response:
        snapshot = metagraph.snapshot()
        stage = metagraph.stage()
        age = metagraph.age_s()
        return JSONResponse(
            {
                "ok": snapshot is not None
                and stage is not StalenessStage.KNOWN_CALLERS_ONLY,
                "hotkey": hotkey_ss58,
                "netuid": netuid,
                "block": None if snapshot is None else snapshot.block,
                "metagraph_age_s": None if age is None else round(age, 3),
                "stage": _STAGE_NAMES[stage],
            }
        )

    @route("GET", "/v1/metagraph")
    async def snapshot(request: Request) -> Response:
        _netuid(request, netuid)
        mg = metagraph.snapshot()
        age = metagraph.age_s()
        if mg is None or age is None:
            raise MetagraphStale()
        return JSONResponse(
            {
                "netuid": netuid,
                "block": mg.block,
                "tempo": mg.tempo,
                "age_s": round(max(age, 0.0), 3),
                "neurons": [_neuron(n) for n in mg.neurons],
            }
        )

    @route("GET", "/v1/caller/{hotkey}")
    async def caller(request: Request) -> Response:
        hotkey = request.path_params["hotkey"]
        if not _is_ss58(hotkey):
            raise _invalid("not an SS58 prefix-42 address")
        _netuid(request, netuid)
        try:
            gate.admit(SCOPE, policy, hotkey)
        except (Forbidden, MetagraphStale) as refused:
            return JSONResponse({"allowed": False, "code": refused.code})
        return JSONResponse({"allowed": True})

    @route("POST", "/v1/serve-axon")
    async def serve_axon(request: Request) -> Response:
        ip, port, cert = parse_serve_axon(await request.body(), netuid)
        text = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        endpoint = parse_axon(text, allow_private=settings.allow_private_axons)
        if endpoint is None:
            raise _invalid("address refused (TW_ALLOW_PRIVATE_AXONS)")
        async with write_lock:  # one chain write at a time, each sent once
            try:
                outcome = await gateway.serve_axon(
                    netuid,
                    endpoint.host,
                    endpoint.port,
                    tls_cert_hex=cert,
                    protocol_tag=settings.protocol_tag,
                )
            except GatewayError as exc:
                _log.error("sidecar_serve_axon_failed", error=str(exc))
                return JSONResponse(
                    {
                        "ok": False,
                        "code": "chain_unavailable",
                        "error_name": None,
                        "remediation": None,
                    },
                    status_code=503,
                )
        if not outcome.ok:
            _log.warning(
                "sidecar_serve_axon_rejected",
                code=outcome.code,
                error_name=outcome.error_name,
            )
            return JSONResponse(
                {
                    "ok": False,
                    "code": outcome.code,
                    "error_name": outcome.error_name,
                    "remediation": outcome.remediation,
                },
                status_code=409,
            )
        _log.info(
            "sidecar_axon_published",
            external=str(endpoint),
            block_hash=outcome.block_hash,
        )
        return JSONResponse({"ok": True, "block_hash": outcome.block_hash})

    return _Auth(BodySizeLimit(api, MAX_BODY_BYTES), token)
