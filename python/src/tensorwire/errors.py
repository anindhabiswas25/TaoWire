"""TensorWire error hierarchy and the error-code catalogue (spec 8.2, Appendix A).

Every error a kit endpoint can return has a stable ``tw.*`` code, a fixed HTTP
status and a fixed public message. Public messages are safe to send to an
unauthenticated caller: they never contain stack traces, signatures, payloads,
hotkeys or internal paths. The only exception is :class:`AuthFailed`, whose
message comes from ``bittensor.http_auth`` and is documented by the SDK as safe
to return (it never echoes the signature or payload).

The body of every error response, in every language, is::

    {"error": {"code": "tw.auth_stale", "message": "...", "request_id": "01J..."}}
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar, Literal

__all__ = [
    "CLIENT_ERROR_CODES",
    "ERROR_CODES",
    "AuthFailed",
    "ChainError",
    "ConfigError",
    "ErrorSpec",
    "Forbidden",
    "HandlerError",
    "HandlerTimeout",
    "InvalidRequest",
    "LegacyAuthFailed",
    "LegacyDisabled",
    "MetagraphStale",
    "PayloadTooLarge",
    "RateLimited",
    "ReplayStoreUnavailable",
    "TWError",
    "client_http_code",
]


@dataclass(frozen=True)
class ErrorSpec:
    """One row of Appendix A.

    ``signed`` says whether the miner signs the error response with ``twresp/1``.
    Errors raised before the caller is authenticated are never signed (the
    miner does not yet know who it would be signing for). ``tw.rate_limited``
    depends on the layer, so its row says ``None`` and :class:`RateLimited`
    decides.
    """

    code: str
    http_status: int
    public_message: str
    signed: bool | None


def _catalogue(*specs: ErrorSpec) -> Mapping[str, ErrorSpec]:
    table = {s.code: s for s in specs}
    if len(table) != len(specs):
        raise RuntimeError("duplicate error code in catalogue")
    return MappingProxyType(table)


#: Server-side error codes (Appendix A), plus the generic fallbacks.
ERROR_CODES: Mapping[str, ErrorSpec] = _catalogue(
    ErrorSpec("tw.internal", 500, "internal error", signed=False),
    ErrorSpec("tw.rate_limited", 429, "rate limit exceeded", signed=None),
    ErrorSpec(
        "tw.payload_too_large", 413, "request body exceeds the size limit", signed=False
    ),
    ErrorSpec("tw.auth_failed", 401, "authentication failed", signed=False),
    ErrorSpec(
        "tw.auth_malformed", 401, "malformed authentication headers", signed=False
    ),
    ErrorSpec(
        "tw.auth_wrong_receiver",
        401,
        "request was signed for a different receiver",
        signed=False,
    ),
    ErrorSpec(
        "tw.auth_stale",
        401,
        "request nonce is outside the freshness window",
        signed=False,
    ),
    ErrorSpec("tw.auth_bad_signature", 401, "signature does not verify", signed=False),
    ErrorSpec("tw.auth_replayed", 401, "request was already accepted", signed=False),
    ErrorSpec("tw.forbidden_denied", 403, "caller is denied", signed=True),
    ErrorSpec(
        "tw.forbidden_not_registered",
        403,
        "caller is not registered on this subnet",
        signed=True,
    ),
    ErrorSpec(
        "tw.forbidden_not_validator", 403, "caller has no validator permit", signed=True
    ),
    ErrorSpec(
        "tw.forbidden_low_stake", 403, "caller stake is below the minimum", signed=True
    ),
    ErrorSpec("tw.forbidden_blacklisted", 403, "caller is blacklisted", signed=True),
    ErrorSpec(
        "tw.invalid_request",
        422,
        "request body does not match the route model",
        signed=True,
    ),
    ErrorSpec("tw.handler_error", 500, "handler failed", signed=True),
    ErrorSpec(
        "tw.metagraph_stale",
        503,
        "metagraph snapshot is too old to admit this caller",
        signed=False,
    ),
    ErrorSpec(
        "tw.replay_store_unavailable",
        503,
        "replay protection store is unavailable",
        signed=False,
    ),
    ErrorSpec("tw.handler_timeout", 504, "handler timed out", signed=True),
    ErrorSpec(
        "tw.legacy_auth_failed", 401, "legacy v10 authentication failed", signed=False
    ),
    ErrorSpec(
        "tw.legacy_disabled",
        410,
        "legacy v10 requests are no longer accepted",
        signed=False,
    ),
    ErrorSpec("tw.config_invalid", 500, "internal error", signed=False),
)

#: Client-side codes used only in ``MinerResult.error_code`` (Appendix A).
#: ``tw.http_<status>`` codes are built with :func:`client_http_code`.
CLIENT_ERROR_CODES: frozenset[str] = frozenset(
    {
        "tw.timeout",
        "tw.connect_error",
        "tw.bad_response_signature",
        "tw.response_too_large",
        "tw.invalid_response",
        "tw.no_axon",
    }
)


def client_http_code(status: int) -> str:
    """The client-side code for an unexpected HTTP status, e.g. ``tw.http_502``."""
    if not 100 <= status <= 599:
        raise ValueError(f"not an HTTP status: {status}")
    return f"tw.http_{status}"


class TWError(Exception):
    """Base of every TensorWire error.

    Subclasses set a default ``code``; families with several codes (auth,
    forbidden) also accept one of their ``allowed_codes`` in the constructor.
    The HTTP status and default public message always come from
    :data:`ERROR_CODES`, so a code can never be sent with the wrong status.
    """

    code: str = "tw.internal"
    #: Extra codes this class may carry besides its default ``code``.
    allowed_codes: ClassVar[frozenset[str]] = frozenset()

    def __init__(
        self, public_message: str | None = None, *, code: str | None = None
    ) -> None:
        chosen = type(self).code if code is None else code
        if chosen != type(self).code and chosen not in self.allowed_codes:
            raise ValueError(f"{type(self).__name__} cannot carry code {chosen!r}")
        spec = ERROR_CODES[chosen]
        self.code = spec.code
        self.http_status: int = spec.http_status
        self.public_message: str = (
            spec.public_message if public_message is None else public_message
        )
        self._signed = bool(spec.signed)
        super().__init__(self.public_message)

    @property
    def signed(self) -> bool:
        """Whether the miner signs this error response with ``twresp/1``."""
        return self._signed

    def response_headers(self) -> dict[str, str]:
        """Extra HTTP headers for the error response (none by default)."""
        return {}

    def response_body(self, request_id: str | None = None) -> bytes:
        """The JSON error body (spec 8.2), as bytes."""
        payload = {
            "error": {
                "code": self.code,
                "message": self.public_message,
                "request_id": request_id,
            }
        }
        return json.dumps(payload, separators=(",", ":")).encode()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


class AuthFailed(TWError):
    """btauth/1 verification failed; the code names which check (spec 8.4.2)."""

    code = "tw.auth_failed"
    allowed_codes = frozenset(
        {
            "tw.auth_malformed",
            "tw.auth_wrong_receiver",
            "tw.auth_stale",
            "tw.auth_bad_signature",
            "tw.auth_replayed",
        }
    )


class Forbidden(TWError):
    """The authenticated caller is not allowed by the caller policy (spec 8.5)."""

    code = "tw.forbidden_denied"
    allowed_codes = frozenset(
        {
            "tw.forbidden_not_registered",
            "tw.forbidden_not_validator",
            "tw.forbidden_low_stake",
            "tw.forbidden_blacklisted",
        }
    )


class PayloadTooLarge(TWError):
    """The request body is over the configured limit (spec 8.6.1)."""

    code = "tw.payload_too_large"


class RateLimited(TWError):
    """A token bucket is empty (spec 8.6.2). Sent with ``Retry-After``."""

    code = "tw.rate_limited"

    def __init__(self, *, retry_after_s: float, layer: Literal["ip", "hotkey"]) -> None:
        if not math.isfinite(retry_after_s) or retry_after_s < 0:
            raise ValueError("retry_after_s must be a finite, non-negative number")
        super().__init__()
        self.layer = layer
        #: Whole seconds, rounded up, at least 1 (``Retry-After`` is an integer).
        self.retry_after = max(1, math.ceil(retry_after_s))

    @property
    def signed(self) -> bool:
        # Pre-auth (IP) rejections have no verified caller to sign for.
        return self.layer == "hotkey"

    def response_headers(self) -> dict[str, str]:
        return {"Retry-After": str(self.retry_after)}


class MetagraphStale(TWError):
    """The metagraph is too old to admit this caller (spec 8.5.1)."""

    code = "tw.metagraph_stale"


class ReplayStoreUnavailable(TWError):
    """The shared nonce store cannot be reached; fail closed (spec 8.4.3)."""

    code = "tw.replay_store_unavailable"


class InvalidRequest(TWError):
    """The verified body does not parse into the route's request model."""

    code = "tw.invalid_request"


class HandlerError(TWError):
    """The route handler raised. The original exception is logged, never sent."""

    code = "tw.handler_error"


class HandlerTimeout(TWError):
    """The route handler exceeded its timeout."""

    code = "tw.handler_timeout"


class LegacyAuthFailed(TWError):
    """A v10 request failed its signature, hash, freshness or replay check.

    See spec 8.11.2.
    """

    code = "tw.legacy_auth_failed"


class LegacyDisabled(TWError):
    """A v10 request arrived after ``TW_LEGACY_V10_UNTIL``."""

    code = "tw.legacy_disabled"


class ConfigError(TWError):
    """Settings are invalid. Raised at startup; never sent to peers.

    Unlike other errors, ``str(err)`` carries the full operator-facing detail
    (which variable, why); the public message stays generic.
    """

    code = "tw.config_invalid"

    def __init__(self, detail: str) -> None:
        super().__init__()
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class ChainError(TWError):
    """A chain read or write failed. Never sent to peers.

    ``error_code`` here is the ``bt.ErrorCode`` value (spec 3.5), not a
    ``tw.*`` code; peers only ever see ``tw.internal``.
    """

    code = "tw.internal"

    def __init__(self, error_code: str, remediation: str) -> None:
        super().__init__()
        self.chain_code = error_code
        self.remediation = remediation

    def __str__(self) -> str:
        return f"chain error {self.chain_code}: {self.remediation}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(chain_code={self.chain_code!r})"
