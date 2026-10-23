"""btauth/1 request verification, off the event loop (spec 8.4.2).

``bittensor.http_auth.verify`` is synchronous and spends CPU on the signature
check (fact A1), so :class:`RequestVerifier` runs it in a worker thread,
bounded by a capacity limiter (64 threads by default) so a flood of requests
cannot take every core.

The kit adds three shape checks in front of the SDK. All of them belong to
step 1 of the normative order (spec 4.3) and fail as ``tw.auth_malformed``:

- **SS58 prefix 42 only** (spec 3.2 A11, gate fix F2). The SDK accepts the
  sender address in any SS58 format, so one hotkey could appear under many
  address strings and slip past deny lists and per-hotkey rate limits keyed
  by the string. Every later stage only ever sees the canonical address.
  The sender must be exactly 48 characters, checked before any base58
  decoding (spec 4.3 step 1, D19): decoding is quadratic, and this runs
  before authentication.
- **No duplicate ``X-Bittensor-*`` headers.** Which copy wins would depend on
  the server framework; the request is ambiguous, so it is rejected.
- **The nonce is plain ASCII digits** (at most 20). Python's ``int()`` also
  accepts signs, underscores, spaces and non-ASCII digits; the TypeScript,
  Go and Rust verifiers do not.
- **``X-Bittensor-Crypto`` is exactly ``ed25519`` or ``sr25519``** (spec 4.1:
  values are exact). The SDK also takes ``0``/``1``, any case and padding.

``require_receiver`` is always ``True``; there is no way to turn it off.
"""

from __future__ import annotations

import functools
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

import anyio
import anyio.to_thread
from bittensor import http_auth

from tensorwire.auth.nonce_store import NonceStore, check_retention_margin
from tensorwire.crypto import public_key_from_ss58, scheme_name
from tensorwire.errors import AuthFailed

__all__ = ["DEFAULT_VERIFY_THREADS", "Caller", "RequestVerifier"]

#: Default bound on concurrent signature checks (spec 8.4.2).
DEFAULT_VERIFY_THREADS = 64

_AUTH_CODES: Mapping[type[http_auth.AuthError], str] = {
    http_auth.MalformedAuth: "tw.auth_malformed",
    http_auth.WrongReceiver: "tw.auth_wrong_receiver",
    http_auth.StaleRequest: "tw.auth_stale",
    http_auth.ReplayedRequest: "tw.auth_replayed",
    http_auth.BadSignature: "tw.auth_bad_signature",
}

_HEADER_PREFIX = "x-bittensor-"
_HOTKEY = http_auth.HEADER_HOTKEY.lower()
_NONCE = http_auth.HEADER_NONCE.lower()
_CRYPTO = http_auth.HEADER_CRYPTO.lower()
_SCHEMES = frozenset({"ed25519", "sr25519"})
_NONCE_RE = re.compile(r"[0-9]{1,20}")

Headers = Mapping[str, str] | Iterable[tuple[str, str]]


@dataclass(frozen=True, slots=True)
class Caller:
    """An authenticated caller: the verified sender of one request."""

    hotkey_ss58: str
    """The sender's hotkey, always a canonical prefix-42 SS58 address."""

    nonce_ns: int
    """The request nonce (Unix time in nanoseconds)."""

    crypto_type: int
    """The signature scheme's crypto type (sr25519 or ed25519)."""

    @property
    def scheme(self) -> str:
        """``"sr25519"`` or ``"ed25519"``."""
        return scheme_name(self.crypto_type)


def _malformed(message: str) -> AuthFailed:
    return AuthFailed(message, code="tw.auth_malformed")


def _auth_headers(headers: Headers) -> dict[str, str]:
    """Lower-case the header names; refuse duplicate ``X-Bittensor-*`` headers."""
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    out: dict[str, str] = {}
    for name, value in pairs:
        key = name.lower()
        if key in out and key.startswith(_HEADER_PREFIX):
            raise _malformed(f"duplicate {name} header")
        out[key] = value
    return out


def _check_shape(headers: Mapping[str, str]) -> None:
    sender = headers.get(_HOTKEY)
    if sender:
        try:
            public_key_from_ss58(sender)
        except ValueError:
            raise _malformed(
                f"{http_auth.HEADER_HOTKEY} is not a Bittensor address (SS58 prefix 42)"
            ) from None
    nonce = headers.get(_NONCE)
    if nonce is not None and not _NONCE_RE.fullmatch(nonce):
        raise _malformed(f"{http_auth.HEADER_NONCE} is not a decimal integer")
    crypto = headers.get(_CRYPTO)
    if crypto is not None and crypto not in _SCHEMES:
        raise _malformed(f"unsupported {http_auth.HEADER_CRYPTO}")


class RequestVerifier:
    """Verifies btauth/1 requests addressed to ``self_hotkey``.

    ``store`` must remember accepted nonces for at least
    ``2 x (max_age + allowed_skew)`` seconds (fact A3, spec 8.4.3, D21); a
    shorter store is refused here, at startup, whatever its kind. ``now_ns``
    replaces the wall clock (tests pass
    :class:`tensorwire.testing.clock.FakeClock`). ``limiter`` bounds the
    threads doing signature checks.
    """

    def __init__(
        self,
        self_hotkey: str,
        store: NonceStore,
        *,
        max_age: float = http_auth.DEFAULT_MAX_AGE,
        allowed_skew: float = http_auth.DEFAULT_ALLOWED_SKEW,
        limiter: anyio.CapacityLimiter | None = None,
        now_ns: Callable[[], int] | None = None,
    ) -> None:
        public_key_from_ss58(self_hotkey)
        for name, value in (("max_age", max_age), ("allowed_skew", allowed_skew)):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a positive number of seconds")
        check_retention_margin(getattr(store, "retention", 0), max_age, allowed_skew)
        self._self = self_hotkey
        self._store = store
        self._max_age = float(max_age)
        self._skew = float(allowed_skew)
        self._limiter = (
            anyio.CapacityLimiter(DEFAULT_VERIFY_THREADS)
            if limiter is None
            else limiter
        )
        self._now_ns = now_ns

    @property
    def self_hotkey(self) -> str:
        """The hotkey requests must be addressed to."""
        return self._self

    @property
    def store(self) -> NonceStore:
        """The replay store in use."""
        return self._store

    async def verify(
        self, headers: Headers, body: bytes, *, method: str, target: str
    ) -> Caller:
        """Authenticate one request, or raise.

        ``body`` is the raw received bytes and ``target`` the request target
        exactly as received (percent-encoded path plus ``?query``). Raises
        :class:`AuthFailed` (401, ``tw.auth_*``), or
        :class:`~tensorwire.errors.ReplayStoreUnavailable` (503) when a
        shared store cannot be reached.
        """
        call = functools.partial(
            self.verify_sync, headers, body, method=method, target=target
        )
        return await anyio.to_thread.run_sync(call, limiter=self._limiter)

    def verify_sync(
        self, headers: Headers, body: bytes, *, method: str, target: str
    ) -> Caller:
        """:meth:`verify` on the calling thread. Prefer :meth:`verify` in async code."""
        lowered = _auth_headers(headers)
        _check_shape(lowered)
        now = None if self._now_ns is None else self._now_ns()
        try:
            caller = http_auth.verify(
                lowered,
                body,
                method=method,
                path=target,
                self_hotkey_ss58=self._self,
                max_age=self._max_age,
                allowed_skew=self._skew,
                require_receiver=True,
                nonce_store=self._store,
                now_ns=now,
            )
        except http_auth.AuthError as exc:
            # SDK messages never echo the signature or payload (spec 3.2).
            raise AuthFailed(
                str(exc), code=_AUTH_CODES.get(type(exc), "tw.auth_failed")
            ) from None
        return Caller(
            hotkey_ss58=caller.hotkey_ss58,
            nonce_ns=caller.nonce_ns,
            crypto_type=caller.crypto_type,
        )
