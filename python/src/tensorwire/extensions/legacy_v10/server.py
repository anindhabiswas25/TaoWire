"""Server side of the legacy bridge: v10 Dendrites → a TensorWire miner (spec 8.11.2).

The miner pipeline calls :class:`LegacyServer` at step [6] when
:meth:`LegacyServer.is_legacy` says a request is v10-shaped, then continues
with the caller policy, the per-hotkey rate limit and the handler exactly as
for btauth/1. Every answer to a v10 request (success or rejection) is built
by :meth:`LegacyServer.respond`, so an unmodified v10 Dendrite parses it.

On top of the v10 rules (signature over ``nonce.sender.receiver.uuid.hash``
against the miner's own hotkey; first nonce per ``(sender, uuid)`` newer than
``now - 4 s - timeout``; later nonces strictly increasing) the kit adds:

- its own freshness window: at most ``max_age`` old, at most
  ``allowed_skew`` in the future (v10 has no upper bound);
- its replay store on ``(sender, nonce)``, under a ``legacy_v10:`` namespace
  so v10 and btauth/1 nonces of one hotkey never collide;
- a body hash computed from the parsed model values (never the header);
- a mandatory end date, checked on every request (410 from that day on).
"""

from __future__ import annotations

import datetime as dt
import functools
import json
import threading
import time
import uuid as uuid_mod
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import anyio
import anyio.to_thread
import structlog
from pydantic import BaseModel

from tensorwire import crypto
from tensorwire.auth.nonce_store import NonceStore
from tensorwire.auth.verifier import DEFAULT_VERIFY_THREADS, Caller
from tensorwire.config import LEGACY_MAX_HORIZON_DAYS
from tensorwire.errors import HandlerError, LegacyAuthFailed, LegacyDisabled, TWError
from tensorwire.extensions.legacy_v10 import wire

__all__ = ["REPLAY_NAMESPACE", "LegacyRequest", "LegacyServer"]

_log = structlog.stdlib.get_logger("tensorwire.legacy_v10")

#: Prefix of the sender in replay-store keys for v10 requests.
REPLAY_NAMESPACE = "legacy_v10:"

#: v10 Axons accept a first nonce up to this much older than ``now - timeout``.
_V10_GRACE_NS = 4_000_000_000

#: Bound on remembered ``(sender, uuid)`` pairs for the strictly-increasing rule.
_MAX_TRACKED_KEYS = 65_536

Headers = Mapping[str, str] | Iterable[tuple[str, str]]


def _utc_today() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


@dataclass(frozen=True, slots=True)
class LegacyRequest:
    """A v10 request that passed every check of :meth:`LegacyServer.verify`."""

    caller: Caller
    """The verified sender (prefix-42 hotkey, nonce, ``CRYPTO_SR25519``)."""

    synapse: BaseModel | None
    """The body parsed into the route's Synapse class, with ``dendrite`` set
    from the verified headers and ``axon`` set to this miner (when the class
    declares those fields). ``None`` on a ``body_hash`` route."""

    headers: wire.RequestHeaders
    """The parsed v10 headers (echoed in the answer)."""


class LegacyServer:
    """Verifies v10 Dendrite requests and answers them in v10 shape.

    ``signer`` is the miner's hotkey: requests must be signed for it, and
    authenticated answers carry its v10 axon signature. ``store`` is the
    miner's replay store; its retention must cover ``max_age +
    allowed_skew``. ``until`` is ``TW_LEGACY_V10_UNTIL``: it must lie after
    today and at most 180 days ahead (D4); from that day on every v10
    request gets 410 ``tw.legacy_disabled``.
    """

    def __init__(
        self,
        *,
        signer: wire.SignerLike,
        store: NonceStore,
        until: dt.date,
        external_ip: str,
        external_port: int,
        max_age: float = 10.0,
        allowed_skew: float = 2.0,
        now_ns: Callable[[], int] | None = None,
        today: Callable[[], dt.date] | None = None,
        limiter: anyio.CapacityLimiter | None = None,
    ) -> None:
        self._today = _utc_today if today is None else today
        current = self._today()
        if until <= current:
            raise ValueError("TW_LEGACY_V10_UNTIL must be in the future (UTC)")
        if until > current + dt.timedelta(days=LEGACY_MAX_HORIZON_DAYS):
            raise ValueError(
                "TW_LEGACY_V10_UNTIL must be at most "
                f"{LEGACY_MAX_HORIZON_DAYS} days ahead"
            )
        for name, value in (("max_age", max_age), ("allowed_skew", allowed_skew)):
            if not value > 0:
                raise ValueError(f"{name} must be a positive number of seconds")
        if store.retention < max_age + allowed_skew:
            raise ValueError("nonce store retention too short")  # fact A3
        if not 0 < external_port <= 65535:
            raise ValueError("external_port must be 1-65535")
        self._signer = signer
        self._hotkey = signer.ss58_address
        crypto.public_key_from_ss58(self._hotkey)
        self._store = store
        self._until = until
        self._ip = external_ip
        self._port = external_port
        self._max_age_ns = int(max_age * 1e9)
        self._skew_ns = int(allowed_skew * 1e9)
        self._now_ns = time.time_ns if now_ns is None else now_ns
        self._limiter = (
            anyio.CapacityLimiter(DEFAULT_VERIFY_THREADS)
            if limiter is None
            else limiter
        )
        self._uuid = str(uuid_mod.uuid4())
        self._last: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._lock = threading.Lock()
        self._axon_nonce = 0

    @staticmethod
    def is_legacy(headers: Headers) -> bool:
        """Whether a request is v10-shaped (see :func:`wire.is_legacy_request`)."""
        return wire.is_legacy_request(headers)

    @property
    def until(self) -> dt.date:
        """The configured end date: v10 requests are refused from this day (UTC) on."""
        return self._until

    def days_remaining(self) -> int:
        """Whole days left before the end date (0 once it is reached)."""
        return max(0, (self._until - self._today()).days)

    def enabled(self) -> bool:
        """Whether v10 requests are still accepted today."""
        return self._today() < self._until

    async def verify(
        self,
        headers: Headers,
        body: bytes,
        *,
        synapse_cls: type[BaseModel] | None,
        body_hash: Callable[[bytes], str] | None,
    ) -> LegacyRequest:
        """Pipeline step [6] for a v10 request. Runs in a worker thread.

        Exactly one of ``synapse_cls`` (a ``compat.Synapse`` route) and
        ``body_hash`` (a native route's ``legacy_body_hash``) is given.
        Raises :class:`LegacyDisabled` (410) after the end date,
        :class:`LegacyAuthFailed` (401) for a malformed, stale, replayed,
        tampered or badly signed request, and
        :class:`~tensorwire.errors.ReplayStoreUnavailable` (503).
        """
        call = functools.partial(
            self.verify_sync,
            headers,
            body,
            synapse_cls=synapse_cls,
            body_hash=body_hash,
        )
        return await anyio.to_thread.run_sync(call, limiter=self._limiter)

    def verify_sync(
        self,
        headers: Headers,
        body: bytes,
        *,
        synapse_cls: type[BaseModel] | None,
        body_hash: Callable[[bytes], str] | None,
    ) -> LegacyRequest:
        """:meth:`verify` on the calling thread. Prefer :meth:`verify` in async code."""
        if (synapse_cls is None) == (body_hash is None):
            raise TypeError("give exactly one of synapse_cls and body_hash")
        if not self.enabled():
            raise LegacyDisabled()
        try:
            parsed = wire.parse_request_headers(headers)
        except wire.WireError as exc:
            raise LegacyAuthFailed(str(exc)) from None
        self._check_freshness(parsed)
        synapse = self._check_body(parsed, body, synapse_cls, body_hash)
        message = wire.request_message(
            parsed.nonce,
            parsed.sender,
            self._hotkey,
            parsed.uuid,
            parsed.computed_body_hash,
        )
        try:
            valid = crypto.verify(
                message.encode("utf-8"),
                parsed.signature,
                parsed.sender,
                crypto.CRYPTO_SR25519,
            )
        except ValueError:
            valid = False
        if not valid:
            raise LegacyAuthFailed("signature does not verify for this axon")
        self._remember(parsed)
        caller = Caller(
            hotkey_ss58=parsed.sender,
            nonce_ns=parsed.nonce,
            crypto_type=crypto.CRYPTO_SR25519,
        )
        return LegacyRequest(caller=caller, synapse=synapse, headers=parsed)

    def _check_freshness(self, parsed: wire.RequestHeaders) -> None:
        now = self._now_ns()
        age = now - parsed.nonce
        if age > self._max_age_ns:
            raise LegacyAuthFailed("nonce is too old")
        if -age > self._skew_ns:
            raise LegacyAuthFailed("nonce is in the future")
        key = (parsed.sender, parsed.uuid)
        with self._lock:
            last = self._last.get(key)
        if last is None:
            if age >= _V10_GRACE_NS + int(parsed.timeout * 1e9):
                raise LegacyAuthFailed("nonce is too old")
        elif parsed.nonce <= last:
            raise LegacyAuthFailed("nonce is not newer than the last one")

    def _check_body(
        self,
        parsed: wire.RequestHeaders,
        body: bytes,
        synapse_cls: type[BaseModel] | None,
        body_hash: Callable[[bytes], str] | None,
    ) -> BaseModel | None:
        if synapse_cls is None:
            if body_hash is None or body_hash(body) != parsed.computed_body_hash:
                raise LegacyAuthFailed("body hash mismatch")
            return None
        try:
            as_sent = wire.decode_request_body(synapse_cls, body)
        except wire.WireError as exc:
            raise LegacyAuthFailed(str(exc)) from None
        if wire.body_hash(as_sent) != parsed.computed_body_hash:
            raise LegacyAuthFailed("body hash mismatch")
        return self._handler_synapse(as_sent, body, parsed)

    def _handler_synapse(
        self, as_sent: BaseModel, body: bytes, parsed: wire.RequestHeaders
    ) -> BaseModel:
        # The handler sees the verified sender in ``dendrite`` and this miner in
        # ``axon``, never what the body claimed for them. The hash above was
        # computed on the body as sent.
        synapse_cls = type(as_sent)
        fields = synapse_cls.model_fields
        if "dendrite" not in fields and "axon" not in fields:
            return as_sent
        data: dict[str, Any] = json.loads(body)
        if "dendrite" in fields:
            data["dendrite"] = {
                "version": parsed.version,
                "nonce": parsed.nonce,
                "uuid": parsed.uuid,
                "hotkey": parsed.sender,
                "signature": crypto.signature_to_hex(parsed.signature),
            }
        if "axon" in fields:
            data["axon"] = {"ip": self._ip, "port": self._port, "hotkey": self._hotkey}
        try:
            return synapse_cls.model_validate(data)
        except ValueError:
            raise LegacyAuthFailed(
                f"body does not parse as {synapse_cls.__name__}"
            ) from None

    def _remember(self, parsed: wire.RequestHeaders) -> None:
        if not self._store.check_and_store(
            REPLAY_NAMESPACE + parsed.sender, parsed.nonce
        ):
            raise LegacyAuthFailed("request was already seen")
        key = (parsed.sender, parsed.uuid)
        with self._lock:
            self._last[key] = max(parsed.nonce, self._last.get(key, 0))
            self._last.move_to_end(key)
            while len(self._last) > _MAX_TRACKED_KEYS:
                self._last.popitem(last=False)

    def _next_axon_nonce(self) -> int:
        with self._lock:
            self._axon_nonce = max(self._axon_nonce + 1, time.time_ns())
            return self._axon_nonce

    def respond(
        self,
        request_headers: Headers,
        *,
        request: object | None = None,
        status: int,
        synapse: BaseModel | None,
        error: TWError | None,
        process_time_s: float,
        raw_body: bytes | None = None,
    ) -> tuple[bytes, list[tuple[str, str]]]:
        """Build the v10 answer to a v10 request: ``(body, headers)``.

        ``request`` is what :meth:`verify` returned, or ``None`` when the
        request was rejected before or by it (anything that is not a
        :class:`LegacyRequest` from this module counts as ``None``). Only
        answers to verified requests carry the v10 axon signature, so
        unauthenticated input never
        makes the miner sign anything. On 200, ``synapse`` is the handler's
        result (``raw_body`` passes a native route's Synapse-shaped JSON
        through unchanged). With ``error``, the body is
        ``{"message": error.public_message}`` and the error's own headers
        (``Retry-After``) are added.

        Raises :class:`~tensorwire.errors.HandlerError` (logged with the field
        name) when a 200 ``synapse`` holds an ``inf`` / ``nan`` the JSON answer
        would turn into ``null`` (8.11.2); the caller answers it as any other
        handler error, through this method again.
        """
        # Typed ``object`` so any caller's "verified request" type is accepted;
        # only one this server produced counts as verified (and gets signed).
        verified = request if isinstance(request, LegacyRequest) else None
        parsed = verified.headers if verified else _try_parse(request_headers)
        message = error.public_message if error is not None else "Success"
        name = _synapse_name(request_headers, synapse)
        signed = verified is not None
        if error is None and synapse is not None:
            field = wire.non_finite_field(synapse)
            if field is not None:
                _log.error(
                    "legacy_non_finite_answer",
                    synapse=type(synapse).__name__,
                    field=field,
                    hint="v10 answers are JSON: inf / nan would become null",
                )
                raise HandlerError()
        body, headers = wire.encode_response(
            parsed,
            status=status,
            status_message=message,
            process_time_s=process_time_s,
            axon_ip=self._ip,
            axon_port=self._port,
            axon_hotkey=self._hotkey,
            name=name,
            synapse=synapse if error is None else None,
            raw_body=raw_body if error is None else None,
            signer=self._signer if signed else None,
            axon_nonce=self._next_axon_nonce() if signed else None,
            axon_uuid=self._uuid if signed else None,
        )
        if error is not None:
            headers += list(error.response_headers().items())
        return body, headers


def _try_parse(headers: Headers) -> wire.RequestHeaders | None:
    try:
        return wire.parse_request_headers(headers)
    except wire.WireError:
        return None


def _synapse_name(headers: Headers, synapse: BaseModel | None) -> str | None:
    if synapse is not None:
        return type(synapse).__name__
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    for key, value in pairs:
        if key.lower() == "name":
            return value if wire.is_synapse_name(value) else None
    return None
