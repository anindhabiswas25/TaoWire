"""The validator's fan-out client (spec 8.8, 5.4; legacy fallback 8.11.3).

:class:`ValidatorClient` sends one request body to many miners and returns
one :class:`MinerResult` per miner. It never raises for one miner's failure.

Rules it enforces:

- The body is serialized once by the caller; each miner and each attempt
  gets its own btauth/1 signature, bound to that miner's hotkey, with a
  fresh nonce.
- The signed target is exactly the ``raw_path`` httpx sends (the URL is
  built with ``copy_with(raw_path=...)``), so both sides agree byte for byte.
- No transport-level retries and no redirects: a signed request is never
  resent by the HTTP stack. The client retries itself, with a new
  signature, only on connect errors, timeouts (idempotent requests only)
  and 502/503/504; never on 4xx.
- Each attempt has a deadline (``timeout_s``) and the response is read with
  a byte cap (``max_response_bytes``, ``tw.response_too_large``).
- With ``verify_responses`` (the default) a 200 is accepted only with a
  valid ``twresp/1`` signature (spec 9.1); otherwise the result is
  ``ok=False, error_code="tw.bad_response_signature"``, and scoring code
  must treat it as a failed response.
- Neurons without a usable axon are never contacted (``tw.no_axon``).

Legacy v10 miners (``legacy_mode="auto"``, spec 8.11.3): a miner whose
on-chain axon protocol is ``TW_PROTOCOL_TAG`` always gets btauth/1. Any
other miner gets btauth/1 first; if it answers like a v10 Axon (HTTP 500
with a ``bt_header_axon_status_code`` header) and the call carries a
``legacy_synapse``, the client retries once at once in the v10 format and
remembers ``v10`` for that hotkey. :meth:`ValidatorClient.reprobe` (the
loop calls it once per tempo) forgets those, so upgraded miners switch
back. A hotkey that has answered with btauth/1 is never sent v10 again
(no downgrade).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import anyio
import httpx
import structlog
from pydantic import BaseModel, ValidationError

from tensorwire.auth.signer import RequestSigner
from tensorwire.chain.gateway import NeuronView
from tensorwire.config import DEFAULT_PROTOCOL_TAG
from tensorwire.errors import ERROR_CODES, client_http_code
from tensorwire.extensions.response_sig import (
    HEADER_SIGNATURE,
    ResponseSignatureError,
    verify_response,
)
from tensorwire.miner.legacy import LegacyTraffic
from tensorwire.observability.metrics import Metrics

__all__ = [
    "RETRY_STATUSES",
    "V10_MARKER_HEADER",
    "LegacyClientLike",
    "LegacyResultLike",
    "MinerResult",
    "ValidatorClient",
    "WireProtocol",
]

WireProtocol = Literal["btauth/1", "v10"]
SchemePolicy = Literal["http", "https", "https-if-tls-published"]

#: Statuses retried with a fresh signature (spec 8.8).
RETRY_STATUSES = frozenset({502, 503, 504})
#: Every v10 Axon response has this header; on a 500 it marks a v10 miner (N7).
V10_MARKER_HEADER = "bt_header_axon_status_code"
_MAX_REMEMBERED = 65_536

_log = structlog.stdlib.get_logger("tensorwire.validator")


@dataclass(frozen=True)
class MinerResult:
    """The outcome of one query to one miner."""

    uid: int
    hotkey: str
    ok: bool
    status: int | None
    latency_ms: float | None
    data: Any | None
    """The parsed ``response_model`` (or Synapse on v10), or the raw bytes."""
    error_code: str | None
    """A ``tw.*`` code: the miner's own code, or ``tw.timeout``,
    ``tw.connect_error``, ``tw.http_<status>``, ``tw.bad_response_signature``,
    ``tw.response_too_large``, ``tw.invalid_response``, ``tw.no_axon``."""
    attempts: int
    protocol: WireProtocol = "btauth/1"
    """Which wire format answered (spec 8.11.3)."""
    response_verified: bool = False
    """True only for a valid ``twresp/1`` signature; always False for v10."""


class LegacyResultLike(Protocol):
    """One v10 attempt's outcome (``extensions.legacy_v10.client.LegacyResult``)."""

    @property
    def status(self) -> int | None:
        """HTTP status, ``None`` when no response arrived."""
        ...

    @property
    def synapse(self) -> BaseModel | None:
        """The 200 body parsed into the request's Synapse class."""
        ...

    @property
    def error_code(self) -> str | None:
        """A client-side ``tw.*`` code, or ``None`` on success."""
        ...

    @property
    def latency_ms(self) -> float | None:
        """Time to the full response."""
        ...


class LegacyClientLike(Protocol):
    """Sends one v10-format request (``extensions.legacy_v10.client.LegacyClient``)."""

    async def query(
        self,
        http: httpx.AsyncClient,
        neuron: NeuronView,
        synapse: BaseModel,
        *,
        timeout_s: float,
        max_response_bytes: int,
    ) -> LegacyResultLike:
        """One attempt, fresh nonce; never raises for the miner's failure."""
        ...


class _TooLarge(Exception):
    pass


@dataclass(frozen=True)
class _Answer:
    status: int
    headers: httpx.Headers
    content: bytes


@dataclass(frozen=True)
class _Attempt:
    answer: _Answer | None
    error_code: str | None
    nonce: int
    latency_ms: float


class ValidatorClient:
    """Fans one request out to many miners (spec 8.8).

    ``transport`` replaces the network transport (tests pass an ASGI or
    mock transport); transport-level retries stay off either way.
    ``legacy`` and ``legacy_mode="auto"`` turn on the v10 fallback;
    ``legacy_until`` stops it after that date (UTC).
    """

    def __init__(
        self,
        signer: RequestSigner,
        *,
        timeout_s: float = 12.0,
        max_concurrency: int = 64,
        max_attempts: int = 2,
        verify_responses: bool = True,
        scheme_policy: SchemePolicy = "http",
        max_response_bytes: int = 4 * 1024 * 1024,
        protocol_tag: int = DEFAULT_PROTOCOL_TAG,
        legacy: LegacyClientLike | None = None,
        legacy_mode: Literal["auto", "off"] = "off",
        legacy_until: dt.date | None = None,
        metrics: Metrics | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        today: Callable[[], dt.date] | None = None,
    ) -> None:
        if timeout_s <= 0 or max_concurrency < 1 or max_attempts < 1:
            raise ValueError("timeout_s, max_concurrency and max_attempts must be > 0")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be at least 1")
        if legacy_mode == "auto" and legacy is None:
            raise ValueError("legacy_mode='auto' needs a legacy client")
        self.signer = signer
        self.timeout_s = float(timeout_s)
        self.max_attempts = max_attempts
        self.verify_responses = verify_responses
        self.scheme_policy = scheme_policy
        self.max_response_bytes = max_response_bytes
        self.protocol_tag = protocol_tag
        self.metrics = metrics
        self._legacy = legacy if legacy_mode == "auto" else None
        self._legacy_until = legacy_until
        self._today = today or (lambda: dt.datetime.now(dt.timezone.utc).date())
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._v10_hotkeys: set[str] = set()
        self._btauth_hotkeys: set[str] = set()
        self._legacy_traffic = (
            None
            if metrics is None or self._legacy is None
            else LegacyTraffic(
                metrics, direction="outbound", monotonic=monotonic, until=legacy_until
            )
        )
        self._http = httpx.AsyncClient(
            transport=transport
            if transport is not None
            else httpx.AsyncHTTPTransport(retries=0),  # NEVER resend a signed request
            limits=httpx.Limits(
                max_connections=max_concurrency * 2,
                max_keepalive_connections=max_concurrency,
            ),
            timeout=httpx.Timeout(timeout_s, connect=min(3.0, timeout_s)),
            follow_redirects=False,  # a redirect would break the target binding
        )

    # ------------------------------------------------------------ lifecycle

    async def aclose(self) -> None:
        """Close the HTTP connection pool."""
        await self._http.aclose()

    async def __aenter__(self) -> ValidatorClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------ protocol memory

    def reprobe(self) -> None:
        """Forget which miners answered v10, so they are probed with btauth/1 again.

        The validator loop calls this once per tempo (spec 8.11.3 step 3).
        """
        self._v10_hotkeys.clear()

    def retain(self, hotkeys: set[str]) -> None:
        """Forget protocol memory for hotkeys no longer in the metagraph."""
        self._v10_hotkeys &= hotkeys
        self._btauth_hotkeys &= hotkeys

    def protocol_of(self, hotkey: str) -> WireProtocol | None:
        """What the client remembers about ``hotkey``, if anything."""
        if hotkey in self._btauth_hotkeys:
            return "btauth/1"
        if hotkey in self._v10_hotkeys:
            return "v10"
        return None

    def _legacy_active(self) -> bool:
        if self._legacy is None:
            return False
        return self._legacy_until is None or self._today() < self._legacy_until

    def _may_use_v10(self, neuron: NeuronView, synapse: BaseModel | None) -> bool:
        return (
            synapse is not None
            and self._legacy_active()
            and neuron.axon_protocol != self.protocol_tag
            and neuron.hotkey not in self._btauth_hotkeys
        )

    @staticmethod
    def _remember(bucket: set[str], hotkey: str) -> None:
        if len(bucket) >= _MAX_REMEMBERED:
            bucket.clear()
        bucket.add(hotkey)

    # ------------------------------------------------------------ queries

    async def query_many(
        self,
        neurons: Sequence[NeuronView],
        route: str,
        body: bytes,
        *,
        method: Literal["POST", "GET"] = "POST",
        idempotent: bool = True,
        response_model: type[BaseModel] | None = None,
        legacy_synapse: BaseModel | None = None,
    ) -> dict[int, MinerResult]:
        """Query every neuron (bounded concurrency); one result per UID."""
        results = await asyncio.gather(
            *(
                self.query(
                    n,
                    route,
                    body,
                    method=method,
                    idempotent=idempotent,
                    response_model=response_model,
                    legacy_synapse=legacy_synapse,
                )
                for n in neurons
            )
        )
        return {r.uid: r for r in results}

    async def query(
        self,
        neuron: NeuronView,
        route: str,
        body: bytes,
        *,
        method: Literal["POST", "GET"] = "POST",
        idempotent: bool = True,
        response_model: type[BaseModel] | None = None,
        legacy_synapse: BaseModel | None = None,
    ) -> MinerResult:
        """Query one miner. Never raises for the miner's failure.

        ``legacy_synapse`` is the same request as a v10 Synapse; without it
        a v10 miner cannot be reached and its answer counts as a failure.
        """
        async with self._semaphore:
            try:
                result = await self._query(
                    neuron,
                    route,
                    body,
                    method=method,
                    idempotent=idempotent,
                    response_model=response_model,
                    legacy_synapse=legacy_synapse,
                )
            except Exception:  # noqa: BLE001 - one miner must never break the round
                _log.exception("query_failed", uid=neuron.uid)
                result = _failed(neuron, "tw.internal", attempts=1)
        self._count(result)
        return result

    async def _query(
        self,
        neuron: NeuronView,
        route: str,
        body: bytes,
        *,
        method: str,
        idempotent: bool,
        response_model: type[BaseModel] | None,
        legacy_synapse: BaseModel | None,
    ) -> MinerResult:
        if neuron.axon is None:
            return _failed(neuron, "tw.no_axon", attempts=0)
        may_v10 = self._may_use_v10(neuron, legacy_synapse)
        if (
            may_v10
            and legacy_synapse is not None
            and neuron.hotkey in self._v10_hotkeys
        ):
            return await self._query_v10(neuron, legacy_synapse, response_model, 0)
        url = self._url(neuron, route)
        attempts = 1
        last = await self._attempt(neuron, method, url, body)
        while attempts < self.max_attempts and self._should_retry(last, idempotent):
            attempts += 1
            last = await self._attempt(neuron, method, url, body)
        answer = last.answer
        v10 = answer is not None and _is_v10_answer(answer)
        if v10 and may_v10 and legacy_synapse is not None:
            self._remember(self._v10_hotkeys, neuron.hotkey)
            _log.info("miner_speaks_v10", uid=neuron.uid)
            return await self._query_v10(
                neuron, legacy_synapse, response_model, attempts
            )
        result = self._to_result(neuron, last, attempts, response_model)
        if result.response_verified or (result.ok and not self.verify_responses):
            self._v10_hotkeys.discard(neuron.hotkey)
            self._remember(self._btauth_hotkeys, neuron.hotkey)
        return result

    def _url(self, neuron: NeuronView, route: str) -> httpx.URL:
        if neuron.axon is None:
            raise ValueError("neuron has no axon")
        scheme: Literal["http", "https"] = (
            "https" if self.scheme_policy == "https" else "http"
        )
        base = httpx.URL(neuron.axon.base_url(scheme))
        if not route.startswith("/"):
            raise ValueError("route must start with /")
        return base.copy_with(raw_path=route.encode("ascii"))

    def _should_retry(self, attempt: _Attempt, idempotent: bool) -> bool:
        if attempt.error_code == "tw.connect_error":
            return True  # nothing reached the miner
        if attempt.error_code == "tw.timeout":
            return idempotent
        answer = attempt.answer
        return answer is not None and answer.status in RETRY_STATUSES

    async def _attempt(
        self, neuron: NeuronView, method: str, url: httpx.URL, body: bytes
    ) -> _Attempt:
        target = url.raw_path.decode("ascii")
        headers = self.signer.sign(
            method=method, target=target, body=body, receiver_ss58=neuron.hotkey
        )
        nonce = int(headers["X-Bittensor-Nonce"])
        if body:
            headers["Content-Type"] = "application/json"
        started = time.perf_counter()
        code: str | None = None
        answer: _Answer | None = None
        try:
            with anyio.fail_after(self.timeout_s):
                answer = await self._send(method, url, headers, body)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout):
            code = "tw.connect_error"
        except (TimeoutError, httpx.TimeoutException):
            code = "tw.timeout"
        except _TooLarge:
            code = "tw.response_too_large"
        except httpx.HTTPError:
            code = "tw.invalid_response"  # protocol error or dropped mid-answer
        latency = (time.perf_counter() - started) * 1000
        return _Attempt(answer=answer, error_code=code, nonce=nonce, latency_ms=latency)

    async def _send(
        self, method: str, url: httpx.URL, headers: dict[str, str], body: bytes
    ) -> _Answer:
        request = self._http.build_request(method, url, headers=headers, content=body)
        response = await self._http.send(request, stream=True)
        try:
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > self.max_response_bytes:
                raise _TooLarge
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > self.max_response_bytes:
                    raise _TooLarge
                chunks.append(chunk)
        finally:
            await response.aclose()
        return _Answer(response.status_code, response.headers, b"".join(chunks))

    def _to_result(
        self,
        neuron: NeuronView,
        attempt: _Attempt,
        attempts: int,
        response_model: type[BaseModel] | None,
    ) -> MinerResult:
        answer = attempt.answer
        if answer is None:
            return _failed(
                neuron,
                attempt.error_code or "tw.invalid_response",
                attempts=attempts,
                latency_ms=attempt.latency_ms,
            )
        verified, signature_error = self._check_signature(neuron, attempt, answer)

        def result(ok: bool, data: Any, code: str | None) -> MinerResult:
            return MinerResult(
                uid=neuron.uid,
                hotkey=neuron.hotkey,
                ok=ok,
                status=answer.status,
                latency_ms=attempt.latency_ms,
                data=data,
                error_code=code,
                attempts=attempts,
                response_verified=verified,
            )

        if signature_error:
            return result(False, None, "tw.bad_response_signature")
        if answer.status != 200:
            return result(False, None, _error_code(answer))
        if response_model is None:
            return result(True, answer.content, None)
        try:
            data = response_model.model_validate_json(answer.content)
        except ValidationError:
            return result(False, None, "tw.invalid_response")
        return result(True, data, None)

    def _check_signature(
        self, neuron: NeuronView, attempt: _Attempt, answer: _Answer
    ) -> tuple[bool, bool]:
        """(verified, failed): a 200 must be signed; any signature must be valid."""
        if not self.verify_responses:
            return False, False
        signed = HEADER_SIGNATURE.lower() in answer.headers
        if not signed and answer.status != 200:
            return False, False  # pre-auth errors are never signed
        try:
            verify_response(
                answer.headers.multi_items(),
                expected_responder=neuron.hotkey,
                request_nonce=attempt.nonce,
                sender_ss58=self.signer.hotkey_ss58,
                status=answer.status,
                body=answer.content,
            )
        except ResponseSignatureError as exc:
            _log.warning("bad_response_signature", uid=neuron.uid, reason=exc.reason)
            return False, True
        return True, False

    async def _query_v10(
        self,
        neuron: NeuronView,
        synapse: BaseModel,
        response_model: type[BaseModel] | None,
        attempts: int,
    ) -> MinerResult:
        if self._legacy is None:
            raise RuntimeError("the legacy v10 client is off")
        legacy = await self._legacy.query(
            self._http,
            neuron,
            synapse,
            timeout_s=self.timeout_s,
            max_response_bytes=self.max_response_bytes,
        )
        data: Any = legacy.synapse
        code = legacy.error_code
        ok = legacy.status == 200 and code is None and data is not None
        if ok and response_model is not None and not isinstance(data, response_model):
            try:
                data = response_model.model_validate(_user_fields(data))
            except ValidationError:
                ok, data, code = False, None, "tw.invalid_response"
        if not ok and code is None:
            code = (
                client_http_code(legacy.status)
                if legacy.status is not None
                else "tw.invalid_response"
            )
        if self._legacy_traffic is not None:
            self._legacy_traffic.record(neuron.hotkey, "ok" if ok else str(code))
        return MinerResult(
            uid=neuron.uid,
            hotkey=neuron.hotkey,
            ok=ok,
            status=legacy.status,
            latency_ms=legacy.latency_ms,
            data=data if ok else None,
            error_code=None if ok else code,
            attempts=attempts + 1,
            protocol="v10",
            response_verified=False,
        )

    def _count(self, result: MinerResult) -> None:
        if self.metrics is None:
            return
        self.metrics.validator_miner_results.labels(
            ok=str(result.ok).lower(), code=result.error_code or "ok"
        ).inc()


def _failed(
    neuron: NeuronView, code: str, *, attempts: int, latency_ms: float | None = None
) -> MinerResult:
    return MinerResult(
        uid=neuron.uid,
        hotkey=neuron.hotkey,
        ok=False,
        status=None,
        latency_ms=latency_ms,
        data=None,
        error_code=code,
        attempts=attempts,
    )


def _is_v10_answer(answer: _Answer) -> bool:
    return answer.status == 500 and V10_MARKER_HEADER in answer.headers


def _error_code(answer: _Answer) -> str:
    """The miner's ``tw.*`` code from an error body, else ``tw.http_<status>``."""
    with contextlib.suppress(ValueError, TypeError, KeyError, AttributeError):
        code = json.loads(answer.content)["error"]["code"]
        if isinstance(code, str) and code in ERROR_CODES:
            return code
    return client_http_code(answer.status)


def _user_fields(model: BaseModel) -> dict[str, Any]:
    fields = getattr(model, "user_fields", None)
    if callable(fields):
        values: dict[str, Any] = fields()
        return values
    return model.model_dump()
