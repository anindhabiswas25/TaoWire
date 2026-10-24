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
  a byte cap (``max_response_bytes``, ``tw.response_too_large``). All
  attempts for one miner, the v10 fallback included, share one budget of
  ``max_attempts * timeout_s``: an attempt gets its deadline or the time
  left, whichever is less, so a round's length is bounded.
- With ``verify_responses`` (the default) a 200 is accepted only with a
  valid ``twresp/1`` signature (spec 9.1); otherwise the result is
  ``ok=False, error_code="tw.bad_response_signature"``, and scoring code
  must treat it as a failed response.
- Neurons without a usable axon are never contacted (``tw.no_axon``).
- TLS (spec 8.6, 16.3, D31, ADR-0011), per ``scheme_policy``: ``http`` uses
  plain HTTP for everyone. ``https`` uses HTTPS for everyone: pinned to the
  miner's published ``ServeAxonTls`` key when it has one, CA-verified when it
  has none. ``https-if-tls-published`` pins miners with a published key and
  uses plain HTTP for the others. A key that does not match, or a published
  value this kit cannot pin, is ``tw.tls_pin_mismatch``
  (``tw_tls_pin_failures_total``): not retried, never over plain HTTP, and
  never through the v10 fallback (v10 is plain HTTP only, so it is used only
  for miners reached over plain HTTP).

Streaming routes (spec 9.2): :meth:`ValidatorClient.stream` returns a
:class:`MinerStream` that hands out chunks as they arrive, **unverified**
(:class:`~taowire.validator.stream.UnverifiedChunk`), and ends with the
result; :meth:`~ValidatorClient.query_stream` waits for it. The same budget,
signing and retry rules apply until the stream starts; after that there is
no retry, and the stream limits (``stream_limits``: ``TW_STREAM_*``) and the
remaining budget bound it. Score from the result only: it says
``response_verified=True`` once the ``tw-end`` trailer verified. Streams use
btauth/1 only (no v10 fallback, D33).

Legacy v10 miners (spec 8.11.3, ``TW_LEGACY_V10_CLIENT=auto``): pass the
bridge's ``legacy`` client and its ``selector``
(``extensions.legacy_v10.client.ProtocolSelector``), which owns the
protocol choice: btauth/1 for miners advertising ``TW_PROTOCOL_TAG``,
btauth/1 first for the others with one immediate v10 attempt when the
answer has the v10 shape, memory per hotkey, a re-probe once per tempo
(:meth:`ValidatorClient.reprobe`) and no downgrade after a verified
btauth/1 answer. v10 needs the request as a Synapse (``legacy_synapse``);
without one a v10 miner's answer counts as a failure.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections import OrderedDict
from collections.abc import AsyncGenerator, Callable, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal, Protocol

import anyio
import httpx
import structlog
from pydantic import BaseModel, ValidationError

from taowire.auth.signer import RequestSigner
from taowire.chain.gateway import NeuronView
from taowire.errors import ERROR_CODES, client_http_code
from taowire.extensions.response_sig import (
    HEADER_SIGNATURE,
    ResponseSignatureError,
    verify_response,
)
from taowire.extensions.streaming import StreamLimits
from taowire.miner.legacy import LegacyTraffic
from taowire.observability.metrics import Metrics
from taowire.tls import TlsPinMismatch, parse_published, pinned_context
from taowire.validator.stream import (
    StreamFailure,
    StreamReader,
    UnverifiedChunk,
    is_event_stream,
)

__all__ = [
    "RETRY_STATUSES",
    "LegacyClientLike",
    "LegacyResultLike",
    "MinerResult",
    "MinerStream",
    "ProtocolSelectorLike",
    "ValidatorClient",
    "WireProtocol",
    "check_scheme_policy",
    "failed_result",
    "is_pin_mismatch",
]

WireProtocol = Literal["btauth/1", "v10"]
SchemePolicy = Literal["http", "https", "https-if-tls-published"]

#: Statuses retried with a fresh signature (spec 8.8).
RETRY_STATUSES = frozenset({502, 503, 504})

_log = structlog.stdlib.get_logger("taowire.validator")


#: Pinned connection pools kept at once, one per miner hotkey (ADR-0011).
MAX_PINNED_CLIENTS = 4096
#: Distinct (hotkey, key) TLS warnings remembered, so a round logs each once.
_MAX_TLS_WARNINGS = 4096


def check_scheme_policy(policy: str) -> None:
    """Refuse an unknown ``TW_SCHEME_POLICY`` (spec 8.6, D31).

    ``https-if-tls-published`` was refused until key pinning shipped with
    ADR-0011 (D13, D31); every policy in :data:`SchemePolicy` is supported now.
    """
    if policy not in ("http", "https", "https-if-tls-published"):
        raise ValueError(f"unknown scheme policy {policy!r}")


def is_pin_mismatch(exc: BaseException) -> bool:
    """Whether ``exc`` (an httpx error) was caused by :class:`TlsPinMismatch`."""
    seen: BaseException | None = exc
    for _ in range(8):  # httpx -> httpcore -> ssl; bounded in case of a cycle
        if seen is None:
            return False
        if isinstance(seen, TlsPinMismatch):
            return True
        seen = seen.__cause__ or seen.__context__
    return False


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
    status_message: str | None = None
    """The v10 Axon's status message (v10 answers only)."""


class MinerStream:
    """One streaming query (spec 9.2): chunks as they arrive, then the result.

    Iterate it (``async for chunk in stream``) to get each chunk as an
    :class:`~taowire.validator.stream.UnverifiedChunk`; nothing in a chunk
    is trustworthy until the stream ends with a verified trailer. When the
    iteration ends, :attr:`result` is the :class:`MinerResult`
    (``data`` = the tuple of chunk values; ``ok`` and ``response_verified``
    only for a stream whose ``tw-end`` matched and verified). Use it as an
    async context manager, or call :meth:`aclose`, to stop early; the
    connection is released either way. Never raises for the miner's failure.
    """

    def __init__(self, source: AsyncGenerator[UnverifiedChunk | MinerResult, None]):
        self._source = source
        self.result: MinerResult | None = None
        """The outcome; ``None`` until the stream ended (or if it was closed early)."""

    def __aiter__(self) -> MinerStream:
        return self

    async def __anext__(self) -> UnverifiedChunk:
        if self.result is not None:
            raise StopAsyncIteration
        item = await anext(self._source)
        if isinstance(item, UnverifiedChunk):
            return item
        self.result = item
        await self._source.aclose()
        raise StopAsyncIteration

    async def finish(self) -> MinerResult:
        """Read the rest of the stream and return the result."""
        async for _ in self:
            pass
        if self.result is None:
            raise RuntimeError("the stream was closed before it ended")
        return self.result

    async def aclose(self) -> None:
        """Stop reading and release the connection."""
        await self._source.aclose()

    async def __aenter__(self) -> MinerStream:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


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

    @property
    def status_message(self) -> str | None:
        """The v10 status message (body ``message`` or header), if any."""
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


class ProtocolSelectorLike(Protocol):
    """Per-miner wire-format choice (``legacy_v10.client.ProtocolSelector``)."""

    def choose(self, neuron: NeuronView) -> WireProtocol:
        """The format to use for the next query to ``neuron``."""
        ...

    def after_btauth(
        self,
        neuron: NeuronView,
        *,
        status: int | None,
        headers: httpx.Headers | None,
        verified: bool,
    ) -> bool:
        """Record a btauth/1 answer; True = send one v10 attempt now."""
        ...

    def reprobe(self) -> None:
        """Forget the v10 memory (once per tempo)."""
        ...

    def forget(self, hotkey: str) -> None:
        """Forget everything about ``hotkey`` (its UID changed hands)."""
        ...


class _TooLarge(Exception):
    pass


@dataclass(frozen=True)
class _Answer:
    status: int
    headers: httpx.Headers
    content: bytes


@dataclass(frozen=True)
class _Target:
    """Where and how one miner is reached: the URL and its client (D31)."""

    url: httpx.URL
    http: httpx.AsyncClient


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
    ``legacy`` and ``selector`` (both or neither) turn on the v10 fallback.
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
        stream_limits: StreamLimits | None = None,
        legacy: LegacyClientLike | None = None,
        selector: ProtocolSelectorLike | None = None,
        metrics: Metrics | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if timeout_s <= 0 or max_concurrency < 1 or max_attempts < 1:
            raise ValueError("timeout_s, max_concurrency and max_attempts must be > 0")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be at least 1")
        if (legacy is None) != (selector is None):
            raise ValueError("pass both legacy and selector, or neither")
        check_scheme_policy(scheme_policy)
        self.signer = signer
        self.timeout_s = float(timeout_s)
        self.max_attempts = max_attempts
        self.verify_responses = verify_responses
        self.scheme_policy = scheme_policy
        self.max_response_bytes = max_response_bytes
        self.stream_limits = StreamLimits() if stream_limits is None else stream_limits
        self.metrics = metrics
        self._legacy = legacy
        self._selector = selector
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._limits = httpx.Limits(
            max_connections=max_concurrency * 2,
            max_keepalive_connections=max_concurrency,
        )
        #: Hotkey -> (its published key, the pool pinned to it or None when
        #: the key cannot be pinned). A new key retires the old pool.
        self._pinned: OrderedDict[str, tuple[bytes, httpx.AsyncClient | None]] = (
            OrderedDict()
        )
        self._retired: set[asyncio.Task[None]] = set()
        #: The longest a request or stream started so far can hold a pool.
        self._longest_hold_s = timeout_s * max_attempts + self.stream_limits.max_s
        self._tls_warned: set[tuple[str, bytes]] = set()
        self._monotonic = monotonic
        self._legacy_traffic = (
            None
            if metrics is None or legacy is None
            else LegacyTraffic(metrics, direction="outbound", monotonic=monotonic)
        )
        self._http = httpx.AsyncClient(
            transport=transport
            if transport is not None
            else httpx.AsyncHTTPTransport(retries=0),  # NEVER resend a signed request
            limits=self._limits,
            timeout=httpx.Timeout(timeout_s, connect=min(3.0, timeout_s)),
            follow_redirects=False,  # a redirect would break the target binding
        )

    # ------------------------------------------------------------ lifecycle

    async def aclose(self) -> None:
        """Close the HTTP connection pools."""
        retired = list(self._retired)
        for task in retired:
            task.cancel()  # each closes its pool on the way out
        await asyncio.gather(*retired, return_exceptions=True)
        clients = [c for _, c in self._pinned.values() if c is not None]
        self._pinned.clear()
        for client in clients:
            await client.aclose()
        await self._http.aclose()

    async def __aenter__(self) -> ValidatorClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------ protocol memory

    @property
    def legacy_enabled(self) -> bool:
        """Whether v10 miners can be reached."""
        return self._selector is not None

    def reprobe(self) -> None:
        """Probe miners remembered as v10 with btauth/1 again (once per tempo)."""
        if self._selector is not None:
            self._selector.reprobe()

    def forget(self, hotkey: str) -> None:
        """Drop protocol memory for ``hotkey`` (its UID changed hands)."""
        if self._selector is not None:
            self._selector.forget(hotkey)

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
        timeout_s: float | None = None,
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
                    timeout_s=timeout_s,
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
        timeout_s: float | None = None,
    ) -> MinerResult:
        """Query one miner. Never raises for the miner's failure.

        ``legacy_synapse`` is the same request as a v10 Synapse; without it
        a v10 miner cannot be reached and its answer counts as a failure.
        ``timeout_s`` overrides the per-attempt deadline for this call.

        One time budget covers every attempt, the v10 fallback included:
        ``max_attempts * timeout`` (spec 8.8). Each attempt's deadline is the
        per-attempt timeout or the time left, whichever is less; with no time
        left, no further attempt is sent.
        """
        timeout = self.timeout_s if timeout_s is None else float(timeout_s)
        if timeout <= 0:
            raise ValueError("timeout_s must be > 0")
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
                    deadline_s=timeout,
                )
            except Exception:  # noqa: BLE001 - one miner must never break the round
                _log.exception("query_failed", uid=neuron.uid)
                result = failed_result(neuron, "tw.internal", attempts=1)
        self._count(result)
        return result

    # ------------------------------------------------------------ streams

    def stream(
        self,
        neuron: NeuronView,
        route: str,
        body: bytes,
        *,
        method: Literal["POST", "GET"] = "POST",
        idempotent: bool = True,
        chunk_model: type[BaseModel] | None = None,
        timeout_s: float | None = None,
        max_s: float | None = None,
        max_bytes: int | None = None,
        idle_s: float | None = None,
    ) -> MinerStream:
        """Start one streaming query (spec 9.2); see :class:`MinerStream`.

        ``timeout_s`` is the per-attempt deadline (the budget is
        ``max_attempts * timeout_s``, as for :meth:`query`); ``max_s``,
        ``max_bytes`` and ``idle_s`` override :attr:`stream_limits` for this
        call. The stream ends by the budget or ``max_s``, whichever is first.
        """
        timeout = self.timeout_s if timeout_s is None else float(timeout_s)
        if timeout <= 0:
            raise ValueError("timeout_s must be > 0")
        limits = self.stream_limits.override(
            max_s=max_s, max_bytes=max_bytes, idle_s=idle_s
        )
        return MinerStream(
            self._stream(
                neuron,
                route,
                body,
                method=method,
                idempotent=idempotent,
                chunk_model=chunk_model,
                deadline_s=timeout,
                limits=limits,
            )
        )

    async def query_stream(
        self, neuron: NeuronView, route: str, body: bytes, **kw: Any
    ) -> MinerResult:
        """Run :meth:`stream` to the end and return its result."""
        async with self.stream(neuron, route, body, **kw) as stream:
            return await stream.finish()

    async def query_stream_many(
        self, neurons: Sequence[NeuronView], route: str, body: bytes, **kw: Any
    ) -> dict[int, MinerResult]:
        """:meth:`query_stream` for every neuron (bounded concurrency), by UID."""
        results = await asyncio.gather(
            *(self.query_stream(n, route, body, **kw) for n in neurons)
        )
        return {r.uid: r for r in results}

    async def _stream(
        self,
        neuron: NeuronView,
        route: str,
        body: bytes,
        *,
        method: str,
        idempotent: bool,
        chunk_model: type[BaseModel] | None,
        deadline_s: float,
        limits: StreamLimits,
    ) -> AsyncGenerator[UnverifiedChunk | MinerResult, None]:
        async with self._semaphore:
            result: MinerResult | None = None
            attempts = self._stream_attempts(
                neuron,
                route,
                body,
                method=method,
                idempotent=idempotent,
                chunk_model=chunk_model,
                deadline_s=deadline_s,
                limits=limits,
            )
            try:
                # aclosing: an early close releases the connection before the slot.
                async with contextlib.aclosing(attempts):
                    async for item in attempts:
                        if isinstance(item, MinerResult):
                            result = item
                        else:
                            yield item
            except Exception:  # noqa: BLE001 - one miner must never break the round
                _log.exception("query_failed", uid=neuron.uid)
                result = failed_result(neuron, "tw.internal", attempts=1)
        if result is not None:
            self._count(result)
            yield result

    async def _stream_attempts(
        self,
        neuron: NeuronView,
        route: str,
        body: bytes,
        *,
        method: str,
        idempotent: bool,
        chunk_model: type[BaseModel] | None,
        deadline_s: float,
        limits: StreamLimits,
    ) -> AsyncGenerator[UnverifiedChunk | MinerResult, None]:
        if neuron.axon is None:
            yield failed_result(neuron, "tw.no_axon", attempts=0)
            return
        self._hold(deadline_s * self.max_attempts + limits.max_s)
        target = self._target(neuron, route)
        if target is None:
            yield failed_result(neuron, "tw.tls_pin_mismatch", attempts=0)
            return
        budget = _Budget(self._monotonic, deadline_s, self.max_attempts)
        attempts = 0
        while True:
            attempts += 1
            started = time.perf_counter()
            attempt, response = await self._open(
                neuron, target, method, body, budget.next_deadline(), stream=True
            )
            if response is not None:
                break
            if not (
                attempts < self.max_attempts
                and self._should_retry(attempt, idempotent)
                and budget.left() > 0
            ):
                answered = self._to_result(neuron, attempt, attempts, None)
                if answered.ok:  # a 200 that is not an event stream
                    answered = replace(
                        answered, ok=False, data=None, error_code="tw.invalid_response"
                    )
                yield answered
                return
        reader = StreamReader(
            response,
            limits=limits,
            deadline=self._monotonic() + min(budget.left(), limits.max_s),
            monotonic=self._monotonic,
            chunk_model=chunk_model,
            verify=self.verify_responses,
            expected_responder=neuron.hotkey,
            request_nonce=attempt.nonce,
            sender_ss58=self.signer.hotkey_ss58,
        )

        def result(ok: bool, code: str | None) -> MinerResult:
            return MinerResult(
                uid=neuron.uid,
                hotkey=neuron.hotkey,
                ok=ok,
                status=200,
                latency_ms=(time.perf_counter() - started) * 1000,
                data=tuple(reader.values) if ok else None,
                error_code=code,
                attempts=attempts,
                response_verified=ok and self.verify_responses,
            )

        try:
            async with contextlib.aclosing(reader.chunks()) as chunks:
                async for chunk in chunks:
                    yield chunk
        except StreamFailure as failure:
            _log.warning(
                "stream_rejected",
                uid=neuron.uid,
                code=failure.code,
                reason=failure.reason,
            )
            if self.metrics is not None:
                self.metrics.stream_aborted.labels(
                    side="validator", reason=failure.metric_reason
                ).inc()
            yield result(False, failure.code)
            return
        finally:
            await response.aclose()
        yield result(True, None)

    # ------------------------------------------------------------ one query

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
        deadline_s: float,
    ) -> MinerResult:
        if neuron.axon is None:
            return failed_result(neuron, "tw.no_axon", attempts=0)
        self._hold(deadline_s * self.max_attempts)
        target = self._target(neuron, route)
        if target is None:
            return failed_result(neuron, "tw.tls_pin_mismatch", attempts=0)
        budget = _Budget(self._monotonic, deadline_s, self.max_attempts)
        # v10 is plain HTTP only: never for a miner this policy reaches over TLS.
        selector = self._selector if target.url.scheme == "http" else None
        if (
            selector is not None
            and legacy_synapse is not None
            and selector.choose(neuron) == "v10"
        ):
            return await self._query_v10(
                neuron, legacy_synapse, response_model, 0, budget
            )
        attempts = 1
        last = await self._attempt(neuron, target, method, body, budget.next_deadline())
        while (
            attempts < self.max_attempts
            and self._should_retry(last, idempotent)
            and budget.left() > 0
        ):
            attempts += 1
            last = await self._attempt(
                neuron, target, method, body, budget.next_deadline()
            )
        result = self._to_result(neuron, last, attempts, response_model)
        if selector is None or legacy_synapse is None:
            return result
        answer = last.answer
        switch = selector.after_btauth(
            neuron,
            status=None if answer is None else answer.status,
            headers=None if answer is None else answer.headers,
            verified=result.response_verified,
        )
        if not switch:
            return result
        _log.info("miner_speaks_v10", uid=neuron.uid)
        return await self._query_v10(
            neuron, legacy_synapse, response_model, attempts, budget
        )

    def _target(self, neuron: NeuronView, route: str) -> _Target | None:
        """The URL and client for ``neuron`` under the scheme policy (D31).

        ``None``: the miner published a TLS key this kit cannot pin, so it is
        refused (``tw.tls_pin_mismatch``) rather than reached another way.
        """
        if neuron.axon is None:
            raise ValueError("neuron has no axon")
        if not route.startswith("/"):
            raise ValueError("route must start with /")
        scheme: Literal["http", "https"] = (
            "https" if self.scheme_policy == "https" else "http"
        )
        http = self._http
        if self.scheme_policy != "http" and neuron.tls_key is not None:
            pinned = self._pinned_client(neuron.hotkey, neuron.tls_key)
            if pinned is None:
                self._pin_failed(neuron, "tls_key_unusable")
                return None
            scheme, http = "https", pinned
        base = httpx.URL(neuron.axon.base_url(scheme))
        return _Target(base.copy_with(raw_path=route.encode("ascii")), http)

    def _pinned_client(self, hotkey: str, published: bytes) -> httpx.AsyncClient | None:
        """The pool pinned to ``hotkey``'s published key; ``None`` if unpinnable."""
        entry = self._pinned.get(hotkey)
        if entry is not None and entry[0] == published:
            self._pinned.move_to_end(hotkey)
            return entry[1]
        client: httpx.AsyncClient | None = None
        if parse_published(published) is not None:
            client = httpx.AsyncClient(
                transport=httpx.AsyncHTTPTransport(
                    verify=pinned_context(published), retries=0
                ),
                limits=self._limits,
                timeout=self._http.timeout,
                follow_redirects=False,
            )
        if entry is not None and entry[1] is not None:
            self._retire(entry[1])  # the miner rotated its key
        self._pinned[hotkey] = (published, client)
        self._pinned.move_to_end(hotkey)
        if len(self._pinned) > MAX_PINNED_CLIENTS:
            _, (_, old) = self._pinned.popitem(last=False)
            if old is not None:
                self._retire(old)
        return client

    def _hold(self, seconds: float) -> None:
        """Note that a request or stream may hold its pool for ``seconds``."""
        self._longest_hold_s = max(self._longest_hold_s, seconds)

    def _retire(self, client: httpx.AsyncClient) -> None:
        """Close a replaced pool once requests that may still use it are over."""
        grace = self._longest_hold_s

        async def close() -> None:
            try:
                await anyio.sleep(grace)
            finally:
                with anyio.CancelScope(shield=True):
                    await client.aclose()

        task = asyncio.get_running_loop().create_task(close())
        self._retired.add(task)
        task.add_done_callback(self._retired.discard)

    def _pin_failed(self, neuron: NeuronView, reason: str) -> None:
        if self.metrics is not None:
            self.metrics.tls_pin_failures.inc()
        key = (neuron.hotkey, neuron.tls_key or b"")
        if key in self._tls_warned:
            return
        if len(self._tls_warned) >= _MAX_TLS_WARNINGS:
            self._tls_warned.clear()
        self._tls_warned.add(key)
        _log.warning(
            "tls_pin_mismatch", uid=neuron.uid, hotkey=neuron.hotkey, reason=reason
        )

    def _should_retry(self, attempt: _Attempt, idempotent: bool) -> bool:
        if attempt.error_code == "tw.connect_error":
            return True  # nothing reached the miner
        if attempt.error_code == "tw.timeout":
            return idempotent
        answer = attempt.answer
        return answer is not None and answer.status in RETRY_STATUSES

    async def _attempt(
        self,
        neuron: NeuronView,
        target: _Target,
        method: str,
        body: bytes,
        deadline_s: float,
    ) -> _Attempt:
        attempt, _ = await self._open(neuron, target, method, body, deadline_s)
        return attempt

    async def _open(
        self,
        neuron: NeuronView,
        target: _Target,
        method: str,
        body: bytes,
        deadline_s: float,
        *,
        stream: bool = False,
    ) -> tuple[_Attempt, httpx.Response | None]:
        """One attempt: a fresh signature, the request, the whole answer.

        With ``stream``, a ``200 text/event-stream`` answer is returned open
        after its head (the caller reads and closes it); any other answer is
        read whole as usual, and the response is ``None``.
        """
        url, http = target.url, target.http
        headers = self.signer.sign(
            method=method,
            target=url.raw_path.decode("ascii"),
            body=body,
            receiver_ss58=neuron.hotkey,
        )
        nonce = int(headers["X-Bittensor-Nonce"])
        if body:
            headers["Content-Type"] = "application/json"
        timeout = httpx.Timeout(deadline_s, connect=min(3.0, deadline_s))
        if stream:
            headers["Accept"] = "text/event-stream"
            headers["Accept-Encoding"] = "identity"  # an encoded stream is refused
            # No read timeout: fail_after bounds the attempt up to the head;
            # after it, StreamReader applies the stream limits to every read.
            timeout = httpx.Timeout(deadline_s, connect=min(3.0, deadline_s), read=None)
        request = http.build_request(
            method, url, headers=headers, content=body, timeout=timeout
        )
        started = time.perf_counter()
        code: str | None = None
        answer: _Answer | None = None
        try:
            with anyio.fail_after(deadline_s):
                response = await http.send(request, stream=True)
                if (
                    stream
                    and response.status_code == 200
                    and is_event_stream(response.headers)
                ):
                    latency = (time.perf_counter() - started) * 1000
                    return _Attempt(None, None, nonce, latency), response
                try:
                    answer = await self._read(response)
                finally:
                    await response.aclose()
        except httpx.ConnectError as exc:
            code = "tw.connect_error"
            if is_pin_mismatch(exc):
                code = "tw.tls_pin_mismatch"
                self._pin_failed(neuron, "key_differs")
        except (httpx.ConnectTimeout, httpx.PoolTimeout):
            code = "tw.connect_error"
        except (TimeoutError, httpx.TimeoutException):
            code = "tw.timeout"
        except _TooLarge:
            code = "tw.response_too_large"
        except httpx.HTTPError:
            code = "tw.invalid_response"  # protocol error or dropped mid-answer
        latency = (time.perf_counter() - started) * 1000
        return _Attempt(answer, code, nonce, latency), None

    async def _read(self, response: httpx.Response) -> _Answer:
        """Read a whole answer with the byte cap (``_TooLarge``)."""
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
            return failed_result(
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
        budget: _Budget,
    ) -> MinerResult:
        if self._legacy is None:
            raise RuntimeError("the legacy v10 client is off")
        deadline_s = budget.next_deadline()
        if deadline_s <= 0:
            # The btauth/1 attempts used the whole budget (spec 8.8).
            return replace(
                failed_result(neuron, "tw.timeout", attempts=attempts), protocol="v10"
            )
        started = time.perf_counter()
        legacy: LegacyResultLike
        try:
            with anyio.fail_after(deadline_s):
                legacy = await self._legacy.query(
                    self._http,
                    neuron,
                    synapse,
                    timeout_s=deadline_s,
                    max_response_bytes=self.max_response_bytes,
                )
        except TimeoutError:
            legacy = _LegacyTimeout((time.perf_counter() - started) * 1000)
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
            status_message=legacy.status_message,
        )

    def _count(self, result: MinerResult) -> None:
        if self.metrics is None:
            return
        self.metrics.validator_miner_results.labels(
            ok=str(result.ok).lower(), code=result.error_code or "ok"
        ).inc()


class _Budget:
    """One query's time budget: ``max_attempts * per-attempt timeout`` (spec 8.8)."""

    def __init__(
        self, monotonic: Callable[[], float], per_attempt_s: float, max_attempts: int
    ) -> None:
        self._monotonic = monotonic
        self._per_attempt_s = per_attempt_s
        self._ends = monotonic() + per_attempt_s * max_attempts

    def left(self) -> float:
        """Seconds left; never negative."""
        return max(0.0, self._ends - self._monotonic())

    def next_deadline(self) -> float:
        """The next attempt's deadline: the per-attempt timeout or the time left."""
        return min(self._per_attempt_s, self.left())


@dataclass(frozen=True)
class _LegacyTimeout:
    """A v10 attempt cut off by the query budget (shaped like a legacy result)."""

    latency_ms: float
    status: int | None = None
    synapse: BaseModel | None = None
    error_code: str | None = "tw.timeout"
    status_message: str | None = None


def failed_result(
    neuron: NeuronView, code: str, *, attempts: int, latency_ms: float | None = None
) -> MinerResult:
    """A failed :class:`MinerResult` for ``neuron`` with ``code`` and no answer."""
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
