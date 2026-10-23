"""Timelocked challenges and responses (spec 8.10, D30; 16.1 row 11).

Data sealed to a future drand round can be opened by anyone once that round
is published (every 3 s, worldwide), and by nobody before. Two opt-in uses:

- **Sealed challenge.** The validator sends ``SealedChallenge`` (the task,
  sealed to open in ``reveal_in``, default 30 s) to every miner ahead of
  time. Miners open it at the reveal moment: none gets a head start from
  network placement.
- **Sealed response.** The miner answers ``SealedResponse`` (its answer
  sealed to a short reveal, default 12 s). The validator holds the
  ciphertext, inside the ``twresp/1``-signed body, before anyone can read
  it, so a colluding validator cannot leak answers before scoring.

``bt.timelock`` itself is called only by the chain gateway (ADR-0001, D30:
``timelock_seal`` / ``timelock_parse`` / ``timelock_signature`` /
``timelock_decrypt``). This module adds what the drand dependency needs:

- **a drand cache**: one round signature serves every ciphertext of that
  round; it is fetched once (concurrent opens wait for the fetch in flight),
  checked by the gateway, and kept for the last :data:`_CACHED_ROUNDS` rounds.
  With a good signature, a ciphertext that does not open is junk
  (``TimelockMalformed``) at once: a hostile miner cannot buy extra drand
  fetches or hold the limiter with bad answers;
- one deadline per open (``timeout_s``, default ``TW_TIMELOCK_TIMEOUT_S``),
  waiting for the reveal on the event loop, a process-wide limit on
  concurrent drand fetches (``TW_TIMELOCK_CONCURRENCY``) and retries with
  backoff (``TW_TIMELOCK_RETRIES``; waiting for a beacon that lags is not a
  retry);
- the outcome mapping: drand unreachable, rate-limited (HTTP 429), failing
  (5xx) or timing out after the retries, or a reveal later than the deadline,
  is :class:`TimelockUnavailable` (``tw.timelock_unavailable``), logged at
  WARNING and counted in ``tw_timelock_open_total{result="unavailable"}``.
  Never an unbounded wait.

Use one :class:`Timelock` per process: its limiter is what bounds the load
on the drand API (the localnet chain uses the same public endpoint).
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Literal, TypeVar

import anyio
import structlog
from pydantic import BaseModel, ConfigDict, ValidationError

from tensorwire.chain.gateway import (
    ChainGateway,
    TimelockMalformed,
    TimelockNotReady,
    TimelockUnavailable,
)
from tensorwire.observability.metrics import Metrics

if TYPE_CHECKING:  # the validator imports this module: no import back at run time
    from tensorwire.validator.client import MinerResult

__all__ = [
    "SealedChallenge",
    "SealedResponse",
    "Timelock",
    "TimelockMalformed",
    "TimelockNotReady",
    "TimelockUnavailable",
    "parse_reveal_in",
]

_M = TypeVar("_M", bound=BaseModel)
_log = structlog.stdlib.get_logger("tensorwire.timelock")

#: Retry backoff: 0.5 s, doubling, at most this.
_BACKOFF_MAX_S = 4.0
#: One drand fetch at most this long, so a hanging fetch cannot hold a limiter
#: slot for the whole deadline.
_TRY_S = 10.0
#: Round signatures kept (one round every 3 s: the last ~3 minutes).
_CACHED_ROUNDS = 64
#: Shortest wait for a beacon that lags its schedule.
_LAG_S = 0.05
_UNITS = {"s": 1.0, "m": 60.0, "h": 3600.0}


def parse_reveal_in(value: str | float) -> float:
    """``"30s"``, ``"2m"``, ``"1h"`` or a number of seconds, as seconds (> 0)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
    elif isinstance(value, str) and value[-1:] in _UNITS:
        seconds = float(value[:-1]) * _UNITS[value[-1]]
    elif isinstance(value, str):
        seconds = float(value)
    else:
        raise ValueError("reveal_in must be seconds or a string like '30s'")
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("reveal_in must be a positive duration")
    return seconds


class SealedChallenge(BaseModel):
    """A task sealed until ``reveal_round`` (validator → miners)."""

    model_config = ConfigDict(frozen=True)

    sealed: str
    """The timelock ciphertext, hex."""
    reveal_round: int


class SealedResponse(BaseModel):
    """An answer sealed until ``reveal_round`` (miner → validator)."""

    model_config = ConfigDict(frozen=True)

    sealed: Literal[True] = True
    ciphertext: str
    """The timelock ciphertext of the answer's JSON, hex."""
    reveal_round: int


class Timelock:
    """Seal and open data through the chain gateway; see the module docstring."""

    def __init__(
        self,
        gateway: ChainGateway,
        *,
        concurrency: int = 8,
        retries: int = 3,
        timeout_s: float = 30.0,
        metrics: Metrics | None = None,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not 1 <= concurrency <= 64:
            raise ValueError("concurrency must be 1-64")
        if not 0 <= retries <= 10:
            raise ValueError("retries must be 0-10")
        if not (math.isfinite(timeout_s) and 1 <= timeout_s <= 300):
            raise ValueError("timeout_s must be 1-300")
        self._gateway = gateway
        self._limiter = anyio.CapacityLimiter(concurrency)
        self._signatures: OrderedDict[int, str] = OrderedDict()  # round -> signature
        self._fetching: dict[int, anyio.Event] = {}  # rounds being fetched now
        self.retries = retries
        self.timeout_s = float(timeout_s)
        self._metrics = metrics
        self._sleep = sleep
        self._clock = clock

    @classmethod
    def from_settings(
        cls, settings: Any, gateway: ChainGateway, *, metrics: Metrics | None = None
    ) -> Timelock:
        """``TW_TIMELOCK_CONCURRENCY`` / ``_RETRIES`` / ``_TIMEOUT_S``."""
        return cls(
            gateway,
            concurrency=settings.timelock_concurrency,
            retries=settings.timelock_retries,
            timeout_s=settings.timelock_timeout_s,
            metrics=metrics,
        )

    @property
    def in_flight(self) -> int:
        """drand signature fetches running now."""
        return int(self._limiter.borrowed_tokens)

    # ------------------------------------------------------------ bytes

    async def seal(self, data: bytes, reveal_in: str | float) -> str:
        """Seal ``data`` to open ``reveal_in`` from now; the ciphertext, hex."""
        sealed = await self._gateway.timelock_seal(
            data, reveal_in_s=parse_reveal_in(reveal_in)
        )
        return sealed.hex

    async def open(
        self, sealed_hex: str, *, wait: bool = True, timeout_s: float | None = None
    ) -> bytes:
        """Open ``sealed_hex`` within ``timeout_s`` (default: the instance's).

        With ``wait`` (default) it sleeps until the reveal first; a reveal
        later than the deadline raises :class:`TimelockUnavailable` at once.
        Without ``wait`` an early call raises :class:`TimelockNotReady`.
        Junk, and a ciphertext that does not open with its round's checked
        signature, raise :class:`TimelockMalformed`.
        """
        deadline = self._clock() + (self.timeout_s if timeout_s is None else timeout_s)
        sealed = self._gateway.timelock_parse(sealed_hex)
        if sealed.reveal_at_s > self._clock():
            if not wait:
                self._count("not_ready")
                raise TimelockNotReady(sealed.reveal_at_s - self._clock())
            if sealed.reveal_at_s > deadline:
                self._unavailable("reveal later than the deadline")
            await self._sleep(sealed.reveal_at_s - self._clock())
        signature = await self._signature(sealed.reveal_round, deadline)
        opened = await anyio.to_thread.run_sync(
            self._gateway.timelock_decrypt, sealed_hex, signature
        )
        self._count("ok")
        return opened

    async def _signature(self, reveal_round: int, deadline: float) -> str:
        """The round's signature: cached, the fetch in flight, or a new fetch."""
        while (cached := self._signatures.get(reveal_round)) is None:
            pending = self._fetching.get(reveal_round)
            if pending is None:
                return await self._fetch(reveal_round, deadline)
            with anyio.move_on_after(max(0.0, deadline - self._clock())):
                await pending.wait()
            if reveal_round not in self._signatures and self._clock() >= deadline:
                self._unavailable("no drand signature within the deadline")
        self._signatures.move_to_end(reveal_round)
        return cached

    async def _fetch(self, reveal_round: int, deadline: float) -> str:
        done = self._fetching[reveal_round] = anyio.Event()
        try:
            delay = 0.5
            failures = 0
            while (left := deadline - self._clock()) > 0:
                try:
                    async with self._limiter:
                        signature = await self._gateway.timelock_signature(
                            reveal_round, timeout_s=min(left, _TRY_S)
                        )
                except TimelockNotReady as exc:  # the beacon lags: not a retry
                    await self._sleep(min(max(exc.remaining_s, _LAG_S), left))
                    continue
                except TimelockUnavailable:
                    if failures == self.retries:
                        break
                    failures += 1
                    await self._sleep(min(delay, left))
                    delay = min(delay * 2, _BACKOFF_MAX_S)
                    continue
                self._signatures[reveal_round] = signature
                while len(self._signatures) > _CACHED_ROUNDS:
                    self._signatures.popitem(last=False)
                return signature
            self._unavailable("drand unreachable or failing after retries")
            raise AssertionError("unreachable")  # pragma: no cover
        finally:
            del self._fetching[reveal_round]
            done.set()

    # ------------------------------------------------------------ models

    async def seal_challenge(
        self, task: BaseModel, reveal_in: str | float = "30s"
    ) -> SealedChallenge:
        """Validator side: seal ``task`` (its JSON) for every miner."""
        sealed = await self._gateway.timelock_seal(
            task.model_dump_json().encode(), reveal_in_s=parse_reveal_in(reveal_in)
        )
        return SealedChallenge(sealed=sealed.hex, reveal_round=sealed.reveal_round)

    async def open_challenge(
        self,
        challenge: SealedChallenge,
        model: type[_M],
        *,
        max_wait_s: float = 300.0,
    ) -> _M:
        """Miner side: wait for the reveal and parse the task as ``model``.

        A challenge is sent ahead of its reveal, so the deadline is the wait
        until the reveal (at most ``max_wait_s``: the reveal time comes from
        the peer) plus ``timeout_s`` for the drand fetch.
        """
        sealed = self._gateway.timelock_parse(challenge.sealed)
        wait_s = max(0.0, sealed.reveal_at_s - self._clock())
        if wait_s > max_wait_s:
            self._unavailable("challenge reveal later than max_wait_s")
        opened = await self.open(challenge.sealed, timeout_s=wait_s + self.timeout_s)
        return model.model_validate_json(opened)

    async def seal_response(
        self, answer: BaseModel, reveal_in: str | float = "12s"
    ) -> SealedResponse:
        """Miner side: seal ``answer`` (its JSON) to a short reveal."""
        sealed = await self._gateway.timelock_seal(
            answer.model_dump_json().encode(), reveal_in_s=parse_reveal_in(reveal_in)
        )
        return SealedResponse(ciphertext=sealed.hex, reveal_round=sealed.reveal_round)

    async def open_results(
        self,
        results: Mapping[int, MinerResult],
        model: type[_M],
        *,
        not_before: float | None = None,
        timeout_s: float | None = None,
    ) -> dict[int, MinerResult]:
        """Validator side: open every ``SealedResponse``; ``data`` becomes ``model``.

        A result that is not ok is passed through. One whose sealed answer
        cannot be opened in time is ``ok=False``, ``tw.timelock_unavailable``;
        junk, an answer that is not a ``model``, or (with ``not_before``, the
        Unix time the query was sent) one that reveals before the query, so
        was not sealed for it, is ``tw.invalid_response`` without any drand
        fetch. All are opened concurrently; one signature per round.
        """
        out: dict[int, MinerResult] = dict(results)

        async def one(uid: int, result: MinerResult) -> None:
            out[uid] = await self._open_result(result, model, not_before, timeout_s)

        async with anyio.create_task_group() as tg:
            for uid, result in results.items():
                if result.ok:
                    tg.start_soon(one, uid, result)
        return out

    async def _open_result(
        self,
        result: MinerResult,
        model: type[_M],
        not_before: float | None,
        timeout_s: float | None,
    ) -> MinerResult:
        data = result.data
        try:
            if isinstance(data, (bytes, bytearray)):
                sealed = SealedResponse.model_validate_json(data)
            elif isinstance(data, SealedResponse):
                sealed = data
            elif isinstance(data, BaseModel):
                sealed = SealedResponse.model_validate(data.model_dump())
            else:
                raise TypeError("not a sealed response")
            reveal = self._gateway.timelock_parse(sealed.ciphertext)
            if not_before is not None and reveal.reveal_at_s < not_before:
                raise TimelockMalformed("sealed before the query was sent")
            opened = await self.open(sealed.ciphertext, timeout_s=timeout_s)
            return replace(result, data=model.model_validate_json(opened))
        except TimelockUnavailable:
            return replace(
                result, ok=False, data=None, error_code="tw.timelock_unavailable"
            )
        except (ValidationError, TimelockMalformed, TypeError, ValueError):
            return replace(
                result, ok=False, data=None, error_code="tw.invalid_response"
            )
        except Exception:  # noqa: BLE001 - one miner's answer must never break a round
            _log.exception("sealed_response_failed", uid=result.uid)
            return replace(
                result, ok=False, data=None, error_code="tw.invalid_response"
            )

    # ------------------------------------------------------------ outcomes

    def _count(self, result: str) -> None:
        if self._metrics is not None:
            self._metrics.timelock_open.labels(result=result).inc()

    def _unavailable(self, reason: str) -> None:
        self._count("unavailable")
        _log.warning(
            "timelock_unavailable", reason=reason, code="tw.timelock_unavailable"
        )
        raise TimelockUnavailable(reason)
