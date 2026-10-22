"""The miner's side of the legacy v10 bridge (spec 8.11.2).

The v10 wire format itself (signature, body hash, v10-shaped responses) is
``tensorwire.extensions.legacy_v10.server.LegacyServer``. This module holds
what the miner needs around it:

- :class:`LegacyServerLike` / :class:`LegacyRequestLike`: the interface the
  pipeline calls at step [6] and when answering (agreed in COORDINATION.md),
  so the request path does not depend on the bridge's internals;
- :func:`build_legacy_server`: builds the bridge at startup when
  ``TW_LEGACY_V10_UNTIL`` is set;
- :class:`LegacyTraffic`: counts and logs inbound legacy calls (INFO per
  call, WARNING once per sender per hour) and exports the days-remaining
  gauge.
"""

from __future__ import annotations

import datetime as dt
import importlib
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

import structlog
from pydantic import BaseModel

from tensorwire.auth.nonce_store import NonceStore
from tensorwire.auth.verifier import Caller
from tensorwire.config import MinerSettings
from tensorwire.crypto import HotkeySigner
from tensorwire.errors import StartupError, TWError
from tensorwire.observability.logging import short_hotkey
from tensorwire.observability.metrics import Metrics

__all__ = [
    "SENDER_WARNING_INTERVAL_S",
    "LegacyRequestLike",
    "LegacyServerFactory",
    "LegacyServerLike",
    "LegacyTraffic",
    "build_legacy_server",
    "days_remaining",
]

#: Seconds between two WARNING lines for the same legacy sender.
SENDER_WARNING_INTERVAL_S = 3600.0
_MAX_TRACKED_SENDERS = 4096

_log = structlog.stdlib.get_logger("tensorwire.legacy_v10")


class LegacyRequestLike(Protocol):
    """A verified v10 request."""

    @property
    def caller(self) -> Caller:
        """The verified dendrite hotkey and its nonce."""
        ...

    @property
    def synapse(self) -> BaseModel | None:
        """The body parsed into the route's Synapse (``None`` on body-hash routes)."""
        ...


class LegacyServerLike(Protocol):
    """What the pipeline calls for v10 requests."""

    def is_legacy(self, headers: Mapping[str, str]) -> bool:
        """Whether a request uses the v10 wire format."""
        ...

    async def verify(
        self,
        headers: Sequence[tuple[str, str]],
        body: bytes,
        *,
        synapse_cls: type[BaseModel] | None,
        body_hash: Callable[[bytes], str] | None,
    ) -> LegacyRequestLike:
        """Step [6] for a v10 request.

        Raises ``LegacyAuthFailed``, ``LegacyDisabled`` or
        ``ReplayStoreUnavailable``.
        """
        ...

    def respond(
        self,
        request_headers: Mapping[str, str],
        *,
        status: int,
        synapse: BaseModel | None,
        error: TWError | None,
        process_time_s: float,
    ) -> tuple[bytes, list[tuple[str, str]]]:
        """The v10-shaped response body and headers."""
        ...


LegacyServerFactory = Callable[..., LegacyServerLike]
"""Builds a :class:`LegacyServerLike` with the keyword arguments of
``LegacyServer`` (``signer``, ``store``, ``until``, ``external_ip``,
``external_port``, ``max_age``, ``allowed_skew``, ``now_ns``)."""


def build_legacy_server(
    settings: MinerSettings,
    *,
    signer: HotkeySigner,
    store: NonceStore,
    now_ns: Callable[[], int] | None,
    factory: LegacyServerFactory | None = None,
) -> LegacyServerLike | None:
    """The bridge for this miner, or ``None`` when ``TW_LEGACY_V10_UNTIL`` is unset."""
    until = settings.legacy_v10_until
    if until is None:
        return None
    if factory is None:
        factory = _bridge_class()
    server: LegacyServerLike = factory(
        signer=signer,
        store=store,
        until=until,
        external_ip=settings.external_ip,
        external_port=settings.effective_external_port,
        max_age=settings.auth_max_age_s,
        allowed_skew=settings.auth_allowed_skew_s,
        now_ns=now_ns,
    )
    return server


def _bridge_class() -> LegacyServerFactory:
    try:
        module = importlib.import_module("tensorwire.extensions.legacy_v10.server")
    except ImportError:
        module = None
    cls: Any = getattr(module, "LegacyServer", None)
    if cls is None:
        raise StartupError(
            "TW_LEGACY_V10_UNTIL is set but the legacy v10 bridge is not in this build"
        )
    factory: LegacyServerFactory = cls
    return factory


def days_remaining(until: dt.date, today: dt.date | None = None) -> int:
    """Whole days until ``until`` (UTC), never negative."""
    now = dt.datetime.now(dt.timezone.utc).date() if today is None else today
    return max(0, (until - now).days)


class LegacyTraffic:
    """Counts and logs legacy v10 calls in one direction."""

    def __init__(
        self,
        metrics: Metrics,
        *,
        direction: str,
        monotonic: Callable[[], float],
        until: dt.date | None = None,
    ) -> None:
        self._metrics = metrics
        self._direction = direction
        self._monotonic = monotonic
        self._warned: dict[str, float] = {}
        if until is not None:
            metrics.legacy_v10_days_remaining.labels(direction=direction).set(
                days_remaining(until)
            )

    def record(self, sender: str | None, result: str) -> None:
        """Count one call (``result`` is ``ok`` or a ``tw.*`` code) and log it."""
        self._metrics.legacy_v10_requests.labels(
            direction=self._direction, result=result
        ).inc()
        who = short_hotkey(sender, full=False)
        _log.info(
            "legacy_v10_request", direction=self._direction, sender=who, result=result
        )
        if sender is None:
            return
        now = self._monotonic()
        last = self._warned.get(sender)
        if last is not None and now - last < SENDER_WARNING_INTERVAL_S:
            return
        if len(self._warned) >= _MAX_TRACKED_SENDERS:
            self._warned.clear()  # bounded: at worst one extra WARNING per sender
        self._warned[sender] = now
        _log.warning(
            "legacy_v10_sender",
            direction=self._direction,
            sender=who,
            hint="this peer still uses the v10 wire format; it stops working "
            "when the legacy end date passes",
        )
