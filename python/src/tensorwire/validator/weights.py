"""When and what the validator submits as weights (spec 8.9 steps 3-5, 8.3).

:meth:`WeightScheduler.maybe_submit` is called after every round. It
submits ``SetWeights({uid: score})`` for UIDs with a positive score when

- the chain says ``blocks_since_last_update >= weights_rate_limit``
  (the rate limit is re-read once per tempo), and
- at least ``TW_MIN_WEIGHT_INTERVAL_BLOCKS`` passed since our last submission.

Outcomes (``TxOutcome.code``, ``bt.ErrorCode`` values):

- ``ok``: on commit-reveal subnets (the default) this means the timelocked
  **commit was included**, not that the weights apply; that is only known
  after the reveal (spec 8.3).
- ``rate_limited``: wait the number of blocks named in the remediation, or
  one tempo, then try again.
- ``not_registered`` / ``not_authorized``: alert and stop setting weights
  (querying continues). Submissions resume when the metagraph shows this
  hotkey registered again, or with a validator permit.
- All scores zero: nothing is submitted (``tw.no_scores``), so weights are
  never burned on an all-zero vector.

The gateway runs the SDK preflight (``plan``) before every submission and
logs its warnings (clipping included).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

import anyio.to_thread
import structlog

from tensorwire.chain.gateway import (
    ChainGateway,
    GatewayError,
    MetagraphView,
    TxOutcome,
)
from tensorwire.observability.metrics import Metrics
from tensorwire.validator.scores import ScoreStore, WeightRecord

__all__ = ["WeightDecision", "WeightScheduler", "blocks_from_remediation"]

Reason = Literal[
    "submitted",
    "not_due",
    "waiting",
    "no_scores",
    "stopped",
    "failed",
]

_BLOCKS_RE = re.compile(r"(\d+)\s*blocks?\b", re.IGNORECASE)
_STOP_CODES = frozenset({"not_registered", "not_authorized"})

_log = structlog.stdlib.get_logger("tensorwire.validator.weights")


@dataclass(frozen=True)
class WeightDecision:
    """What :meth:`WeightScheduler.maybe_submit` did."""

    reason: Reason
    block: int | None = None
    outcome: TxOutcome | None = None
    n_uids: int = 0

    @property
    def submitted(self) -> bool:
        """A commit was included (``TxOutcome.ok``)."""
        return self.reason == "submitted"


def blocks_from_remediation(text: str | None) -> int | None:
    """The block count in a ``rate_limited`` remediation ("retry in 37 blocks")."""
    if not text:
        return None
    match = _BLOCKS_RE.search(text)
    return int(match.group(1)) if match else None


class WeightScheduler:
    """Submits weights on the chain's schedule for one validator hotkey."""

    def __init__(
        self,
        gateway: ChainGateway,
        netuid: int,
        hotkey_ss58: str,
        *,
        min_interval_blocks: int = 100,
        version_key: int = 0,
        mechid: int = 0,
        store: ScoreStore | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        if min_interval_blocks < 0:
            raise ValueError("min_interval_blocks must not be negative")
        self._gateway = gateway
        self.netuid = netuid
        self.hotkey_ss58 = hotkey_ss58
        self.min_interval_blocks = min_interval_blocks
        self.version_key = version_key
        self.mechid = mechid
        self._store = store
        self._metrics = metrics
        self._rate_limit: int | None = None
        self._rate_limit_read_at: int | None = None
        self._last_submit_block: int | None = None
        self._wait_until = 0
        self.stopped: str | None = None
        """``not_registered`` / ``not_authorized`` while submissions are stopped."""

    async def maybe_submit(
        self, scores: Mapping[int, float], mg: MetagraphView
    ) -> WeightDecision:
        """Submit weights if they are due. Never raises for chain failures."""
        me = mg.by_hotkey(self.hotkey_ss58)
        if not self._may_resume(me is not None, me is not None and me.validator_permit):
            return WeightDecision("stopped")
        if me is None:
            self._stop("not_registered", None)
            return WeightDecision("stopped")
        try:
            block = await self._gateway.block()
            if block < self._wait_until:
                return WeightDecision("waiting", block)
            if not await self._due(block, me.uid, mg.tempo):
                return WeightDecision("not_due", block)
        except GatewayError as exc:
            _log.warning("weights_check_failed", error=str(exc))
            return WeightDecision("failed")
        uids = {n.uid for n in mg.neurons}
        weights = {u: float(s) for u, s in scores.items() if s > 0 and u in uids}
        if not weights:
            _log.warning("tw.no_scores", hint="every score is zero; nothing submitted")
            return WeightDecision("no_scores", block)
        return await self._submit(block, weights, mg.tempo)

    def _may_resume(self, registered: bool, permit: bool) -> bool:
        if self.stopped is None:
            return True
        if (self.stopped == "not_registered" and registered) or (
            self.stopped == "not_authorized" and permit
        ):
            _log.info("weights_resumed", previously=self.stopped)
            self.stopped = None
            return True
        return False

    async def _due(self, block: int, uid: int, tempo: int) -> bool:
        read_at = self._rate_limit_read_at
        if self._rate_limit is None or read_at is None or block - read_at >= tempo:
            self._rate_limit = await self._gateway.weights_rate_limit(self.netuid)
            self._rate_limit_read_at = block
        since = await self._gateway.blocks_since_last_update(self.netuid, uid)
        if since is None or since < self._rate_limit:
            return False
        last = self._last_submit_block
        return last is None or block - last >= self.min_interval_blocks

    async def _submit(
        self, block: int, weights: dict[int, float], tempo: int
    ) -> WeightDecision:
        try:
            outcome = await self._gateway.set_weights(
                self.netuid, weights, mechid=self.mechid, version_key=self.version_key
            )
        except GatewayError as exc:
            _log.error("weights_submit_failed", error=str(exc))
            outcome = TxOutcome(
                ok=False, code="unknown", remediation=str(exc), block_hash=None
            )
        code = None if outcome.ok else (outcome.code or "unknown")
        await self._record(block, outcome, code, len(weights))
        if outcome.ok:
            self._last_submit_block = block
            _log.info(
                "weights submitted",
                block=block,
                block_hash=outcome.block_hash,
                n_uids=len(weights),
                meaning="commit included; weights apply after the reveal",
            )
            return WeightDecision("submitted", block, outcome, len(weights))
        if code == "rate_limited":
            wait = blocks_from_remediation(outcome.remediation) or tempo
            self._wait_until = block + wait
            _log.warning("weights_rate_limited", wait_blocks=wait)
        elif code in _STOP_CODES:
            self._stop(code, outcome.remediation)
        else:
            self._wait_until = block + max(1, min(self.min_interval_blocks, tempo))
            _log.error("weights_rejected", code=code, remediation=outcome.remediation)
        return WeightDecision("failed", block, outcome, len(weights))

    def _stop(self, code: str, remediation: str | None) -> None:
        if self.stopped == code:
            return
        self.stopped = code
        _log.error(
            "weights_stopped",
            code=code,
            remediation=remediation,
            hint="querying continues; submissions resume when the metagraph shows "
            "this hotkey registered with a validator permit",
        )

    async def _record(
        self, block: int, outcome: TxOutcome, code: str | None, n_uids: int
    ) -> None:
        if self._metrics is not None:
            self._metrics.validator_weight_submissions.labels(
                ok=str(outcome.ok).lower(), code=code or "ok"
            ).inc()
            if outcome.ok:
                self._metrics.validator_last_weights_block.set(block)
        store = self._store
        if store is not None:
            record = WeightRecord(block, outcome.ok, code, n_uids, outcome.block_hash)
            await anyio.to_thread.run_sync(store.record_weights, record)
