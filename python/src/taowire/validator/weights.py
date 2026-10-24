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
- ``expired`` / ``too_early`` from a timelocked commit that a new plan can fix
  (:attr:`TxOutcome.replannable`: the chain's ``InvalidRevealRound``, i.e. it
  stored the commit's drand round before the commit was included, likely on
  fast blocks; or ``RevealTooEarly``), decision D32: the next
  :meth:`~WeightScheduler.maybe_submit` at least one block later plans again
  against the current block, a **new** extrinsic with a new reveal round; the
  rejected one is never resent (8.3). At most :data:`MAX_REPLANS` re-plans per
  weight window (``max(weights_rate_limit, tempo)`` blocks from the first
  rejection), then ``weights_commit_replan_exhausted`` and a wait until that
  window ends. Pool errors with the same codes (``Stale`` / ``Future``, which
  the gateway already re-signs) are not re-planned.
- All scores zero: nothing is submitted (``tw.no_scores``), so weights are
  never burned on an all-zero vector.
- **Version key preflight (D38, G7-3).** Right before each commit the
  subnet's ``WeightsVersionKey`` is read through the gateway: one read per
  attempt that would commit, never cached, so a key the owner raises
  mid-tempo stops the very next commit. A
  timelocked commit with a lower ``version_key`` would be accepted and then
  dropped at reveal, so with a stale ``TW_WEIGHTS_VERSION_KEY`` nothing is
  committed: ERROR ``weights_version_key_stale`` (both keys),
  ``tw_validator_weight_submissions_total{ok="false",code="version_key_stale"}``
  and a retry in the next weight window. This is how stage 3 of the rollout
  (10b.5) reaches a validator with a stale key at commit time, not at reveal.

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

from taowire.chain.gateway import (
    ChainGateway,
    GatewayError,
    MetagraphView,
    TxOutcome,
)
from taowire.observability.metrics import Metrics
from taowire.validator.scores import ScoreStore, WeightRecord

__all__ = [
    "MAX_REPLANS",
    "WeightDecision",
    "WeightScheduler",
    "blocks_from_remediation",
]

Reason = Literal[
    "submitted",
    "replanning",
    "not_due",
    "waiting",
    "no_scores",
    "version_key_stale",
    "stopped",
    "failed",
    "disabled",
]

_BLOCKS_RE = re.compile(r"(\d+)\s*blocks?\b", re.IGNORECASE)
_STOP_CODES = frozenset({"not_registered", "not_authorized"})

MAX_REPLANS = 3
"""Re-plans per weight window (D32); each one is a new, freshly signed extrinsic."""

_log = structlog.stdlib.get_logger("taowire.validator.weights")


@dataclass(frozen=True)
class WeightDecision:
    """What :meth:`WeightScheduler.maybe_submit` did."""

    reason: Reason
    block: int | None = None
    outcome: TxOutcome | None = None
    n_uids: int = 0
    replans: int = 0
    """Re-plans used in the current weight window (D32), this one included."""

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
        self._replan_window_end: int | None = None
        self._replans_used = 0  # in the window that ends at _replan_window_end
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
        try:
            chain_key = await self._gateway.weights_version_key(self.netuid)
        except GatewayError as exc:
            _log.warning("weights_check_failed", error=str(exc))
            return WeightDecision("failed", block)
        if self.version_key < chain_key:
            return await self._stale_key(block, chain_key, len(weights), mg.tempo)
        return await self._submit(block, weights, mg.tempo)

    async def _stale_key(
        self, block: int, chain_key: int, n_uids: int, tempo: int
    ) -> WeightDecision:
        """No commit with a stale key (D38): it would be dropped at reveal."""
        outcome = TxOutcome(
            ok=False,
            code="version_key_stale",
            remediation=f"set TW_WEIGHTS_VERSION_KEY to {chain_key} or more",
            block_hash=None,
        )
        await self._record(block, outcome, "version_key_stale", n_uids)
        window = max(self._rate_limit or 0, tempo, 1)
        self._wait_until = block + window
        _log.error(
            "weights_version_key_stale",
            version_key=self.version_key,
            chain_version_key=chain_key,
            retry_in_blocks=window,
            hint="the chain would drop this commit at reveal; upgrade the "
            "validator (TW_WEIGHTS_VERSION_KEY)",
        )
        return WeightDecision("version_key_stale", block, outcome, n_uids)

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
        outcome = await self._set_weights(weights)
        code = None if outcome.ok else (outcome.code or "unknown")
        await self._record(block, outcome, code, len(weights))
        n = len(weights)
        if outcome.ok:
            end = self._replan_window_end
            replans = self._replans_used if end is not None and block < end else 0
            self._last_submit_block = block
            self._replan_window_end = None
            self._replans_used = 0
            _log.info(
                "weights submitted",
                block=block,
                block_hash=outcome.block_hash,
                n_uids=n,
                replans=replans,
                meaning="commit included; weights apply after the reveal",
            )
            return WeightDecision("submitted", block, outcome, n, replans)
        if outcome.replannable:
            return self._replan(block, outcome, n, tempo)
        if code == "rate_limited":
            wait = blocks_from_remediation(outcome.remediation) or tempo
            self._wait_until = block + wait
            _log.warning("weights_rate_limited", wait_blocks=wait)
        elif code in _STOP_CODES:
            self._stop(code, outcome.remediation)
        else:
            self._wait_until = block + max(1, min(self.min_interval_blocks, tempo))
            _log.error("weights_rejected", code=code, remediation=outcome.remediation)
        return WeightDecision("failed", block, outcome, n, self._replans_used)

    def _replan(
        self, block: int, outcome: TxOutcome, n_uids: int, tempo: int
    ) -> WeightDecision:
        """Plan again from the next block, within the window's budget (D32)."""
        end = self._replan_window_end
        if end is None or block >= end:
            end = block + max(self._rate_limit or 0, tempo, 1)
            self._replan_window_end = end
            self._replans_used = 0
        fields = {
            "code": outcome.code,
            "error_name": outcome.error_name,
            "remediation": outcome.remediation,
        }
        if self._replans_used >= MAX_REPLANS:
            self._wait_until = end
            _log.error(
                "weights_commit_replan_exhausted",
                replans=self._replans_used,
                wait_until_block=end,
                **fields,
            )
            return WeightDecision("failed", block, outcome, n_uids, self._replans_used)
        self._replans_used += 1
        # The next maybe_submit (a block later at least) plans and signs a new
        # extrinsic with a new reveal round; the rejected one is never resent.
        self._wait_until = block + 1
        _log.warning(
            "weights_commit_replanned",
            attempt=self._replans_used,
            max_replans=MAX_REPLANS,
            **fields,
        )
        return WeightDecision("replanning", block, outcome, n_uids, self._replans_used)

    async def _set_weights(self, weights: dict[int, float]) -> TxOutcome:
        try:
            return await self._gateway.set_weights(
                self.netuid, weights, mechid=self.mechid, version_key=self.version_key
            )
        except GatewayError as exc:
            _log.error("weights_submit_failed", error=str(exc))
            return TxOutcome(
                ok=False, code="unknown", remediation=str(exc), block_hash=None
            )

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
