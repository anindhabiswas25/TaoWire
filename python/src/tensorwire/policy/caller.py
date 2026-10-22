"""Who may call a miner route (spec 8.5), and what stale chain data changes (8.5.1).

Authenticated is not authorized: a valid btauth/1 signature only proves which
hotkey sent the request. :class:`CallerPolicy` decides whether that hotkey may
use a route, from the latest metagraph snapshot. The order is fixed: deny
list, allow list, registered, validator permit, minimum stake.

:class:`CallerGate` adds the staged staleness rule. While the snapshot is
fresh or degraded, the policy runs normally and every caller that passes is
remembered. Past the max age only those remembered ("known") callers are
served; everyone else gets 503 ``tw.metagraph_stale``, and with
``TW_METAGRAPH_STRICT=1`` everyone does. A new snapshot clears the known set,
so the fresh data decides again.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace

from tensorwire.chain.gateway import MetagraphView, NeuronView
from tensorwire.chain.metagraph_cache import MetagraphSource, StalenessStage
from tensorwire.config import MinerSettings
from tensorwire.errors import Forbidden, MetagraphStale

__all__ = ["CallerGate", "CallerPolicy", "KnownCallers"]


@dataclass(frozen=True, slots=True)
class CallerPolicy:
    """Rules for one route. The defaults are the strict policy.

    ``min_stake_tao`` compares against ``NeuronView.total_stake_tao`` (TAO
    value at spot price, PM decision D2); 0 disables the check.
    ``allow_hotkeys`` are always allowed, even unregistered (operator
    tooling); ``deny_hotkeys`` are always denied and checked first.
    """

    require_registered: bool = True
    require_validator_permit: bool = True
    min_stake_tao: float = 0.0
    allow_hotkeys: frozenset[str] = field(default_factory=frozenset)
    deny_hotkeys: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.min_stake_tao >= 0:  # also rejects NaN
            raise ValueError("min_stake_tao must be >= 0")
        if self.allow_hotkeys & self.deny_hotkeys:
            raise ValueError("a hotkey cannot be both allowed and denied")

    @classmethod
    def from_settings(cls, settings: MinerSettings) -> CallerPolicy:
        """The default route policy from ``TW_REQUIRE_PERMIT``, stake and lists."""
        return cls(
            require_registered=True,
            require_validator_permit=settings.require_permit,
            min_stake_tao=settings.min_caller_stake_tao,
            allow_hotkeys=settings.allow_hotkeys,
            deny_hotkeys=settings.deny_hotkeys,
        )

    def with_denied(self, hotkeys: Iterable[str]) -> CallerPolicy:
        """This policy with ``hotkeys`` added to the deny list.

        The miner applies ``TW_DENY_HOTKEYS`` to every route this way, so a
        route-specific policy cannot drop the operator's deny list. A hotkey
        in both lists ends up denied only.
        """
        denied = self.deny_hotkeys | frozenset(hotkeys)
        return replace(
            self, deny_hotkeys=denied, allow_hotkeys=self.allow_hotkeys - denied
        )

    def check(self, caller_hotkey: str, mg: MetagraphView) -> NeuronView | None:
        """Raise :class:`Forbidden` unless the caller may use the route.

        Returns the caller's neuron (``None`` for an allow-listed hotkey that
        is not registered).
        """
        if caller_hotkey in self.deny_hotkeys:
            raise Forbidden(code="tw.forbidden_denied")
        n = mg.by_hotkey(caller_hotkey)
        if caller_hotkey in self.allow_hotkeys:
            return n
        if self.require_registered and n is None:
            raise Forbidden(code="tw.forbidden_not_registered")
        if self.require_validator_permit and (n is None or not n.validator_permit):
            raise Forbidden(code="tw.forbidden_not_validator")
        if self.min_stake_tao and (n is None or n.total_stake_tao < self.min_stake_tao):
            raise Forbidden(code="tw.forbidden_low_stake")
        return n


class KnownCallers:
    """Callers that passed full policy on a fresh or degraded snapshot.

    Keyed by ``(scope, hotkey)`` (the miner uses the route path as scope, so
    passing a relaxed route's policy does not admit a caller to a strict
    route). The value is the monotonic time of the last accepted request.
    Bounded by the number of distinct callers that pass policy, which the
    metagraph size and the allow list bound.
    """

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._seen)

    def __contains__(self, key: object) -> bool:
        return key in self._seen

    def add(self, scope: str, hotkey: str, now: float) -> None:
        """Remember that ``hotkey`` passed policy for ``scope`` at ``now``."""
        with self._lock:
            self._seen[(scope, hotkey)] = now

    def last_accepted(self, scope: str, hotkey: str) -> float | None:
        """When ``hotkey`` last passed policy for ``scope``, or ``None``."""
        return self._seen.get((scope, hotkey))

    def clear(self) -> None:
        """Forget everyone (a fresh snapshot decides again)."""
        with self._lock:
            self._seen.clear()


class CallerGate:
    """Applies a :class:`CallerPolicy` under the staged staleness rule (8.5.1).

    The miner calls :meth:`precheck` before signature verification (step 5
    of spec 5.3) and :meth:`admit` after it (step 7).
    """

    def __init__(
        self,
        source: MetagraphSource,
        *,
        strict: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._source = source
        self._strict = strict
        self._clock = clock
        self.known = KnownCallers()
        source.add_refresh_listener(self._on_refresh)

    @property
    def strict(self) -> bool:
        """``TW_METAGRAPH_STRICT``: 503 for everyone past the max age."""
        return self._strict

    def _on_refresh(self, _mg: MetagraphView) -> None:
        self.known.clear()

    def precheck(self) -> StalenessStage:
        """Step 5: refuse everyone at once when strict and past the max age."""
        stage = self._source.stage()
        if stage is StalenessStage.KNOWN_CALLERS_ONLY and self._strict:
            raise MetagraphStale()
        return stage

    def admit(self, scope: str, policy: CallerPolicy, hotkey: str) -> NeuronView | None:
        """Step 7: raise :class:`Forbidden` / :class:`MetagraphStale`, or admit.

        Returns the caller's neuron from the latest snapshot, if registered.
        """
        if hotkey in policy.deny_hotkeys:
            raise Forbidden(code="tw.forbidden_denied")
        stage = self._source.stage()
        mg = self._source.snapshot()
        if stage is StalenessStage.KNOWN_CALLERS_ONLY or mg is None:
            if self._strict or (scope, hotkey) not in self.known:
                raise MetagraphStale()
            return None if mg is None else mg.by_hotkey(hotkey)
        neuron = policy.check(hotkey, mg)
        self.known.add(scope, hotkey, self._clock())
        return neuron
