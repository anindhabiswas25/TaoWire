"""The chain boundary (spec 8.3, ADR-0001).

Every chain read and write in the kit goes through a :class:`ChainGateway`.
The rest of the kit only sees the kit-owned views defined here
(:class:`NeuronView`, :class:`MetagraphView`, :class:`TxOutcome`), never
``bittensor`` types, so an SDK change is fixed in this one module.

``tensorwire.testing.fake_chain.FakeChain`` implements the same Protocol for
tests. The real ``BittensorGateway`` lands in Phase 1.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from tensorwire.chain.axon import Endpoint

__all__ = [
    "ChainGateway",
    "ChainUnavailable",
    "GatewayError",
    "MetagraphView",
    "NeuronView",
    "SubnetNotFound",
    "TxOutcome",
]


class GatewayError(Exception):
    """Base class for gateway read failures. Never sent to peers."""


class ChainUnavailable(GatewayError):
    """A read failed after retries or timed out: no usable chain endpoint."""


class SubnetNotFound(GatewayError):
    """The requested netuid does not exist on the connected chain."""


@dataclass(frozen=True, slots=True)
class NeuronView:
    """One neuron, as the kit sees it. A kit-owned copy of the SDK's row.

    ``total_stake_tao`` is for coarse policy thresholds only. ``alpha_stake``
    is in the subnet's alpha, ``tao_stake`` in root TAO. ``axon`` is ``None``
    when nothing is served or the published address is rejected by
    :func:`tensorwire.chain.axon.parse_axon`. ``axon_protocol`` is the
    ``protocol`` byte published with ``ServeAxon`` (0 to 255), or ``None`` when
    nothing is served; it is advisory, not a security signal.
    """

    uid: int
    hotkey: str
    coldkey: str
    validator_permit: bool
    active: bool
    total_stake_tao: float
    alpha_stake: float
    tao_stake: float
    axon: Endpoint | None
    last_update: int
    incentive: float
    dividends: float
    axon_protocol: int | None = None


@dataclass(frozen=True, slots=True)
class MetagraphView:
    """An immutable snapshot of one subnet.

    ``neurons`` is in UID order. ``fetched_at_monotonic`` is the
    ``time.monotonic()`` value (or the injected clock's value) when the
    snapshot was read; staleness is measured from it (spec 8.5.1). ``tempo``
    is the subnet's epoch length in blocks, used for the default maximum
    snapshot age.
    """

    netuid: int
    block: int
    fetched_at_monotonic: float
    neurons: tuple[NeuronView, ...]
    tempo: int
    _by_hotkey: Mapping[str, NeuronView] = field(
        init=False, repr=False, compare=False, hash=False
    )

    def __post_init__(self) -> None:
        index = {n.hotkey: n for n in self.neurons}
        object.__setattr__(self, "_by_hotkey", index)

    def by_hotkey(self, hotkey: str) -> NeuronView | None:
        """Return the neuron registered with ``hotkey``, or ``None``. O(1)."""
        return self._by_hotkey.get(hotkey)

    def validators(self) -> tuple[NeuronView, ...]:
        """Return the neurons holding a validator permit, in UID order."""
        return tuple(n for n in self.neurons if n.validator_permit)


@dataclass(frozen=True, slots=True)
class TxOutcome:
    """The result of a chain write.

    ``code`` is a ``bittensor.ErrorCode`` value (for example
    ``"rate_limited"``) when ``ok`` is false, else ``None``. ``remediation`` is
    the SDK's human hint for that failure.
    """

    ok: bool
    code: str | None
    remediation: str | None
    block_hash: str | None


@runtime_checkable
class ChainGateway(Protocol):
    """All chain operations the kit performs.

    Reads raise :class:`ChainUnavailable` when the chain cannot be reached
    after retries, and :class:`SubnetNotFound` for an unknown netuid. Writes
    are signed by the gateway's hotkey, are never retried blindly, and report
    chain-side failures through :class:`TxOutcome` instead of raising.
    """

    async def connect(self) -> None:
        """Open the chain connection. Must be called before any other method."""
        ...

    async def close(self) -> None:
        """Close the chain connection. Safe to call more than once."""
        ...

    async def block(self) -> int:
        """Return the current block number."""
        ...

    async def metagraph(self, netuid: int) -> MetagraphView:
        """Return a fresh snapshot of subnet ``netuid``."""
        ...

    async def uid_for_hotkey(self, netuid: int, hotkey: str) -> int | None:
        """Return the UID of ``hotkey`` on ``netuid``, or ``None`` if unregistered."""
        ...

    async def weights_rate_limit(self, netuid: int) -> int:
        """Return the subnet's weights rate limit, in blocks."""
        ...

    async def blocks_since_last_update(self, netuid: int, uid: int) -> int | None:
        """Return blocks since ``uid`` last set weights, or ``None`` if unknown."""
        ...

    async def serve_axon(
        self,
        netuid: int,
        ip: str,
        port: int,
        *,
        tls_cert_hex: str | None,
        protocol_tag: int,
    ) -> TxOutcome:
        """Publish ``ip:port`` for the gateway's hotkey (``ServeAxon[Tls]``)."""
        ...

    async def set_weights(
        self,
        netuid: int,
        weights: dict[int, float],
        *,
        mechid: int,
        version_key: int,
    ) -> TxOutcome:
        """Submit weights for the gateway's hotkey (``SetWeights``)."""
        ...
