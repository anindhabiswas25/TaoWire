"""A read-only, v10-shaped view of the kit's metagraph (spec 10b.1, 10b.3).

Template code reads ``metagraph.hotkeys``, ``metagraph.S``,
``metagraph.validator_permit``, ``metagraph.axons`` and friends as arrays
indexed by UID. :class:`Metagraph` gives the same attributes over a
``MetagraphSource`` (the miner's or validator's cache, refreshed in the
background) or a fixed ``MetagraphView``::

    metagraph = Metagraph(miner.lifecycle.runtime.metagraph)
    uid = metagraph.hotkeys.index(synapse.dendrite.hotkey)
    stake = float(metagraph.S[uid])

Every attribute reads the latest snapshot. ``sync()`` is a no-op: the kit's
cache refreshes itself. Values are plain Python lists (``S`` is the
caller's stake in TAO at spot price, ``NeuronView.total_stake_tao``), not
tensors; wrap them in ``numpy.array(...)`` where the code needs arrays.
"""

from __future__ import annotations

from typing import Any

from tensorwire.chain.gateway import MetagraphView, NeuronView
from tensorwire.chain.metagraph_cache import MetagraphSource
from tensorwire.compat.dendrite import AxonInfo

__all__ = ["Metagraph"]


class Metagraph:
    """``bt.metagraph`` attributes over a TensorWire metagraph."""

    def __init__(self, source: MetagraphSource | MetagraphView) -> None:
        self._source = source

    def snapshot(self) -> MetagraphView:
        """The current snapshot. ``RuntimeError`` before the first one."""
        source = self._source
        view = source if isinstance(source, MetagraphView) else source.snapshot()
        if view is None:
            raise RuntimeError("no metagraph snapshot yet")
        return view

    def _neurons(self) -> list[NeuronView]:
        neurons = sorted(self.snapshot().neurons, key=lambda n: n.uid)
        if [n.uid for n in neurons] != list(range(len(neurons))):
            raise RuntimeError("metagraph UIDs are not contiguous")
        return neurons

    def sync(self, *_args: Any, **_kwargs: Any) -> None:
        """No-op: the kit's metagraph cache refreshes in the background."""

    @property
    def netuid(self) -> int:
        """The subnet."""
        return self.snapshot().netuid

    @property
    def block(self) -> int:
        """The snapshot's block."""
        return self.snapshot().block

    @property
    def n(self) -> int:
        """Number of neurons."""
        return len(self.snapshot().neurons)

    @property
    def uids(self) -> list[int]:
        """UIDs in order."""
        return [n.uid for n in self._neurons()]

    @property
    def hotkeys(self) -> list[str]:
        """Hotkey per UID."""
        return [n.hotkey for n in self._neurons()]

    @property
    def coldkeys(self) -> list[str]:
        """Coldkey per UID."""
        return [n.coldkey for n in self._neurons()]

    @property
    def S(self) -> list[float]:  # noqa: N802 - v10's attribute name
        """Stake per UID (TAO value at spot price, approximate; spec 8.3)."""
        return [n.total_stake_tao for n in self._neurons()]

    @property
    def validator_permit(self) -> list[bool]:
        """Validator permit per UID."""
        return [n.validator_permit for n in self._neurons()]

    @property
    def last_update(self) -> list[int]:
        """Block of each UID's last weight update."""
        return [n.last_update for n in self._neurons()]

    @property
    def I(self) -> list[float]:  # noqa: E743, N802 - v10's attribute name
        """Incentive per UID."""
        return [n.incentive for n in self._neurons()]

    @property
    def D(self) -> list[float]:  # noqa: N802 - v10's attribute name
        """Dividends per UID."""
        return [n.dividends for n in self._neurons()]

    @property
    def axons(self) -> list[AxonInfo]:
        """``AxonInfo`` per UID (``is_serving`` False when nothing is published)."""
        return [AxonInfo.from_neuron(n) for n in self._neurons()]
