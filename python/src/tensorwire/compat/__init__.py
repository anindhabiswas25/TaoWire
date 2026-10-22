"""v10-shaped API over TensorWire, for migrating v10 subnets (10b.2, ADR-0007).

New projects should use the native API (``Miner``, ``SubnetValidator``).
``compat`` adds no security logic of its own: every request still goes
through the full pipeline of spec 5.3.

Import changes for a template-derived subnet::

    import bittensor as bt; bt.Synapse        ->  from tensorwire.compat import Synapse
    bt.axon(wallet=..., config=...)           ->  Axon(miner=Miner.from_env())
    bt.dendrite(wallet=wallet)                ->  Dendrite(signer=RequestSigner(wallet))
    [metagraph.axons[uid] for uid in uids]    ->  axons_from(metagraph_view, uids)
    process_weights_for_netuid(...)           ->  weights.to_mapping(uids, weights)
    bt.metagraph(...).hotkeys / .S / .axons   ->  Metagraph(source).hotkeys / .S
"""

from tensorwire.compat import weights
from tensorwire.compat.axon import Axon
from tensorwire.compat.dendrite import AxonInfo, Dendrite, axons_from
from tensorwire.compat.metagraph import Metagraph
from tensorwire.compat.synapse import Synapse, TerminalInfo

__all__ = [
    "Axon",
    "AxonInfo",
    "Dendrite",
    "Metagraph",
    "Synapse",
    "TerminalInfo",
    "axons_from",
    "weights",
]
