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
    template.base.validator.BaseValidatorNeuron -> TemplateValidatorAdapter
    a customised template base (TWM031)        -> TemplateMinerAdapter /
                                                  TemplateValidatorAdapter
    bt.config(parser)                          -> config(parser)
    bt.wallet.add_args(parser)                 -> add_v10_args(parser, "wallet")
"""

from tensorwire.compat import weights
from tensorwire.compat.axon import Axon
from tensorwire.compat.config import Config, add_v10_args, config
from tensorwire.compat.dendrite import AxonInfo, Dendrite, axons_from
from tensorwire.compat.metagraph import Metagraph
from tensorwire.compat.neuron import HotkeyWallet, SubtensorView
from tensorwire.compat.synapse import Synapse, TerminalInfo
from tensorwire.compat.template import TemplateValidatorAdapter
from tensorwire.compat.template_miner import TemplateMinerAdapter

__all__ = [
    "Axon",
    "AxonInfo",
    "Config",
    "Dendrite",
    "HotkeyWallet",
    "Metagraph",
    "SubtensorView",
    "Synapse",
    "TemplateMinerAdapter",
    "TemplateValidatorAdapter",
    "TerminalInfo",
    "add_v10_args",
    "axons_from",
    "config",
    "weights",
]
