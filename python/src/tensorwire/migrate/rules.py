"""The ``tensorwire migrate`` rule table (spec 10b.4.1).

Each rule has an id (``TWM0xx`` for API changes, ``TWM1xx`` for security
risks), a severity, the replacement and a link into
``docs/migration-from-v10.md``:

- ``auto``: ``tensorwire migrate apply`` can rewrite it;
- ``manual``: a person has to change it (``apply`` leaves a
  ``# TW-MIGRATE:`` comment);
- ``risk``: security-relevant; the code works but weakens the subnet.

The rules start from the symbols v11 removed (spec 3.8) and the table of
things the compat layer does not cover (10b.3).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

__all__ = [
    "ATTRIBUTE_RULES",
    "DOC_BASE",
    "MODULE_RULES",
    "RULES",
    "Rule",
    "Severity",
]

Severity = Literal["auto", "manual", "risk"]

DOC_BASE = "docs/migration-from-v10.md"


@dataclass(frozen=True)
class Rule:
    """One migration rule."""

    id: str
    title: str
    severity: Severity
    replacement: str

    @property
    def doc(self) -> str:
        """Where the rule is explained."""
        return f"{DOC_BASE}#{self.id.lower()}"


def _table(*rules: Rule) -> Mapping[str, Rule]:
    table = {r.id: r for r in rules}
    if len(table) != len(rules):
        raise RuntimeError("duplicate migrate rule id")
    return MappingProxyType(table)


RULES: Mapping[str, Rule] = _table(
    Rule(
        "TWM001",
        "bt.Synapse",
        "auto",
        "from tensorwire.compat import Synapse",
    ),
    Rule(
        "TWM002",
        "bt.StreamingSynapse",
        "manual",
        "compat.StreamingSynapse arrives with the kit's streaming support "
        "(Phase 4); until then keep the route on v10 or answer without streaming",
    ),
    Rule(
        "TWM003",
        "bt.axon / bt.Axon",
        "auto",
        "tensorwire.compat.Axon(miner=Miner.from_env()); settings come from TW_*",
    ),
    Rule(
        "TWM004",
        "bt.dendrite / bt.Dendrite",
        "auto",
        "tensorwire.compat.Dendrite(signer=RequestSigner(wallet))",
    ),
    Rule(
        "TWM005",
        "bt.Tensor",
        "manual",
        "serialize tensors with the ML library (bytes/base64 or lists)",
    ),
    Rule(
        "TWM006",
        "bt.config / bt.Config / add_args",
        "manual",
        "kit settings (TW_* variables, spec 12) or the team's own config",
    ),
    Rule(
        "TWM007",
        "bt.logging calls",
        "auto",
        "standard logging: bt.logging.info(...) -> logging.info(...); trace -> "
        "debug, success -> info (the kit configures JSON logs)",
    ),
    Rule(
        "TWM008",
        "bt.subtensor / bt.AsyncSubtensor",
        "manual",
        "the kit's chain gateway and MetagraphCache, or bt.Subtensor directly",
    ),
    Rule(
        "TWM009",
        "bt.metagraph / metagraph.sync()",
        "manual",
        "the kit's MetagraphCache (refreshes itself); compat.Metagraph for "
        "hotkeys / S / validator_permit",
    ),
    Rule(
        "TWM010",
        "subtensor.set_weights(...)",
        "manual",
        "the kit's weight scheduler (SubnetValidator), or bt.SetWeights",
    ),
    Rule(
        "TWM011",
        "subtensor.serve_axon(...)",
        "manual",
        "nothing: the kit publishes the axon at startup (TW_EXTERNAL_IP)",
    ),
    Rule(
        "TWM012",
        "weight_utils helpers",
        "auto",
        "tensorwire.compat.weights.to_mapping(uids, weights); v11 SetWeights "
        "normalises itself",
    ),
    Rule(
        "TWM013",
        "[metagraph.axons[uid] for uid in uids]",
        "auto",
        "tensorwire.compat.axons_from(metagraph, uids)",
    ),
    Rule(
        "TWM014",
        "bt.wallet",
        "manual",
        "load the hotkey only (TW_WALLET_*); the kit never touches the coldkey",
    ),
    Rule(
        "TWM015",
        "mock chain objects",
        "manual",
        "tensorwire.testing.FakeChain and the pytest fixtures",
    ),
    Rule(
        "TWM016",
        "bt.SubnetsAPI",
        "manual",
        "call the subnet with compat.Dendrite or ValidatorClient",
    ),
    Rule(
        "TWM017",
        "top-level bt.Keypair",
        "manual",
        "from bittensor.keyfiles import Keypair",
    ),
    Rule(
        "TWM018",
        "v10 module paths",
        "manual",
        "bittensor.core.* and bittensor.utils.* are gone in v11; see spec 3.8",
    ),
    Rule(
        "TWM019",
        "custom Axon / Dendrite subclass",
        "manual",
        "port by hand onto Miner routes / ValidatorClient",
    ),
    Rule(
        "TWM020",
        "custom verify_fn",
        "manual",
        "remove it: the kit verifies every request; use the caller policy or "
        "blacklist_fn",
    ),
    Rule(
        "TWM021",
        "bt.AxonInfo",
        "auto",
        "tensorwire.compat.AxonInfo (ip, port, hotkey, is_serving)",
    ),
    Rule(
        "TWM022",
        "v10 chain info types",
        "manual",
        "NeuronInfo / PrometheusInfo are gone: read NeuronView from the kit's "
        "metagraph; the SS58 format is 42 (tensorwire.crypto.SS58_FORMAT)",
    ),
    Rule(
        "TWM023",
        "tensor methods on metagraph values",
        "auto",
        "compat.Metagraph values are plain ints and lists: .item() / .tolist() "
        "are dropped (wrap in numpy.array(...) where an array is needed)",
    ),
    Rule(
        "TWM024",
        "template BaseValidatorNeuron",
        "auto",
        "from tensorwire.compat import TemplateValidatorAdapter as "
        "BaseValidatorNeuron (the kit runs the loop, scores and weights)",
    ),
    Rule(
        "TWM025",
        "bt.logging configuration",
        "manual",
        "remove it: the kit configures logging (TW_LOG_LEVEL); use the standard "
        "logging module for anything else",
    ),
    Rule(
        "TWM026",
        "customised template BaseValidatorNeuron",
        "manual",
        "keep your additions: make your BaseValidatorNeuron subclass "
        "tensorwire.compat.TemplateValidatorAdapter and keep only the methods "
        "the template does not have (spec 10b.2.4)",
    ),
    Rule(
        "TWM027",
        "time.sleep in a coroutine",
        "auto",
        "await asyncio.sleep(...): a blocking sleep also stops the kit's "
        "health and metrics endpoints",
    ),
    Rule(
        "TWM100",
        "Synapse without required_hash_fields",
        "risk",
        "list every request field that matters in required_hash_fields: on the "
        "v10 wire other fields can be changed without breaking the signature",
    ),
    Rule(
        "TWM101",
        "Synapse with partial required_hash_fields",
        "risk",
        "add the missing request fields to required_hash_fields",
    ),
    Rule(
        "TWM102",
        "allow_non_registered=True",
        "risk",
        "remove it: unregistered callers are refused by the kit's caller policy",
    ),
    Rule(
        "TWM103",
        "force_validator_permit=False",
        "risk",
        "require a permit (TW_REQUIRE_PERMIT=1, the kit default)",
    ),
    Rule(
        "TWM104",
        "blacklist that never checks registration",
        "risk",
        "rely on the kit's caller policy (registered + permit) and keep "
        "blacklist_fn for extra, narrower rules",
    ),
)

#: ``bt.<name>`` attributes that v11 removed or the kit replaces -> rule id.
ATTRIBUTE_RULES: Mapping[str, str] = MappingProxyType(
    {
        "Synapse": "TWM001",
        "StreamingSynapse": "TWM002",
        "axon": "TWM003",
        "Axon": "TWM003",
        "dendrite": "TWM004",
        "Dendrite": "TWM004",
        "Tensor": "TWM005",
        "config": "TWM006",
        "Config": "TWM006",
        "logging": "TWM007",
        "subtensor": "TWM008",
        "AsyncSubtensor": "TWM008",
        "metagraph": "TWM009",
        "wallet": "TWM014",
        "MockSubtensor": "TWM015",
        "MockWallet": "TWM015",
        "MockMetagraph": "TWM015",
        "SubnetsAPI": "TWM016",
        "Keypair": "TWM017",
        "AxonInfo": "TWM021",
        "NeuronInfo": "TWM022",
        "PrometheusInfo": "TWM022",
        "__ss58_format__": "TWM022",
        "utils": "TWM018",
        "core": "TWM018",
    }
)

#: ``bittensor.<module>`` imports -> rule id (longest prefix wins).
MODULE_RULES: Mapping[str, str] = MappingProxyType(
    {
        "bittensor.utils.weight_utils": "TWM012",
        "bittensor.utils": "TWM018",
        "bittensor.core": "TWM018",
        "bittensor.mock": "TWM015",
        "bittensor.subnets": "TWM016",
    }
)
