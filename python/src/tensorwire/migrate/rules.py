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
    "V11_PUBLIC",
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
        "bt.Synapse / bt.TerminalInfo",
        "auto",
        "from tensorwire.compat import Synapse (TerminalInfo likewise)",
    ),
    Rule(
        "TWM002",
        "bt.StreamingSynapse",
        "auto",
        "from tensorwire.compat import StreamingSynapse (the kit's signed SSE "
        "streaming, spec 9.2; same process_streaming_response / "
        "extract_response_json / deserialize)",
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
        "bt.subtensor(...) / bt.Subtensor(config=...)",
        "auto",
        "tensorwire.compat.Subtensor: the v10 reads and commitments on the "
        "kit's gateway (spec 10b.2.6); or the kit's MetagraphCache",
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
        "customised template bases",
        "auto",
        "BaseMinerNeuron / BaseValidatorNeuron also subclass "
        "tensorwire.compat.TemplateMinerAdapter / TemplateValidatorAdapter; the "
        "run loops, axon serving, set_weights and wallet/subtensor set-up go, "
        "your own methods stay (spec 10b.2.4)",
    ),
    Rule(
        "TWM027",
        "time.sleep in a coroutine",
        "auto",
        "await asyncio.sleep(...): a blocking sleep also stops the kit's "
        "health and metrics endpoints",
    ),
    Rule(
        "TWM028",
        "bittensor type in a string annotation",
        "auto",
        'the compat type: "bt.Synapse" -> "Synapse", "bt.metagraph.Metagraph" -> '
        '"Metagraph" (AxonInfo, TerminalInfo, "bt.subtensor" -> "Subtensor" likewise)',
    ),
    Rule(
        "TWM029",
        "bittensor name inside a string",
        "manual",
        "update it by hand (a mock.patch target such as 'mod.bt.logging.info' "
        "breaks once the code it names is migrated)",
    ),
    Rule(
        "TWM030",
        "unknown bittensor name",
        "manual",
        "neither a known v10 symbol nor part of the v11 public API: check it by "
        "hand (removed in v11, or a typo)",
    ),
    Rule(
        "TWM031",
        "v10 config calls",
        "auto",
        'bt.<group>.add_args(parser) -> add_v10_args(parser, "<group>"), '
        "bt.config(parser) -> tensorwire.compat.config(parser), a bt.Config "
        "annotation -> Config, bt.logging.check_config(...) removed: defaults "
        "come from TW_* settings",
    ),
    Rule(
        "TWM032",
        "bt.logging set-up statement",
        "auto",
        "removed: the kit configures logging (TW_LOG_LEVEL); bare "
        "bt.logging(...), bt.logging.set_debug(...), set_trace, enable_* ... "
        "statements have nothing left to do",
    ),
    Rule(
        "TWM033",
        "bt.Wallet(config=c)",
        "auto",
        "v11's constructor: bt.Wallet(name=c.wallet.name, hotkey=c.wallet.hotkey, "
        "path=c.wallet.path) (the subnet's own wallet use; the kit loads its "
        "hotkey from TW_WALLET_*)",
    ),
    Rule(
        "TWM100",
        "Synapse without required_hash_fields",
        "risk",
        "list every request field that matters in required_hash_fields: on the "
        "v10 wire other fields can be changed without breaking the signature. "
        "This changes the v10 body hash: ship it to every peer at once, or after "
        "rollout stage 4 (D28)",
    ),
    Rule(
        "TWM101",
        "Synapse with partial required_hash_fields",
        "risk",
        "add the missing request fields to required_hash_fields (every peer at "
        "once, or after rollout stage 4: it changes the v10 body hash, D28)",
    ),
    Rule(
        "TWM102",
        "allow_non_registered=True",
        "risk",
        "remove it: unregistered callers are refused by the kit's caller policy",
    ),
    Rule(
        "TWM034",
        "StreamingSynapse route in a mixed fleet",
        "risk",
        "streaming works TensorWire to TensorWire only: a v10 Dendrite gets "
        "tw.invalid_request from it and a v10 miner cannot stream to a "
        "TensorWire validator (D33); move streaming routes after rollout "
        "stage 2 or give v10 peers a non-streaming route",
    ),
    Rule(
        "TWM035",
        "bt.AsyncSubtensor",
        "manual",
        "the kit's chain gateway (async) and MetagraphCache, or v11's bt.Subtensor "
        "(await bt.Subtensor(...)); compat.Subtensor is synchronous",
    ),
    Rule(
        "TWM036",
        "subtensor write compat.Subtensor does not perform",
        "manual",
        "the v11 replacement named in the finding (stake, transfer and "
        "registration are coldkey operations: run them from btcli, not a server)",
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

#: v10 ``subtensor`` writes that ``compat.Subtensor`` does not perform, with
#: their v11 replacement (spec 10b.2.6; TWM036).
V10_SUBTENSOR_WRITES: Mapping[str, str] = MappingProxyType(
    {
        "add_stake": "bt.AddStake (coldkey-signed: run it from btcli, not a server)",
        "add_stake_multiple": "bt.AddStake per hotkey (coldkey-signed)",
        "unstake": "bt.RemoveStake (coldkey-signed)",
        "unstake_multiple": "bt.RemoveStake per hotkey (coldkey-signed)",
        "transfer": "bt.Transfer (coldkey-signed)",
        "register": "btcli subnets register / bt.BurnedRegister",
        "burned_register": "bt.BurnedRegister (coldkey-signed)",
        "root_register": "bt.RootRegister (coldkey-signed)",
        "root_set_weights": "bt.SetWeights on netuid 0",
        "commit_weights": "the kit's weight scheduler (timelocked commit-reveal, 8.9)",
        "reveal_weights": "the kit's weight scheduler (reveals are automatic in v11)",
        "set_children": "bt.SetChildren",
        "set_delegate_take": "bt.SetTake",
        "move_stake": "bt.MoveStake (coldkey-signed)",
        "swap_stake": "bt.SwapStake (coldkey-signed)",
        "serve_prometheus": "nothing: v11 has no prometheus endpoint on chain",
        "set_identity": "bt.SetIdentity (coldkey-signed)",
        "update_identity": "bt.SetIdentity (coldkey-signed)",
    }
)

#: v10 ``subtensor`` methods that v11's ``bt.Subtensor`` does not have: a file
#: that calls one builds v10's ``bt.Subtensor``, whatever its arguments (TWM008).
V10_SUBTENSOR_METHODS = frozenset(
    {
        "get_current_block",
        "get_block_hash",
        "get_uid_for_hotkey_on_subnet",
        "is_hotkey_registered",
        "get_commitment",
        "set_commitment",
        "query_subtensor",
    }
)

#: ``bt.<name>`` attributes that v11 removed or the kit replaces -> rule id.
ATTRIBUTE_RULES: Mapping[str, str] = MappingProxyType(
    {
        "Synapse": "TWM001",
        "TerminalInfo": "TWM001",
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
        "AsyncSubtensor": "TWM035",
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
        "bittensor_wallet.keypair": "TWM017",
        "bittensor_wallet": "TWM014",
    }
)

#: ``bittensor`` 11.3.0's public names (``dir(bittensor)``), for the TWM030
#: catch-all: a ``bt.<name>`` that is neither in ATTRIBUTE_RULES nor here.
#: Regenerate when the supported SDK range moves (spec 18.3).
V11_PUBLIC: frozenset[str] = frozenset(
    {
        "AddCollateral",
        "AddProxy",
        "AddStake",
        "AddStakeLimit",
        "AnnounceColdkeySwap",
        "AssociateEvmKey",
        "AssociateHotkey",
        "Balance",
        "Batch",
        "BittensorError",
        "BlockHeader",
        "BlockInfo",
        "BridgeClient",
        "BridgeError",
        "BridgeServer",
        "BurnedRegister",
        "CRYPTO_ED25519",
        "CRYPTO_SR25519",
        "ChainError",
        "ClaimRoot",
        "ClaimRootWithHotkey",
        "ClearColdkeySwapAnnouncement",
        "Client",
        "CommitWeights",
        "Commitment",
        "ConnectionNotReady",
        "ContributeCrowdloan",
        "CreateCrowdloan",
        "CreatePureProxy",
        "DEFAULT_CRYPTO_TYPE",
        "DecreaseTake",
        "DelegateInfo",
        "DelegatedStake",
        "DisputeColdkeySwap",
        "DissolveCrowdloan",
        "EpochEvent",
        "ErrorCode",
        "EvmWithdraw",
        "ExecuteProxyAnnounced",
        "ExtensionAccount",
        "ExtensionSigner",
        "ExtrinsicResult",
        "FinalizeCrowdloan",
        "FundEvmKey",
        "IncreaseTake",
        "Intent",
        "KeyedWallet",
        "KillPureProxy",
        "LedgerError",
        "LedgerSigner",
        "LockStake",
        "Metagraph",
        "MetagraphNeuron",
        "MoveLock",
        "MoveStake",
        "MoveSwapStake",
        "Multisig",
        "MultisigApprove",
        "MultisigCancel",
        "MultisigExecute",
        "MultisigThreshold1",
        "Neuron",
        "NeuronCommitment",
        "Plan",
        "Policy",
        "PolicyError",
        "PowRegister",
        "RefundCrowdloan",
        "RegisterLeasedNetwork",
        "RegisterSubnet",
        "RemoveProxies",
        "RemoveProxy",
        "RemoveStake",
        "RemoveStakeLimit",
        "ResetAxon",
        "RevealWeights",
        "RootRegister",
        "RpcConnectionError",
        "RpcPolicyError",
        "RpcSubstrate",
        "ServeAxon",
        "ServeAxonTls",
        "ServePrometheus",
        "SetAutoStake",
        "SetChildkeyTake",
        "SetChildren",
        "SetCrowdloanMaxContribution",
        "SetHyperparameter",
        "SetIdentity",
        "SetMechanismCount",
        "SetMinCollateral",
        "SetPerpetualLock",
        "SetRejectLockedAlpha",
        "SetRootClaimThreshold",
        "SetSubnetEmissionEnabled",
        "SetSubnetIdentity",
        "SetTake",
        "SetWeights",
        "Signer",
        "SigningContext",
        "Snapshot",
        "StakeBurn",
        "StakeIntoBasket",
        "StakePosition",
        "StakeValuation",
        "StartCall",
        "SubnetInfo",
        "Substrate",
        "Subtensor",
        "SwapBasket",
        "SwapBasketMany",
        "SwapColdkeyAnnounced",
        "SwapHotkey",
        "SwapQuote",
        "SwapStake",
        "SyncClient",
        "TerminateLease",
        "TimelockError",
        "TimelockNotReady",
        "Timelocked",
        "Transfer",
        "TransferAll",
        "TransferStake",
        "TrimNullSubnetBatch",
        "TrimSubnet",
        "UnitMismatchError",
        "UnsignedExtrinsic",
        "UnstakeAll",
        "UnstakeAllAlpha",
        "UpdateCrowdloanCap",
        "UpdateCrowdloanEnd",
        "UpdateCrowdloanMinContribution",
        "UpdateSymbol",
        "VaultError",
        "VaultSigner",
        "Wallet",
        "WalletLike",
        "WalletSigner",
        "WithdrawCrowdloan",
        "alpha",
        "balance",
        "calls",
        "client",
        "close_shared_clients",
        "config",
        "connect_extension_signer",
        "constants",
        "ensure_bridge",
        "error_descriptions",
        "error_map",
        "evm",
        "executor",
        "extension",
        "fee_filters",
        "format_crypto_type",
        "http_auth",
        "hyperparams",
        "intents",
        "keyfiles",
        "ledger",
        "masked_input",
        "metagraph",
        "multisig",
        "namespaces",
        "parse_crypto_type",
        "public_view",
        "rao",
        "reads",
        "resolve_signer",
        "result",
        "run_bridge",
        "runtime_api",
        "set_weights",
        "settings",
        "signing",
        "snapshot",
        "sp_core",
        "stop_bridge_daemon",
        "storage",
        "subtensor",
        "sync",
        "tao",
        "timelock",
        "vault",
        "wallet",
        "wallets",
    }
)
