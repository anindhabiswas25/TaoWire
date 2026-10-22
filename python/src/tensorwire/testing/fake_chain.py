"""An in-memory chain implementing :class:`ChainGateway` (spec 8.13).

``FakeChain`` holds subnets, neurons, axons and submitted weights in memory,
and applies the chain rules the kit depends on: registration, validator
permits, the serving and weights rate limits, and the weights version key.
Failed writes come back as :class:`TxOutcome` values with the same
``bittensor.ErrorCode`` values the real chain produces.

Several gateways can share one chain: :meth:`FakeChain.with_signer` returns a
gateway signing as another hotkey (for example a miner and a validator in
the same test).

Example::

    chain = FakeChain(signer_hotkey=miner_hotkey)
    chain.add_subnet(2)
    chain.register(2, validator_hotkey, validator_permit=True, stake_tao=1000)
    chain.register(2, miner_hotkey)
    await chain.connect()
    mg = await chain.metagraph(2)
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

from tensorwire.chain.axon import Endpoint, parse_axon
from tensorwire.chain.gateway import (
    ChainUnavailable,
    MetagraphView,
    NeuronView,
    SubnetNotFound,
    TxOutcome,
)

__all__ = [
    "OPERATIONS",
    "AxonPublication",
    "FakeChain",
    "WeightSubmission",
]

OPERATIONS = frozenset(
    {
        "connect",
        "block",
        "metagraph",
        "uid_for_hotkey",
        "weights_rate_limit",
        "blocks_since_last_update",
        "serve_axon",
        "set_weights",
    }
)
"""Gateway operations that accept injected failures and are counted in ``calls``."""

_WRITES = frozenset({"serve_axon", "set_weights"})

_REMEDIATION = {
    "not_registered": "register the hotkey on this subnet first",
    "not_authorized": "this hotkey lacks a validator permit on the subnet",
    "rate_limited": "wait for the rate-limit window to pass, then retry",
    "invalid_argument": "check the argument values against the operation schema",
    "subnet_not_exists": "use an existing netuid",
}


@dataclass(frozen=True, slots=True)
class WeightSubmission:
    """A successful ``set_weights`` call, as recorded by :class:`FakeChain`."""

    netuid: int
    hotkey: str
    uid: int
    weights: dict[int, float]
    mechid: int
    version_key: int
    block: int


@dataclass(frozen=True, slots=True)
class AxonPublication:
    """A successful ``serve_axon`` call, as recorded by :class:`FakeChain`."""

    netuid: int
    hotkey: str
    ip: str
    port: int
    protocol_tag: int
    tls_cert_hex: str | None
    block: int


@dataclass(slots=True)
class _Neuron:
    uid: int
    hotkey: str
    coldkey: str
    validator_permit: bool
    active: bool
    total_stake_tao: float
    alpha_stake: float
    tao_stake: float
    axon: str | None
    axon_protocol: int | None
    last_update: int
    incentive: float
    dividends: float
    last_served_block: int | None = None


@dataclass(slots=True)
class _Subnet:
    netuid: int
    tempo: int
    max_uids: int
    weights_rate_limit: int
    serving_rate_limit: int
    weights_version_key: int
    neurons: dict[int, _Neuron] = field(default_factory=dict)


@dataclass(slots=True)
class _Fault:
    remaining: int
    error: BaseException | None = None
    outcome: TxOutcome | None = None


@dataclass(slots=True)
class _State:
    block: int
    subnets: dict[int, _Subnet] = field(default_factory=dict)
    weights: list[WeightSubmission] = field(default_factory=list)
    publications: list[AxonPublication] = field(default_factory=list)
    faults: dict[str, list[_Fault]] = field(default_factory=dict)
    calls: Counter[str] = field(default_factory=Counter)


class FakeChain:
    """In-memory :class:`~tensorwire.chain.gateway.ChainGateway` for tests.

    ``signer_hotkey`` is the hotkey that signs writes (``serve_axon``,
    ``set_weights``); writes without one raise ``RuntimeError``.
    ``monotonic`` is the clock stamped into ``MetagraphView.fetched_at_monotonic``;
    pass a controllable clock to test staleness. ``allow_private_axons``
    controls how axons are parsed into ``NeuronView.axon`` and defaults to
    ``True``, as on a localnet.
    """

    def __init__(
        self,
        *,
        signer_hotkey: str | None = None,
        block: int = 1,
        monotonic: Callable[[], float] = time.monotonic,
        allow_private_axons: bool = True,
    ) -> None:
        self._state = _State(block=block)
        self._signer = signer_hotkey
        self._monotonic = monotonic
        self._allow_private = allow_private_axons
        self._connected = False

    # -- shared chain views ------------------------------------------------

    def with_signer(self, hotkey: str) -> FakeChain:
        """Return a gateway on the same chain state that signs as ``hotkey``.

        The new gateway has its own connection state and starts disconnected.
        """
        other = FakeChain(
            signer_hotkey=hotkey,
            monotonic=self._monotonic,
            allow_private_axons=self._allow_private,
        )
        other._state = self._state
        return other

    @property
    def signer_hotkey(self) -> str | None:
        """The hotkey that signs this gateway's writes."""
        return self._signer

    @property
    def connected(self) -> bool:
        """Whether :meth:`connect` was called and :meth:`close` was not."""
        return self._connected

    # -- test setup ----------------------------------------------------------

    def add_subnet(
        self,
        netuid: int,
        *,
        tempo: int = 360,
        max_uids: int = 256,
        weights_rate_limit: int = 100,
        serving_rate_limit: int = 50,
        weights_version_key: int = 0,
    ) -> None:
        """Create subnet ``netuid`` with the given hyperparameters (chain defaults)."""
        if netuid in self._state.subnets:
            raise ValueError(f"subnet {netuid} already exists")
        if tempo <= 0 or max_uids <= 0:
            raise ValueError("tempo and max_uids must be positive")
        self._state.subnets[netuid] = _Subnet(
            netuid=netuid,
            tempo=tempo,
            max_uids=max_uids,
            weights_rate_limit=weights_rate_limit,
            serving_rate_limit=serving_rate_limit,
            weights_version_key=weights_version_key,
        )

    def set_hyperparameters(
        self,
        netuid: int,
        *,
        tempo: int | None = None,
        weights_rate_limit: int | None = None,
        serving_rate_limit: int | None = None,
        weights_version_key: int | None = None,
    ) -> None:
        """Change hyperparameters of an existing subnet."""
        subnet = self._subnet_or_raise(netuid)
        if tempo is not None:
            if tempo <= 0:
                raise ValueError("tempo must be positive")
            subnet.tempo = tempo
        if weights_rate_limit is not None:
            subnet.weights_rate_limit = weights_rate_limit
        if serving_rate_limit is not None:
            subnet.serving_rate_limit = serving_rate_limit
        if weights_version_key is not None:
            subnet.weights_version_key = weights_version_key

    def register(
        self,
        netuid: int,
        hotkey: str,
        *,
        coldkey: str | None = None,
        validator_permit: bool = False,
        stake_tao: float = 0.0,
        alpha_stake: float = 0.0,
        tao_stake: float = 0.0,
        axon: str | None = None,
        axon_protocol: int | None = None,
        active: bool = True,
        uid: int | None = None,
    ) -> int:
        """Register ``hotkey`` on ``netuid`` and return its UID.

        Takes the lowest free UID unless ``uid`` is given; an occupied ``uid``
        is replaced, as when the chain evicts a neuron, so the UID's hotkey
        changes. ``axon`` is an on-chain axon string (``"ip:port"`` or
        ``"[v6]:port"``); ``axon_protocol`` defaults to 4 when an axon is set.
        As on the real chain, ``last_update`` starts at the registration block,
        so the first ``set_weights`` must wait ``weights_rate_limit`` blocks
        (use :meth:`advance`).
        """
        subnet = self._subnet_or_raise(netuid)
        if any(n.hotkey == hotkey for n in subnet.neurons.values()):
            raise ValueError(f"hotkey already registered on subnet {netuid}")
        if uid is None:
            uid = next(
                (u for u in range(subnet.max_uids) if u not in subnet.neurons), None
            )
            if uid is None:
                raise ValueError(
                    f"subnet {netuid} is full; pass uid= to replace a neuron"
                )
        elif not 0 <= uid < subnet.max_uids:
            raise ValueError(f"uid {uid} is out of range for subnet {netuid}")
        subnet.neurons[uid] = _Neuron(
            uid=uid,
            hotkey=hotkey,
            coldkey=coldkey if coldkey is not None else hotkey,
            validator_permit=validator_permit,
            active=active,
            total_stake_tao=stake_tao,
            alpha_stake=alpha_stake,
            tao_stake=tao_stake,
            axon=axon,
            axon_protocol=(4 if axon_protocol is None else axon_protocol)
            if axon
            else None,
            last_update=self._state.block,
            incentive=0.0,
            dividends=0.0,
        )
        return uid

    def deregister(self, netuid: int, hotkey: str) -> None:
        """Remove ``hotkey`` from ``netuid``, freeing its UID."""
        neuron = self._neuron_or_raise(netuid, hotkey)
        del self._state.subnets[netuid].neurons[neuron.uid]

    def set_permit(self, netuid: int, hotkey: str, permit: bool) -> None:
        """Grant or revoke ``hotkey``'s validator permit."""
        self._neuron_or_raise(netuid, hotkey).validator_permit = permit

    def set_stake(
        self,
        netuid: int,
        hotkey: str,
        *,
        stake_tao: float,
        alpha_stake: float | None = None,
        tao_stake: float | None = None,
    ) -> None:
        """Set ``hotkey``'s stake (``stake_tao`` is ``NeuronView.total_stake_tao``)."""
        neuron = self._neuron_or_raise(netuid, hotkey)
        neuron.total_stake_tao = stake_tao
        if alpha_stake is not None:
            neuron.alpha_stake = alpha_stake
        if tao_stake is not None:
            neuron.tao_stake = tao_stake

    def set_axon(
        self, netuid: int, hotkey: str, axon: str | None, *, protocol: int = 4
    ) -> None:
        """Set ``hotkey``'s on-chain axon string directly, bypassing rate limits."""
        neuron = self._neuron_or_raise(netuid, hotkey)
        neuron.axon = axon
        neuron.axon_protocol = protocol if axon else None

    def set_scores(
        self, netuid: int, hotkey: str, *, incentive: float, dividends: float
    ) -> None:
        """Set ``hotkey``'s incentive and dividends (0..1)."""
        neuron = self._neuron_or_raise(netuid, hotkey)
        neuron.incentive = incentive
        neuron.dividends = dividends

    def advance(self, blocks: int = 1) -> int:
        """Produce ``blocks`` blocks and return the new block number."""
        if blocks < 0:
            raise ValueError("blocks must not be negative")
        self._state.block += blocks
        return self._state.block

    def fail_next(
        self, operation: str, times: int = 1, *, error: BaseException | None = None
    ) -> None:
        """Make the next ``times`` calls of ``operation`` raise.

        The default error is :class:`ChainUnavailable`, which is what a real
        gateway raises after its retries are exhausted. Queued failures run
        in the order they were added.
        """
        self._add_fault(operation, times, _Fault(remaining=times, error=error))

    def reject_next(
        self,
        operation: str,
        code: str,
        times: int = 1,
        *,
        remediation: str | None = None,
    ) -> None:
        """Make the next ``times`` writes of ``operation`` return a failed outcome."""
        if operation not in _WRITES:
            raise ValueError(f"reject_next only applies to writes: {sorted(_WRITES)}")
        outcome = TxOutcome(
            ok=False,
            code=code,
            remediation=remediation
            if remediation is not None
            else _REMEDIATION.get(code),
            block_hash=None,
        )
        self._add_fault(operation, times, _Fault(remaining=times, outcome=outcome))

    # -- inspection ----------------------------------------------------------

    @property
    def current_block(self) -> int:
        """The current block number, without counting a call."""
        return self._state.block

    @property
    def calls(self) -> Counter[str]:
        """How many times each gateway operation was called, across shared gateways."""
        return self._state.calls

    def weight_submissions(
        self, netuid: int | None = None
    ) -> tuple[WeightSubmission, ...]:
        """Successful ``set_weights`` calls, oldest first, optionally for one subnet."""
        return tuple(
            w for w in self._state.weights if netuid is None or w.netuid == netuid
        )

    def axon_publications(
        self, netuid: int | None = None
    ) -> tuple[AxonPublication, ...]:
        """Successful ``serve_axon`` calls, oldest first, optionally for one subnet."""
        return tuple(
            p for p in self._state.publications if netuid is None or p.netuid == netuid
        )

    # -- ChainGateway ----------------------------------------------------------

    async def connect(self) -> None:
        """Mark the gateway connected (or raise an injected failure)."""
        self._enter("connect", needs_connection=False)
        self._connected = True

    async def close(self) -> None:
        """Mark the gateway closed. Safe to call more than once."""
        self._connected = False

    async def block(self) -> int:
        """Return the current block."""
        self._enter("block")
        return self._state.block

    async def metagraph(self, netuid: int) -> MetagraphView:
        """Return a snapshot of ``netuid`` stamped with the injected clock."""
        self._enter("metagraph")
        subnet = self._subnet_or_raise(netuid)
        neurons = tuple(
            self._view(subnet.neurons[uid]) for uid in sorted(subnet.neurons)
        )
        return MetagraphView(
            netuid=netuid,
            block=self._state.block,
            fetched_at_monotonic=self._monotonic(),
            neurons=neurons,
            tempo=subnet.tempo,
        )

    async def uid_for_hotkey(self, netuid: int, hotkey: str) -> int | None:
        """Return ``hotkey``'s UID on ``netuid``, or ``None``."""
        self._enter("uid_for_hotkey")
        neuron = self._find(self._subnet_or_raise(netuid), hotkey)
        return None if neuron is None else neuron.uid

    async def weights_rate_limit(self, netuid: int) -> int:
        """Return the subnet's weights rate limit in blocks."""
        self._enter("weights_rate_limit")
        return self._subnet_or_raise(netuid).weights_rate_limit

    async def blocks_since_last_update(self, netuid: int, uid: int) -> int | None:
        """Return blocks since ``uid`` last set weights; ``None`` for an empty UID."""
        self._enter("blocks_since_last_update")
        neuron = self._subnet_or_raise(netuid).neurons.get(uid)
        return None if neuron is None else self._state.block - neuron.last_update

    async def serve_axon(
        self,
        netuid: int,
        ip: str,
        port: int,
        *,
        tls_cert_hex: str | None,
        protocol_tag: int,
    ) -> TxOutcome:
        """Publish ``ip:port`` for the signer, applying the serving rate limit."""
        injected = self._enter("serve_axon")
        if injected is not None:
            return injected
        subnet = self._state.subnets.get(netuid)
        if subnet is None:
            return _failed("subnet_not_exists")
        neuron = self._find(subnet, self._signer_or_raise())
        if neuron is None:
            return _failed("not_registered")
        axon = _axon_string(ip, port)
        if axon is None or not 0 <= protocol_tag <= 255:
            return _failed("invalid_argument")
        if (
            neuron.last_served_block is not None
            and self._state.block - neuron.last_served_block < subnet.serving_rate_limit
        ):
            return _failed("rate_limited")
        neuron.axon = axon
        neuron.axon_protocol = protocol_tag
        neuron.last_served_block = self._state.block
        self._state.publications.append(
            AxonPublication(
                netuid=netuid,
                hotkey=neuron.hotkey,
                ip=ip,
                port=port,
                protocol_tag=protocol_tag,
                tls_cert_hex=tls_cert_hex,
                block=self._state.block,
            )
        )
        return self._succeeded()

    async def set_weights(
        self,
        netuid: int,
        weights: dict[int, float],
        *,
        mechid: int,
        version_key: int,
    ) -> TxOutcome:
        """Record the signer's weights, applying permit, version and rate rules."""
        injected = self._enter("set_weights")
        if injected is not None:
            return injected
        subnet = self._state.subnets.get(netuid)
        if subnet is None:
            return _failed("subnet_not_exists")
        neuron = self._find(subnet, self._signer_or_raise())
        if neuron is None:
            return _failed("not_registered")
        if not neuron.validator_permit:
            return _failed("not_authorized")
        if version_key < subnet.weights_version_key:
            return _failed("invalid_argument")
        if (
            not weights
            or any(uid not in subnet.neurons for uid in weights)
            or any(not w >= 0 for w in weights.values())
        ):
            return _failed("invalid_argument")
        if self._state.block - neuron.last_update < subnet.weights_rate_limit:
            return _failed("rate_limited")
        neuron.last_update = self._state.block
        self._state.weights.append(
            WeightSubmission(
                netuid=netuid,
                hotkey=neuron.hotkey,
                uid=neuron.uid,
                weights=dict(weights),
                mechid=mechid,
                version_key=version_key,
                block=self._state.block,
            )
        )
        return self._succeeded()

    # -- internals -------------------------------------------------------------

    def _add_fault(self, operation: str, times: int, fault: _Fault) -> None:
        if operation not in OPERATIONS:
            raise ValueError(
                f"unknown operation {operation!r}; expected one of {sorted(OPERATIONS)}"
            )
        if times < 1:
            raise ValueError("times must be at least 1")
        self._state.faults.setdefault(operation, []).append(fault)

    def _enter(
        self, operation: str, *, needs_connection: bool = True
    ) -> TxOutcome | None:
        self._state.calls[operation] += 1
        if needs_connection and not self._connected:
            raise RuntimeError("FakeChain is not connected; await connect() first")
        queue = self._state.faults.get(operation)
        if not queue:
            return None
        fault = queue[0]
        fault.remaining -= 1
        if fault.remaining == 0:
            queue.pop(0)
        if fault.outcome is not None:
            return fault.outcome
        raise (
            fault.error
            if fault.error is not None
            else ChainUnavailable(f"injected failure: {operation}")
        )

    def _view(self, n: _Neuron) -> NeuronView:
        endpoint: Endpoint | None = parse_axon(
            n.axon, allow_private=self._allow_private
        )
        return NeuronView(
            uid=n.uid,
            hotkey=n.hotkey,
            coldkey=n.coldkey,
            validator_permit=n.validator_permit,
            active=n.active,
            total_stake_tao=n.total_stake_tao,
            alpha_stake=n.alpha_stake,
            tao_stake=n.tao_stake,
            axon=endpoint,
            last_update=n.last_update,
            incentive=n.incentive,
            dividends=n.dividends,
            axon_protocol=n.axon_protocol,
        )

    def _subnet_or_raise(self, netuid: int) -> _Subnet:
        subnet = self._state.subnets.get(netuid)
        if subnet is None:
            raise SubnetNotFound(f"subnet {netuid} does not exist")
        return subnet

    def _neuron_or_raise(self, netuid: int, hotkey: str) -> _Neuron:
        neuron = self._find(self._subnet_or_raise(netuid), hotkey)
        if neuron is None:
            raise ValueError(f"hotkey is not registered on subnet {netuid}")
        return neuron

    @staticmethod
    def _find(subnet: _Subnet, hotkey: str) -> _Neuron | None:
        return next((n for n in subnet.neurons.values() if n.hotkey == hotkey), None)

    def _signer_or_raise(self) -> str:
        if self._signer is None:
            raise RuntimeError("this FakeChain has no signer_hotkey; use with_signer()")
        return self._signer

    def _succeeded(self) -> TxOutcome:
        return TxOutcome(
            ok=True,
            code=None,
            remediation=None,
            block_hash=f"0x{self._state.block:064x}",
        )


def _failed(code: str) -> TxOutcome:
    return TxOutcome(
        ok=False, code=code, remediation=_REMEDIATION.get(code), block_hash=None
    )


def _axon_string(ip: str, port: int) -> str | None:
    """Format ``ip:port`` the way the metagraph reports it, or ``None`` if invalid."""
    candidate = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    endpoint = parse_axon(candidate, allow_private=True)
    return None if endpoint is None else str(endpoint)
