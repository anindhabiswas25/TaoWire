"""The chain boundary (spec 8.3, ADR-0001).

Every chain read and write in the kit goes through a :class:`ChainGateway`.
The rest of the kit only sees the kit-owned views defined here
(:class:`NeuronView`, :class:`MetagraphView`, :class:`TxOutcome`), never
``bittensor`` types, so an SDK change is fixed in this one module.

:class:`BittensorGateway` is the real implementation on the v11 SDK;
``tensorwire.testing.fake_chain.FakeChain`` implements the same Protocol for
tests.
"""

from __future__ import annotations

import asyncio
import logging
import math
import random
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeVar, runtime_checkable

import bittensor as bt

from tensorwire.chain.axon import Endpoint, parse_axon

__all__ = [
    "BittensorGateway",
    "ChainGateway",
    "ChainUnavailable",
    "GatewayError",
    "MetagraphView",
    "NeuronView",
    "SdkSurfaceError",
    "SubnetNotFound",
    "TxOutcome",
    "check_sdk_surface",
]


class GatewayError(Exception):
    """Base class for gateway read failures. Never sent to peers."""


class ChainUnavailable(GatewayError):
    """A read failed after retries or timed out: no usable chain endpoint."""


class SubnetNotFound(GatewayError):
    """The requested netuid does not exist on the connected chain."""


class SdkSurfaceError(GatewayError):
    """The installed ``bittensor`` lacks a symbol the gateway uses (spec 8.7.3)."""


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

    async def serving_rate_limit(self, netuid: int) -> int:
        """Return the subnet's serving rate limit (blocks between ``ServeAxon``)."""
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


# ---------------------------------------------------------------------------
# BittensorGateway: the real gateway on the v11 SDK.

_log = logging.getLogger("tensorwire.chain")

_T = TypeVar("_T")

_U8_MAX = 255

READ_ATTEMPTS = 5
"""Attempts per read (spec 8.3): the first try plus four retries."""

BACKOFF_BASE_S = 0.5
BACKOFF_MAX_S = 8.0

WRITE_ATTEMPTS = 3
"""Submissions per write, counting only definite pool rejections (see below)."""

RESIGN_ERROR_NAMES = frozenset(
    {
        "BadProof",  # "signature does not match": signed against a forked block
        "AncientBirthBlock",  # era birth block too old
        "Stale",  # nonce already used by another transaction
        "Future",  # cached nonce ahead of the chain
        "PriorityTooLow",  # another transaction holds the nonce in the pool
        "Invalid",  # the pool dropped it as invalid (e.g. its era ran out)
        "Dropped",  # the pool dropped it
        "Usurped",  # replaced by another transaction with the same nonce
    }
)
"""Write failures where the extrinsic was rejected or dropped before inclusion.

Only these are retried, and always with a new extrinsic (fresh nonce, fresh
era, new signature), never by resending the old bytes. Every other failure,
including ``Retracted`` and ``FinalityTimeout`` (it may still be on chain),
is returned to the caller.
"""

_NOT_SUBMITTED = (
    "the chain could not be reached to prepare the transaction; nothing was submitted"
)

_UNKNOWN_FATE = (
    "the chain connection failed or timed out after submission; the transaction "
    "may still be included. Read the chain state before submitting again"
)

ClientFactory = Callable[[str, "list[str] | None"], Any]
"""Builds an unopened SDK client for ``(endpoint_or_network, fallback_endpoints)``."""


def _default_client(network: str, fallbacks: list[str] | None) -> Any:
    # bt.Client is the async client that ``await bt.Subtensor(...)`` yields;
    # building it directly keeps connect() and close() explicit.
    return bt.Client(network, fallback_endpoints=fallbacks)


REQUIRED_SDK_SYMBOLS = (
    "Client",
    "ServeAxon",
    "ServeAxonTls",
    "SetWeights",
    "ChainError",
    "PolicyError",
    "RpcConnectionError",
    "ConnectionNotReady",
)
"""Top-level ``bittensor`` names the gateway uses (spec 3.3, 3.5)."""

REQUIRED_CLIENT_READS = (
    "subnets.metagraph",
    "neurons.uid",
    "hyperparameters.weights_rate_limit",
    "epochs.blocks_since_last_update",
    "block",
    "finalized_block",
    "block_time",
    "query",
    "execute",
)
"""Client attributes the gateway calls, checked after connecting."""


class _MissingSdkError(Exception):
    """Stands in for an exception class the installed SDK lacks; never raised."""


def _sdk_error(name: str) -> type[BaseException]:
    value = getattr(bt, name, None)
    if isinstance(value, type) and issubclass(value, BaseException):
        return value
    return _MissingSdkError


def check_sdk_surface(client: Any = None) -> list[str]:
    """Return the SDK names the gateway needs but cannot find (empty when fine).

    Checks the top-level symbols, and with ``client`` (a connected
    ``bt.Client``) the read namespaces and methods it calls.
    """
    missing = [f"bittensor.{n}" for n in REQUIRED_SDK_SYMBOLS if not hasattr(bt, n)]
    if client is not None:
        for path in REQUIRED_CLIENT_READS:
            obj = client
            for part in path.split("."):
                obj = getattr(obj, part, None)
            if obj is None:
                missing.append(f"bittensor.Client.{path}")
    return missing


_TRANSIENT_READ_ERRORS: tuple[type[BaseException], ...] = (
    _sdk_error("ChainError"),
    _sdk_error("RpcConnectionError"),
    _sdk_error("ConnectionNotReady"),
    ConnectionError,
    OSError,
    TimeoutError,
    asyncio.TimeoutError,
)
"""Read failures worth retrying. Anything else is a bug and propagates."""

_CONNECTION_ERRORS: tuple[type[BaseException], ...] = (
    _sdk_error("RpcConnectionError"),
    _sdk_error("ConnectionNotReady"),
    ConnectionError,
    OSError,
)
"""Failures after which the SDK client is rebuilt on the next endpoint."""


class BittensorGateway:
    """:class:`ChainGateway` on the ``bittensor`` v11 SDK (spec 8.3, ADR-0001).

    ``network`` is ``finney``, ``test``, ``local`` or a ``ws(s)://`` URL.
    ``fallback_endpoints`` are tried in order when the current endpoint fails;
    an empty sequence keeps the SDK's public fallback pool for named
    networks. ``hotkey`` signs ``ServeAxon`` and ``SetWeights``: pass the
    hotkey ``Keypair`` (``wallet.hotkey``) or any ``bittensor.signing.Signer``,
    never a coldkey; without it, writes raise ``RuntimeError``.

    Reads: each attempt has ``timeout_s``; connection errors and timeouts are
    retried ``read_attempts`` times with jittered exponential backoff
    (0.5 s doubling to 8 s), and the client is rebuilt on the next endpoint
    after a connection failure. When the attempts run out, reads raise
    :class:`ChainUnavailable`.

    Writes are planned first (``client.plan``: a dry run, nothing signed).
    A failed SDK preflight, such as the weights rate-limit check, is returned
    with its own code without submitting. Writes are never resent blindly. A
    submission rejected or dropped before
    inclusion (:data:`RESIGN_ERROR_NAMES`, e.g. "signature does not match" or
    an expired era on a short fork) is retried as a new extrinsic signed after
    the next finalized block, up to ``write_attempts`` times. A timeout or
    connection loss after submission returns ``code="unknown"`` without a
    retry, because the transaction may still land. Each write waits up to
    ``write_timeout_s`` (default: four times ``timeout_s``) for inclusion and,
    with ``wait_for_finalization``, finality.
    """

    def __init__(
        self,
        network: str,
        *,
        hotkey: Any = None,
        fallback_endpoints: Sequence[str] = (),
        timeout_s: float = 30.0,
        write_timeout_s: float | None = None,
        allow_private_axons: bool = False,
        wait_for_finalization: bool = True,
        read_attempts: int = READ_ATTEMPTS,
        write_attempts: int = WRITE_ATTEMPTS,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[], float] = random.random,
        client_factory: ClientFactory = _default_client,
    ) -> None:
        if timeout_s <= 0 or (write_timeout_s is not None and write_timeout_s <= 0):
            raise ValueError("timeouts must be positive")
        if read_attempts < 1 or write_attempts < 1:
            raise ValueError("attempts must be at least 1")
        self._endpoints = [network, *(e for e in fallback_endpoints if e != network)]
        self._custom_fallbacks = bool(fallback_endpoints)
        self._endpoint_index = 0
        self._hotkey = hotkey
        self._timeout_s = timeout_s
        self._write_timeout_s = (
            write_timeout_s if write_timeout_s is not None else 4 * timeout_s
        )
        self._allow_private = allow_private_axons
        self._finalization = wait_for_finalization
        self._read_attempts = read_attempts
        self._write_attempts = write_attempts
        self._monotonic = monotonic
        self._sleep = sleep
        self._jitter = jitter
        self._factory = client_factory
        self._client: Any = None
        self._connected = False
        self._lock = asyncio.Lock()

    @classmethod
    def from_settings(cls, settings: Any, *, hotkey: Any = None) -> BittensorGateway:
        """Build a gateway from ``tensorwire.config.CommonSettings`` (or a subclass).

        Uses ``network``, ``chain_fallbacks``, ``chain_timeout_s`` and
        ``allow_private_axons``.
        """
        return cls(
            settings.network,
            hotkey=hotkey,
            fallback_endpoints=tuple(settings.chain_fallbacks),
            timeout_s=float(settings.chain_timeout_s),
            allow_private_axons=bool(settings.allow_private_axons),
        )

    @property
    def endpoint(self) -> str:
        """The endpoint (or network name) the current client was opened on."""
        return self._endpoints[self._endpoint_index]

    # -- connection ------------------------------------------------------------

    async def connect(self) -> None:
        """Open the client, trying each endpoint in turn.

        Raises :class:`SdkSurfaceError` naming every missing SDK symbol when
        the installed ``bittensor`` does not provide what the gateway uses,
        and :class:`ChainUnavailable` when no endpoint answers.
        """
        missing = check_sdk_surface()
        if missing:
            raise SdkSurfaceError(_missing_message(missing))
        self._connected = True
        try:
            client = await self._call("connect", self._ensure_client)
        except ChainUnavailable:
            self._connected = False
            raise
        missing = check_sdk_surface(client)
        if missing:
            await self.close()
            raise SdkSurfaceError(_missing_message(missing))

    async def close(self) -> None:
        """Close the client. Safe to call more than once."""
        self._connected = False
        await self._drop_client(rotate=False)

    async def _ensure_client(self) -> Any:
        if not self._connected:
            raise RuntimeError("gateway is not connected; await connect() first")
        async with self._lock:
            if self._client is None:
                network = self.endpoint
                rest = self._endpoints[self._endpoint_index + 1 :]
                rest += self._endpoints[: self._endpoint_index]
                fallbacks = rest if self._custom_fallbacks else None
                client = self._factory(network, fallbacks)
                try:
                    await client.connect()
                except BaseException:
                    await _close_quietly(client)
                    raise
                self._client = client
            return self._client

    async def _drop_client(self, *, rotate: bool) -> None:
        async with self._lock:
            client, self._client = self._client, None
            if rotate:
                self._endpoint_index = (self._endpoint_index + 1) % len(self._endpoints)
        if client is not None:
            await _close_quietly(client)

    async def _call(
        self,
        what: str,
        op: Callable[[], Awaitable[_T]],
    ) -> _T:
        """Run a read with per-attempt timeout, retries and backoff."""
        last: BaseException | None = None
        for attempt in range(1, self._read_attempts + 1):
            try:
                return await asyncio.wait_for(op(), self._timeout_s)
            except _TRANSIENT_READ_ERRORS as e:
                last = e
                connection_lost = isinstance(
                    e, (*_CONNECTION_ERRORS, TimeoutError, asyncio.TimeoutError)
                )
                _log.warning(
                    "chain read failed",
                    extra={
                        "op": what,
                        "attempt": attempt,
                        "error": type(e).__name__,
                        # no endpoint: private node URLs can carry API tokens
                    },
                )
                if connection_lost:
                    await self._drop_client(rotate=True)
                if attempt < self._read_attempts:
                    await self._sleep(self._backoff(attempt))
        raise ChainUnavailable(
            f"{what} failed after {self._read_attempts} attempts "
            f"({type(last).__name__})"
        ) from last

    def _backoff(self, attempt: int) -> float:
        """0.5 s doubling per attempt, jittered by x[0.5, 1.5), capped at 8 s."""
        base = BACKOFF_BASE_S * 2 ** (attempt - 1)
        return float(min(BACKOFF_MAX_S, base * (0.5 + self._jitter())))

    # -- reads -----------------------------------------------------------------

    async def block(self) -> int:
        """Return the current (best) block number."""

        async def op() -> int:
            return int(await (await self._ensure_client()).block())

        return await self._call("block", op)

    async def metagraph(self, netuid: int) -> MetagraphView:
        """Return a snapshot of ``netuid``; raise :class:`SubnetNotFound` if absent."""

        async def op() -> Any:
            client = await self._ensure_client()
            return await client.subnets.metagraph(netuid, commitments=False)

        mg = await self._call("metagraph", op)
        if mg is None:
            raise SubnetNotFound(f"subnet {netuid} does not exist")
        return metagraph_view(
            mg,
            fetched_at_monotonic=self._monotonic(),
            allow_private_axons=self._allow_private,
        )

    async def uid_for_hotkey(self, netuid: int, hotkey: str) -> int | None:
        """Return ``hotkey``'s UID on ``netuid``, or ``None`` if unregistered."""

        async def op() -> Any:
            client = await self._ensure_client()
            return await client.neurons.uid(hotkey_ss58=hotkey, netuid=netuid)

        uid = await self._call("uid_for_hotkey", op)
        if uid is None:
            await self._require_subnet(netuid)
            return None
        return int(uid)

    async def weights_rate_limit(self, netuid: int) -> int:
        """Return the subnet's weights rate limit, in blocks."""
        await self._require_subnet(netuid)

        async def op() -> Any:
            client = await self._ensure_client()
            return await client.hyperparameters.weights_rate_limit(netuid=netuid)

        return int(await self._call("weights_rate_limit", op))

    async def blocks_since_last_update(self, netuid: int, uid: int) -> int | None:
        """Return blocks since ``uid`` last set weights, or ``None`` if unknown."""

        async def op() -> Any:
            client = await self._ensure_client()
            return await client.epochs.blocks_since_last_update(netuid=netuid, uid=uid)

        value = await self._call("blocks_since_last_update", op)
        if value is None:
            await self._require_subnet(netuid)
            return None
        return int(value)

    async def serving_rate_limit(self, netuid: int) -> int:
        """Return the subnet's serving rate limit, in blocks."""
        await self._require_subnet(netuid)

        async def op() -> Any:
            client = await self._ensure_client()
            return await client.query(("SubtensorModule", "ServingRateLimit"), [netuid])

        return int(await self._call("serving_rate_limit", op) or 0)

    async def _require_subnet(self, netuid: int) -> None:
        async def op() -> Any:
            client = await self._ensure_client()
            return await client.query(("SubtensorModule", "NetworksAdded"), [netuid])

        if not await self._call("subnet_exists", op):
            raise SubnetNotFound(f"subnet {netuid} does not exist")

    # -- writes ----------------------------------------------------------------

    async def serve_axon(
        self,
        netuid: int,
        ip: str,
        port: int,
        *,
        tls_cert_hex: str | None,
        protocol_tag: int,
    ) -> TxOutcome:
        """Publish ``ip:port`` (``ServeAxon``, or ``ServeAxonTls`` with a certificate).

        ``protocol_tag`` is stored in the chain's u8 ``protocol`` field; values
        outside 0..255 return ``invalid_argument`` without submitting.
        """
        if not 0 <= protocol_tag <= _U8_MAX or not 0 < port <= 65535:
            return _rejected(
                "invalid_argument", "protocol_tag must be 0..255, port 1..65535"
            )
        intent: Any
        if tls_cert_hex is None:
            intent = bt.ServeAxon(
                netuid=netuid, ip=ip, port=port, protocol=protocol_tag
            )
        else:
            intent = bt.ServeAxonTls(
                netuid=netuid,
                ip=ip,
                port=port,
                certificate=tls_cert_hex,
                protocol=protocol_tag,
            )
        summary = {
            "op": "serve_axon_tls" if tls_cert_hex else "serve_axon",
            "netuid": netuid,
            "axon": f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}",
            "protocol": protocol_tag,
        }
        return await self._write(intent, summary)

    async def set_weights(
        self,
        netuid: int,
        weights: dict[int, float],
        *,
        mechid: int,
        version_key: int,
    ) -> TxOutcome:
        """Submit ``weights`` ({uid: weight}) with ``SetWeights``.

        The SDK normalises, quantises and picks plain or commit-reveal.
        Empty, negative or non-finite weights return ``invalid_argument``
        without submitting.
        """
        if not weights or any(
            not (math.isfinite(w) and w >= 0) for w in weights.values()
        ):
            return _rejected(
                "invalid_argument", "weights must be finite, >= 0, non-empty"
            )
        intent = bt.SetWeights(
            netuid=netuid,
            weights={int(u): float(w) for u, w in weights.items()},
            mechid=mechid,
            version_key=version_key,
        )
        summary = {
            "op": "set_weights",
            "netuid": netuid,
            "mechid": mechid,
            "n_weights": len(weights),
            "version_key": version_key,
        }
        return await self._write(intent, summary)

    async def _write(self, intent: Any, summary: dict[str, Any]) -> TxOutcome:
        if self._hotkey is None:
            raise RuntimeError("this gateway has no hotkey; writes need one")
        outcome = _rejected("unknown", _NOT_SUBMITTED)
        for attempt in range(1, self._write_attempts + 1):
            if attempt > 1:
                await self._wait_for_new_finalized()
            rejected, client = await self._plan(intent, summary, attempt)
            if rejected is not None:
                outcome = rejected
                if rejected.code == "unknown":
                    continue  # nothing was submitted: safe to try again
                break
            try:
                result = await asyncio.wait_for(
                    client.execute(
                        intent,
                        self._hotkey,
                        wait_for_inclusion=True,
                        wait_for_finalization=self._finalization,
                    ),
                    self._write_timeout_s,
                )
            except _sdk_error("PolicyError") as e:
                outcome = _policy_outcome(e)
                break
            except _TRANSIENT_READ_ERRORS as e:
                if isinstance(e, _CONNECTION_ERRORS):
                    await self._drop_client(rotate=True)
                outcome = _rejected("unknown", _UNKNOWN_FATE)
                _log.warning(
                    "chain write fate unknown",
                    extra={**summary, "attempt": attempt, "error": type(e).__name__},
                )
                break
            outcome = _outcome(result)
            error = getattr(result, "error", None)
            name = getattr(error, "name", None)
            resign = not outcome.ok and name in RESIGN_ERROR_NAMES
            _log.info(
                "chain write",
                extra={
                    **summary,
                    "attempt": attempt,
                    "ok": outcome.ok,
                    "code": outcome.code,
                    "error_name": name,
                    "block_hash": outcome.block_hash,
                },
            )
            if not resign:
                break
        return outcome

    async def _plan(
        self, intent: Any, summary: dict[str, Any], attempt: int
    ) -> tuple[TxOutcome | None, Any]:
        """Dry-run ``intent`` (``client.plan``); nothing is signed or submitted.

        Returns ``(rejection, None)`` when the write must not be submitted:
        a chain-side check failed (e.g. the SDK's weights rate-limit
        preflight, with its own code), the plan violates a policy, or the
        chain could not be reached (``code="unknown"``, nothing submitted).
        Otherwise ``(None, client)``.
        """
        try:
            client = await self._call("connect", self._ensure_client)
            plan = await asyncio.wait_for(
                client.plan(intent, self._hotkey), self._timeout_s
            )
        except ChainUnavailable as e:
            return _rejected("unknown", f"{_NOT_SUBMITTED} ({e})"), None
        except _sdk_error("PolicyError") as e:
            return _policy_outcome(e), None
        except _TRANSIENT_READ_ERRORS as e:
            code = getattr(getattr(e, "code", None), "value", None)
            if isinstance(e, _sdk_error("ChainError")) and code not in (
                None,
                "unknown",
            ):
                rejection = _rejected(str(code), str(e))
                _log.info(
                    "chain write",
                    extra={**summary, "attempt": attempt, "ok": False, "code": code},
                )
                return rejection, None
            if isinstance(e, (*_CONNECTION_ERRORS, TimeoutError, asyncio.TimeoutError)):
                await self._drop_client(rotate=True)
            _log.warning(
                "chain write plan failed",
                extra={**summary, "attempt": attempt, "error": type(e).__name__},
            )
            return _rejected("unknown", _NOT_SUBMITTED), None
        if not plan.ok:
            return _rejected("policy_violation", "; ".join(plan.violations)), None
        return None, client

    async def _wait_for_new_finalized(self) -> None:
        """Wait (bounded by the read timeout) until a new block is finalized.

        A new extrinsic signed right after that has the most of its mortal era
        left, because the SDK anchors the era at the finalized head.
        """

        async def op() -> None:
            client = await self._ensure_client()
            start = int(await client.finalized_block())
            step = float(await client.block_time()) / 4
            while int(await client.finalized_block()) <= start:
                await self._sleep(step)

        try:
            await asyncio.wait_for(op(), self._timeout_s)
        except _TRANSIENT_READ_ERRORS:
            _log.warning("no new finalized block before re-signing")


def metagraph_view(
    mg: Any, *, fetched_at_monotonic: float, allow_private_axons: bool
) -> MetagraphView:
    """Convert a ``bt.Metagraph`` into a kit-owned :class:`MetagraphView`.

    ``total_stake_tao`` (decision D2, ADR-0001) is ``alpha_stake x price +
    tao_stake``: the alpha valued at the pool's spot price, plus root TAO. It
    is approximate (spot, no slippage). With no price (empty pool, or a price
    that is not a finite positive number) the alpha part counts as 0, so stake
    thresholds fail closed. On the root subnet (netuid 0) alpha is TAO.
    """
    netuid = int(mg.netuid)
    price = _price(mg.price) if netuid != 0 else 1.0
    raw_axons = (mg.raw or {}).get("axons") if isinstance(mg.raw, dict) else None
    neurons = tuple(
        _neuron_view(n, price, raw_axons, allow_private_axons) for n in mg.neurons
    )
    return MetagraphView(
        netuid=netuid,
        block=int(mg.block),
        fetched_at_monotonic=fetched_at_monotonic,
        neurons=neurons,
        tempo=int(mg.tempo),
    )


def _price(value: Any) -> float:
    if value is None:
        return 0.0
    price = float(value)
    return price if math.isfinite(price) and price > 0 else 0.0


def _neuron_view(
    n: Any, price: float, raw_axons: Any, allow_private: bool
) -> NeuronView:
    alpha = float(n.alpha_stake.amount)
    tao = float(n.tao_stake.amount)
    return NeuronView(
        uid=int(n.uid),
        hotkey=str(n.hotkey),
        coldkey=str(n.coldkey),
        validator_permit=bool(n.validator_permit),
        active=bool(n.active),
        total_stake_tao=alpha * price + tao,
        alpha_stake=alpha,
        tao_stake=tao,
        axon=parse_axon(n.axon, allow_private=allow_private),
        last_update=int(n.last_update),
        incentive=float(n.incentive),
        dividends=float(n.dividends),
        axon_protocol=_axon_protocol(raw_axons, int(n.uid)) if n.axon else None,
    )


def _axon_protocol(raw_axons: Any, uid: int) -> int | None:
    """The ``protocol`` byte from ``Metagraph.raw["axons"][uid]``, or ``None``."""
    if not isinstance(raw_axons, Sequence) or not 0 <= uid < len(raw_axons):
        return None
    entry = raw_axons[uid]
    value = entry.get("protocol") if isinstance(entry, Mapping) else None
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _U8_MAX:
        return value
    return None


def _outcome(result: Any) -> TxOutcome:
    if result.success:
        return TxOutcome(
            ok=True, code=None, remediation=None, block_hash=result.block_hash
        )
    error = result.error
    code = getattr(getattr(error, "code", None), "value", None) or "unknown"
    remediation = getattr(error, "remediation", None)
    return TxOutcome(
        ok=False,
        code=str(code),
        remediation=None if remediation is None else str(remediation),
        block_hash=result.block_hash,
    )


def _missing_message(missing: list[str]) -> str:
    return (
        "the installed bittensor does not provide "
        + ", ".join(missing)
        + "; TensorWire supports bittensor>=11.3.0,<12 (see the compatibility matrix)"
    )


def _policy_outcome(error: BaseException) -> TxOutcome:
    violations = getattr(error, "violations", None) or [str(error)]
    return _rejected("policy_violation", "; ".join(violations))


def _rejected(code: str, remediation: str) -> TxOutcome:
    return TxOutcome(ok=False, code=code, remediation=remediation, block_hash=None)


async def _close_quietly(client: Any) -> None:
    try:
        await client.close()
    except Exception:  # noqa: BLE001 - closing a broken client must not mask the cause
        _log.debug("error while closing chain client", exc_info=True)
