"""v10-shaped ``Dendrite`` over the validator client (spec 10b.2.3).

::

    from tensorwire.compat import Dendrite, axons_from

    dendrite = Dendrite(signer=RequestSigner(wallet))     # bt.dendrite(wallet=wallet)
    axons = axons_from(metagraph_view, uids=miner_uids)   # [metagraph.axons[uid] ...]
    responses = await dendrite(axons=axons, synapse=Dummy(dummy_input=step),
                               timeout=12, deserialize=True)

Same call and return shape as v10: one item per axon, in order (a single
item when one ``AxonInfo`` is passed), each the deserialized value or the
filled Synapse. Underneath is :meth:`ValidatorClient.query_many` with all its
rules (fresh signature per attempt, no transport retries, response cap,
``twresp/1`` checks, v10 fallback when configured).

Failures never raise. As in v10, the item comes back with
``dendrite.status_code`` set (408 timeout, 503 connect error or no axon,
401/403/... passed through, 500 for an answer that failed verification or
did not parse) and ``dendrite.status_message`` set to the ``tw.*`` code.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar, overload

from tensorwire.auth.signer import RequestSigner
from tensorwire.chain.gateway import MetagraphView, NeuronView
from tensorwire.compat.synapse import Synapse, TerminalInfo
from tensorwire.validator.client import MinerResult, ValidatorClient

__all__ = ["AxonInfo", "Dendrite", "axons_from", "status_code_for"]

_S = TypeVar("_S", bound=Synapse)

_STATUS_FOR_CODE = {
    "tw.timeout": 408,
    "tw.connect_error": 503,
    "tw.no_axon": 503,
}


@dataclass(frozen=True)
class AxonInfo:
    """v10's ``AxonInfo``: where a neuron serves, built from a ``NeuronView``."""

    ip: str
    port: int
    hotkey: str
    uid: int | None = None
    neuron: NeuronView | None = field(default=None, repr=False, compare=False)

    @property
    def is_serving(self) -> bool:
        """Whether the neuron published a usable axon."""
        return self.neuron is not None and self.neuron.axon is not None

    @classmethod
    def from_neuron(cls, neuron: NeuronView) -> AxonInfo:
        """The neuron's axon (``0.0.0.0:0`` when it serves nothing)."""
        axon = neuron.axon
        return cls(
            ip="0.0.0.0" if axon is None else axon.host,  # noqa: S104 - v10's "not serving"
            port=0 if axon is None else axon.port,
            hotkey=neuron.hotkey,
            uid=neuron.uid,
            neuron=neuron,
        )


def axons_from(mg: MetagraphView, uids: Iterable[int] | None = None) -> list[AxonInfo]:
    """``[metagraph.axons[uid] for uid in uids]`` for a TensorWire metagraph.

    ``uids=None`` means every neuron, in UID order. An unknown UID raises
    ``KeyError``.
    """
    by_uid = {n.uid: n for n in mg.neurons}
    chosen = sorted(by_uid) if uids is None else [int(u) for u in uids]
    return [AxonInfo.from_neuron(by_uid[uid]) for uid in chosen]


def status_code_for(result: MinerResult) -> int:
    """The v10 ``dendrite.status_code`` for one result."""
    if result.ok:
        return 200
    if result.error_code in _STATUS_FOR_CODE:
        return _STATUS_FOR_CODE[result.error_code]
    if result.status is not None and result.status != 200:
        return result.status
    return 500


class Dendrite:
    """The v10 ``dendrite`` API, backed by a :class:`ValidatorClient`."""

    def __init__(
        self,
        signer: RequestSigner | None = None,
        *,
        client: ValidatorClient | None = None,
        on_results: Callable[[dict[int, MinerResult]], None] | None = None,
        **client_options: Any,
    ) -> None:
        """Pass a ``signer`` (plus ``ValidatorClient`` options) or a ``client``.

        ``on_results`` is called with every query's raw ``{uid: MinerResult}``
        (``TemplateValidatorAdapter`` uses it for the round report).
        """
        if client is None:
            if signer is None:
                raise TypeError("Dendrite needs signer= or client=")
            client = ValidatorClient(signer, **client_options)
        elif signer is not None or client_options:
            raise TypeError("pass signer/options or client, not both")
        self.client = client
        self._on_results = on_results

    @property
    def hotkey(self) -> str:
        """The validator hotkey requests are signed as."""
        return self.client.signer.hotkey_ss58

    async def aclose(self) -> None:
        """Close the HTTP pool."""
        await self.client.aclose()

    async def __aenter__(self) -> Dendrite:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    @overload
    async def __call__(
        self,
        axons: AxonInfo,
        synapse: _S,
        timeout: float = ...,
        deserialize: bool = ...,
        **kwargs: Any,
    ) -> Any: ...

    @overload
    async def __call__(
        self,
        axons: Sequence[AxonInfo],
        synapse: _S,
        timeout: float = ...,
        deserialize: bool = ...,
        **kwargs: Any,
    ) -> list[Any]: ...

    async def __call__(
        self,
        axons: AxonInfo | Sequence[AxonInfo],
        synapse: _S,
        timeout: float = 12.0,
        deserialize: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Query every axon with ``synapse``; see the module docs for the shapes."""
        return await self.forward(axons, synapse, timeout, deserialize, **kwargs)

    async def forward(  # noqa: PLR0917 - v10's positional signature
        self,
        axons: AxonInfo | Sequence[AxonInfo],
        synapse: _S,
        timeout: float = 12.0,
        deserialize: bool = True,
        run_async: bool = True,
        streaming: bool = False,
    ) -> Any:
        """v10's ``dendrite.forward`` (``run_async`` is ignored; no streaming yet)."""
        del run_async
        if streaming:
            raise NotImplementedError("compat.StreamingSynapse arrives with streaming")
        single = isinstance(axons, AxonInfo)
        targets = [axons] if isinstance(axons, AxonInfo) else list(axons)
        synapse.timeout = float(timeout)
        body = synapse.user_json()
        neurons = [a.neuron for a in targets if a.neuron is not None]
        results = await self.client.query_many(
            neurons,
            "/" + type(synapse).__name__,
            body,
            response_model=type(synapse),
            legacy_synapse=synapse,
            timeout_s=timeout,
        )
        if self._on_results is not None:
            self._on_results(results)
        items = [
            self._item(
                axon,
                synapse,
                None if axon.neuron is None else results.get(axon.neuron.uid),
            )
            for axon in targets
        ]
        out = [s.deserialize() if deserialize else s for s in items]
        return out[0] if single else out

    def _item(self, axon: AxonInfo, request: _S, result: MinerResult | None) -> _S:
        item = request.model_copy(deep=True)
        if result is None:
            result = MinerResult(
                uid=axon.uid if axon.uid is not None else -1,
                hotkey=axon.hotkey,
                ok=False,
                status=None,
                latency_ms=None,
                data=None,
                error_code="tw.no_axon",
                attempts=0,
            )
        data = result.data
        if result.ok and isinstance(data, Synapse):
            for name, value in data.user_fields().items():
                setattr(item, name, value)
        code = status_code_for(result)
        message = "Success" if result.ok else result.status_message or result.error_code
        process_time = None if result.latency_ms is None else result.latency_ms / 1000
        item.dendrite = TerminalInfo(
            status_code=code,
            status_message=message,
            process_time=process_time,
            hotkey=self.hotkey,
        )
        item.axon = TerminalInfo(
            status_code=code,
            status_message=message,
            process_time=process_time,
            ip=axon.ip,
            port=axon.port,
            hotkey=axon.hotkey,
        )
        return item
