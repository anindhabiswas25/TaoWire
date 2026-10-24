"""v10-shaped ``Dendrite`` over the validator client (spec 10b.2.3).

::

    from taowire.compat import Dendrite, axons_from

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

Streaming (a ``StreamingSynapse``, or ``streaming=True``): one async
generator per axon, as v10's ``call_stream``. It yields what the Synapse's
``process_streaming_response`` yields (unverified bytes, see
``compat.stream``) and then the final item: the filled Synapse when the
stream's trailer verified, else a fresh copy of the request with the error
status. Built on :meth:`ValidatorClient.stream` (spec 9.2).
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeVar, overload

import structlog

from taowire.auth.signer import RequestSigner
from taowire.chain.gateway import MetagraphView, NeuronView
from taowire.compat.stream import Frame, StreamingSynapse, StreamResponse
from taowire.compat.synapse import Synapse, TerminalInfo
from taowire.extensions.streaming import MAX_S_RANGE
from taowire.validator.client import (
    MinerResult,
    MinerStream,
    ValidatorClient,
    failed_result,
)

__all__ = ["AxonInfo", "Dendrite", "axons_from", "status_code_for"]

_S = TypeVar("_S", bound=Synapse)
_log = structlog.stdlib.get_logger("taowire.compat")

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


class _Snapshots(Protocol):
    def snapshot(self) -> MetagraphView: ...


def axons_from(
    mg: MetagraphView | _Snapshots, uids: Iterable[int] | None = None
) -> list[AxonInfo]:
    """``[metagraph.axons[uid] for uid in uids]`` for a TaoWire metagraph.

    ``mg`` is a ``MetagraphView`` or anything with ``snapshot()`` (such as
    ``compat.Metagraph``). ``uids=None`` means every neuron, in UID order;
    UIDs may be numpy integers. An unknown UID raises ``KeyError``.
    """
    view = mg if isinstance(mg, MetagraphView) else mg.snapshot()
    by_uid = {n.uid: n for n in view.neurons}
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
        """v10's ``dendrite.forward`` (``run_async`` is ignored)."""
        del run_async
        if streaming != isinstance(synapse, StreamingSynapse):
            _log.warning(
                "dendrite_streaming_mismatch",
                streaming=streaming,
                synapse=type(synapse).__name__,
                hint="streaming follows whether the Synapse is a StreamingSynapse",
            )
        if isinstance(synapse, StreamingSynapse):
            return self._streams(axons, synapse, timeout, deserialize)
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

    def _streams(
        self,
        axons: AxonInfo | Sequence[AxonInfo],
        synapse: StreamingSynapse,
        timeout: float,
        deserialize: bool,
    ) -> Any:
        synapse.timeout = float(timeout)
        if isinstance(axons, AxonInfo):
            return self._stream(axons, synapse, timeout, deserialize)
        return [self._stream(a, synapse, timeout, deserialize) for a in axons]

    async def _stream(
        self,
        axon: AxonInfo,
        request: StreamingSynapse,
        timeout: float,
        deserialize: bool,
    ) -> AsyncIterator[Any]:
        """v10's ``call_stream``: the user's chunks, then the final item."""
        neuron = axon.neuron
        if neuron is None:
            final = self._item(axon, request, None)
            yield final.deserialize() if deserialize else final
            return
        item = request.model_copy(deep=True)
        # v10's timeout bounds the stream; it never loosens TW_STREAM_MAX_S.
        max_s = min(max(timeout, MAX_S_RANGE[0]), self.client.stream_limits.max_s)
        stream = self.client.stream(
            neuron,
            "/" + type(request).__name__,
            request.user_json(),
            chunk_model=Frame,
            timeout_s=timeout,
            max_s=max_s,
        )
        response = StreamResponse(
            _bytes(stream), name=type(request).__name__, timeout=timeout
        )
        user_failed = False
        async with stream:
            try:
                async for chunk in item.process_streaming_response(response):
                    yield chunk
            except Exception:  # noqa: BLE001 - as v10: a failure is the final status
                _log.exception("stream_processing_failed", uid=neuron.uid)
                user_failed = True
            # The miner's real outcome, also when the user code stopped early.
            result = stream.result or await stream.finish()
        if self._on_results is not None:
            self._on_results({result.uid: result})
        if result.ok and not user_failed:
            user_failed = not _merge_response_json(item, response)
        if result.ok and not user_failed:
            final = self._status(axon, item, result)
        else:
            if result.ok:  # the miner's stream verified; the validator's code failed
                result = failed_result(neuron, "tw.invalid_response", attempts=1)
            final = self._item(axon, request, result)  # none of the unverified values
        yield final.deserialize() if deserialize else final

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
            fields = type(item).model_fields
            for name, value in data.user_fields().items():
                if name in fields and fields[name].frozen:
                    continue  # a request field the miner cannot change (as in v10)
                setattr(item, name, value)
        return self._status(axon, item, result)

    def _status(self, axon: AxonInfo, item: _S, result: MinerResult) -> _S:
        """Fill the v10 status fields of ``item.dendrite`` and ``.axon``."""
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


async def _bytes(stream: MinerStream) -> AsyncIterator[bytes]:
    """The raw frames of a compat stream, as they arrive (unverified)."""
    async for chunk in stream:
        yield chunk.data.b


def _merge_response_json(item: StreamingSynapse, response: StreamResponse) -> bool:
    """v10's ``process_server_response`` after a 200: ``extract_response_json``'s
    fields onto ``item``. False when the user's method raised."""
    try:
        values = item.extract_response_json(response)
    except Exception:  # noqa: BLE001 - user code; the final item says it failed
        _log.exception("extract_response_json_failed")
        return False
    try:
        server = type(item)(**values)
    except Exception:  # noqa: BLE001 - v10 ignores a dict that does not build
        return True
    fields = type(item).model_fields
    for name in item.user_field_names():
        if name in fields and fields[name].frozen:
            continue  # a request field the miner cannot change (as in v10)
        with contextlib.suppress(Exception):
            setattr(item, name, getattr(server, name))
    return True
