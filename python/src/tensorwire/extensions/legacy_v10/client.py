"""Client side of the legacy bridge: a TensorWire validator → v10 Axons (spec 8.11.3).

- :class:`LegacyClient` sends one v10-format request and parses the answer.
- :class:`ProtocolSelector` decides, per miner hotkey, which format to use:
  the on-chain ``axon_protocol`` first, then btauth/1 with one immediate v10
  attempt when the answer carries the v10 marker, re-probing once per tempo
  (:meth:`ProtocolSelector.reprobe`), and never downgrading a hotkey that has
  given a verified btauth/1 answer.

The validator client (``validator/client.py``) wires both together.
"""

from __future__ import annotations

import datetime as dt
import threading
import time
import uuid as uuid_mod
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

import httpx
from pydantic import BaseModel

from tensorwire import crypto
from tensorwire.chain.gateway import NeuronView
from tensorwire.extensions.legacy_v10 import wire

__all__ = ["LegacyClient", "LegacyResult", "ProtocolSelector", "WireProtocol"]

WireProtocol = Literal["btauth/1", "v10"]
Headers = Mapping[str, str] | Iterable[tuple[str, str]]

_MAX_HOTKEYS = 65_536


def _utc_today() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


@dataclass(frozen=True, slots=True)
class LegacyResult:
    """The outcome of one v10 request. Never authenticated."""

    status: int | None
    synapse: BaseModel | None
    """On 200: the body parsed into ``type(synapse)``, output fields filled."""
    error_code: str | None
    """``tw.timeout``, ``tw.connect_error``, ``tw.response_too_large``,
    ``tw.invalid_response``, ``tw.no_axon`` or ``tw.http_<status>``."""
    latency_ms: float | None
    status_message: str | None = None


class LegacyClient:
    """Sends v10 Dendrite requests signed by ``signer`` (an sr25519 hotkey).

    One uuid4 per instance (v10 Dendrites use uuid1, which embeds the host
    MAC; Axons never check the format) and strictly increasing nonces, so a
    v10 Axon's per-``(hotkey, uuid)`` rule accepts sequential requests.
    """

    def __init__(
        self,
        signer: wire.SignerLike,
        *,
        now_ns: Callable[[], int] | None = None,
        dendrite_ip: str | None = None,
    ) -> None:
        if signer.crypto_type != crypto.CRYPTO_SR25519:
            raise ValueError("v10 Axons verify sr25519 signatures only")
        self._signer = signer
        self._now_ns = time.time_ns if now_ns is None else now_ns
        self._dendrite_ip = dendrite_ip
        self._uuid = str(uuid_mod.uuid4())
        self._last_nonce = 0
        self._lock = threading.Lock()

    @property
    def uuid(self) -> str:
        """The ``bt_header_dendrite_uuid`` this client sends."""
        return self._uuid

    def _nonce(self) -> int:
        with self._lock:
            self._last_nonce = max(self._last_nonce + 1, self._now_ns())
            return self._last_nonce

    async def query(
        self,
        http: httpx.AsyncClient,
        neuron: NeuronView,
        synapse: BaseModel,
        *,
        timeout_s: float,
        max_response_bytes: int,
    ) -> LegacyResult:
        """One attempt, fresh nonce, ``POST http://{axon}/{SynapseName}``.

        Never raises for the miner's failure; every outcome is a
        :class:`LegacyResult`. ``http`` should have transport retries off and
        redirects off (the validator client's own client does).
        """
        if neuron.axon is None:
            return LegacyResult(None, None, "tw.no_axon", None)
        request = wire.encode_request(
            synapse,
            signer=self._signer,
            axon_hotkey=neuron.hotkey,
            axon_ip=neuron.axon.host,
            axon_port=neuron.axon.port,
            nonce=self._nonce(),
            uuid=self._uuid,
            timeout=timeout_s,
            dendrite_ip=self._dendrite_ip,
        )
        url = neuron.axon.base_url("http") + request.path
        started = time.perf_counter()

        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000

        try:
            async with http.stream(
                "POST",
                url,
                headers=request.headers,
                content=request.body,
                timeout=timeout_s,
            ) as response:
                chunks: list[bytes] = []
                received = 0
                async for chunk in response.aiter_bytes():
                    received += len(chunk)
                    if received > max_response_bytes:
                        return LegacyResult(
                            response.status_code,
                            None,
                            "tw.response_too_large",
                            elapsed(),
                        )
                    chunks.append(chunk)
                status = response.status_code
                headers = list(response.headers.items())
        except httpx.TimeoutException:
            return LegacyResult(None, None, "tw.timeout", elapsed())
        except httpx.HTTPError:
            return LegacyResult(None, None, "tw.connect_error", elapsed())
        try:
            decoded = wire.decode_response(
                type(synapse), status, headers, b"".join(chunks)
            )
        except wire.WireError:
            return LegacyResult(status, None, "tw.invalid_response", elapsed())
        code = None if status == 200 else f"tw.http_{status}"
        return LegacyResult(
            status, decoded.synapse, code, elapsed(), decoded.status_message
        )


class ProtocolSelector:
    """Per-hotkey wire-format choice for ``TW_LEGACY_V10_CLIENT=auto`` (spec 8.11.3).

    ``until`` is ``TW_LEGACY_V10_CLIENT_UNTIL``: from that day (UTC) on the
    selector always answers btauth/1. Memory is bounded (LRU).
    """

    def __init__(
        self,
        protocol_tag: int,
        *,
        until: dt.date,
        today: Callable[[], dt.date] | None = None,
        max_hotkeys: int = _MAX_HOTKEYS,
    ) -> None:
        if not 0 <= protocol_tag <= 255:
            raise ValueError("protocol_tag must be 0-255")
        self._tag = protocol_tag
        self._until = until
        self._today = _utc_today if today is None else today
        self._max = max_hotkeys
        self._memory: OrderedDict[str, WireProtocol] = OrderedDict()
        self._lock = threading.Lock()

    def enabled(self) -> bool:
        """Whether v10 may still be used today."""
        return self._today() < self._until

    def days_remaining(self) -> int:
        """Whole days left before the end date (0 once it is reached)."""
        return max(0, (self._until - self._today()).days)

    def known(self, hotkey: str) -> WireProtocol | None:
        """What the selector remembers for ``hotkey``."""
        with self._lock:
            return self._memory.get(hotkey)

    def choose(self, neuron: NeuronView) -> WireProtocol:
        """The format for the next request to ``neuron``."""
        if not self.enabled() or neuron.axon_protocol == self._tag:
            return "btauth/1"
        return "v10" if self.known(neuron.hotkey) == "v10" else "btauth/1"

    def after_btauth(
        self, neuron: NeuronView, *, status: int, headers: Headers, verified: bool
    ) -> bool:
        """Record a btauth/1 answer; True = send one v10 attempt now.

        ``verified`` (a valid twresp/1 signature, signed errors included)
        makes the hotkey btauth-only until it changes: no downgrade.
        Unverified answers prove nothing either way and change nothing.
        """
        if verified:
            self._set(neuron.hotkey, "btauth/1")
            return False
        if (
            not self.enabled()
            or neuron.axon_protocol == self._tag
            or self.known(neuron.hotkey) == "btauth/1"
            or not wire.is_v10_response(status, headers)
        ):
            return False
        self._set(neuron.hotkey, "v10")
        return True

    def reprobe(self) -> None:
        """Forget every v10 memory (call once per tempo); btauth/1 stays sticky."""
        with self._lock:
            for hotkey in [h for h, p in self._memory.items() if p == "v10"]:
                del self._memory[hotkey]

    def forget(self, hotkey: str) -> None:
        """Drop all memory of ``hotkey`` (it left the subnet or changed)."""
        with self._lock:
            self._memory.pop(hotkey, None)

    def _set(self, hotkey: str, protocol: WireProtocol) -> None:
        with self._lock:
            self._memory[hotkey] = protocol
            self._memory.move_to_end(hotkey)
            while len(self._memory) > self._max:
                self._memory.popitem(last=False)
