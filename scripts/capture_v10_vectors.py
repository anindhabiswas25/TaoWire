#!/usr/bin/env python3
"""Capture v10 wire vectors from a real bittensor==10.5.0 Dendrite and Axon.

Runs a v10 Axon on loopback behind a recording TCP proxy, sends requests
with a real v10 Dendrite (plus a few hand-built requests for the failure
cases) and writes the exact bytes seen on the wire, with the values derived
from them, to ``conformance/vectors/legacy_v10.json`` (spec 10b.6, 11.7).

Run it ONLY with the legacy interpreter from ``scripts/legacy_venv.sh``:

    "$(scripts/legacy_venv.sh | tail -1)" -I scripts/capture_v10_vectors.py \\
        --out conformance/vectors/legacy_v10.json [--force]

The output is reviewed and committed once; it is never overwritten without
``--force``. Nothing leaves the machine: external-IP lookups are disabled,
the Axon listens on 127.0.0.1 only, and the keys are public dev keys
(``//Alice`` signs as the validator, ``//Bob`` is the miner).
"""

# No ``from __future__ import annotations``: the v10 Axon inspects the
# forward functions' annotations and needs real classes, not strings.
import argparse
import asyncio
import base64
import contextlib
import datetime
import hashlib
import http.client
import importlib.metadata
import json
import platform
import socket
import sys
import tempfile
import time
import typing
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

import pydantic

REQUIRED_VERSION = "10.5.0"
SCHEMA_VERSION = 1
DENDRITE_URI = "//Alice"
AXON_URI = "//Bob"
AXON_COLDKEY_URI = "//Bob//stash"
FOREIGN_URI = "//Charlie"
FOREIGN_SS58 = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"
BLACKLIST_SEEN: list[dict[str, Any]] = []
"""What blacklist_fn saw for each call: v10 runs it on a header-only Synapse."""


def _require_v10() -> None:
    version = importlib.metadata.version("bittensor")
    if version != REQUIRED_VERSION:
        raise SystemExit(
            f"bittensor {version} is installed; run this with the "
            f"bittensor=={REQUIRED_VERSION} "
            "venv from scripts/legacy_venv.sh"
        )


_require_v10()

import bittensor as bt  # noqa: E402  (imported after the version guard)
import bittensor.utils.networking as bt_networking  # noqa: E402
from bittensor.core.chain_data import AxonInfo  # noqa: E402
from bittensor.utils import get_hash  # noqa: E402

# The Dendrite looks up its public IP over the internet when it is created.
# Vectors must be captured offline, so the lookup is replaced.
FAKE_DENDRITE_IP = "198.51.100.20"
bt_networking.get_external_ip = lambda: FAKE_DENDRITE_IP


# -- Synapses under test ------------------------------------------------------


class Dummy(bt.Synapse):
    """The archived template's Synapse."""

    dummy_input: int
    dummy_output: int | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)


class TextOps(bt.Synapse):
    """Several field types; hash fields declared in a different order than the model."""

    text: str
    op: str
    count: int = 1
    ratio: float = 0.5
    tags: list[str] = pydantic.Field(default_factory=list)
    weights: dict[str, float] = pydantic.Field(default_factory=dict)
    flag: bool = False
    maybe: int | None = None
    result: str | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = (
        "op",
        "text",
        "count",
        "ratio",
        "tags",
        "weights",
        "flag",
        "maybe",
    )


class NoHash(bt.Synapse):
    """No hash fields: nothing in the body is covered by the signature."""

    payload: str
    answer: str | None = None


class LegacyFieldHash(bt.Synapse):
    """Deprecated style: required_hash_fields as a pydantic field (model order wins)."""

    a_field: int
    b_field: str
    out: str | None = None
    required_hash_fields: list[str] = pydantic.Field(  # type: ignore[assignment,misc]
        default=["b_field", "a_field"]
    )


SYNAPSES: tuple[type[bt.Synapse], ...] = (Dummy, TextOps, NoHash, LegacyFieldHash)


async def forward_dummy(synapse: Dummy) -> Dummy:
    synapse.dummy_output = synapse.dummy_input * 2
    return synapse


# v10 compares signatures exactly and expects typing.Tuple, not tuple.
async def blacklist_dummy(synapse: Dummy) -> typing.Tuple[bool, str]:  # noqa: UP006
    hotkey = synapse.dendrite.hotkey if synapse.dendrite else None
    BLACKLIST_SEEN.append(
        {"dendrite_hotkey": hotkey, "dummy_input": synapse.dummy_input}
    )
    if hotkey == FOREIGN_SS58:
        return True, "blacklisted hotkey"
    return False, "allowed"


async def forward_text(synapse: TextOps) -> TextOps:
    synapse.result = (
        synapse.text.upper() if synapse.op == "upper" else synapse.text[::-1]
    )
    return synapse


async def forward_nohash(synapse: NoHash) -> NoHash:
    synapse.answer = f"echo:{synapse.payload}"
    return synapse


async def forward_legacy(synapse: LegacyFieldHash) -> LegacyFieldHash:
    synapse.out = f"{synapse.b_field}{synapse.a_field}"
    return synapse


# -- Recording proxy ----------------------------------------------------------


@dataclass
class Connection:
    to_server: bytearray = field(default_factory=bytearray)
    to_client: bytearray = field(default_factory=bytearray)


class RecordingProxy:
    """A TCP proxy on 127.0.0.1 that keeps every byte in both directions."""

    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        self.connections: list[Connection] = []
        self.port = 0
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn = Connection()
        self.connections.append(conn)
        up_reader, up_writer = await asyncio.open_connection(
            "127.0.0.1", self.upstream_port
        )

        async def pipe(
            src: asyncio.StreamReader, dst: asyncio.StreamWriter, sink: bytearray
        ) -> None:
            try:
                while data := await src.read(65536):
                    sink.extend(data)
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    dst.close()

        await asyncio.gather(
            pipe(reader, up_writer, conn.to_server),
            pipe(up_reader, writer, conn.to_client),
        )

    def exchanges(self) -> list[list[tuple[dict[str, Any], dict[str, Any]]]]:
        """The (request, response) pairs seen on each connection, in order."""
        out = []
        for conn in self.connections:
            requests = _parse_http(bytes(conn.to_server), is_request=True)
            responses = _parse_http(bytes(conn.to_client), is_request=False)
            out.append(list(zip(requests, responses, strict=False)))
        return out

    def counts(self) -> list[int]:
        return [len(pairs) for pairs in self.exchanges()]

    def new_since(
        self, counts: list[int]
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """Pairs added since ``counts`` was taken, on old and new connections."""
        new = []
        for i, pairs in enumerate(self.exchanges()):
            new.extend(pairs[counts[i] if i < len(counts) else 0 :])
        return new


def _parse_http(data: bytes, *, is_request: bool) -> list[dict[str, Any]]:
    """Split an HTTP/1.1 byte stream into messages (sized or chunked bodies)."""
    messages = []
    while data:
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            break
        lines = head.decode("latin-1").split("\r\n")
        headers = [tuple(line.split(": ", 1)) for line in lines[1:]]
        lowered = {k.lower(): v for k, v in headers}
        if "content-length" in lowered:
            length = int(lowered["content-length"])
            body, data = rest[:length], rest[length:]
        elif lowered.get("transfer-encoding", "").lower() == "chunked":
            body, data = _dechunk(rest)
        else:
            body, data = b"", rest
        message: dict[str, Any] = {
            "start_line": lines[0],
            "headers": [list(h) for h in headers],
        }
        if is_request:
            method, target, _ = lines[0].split(" ", 2)
            message.update(method=method, target=target)
        else:
            message["status"] = int(lines[0].split(" ", 2)[1])
        message["body"] = body
        messages.append(message)
    return messages


def _dechunk(data: bytes) -> tuple[bytes, bytes]:
    body = bytearray()
    while True:
        size_line, _, data = data.partition(b"\r\n")
        size = int(size_line.split(b";")[0], 16)
        if size == 0:
            _, _, data = data.partition(b"\r\n")
            return bytes(body), data
        body.extend(data[:size])
        data = data[size + 2 :]


# -- Derived values -----------------------------------------------------------


def header(message: dict[str, Any], name: str) -> str | None:
    for key, value in message["headers"]:
        if key.lower() == name.lower():
            return str(value)
    return None


def _sha3(text: str) -> str:
    """The v10 SDK's own hash helper (sha3_256 hex of the UTF-8 text)."""
    return str(get_hash(text))  # type: ignore[no-untyped-call]


def hash_inputs(
    synapse_cls: type[bt.Synapse], body: dict[str, Any]
) -> list[dict[str, str]]:
    """The per-field inputs of computed_body_hash, as the v10 Synapse computes them."""
    instance = synapse_cls(**body)
    dumped = instance.model_dump()
    fields = _hash_field_order(synapse_cls, dumped)
    return [
        {"field": f, "str_value": str(dumped[f]), "sha3_256": _sha3(str(dumped[f]))}
        for f in fields
    ]


def _hash_field_order(
    synapse_cls: type[bt.Synapse], dumped: dict[str, Any]
) -> list[str]:
    model_field = synapse_cls.model_fields.get("required_hash_fields")
    if model_field is not None:
        declared = model_field.default or []
        return [f for f in dumped if f in declared]
    return list(synapse_cls.required_hash_fields)


def request_message(req: dict[str, Any], axon_hotkey: str) -> str:
    """The v10 request signing message, rebuilt from the captured headers."""
    return ".".join(
        [
            header(req, "bt_header_dendrite_nonce") or "",
            header(req, "bt_header_dendrite_hotkey") or "",
            axon_hotkey,
            header(req, "bt_header_dendrite_uuid") or "",
            header(req, "computed_body_hash") or "",
        ]
    )


def response_message(resp: dict[str, Any]) -> str | None:
    nonce = header(resp, "bt_header_axon_nonce")
    if nonce is None:
        return None
    return ".".join(
        [
            nonce,
            header(resp, "bt_header_dendrite_hotkey") or "",
            header(resp, "bt_header_axon_hotkey") or "",
            header(resp, "bt_header_axon_uuid") or "",
        ]
    )


def verifies(
    message: str | None, signature: str | None, ss58: str | None
) -> bool | None:
    if message is None or signature is None or ss58 is None:
        return None
    try:
        return bool(bt.Keypair(ss58_address=ss58).verify(message, signature))
    except Exception:  # noqa: BLE001 - any verify error means "not valid"
        return False


def encode_message(message: dict[str, Any]) -> dict[str, Any]:
    body: bytes = message.pop("body")
    out = dict(message)
    out["body_utf8"] = body.decode("utf-8", errors="strict") if body else ""
    out["body_base64"] = base64.b64encode(body).decode()
    out["body_sha256"] = hashlib.sha256(body).hexdigest()
    return out


# -- Capture ------------------------------------------------------------------


@dataclass
class Case:
    id: str
    description: str
    synapse: type[bt.Synapse] | None
    accepted: bool
    send: Callable[[], Any]
    notes: list[str] = field(default_factory=list)


class Capture:
    def __init__(self) -> None:
        self.dendrite_key = bt.Keypair.create_from_uri(DENDRITE_URI)
        self.axon_key = bt.Keypair.create_from_uri(AXON_URI)
        self.foreign_key = bt.Keypair.create_from_uri(FOREIGN_URI)
        self.tmp = tempfile.TemporaryDirectory()
        wallet = bt.Wallet(name="axon", hotkey="default", path=self.tmp.name)
        wallet.set_hotkey(self.axon_key, encrypt=False, overwrite=True)
        wallet.set_coldkeypub(
            bt.Keypair.create_from_uri(AXON_COLDKEY_URI), overwrite=True
        )
        self.axon_port = _free_port()
        self.axon = bt.Axon(
            wallet=wallet, port=self.axon_port, ip="127.0.0.1", external_ip="127.0.0.1"
        )
        self.axon.fast_config.host = "127.0.0.1"  # v10 binds 0.0.0.0; keep it local
        self.axon.attach(forward_fn=forward_dummy, blacklist_fn=blacklist_dummy)
        self.axon.attach(forward_fn=forward_text)
        self.axon.attach(forward_fn=forward_nohash)
        self.axon.attach(forward_fn=forward_legacy)
        self.dendrite = bt.Dendrite(wallet=self.dendrite_key)
        self.proxy = RecordingProxy(self.axon_port)
        self.records: list[dict[str, Any]] = []

    def target(self, hotkey: str | None = None) -> AxonInfo:
        return AxonInfo(
            version=0,
            ip="127.0.0.1",
            port=self.proxy.port,
            ip_type=4,
            hotkey=hotkey or self.axon_key.ss58_address,
            coldkey=self.axon_key.ss58_address,
        )

    async def run(self) -> list[dict[str, Any]]:
        self.axon.start()
        await _wait_listening(self.axon_port)
        _assert_loopback_only(self.axon_port)
        await self.proxy.start()
        try:
            for case in self.cases():
                before = self.proxy.counts()
                result = case.send()
                if asyncio.iscoroutine(result):
                    result = await result
                await asyncio.sleep(0.2)
                pairs = self.proxy.new_since(before)
                if len(pairs) != 1:
                    raise SystemExit(
                        f"{case.id}: expected one exchange, saw {len(pairs)}"
                    )
                self.records.append(self.record(case, *pairs[0]))
        finally:
            await self.dendrite.aclose_session()  # type: ignore[no-untyped-call]
            await self.proxy.stop()
            self.axon.stop()
            self.tmp.cleanup()
        return self.records

    def record(
        self, case: Case, req: dict[str, Any], resp: dict[str, Any]
    ) -> dict[str, Any]:
        body_text = req["body"].decode() if req["body"] else ""
        expected: dict[str, Any] = {}
        if case.synapse is not None and body_text and header(req, "computed_body_hash"):
            body = json.loads(body_text)
            inputs = hash_inputs(case.synapse, body)
            recomputed = _sha3("".join(i["sha3_256"] for i in inputs))
            message = request_message(req, self.axon_key.ss58_address)
            as_sent = request_message(req, header(req, "bt_header_axon_hotkey") or "")
            expected = {
                "hash_fields": [i["field"] for i in inputs],
                "hash_inputs": inputs,
                "computed_body_hash": recomputed,
                "computed_body_hash_matches_header": recomputed
                == header(req, "computed_body_hash"),
                "signed_message": message,
                "signature_verifies": verifies(
                    message,
                    header(req, "bt_header_dendrite_signature"),
                    header(req, "bt_header_dendrite_hotkey"),
                ),
                "signed_message_with_header_axon_hotkey": as_sent,
                "signature_verifies_with_header_axon_hotkey": verifies(
                    as_sent,
                    header(req, "bt_header_dendrite_signature"),
                    header(req, "bt_header_dendrite_hotkey"),
                ),
            }
        resp_message = response_message(resp)
        response_expected = {
            "status": resp["status"],
            "axon_status_code_header": header(resp, "bt_header_axon_status_code"),
            "axon_signed_message": resp_message,
            "axon_signature_verifies": verifies(
                resp_message,
                header(resp, "bt_header_axon_signature"),
                self.axon_key.ss58_address,
            ),
        }
        return {
            "id": case.id,
            "description": case.description,
            "synapse": case.synapse.__name__ if case.synapse else None,
            "accepted_by_v10_axon": case.accepted,
            "accepted_matches_status": (resp["status"] == 200) == case.accepted,
            "notes": case.notes,
            "request": encode_message(req),
            "request_expected": expected,
            "response": encode_message(resp),
            "response_expected": response_expected,
        }

    def cases(self) -> list[Case]:
        d = self.dendrite

        def call(synapse: bt.Synapse, hotkey: str | None = None) -> Any:
            return d.call(
                target_axon=self.target(hotkey), synapse=synapse, deserialize=False
            )

        return [
            Case(
                "V1",
                "template Dummy, accepted",
                Dummy,
                True,
                lambda: call(Dummy(dummy_input=7)),
            ),
            Case(
                "V2",
                "several field types, unicode text, hash fields in non-model order",
                TextOps,
                True,
                lambda: call(
                    TextOps(
                        text='héllo ☃ 你好 "quoted" \\ back',
                        op="upper",
                        count=3,
                        ratio=0.1,
                        tags=["a", "b c"],
                        weights={"x": 1.0, "y": 1e-07},
                        flag=True,
                    )
                ),
            ),
            Case(
                "V3",
                "empty required_hash_fields: body hash is sha3_256 of the empty string",
                NoHash,
                True,
                lambda: call(NoHash(payload="anything")),
                ["Fields outside required_hash_fields can be changed on the wire."],
            ),
            Case(
                "V4",
                "deprecated pydantic-field required_hash_fields: model order wins",
                LegacyFieldHash,
                True,
                lambda: call(LegacyFieldHash(a_field=5, b_field="bee")),
            ),
            Case(
                "V5",
                "Dummy with dummy_input=0 (falsy value still hashed)",
                Dummy,
                True,
                lambda: call(Dummy(dummy_input=0)),
            ),
            Case(
                "N1",
                "caller //Charlie is blacklisted by hotkey: 403",
                Dummy,
                False,
                lambda: self.from_foreign_dendrite(Dummy(dummy_input=7)),
                [
                    "blacklist_fn runs on a Synapse built from headers only: "
                    "body fields "
                    "hold placeholder values (see blacklist_observations)."
                ],
            ),
            Case(
                "N2",
                "signed for axon //Charlie: the axon verifies with its own hotkey",
                Dummy,
                False,
                lambda: call(Dummy(dummy_input=8), self.foreign_key.ss58_address),
            ),
            Case(
                "N3",
                "exact replay of V1's request bytes: nonce not newer than the last",
                Dummy,
                False,
                lambda: self.replay("V1"),
            ),
            Case(
                "N4",
                "fresh valid signature, hashed body field changed after signing",
                Dummy,
                False,
                lambda: self.replay_fresh(
                    Dummy(dummy_input=7), body=b'{"dummy_input": 8}'
                ),
            ),
            Case(
                "N5",
                "valid signature but nonce 30 s old (first request for this uuid)",
                Dummy,
                False,
                self.stale_request,
            ),
            Case(
                "N6",
                "unknown Synapse name in the path: 404",
                None,
                False,
                lambda: self.raw(
                    "POST", "/Unknown", b"{}", [("Content-Type", "application/json")]
                ),
            ),
            Case(
                "N7",
                "btauth/1-style request without v10 headers: how a v10 axon answers",
                Dummy,
                False,
                lambda: self.raw(
                    "POST",
                    "/Dummy",
                    b'{"dummy_input": 1}',
                    [
                        ("Content-Type", "application/json"),
                        ("X-Bittensor-Version", "1"),
                        ("X-Bittensor-Hotkey", self.dendrite_key.ss58_address),
                        ("X-Bittensor-Receiver", self.axon_key.ss58_address),
                        ("X-Bittensor-Nonce", str(time.time_ns())),
                        ("X-Bittensor-Signature", "0x" + "00" * 64),
                    ],
                ),
            ),
            Case(
                "N8",
                "NoHash body field changed on the wire after signing: still accepted",
                NoHash,
                True,
                lambda: self.replay_fresh(
                    NoHash(payload="original"), body=b'{"payload": "tampered"}'
                ),
                ["Shows that unhashed fields are not protected (spec 8.11.1)."],
            ),
        ]

    async def from_foreign_dendrite(self, synapse: bt.Synapse) -> None:
        foreign = bt.Dendrite(wallet=self.foreign_key)
        try:
            await foreign.call(
                target_axon=self.target(), synapse=synapse, deserialize=False
            )
        finally:
            await foreign.aclose_session()  # type: ignore[no-untyped-call]

    async def replay(self, case_id: str, body: bytes | None = None) -> None:
        original = next(r for r in self.records if r["id"] == case_id)["request"]
        headers = [
            (k, v) for k, v in original["headers"] if k.lower() != "content-length"
        ]
        new_body = base64.b64decode(original["body_base64"]) if body is None else body
        await asyncio.to_thread(
            self._send, original["method"], original["target"], new_body, headers
        )

    async def replay_fresh(self, synapse: bt.Synapse, body: bytes) -> None:
        prepared = self.dendrite.preprocess_synapse_for_request(
            self.target(), synapse, 12.0
        )
        headers = [(k, v) for k, v in prepared.to_headers().items()]
        headers.append(("Content-Type", "application/json"))
        await asyncio.to_thread(
            self._send, "POST", f"/{type(synapse).__name__}", body, headers
        )

    async def stale_request(self) -> None:
        # A new Dendrite has a new uuid, so the axon has no stored nonce for it.
        stale_dendrite = bt.Dendrite(wallet=self.dendrite_key)
        synapse = stale_dendrite.preprocess_synapse_for_request(
            self.target(), Dummy(dummy_input=9), 12.0
        )
        dendrite, axon = synapse.dendrite, synapse.axon
        assert dendrite is not None
        assert axon is not None
        dendrite.nonce = time.time_ns() - 30 * 10**9
        message = (
            f"{dendrite.nonce}.{dendrite.hotkey}.{axon.hotkey}."
            f"{dendrite.uuid}.{synapse.body_hash}"
        )
        dendrite.signature = f"0x{self.dendrite_key.sign(message).hex()}"
        headers = [(k, v) for k, v in synapse.to_headers().items()]
        headers.append(("Content-Type", "application/json"))
        body = json.dumps(synapse.model_dump()).encode()
        await asyncio.to_thread(self._send, "POST", "/Dummy", body, headers)
        await stale_dendrite.aclose_session()  # type: ignore[no-untyped-call]

    async def raw(
        self, method: str, target: str, body: bytes, headers: list[tuple[str, str]]
    ) -> None:
        await asyncio.to_thread(self._send, method, target, body, headers)

    def _send(
        self, method: str, target: str, body: bytes, headers: list[tuple[str, str]]
    ) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy.port, timeout=15)
        try:
            conn.putrequest(method, target, skip_accept_encoding=True)
            for key, value in headers:
                if key.lower() == "host":
                    continue
                conn.putheader(key, value)
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            conn.getresponse().read()
        finally:
            conn.close()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def _wait_listening(port: int, timeout_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            return
        await asyncio.sleep(0.1)
    raise SystemExit(f"v10 axon did not start on port {port}")


def _assert_loopback_only(port: int) -> None:
    """Fail if the axon is reachable on a non-loopback address."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(
            ("192.0.2.1", 9)
        )  # no packet is sent; picks the outbound interface
        own_ip = probe.getsockname()[0]
    finally:
        probe.close()
    if own_ip.startswith("127."):
        return
    with socket.socket() as s:
        s.settimeout(0.5)
        if s.connect_ex((own_ip, port)) == 0:
            raise SystemExit(f"v10 axon is listening on {own_ip}; refusing to continue")


def summarise_synapses() -> dict[str, Any]:
    out = {}
    for cls in SYNAPSES:
        fields = [
            name
            for name in cls.model_fields
            if name not in bt.Synapse.model_fields and name != "required_hash_fields"
        ]
        style = (
            "pydantic_field"
            if "required_hash_fields" in cls.model_fields
            else "classvar"
        )
        declared = (
            list(cls.model_fields["required_hash_fields"].default)
            if style == "pydantic_field"
            else list(cls.required_hash_fields)
        )
        out[cls.__name__] = {
            "fields": fields,
            "required_hash_fields_declared": declared,
            "required_hash_fields_style": style,
        }
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--force", action="store_true", help="overwrite an existing file"
    )
    args = parser.parse_args(argv)
    try:
        with open(args.out, encoding="utf-8"):
            exists = True
    except FileNotFoundError:
        exists = False
    if exists and not args.force:
        parser.error(
            f"{args.out} exists; captured vectors are never regenerated without --force"
        )

    capture = Capture()
    records = asyncio.run(capture.run())
    report = {
        "schema_version": SCHEMA_VERSION,
        "description": (
            "Wire captures from a real bittensor==10.5.0 Dendrite and Axon "
            "(spec 10b.6). Python only. Each vector holds the exact request and "
            "response bytes and the values derived from them."
        ),
        "captured_with": {
            "bittensor": importlib.metadata.version("bittensor"),
            "bittensor_wallet": importlib.metadata.version("bittensor-wallet"),
            "python": platform.python_version(),
            "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(
                timespec="seconds"
            ),
        },
        "keys": {
            "dendrite": {
                "uri": DENDRITE_URI,
                "ss58": capture.dendrite_key.ss58_address,
            },
            "axon": {"uri": AXON_URI, "ss58": capture.axon_key.ss58_address},
            "foreign_axon": {
                "uri": FOREIGN_URI,
                "ss58": capture.foreign_key.ss58_address,
            },
            "dendrite_external_ip_reported": FAKE_DENDRITE_IP,
        },
        "synapses": summarise_synapses(),
        "blacklist_observations": BLACKLIST_SEEN,
        "vectors": records,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")
    bad = [r["id"] for r in records if not r["accepted_matches_status"]]
    print(f"wrote {len(records)} vectors to {args.out}")
    for r in records:
        print(
            f"  {r['id']:3} status={r['response']['status']} "
            f"hash_ok={r['request_expected'].get('computed_body_hash_matches_header')} "
            f"sig_ok={r['request_expected'].get('signature_verifies')} "
            f"axon_sig_ok={r['response_expected']['axon_signature_verifies']}  "
            f"{r['description']}"
        )
    if bad:
        print(f"unexpected acceptance for {bad}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
