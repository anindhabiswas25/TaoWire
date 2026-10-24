"""The legacy bridge against the captured v10 vectors (spec 8.11.1, 8.11.2).

Captured requests from a real bittensor 10.5.0 Dendrite are replayed through
:class:`LegacyServer` (with the clock set to the capture time), and the kit's
own encoder is checked to produce what that Dendrite produced. Answers are
checked against the captured v10 Axon answers.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
from pydantic import BaseModel

from legacy_v10_models import (
    ALICE,
    BOB,
    BY_ID,
    CHARLIE,
    SYNAPSES,
    VECTORS,
    Dummy,
    body_bytes,
    header,
    nonce_of,
    request_headers,
)
from taowire import crypto
from taowire.auth.nonce_store import MemoryNonceStore
from taowire.errors import LegacyAuthFailed
from taowire.extensions.legacy_v10 import wire
from taowire.extensions.legacy_v10.server import LegacyServer

CAPTURE_DAY = dt.date(2026, 10, 22)
ACCEPTED = ["V1", "V2", "V3", "V4", "V5"]
# Headers the HTTP client adds; not part of the v10 format.
TRANSPORT = {"host", "accept", "accept-encoding", "user-agent", "content-length"}


class Clock:
    def __init__(self, now_ns: int) -> None:
        self.now = now_ns

    def __call__(self) -> int:
        return self.now


def make_server(now_ns: int) -> tuple[LegacyServer, Clock]:
    clock = Clock(now_ns)
    server = LegacyServer(
        signer=crypto.HotkeySigner(crypto.keypair_from_uri("//Bob")),
        store=MemoryNonceStore(60.0),
        until=CAPTURE_DAY + dt.timedelta(days=30),
        external_ip="127.0.0.1",
        external_port=39333,
        now_ns=clock,
        today=lambda: CAPTURE_DAY,
    )
    return server, clock


def synapse_cls(vector: dict[str, Any]) -> type[BaseModel]:
    return SYNAPSES[vector["synapse"]]


def verify(server: LegacyServer, vector: dict[str, Any]) -> Any:
    return server.verify_sync(
        request_headers(vector),
        body_bytes(vector["request"]),
        synapse_cls=synapse_cls(vector),
        body_hash=None,
    )


@pytest.mark.parametrize("vid", ACCEPTED)
def test_accepted_vectors_verify(vid: str) -> None:
    vector = BY_ID[vid]
    server, _ = make_server(nonce_of(vector) + 1_000_000)
    accepted = verify(server, vector)
    assert accepted.caller.hotkey_ss58 == ALICE
    assert accepted.caller.nonce_ns == nonce_of(vector)
    assert accepted.caller.crypto_type == crypto.CRYPTO_SR25519
    synapse = accepted.synapse
    assert isinstance(synapse, synapse_cls(vector))
    body = json.loads(body_bytes(vector["request"]))
    for name, value in synapse.model_dump(exclude={"dendrite", "axon"}).items():
        assert value == body[name]
    # The handler sees the verified sender and this axon, not the body's claims.
    assert synapse.dendrite.hotkey == ALICE  # type: ignore[attr-defined]
    assert synapse.axon.hotkey == BOB  # type: ignore[attr-defined]


@pytest.mark.parametrize("vid", [*ACCEPTED, "N1", "N2", "N3", "N4", "N5"])
def test_kit_hash_matches_capture(vid: str) -> None:
    vector = BY_ID[vid]
    parsed = wire.decode_request_body(
        synapse_cls(vector), body_bytes(vector["request"])
    )
    assert wire.body_hash(parsed) == vector["request_expected"]["computed_body_hash"]


def test_n1_blacklisting_is_policy_not_authentication() -> None:
    # v10's blacklist_fn rejected //Charlie; the signature itself is valid, so
    # the bridge authenticates the caller and the caller policy decides.
    n1 = BY_ID["N1"]
    server, _ = make_server(nonce_of(n1) + 1_000_000)
    assert verify(server, n1).caller.hotkey_ss58 == CHARLIE


def test_n2_signed_for_another_axon_is_rejected() -> None:
    n2 = BY_ID["N2"]
    server, _ = make_server(nonce_of(n2) + 1_000_000)
    with pytest.raises(LegacyAuthFailed, match="signature"):
        verify(server, n2)


def test_n3_replay_of_v1_is_rejected() -> None:
    v1, n3 = BY_ID["V1"], BY_ID["N3"]
    assert body_bytes(n3["request"]) == body_bytes(v1["request"])
    server, _ = make_server(nonce_of(v1) + 1_000_000)
    verify(server, v1)
    with pytest.raises(LegacyAuthFailed):
        verify(server, n3)


def test_n3_replay_rejected_by_the_store_alone() -> None:
    # A second miner process (no per-uuid memory) sharing the replay store.
    v1 = BY_ID["V1"]
    first, _ = make_server(nonce_of(v1) + 1_000_000)
    verify(first, v1)
    second = LegacyServer(
        signer=crypto.HotkeySigner(crypto.keypair_from_uri("//Bob")),
        store=first._store,
        until=CAPTURE_DAY + dt.timedelta(days=30),
        external_ip="127.0.0.1",
        external_port=39333,
        now_ns=lambda: nonce_of(v1) + 1_000_000,
        today=lambda: CAPTURE_DAY,
    )
    with pytest.raises(LegacyAuthFailed, match="already seen"):
        verify(second, BY_ID["N3"])


def test_n4_tampered_hash_field_is_rejected() -> None:
    n4 = BY_ID["N4"]
    server, _ = make_server(nonce_of(n4) + 1_000_000)
    with pytest.raises(LegacyAuthFailed, match="hash"):
        verify(server, n4)


def test_n5_thirty_second_old_nonce_is_rejected() -> None:
    n5 = BY_ID["N5"]
    server, _ = make_server(nonce_of(n5) + 30_000_000_000)
    with pytest.raises(LegacyAuthFailed, match="too old"):
        verify(server, n5)


def test_n7_btauth_request_is_not_legacy() -> None:
    n7 = BY_ID["N7"]
    assert not LegacyServer.is_legacy(request_headers(n7))
    assert all(LegacyServer.is_legacy(request_headers(BY_ID[v])) for v in ACCEPTED)


def test_n7_answer_is_the_v10_marker() -> None:
    response = BY_ID["N7"]["response"]
    headers = [(str(k), str(v)) for k, v in response["headers"]]
    assert wire.is_v10_response(response["status"], headers)
    v1 = BY_ID["V1"]["response"]
    v1_headers = [(str(k), str(v)) for k, v in v1["headers"]]
    assert not wire.is_v10_response(v1["status"], v1_headers)


def test_n8_unhashed_field_change_is_accepted_documented_weakness() -> None:
    n8 = BY_ID["N8"]
    server, _ = make_server(nonce_of(n8) + 1_000_000)
    assert verify(server, n8).caller.hotkey_ss58 == ALICE


@pytest.mark.parametrize("vid", ACCEPTED)
def test_encode_request_reproduces_the_v10_dendrite(vid: str) -> None:
    vector = BY_ID[vid]
    captured = vector["request"]
    cls = synapse_cls(vector)
    captured_body = json.loads(body_bytes(captured))
    synapse = cls.model_validate(
        {k: v for k, v in captured_body.items() if k not in wire.ENVELOPE_FIELDS}
    )
    port = header(captured, "bt_header_axon_port")
    assert port is not None
    encoded = wire.encode_request(
        synapse,
        signer=crypto.HotkeySigner(crypto.keypair_from_uri("//Alice")),
        axon_hotkey=BOB,
        axon_ip="127.0.0.1",
        axon_port=int(port),
        nonce=nonce_of(vector),
        uuid=str(header(captured, "bt_header_dendrite_uuid")),
        timeout=12.0,
        dendrite_ip=VECTORS["keys"]["dendrite_external_ip_reported"],
    )
    assert encoded.path == captured["target"]
    assert encoded.computed_body_hash == header(captured, "computed_body_hash")
    ours = [(k.lower(), v) for k, v in encoded.headers]
    theirs = [
        (k.lower(), v) for k, v in captured["headers"] if k.lower() not in TRANSPORT
    ]
    assert [k for k, _ in ours] == [k for k, _ in theirs]
    differ = {"bt_header_dendrite_signature", "header_size", "total_size"}
    assert [p for p in ours if p[0] not in differ] == [
        p for p in theirs if p[0] not in differ
    ]
    # Same JSON text apart from the (randomised) signature and the size estimate.
    sig = dict(ours)["bt_header_dendrite_signature"]
    mine = json.loads(encoded.body)
    assert mine["dendrite"]["signature"] == sig
    for doc in (mine, captured_body):
        doc["dendrite"]["signature"] = "SIG"
        doc["total_size"] = 0
    assert json.dumps(mine) == json.dumps(captured_body)
    message = wire.request_message(
        encoded.nonce,
        ALICE,
        BOB,
        str(header(captured, "bt_header_dendrite_uuid")),
        encoded.computed_body_hash,
    )
    assert crypto.verify(
        message.encode(), crypto.signature_from_hex(sig), ALICE, crypto.CRYPTO_SR25519
    )


def test_our_encoded_request_verifies_on_our_server() -> None:
    nonce = 1_792_672_891_413_060_785
    encoded = wire.encode_request(
        Dummy(dummy_input=7),
        signer=crypto.HotkeySigner(crypto.keypair_from_uri("//Alice")),
        axon_hotkey=BOB,
        axon_ip="127.0.0.1",
        axon_port=39333,
        nonce=nonce,
        uuid="e85a70d0-ce15-11f1-a10f-847b57c7b217",
        timeout=12.0,
    )
    server, _ = make_server(nonce + 1)
    accepted = server.verify_sync(
        encoded.headers, encoded.body, synapse_cls=Dummy, body_hash=None
    )
    synapse = accepted.synapse
    assert isinstance(synapse, Dummy)
    sent = json.loads(encoded.body)
    assert synapse.dummy_input == sent["dummy_input"] == 7
    assert synapse.dendrite.nonce == nonce
    assert synapse.axon.hotkey == BOB


@pytest.mark.parametrize("vid", ACCEPTED)
def test_decode_captured_success(vid: str) -> None:
    vector = BY_ID[vid]
    response = vector["response"]
    decoded = wire.decode_response(
        synapse_cls(vector),
        response["status"],
        response["headers"],
        body_bytes(response),
    )
    assert decoded.status == 200
    assert decoded.synapse is not None
    assert decoded.synapse.model_dump(mode="json") == {
        **json.loads(body_bytes(response)),
        **({"required_hash_fields": ["b_field", "a_field"]} if vid == "V4" else {}),
    }
    assert decoded.status_message == "Success"


@pytest.mark.parametrize("vid", ["N1", "N2", "N3", "N4", "N5", "N6", "N7"])
def test_decode_captured_errors(vid: str) -> None:
    response = BY_ID[vid]["response"]
    decoded = wire.decode_response(
        Dummy, response["status"], response["headers"], body_bytes(response)
    )
    assert decoded.status == response["status"] != 200
    assert decoded.synapse is None
    assert decoded.status_message == json.loads(body_bytes(response))["message"]


def _names(headers: list[tuple[str, str]] | list[list[str]]) -> list[str]:
    skip = {"date", "server", "content-length", "content-type"}
    return [str(k).lower() for k, _ in headers if str(k).lower() not in skip]


def test_success_answer_has_the_captured_v10_shape() -> None:
    v1 = BY_ID["V1"]
    server, _ = make_server(nonce_of(v1) + 1_000_000)
    accepted = verify(server, v1)
    result = accepted.synapse.model_copy(update={"dummy_output": 14})
    body, headers = server.respond(
        request_headers(v1),
        status=200,
        synapse=result,
        error=None,
        process_time_s=0.001,
    )
    assert _names(headers) == _names(v1["response"]["headers"])
    ours, theirs = json.loads(body), json.loads(body_bytes(v1["response"]))
    assert list(ours) == list(theirs)
    assert ours["dummy_output"] == theirs["dummy_output"] == 14
    assert ours["dendrite"] == theirs["dendrite"]
    assert ours["axon"]["status_code"] == 200
    assert wire.decode_response(
        Dummy, 200, headers, body
    ).synapse == Dummy.model_validate(ours)


def test_signed_rejection_has_the_captured_v10_shape() -> None:
    from taowire.errors import Forbidden

    n1 = BY_ID["N1"]
    server, _ = make_server(nonce_of(n1) + 1_000_000)
    accepted = verify(server, n1)
    error = Forbidden(code="tw.forbidden_blacklisted")
    body, headers = server.respond(
        request_headers(n1),
        request=accepted,
        status=403,
        synapse=None,
        error=error,
        process_time_s=0.001,
    )
    captured = set(_names(n1["response"]["headers"]))
    # v10 echoes a dendrite port it learns from the socket; the kit has none.
    assert set(_names(headers)) == captured - {"bt_header_dendrite_port"}
    assert json.loads(body) == {"message": error.public_message}
    values = dict(headers)
    message = wire.response_message(
        int(values["bt_header_axon_nonce"]), CHARLIE, BOB, values["bt_header_axon_uuid"]
    )
    assert crypto.verify(
        message.encode(),
        crypto.signature_from_hex(values["bt_header_axon_signature"]),
        BOB,
        crypto.CRYPTO_SR25519,
    )
