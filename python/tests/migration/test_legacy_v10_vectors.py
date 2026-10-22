"""Re-derive the captured v10 wire vectors from the rules in spec 8.11.1.

``conformance/vectors/legacy_v10.json`` holds bytes captured from a real
bittensor==10.5.0 Dendrite and Axon. These tests rebuild every derived value
(body hash, signed messages, signatures) from those bytes using only the
documented rules and ``tensorwire.crypto`` (the v11 SDK), so the spec text,
the vectors and the kit's crypto are checked against each other.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tensorwire import crypto

VECTORS_PATH = (
    Path(__file__).resolve().parents[3] / "conformance" / "vectors" / "legacy_v10.json"
)
VECTORS: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
BY_ID: dict[str, dict[str, Any]] = {v["id"]: v for v in VECTORS["vectors"]}
AXON_SS58: str = VECTORS["keys"]["axon"]["ss58"]
SIGNED = [v for v in VECTORS["vectors"] if v["request_expected"]]


def sha3(text: str) -> str:
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()


def header(message: dict[str, Any], name: str) -> str | None:
    for key, value in message["headers"]:
        if key.lower() == name.lower():
            return str(value)
    return None


def body_bytes(message: dict[str, Any]) -> bytes:
    return base64.b64decode(message["body_base64"])


def hash_fields(vector: dict[str, Any], body: dict[str, Any]) -> list[str]:
    """8.11.1: ClassVar = declared order; deprecated field style = model order."""
    synapse = VECTORS["synapses"][vector["synapse"]]
    declared = synapse["required_hash_fields_declared"]
    if synapse["required_hash_fields_style"] == "pydantic_field":
        return [name for name in body if name in declared]
    return list(declared)


def computed_body_hash(vector: dict[str, Any]) -> str:
    """8.11.1: sha3_256 of the joined sha3_256 hex of str(value) per hash field."""
    body = json.loads(body_bytes(vector["request"]))
    return sha3("".join(sha3(str(body[f])) for f in hash_fields(vector, body)))


def signed_request_message(request: dict[str, Any], receiver: str) -> str:
    parts = ("nonce", "hotkey")
    nonce, sender = (header(request, f"bt_header_dendrite_{p}") for p in parts)
    uuid = header(request, "bt_header_dendrite_uuid")
    return f"{nonce}.{sender}.{receiver}.{uuid}.{header(request, 'computed_body_hash')}"


def verify(message: str, signature: str | None, ss58: str | None) -> bool:
    assert signature is not None
    assert ss58 is not None
    return crypto.verify(
        message.encode("utf-8"),
        crypto.signature_from_hex(signature),
        ss58,
        crypto.CRYPTO_SR25519,
    )


def test_capture_metadata() -> None:
    assert VECTORS["schema_version"] == 1
    assert VECTORS["captured_with"]["bittensor"] == "10.5.0"
    assert (
        VECTORS["keys"]["dendrite"]["ss58"]
        == crypto.keypair_from_uri("//Alice").ss58_address
    )
    assert crypto.keypair_from_uri("//Bob").ss58_address == AXON_SS58


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["id"])
def test_recorded_bodies_are_intact(vector: dict[str, Any]) -> None:
    for side in ("request", "response"):
        message = vector[side]
        raw = body_bytes(message)
        assert hashlib.sha256(raw).hexdigest() == message["body_sha256"]
        assert raw.decode("utf-8") == message["body_utf8"]


@pytest.mark.parametrize("vector", SIGNED, ids=lambda v: v["id"])
def test_body_hash_rule(vector: dict[str, Any]) -> None:
    recomputed = computed_body_hash(vector)
    assert recomputed == vector["request_expected"]["computed_body_hash"]
    matches = recomputed == header(vector["request"], "computed_body_hash")
    assert matches == vector["request_expected"]["computed_body_hash_matches_header"]


def test_empty_hash_fields_hash_the_empty_string() -> None:
    assert computed_body_hash(BY_ID["V3"]) == sha3("")


def test_deprecated_field_style_uses_model_order() -> None:
    v4 = BY_ID["V4"]
    assert VECTORS["synapses"]["LegacyFieldHash"]["required_hash_fields_declared"] == [
        "b_field",
        "a_field",
    ]
    assert v4["request_expected"]["hash_fields"] == ["a_field", "b_field"]


@pytest.mark.parametrize("vector", SIGNED, ids=lambda v: v["id"])
def test_request_signature_rule(vector: dict[str, Any]) -> None:
    request = vector["request"]
    expected = vector["request_expected"]
    message = signed_request_message(request, AXON_SS58)
    assert message == expected["signed_message"]
    sender = header(request, "bt_header_dendrite_hotkey")
    signature = header(request, "bt_header_dendrite_signature")
    assert verify(message, signature, sender) is expected["signature_verifies"]
    as_sent = signed_request_message(
        request, header(request, "bt_header_axon_hotkey") or ""
    )
    assert verify(as_sent, signature, sender) is True


def test_receiver_binding_uses_the_axons_own_hotkey() -> None:
    n2 = BY_ID["N2"]
    assert header(n2["request"], "bt_header_axon_hotkey") != AXON_SS58
    assert n2["request_expected"]["signature_verifies"] is False
    assert n2["response"]["status"] == 401


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["id"])
def test_axon_response_signature_rule(vector: dict[str, Any]) -> None:
    response = vector["response"]
    signature = header(response, "bt_header_axon_signature")
    if response["status"] == 200:
        # Successful v10 responses carry no axon nonce, uuid or signature.
        assert signature is None
        assert header(response, "bt_header_axon_nonce") is None
        return
    if signature is None:
        return
    message = ".".join(
        [
            header(response, "bt_header_axon_nonce") or "",
            header(response, "bt_header_dendrite_hotkey") or "",
            header(response, "bt_header_axon_hotkey") or "",
            header(response, "bt_header_axon_uuid") or "",
        ]
    )
    assert message == vector["response_expected"]["axon_signed_message"]
    assert verify(message, signature, AXON_SS58)


def test_request_wire_shape() -> None:
    request = BY_ID["V1"]["request"]
    assert request["start_line"] == "POST /Dummy HTTP/1.1"
    names = [k for k, _ in request["headers"]]
    v10_headers = [
        "name",
        "timeout",
        "bt_header_axon_ip",
        "bt_header_axon_port",
        "bt_header_axon_hotkey",
        "bt_header_dendrite_ip",
        "bt_header_dendrite_version",
        "bt_header_dendrite_nonce",
        "bt_header_dendrite_uuid",
        "bt_header_dendrite_hotkey",
        "bt_header_dendrite_signature",
        "bt_header_input_obj_dummy_input",
        "header_size",
        "total_size",
        "computed_body_hash",
    ]
    assert [n for n in names if n in v10_headers] == v10_headers
    # input_obj headers carry a default instance of the field type, not the value.
    assert (
        base64.b64decode(header(request, "bt_header_input_obj_dummy_input") or "")
        == b"0"
    )
    body = json.loads(body_bytes(request))
    assert body["computed_body_hash"] == ""
    assert body["dendrite"]["signature"] == header(
        request, "bt_header_dendrite_signature"
    )
    assert body["dummy_input"] == 7
    # The Dendrite uses json.dumps defaults: ", " and ": " separators, ASCII escapes.
    assert body_bytes(request).startswith(b'{"name": "Dummy", "timeout": 12.0, ')
    assert b"\\u00e9" in body_bytes(BY_ID["V2"]["request"])


def test_response_wire_shape() -> None:
    response = BY_ID["V1"]["response"]
    assert header(response, "bt_header_axon_status_code") == "200"
    assert header(response, "bt_header_axon_status_message") == "Success"
    body = json.loads(body_bytes(response))
    assert body["dummy_output"] == 14
    assert body_bytes(response).startswith(b'{"name":"Dummy","timeout":12.0,')


@pytest.mark.parametrize(
    ("vector_id", "status"),
    [
        ("N1", 403),
        ("N2", 401),
        ("N3", 401),
        ("N4", 500),
        ("N5", 401),
        ("N6", 404),
        ("N7", 500),
    ],
)
def test_rejections(vector_id: str, status: int) -> None:
    vector = BY_ID[vector_id]
    assert vector["response"]["status"] == status
    assert header(vector["response"], "bt_header_axon_status_code") == str(status)


def test_btauth_request_to_v10_axon_is_recognisable() -> None:
    """8.11.3: a v10 axon answers btauth/1 with a bt_header_axon_status_code header."""
    response = BY_ID["N7"]["response"]
    assert response["status"] == 500
    assert header(response, "bt_header_axon_status_code") == "500"
    assert json.loads(body_bytes(response))["message"].startswith(
        "Internal Server Error #"
    )


def test_unhashed_fields_are_not_protected() -> None:
    n8 = BY_ID["N8"]
    assert VECTORS["synapses"]["NoHash"]["required_hash_fields_declared"] == []
    assert n8["response"]["status"] == 200
    assert json.loads(body_bytes(n8["response"]))["answer"] == "echo:tampered"


def test_blacklist_sees_placeholder_body_fields() -> None:
    observations = VECTORS["blacklist_observations"]
    assert observations
    assert {o["dummy_input"] for o in observations} == {0}
