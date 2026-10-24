"""``conformance/vectors/twresp.json`` against spec 9.1 / 9.2 and ``response_sig``.

Two independent checks: the payloads, digests and signatures are re-derived
here from the spec text with only ``hashlib`` and ``taowire.crypto``; and
``taowire.extensions.response_sig`` (when present) must agree with every
vector, accept and reject alike.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from taowire import crypto

PATH = Path(__file__).resolve().parents[3] / "conformance" / "vectors" / "twresp.json"
DATA: dict[str, Any] = json.loads(PATH.read_text(encoding="utf-8"))
VECTORS: list[dict[str, Any]] = DATA["vectors"]
BUILDS = [v for v in VECTORS if v["kind"] in ("build_sr25519", "sign_ed25519")]
VERIFIES = [v for v in VECTORS if v["kind"] == "verify"]
STREAM = next(v for v in VECTORS if v["kind"] == "stream_ed25519")
SCHEME_TYPES = {"sr25519": crypto.CRYPTO_SR25519, "ed25519": crypto.CRYPTO_ED25519}


def payload(
    scheme: str, nonce: str, sender: str, responder: str, status: int, digest: str
) -> str:
    return "\n".join(
        ("twresp/1", scheme, nonce, sender, responder, str(status), digest)
    )


def b64(value: str) -> bytes:
    return base64.b64decode(value)


def test_ids_are_unique() -> None:
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids))
    assert DATA["schema_version"] == 1


@pytest.mark.parametrize("vector", BUILDS, ids=lambda v: v["id"])
def test_build_vectors_follow_the_spec(vector: dict[str, Any]) -> None:
    i, e = vector["inputs"], vector["expected"]
    digest = hashlib.sha256(b64(i["body_base64"])).hexdigest()
    assert digest == e["body_sha256"]
    text = payload(
        i["scheme"],
        i["request_nonce"],
        i["sender_ss58"],
        i["responder_ss58"],
        i["status"],
        digest,
    )
    assert text == e["payload_utf8"]
    assert not text.endswith("\n")
    headers = e["headers"]
    assert headers["X-TW-Resp-Version"] == "1"
    assert headers["X-TW-Resp-Hotkey"] == i["responder_ss58"]
    assert ("X-TW-Resp-Crypto" in headers) == (i["scheme"] == "ed25519")
    signature = crypto.signature_from_hex(headers["X-TW-Resp-Signature"])
    assert crypto.verify(
        text.encode(), signature, i["responder_ss58"], SCHEME_TYPES[i["scheme"]]
    )


@pytest.mark.parametrize(
    "vector", [v for v in BUILDS if v["kind"] == "sign_ed25519"], ids=lambda v: v["id"]
)
def test_ed25519_signatures_are_deterministic(vector: dict[str, Any]) -> None:
    i = vector["inputs"]
    uri = "//Bob" if i["responder_ss58"] == DATA["keys"]["bob_ed25519"] else "//Alice"
    key = crypto.keypair_from_uri(uri, crypto_type=crypto.CRYPTO_ED25519)
    assert key.ss58_address == i["responder_ss58"]
    signed = crypto.signature_to_hex(
        key.sign(vector["expected"]["payload_utf8"].encode())
    )
    assert signed == vector["expected"]["headers"]["X-TW-Resp-Signature"]


def test_stream_digest_vector() -> None:
    i, e = STREAM["inputs"], STREAM["expected"]
    chunks = [b64(c) for c in i["chunks_base64"]]
    assert len(chunks) == e["count"] == 3
    digest = hashlib.sha256(b"".join(chunks)).hexdigest()
    assert digest == e["digest"]
    text = payload(
        "ed25519",
        i["request_nonce"],
        i["sender_ss58"],
        i["responder_ss58"],
        200,
        digest,
    )
    assert text == e["payload_utf8"]
    key = crypto.keypair_from_uri("//Bob", crypto_type=crypto.CRYPTO_ED25519)
    assert crypto.signature_to_hex(key.sign(text.encode())) == e["signature"]


def reference_verify(i: dict[str, Any]) -> bool:
    """Spec 9.1 verification, written from the spec text (not from response_sig)."""
    pairs = i["headers"].items() if isinstance(i["headers"], dict) else i["headers"]
    seen: dict[str, str] = {}
    for name, value in pairs:
        key = name.lower()
        if key.startswith("x-tw-resp-"):
            if key in seen:
                return False
            seen[key] = value
    if seen.get("x-tw-resp-version") != "1":
        return False
    if seen.get("x-tw-resp-hotkey") != i["expected_responder"]:
        return False
    scheme = seen.get("x-tw-resp-crypto", "sr25519")
    if scheme not in SCHEME_TYPES:
        return False
    try:
        signature = crypto.signature_from_hex(seen.get("x-tw-resp-signature", ""))
        digest = hashlib.sha256(b64(i["body_base64"])).hexdigest()
        text = payload(
            scheme,
            i["request_nonce"],
            i["sender_ss58"],
            i["expected_responder"],
            i["status"],
            digest,
        )
        return crypto.verify(
            text.encode(), signature, i["expected_responder"], SCHEME_TYPES[scheme]
        )
    except ValueError:
        return False


@pytest.mark.parametrize("vector", VERIFIES, ids=lambda v: v["id"])
def test_verify_vectors_follow_the_spec(vector: dict[str, Any]) -> None:
    assert reference_verify(vector["inputs"]) is vector["expected"]["valid"]


# ---------------------------------------------------- agreement with response_sig


@pytest.fixture(scope="module")
def rs() -> Any:
    try:
        return importlib.import_module("taowire.extensions.response_sig")
    except ImportError:
        pytest.skip("taowire.extensions.response_sig is not in this build")


@pytest.mark.parametrize("vector", BUILDS, ids=lambda v: v["id"])
def test_response_sig_builds_the_same(vector: dict[str, Any], rs: Any) -> None:
    i, e = vector["inputs"], vector["expected"]
    built = rs.response_payload(
        scheme=i["scheme"],
        request_nonce=int(i["request_nonce"]),
        sender_ss58=i["sender_ss58"],
        responder_ss58=i["responder_ss58"],
        status=i["status"],
        digest=rs.body_digest(b64(i["body_base64"])),
    )
    assert built.decode() == e["payload_utf8"]


@pytest.mark.parametrize("vector", VERIFIES, ids=lambda v: v["id"])
def test_response_sig_verifies_the_same(vector: dict[str, Any], rs: Any) -> None:
    i = vector["inputs"]
    headers = (
        i["headers"]
        if isinstance(i["headers"], dict)
        else [tuple(p) for p in i["headers"]]
    )
    call = {
        "expected_responder": i["expected_responder"],
        "request_nonce": int(i["request_nonce"]),
        "sender_ss58": i["sender_ss58"],
        "status": i["status"],
        "body": b64(i["body_base64"]),
    }
    if vector["expected"]["valid"]:
        rs.verify_response(headers, **call)
        return
    with pytest.raises(rs.ResponseSignatureError) as caught:
        rs.verify_response(headers, **call)
    assert caught.value.code == vector["expected"]["error_code"]
