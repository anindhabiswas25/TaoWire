"""The btauth/1 conformance vectors against spec 4 and the Python reference.

``payload.json``, ``ed25519.json``, ``sr25519_verify.json`` and
``negative.json`` (spec 11.7). Two independent checks, as for ``twresp.json``:

- every vector is re-derived here from the spec text (Section 4, Appendix C,
  Appendix D) with only ``hashlib``, a base58 decoder written here and
  ``tensorwire.crypto`` for the signature maths;
- the kit's ``RequestVerifier`` (the Python reference over
  ``bittensor.http_auth``) gives each vector's answer, or the
  ``python_reference`` answer where a vector declares a known divergence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from tensorwire import crypto
from tensorwire.auth.nonce_store import MemoryNonceStore
from tensorwire.auth.verifier import RequestVerifier
from tensorwire.errors import AuthFailed

DIR = Path(__file__).resolve().parents[3] / "conformance" / "vectors"


def load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((DIR / f"{name}.json").read_text("utf-8"))
    return data


PAYLOAD, ED25519, SR25519, NEGATIVE = (
    load(n) for n in ("payload", "ed25519", "sr25519_verify", "negative")
)
FILES = {"payload": PAYLOAD, "ed25519": ED25519, "sr25519_verify": SR25519}
FILES["negative"] = NEGATIVE
VERIFY = [*ED25519["vectors"], *SR25519["vectors"], *NEGATIVE["vectors"]]
KEYS: dict[str, dict[str, str]] = PAYLOAD["keys"]
SCHEME_TYPES = {"sr25519": crypto.CRYPTO_SR25519, "ed25519": crypto.CRYPTO_ED25519}
APPENDIX_C_ED25519 = (
    "0x1a6b631988bf1f7ea093ab9d5acf61f05c316d0b0e428b24b487b75a5f6ee0e1"
    "a56a26918fdf871b6cf09437e6588023a4ce423cf622621b2a7feee17612f704"
)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#: The canonical encodings of the eight ed25519 points of small order.
ED25519_TORSION = {
    bytes.fromhex(h)
    for h in (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    )
}


def b64(value: str) -> bytes:
    return base64.b64decode(value)


def spec_payload(
    scheme: str,
    method: str,
    target: str,
    body: bytes,
    nonce: str,
    sender: str,
    receiver: str | None,
) -> str:
    """Spec 4.2, written from the text."""
    lines = (
        "btauth/1",
        scheme,
        method.upper(),
        target,
        hashlib.sha256(body).hexdigest(),
        str(int(nonce)),
        sender,
        "-" if receiver is None else receiver,
    )
    return "\n".join(lines)


def ss58_decode(address: str) -> bytes:
    """Appendix D: base58 → 35 bytes, prefix 42, blake2b-512 checksum."""
    if not address or any(c not in B58 for c in address):
        raise ValueError("not base58")
    n = 0
    for c in address:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(address) - len(address.lstrip("1"))) + raw
    if len(raw) != 35 or raw[0] != 42:
        raise ValueError("not a prefix-42 address")
    check = hashlib.blake2b(b"SS58PRE" + raw[:33], digest_size=64).digest()[:2]
    if check != raw[33:]:
        raise ValueError("bad checksum")
    return raw[1:33]


def raw_only_verify(payload: bytes, signature: bytes, ss58: str, ctype: int) -> bool:
    """Verify over exactly ``payload``, never a ``<Bytes>`` form (spec 11.2 rule 8).

    The SDK's primitive accepts the payload or its wrapping, and
    ``crypto.verify(strict=True)`` rejects any signature that also fits the
    wrapping. A weak key's universal signature fits every message, wrapped or
    not, so that test would reject it where a raw-only verifier (Go, Rust)
    accepts it. Here: the signature fits the payload, and it is not a
    signature over the wrapping, which fits the wrapping but not an unrelated
    message.
    """
    if not crypto.verify(payload, signature, ss58, ctype, strict=False):
        return False
    wrapped = b"<Bytes>" + payload + b"</Bytes>"
    if not crypto.verify(wrapped, signature, ss58, ctype, strict=False):
        return True
    return crypto.verify(b"unrelated", signature, ss58, ctype, strict=False)


class Refused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


NONCE_RE = re.compile(r"[0-9]{1,20}")
SIG_RE = re.compile(r"(?:0x)?((?:[0-9a-fA-F]{2})*)")


def spec_verify(  # noqa: PLR0912 - the five steps of spec 4.3, in order
    i: dict[str, Any], r: dict[str, Any], seen: set[tuple[str, int]]
) -> str:
    """Spec 4.3 with the kit's stricter step 1, from the text. Returns the sender."""
    headers: dict[str, str] = {}
    for name, value in r["headers"]:
        key = name.lower()
        if key.startswith("x-bittensor-") and key in headers:
            raise Refused("tw.auth_malformed")
        headers[key] = value
    # 1. shape
    if headers.get("x-bittensor-version") != "1":
        raise Refused("tw.auth_malformed")
    sender = headers.get("x-bittensor-hotkey")
    nonce_text = headers.get("x-bittensor-nonce")
    signature_text = headers.get("x-bittensor-signature")
    scheme = headers.get("x-bittensor-crypto", "sr25519")
    if not sender or nonce_text is None or signature_text is None:
        raise Refused("tw.auth_malformed")
    if scheme not in SCHEME_TYPES or not NONCE_RE.fullmatch(nonce_text):
        raise Refused("tw.auth_malformed")
    sig_match = SIG_RE.fullmatch(signature_text)
    if sig_match is None:
        raise Refused("tw.auth_malformed")
    try:
        ss58_decode(sender)
    except ValueError:
        raise Refused("tw.auth_malformed") from None
    # 2. receiver
    if headers.get("x-bittensor-receiver") != i["self_hotkey"]:
        raise Refused("tw.auth_wrong_receiver")
    # 3. freshness
    nonce, now = int(nonce_text), int(i["now_ns"])
    if (
        now - nonce > i["max_age_s"] * 10**9
        or nonce - now > i["allowed_skew_s"] * 10**9
    ):
        raise Refused("tw.auth_stale")
    # 4. signature, declared scheme only, never a wrapped form
    signature = bytes.fromhex(sig_match.group(1))
    if len(signature) != 64:
        raise Refused("tw.auth_malformed")
    text = spec_payload(
        scheme,
        r["method"],
        r["target"],
        b64(r["body_base64"]),
        nonce_text,
        sender,
        headers["x-bittensor-receiver"],
    )
    if not raw_only_verify(text.encode(), signature, sender, SCHEME_TYPES[scheme]):
        raise Refused("tw.auth_bad_signature")
    key = ss58_decode(sender)
    weak = key == bytes(32) if scheme == "sr25519" else key in ED25519_TORSION
    if weak:  # the kit's weak-key rule: universal signatures are refused
        raise Refused("tw.auth_bad_signature")
    # 5. replay, only after the signature
    if (sender, nonce) in seen:
        raise Refused("tw.auth_replayed")
    seen.add((sender, nonce))
    return sender


def spec_answer(vector: dict[str, Any]) -> tuple[bool, str | None, str | None]:
    i = vector["inputs"]
    seen: set[tuple[str, int]] = set()
    if i["prior"] is not None:
        spec_verify(i, i["prior"], seen)
    try:
        return True, None, spec_verify(i, i, seen)
    except Refused as exc:
        return False, exc.code, None


def reference_answer(vector: dict[str, Any]) -> tuple[bool, str | None, str | None]:
    i = vector["inputs"]
    verifier = RequestVerifier(
        i["self_hotkey"],
        MemoryNonceStore(),
        max_age=i["max_age_s"],
        allowed_skew=i["allowed_skew_s"],
        now_ns=lambda: int(i["now_ns"]),
    )

    def one(r: dict[str, Any]) -> str:
        caller = verifier.verify_sync(
            [(n, v) for n, v in r["headers"]],
            b64(r["body_base64"]),
            method=r["method"],
            target=r["target"],
        )
        return caller.hotkey_ss58

    if i["prior"] is not None:
        one(i["prior"])
    try:
        return True, None, one(i)
    except AuthFailed as exc:
        return False, exc.code, None


def expected(vector: dict[str, Any]) -> tuple[bool, str | None, str | None]:
    e = vector["expected"]
    return e["valid"], e["code"], e["caller_ss58"]


# ------------------------------------------------------------------------ files


@pytest.mark.parametrize("name", sorted(FILES))
def test_file_metadata(name: str) -> None:
    data = FILES[name]
    assert data["schema_version"] == 1
    ids = [v["id"] for v in data["vectors"]]
    assert len(ids) == len(set(ids))
    assert data["keys"] == KEYS


@pytest.mark.parametrize("name", sorted(KEYS))
def test_pinned_dev_seeds_derive_the_uri_keys(name: str) -> None:
    key = KEYS[name]
    ctype = SCHEME_TYPES[key["scheme"]]
    by_uri = crypto.keypair_from_uri(key["uri"], crypto_type=ctype)
    by_seed = crypto.keypair_from_seed(
        bytes.fromhex(key["secret_seed_hex"]), crypto_type=ctype
    )
    assert by_seed.ss58_address == by_uri.ss58_address == key["ss58"]
    assert bytes(by_uri.public_key).hex() == key["public_key_hex"]
    assert ss58_decode(key["ss58"]).hex() == key["public_key_hex"]


def test_appendix_d_alice() -> None:
    assert (
        ss58_decode("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").hex()
        == "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
    )


# ---------------------------------------------------------------------- payload


def test_payload_covers_spec_11_7() -> None:
    ids = {v["id"] for v in PAYLOAD["vectors"]}
    assert {"P1", "P2", "P3", "P4", "P5a", "P5b", "P6", "P7", "P8", "P9"} <= ids


@pytest.mark.parametrize("vector", PAYLOAD["vectors"], ids=lambda v: v["id"])
def test_payload_vectors_follow_the_spec(vector: dict[str, Any]) -> None:
    i, e = vector["inputs"], vector["expected"]
    body = b64(i["body_base64"])
    assert hashlib.sha256(body).hexdigest() == e["body_sha256"]
    text = spec_payload(
        i["scheme"],
        i["method"],
        i["target"],
        body,
        i["nonce"],
        i["sender_ss58"],
        i["receiver_ss58"],
    )
    assert text == e["payload_utf8"]
    assert b64(e["payload_base64"]) == text.encode()
    assert len(text.split("\n")) == 8
    assert not text.endswith("\n")


def test_payload_golden_is_appendix_c() -> None:
    p1 = next(v for v in PAYLOAD["vectors"] if v["id"] == "P1")
    assert p1["expected"]["body_sha256"] == (
        "341c57448e531310fbbe83f44cea2a5e838bd9e8a6b82b269f01d0dbbc23c3cc"
    )
    assert p1["expected"]["payload_utf8"].split("\n")[5] == "1752076800000000000"


@pytest.mark.parametrize("vector", PAYLOAD["vectors"], ids=lambda v: v["id"])
def test_payload_vectors_match_the_sdk(vector: dict[str, Any]) -> None:
    i = vector["inputs"]
    built = crypto.btauth_payload(
        scheme=i["scheme"],
        method=i["method"],
        target=i["target"],
        body=b64(i["body_base64"]),
        nonce_ns=int(i["nonce"]),
        sender_ss58=i["sender_ss58"],
        receiver_ss58=i["receiver_ss58"],
    )
    assert built == b64(vector["expected"]["payload_base64"])


# ---------------------------------------------------------------------- ed25519


@pytest.mark.parametrize("vector", ED25519["vectors"], ids=lambda v: v["id"])
def test_ed25519_signatures_are_deterministic(vector: dict[str, Any]) -> None:
    i = vector["inputs"]
    key = KEYS[i["key"]]
    assert key["scheme"] == "ed25519"
    signer = crypto.keypair_from_seed(
        bytes.fromhex(key["secret_seed_hex"]), crypto_type=crypto.CRYPTO_ED25519
    )
    payload = i["signed_payload_utf8"].encode()
    assert (
        crypto.signature_to_hex(signer.sign(payload))
        == (vector["expected"]["signature"])
    )
    assert (
        dict(i["headers"])["X-Bittensor-Signature"] == (vector["expected"]["signature"])
    )


def test_ed25519_e1_is_appendix_c() -> None:
    e1 = next(v for v in ED25519["vectors"] if v["id"] == "E1")
    assert e1["expected"]["signature"] == APPENDIX_C_ED25519
    assert e1["expected"]["caller_ss58"] == (
        "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu"
    )


def test_sr25519_file_has_ten_requests_from_alice_and_bob() -> None:
    vectors = SR25519["vectors"]
    assert len(vectors) == 10
    senders = {v["expected"]["caller_ss58"] for v in vectors}
    assert senders == {KEYS["alice_sr25519"]["ss58"], KEYS["bob_sr25519"]["ss58"]}


@pytest.mark.parametrize(
    "vector", [*ED25519["vectors"], *SR25519["vectors"]], ids=lambda v: v["id"]
)
def test_signed_payload_is_rebuilt_from_the_request(vector: dict[str, Any]) -> None:
    i = vector["inputs"]
    h = {n.lower(): v for n, v in i["headers"]}
    text = spec_payload(
        h.get("x-bittensor-crypto", "sr25519"),
        i["method"],
        i["target"],
        b64(i["body_base64"]),
        h["x-bittensor-nonce"],
        h["x-bittensor-hotkey"],
        h["x-bittensor-receiver"],
    )
    assert text == i["signed_payload_utf8"]


# ----------------------------------------------------------------------- verify


def test_negative_covers_spec_11_7() -> None:
    """Every case listed in spec 11.7 has a vector with the right code."""
    by_id = {v["id"]: v["expected"]["code"] for v in NEGATIVE["vectors"]}
    required = {
        "N1": "tw.auth_malformed", "N2": "tw.auth_malformed",
        "N3": "tw.auth_malformed", "N4": "tw.auth_malformed",
        "N5": "tw.auth_wrong_receiver", "N6": "tw.auth_malformed",
        "N7": "tw.auth_malformed", "N8": "tw.auth_malformed",
        "N9": "tw.auth_malformed", "N10": "tw.auth_malformed",
        "N11": "tw.auth_wrong_receiver", "N12": "tw.auth_stale",
        "N13": "tw.auth_stale", "N14": "tw.auth_bad_signature",
        "N15": "tw.auth_bad_signature", "N16": "tw.auth_bad_signature",
        "N17": "tw.auth_bad_signature", "N18": "tw.auth_bad_signature",
        "N19": "tw.auth_bad_signature", "N20": "tw.auth_bad_signature",
        "N21": "tw.auth_replayed",
        # the stricter 4.3 shape rules
        "N23": "tw.auth_malformed", "N27": "tw.auth_malformed",
        "N29": "tw.auth_malformed", "N30": "tw.auth_malformed",
        "N34": "tw.auth_malformed",
        # weak keys and lax hex (kit rules, every language)
        "N45": "tw.auth_malformed", "N46": "tw.auth_malformed",
        "N63": "tw.auth_bad_signature", "N64": "tw.auth_bad_signature",
    }  # fmt: skip
    for vid, code in required.items():
        assert by_id[vid] == code, vid
    for v in NEGATIVE["vectors"]:
        assert v["expected"]["status"] == (None if v["expected"]["valid"] else 401)


@pytest.mark.parametrize("vector", VERIFY, ids=lambda v: v["id"])
def test_verify_vectors_follow_the_spec(vector: dict[str, Any]) -> None:
    assert spec_answer(vector) == expected(vector)


@pytest.mark.parametrize("vector", VERIFY, ids=lambda v: v["id"])
def test_python_reference_agrees(vector: dict[str, Any]) -> None:
    want = vector.get("python_reference") or vector["expected"]
    valid, code, _ = reference_answer(vector)
    assert (valid, code) == (want["valid"], want["code"])


def test_divergences_are_only_the_documented_ones() -> None:
    """The Python reference differs only on <Bytes> wrapping (spec 11.7)."""
    divergent = {v["id"] for v in VERIFY if "python_reference" in v}
    assert divergent == {"N19", "N20"}
    for v in VERIFY:
        if v["id"] in divergent:
            assert v["python_reference"]["note"]
            assert v["expected"]["valid"] is False


def test_signed_payload_of_negative_cases_is_the_spec_payload() -> None:
    """Where a case records the payload it signed, it is the spec 4.2 payload."""
    for v in NEGATIVE["vectors"]:
        text = v["inputs"].get("signed_payload_utf8")
        if text is not None:
            assert text.startswith("btauth/1\n")
            assert len(text.split("\n")) == 8


@pytest.mark.parametrize("key", sorted(ED25519_TORSION), ids=lambda k: k.hex()[:8])
def test_crypto_finds_every_small_order_ed25519_key(key: bytes) -> None:
    assert crypto.is_weak_public_key(key, crypto.CRYPTO_ED25519)


def test_real_keys_are_not_weak() -> None:
    for name, key in KEYS.items():
        ctype = SCHEME_TYPES[key["scheme"]]
        assert not crypto.is_weak_public_key(
            bytes.fromhex(key["public_key_hex"]), ctype
        ), name
    assert crypto.is_weak_public_key(bytes(32), crypto.CRYPTO_SR25519)
    assert not crypto.is_weak_public_key(b"\xff" * 32, crypto.CRYPTO_ED25519)
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.is_weak_public_key(b"\x01", crypto.CRYPTO_SR25519)
