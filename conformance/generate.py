#!/usr/bin/env python3
"""Generate conformance vectors from the Python reference (spec 11.7).

    cd python && uv run python ../conformance/generate.py twresp [--force]

Each file is generated once, reviewed and committed; an existing file is
never overwritten without ``--force``. Only public dev keys are used.

Files:

- ``payload.json`` (spec 4.2, 11.7): btauth/1 payload builds P1-P9.
- ``ed25519.json``: deterministic ed25519 request signatures (Appendix C plus
  five more with ``//Alice`` / ``//Bob``), with the full header set.
- ``sr25519_verify.json``: ten requests pre-signed with sr25519 ``//Alice`` and
  ``//Bob`` that every verifier must accept.
- ``negative.json``: verify cases with the expected ``tw.*`` code (spec 4.3
  order, the kit's stricter shape rules, and a few accept controls). Where the
  Python reference is knowingly laxer than the normative answer, the vector
  says so in ``python_reference``.
- ``twresp.json`` (spec 9.1, 9.2): ``twresp/1`` payload builds, deterministic
  ed25519 signatures, a 3-chunk streaming digest, and verify cases (accept
  and reject) every implementation must agree on. sr25519 signatures are
  randomized: those vectors carry one pre-made signature that must verify.

Every btauth/1 vector is run through the Python reference
(``tensorwire.auth.verifier.RequestVerifier`` over ``bittensor.http_auth``)
while it is generated; a disagreement aborts the generation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tensorwire import crypto
from tensorwire.auth.nonce_store import MemoryNonceStore
from tensorwire.auth.verifier import RequestVerifier
from tensorwire.errors import AuthFailed
from tensorwire.extensions import response_sig as rs

VECTORS_DIR = Path(__file__).resolve().parent / "vectors"
SCHEMA_VERSION = 1

ALICE = crypto.keypair_from_uri("//Alice")
BOB = crypto.keypair_from_uri("//Bob")
BOB_ED = crypto.keypair_from_uri("//Bob", crypto_type=crypto.CRYPTO_ED25519)
ALICE_ED = crypto.keypair_from_uri("//Alice", crypto_type=crypto.CRYPTO_ED25519)
NONCE = 1_752_076_800_000_000_000  # Appendix C


def _signer(keypair: crypto.Keypair) -> crypto.HotkeySigner:
    return crypto.HotkeySigner(keypair)


def _build(
    vid: str,
    description: str,
    *,
    responder: crypto.Keypair,
    status: int,
    body: bytes,
    nonce: int = NONCE,
    sender: str = ALICE.ss58_address,
) -> dict[str, Any]:
    signer = _signer(responder)
    digest = rs.body_digest(body)
    payload = rs.response_payload(
        scheme=signer.scheme,
        request_nonce=nonce,
        sender_ss58=sender,
        responder_ss58=signer.ss58_address,
        status=status,
        digest=digest,
    )
    headers = rs.sign_response(
        signer, request_nonce=nonce, sender_ss58=sender, status=status, body=body
    )
    vector: dict[str, Any] = {
        "id": vid,
        "description": description,
        "kind": "sign_ed25519" if signer.scheme == "ed25519" else "build_sr25519",
        "inputs": {
            "scheme": signer.scheme,
            "request_nonce": str(nonce),
            "sender_ss58": sender,
            "responder_ss58": signer.ss58_address,
            "status": status,
            "body_base64": _b64(body),
        },
        "expected": {
            "body_sha256": digest,
            "payload_utf8": payload.decode(),
            "headers": headers,
        },
    }
    if signer.scheme == "sr25519":
        vector["notes"] = [
            "sr25519 signatures are randomized: implementations must verify this "
            "signature and produce their own that the Python verifier accepts."
        ]
    return vector


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _stream_vector() -> dict[str, Any]:
    chunks = [b'{"token":"Hel"}', b'{"token":"lo \\u2603"}', b'{"token":"!"}']
    digest = hashlib.sha256(b"".join(chunks)).hexdigest()
    signer = _signer(BOB_ED)
    payload = rs.response_payload(
        scheme="ed25519",
        request_nonce=NONCE,
        sender_ss58=ALICE.ss58_address,
        responder_ss58=signer.ss58_address,
        status=200,
        digest=digest,
    )
    return {
        "id": "S1",
        "description": "streaming (spec 9.2): digest over 3 chunks' data bytes, "
        "tw-end signature with status 200 and the stream digest",
        "kind": "stream_ed25519",
        "inputs": {
            "scheme": "ed25519",
            "request_nonce": str(NONCE),
            "sender_ss58": ALICE.ss58_address,
            "responder_ss58": signer.ss58_address,
            "chunks_base64": [_b64(c) for c in chunks],
        },
        "expected": {
            "digest": digest,
            "count": len(chunks),
            "payload_utf8": payload.decode(),
            "signature": crypto.signature_to_hex(signer.sign(payload)),
        },
    }


def _verify_cases() -> list[dict[str, Any]]:
    """Verify-side cases: a valid ed25519 response, then one change each."""
    body = b'{"result":"HELLO"}'
    signer = _signer(BOB_ED)
    good = rs.sign_response(
        signer,
        request_nonce=NONCE,
        sender_ss58=ALICE.ss58_address,
        status=200,
        body=body,
    )
    context = {
        "expected_responder": signer.ss58_address,
        "request_nonce": str(NONCE),
        "sender_ss58": ALICE.ss58_address,
        "status": 200,
        "body_base64": _b64(body),
    }
    payload = rs.response_payload(
        scheme="ed25519",
        request_nonce=NONCE,
        sender_ss58=ALICE.ss58_address,
        responder_ss58=signer.ss58_address,
        status=200,
        digest=rs.body_digest(body),
    )
    wrapped = crypto.signature_to_hex(BOB_ED.sign(b"<Bytes>" + payload + b"</Bytes>"))
    sr_signer = _signer(BOB)
    sr_headers = rs.sign_response(
        sr_signer,
        request_nonce=NONCE,
        sender_ss58=ALICE.ss58_address,
        status=200,
        body=body,
    )

    def case(
        vid: str,
        description: str,
        *,
        headers: dict[str, str] | list[list[str]],
        valid: bool,
        **overrides: Any,
    ) -> dict[str, Any]:
        inputs = {**context, **overrides, "headers": headers}
        return {
            "id": vid,
            "description": description,
            "kind": "verify",
            "inputs": inputs,
            "expected": {
                "valid": valid,
                "error_code": None if valid else rs.ResponseSignatureError.code,
            },
        }

    without_crypto = {k: v for k, v in good.items() if k != rs.HEADER_CRYPTO}
    return [
        case("V1", "valid ed25519 response", headers=good, valid=True),
        case(
            "V2",
            "valid sr25519 response (no X-TW-Resp-Crypto header)",
            headers=sr_headers,
            valid=True,
            expected_responder=BOB.ss58_address,
        ),
        case(
            "X1",
            "body changed by one byte",
            headers=good,
            valid=False,
            body_base64=_b64(b'{"result":"HELLo"}'),
        ),
        case("X2", "other status", headers=good, valid=False, status=500),
        case(
            "X3",
            "other request nonce",
            headers=good,
            valid=False,
            request_nonce=str(NONCE + 1),
        ),
        case(
            "X4",
            "other sender (another validator's answer)",
            headers=good,
            valid=False,
            sender_ss58=BOB.ss58_address,
        ),
        case(
            "X5",
            "signed by another hotkey than the one queried",
            headers=good,
            valid=False,
            expected_responder=ALICE_ED.ss58_address,
        ),
        case("X6", "version 2", headers={**good, rs.HEADER_VERSION: "2"}, valid=False),
        case(
            "X7",
            "ed25519 signature without X-TW-Resp-Crypto: must fail as "
            "sr25519, never fall back",
            headers=without_crypto,
            valid=False,
        ),
        case(
            "X8",
            "sr25519 signature declared as ed25519",
            headers={**sr_headers, rs.HEADER_CRYPTO: "ed25519"},
            valid=False,
            expected_responder=BOB.ss58_address,
        ),
        case(
            "X9",
            "<Bytes>-wrapped signature (strict: rejected)",
            headers={**good, rs.HEADER_SIGNATURE: wrapped},
            valid=False,
        ),
        case(
            "X10",
            "unknown scheme",
            headers={**good, rs.HEADER_CRYPTO: "ecdsa"},
            valid=False,
        ),
        case(
            "X11",
            "signature not hex",
            headers={**good, rs.HEADER_SIGNATURE: "0x" + "zz" * 64},
            valid=False,
        ),
        case(
            "X12",
            "duplicate X-TW-Resp-Signature header",
            headers=[[k, v] for k, v in good.items()]
            + [[rs.HEADER_SIGNATURE, good[rs.HEADER_SIGNATURE]]],
            valid=False,
        ),
        case("X13", "response not signed", headers={}, valid=False),
    ]


def twresp() -> dict[str, Any]:
    """``twresp.json``."""
    vectors = [
        _build(
            "B1",
            "200 JSON body, sr25519 responder (Appendix C nonce and keys)",
            responder=BOB,
            status=200,
            body=b'{"result":"HELLO"}',
        ),
        _build(
            "B2",
            "403 kit error body after authentication, sr25519",
            responder=BOB,
            status=403,
            body=b'{"error":{"code":"tw.forbidden_not_validator",'
            b'"message":"caller has no validator permit","request_id":null}}',
        ),
        _build("B3", "empty body", responder=BOB, status=204, body=b""),
        _build(
            "B4",
            "nonce at the u64 maximum (string handling)",
            responder=BOB,
            status=200,
            body=b"{}",
            nonce=18_446_744_073_709_551_615,
        ),
        _build(
            "E1",
            "ed25519 responder: deterministic signature",
            responder=BOB_ED,
            status=200,
            body=b'{"result":"HELLO"}',
        ),
        _build(
            "E2",
            "ed25519, unicode body (UTF-8 bytes hashed)",
            responder=BOB_ED,
            status=200,
            body='{"result":"héllo ☃ 你好"}'.encode(),
        ),
        _build(
            "E3",
            "ed25519, 504 handler timeout body",
            responder=BOB_ED,
            status=504,
            body=b'{"error":{"code":"tw.handler_timeout",'
            b'"message":"handler timed out","request_id":"01J"}}',
        ),
        _build(
            "E4",
            "ed25519, raw bytes body",
            responder=BOB_ED,
            status=200,
            body=bytes(range(256)),
        ),
        _build(
            "E5",
            "ed25519, sender //Bob, responder //Alice",
            responder=ALICE_ED,
            status=200,
            body=b"ok",
            sender=BOB.ss58_address,
        ),
        _stream_vector(),
        *_verify_cases(),
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "description": "twresp/1 response signing (spec 9.1) and the streaming "
        "trailer digest (9.2). Generated by conformance/generate.py from "
        "tensorwire.extensions.response_sig.",
        "keys": {
            "alice_sr25519": ALICE.ss58_address,
            "bob_sr25519": BOB.ss58_address,
            "alice_ed25519": ALICE_ED.ss58_address,
            "bob_ed25519": BOB_ED.ss58_address,
            "uris": "//Alice and //Bob; ed25519 = the same URI with ed25519 derivation",
        },
        "vectors": vectors,
    }


# ------------------------------------------------------------------ btauth/1

#: Public dev seeds (32-byte sr25519 mini-secrets / ed25519 seeds) of
#: ``//Alice`` and ``//Bob``, so languages without substrate URI derivation
#: can sign. ``_keys()`` proves each one against the SDK's URI derivation.
DEV_SEEDS = {
    "alice_sr25519": ("//Alice", crypto.CRYPTO_SR25519,
                      "e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"),
    "bob_sr25519": ("//Bob", crypto.CRYPTO_SR25519,
                    "398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89"),
    "alice_ed25519": ("//Alice", crypto.CRYPTO_ED25519,
                      "abf8e5bdbe30c65656c0a3cbd181ff8a56294a69dfedd27982aace4a76909115"),
    "bob_ed25519": ("//Bob", crypto.CRYPTO_ED25519,
                    "3b7b60af2abcd57ba401ab398f84f4ca54bd6b2140d2503fbcf3286535fe3ff1"),
}  # fmt: skip
GOLDEN_BODY = b'{"prompt": "hello"}'
GOLDEN_TARGET = "/generate?stream=false"
GOLDEN_ED25519_SIG = (
    "0x1a6b631988bf1f7ea093ab9d5acf61f05c316d0b0e428b24b487b75a5f6ee0e1"
    "a56a26918fdf871b6cf09437e6588023a4ce423cf622621b2a7feee17612f704"
)  # Appendix C
MAX_AGE_S = 10
SKEW_S = 2
S_NS = 1_000_000_000
H_VERSION, H_HOTKEY, H_RECEIVER = (
    "X-Bittensor-Version",
    "X-Bittensor-Hotkey",
    "X-Bittensor-Receiver",
)
H_NONCE, H_CRYPTO, H_SIG = (
    "X-Bittensor-Nonce",
    "X-Bittensor-Crypto",
    "X-Bittensor-Signature",
)
L_ED25519 = 2**252 + 27742317777372353535851937790883648493
#: Appendix A: every btauth/1 refusal is 401.
STATUS: dict[str, int] = dict.fromkeys(
    (
        "tw.auth_malformed",
        "tw.auth_wrong_receiver",
        "tw.auth_stale",
        "tw.auth_bad_signature",
        "tw.auth_replayed",
    ),
    401,
)

Pairs = list[list[str]]


def _keys() -> dict[str, dict[str, str]]:
    out = {}
    for name, (uri, ctype, seed) in DEV_SEEDS.items():
        derived = crypto.keypair_from_uri(uri, crypto_type=ctype)
        pinned = crypto.keypair_from_seed(bytes.fromhex(seed), crypto_type=ctype)
        if pinned.ss58_address != derived.ss58_address:
            raise SystemExit(f"{name}: pinned seed does not derive {uri}")
        out[name] = {
            "uri": uri,
            "scheme": crypto.scheme_name(ctype),
            "secret_seed_hex": seed,
            "public_key_hex": bytes(derived.public_key).hex(),
            "ss58": derived.ss58_address,
        }
    return out


KEYS = _keys()
ALICE_SS58 = KEYS["alice_sr25519"]["ss58"]
BOB_SS58 = KEYS["bob_sr25519"]["ss58"]


def _payload(  # noqa: PLR0917 - the eight payload lines
    scheme: str,
    method: str,
    target: str,
    body: bytes,
    nonce: int,
    sender: str,
    receiver: str | None,
) -> bytes:
    return crypto.btauth_payload(
        scheme=scheme,
        method=method,
        target=target,
        body=body,
        nonce_ns=nonce,
        sender_ss58=sender,
        receiver_ss58=receiver,
    )


def _build_vector(
    vid: str,
    description: str,
    *,
    scheme: str = "sr25519",
    method: str = "POST",
    target: str = GOLDEN_TARGET,
    body: bytes = GOLDEN_BODY,
    nonce: int = NONCE,
    sender: str = ALICE_SS58,
    receiver: str | None = BOB_SS58,
) -> dict[str, Any]:
    payload = _payload(scheme, method, target, body, nonce, sender, receiver)
    return {
        "id": vid,
        "description": description,
        "kind": "build_payload",
        "inputs": {
            "scheme": scheme,
            "method": method,
            "target": target,
            "body_base64": _b64(body),
            "nonce": str(nonce),
            "sender_ss58": sender,
            "receiver_ss58": receiver,
        },
        "expected": {
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "payload_utf8": payload.decode(),
            "payload_base64": _b64(payload),
        },
    }


def payload() -> dict[str, Any]:
    """``payload.json``: P1-P9 of spec 11.7."""
    vectors = [
        _build_vector("P1", "the golden request of Appendix C (sr25519)"),
        _build_vector("P2", "empty body (sha256 of zero bytes)", body=b""),
        _build_vector("P3", "lower-case method 'post' is written as POST",
                      method="post"),
        _build_vector("P4", "percent-encoded target kept as sent",
                      target="/a%20b?x=%2F"),
        _build_vector("P5a", "target with no query", target="/p"),
        _build_vector("P5b", "target with an empty query: the '?' is kept",
                      target="/p?"),
        _build_vector("P6", "unicode JSON body: the UTF-8 bytes are hashed",
                      body='{"text":"héllo ☃ 你好 🙂"}'.encode()),
        _build_vector("P7", "unbound receiver: line 8 is '-'", receiver=None),
        _build_vector("P8", "nonce 18446744073709551615 (u64 maximum)",
                      nonce=2**64 - 1),
        _build_vector("P9", "ed25519 scheme line (Appendix C ed25519 sender)",
                      scheme="ed25519", sender=KEYS["alice_ed25519"]["ss58"]),
    ]  # fmt: skip
    return {
        "schema_version": SCHEMA_VERSION,
        "description": "btauth/1 signed payload builds (spec 4.2). Generated by "
        "conformance/generate.py from bittensor.http_auth.build_payload.",
        "keys": KEYS,
        "vectors": vectors,
    }


def _keypair(name: str) -> crypto.Keypair:
    uri, ctype, _ = DEV_SEEDS[name]
    return crypto.keypair_from_uri(uri, crypto_type=ctype)


def _headers(
    sender: str,
    nonce: str,
    signature: str,
    *,
    scheme: str,
    receiver: str | None = BOB_SS58,
) -> Pairs:
    pairs = [[H_VERSION, "1"], [H_HOTKEY, sender]]
    if receiver is not None:
        pairs.append([H_RECEIVER, receiver])
    pairs.append([H_NONCE, nonce])
    if scheme == "ed25519":
        pairs.append([H_CRYPTO, "ed25519"])
    pairs.append([H_SIG, signature])
    return pairs


def _request(
    key: str = "alice_sr25519",
    *,
    method: str = "POST",
    target: str = GOLDEN_TARGET,
    body: bytes = GOLDEN_BODY,
    nonce: int = NONCE,
    receiver: str | None = BOB_SS58,
    sign: Callable[[bytes], bytes] | None = None,
) -> dict[str, Any]:
    """A correctly signed request: method, target, body and header pairs."""
    kp = _keypair(key)
    scheme = KEYS[key]["scheme"]
    data = _payload(scheme, method, target, body, nonce, kp.ss58_address, receiver)
    sig = (sign or kp.sign)(data)
    return {
        "method": method,
        "target": target,
        "body": body,
        "headers": _headers(
            kp.ss58_address,
            str(nonce),
            crypto.signature_to_hex(bytes(sig)),
            scheme=scheme,
            receiver=receiver,
        ),
        "payload": data,
    }


def _set(headers: Pairs, name: str, value: str | None) -> Pairs:
    """Replace (or with ``None`` drop) one header; names compared case-blind."""
    out = (
        [h for h in headers if h[0].lower() != name.lower()]
        if value is None
        else [[h[0], value] if h[0].lower() == name.lower() else h for h in headers]
    )
    if value is not None and not any(h[0].lower() == name.lower() for h in headers):
        out.append([name, value])
    return out


def _run_reference(case: dict[str, Any]) -> tuple[bool, str | None, str | None]:
    """Run one verify case through the Python reference: (valid, code, caller)."""
    i = case["inputs"]
    verifier = RequestVerifier(
        i["self_hotkey"],
        MemoryNonceStore(retention=60.0),
        max_age=i["max_age_s"],
        allowed_skew=i["allowed_skew_s"],
        now_ns=lambda: int(i["now_ns"]),
    )

    def one(r: dict[str, Any]) -> tuple[bool, str | None, str | None]:
        try:
            caller = verifier.verify_sync(
                [(n, v) for n, v in r["headers"]],
                base64.b64decode(r["body_base64"]),
                method=r["method"],
                target=r["target"],
            )
        except AuthFailed as exc:
            return False, exc.code, None
        return True, None, caller.hotkey_ss58

    if i.get("prior") is not None:
        first = one(i["prior"])
        if not first[0]:
            raise SystemExit(f"{case['id']}: prior request refused: {first}")
    return one(i)


def _verify_case(
    vid: str,
    description: str,
    request: dict[str, Any],
    *,
    code: str | None,
    kind: str = "verify_request",
    now_ns: int = NONCE,
    self_hotkey: str = BOB_SS58,
    prior: dict[str, Any] | None = None,
    python_reference: dict[str, Any] | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    def wire(r: dict[str, Any]) -> dict[str, Any]:
        return {
            "method": r["method"],
            "target": r["target"],
            "body_base64": _b64(r["body"]),
            "headers": r["headers"],
        }

    sender = next(
        (v for n, v in request["headers"] if n.lower() == H_HOTKEY.lower()), None
    )
    case: dict[str, Any] = {
        "id": vid,
        "description": description,
        "kind": kind,
        "inputs": {
            "self_hotkey": self_hotkey,
            "now_ns": str(now_ns),
            "max_age_s": MAX_AGE_S,
            "allowed_skew_s": SKEW_S,
            **wire(request),
            "prior": None if prior is None else wire(prior),
        },
        "expected": {
            "valid": code is None,
            "code": code,
            "status": None if code is None else STATUS[code],
            "caller_ss58": sender if code is None else None,
        },
    }
    if "payload" in request:
        case["inputs"]["signed_payload_utf8"] = request["payload"].decode()
    if python_reference is not None:
        case["python_reference"] = python_reference
    if notes:
        case["notes"] = notes
    want = python_reference or case["expected"]
    got = _run_reference(case)
    if (got[0], got[1]) != (want["valid"], want["code"]):
        raise SystemExit(f"{vid}: Python reference gives {got}, vector says {want}")
    return case


def ed25519() -> dict[str, Any]:
    """``ed25519.json``: deterministic request signatures, Appendix C first."""
    cases: list[tuple[str, str, str, dict[str, Any]]] = [
        ("E1", "Appendix C golden request, ed25519 //Alice -> //Bob",
         "alice_ed25519", {}),
        ("E2", "//Bob signs an empty-body GET with a query", "bob_ed25519",
         {"method": "GET", "target": "/health?full=1", "body": b""}),
        ("E3", "//Alice, unicode body", "alice_ed25519",
         {"body": '{"q":"naïve café ☕"}'.encode(), "target": "/q"}),
        ("E4", "//Bob, binary body (all 256 byte values)", "bob_ed25519",
         {"body": bytes(range(256)), "target": "/upload"}),
        ("E5", "//Alice, percent-encoded target", "alice_ed25519",
         {"target": "/a%20b/c?x=%2F&y=1", "body": b"{}"}),
        ("E6", "//Bob -> //Alice (receiver //Alice sr25519), PUT", "bob_ed25519",
         {"method": "PUT", "target": "/item/7", "body": b'{"v":1}',
          "receiver": ALICE_SS58}),
    ]  # fmt: skip
    vectors = []
    for vid, description, key, kw in cases:
        request = _request(key, **kw)
        receiver = kw.get("receiver", BOB_SS58)
        signature = dict(request["headers"])[H_SIG]
        if vid == "E1" and signature != GOLDEN_ED25519_SIG:
            raise SystemExit("E1 does not reproduce the Appendix C signature")
        vector = _verify_case(
            vid, description, request, code=None, kind="sign_ed25519",
            self_hotkey=receiver,
        )  # fmt: skip
        vector["inputs"]["key"] = key
        vector["expected"]["signature"] = signature
        vectors.append(vector)
    return {
        "schema_version": SCHEMA_VERSION,
        "description": "btauth/1 ed25519 request signatures (RFC 8032, "
        "deterministic). Sign inputs.signed_payload_utf8 with keys[inputs.key] "
        "and compare with expected.signature; the headers must also verify.",
        "keys": KEYS,
        "vectors": vectors,
    }


def sr25519_verify() -> dict[str, Any]:
    """``sr25519_verify.json``: ten pre-signed requests every verifier accepts."""
    cases: list[tuple[str, str, str, dict[str, Any]]] = [
        ("R1", "Appendix C golden request, //Alice -> //Bob", "alice_sr25519", {}),
        ("R2", "//Bob -> //Alice, empty-body GET", "bob_sr25519",
         {"method": "GET", "target": "/", "body": b"", "receiver": ALICE_SS58}),
        ("R3", "//Alice, unicode body", "alice_sr25519",
         {"body": '{"t":"Grüße ✓"}'.encode()}),
        ("R4", "//Bob -> //Alice, percent-encoded target", "bob_sr25519",
         {"target": "/a%20b?x=%2F", "receiver": ALICE_SS58}),
        ("R5", "//Alice, empty query kept", "alice_sr25519", {"target": "/p?"}),
        ("R6", "//Bob -> //Alice, 4 KiB body", "bob_sr25519",
         {"body": b"x" * 4096, "receiver": ALICE_SS58}),
        ("R7", "//Alice, DELETE", "alice_sr25519",
         {"method": "DELETE", "target": "/item/1", "body": b""}),
        ("R8", "//Bob -> //Alice, nonce = now - 9 s", "bob_sr25519",
         {"nonce": NONCE - 9 * S_NS, "receiver": ALICE_SS58}),
        ("R9", "//Alice, nonce = now + 1 s", "alice_sr25519",
         {"nonce": NONCE + S_NS}),
        ("R10", "//Bob -> //Alice, binary body", "bob_sr25519",
         {"body": bytes(range(255, -1, -1)), "receiver": ALICE_SS58}),
    ]  # fmt: skip
    vectors = [
        _verify_case(
            vid,
            description,
            _request(key, **kw),
            code=None,
            kind="verify_sr25519",
            self_hotkey=kw.get("receiver", BOB_SS58),
        )
        for vid, description, key, kw in cases
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "description": "btauth/1 sr25519 requests pre-signed by the Python "
        "reference (schnorrkel, context b'substrate'). Signatures are randomized: "
        "every verifier must accept each one, and its own signatures must be "
        "accepted by the Python verifier (live interop, spec 13.5).",
        "keys": KEYS,
        "vectors": vectors,
    }


def _ss58(public_key: bytes, prefix: int = 42) -> str:
    """SS58-encode ``public_key`` under any prefix (spec Appendix D, both forms)."""
    if prefix < 64:
        head = bytes([prefix])
    else:  # two-byte form of the SS58 spec
        head = bytes(
            [((prefix & 0xFC) >> 2) | 0x40, (prefix >> 8) | ((prefix & 0x03) << 6)]
        )
    raw = head + public_key
    check = hashlib.blake2b(b"SS58PRE" + raw, digest_size=64).digest()[:2]
    return _b58encode(raw + check)


def _b58_checksum_broken(address: str) -> str:
    """``address`` with its last base58 digit changed: same length, bad checksum."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    last = address[-1]
    return address[:-1] + alphabet[(alphabet.index(last) + 1) % len(alphabet)]


def _b58encode(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def _universal(scheme: str) -> dict[str, Any]:
    """A request from a weak key; its all-identity signature fits any payload."""
    if scheme == "ed25519":
        identity = bytes([1]) + bytes(31)  # the neutral point, small order
        pub, sig = identity, identity + bytes(32)  # R = identity, S = 0
    else:
        pub, sig = bytes(32), bytes(63) + b"\x80"  # ristretto identity, s = 0, marker
    sender = _ss58(pub)
    data = _payload(scheme, "POST", GOLDEN_TARGET, GOLDEN_BODY, NONCE, sender, BOB_SS58)
    return {
        "method": "POST",
        "target": GOLDEN_TARGET,
        "body": GOLDEN_BODY,
        "headers": _headers(
            sender, str(NONCE), crypto.signature_to_hex(sig), scheme=scheme
        ),
        "payload": data,
    }


def negative() -> dict[str, Any]:
    """``negative.json``: verify cases with the expected ``tw.*`` code."""
    good = _request()
    good_ed = _request("alice_ed25519")
    gh = good["headers"]
    sig = dict(gh)[H_SIG]
    alice = _keypair("alice_sr25519")
    alice_ed = _keypair("alice_ed25519")
    pk_alice = bytes(alice.public_key)

    def with_headers(headers: Pairs, base: dict[str, Any] = good) -> dict[str, Any]:
        return {**base, "headers": headers}

    def with_sig(signature: bytes, base: dict[str, Any] = good) -> dict[str, Any]:
        return with_headers(
            _set(base["headers"], H_SIG, crypto.signature_to_hex(signature)), base
        )

    def wrap(kp: crypto.Keypair) -> Callable[[bytes], bytes]:
        return lambda data: bytes(kp.sign(b"<Bytes>" + data + b"</Bytes>"))

    ed_sig = bytes.fromhex(dict(good_ed["headers"])[H_SIG][2:])
    s_val = int.from_bytes(ed_sig[32:], "little")
    sr_sig = bytearray(bytes.fromhex(sig[2:]))
    sr_sig[63] &= 0x7F
    signed_spaced = _request(target="/a%20b?x=1")
    signed_post = good
    ed_pub_ss58 = KEYS["alice_ed25519"]["ss58"]
    sender_wrong_len = _b58encode(b"\x2a" + pk_alice + b"\x00")  # 34 bytes
    py_wrapped = {
        "valid": True,
        "code": None,
        "note": "spec 11.7: the Python request verifier (bittensor.http_auth over "
        "sp_core.verify) accepts <Bytes>-wrapped signatures; strict "
        "implementations (TypeScript, Go, Rust) reject them.",
    }
    universal_note = [
        "Weak key: the identity point has a signature (R = identity, S = 0) "
        "that verifies for every payload. bittensor.http_auth accepts it; kit "
        "verifiers in every language reject it as a bad signature, checked after "
        "the signature and before the replay store."
    ]
    v = _verify_case
    cases = [
        # -- spec 11.7 list, step 1 (shape)
        v("N1", "missing X-Bittensor-Version", with_headers(_set(gh, H_VERSION, None)),
          code="tw.auth_malformed"),
        v("N2", "missing X-Bittensor-Hotkey", with_headers(_set(gh, H_HOTKEY, None)),
          code="tw.auth_malformed"),
        v("N3", "missing X-Bittensor-Nonce", with_headers(_set(gh, H_NONCE, None)),
          code="tw.auth_malformed"),
        v("N4", "missing X-Bittensor-Signature", with_headers(_set(gh, H_SIG, None)),
          code="tw.auth_malformed"),
        v("N5", "missing X-Bittensor-Receiver (TensorWire always requires it)",
          with_headers(_set(gh, H_RECEIVER, None)), code="tw.auth_wrong_receiver"),
        v("N6", "version 2", with_headers(_set(gh, H_VERSION, "2")),
          code="tw.auth_malformed"),
        v("N7", "unknown crypto ecdsa", with_headers(_set(gh, H_CRYPTO, "ecdsa")),
          code="tw.auth_malformed"),
        v("N8", "signature not hex", with_headers(_set(gh, H_SIG, "0x" + "zz" * 64)),
          code="tw.auth_malformed"),
        v("N9", "signature 63 bytes", with_headers(_set(gh, H_SIG, sig[:-2])),
          code="tw.auth_malformed"),
        v("N10", "sender SS58 with a bad checksum",
          with_headers(_set(gh, H_HOTKEY, _b58_checksum_broken(ALICE_SS58))),
          code="tw.auth_malformed"),
        # -- steps 2-4
        v("N11", "receiver is another hotkey", good, code="tw.auth_wrong_receiver",
          self_hotkey=ALICE_SS58),
        v("N12", "nonce 11 s old", good, code="tw.auth_stale",
          now_ns=NONCE + 11 * S_NS),
        v("N13", "nonce 3 s in the future", good, code="tw.auth_stale",
          now_ns=NONCE - 3 * S_NS),
        v("N14", "body changed by one byte",
          {**good, "body": b'{"prompt": "hellO"}'}, code="tw.auth_bad_signature"),
        v("N15", "target decoded by the router ('/a b' instead of '/a%20b')",
          {**signed_spaced, "target": "/a b?x=1"}, code="tw.auth_bad_signature"),
        v("N16", "method changed (signed POST, received PUT)",
          {**signed_post, "method": "PUT"}, code="tw.auth_bad_signature"),
        v("N17", "ed25519 signature without X-Bittensor-Crypto: verified as "
          "sr25519 only, never falls back",
          with_headers(_set(good_ed["headers"], H_CRYPTO, None), good_ed),
          code="tw.auth_bad_signature"),
        v("N18", "sr25519 signature declared as ed25519",
          with_headers(_set(gh, H_CRYPTO, "ed25519")), code="tw.auth_bad_signature"),
        v("N19", "<Bytes>-wrapped sr25519 signature (strict: rejected)",
          _request(sign=wrap(alice)), code="tw.auth_bad_signature",
          python_reference=py_wrapped),
        v("N20", "<Bytes>-wrapped ed25519 signature (strict: rejected)",
          _request("alice_ed25519", sign=wrap(alice_ed)),
          code="tw.auth_bad_signature", python_reference=py_wrapped),
        # -- step 5
        v("N21", "replay of an accepted request (inputs.prior is the same "
          "request, verified first with the same store)", good,
          code="tw.auth_replayed", prior=good),
        v("N22", "accepted nonce reused with a changed body: the signature "
          "fails first, the store is consulted only after step 4",
          {**good, "body": b'{"prompt": "bye"}'}, code="tw.auth_bad_signature",
          prior=good),
        # -- the kit's stricter shape rules (spec 4.3 step 1, A11)
        v("N23", "sender SS58 with prefix 0 (Alice's Polkadot address)",
          with_headers(_set(gh, H_HOTKEY, _ss58(pk_alice, 0))),
          code="tw.auth_malformed"),
        v("N24", "sender SS58 with a two-byte prefix (1284)",
          with_headers(_set(gh, H_HOTKEY, _ss58(pk_alice, 1284))),
          code="tw.auth_malformed"),
        v("N25", "sender SS58 decodes to 36 bytes (one byte too many)",
          with_headers(_set(gh, H_HOTKEY, sender_wrong_len)),
          code="tw.auth_malformed"),
        v("N26", "sender not base58 (contains '0')",
          with_headers(_set(gh, H_HOTKEY, "0" + ALICE_SS58[1:])),
          code="tw.auth_malformed"),
        v("N27", "duplicate X-Bittensor-Signature header (same value)",
          with_headers([*gh, [H_SIG, sig]]), code="tw.auth_malformed"),
        v("N28", "duplicate nonce header, names differ in case only",
          with_headers([*gh, ["x-bittensor-nonce", str(NONCE)]]),
          code="tw.auth_malformed"),
        v("N29", "nonce with a '+' sign", with_headers(_set(gh, H_NONCE, f"+{NONCE}")),
          code="tw.auth_malformed"),
        v("N30", "nonce of 21 digits", with_headers(_set(gh, H_NONCE, "0" + "1" * 20)),
          code="tw.auth_malformed"),
        v("N31", "nonce with non-ASCII digits (Arabic-Indic)",
          with_headers(_set(gh, H_NONCE, "١٧٥٢٠٧٦٨٠٠٠٠٠٠٠٠٠٠٠٠")),
          code="tw.auth_malformed"),
        v("N32", "empty nonce", with_headers(_set(gh, H_NONCE, "")),
          code="tw.auth_malformed"),
        v("N33", "nonce with an underscore", with_headers(
            _set(gh, H_NONCE, "1_752_076_800_000_000_000")), code="tw.auth_malformed"),
        v("N34", "X-Bittensor-Crypto 'ED25519' (values are exact)",
          with_headers(_set(good_ed["headers"], H_CRYPTO, "ED25519"), good_ed),
          code="tw.auth_malformed"),
        v("N35", "X-Bittensor-Crypto '1' (the SDK's numeric form)",
          with_headers(_set(gh, H_CRYPTO, "1")), code="tw.auth_malformed"),
        v("N36", "X-Bittensor-Crypto with padding ' sr25519'",
          with_headers(_set(gh, H_CRYPTO, " sr25519")), code="tw.auth_malformed"),
        v("N37", "empty X-Bittensor-Crypto", with_headers(_set(gh, H_CRYPTO, "")),
          code="tw.auth_malformed"),
        # -- more shape cases every language must agree on
        v("N38", "version ' 1' (values are exact)",
          with_headers(_set(gh, H_VERSION, " 1")), code="tw.auth_malformed"),
        v("N39", "empty sender", with_headers(_set(gh, H_HOTKEY, "")),
          code="tw.auth_malformed"),
        v("N40", "signature prefix '0X' (only '0x' is stripped)",
          with_headers(_set(gh, H_SIG, "0X" + sig[2:])), code="tw.auth_malformed"),
        v("N41", "signature prefix '0x0x'",
          with_headers(_set(gh, H_SIG, "0x" + sig)), code="tw.auth_malformed"),
        v("N42", "empty signature '0x'", with_headers(_set(gh, H_SIG, "0x")),
          code="tw.auth_malformed"),
        v("N43", "signature with an odd number of hex digits",
          with_headers(_set(gh, H_SIG, sig[:-1])), code="tw.auth_malformed"),
        v("N44", "signature 65 bytes", with_headers(_set(gh, H_SIG, sig + "00")),
          code="tw.auth_malformed"),
        v("N45", "signature hex with an inner space",
          with_headers(_set(gh, H_SIG, sig[:10] + " " + sig[10:])),
          code="tw.auth_malformed"),
        v("N46", "signature hex with a trailing space (a server that keeps "
          "trailing whitespace passes it on)",
          with_headers(_set(gh, H_SIG, sig + " ")), code="tw.auth_malformed",),
        v("N47", "receiver header is the literal unbound marker '-'",
          with_headers(_set(gh, H_RECEIVER, "-")), code="tw.auth_wrong_receiver"),
        v("N48", "empty receiver", with_headers(_set(gh, H_RECEIVER, "")),
          code="tw.auth_wrong_receiver"),
        # -- freshness boundaries
        v("N49", "nonce max_age + 1 ns old", good, code="tw.auth_stale",
          now_ns=NONCE + MAX_AGE_S * S_NS + 1),
        v("N50", "nonce allowed_skew + 1 ns in the future", good, code="tw.auth_stale",
          now_ns=NONCE - SKEW_S * S_NS - 1),
        v("N51", "nonce of 20 digits above the u64 maximum: well-formed, far in "
          "the future", with_headers(_set(gh, H_NONCE, "9" * 20)), code="tw.auth_stale",
          notes=["Implementations holding the nonce as u64 must report this as "
                 "stale (step 3), not malformed: the digits are valid."]),
        v("N52", "nonce 0", with_headers(_set(gh, H_NONCE, "0")), code="tw.auth_stale"),
        # -- signature edge cases
        v("N53", "sr25519 signature with the schnorrkel marker bit cleared",
          with_sig(bytes(sr_sig)), code="tw.auth_bad_signature"),
        v("N54", "ed25519 signature with a non-canonical S (S + L)",
          with_sig(ed_sig[:32] + (s_val + L_ED25519).to_bytes(32, "little"), good_ed),
          code="tw.auth_bad_signature"),
        v("N55", "sr25519 sender whose key bytes are not a ristretto point",
          with_headers(_set(gh, H_HOTKEY, _ss58(b"\xff" * 32))),
          code="tw.auth_bad_signature"),
        v("N56", "ed25519 sender whose key bytes are not a curve point",
          with_headers(
              _set(good_ed["headers"], H_HOTKEY, _ss58(b"\xff" * 32)), good_ed
          ),
          code="tw.auth_bad_signature"),
        v("N57", "all-zero sr25519 signature", with_sig(bytes(64)),
          code="tw.auth_bad_signature"),
        v("N58", "signature of another sender (//Bob signs, header says //Alice)",
          with_sig(_keypair("bob_sr25519").sign(good["payload"])),
          code="tw.auth_bad_signature"),
        v("N65", "sender of 49 characters: longer than any prefix-42 address, "
          "refused before base58 decoding (quadratic in the input length)",
          with_headers(_set(gh, H_HOTKEY, "1" + ALICE_SS58)), code="tw.auth_malformed"),
        # -- order of the checks (spec 4.3)
        v("N59", "order: duplicate header and wrong receiver -> shape first",
          with_headers([*gh, [H_SIG, sig]]), code="tw.auth_malformed",
          self_hotkey=ALICE_SS58),
        v("N60", "order: wrong receiver and stale -> receiver first", good,
          code="tw.auth_wrong_receiver", self_hotkey=ALICE_SS58,
          now_ns=NONCE + 60 * S_NS),
        v("N61", "order: stale and bad signature -> freshness first",
          {**good, "body": b"tampered"}, code="tw.auth_stale",
          now_ns=NONCE + 60 * S_NS),
        v("N62", "order: bad SS58 and stale -> shape first",
          with_headers(_set(gh, H_HOTKEY, _b58_checksum_broken(ALICE_SS58))),
          code="tw.auth_malformed", now_ns=NONCE + 60 * S_NS),
        # -- accept controls: what must NOT be rejected
        v("A1", "golden request accepted (sr25519)", good, code=None),
        v("A2", "golden request accepted (ed25519, Appendix C)", good_ed, code=None),
        v("A3", "header names in any case",
          with_headers([[n.lower() if k % 2 else n.upper(), v]
                        for k, (n, v) in enumerate(gh)]), code=None),
        v("A4", "signature without the 0x prefix",
          with_headers(_set(gh, H_SIG, sig[2:])), code=None),
        v("A5", "signature in upper-case hex",
          with_headers(_set(gh, H_SIG, "0x" + sig[2:].upper())), code=None),
        v("A6", "nonce exactly max_age old", good, code=None,
          now_ns=NONCE + MAX_AGE_S * S_NS),
        v("A7", "nonce exactly allowed_skew in the future", good, code=None,
          now_ns=NONCE - SKEW_S * S_NS),
        v("A8", "nonce with a leading zero: the payload uses the canonical "
          "decimal", with_headers(_set(gh, H_NONCE, f"0{NONCE}")), code=None),
        v("A9", "method received in lower case: the payload upper-cases it",
          {**good, "method": "post"}, code=None),
        v("A10", "explicit X-Bittensor-Crypto: sr25519",
          with_headers(_set(gh, H_CRYPTO, "sr25519")), code=None),
        v("A11", "duplicate non-auth headers are not the verifier's concern",
          with_headers([*gh, ["Accept", "a/b"], ["Accept", "c/d"]]), code=None),
        v("A12", "reserved X-Bittensor-Drand-Round header is ignored (spec 4.4)",
          with_headers([*gh, ["X-Bittensor-Drand-Round", "1"]]), code=None),
        v("N63", "weak ed25519 key (identity point) with the universal signature",
          _universal("ed25519"), code="tw.auth_bad_signature", notes=universal_note),
        v("N64", "weak sr25519 key (ristretto identity) with the universal "
          "signature", _universal("sr25519"), code="tw.auth_bad_signature",
          notes=universal_note),
        v("A13", "ed25519 sender header for the golden ed25519 address",
          with_headers(_set(good_ed["headers"], H_HOTKEY, ed_pub_ss58), good_ed),
          code=None),
    ]  # fmt: skip
    return {
        "schema_version": SCHEMA_VERSION,
        "description": "btauth/1 verify cases (spec 4.3, 11.7). Verify inputs with "
        "self_hotkey, now_ns, max_age_s and allowed_skew_s; when inputs.prior is "
        "set, verify it first with the same nonce store (it must be accepted). "
        "headers is a list of [name, value] pairs, so duplicates can be expressed. "
        "expected is the normative answer; python_reference, when present, is "
        "what the Python reference does instead and why.",
        "keys": KEYS,
        "vectors": cases,
    }


GENERATORS: dict[str, Callable[[], dict[str, Any]]] = {
    "ed25519": ed25519,
    "negative": negative,
    "payload": payload,
    "sr25519_verify": sr25519_verify,
    "twresp": twresp,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", choices=sorted(GENERATORS))
    parser.add_argument("--out", type=Path, default=VECTORS_DIR)
    parser.add_argument("--force", action="store_true", help="overwrite existing files")
    args = parser.parse_args()
    for name in args.files:
        path = args.out / f"{name}.json"
        if path.exists() and not args.force:
            print(f"refusing to overwrite {path} (use --force)", file=sys.stderr)
            return 1
        text = json.dumps(GENERATORS[name](), indent=1, ensure_ascii=False) + "\n"
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
