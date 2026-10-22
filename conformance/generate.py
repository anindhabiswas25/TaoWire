#!/usr/bin/env python3
"""Generate conformance vectors from the Python reference (spec 11.7).

    cd python && uv run python ../conformance/generate.py twresp [--force]

Each file is generated once, reviewed and committed; an existing file is
never overwritten without ``--force``. Only public dev keys are used.

Files so far:

- ``twresp.json`` (spec 9.1, 9.2): ``twresp/1`` payload builds, deterministic
  ed25519 signatures, a 3-chunk streaming digest, and verify cases (accept
  and reject) every implementation must agree on. sr25519 signatures are
  randomized: those vectors carry one pre-made signature that must verify.

Phase 5 adds ``payload.json``, ``ed25519.json``, ``sr25519_verify.json`` and
``negative.json`` here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tensorwire import crypto
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
    import base64  # noqa: PLC0415 - one use

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


GENERATORS: dict[str, Callable[[], dict[str, Any]]] = {"twresp": twresp}


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
