"""``twresp/1``: signed responses (spec 9.1, ADR-0004).

btauth/1 authenticates requests only. A TensorWire miner also signs each
response from a protected route, so the validator knows the answer came
from that miner, unmodified, for *this* request (the signed payload binds
the request's nonce and sender, so an older answer or another validator's
answer cannot be replayed).

Headers set by the miner:

=========================  ==========================================
``X-TW-Resp-Version``      ``1``
``X-TW-Resp-Hotkey``       miner hotkey SS58
``X-TW-Resp-Crypto``       ``ed25519``; omitted for sr25519
``X-TW-Resp-Signature``    ``0x`` + lowercase hex
=========================  ==========================================

Signed payload (UTF-8, ``\\n``-joined, no trailing newline)::

    twresp/1
    <scheme>
    <request nonce, decimal>
    <request sender ss58 (validator)>
    <responder ss58 (miner)>
    <HTTP status code, decimal>
    <sha256 of the raw response body, lowercase hex>

Signatures are over the raw payload (no ``<Bytes>`` wrapping), verified
under the declared scheme only, through :mod:`tensorwire.crypto`.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from typing import Literal

from tensorwire.crypto import (
    HotkeySigner,
    crypto_type_from_scheme,
    signature_from_hex,
    signature_to_hex,
    verify,
)

__all__ = [
    "HEADER_CRYPTO",
    "HEADER_HOTKEY",
    "HEADER_SIGNATURE",
    "HEADER_VERSION",
    "PAYLOAD_TAG",
    "VERSION",
    "ResponseSignatureError",
    "body_digest",
    "identity_headers",
    "response_payload",
    "sign_response",
    "verify_response",
]

VERSION = "1"
PAYLOAD_TAG = "twresp/1"
HEADER_VERSION = "X-TW-Resp-Version"
HEADER_HOTKEY = "X-TW-Resp-Hotkey"
HEADER_CRYPTO = "X-TW-Resp-Crypto"
HEADER_SIGNATURE = "X-TW-Resp-Signature"

_PREFIX = "x-tw-resp-"
_SCHEMES = frozenset({"sr25519", "ed25519"})
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
_SIGNATURE = re.compile(r"0x[0-9a-fA-F]{128}")

Headers = Mapping[str, str] | Iterable[tuple[str, str]]


class ResponseSignatureError(Exception):
    """A response failed ``twresp/1`` verification (``tw.bad_response_signature``).

    ``reason`` is a short, safe description (never the signature itself).
    """

    code = "tw.bad_response_signature"

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def body_digest(body: bytes) -> str:
    """sha256 of ``body`` as lowercase hex (the payload's last line)."""
    return hashlib.sha256(body).hexdigest()


def response_payload(
    *,
    scheme: str,
    request_nonce: int,
    sender_ss58: str,
    responder_ss58: str,
    status: int,
    digest: str,
) -> bytes:
    """The exact bytes a ``twresp/1`` signature covers.

    ``digest`` is :func:`body_digest` of the raw response body (or, for a
    streamed response, the stream digest of spec 9.2).
    """
    if scheme not in _SCHEMES:
        raise ValueError(f"unsupported scheme {scheme!r}")
    if request_nonce < 0:
        raise ValueError("request_nonce must not be negative")
    if not 100 <= status <= 599:
        raise ValueError("status must be an HTTP status code")
    if not _HEX_DIGEST.fullmatch(digest):
        raise ValueError("digest must be 64 lowercase hex characters")
    for name, value in (("sender", sender_ss58), ("responder", responder_ss58)):
        if not value or "\n" in value:
            raise ValueError(f"{name} must be a non-empty single line")
    lines = (
        PAYLOAD_TAG,
        scheme,
        str(request_nonce),
        sender_ss58,
        responder_ss58,
        str(status),
        digest,
    )
    return "\n".join(lines).encode()


def identity_headers(signer: HotkeySigner) -> dict[str, str]:
    """``X-TW-Resp-Version``, ``-Hotkey`` and (ed25519) ``-Crypto`` for ``signer``.

    Every signed response carries them; a stream sends them at its start and
    the signature in its ``tw-end`` trailer (spec 9.2).
    """
    headers = {HEADER_VERSION: VERSION, HEADER_HOTKEY: signer.ss58_address}
    if signer.scheme == "ed25519":
        headers[HEADER_CRYPTO] = "ed25519"
    return headers


def sign_response(
    signer: HotkeySigner,
    *,
    request_nonce: int,
    sender_ss58: str,
    status: int,
    body: bytes | None = None,
    digest: str | None = None,
) -> dict[str, str]:
    """Return the ``X-TW-Resp-*`` headers for one response.

    Pass the raw response ``body`` (hashed here) or a precomputed ``digest``.
    """
    if (body is None) == (digest is None):
        raise ValueError("pass exactly one of body or digest")
    payload = response_payload(
        scheme=signer.scheme,
        request_nonce=request_nonce,
        sender_ss58=sender_ss58,
        responder_ss58=signer.ss58_address,
        status=status,
        digest=body_digest(body) if body is not None else str(digest),
    )
    return {
        **identity_headers(signer),
        HEADER_SIGNATURE: signature_to_hex(signer.sign(payload)),
    }


def _resp_headers(headers: Headers) -> dict[str, str]:
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    out: dict[str, str] = {}
    for name, value in pairs:
        key = name.lower()
        if not key.startswith(_PREFIX):
            continue
        if key in out:
            raise ResponseSignatureError(f"duplicate {name} header")
        out[key] = value
    return out


def verify_response(
    headers: Headers,
    *,
    expected_responder: str,
    request_nonce: int,
    sender_ss58: str,
    status: int,
    body: bytes | None = None,
    digest: str | None = None,
) -> Literal["sr25519", "ed25519"]:
    """Check a response's ``twresp/1`` signature; return the scheme used.

    ``expected_responder`` is the hotkey the request was addressed to;
    ``request_nonce`` and ``sender_ss58`` are what this validator sent.
    Raises :class:`ResponseSignatureError` when anything does not match:
    missing or duplicate headers, another version or responder, an unknown
    scheme, a signature that is not hex or does not verify.
    """
    if (body is None) == (digest is None):
        raise ValueError("pass exactly one of body or digest")
    h = _resp_headers(headers)
    version = h.get(HEADER_VERSION.lower())
    if version is None:
        raise ResponseSignatureError("response is not signed")
    if version != VERSION:
        raise ResponseSignatureError("unsupported response signature version")
    responder = h.get(HEADER_HOTKEY.lower())
    if responder != expected_responder:
        raise ResponseSignatureError("response signed by another hotkey")
    scheme = h.get(HEADER_CRYPTO.lower(), "sr25519")
    if scheme == "ed25519":
        chosen: Literal["sr25519", "ed25519"] = "ed25519"
    elif scheme == "sr25519":
        chosen = "sr25519"
    else:
        raise ResponseSignatureError("unsupported response signature scheme")
    raw_sig = h.get(HEADER_SIGNATURE.lower(), "")
    if not _SIGNATURE.fullmatch(raw_sig):
        raise ResponseSignatureError("malformed response signature")
    payload = response_payload(
        scheme=chosen,
        request_nonce=request_nonce,
        sender_ss58=sender_ss58,
        responder_ss58=expected_responder,
        status=status,
        digest=body_digest(body) if body is not None else str(digest),
    )
    try:
        ok = verify(
            payload,
            signature_from_hex(raw_sig),
            expected_responder,
            crypto_type_from_scheme(chosen),
        )
    except ValueError:
        raise ResponseSignatureError("malformed response signature") from None
    if not ok:
        raise ResponseSignatureError("invalid response signature")
    return chosen
