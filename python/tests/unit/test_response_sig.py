"""twresp/1 signing and verification (spec 9.1)."""

from __future__ import annotations

from typing import Any

import pytest
from bittensor import sp_core

from taowire.crypto import HotkeySigner, signature_to_hex
from taowire.extensions import response_sig as rs
from taowire.testing.keys import dev_key

MINER = dev_key("bob")
VALIDATOR = dev_key("alice")
NONCE = 1_700_000_000_123_456_789
BODY = b'{"result":"HELLO"}'


def signed(
    scheme: str = "sr25519", *, status: int = 200, body: bytes = BODY
) -> dict[str, str]:
    signer = HotkeySigner(dev_key("bob", scheme).keypair)  # type: ignore[arg-type]
    return rs.sign_response(
        signer,
        request_nonce=NONCE,
        sender_ss58=VALIDATOR.ss58,
        status=status,
        body=body,
    )


def check(headers: Any, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "expected_responder": MINER.ss58,
        "request_nonce": NONCE,
        "sender_ss58": VALIDATOR.ss58,
        "status": 200,
        "body": BODY,
    }
    kwargs.update(overrides)
    return rs.verify_response(headers, **kwargs)


def test_payload_is_exactly_the_spec_lines() -> None:
    payload = rs.response_payload(
        scheme="sr25519",
        request_nonce=42,
        sender_ss58="5Sender",
        responder_ss58="5Miner",
        status=200,
        digest=rs.body_digest(b""),
    )
    assert payload == (
        b"twresp/1\nsr25519\n42\n5Sender\n5Miner\n200\n"
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


@pytest.mark.parametrize("scheme", ["sr25519", "ed25519"])
def test_sign_then_verify(scheme: str) -> None:
    headers = signed(scheme)
    assert headers[rs.HEADER_VERSION] == "1"
    assert headers[rs.HEADER_HOTKEY] == dev_key("bob", scheme).ss58  # type: ignore[arg-type]
    assert headers[rs.HEADER_SIGNATURE].startswith("0x")
    assert (rs.HEADER_CRYPTO in headers) == (scheme == "ed25519")
    responder = dev_key("bob", scheme).ss58  # type: ignore[arg-type]
    assert check(headers, expected_responder=responder) == scheme


def test_ed25519_signature_is_deterministic() -> None:
    assert signed("ed25519") == signed("ed25519")


def test_digest_form_matches_body_form() -> None:
    headers = signed()
    assert check(headers, body=None, digest=rs.body_digest(BODY)) == "sr25519"


def test_header_names_are_case_insensitive() -> None:
    headers = [(k.lower(), v) for k, v in signed().items()]
    assert check(headers) == "sr25519"


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"body": b'{"result":"hello"}'}, "invalid response signature"),
        ({"status": 500}, "invalid response signature"),
        ({"request_nonce": NONCE + 1}, "invalid response signature"),
        ({"sender_ss58": dev_key("charlie").ss58}, "invalid response signature"),
        ({"expected_responder": dev_key("dave").ss58}, "another hotkey"),
    ],
)
def test_any_change_fails(override: dict[str, Any], reason: str) -> None:
    with pytest.raises(rs.ResponseSignatureError, match=reason) as info:
        check(signed(), **override)
    assert info.value.code == "tw.bad_response_signature"


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda h: h.pop(rs.HEADER_VERSION), "not signed"),
        (lambda h: h.update({rs.HEADER_VERSION: "2"}), "version"),
        (lambda h: h.pop(rs.HEADER_HOTKEY), "another hotkey"),
        (lambda h: h.update({rs.HEADER_CRYPTO: "ecdsa"}), "scheme"),
        (lambda h: h.update({rs.HEADER_CRYPTO: "ed25519"}), "invalid"),
        (lambda h: h.pop(rs.HEADER_SIGNATURE), "malformed"),
        (lambda h: h.update({rs.HEADER_SIGNATURE: "0xzz"}), "malformed"),
        (
            lambda h: h.update({rs.HEADER_SIGNATURE: h[rs.HEADER_SIGNATURE][2:]}),
            "malformed",
        ),
    ],
)
def test_header_problems_fail(mutate: Any, reason: str) -> None:
    headers = signed()
    mutate(headers)
    with pytest.raises(rs.ResponseSignatureError, match=reason):
        check(headers)


def test_duplicate_header_fails() -> None:
    pairs = [*signed().items(), (rs.HEADER_HOTKEY, MINER.ss58)]
    with pytest.raises(rs.ResponseSignatureError, match="duplicate"):
        check(pairs)


def test_unrelated_headers_are_ignored() -> None:
    pairs = [*signed().items(), ("Content-Type", "a"), ("content-type", "b")]
    assert check(pairs) == "sr25519"


def test_wrapped_signature_is_rejected() -> None:
    # A signature over <Bytes>payload</Bytes> (Polkadot-JS signRaw) is refused.
    payload = rs.response_payload(
        scheme="sr25519",
        request_nonce=NONCE,
        sender_ss58=VALIDATOR.ss58,
        responder_ss58=MINER.ss58,
        status=200,
        digest=rs.body_digest(BODY),
    )
    wrapped = MINER.keypair.sign(b"<Bytes>" + payload + b"</Bytes>")
    headers = signed()
    headers[rs.HEADER_SIGNATURE] = signature_to_hex(bytes(wrapped))
    with pytest.raises(rs.ResponseSignatureError, match="invalid"):
        check(headers)


def test_weak_responder_key_is_refused() -> None:
    """D20 / ADR-0010: a universal signature from a weak key never verifies."""
    weak = str(sp_core.ss58_encode(bytes(32), 42))  # the sr25519 identity
    headers = signed()
    headers[rs.HEADER_HOTKEY] = weak
    headers[rs.HEADER_SIGNATURE] = signature_to_hex(bytes(63) + b"\x80")
    with pytest.raises(rs.ResponseSignatureError, match="invalid"):
        check(headers, expected_responder=weak)


def test_bad_responder_address_is_malformed() -> None:
    headers = signed()
    headers[rs.HEADER_HOTKEY] = "not-an-address"
    with pytest.raises(rs.ResponseSignatureError, match="malformed"):
        check(headers, expected_responder="not-an-address")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scheme": "ecdsa"},
        {"request_nonce": -1},
        {"status": 99},
        {"status": 600},
        {"digest": "ABC"},
        {"sender_ss58": ""},
        {"responder_ss58": "a\nb"},
    ],
)
def test_payload_rejects_bad_input(kwargs: dict[str, Any]) -> None:
    base: dict[str, Any] = {
        "scheme": "sr25519",
        "request_nonce": 1,
        "sender_ss58": "s",
        "responder_ss58": "r",
        "status": 200,
        "digest": rs.body_digest(b""),
    }
    base.update(kwargs)
    with pytest.raises(ValueError):  # noqa: PT011 - each case has its own message
        rs.response_payload(**base)


def test_body_or_digest_exactly_one() -> None:
    signer = HotkeySigner(MINER.keypair)
    with pytest.raises(ValueError, match="exactly one"):
        rs.sign_response(signer, request_nonce=1, sender_ss58="s", status=200)
    with pytest.raises(ValueError, match="exactly one"):
        rs.verify_response(
            {},
            expected_responder=MINER.ss58,
            request_nonce=1,
            sender_ss58="s",
            status=200,
            body=b"",
            digest=rs.body_digest(b""),
        )
