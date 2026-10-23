from __future__ import annotations

from typing import Any

import pytest
from bittensor import http_auth
from bittensor.signing import Signer

from tensorwire import crypto

ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
ALICE_PUBKEY = bytes.fromhex(
    "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
)
ALICE_ED25519 = "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu"
ALICE_POLKADOT = "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
BOB = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"

# Appendix C: the ed25519 golden vector has a fixed signature.
GOLDEN_ED25519_SIGNATURE = (
    "0x1a6b631988bf1f7ea093ab9d5acf61f05c316d0b0e428b24b487b75a5f6ee0e1"
    "a56a26918fdf871b6cf09437e6588023a4ce423cf622621b2a7feee17612f704"
)


def _golden_payload(scheme: str, sender: str) -> bytes:
    return http_auth.build_payload(
        scheme=scheme,
        method="POST",
        path="/generate?stream=false",
        body=b'{"prompt": "hello"}',
        nonce_ns=1752076800000000000,
        sender_ss58=sender,
        receiver_ss58=BOB,
    )


@pytest.fixture
def alice() -> crypto.Keypair:
    return crypto.keypair_from_uri("//Alice")


@pytest.fixture
def alice_ed() -> crypto.Keypair:
    return crypto.keypair_from_uri("//Alice", crypto_type=crypto.CRYPTO_ED25519)


def test_dev_keys_match_appendix_c(
    alice: crypto.Keypair, alice_ed: crypto.Keypair
) -> None:
    assert alice.ss58_address == ALICE
    assert alice_ed.ss58_address == ALICE_ED25519


def test_ed25519_golden_signature(alice_ed: crypto.Keypair) -> None:
    signer = crypto.HotkeySigner(alice_ed)
    signature = signer.sign(_golden_payload("ed25519", ALICE_ED25519))
    assert crypto.signature_to_hex(signature) == GOLDEN_ED25519_SIGNATURE
    assert signer.scheme == "ed25519"


def test_sr25519_sign_then_verify(alice: crypto.Keypair) -> None:
    signer = crypto.HotkeySigner(alice)
    payload = _golden_payload("sr25519", ALICE)
    signature = signer.sign(payload)
    assert signer.ss58_address == ALICE
    assert signer.crypto_type == crypto.CRYPTO_SR25519
    assert crypto.verify(payload, signature, ALICE, crypto.CRYPTO_SR25519)


def test_verify_rejects_changed_payload(alice: crypto.Keypair) -> None:
    signature = crypto.HotkeySigner(alice).sign(b"payload")
    assert not crypto.verify(b"payloaD", signature, ALICE, crypto.CRYPTO_SR25519)


def test_verify_rejects_other_signer(alice: crypto.Keypair) -> None:
    signature = crypto.HotkeySigner(alice).sign(b"payload")
    assert not crypto.verify(b"payload", signature, BOB, crypto.CRYPTO_SR25519)


def test_verify_uses_declared_scheme_only(alice_ed: crypto.Keypair) -> None:
    signature = crypto.HotkeySigner(alice_ed).sign(b"payload")
    assert crypto.verify(b"payload", signature, ALICE_ED25519, crypto.CRYPTO_ED25519)
    assert not crypto.verify(
        b"payload", signature, ALICE_ED25519, crypto.CRYPTO_SR25519
    )


@pytest.mark.parametrize("crypto_type", [crypto.CRYPTO_SR25519, crypto.CRYPTO_ED25519])
def test_strict_mode_rejects_bytes_wrapped_signature(crypto_type: int) -> None:
    keypair = crypto.keypair_from_uri("//Alice", crypto_type=crypto_type)
    payload = b"twresp/1\nsr25519\n1"
    wrapped_signature = keypair.sign(b"<Bytes>" + payload + b"</Bytes>")
    address = keypair.ss58_address
    assert not crypto.verify(payload, wrapped_signature, address, crypto_type)
    assert crypto.verify(payload, wrapped_signature, address, crypto_type, strict=False)


def test_strict_mode_accepts_plain_signature(alice: crypto.Keypair) -> None:
    payload = b"<Bytes>looks wrapped but is the real payload</Bytes>"
    signature = crypto.HotkeySigner(alice).sign(payload)
    assert crypto.verify(payload, signature, ALICE, crypto.CRYPTO_SR25519)


@pytest.mark.parametrize(
    "address",
    [
        "",
        "5Grwbad",
        "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ",  # bad checksum
        ALICE_POLKADOT,  # valid key, wrong network prefix
    ],
)
def test_verify_raises_on_malformed_address(
    alice: crypto.Keypair, address: str
) -> None:
    signature = crypto.HotkeySigner(alice).sign(b"payload")
    with pytest.raises(ValueError, match="invalid ss58 address"):
        crypto.verify(b"payload", signature, address, crypto.CRYPTO_SR25519)


@pytest.mark.parametrize("length", [0, 63, 65])
def test_verify_raises_on_wrong_signature_length(length: int) -> None:
    with pytest.raises(ValueError, match="signature length"):
        crypto.verify(b"payload", b"\x01" * length, ALICE, crypto.CRYPTO_SR25519)


def test_verify_raises_on_unknown_crypto_type(alice: crypto.Keypair) -> None:
    signature = crypto.HotkeySigner(alice).sign(b"payload")
    with pytest.raises(ValueError, match="unsupported crypto type"):
        crypto.verify(b"payload", signature, ALICE, 7)


def test_public_key_from_ss58() -> None:
    assert crypto.public_key_from_ss58(ALICE) == ALICE_PUBKEY


def test_public_key_rejects_other_prefix() -> None:
    with pytest.raises(ValueError, match="prefix-42"):
        crypto.public_key_from_ss58(ALICE_POLKADOT)


def test_scheme_names() -> None:
    assert crypto.scheme_name(crypto.CRYPTO_SR25519) == "sr25519"
    assert crypto.scheme_name(crypto.CRYPTO_ED25519) == "ed25519"
    assert crypto.crypto_type_from_scheme("sr25519") == crypto.CRYPTO_SR25519
    assert crypto.crypto_type_from_scheme("ed25519") == crypto.CRYPTO_ED25519
    with pytest.raises(ValueError, match="unsupported crypto type"):
        crypto.scheme_name(2)
    with pytest.raises(ValueError, match="unsupported scheme"):
        crypto.crypto_type_from_scheme("ecdsa")


def test_signature_hex_round_trip() -> None:
    signature = bytes(range(64))
    encoded = crypto.signature_to_hex(signature)
    assert encoded.startswith("0x")
    assert encoded == encoded.lower()
    assert crypto.signature_from_hex(encoded) == signature
    assert crypto.signature_from_hex(encoded[2:]) == signature
    with pytest.raises(ValueError, match="non-hexadecimal"):
        crypto.signature_from_hex("0xzz")


@pytest.mark.parametrize(
    "value",
    ["0xab cd", "0xabcd ", " 0xabcd", "0xab\tcd", "0xab\ncd", "0X" + "ab", "0xa"],
)
def test_signature_hex_is_strict(value: str) -> None:
    """Hex digits only: ``bytes.fromhex`` would skip the whitespace (vector N45)."""
    with pytest.raises(ValueError, match="non-hexadecimal"):
        crypto.signature_from_hex(value)


def test_signature_hex_accepts_upper_case_and_empty() -> None:
    assert crypto.signature_from_hex("0xABcd") == b"\xab\xcd"
    assert crypto.signature_from_hex("0x") == b""


@pytest.mark.parametrize(
    ("uri", "crypto_type", "seed"),
    [
        (
            "//Alice",
            crypto.CRYPTO_SR25519,
            "e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a",
        ),
        (
            "//Alice",
            crypto.CRYPTO_ED25519,
            "abf8e5bdbe30c65656c0a3cbd181ff8a56294a69dfedd27982aace4a76909115",
        ),
    ],
)
def test_keypair_from_seed_matches_the_uri(
    uri: str, crypto_type: int, seed: str
) -> None:
    by_seed = crypto.keypair_from_seed(bytes.fromhex(seed), crypto_type=crypto_type)
    by_uri = crypto.keypair_from_uri(uri, crypto_type=crypto_type)
    assert by_seed.ss58_address == by_uri.ss58_address


def test_keypair_from_seed_rejects_bad_input() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.keypair_from_seed(b"\x01" * 31)
    with pytest.raises(ValueError, match="unsupported crypto type"):
        crypto.keypair_from_seed(b"\x01" * 32, crypto_type=7)


def test_btauth_payload_is_the_sdk_payload(alice: crypto.Keypair) -> None:
    kwargs: dict[str, Any] = {
        "scheme": "sr25519",
        "method": "post",
        "body": b"{}",
        "nonce_ns": 1,
        "sender_ss58": alice.ss58_address,
        "receiver_ss58": None,
    }
    built = crypto.btauth_payload(target="/a%20b?", **kwargs)
    assert built == http_auth.build_payload(path="/a%20b?", **kwargs)
    assert built.split(b"\n")[2:4] == [b"POST", b"/a%20b?"]
    assert built.endswith(b"\n-")


def test_keypair_from_uri_rejects_unknown_crypto_type() -> None:
    with pytest.raises(ValueError, match="unsupported crypto type"):
        crypto.keypair_from_uri("//Alice", crypto_type=9)


class _WalletWithoutColdkey:
    """Wallet-shaped object whose coldkey must never be touched."""

    def __init__(self, hotkey: crypto.Keypair) -> None:
        self._hotkey = hotkey

    @property
    def hotkey(self) -> crypto.Keypair:
        return self._hotkey

    @property
    def coldkey(self) -> Any:
        raise AssertionError("coldkey accessed")

    @property
    def coldkeypub(self) -> Any:
        raise AssertionError("coldkeypub accessed")


def test_signer_uses_hotkey_and_never_touches_coldkey(alice: crypto.Keypair) -> None:
    signer = crypto.HotkeySigner(_WalletWithoutColdkey(alice))
    signature = signer.sign(b"payload")
    assert signer.ss58_address == ALICE
    assert crypto.verify(b"payload", signature, ALICE, crypto.CRYPTO_SR25519)


class _AsyncSigner:
    ss58_address = ALICE
    public_key = ALICE_PUBKEY
    crypto_type = 1

    async def sign(self, payload: bytes) -> bytes:
        return b""


class _AwaitableResultSigner:
    ss58_address = ALICE
    public_key = ALICE_PUBKEY
    crypto_type = 1

    def sign(self, payload: bytes) -> Any:
        return _AsyncSigner().sign(payload)


def test_rejects_async_signer() -> None:
    with pytest.raises(TypeError, match="asynchronous signers"):
        crypto.HotkeySigner(_AsyncSigner())  # type: ignore[arg-type]


def test_rejects_signer_returning_awaitable() -> None:
    signer = crypto.HotkeySigner(_AwaitableResultSigner())
    with pytest.raises(TypeError, match="asynchronous signers"):
        signer.sign(b"payload")


def test_signer_satisfies_sdk_signer_protocol(alice: crypto.Keypair) -> None:
    signer = crypto.HotkeySigner(alice)
    assert isinstance(signer, Signer)
    assert signer.public_key == ALICE_PUBKEY
    headers = http_auth.sign(
        signer, method="POST", path="/x", body=b"{}", receiver_ss58=BOB
    )
    caller = http_auth.verify(
        headers,
        b"{}",
        method="POST",
        path="/x",
        self_hotkey_ss58=BOB,
        nonce_store=http_auth.InMemoryNonceStore(),
    )
    assert caller.hotkey_ss58 == ALICE


def test_repr_has_no_secrets(alice: crypto.Keypair) -> None:
    assert (
        repr(crypto.HotkeySigner(alice)) == f"HotkeySigner('{ALICE}', scheme='sr25519')"
    )
