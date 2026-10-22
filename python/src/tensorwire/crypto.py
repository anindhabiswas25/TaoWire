"""Signing and verification of arbitrary bytes with hotkeys (spec 3.6).

A thin wrapper over the same SDK primitives ``bittensor.http_auth`` uses:
``bittensor.signing.resolve_signer`` to sign and ``bittensor.sp_core.verify``
to verify. Kit extensions (``twresp/1``, the legacy v10 wire format) use
this module and nothing else, so an SDK rename touches one file.

Only the hotkey is ever resolved. Nothing here touches a coldkey.
"""

from __future__ import annotations

import inspect
from typing import Any

from bittensor import sp_core as _sp_core
from bittensor.keyfiles import Keypair
from bittensor.signing import Signer, WalletLike, resolve_signer
from bittensor.wallet import Wallet

__all__ = [
    "CRYPTO_ED25519",
    "CRYPTO_SR25519",
    "SS58_FORMAT",
    "HotkeySigner",
    "Keypair",
    "crypto_type_from_scheme",
    "keypair_from_uri",
    "public_key_from_ss58",
    "scheme_name",
    "signature_from_hex",
    "signature_to_hex",
    "verify",
]

CRYPTO_ED25519: int = _sp_core.CRYPTO_ED25519
CRYPTO_SR25519: int = _sp_core.CRYPTO_SR25519
SS58_FORMAT = 42
"""Bittensor's SS58 network prefix."""

# The btauth/1 scheme names (spec 4.2). check_sdk_surface.py confirms they
# match ``bittensor.http_auth.CRYPTO_TYPE_NAMES``.
_SCHEMES: dict[int, str] = {CRYPTO_ED25519: "ed25519", CRYPTO_SR25519: "sr25519"}
_SCHEME_TYPES: dict[str, int] = {name: ct for ct, name in _SCHEMES.items()}

_WRAP_PREFIX = b"<Bytes>"
_WRAP_SUFFIX = b"</Bytes>"


def scheme_name(crypto_type: int) -> str:
    """Return the scheme name of a crypto type. ``ValueError`` if unknown."""
    try:
        return _SCHEMES[crypto_type]
    except KeyError:
        raise ValueError(f"unsupported crypto type {crypto_type!r}") from None


def crypto_type_from_scheme(scheme: str) -> int:
    """Return the crypto type of a scheme name. ``ValueError`` if unknown."""
    try:
        return _SCHEME_TYPES[scheme]
    except KeyError:
        raise ValueError(f"unsupported scheme {scheme!r}") from None


class HotkeySigner:
    """Signs bytes with a wallet's hotkey.

    ``wallet`` is anything the SDK accepts as a wallet: a ``bittensor.Wallet``,
    a ``Keypair`` (tests), or another synchronous signer. The signer is
    resolved once, at construction, with ``role="hotkey"``. Asynchronous
    signers (Ledger, Vault, browser extensions) are rejected: the kit signs
    on the request path and needs a synchronous signature (spec 3.2, A6).
    """

    def __init__(self, wallet: WalletLike) -> None:
        self._signer = resolve_signer(_hotkey_source(wallet), role="hotkey")
        if inspect.iscoroutinefunction(self._signer.sign):
            raise TypeError(
                "asynchronous signers are not supported; use a local hotkey file"
            )
        self.ss58_address: str = self._signer.ss58_address
        self.crypto_type: int = self._signer.crypto_type
        self.scheme: str = scheme_name(self.crypto_type)

    def sign(self, payload: bytes) -> bytes:
        """Return the raw signature over exactly ``payload`` (never a wrapped form)."""
        signature: Any = self._signer.sign(payload)
        if inspect.isawaitable(signature):
            close = getattr(signature, "close", None)
            if close is not None:
                close()
            raise TypeError(
                "asynchronous signers are not supported; use a local hotkey file"
            )
        return bytes(signature)

    def __repr__(self) -> str:
        return f"HotkeySigner({self.ss58_address!r}, scheme={self.scheme!r})"


def _hotkey_source(wallet: WalletLike) -> WalletLike:
    """Hand the SDK the hotkey of a wallet-shaped object, never the object itself.

    On Python < 3.12 the SDK's ``isinstance(wallet, KeyedWallet)`` check reads
    every protocol member with ``hasattr``, which evaluates ``wallet.coldkey``.
    A ``Wallet``, a ``Signer`` or a wallet name is passed through unchanged.
    """
    if isinstance(wallet, (str, Wallet, Signer)):
        return wallet
    hotkey: WalletLike = wallet.hotkey
    return hotkey


def verify(
    payload: bytes,
    signature: bytes,
    ss58_address: str,
    crypto_type: int,
    *,
    strict: bool = True,
) -> bool:
    """Return whether ``signature`` is ``ss58_address``'s signature over ``payload``.

    Verifies under ``crypto_type`` only; never tries the other scheme. Raises
    ``ValueError`` when the address is not a valid prefix-42 SS58 address,
    the signature has the wrong length, or the crypto type is unknown, so
    callers can tell a malformed input from a bad signature.

    ``sp_core.verify`` also accepts a signature over the
    ``<Bytes>payload</Bytes>`` wrapping (Polkadot-JS ``signRaw``). With
    ``strict=True`` (the default, and the rule for every kit extension) such
    a signature is rejected, matching the TypeScript, Go and Rust
    implementations (spec 3.2 A10, 11.2 rule 8).
    """
    scheme_name(crypto_type)
    public_key_from_ss58(ss58_address)
    if not _sp_core.verify(payload, signature, ss58_address, crypto_type):
        return False
    if not strict:
        return True
    wrapped = _WRAP_PREFIX + payload + _WRAP_SUFFIX
    return not _sp_core.verify(wrapped, signature, ss58_address, crypto_type)


def public_key_from_ss58(ss58_address: str) -> bytes:
    """Return the 32-byte public key of a Bittensor SS58 address (prefix 42).

    Raises ``ValueError`` for anything else: bad base58, bad checksum, wrong
    length, or another network's prefix (spec Appendix D). The SDK itself
    accepts any prefix; the kit does not, so every language agrees.
    """
    key = bytes(_sp_core.ss58_decode(ss58_address))
    if _sp_core.ss58_encode(key, SS58_FORMAT) != ss58_address:
        raise ValueError(f"invalid ss58 address: not a prefix-{SS58_FORMAT} address")
    return key


def signature_to_hex(signature: bytes) -> str:
    """Encode a signature for a header: ``0x`` + lowercase hex."""
    return "0x" + signature.hex()


def signature_from_hex(value: str) -> bytes:
    """Decode a header signature (``0x`` optional). ``ValueError`` if not hex."""
    return bytes.fromhex(value.removeprefix("0x"))


def keypair_from_uri(uri: str, *, crypto_type: int = CRYPTO_SR25519) -> Keypair:
    """Derive a keypair from a dev URI such as ``"//Alice"``. Tests and localnet only.

    A ``Keypair`` can be passed anywhere the SDK or :class:`HotkeySigner`
    expects a wallet.
    """
    scheme_name(crypto_type)
    return Keypair.create_from_uri(uri, crypto_type=crypto_type)
