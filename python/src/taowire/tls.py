"""TLS keys: what a miner publishes with ``ServeAxonTls`` and how validators pin it.

Spec 16.3, decision D31, ADR-0011. The chain stores 1 algorithm byte plus at
most 64 key bytes and gives the byte no meaning; TaoWire uses:

========  ===========  ==============================================
Byte      Key          Key bytes
========  ===========  ==============================================
``0x01``  Ed25519      32: the raw key (RFC 8032)
``0x02``  ECDSA P-256  64: ``X || Y`` (the uncompressed point, no ``0x04``)
========  ===========  ==============================================

A validator pins the leaf certificate's public key against the published one
right after the TLS handshake, before any request byte is sent. CA trust,
hostnames and validity dates are not used for a pinned miner: the key on chain
is the trust anchor.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import ClassVar

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from taowire.errors import StartupError

__all__ = [
    "ALG_ED25519",
    "ALG_P256",
    "MAX_PUBLISHED_BYTES",
    "TlsPinMismatch",
    "UnsupportedKey",
    "load_published_certificate",
    "load_server_identity",
    "parse_published",
    "pinned_context",
    "published_key_from_der",
]

#: Algorithm byte for an Ed25519 key (ADR-0011).
ALG_ED25519 = 0x01
#: Algorithm byte for an ECDSA P-256 key (ADR-0011).
ALG_P256 = 0x02
#: What the chain stores at most: the algorithm byte plus 64 key bytes.
MAX_PUBLISHED_BYTES = 65

_KEY_BYTES = {ALG_ED25519: 32, ALG_P256: 64}
_SUPPORTED = "Ed25519 or ECDSA P-256 (secp256r1)"
#: Permission bits that must be clear on TW_TLS_KEY_FILE (spec 12.2).
_KEY_FILE_FORBIDDEN_MODE = 0o044


class UnsupportedKey(ValueError):
    """A certificate whose key cannot be published (ADR-0011), or no certificate."""


class TlsPinMismatch(ssl.SSLCertVerificationError):
    """The peer's certificate key is not the miner's published key (16.3)."""


def _compact(key: object) -> bytes:
    if isinstance(key, ed25519.Ed25519PublicKey):
        raw = key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return bytes([ALG_ED25519]) + raw
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(
        key.curve, ec.SECP256R1
    ):
        point = key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return bytes([ALG_P256]) + point[1:]
    raise UnsupportedKey(f"the certificate's key is not {_SUPPORTED}")


def published_key_from_der(der: bytes) -> bytes:
    """The compact key (algorithm byte + key) of a DER certificate.

    Raises :class:`UnsupportedKey` for anything that is not a certificate with
    an Ed25519 or P-256 key.
    """
    try:
        key = x509.load_der_x509_certificate(der).public_key()
    except (ValueError, UnsupportedAlgorithm):
        raise UnsupportedKey("not a certificate with a readable public key") from None
    return _compact(key)


def parse_published(raw: bytes) -> bytes | None:
    """``raw`` if it is a key this kit can pin, else ``None`` (published but unusable).

    ``raw`` is what the chain stores for a hotkey (algorithm byte + key),
    untrusted. A P-256 value must be a point on the curve.
    """
    if not raw or len(raw) > MAX_PUBLISHED_BYTES:
        return None
    algorithm, key = raw[0], raw[1:]
    if _KEY_BYTES.get(algorithm) != len(key):
        return None
    if algorithm == ALG_P256:
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + key)
        except ValueError:
            return None
    return bytes(raw)


def _read_pem_certificate(path: Path, setting: str) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise StartupError(f"cannot read {setting} {path}: {exc.strerror}") from None
    try:
        leaf = x509.load_pem_x509_certificates(data)[0]
        return _compact(leaf.public_key())
    except UnsupportedKey:
        raise StartupError(
            f"{setting} {path}: the certificate's key is not {_SUPPORTED}; validators "
            "can only pin these key types (ADR-0011). Issue an EC P-256 or Ed25519 "
            "certificate"
        ) from None
    except (ValueError, UnsupportedAlgorithm):
        raise StartupError(f"{setting} {path} is not a PEM certificate") from None


def load_published_certificate(cert_file: Path) -> bytes:
    """Proxy mode: the compact key of ``TW_TLS_PUBLISHED_CERT_FILE``."""
    return _read_pem_certificate(cert_file, "TW_TLS_PUBLISHED_CERT_FILE")


def _refuse_password() -> bytes:
    return b""  # never let OpenSSL prompt on a terminal; an encrypted key fails


def load_server_identity(cert_file: Path, key_file: Path) -> bytes:
    """Check uvicorn's certificate and key; return the compact key to publish.

    StartupError when a file is missing or unreadable, the key file is group
    or world readable, the key is encrypted or does not match the
    certificate, or the key type is not supported. Messages name files,
    never their contents.
    """
    published = _read_pem_certificate(cert_file, "TW_TLS_CERT_FILE")
    try:
        mode = key_file.stat().st_mode
    except OSError as exc:
        raise StartupError(
            f"cannot read TW_TLS_KEY_FILE {key_file}: {exc.strerror}"
        ) from None
    if os.name == "posix" and mode & _KEY_FILE_FORBIDDEN_MODE:
        raise StartupError(
            f"TW_TLS_KEY_FILE {key_file} is readable by group or others; "
            f"run: chmod 600 {key_file}"
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert_file, key_file, password=_refuse_password)
    except ssl.SSLError as exc:
        reason = exc.reason or "unreadable key"
        raise StartupError(
            f"TW_TLS_KEY_FILE {key_file} cannot be used with TW_TLS_CERT_FILE "
            f"{cert_file} ({reason}): the key must be an unencrypted PEM private "
            "key matching the certificate"
        ) from None
    except OSError as exc:
        raise StartupError(
            f"cannot read TW_TLS_KEY_FILE {key_file}: {exc.strerror}"
        ) from None
    return published


def _check_pin(der: bytes | None, expected: bytes) -> None:
    try:
        seen = published_key_from_der(der) if der else None
    except UnsupportedKey:
        seen = None
    if seen != expected:
        # (errno, strerror): anyio reads strerror while mapping the error.
        raise TlsPinMismatch(1, "the miner's TLS key is not its published key")


class _PinnedSSLObject(ssl.SSLObject):
    """Checks the leaf key as soon as the handshake completes (asyncio, anyio)."""

    _expected: ClassVar[bytes]

    def do_handshake(self) -> None:
        super().do_handshake()  # raises SSLWantRead/Write until it is done
        _check_pin(self.getpeercert(binary_form=True), self._expected)


class _PinnedSSLSocket(ssl.SSLSocket):
    """The same check for blocking sockets (``ssl.SSLContext.wrap_socket``)."""

    _expected: ClassVar[bytes]

    def do_handshake(self, block: bool = False) -> None:
        super().do_handshake(block)
        _check_pin(self.getpeercert(binary_form=True), self._expected)


def pinned_context(expected: bytes) -> ssl.SSLContext:
    """A client context that accepts only a leaf certificate with key ``expected``.

    ``expected`` is a usable published key (:func:`parse_published`). TLS 1.2
    or later; no CA, hostname or date checks (the key is the trust anchor).
    """
    if parse_published(expected) is None:
        raise ValueError("not a usable published key")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # TLS 1.2 renegotiation could present another certificate after the check.
    context.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    pin = {"_expected": bytes(expected)}
    context.sslobject_class = type("PinnedSSLObject", (_PinnedSSLObject,), pin)
    context.sslsocket_class = type("PinnedSSLSocket", (_PinnedSSLSocket,), pin)
    return context
