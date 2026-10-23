"""tensorwire.tls: compact keys, certificate checks, pinning (16.3, ADR-0011)."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from tensorwire.errors import StartupError
from tensorwire.testing.tls import KeyKind, make_certificate
from tensorwire.tls import (
    ALG_ED25519,
    ALG_P256,
    TlsPinMismatch,
    UnsupportedKey,
    load_published_certificate,
    load_server_identity,
    parse_published,
    pinned_context,
    published_key_from_der,
)

P256_POINT = (
    ec.generate_private_key(ec.SECP256R1())
    .public_key()
    .public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )[1:]
)


def _der(path: Path) -> bytes:
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return cert.public_bytes(serialization.Encoding.DER)


def test_ed25519_certificate_key(tmp_path: Path) -> None:
    cert = make_certificate(tmp_path, kind="ed25519")
    published = load_server_identity(cert.cert_file, cert.key_file)
    key = serialization.load_pem_private_key(cert.key_file.read_bytes(), None)
    assert isinstance(key, ed25519.Ed25519PrivateKey)
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert published == bytes([ALG_ED25519]) + raw
    assert published_key_from_der(_der(cert.cert_file)) == published
    assert parse_published(published) == published


def test_p256_certificate_key(tmp_path: Path) -> None:
    cert = make_certificate(tmp_path, kind="p256")
    published = load_server_identity(cert.cert_file, cert.key_file)
    key = serialization.load_pem_private_key(cert.key_file.read_bytes(), None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    point = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert published == bytes([ALG_P256]) + point[1:]  # X || Y, no 0x04
    assert len(published) == 65
    assert load_published_certificate(cert.cert_file) == published


@pytest.mark.parametrize("kind", ["rsa", "p384"])
def test_unsupported_key_types_are_refused(tmp_path: Path, kind: KeyKind) -> None:
    cert = make_certificate(tmp_path, kind=kind)
    with pytest.raises(StartupError, match="Ed25519 or ECDSA P-256"):
        load_server_identity(cert.cert_file, cert.key_file)
    with pytest.raises(StartupError, match="TW_TLS_PUBLISHED_CERT_FILE"):
        load_published_certificate(cert.cert_file)
    with pytest.raises(UnsupportedKey):
        published_key_from_der(_der(cert.cert_file))


@pytest.mark.parametrize("der", [b"", b"junk", b"\x30\x03\x02\x01\x01"])
def test_not_a_certificate(der: bytes) -> None:
    with pytest.raises(UnsupportedKey):
        published_key_from_der(der)


@pytest.mark.parametrize(
    ("raw", "usable"),
    [
        (b"", False),
        (b"\x01", False),  # algorithm byte only (the chain stores it)
        (b"\x01" + b"\x11" * 32, True),
        (b"\x01" + b"\x11" * 31, False),
        (b"\x01" + b"\x11" * 33, False),
        (b"\x02" + P256_POINT, True),
        (b"\x02" + b"\x00" * 64, False),  # not a point on the curve
        (b"\x02" + P256_POINT[:-1], False),
        (b"\x07" + b"\x11" * 32, False),  # unknown algorithm
        (b"\x02" + P256_POINT + b"\x00", False),  # longer than the chain stores
    ],
)
def test_parse_published(raw: bytes, usable: bool) -> None:
    assert parse_published(raw) == (raw if usable else None)


def test_pinned_context_needs_a_usable_key() -> None:
    with pytest.raises(ValueError, match="usable"):
        pinned_context(b"\x07")
    ctx = pinned_context(b"\x02" + P256_POINT)
    assert ctx.minimum_version is ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode is ssl.CERT_NONE  # the key pin replaces CA trust
    assert not ctx.check_hostname


def test_pin_mismatch_is_a_certificate_error() -> None:
    exc = TlsPinMismatch(1, "x")
    assert isinstance(exc, ssl.SSLCertVerificationError)
    assert exc.strerror == "x"


# ------------------------------------------------------------ startup errors


def test_missing_files(tmp_path: Path) -> None:
    cert = make_certificate(tmp_path)
    with pytest.raises(StartupError, match="cannot read TW_TLS_CERT_FILE"):
        load_server_identity(tmp_path / "nope.crt", cert.key_file)
    with pytest.raises(StartupError, match="cannot read TW_TLS_KEY_FILE"):
        load_server_identity(cert.cert_file, tmp_path / "nope.key")
    with pytest.raises(StartupError, match="cannot read TW_TLS_PUBLISHED_CERT_FILE"):
        load_published_certificate(tmp_path / "nope.crt")


def test_not_pem(tmp_path: Path) -> None:
    junk = tmp_path / "junk.crt"
    junk.write_text("not a certificate")
    with pytest.raises(StartupError, match="is not a PEM certificate"):
        load_published_certificate(junk)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644])
def test_key_file_readable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    cert = make_certificate(tmp_path)
    cert.key_file.chmod(mode)
    with pytest.raises(StartupError, match="chmod 600"):
        load_server_identity(cert.cert_file, cert.key_file)


def test_key_not_matching_the_certificate(tmp_path: Path) -> None:
    one = make_certificate(tmp_path, "one")
    two = make_certificate(tmp_path, "two")
    with pytest.raises(StartupError, match="cannot be used with") as caught:
        load_server_identity(one.cert_file, two.key_file)
    assert "PRIVATE KEY" not in str(caught.value)  # never the file's contents


def test_encrypted_key_never_prompts(tmp_path: Path) -> None:
    cert = make_certificate(tmp_path)
    key = serialization.load_pem_private_key(cert.key_file.read_bytes(), None)
    cert.key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"secret"),
        )
    )
    with pytest.raises(StartupError, match="unencrypted PEM private key"):
        load_server_identity(cert.cert_file, cert.key_file)


def test_unreadable_key_file(tmp_path: Path) -> None:
    cert = make_certificate(tmp_path)
    cert.key_file.chmod(0o000)
    try:
        with pytest.raises(StartupError, match="TW_TLS_KEY_FILE"):
            load_server_identity(cert.cert_file, cert.key_file)
    finally:
        cert.key_file.chmod(0o600)


def test_blocking_sockets_are_pinned_too(tmp_path: Path) -> None:
    """``ssl.SSLContext.wrap_socket`` (sync clients) runs the same check."""
    import socket
    import threading

    cert = make_certificate(tmp_path, kind="p256", ip="127.0.0.1")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert.cert_file, cert.key_file)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def serve() -> None:
        for _ in range(2):
            conn, _ = listener.accept()
            try:
                with server_ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    good = load_published_certificate(cert.cert_file)
    with socket.create_connection(("127.0.0.1", port)) as raw:
        pinned_context(good).wrap_socket(raw).close()
    with (
        socket.create_connection(("127.0.0.1", port)) as raw,
        pytest.raises(TlsPinMismatch),
    ):
        pinned_context(b"\x02" + P256_POINT).wrap_socket(raw)
    thread.join(timeout=5)
    listener.close()
    assert pinned_context(good).options & getattr(ssl, "OP_NO_RENEGOTIATION", 0)
