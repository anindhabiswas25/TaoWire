"""Test certificates, generated at test time (spec 16.3: never committed).

:func:`make_certificate` writes a self-signed certificate and its key, or one
signed by a test CA from :func:`make_ca`, into a directory (the key file
``chmod 600``, as the miner requires).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

__all__ = ["KeyKind", "TestCertificate", "make_ca", "make_certificate"]

KeyKind = Literal["ed25519", "p256", "p384", "rsa"]
_PrivateKey = ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey


@dataclass(frozen=True)
class TestCertificate:
    """Paths of a generated certificate and key; ``ca`` signed it (or ``None``)."""

    __test__ = False  # not a pytest test class

    cert_file: Path
    key_file: Path
    ca: TestCertificate | None = None


def _key(kind: KeyKind) -> _PrivateKey:
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if kind == "p256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "p384":
        return ec.generate_private_key(ec.SECP384R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write(
    directory: Path, name: str, cert: x509.Certificate, key: _PrivateKey
) -> TestCertificate:
    directory.mkdir(parents=True, exist_ok=True)
    cert_file = directory / f"{name}.crt"
    key_file = directory / f"{name}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.touch(mode=0o600)
    key_file.chmod(0o600)
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return TestCertificate(cert_file, key_file)


def _builder(subject: str, issuer: str, public_key: object) -> x509.CertificateBuilder:
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(public_key)  # type: ignore[arg-type]
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
    )


def _sign(builder: x509.CertificateBuilder, key: _PrivateKey) -> x509.Certificate:
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm)


def make_ca(directory: Path, name: str = "ca") -> TestCertificate:
    """A P-256 test CA (for ``https`` mode with CA verification)."""
    key = _key("p256")
    builder = _builder(name, name, key.public_key()).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    return _write(directory, name, _sign(builder, key), key)


def make_certificate(
    directory: Path,
    name: str = "miner",
    *,
    kind: KeyKind = "p256",
    ip: str = "127.0.0.2",
    ca: TestCertificate | None = None,
) -> TestCertificate:
    """A server certificate for ``ip`` with a fresh ``kind`` key.

    Self-signed unless ``ca`` is given.
    """
    key = _key(kind)
    issuer = name
    if ca is not None:
        ca_cert = x509.load_pem_x509_certificate(ca.cert_file.read_bytes())
        issuer = ca_cert.subject.rfc4514_string().removeprefix("CN=")
    builder = _builder(name, issuer, key.public_key()).add_extension(
        x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
        critical=False,
    )
    if ca is None:
        return _write(directory, name, _sign(builder, key), key)
    ca_key = serialization.load_pem_private_key(ca.key_file.read_bytes(), None)
    cert = _sign(builder, ca_key)  # type: ignore[arg-type]
    written = _write(directory, name, cert, key)
    return TestCertificate(written.cert_file, written.key_file, ca)
