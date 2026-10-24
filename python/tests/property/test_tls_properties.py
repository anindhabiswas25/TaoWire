"""Property tests for TLS key parsers of untrusted input (spec 16.3, ADR-0011).

What the chain stores for a hotkey, the SDK's decoding of it, and a peer's
certificate are all chosen by others.

1. ``parse_published`` never raises; it returns its input unchanged (a
   documented algorithm byte with the right key length) or ``None``.
2. ``neuron_certificates`` raises only ``SdkSurfaceError`` (fail closed)
   for any rows the SDK could return, and gives bytes for every hotkey.
3. ``published_key_from_der`` raises only ``UnsupportedKey`` for any bytes.
4. A key built from a real P-256 point or Ed25519 key round-trips.
"""

from __future__ import annotations

import contextlib
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from hypothesis import given, settings
from hypothesis import strategies as st

from taowire.chain.gateway import SdkSurfaceError, neuron_certificates
from taowire.tls import (
    ALG_ED25519,
    ALG_P256,
    MAX_PUBLISHED_BYTES,
    UnsupportedKey,
    parse_published,
    published_key_from_der,
)

published = st.one_of(
    st.binary(max_size=80),
    st.builds(
        lambda alg, key: bytes([alg]) + key,
        st.sampled_from([ALG_ED25519, ALG_P256, 0, 3, 255]),
        st.one_of(
            st.binary(min_size=32, max_size=32), st.binary(min_size=64, max_size=64)
        ),
    ),
)


@settings(max_examples=500)
@given(raw=published)
def test_parse_published_is_total(raw: bytes) -> None:
    got = parse_published(raw)
    if got is None:
        return
    assert got == raw
    assert len(raw) <= MAX_PUBLISHED_BYTES
    assert (raw[0], len(raw) - 1) in ((ALG_ED25519, 32), (ALG_P256, 64))


sdk_values = st.one_of(
    st.none(),
    st.integers(),
    st.text(max_size=10),
    st.dictionaries(
        st.sampled_from(["algorithm", "public_key", "x"]),
        st.one_of(
            st.integers(min_value=-5, max_value=300),
            st.booleans(),
            st.text(max_size=70),
            st.binary(max_size=70).map(lambda b: "0x" + b.hex()),
            st.lists(st.integers(min_value=-1, max_value=256), max_size=70),
            st.binary(max_size=70),
            st.none(),
        ),
        max_size=3,
    ),
)
rows = st.one_of(
    st.none(),
    st.integers(),
    st.lists(
        st.one_of(
            st.tuples(st.one_of(st.text(max_size=8), st.integers()), sdk_values),
            st.tuples(st.text(max_size=8)),
            sdk_values,
        ),
        max_size=6,
    ),
)


@settings(max_examples=500)
@given(value=rows)
def test_neuron_certificates_raises_only_sdk_surface_error(value: Any) -> None:
    try:
        out = neuron_certificates(value)
    except SdkSurfaceError:
        return
    for hotkey, key in out.items():
        assert isinstance(hotkey, str)
        assert isinstance(key, bytes)


@settings(max_examples=300)
@given(der=st.binary(max_size=400))
def test_certificate_parsing_raises_only_unsupported_key(der: bytes) -> None:
    with contextlib.suppress(UnsupportedKey):
        published_key_from_der(der)


@settings(max_examples=50)
@given(st.booleans())
def test_real_keys_round_trip(use_ed25519: bool) -> None:
    if use_ed25519:
        raw = (
            ed25519.Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        key = bytes([ALG_ED25519]) + raw
    else:
        point = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        )
        key = bytes([ALG_P256]) + point[1:]
    assert parse_published(key) == key
    sdk_hex = {"algorithm": key[0], "public_key": "0x" + key[1:].hex()}
    assert neuron_certificates([("hk", sdk_hex)]) == {"hk": key}
