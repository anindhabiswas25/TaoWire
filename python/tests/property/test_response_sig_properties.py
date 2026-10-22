"""Property tests for ``twresp/1`` (spec 9.1, 13.3; gate item G2-1).

1. ``verify_response`` on arbitrary response headers never raises anything
   but ``ResponseSignatureError`` and never accepts a forged response.
2. Sign then verify succeeds for any body, status, nonce and scheme, and
   changing any one bound input (body, status, nonce, sender, responder,
   one signature character) makes it fail.
3. Header names are case-insensitive; the order of headers does not matter.
4. ``response_payload`` either rejects its input with ``ValueError`` or
   produces exactly seven lines, so no field can smuggle in another line.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tensorwire.crypto import HotkeySigner
from tensorwire.extensions import response_sig as rs
from tensorwire.testing.keys import dev_key

MINER = {"sr25519": dev_key("bob"), "ed25519": dev_key("bob", "ed25519")}
SENDER = dev_key("alice").ss58
OTHER = dev_key("charlie").ss58
SIGNERS = {scheme: HotkeySigner(key.keypair) for scheme, key in MINER.items()}

RESP_NAMES = [
    rs.HEADER_VERSION,
    rs.HEADER_HOTKEY,
    rs.HEADER_CRYPTO,
    rs.HEADER_SIGNATURE,
]


def random_case(name: str, flips: list[bool]) -> str:
    return "".join(
        c.upper() if flip else c.lower()
        for c, flip in zip(name, flips + [False] * len(name), strict=False)
    )


header_names = st.one_of(
    st.sampled_from(RESP_NAMES),
    st.tuples(st.sampled_from(RESP_NAMES), st.lists(st.booleans(), max_size=20)).map(
        lambda t: random_case(*t)
    ),
    st.text(min_size=1, max_size=20),
)
header_values = st.one_of(
    st.text(max_size=150),
    st.sampled_from(
        ["1", "2", "", "ed25519", "sr25519", "ED25519", MINER["sr25519"].ss58]
    ),
    st.binary(max_size=80).map(lambda b: "0x" + b.hex()),
    st.binary(min_size=64, max_size=64).map(lambda b: "0x" + b.hex()),
    st.binary(min_size=64, max_size=64).map(lambda b: b.hex()),
)
statuses = st.integers(min_value=100, max_value=599)
nonces = st.integers(min_value=0, max_value=2**64)
schemes = st.sampled_from(["sr25519", "ed25519"])


@settings(max_examples=300, deadline=None)
@given(
    headers=st.lists(st.tuples(header_names, header_values), max_size=8),
    body=st.binary(max_size=256),
    status=statuses,
    nonce=nonces,
)
def test_verify_never_raises_unexpectedly_and_never_accepts_forgeries(
    headers: list[tuple[str, str]], body: bytes, status: int, nonce: int
) -> None:
    with pytest.raises(rs.ResponseSignatureError) as info:
        rs.verify_response(
            headers,
            expected_responder=MINER["sr25519"].ss58,
            request_nonce=nonce,
            sender_ss58=SENDER,
            status=status,
            body=body,
        )
    assert info.value.code == "tw.bad_response_signature"
    assert info.value.reason  # a short, safe reason


def signed(scheme: str, *, nonce: int, status: int, body: bytes) -> dict[str, str]:
    return rs.sign_response(
        SIGNERS[scheme],
        request_nonce=nonce,
        sender_ss58=SENDER,
        status=status,
        body=body,
    )


def verify(headers: Any, scheme: str, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "expected_responder": MINER[scheme].ss58,
        "sender_ss58": SENDER,
    }
    kwargs.update(overrides)
    return rs.verify_response(headers, **kwargs)


@settings(max_examples=60, deadline=None)
@given(scheme=schemes, body=st.binary(max_size=512), status=statuses, nonce=nonces)
def test_sign_then_verify_round_trips(
    scheme: str, body: bytes, status: int, nonce: int
) -> None:
    headers = signed(scheme, nonce=nonce, status=status, body=body)
    assert (
        verify(headers, scheme, request_nonce=nonce, status=status, body=body) == scheme
    )
    digest = rs.body_digest(body)
    assert (
        verify(headers, scheme, request_nonce=nonce, status=status, digest=digest)
        == scheme
    )


@settings(max_examples=60, deadline=None)
@given(
    scheme=schemes,
    body=st.binary(max_size=256),
    status=statuses,
    nonce=nonces,
    which=st.sampled_from(["body", "status", "nonce", "sender", "responder", "sig"]),
    position=st.integers(min_value=2, max_value=129),
)
def test_any_single_change_is_rejected(
    scheme: str,
    body: bytes,
    status: int,
    nonce: int,
    which: str,
    position: int,
) -> None:
    headers = signed(scheme, nonce=nonce, status=status, body=body)
    args: dict[str, Any] = {"request_nonce": nonce, "status": status, "body": body}
    responder = MINER[scheme].ss58
    if which == "body":
        args["body"] = body + b"\x00"
    elif which == "status":
        args["status"] = 100 + (status - 99) % 500
    elif which == "nonce":
        args["request_nonce"] = nonce + 1
    elif which == "sender":
        args["sender_ss58"] = OTHER
    elif which == "responder":
        responder = OTHER
    else:
        sig = headers[rs.HEADER_SIGNATURE]
        flipped = "0" if sig[position] != "0" else "1"
        headers[rs.HEADER_SIGNATURE] = sig[:position] + flipped + sig[position + 1 :]
    with pytest.raises(rs.ResponseSignatureError):
        verify(headers, scheme, expected_responder=responder, **args)


@settings(max_examples=40, deadline=None)
@given(
    scheme=schemes,
    flips=st.lists(st.booleans(), min_size=20, max_size=20),
    order=st.permutations(range(4)),
    status=statuses,
)
def test_header_case_and_order_do_not_matter(
    scheme: str, flips: list[bool], order: list[int], status: int
) -> None:
    headers = list(signed(scheme, nonce=7, status=status, body=b"x").items())
    shuffled = [headers[i] for i in order if i < len(headers)]
    renamed = [(random_case(name, flips), value) for name, value in shuffled]
    assert verify(renamed, scheme, request_nonce=7, status=status, body=b"x") == scheme


@settings(max_examples=300, deadline=None)
@given(
    scheme=st.one_of(schemes, st.text(max_size=10)),
    nonce=st.integers(min_value=-(2**65), max_value=2**65),
    sender=st.text(max_size=60),
    responder=st.text(max_size=60),
    status=st.integers(min_value=-1000, max_value=1000),
    digest=st.one_of(
        st.binary(min_size=32, max_size=32).map(bytes.hex), st.text(max_size=70)
    ),
)
def test_payload_is_seven_lines_or_value_error(
    scheme: str, nonce: int, sender: str, responder: str, status: int, digest: str
) -> None:
    try:
        payload = rs.response_payload(
            scheme=scheme,
            request_nonce=nonce,
            sender_ss58=sender,
            responder_ss58=responder,
            status=status,
            digest=digest,
        )
    except ValueError:
        return
    lines = payload.split(b"\n")
    assert len(lines) == 7
    assert lines[0] == b"twresp/1"
    assert lines[2] == str(nonce).encode()
    assert lines[5] == str(status).encode()
