"""Property tests for the legacy v10 bridge on the miner side (spec 8.11, 13.3).

1. ``wire.parse_request_headers`` raises nothing but ``WireError`` for
   arbitrary header lists.
2. ``LegacyServer.verify`` raises nothing but ``LegacyAuthFailed`` /
   ``LegacyDisabled`` / ``ReplayStoreUnavailable`` for arbitrary headers and
   bodies, and never accepts them; the same for mutations of a valid request
   that touch what the signature covers.
3. ``wire.body_hash`` of arbitrary model values equals the 8.11.1 rule
   ``sha3(concat(sha3(str(v))))``, and survives the encode → decode trip.
4. A valid request with any one hashed field, the nonce, the uuid or the
   sender hotkey changed is rejected.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections.abc import Callable
from typing import Any, ClassVar

import pytest
from bittensor import sp_core
from hypothesis import HealthCheck, assume, given, note, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from legacy_v10_models import (
    BOB,
    CHARLIE,
    Dummy,
    LegacyFieldHash,
    NoHash,
    TextOps,
    V10Synapse,
)
from tensorwire import crypto
from tensorwire.auth.nonce_store import MemoryNonceStore
from tensorwire.errors import LegacyAuthFailed, LegacyDisabled, ReplayStoreUnavailable
from tensorwire.extensions.legacy_v10 import wire
from tensorwire.extensions.legacy_v10.server import LegacyServer

TODAY = dt.date(2026, 10, 22)
NOW = 1_792_672_891_000_000_000
ALICE_KEY = crypto.keypair_from_uri("//Alice")
ALICE = ALICE_KEY.ss58_address
ALICE_SIGNER = crypto.HotkeySigner(ALICE_KEY)
BOB_SIGNER = crypto.HotkeySigner(crypto.keypair_from_uri("//Bob"))
UUID = "e85a70d0-ce15-11f1-a10f-847b57c7b217"
ALLOWED = (LegacyAuthFailed, LegacyDisabled, ReplayStoreUnavailable)


class Blob(V10Synapse):
    """A Synapse whose hashed field takes any JSON value."""

    data: Any
    out: str | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("data",)


SYNAPSE_CLASSES: list[type[BaseModel]] = [Dummy, TextOps, NoHash, LegacyFieldHash, Blob]

# ------------------------------------------------------------------ strategies

V10_NAMES = [
    "name",
    "timeout",
    "total_size",
    "header_size",
    "computed_body_hash",
    "bt_header_dendrite_hotkey",
    "bt_header_dendrite_nonce",
    "bt_header_dendrite_uuid",
    "bt_header_dendrite_signature",
    "bt_header_dendrite_version",
    "bt_header_dendrite_ip",
    "bt_header_axon_hotkey",
    "bt_header_input_obj_dummy_input",
    "bt_header_input_obj_",
]

header_names = st.one_of(
    st.sampled_from(V10_NAMES),
    st.sampled_from(V10_NAMES).map(str.upper),
    st.text(min_size=1, max_size=12).map(lambda s: "bt_header_" + s),
    st.text(min_size=1, max_size=20),
)
header_values = st.one_of(
    st.text(max_size=80),
    st.sampled_from(
        ["", "0x", "12.0", "nan", "inf", "-1", "1e400", "MA==", "a.b", ALICE, BOB]
    ),
    st.integers(min_value=-(10**25), max_value=10**25).map(str),
    st.binary(min_size=63, max_size=65).map(lambda b: "0x" + b.hex()),
    st.binary(min_size=32, max_size=32).map(lambda b: b.hex()),
    st.binary(max_size=40).map(lambda b: b.hex().upper()),
)
header_lists = st.lists(st.tuples(header_names, header_values), max_size=16)

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=20),
    lambda inner: (
        st.lists(inner, max_size=4)
        | st.dictionaries(st.text(max_size=8), inner, max_size=4)
    ),
    max_leaves=20,
)
FIELD_NAMES = [
    "dummy_input",
    "text",
    "op",
    "count",
    "ratio",
    "tags",
    "weights",
    "flag",
    "maybe",
    "payload",
    "a_field",
    "b_field",
    "data",
    "dendrite",
    "axon",
    "required_hash_fields",
    "name",
    "computed_body_hash",
]
field_names = st.sampled_from(FIELD_NAMES) | st.text(max_size=8)
bodies = st.one_of(
    st.binary(max_size=200),
    st.dictionaries(field_names, json_values, max_size=8).map(
        lambda d: json.dumps(d).encode()
    ),
    json_values.map(lambda v: json.dumps(v).encode()),
    st.integers(min_value=1, max_value=3000).map(
        lambda n: b'{"data":' + b"[" * n + b"]" * n + b"}"
    ),
)

# Values that pydantic accepts for TextOps and that JSON carries unchanged
# (any float, including nan / inf: both json and pydantic accept them).
text_ops = st.builds(
    TextOps,
    text=st.text(max_size=40),
    op=st.text(max_size=12),
    count=st.integers(min_value=-(2**70), max_value=2**70),
    ratio=st.floats(),
    tags=st.lists(st.text(max_size=10), max_size=5),
    weights=st.dictionaries(st.text(max_size=8), st.floats(), max_size=4),
    flag=st.booleans(),
    maybe=st.none() | st.integers(),
)
legacy_field_hash = st.builds(
    LegacyFieldHash, a_field=st.integers(), b_field=st.text(max_size=30)
)
blobs = st.builds(Blob, data=json_values)


# ------------------------------------------------------------------ helpers


class FlakyStore:
    """A replay store that is up or down, as the example says."""

    retention = 60.0

    def __init__(self, down: bool) -> None:
        self.down = down
        self.inner = MemoryNonceStore(60.0)

    def check_and_store(self, hotkey: str, nonce: int) -> bool:
        if self.down:
            raise ReplayStoreUnavailable()
        return self.inner.check_and_store(hotkey, nonce)


def server(
    *, store: Any = None, today: Callable[[], dt.date] = lambda: TODAY
) -> LegacyServer:
    return LegacyServer(
        signer=BOB_SIGNER,
        store=MemoryNonceStore(60.0) if store is None else store,
        until=TODAY + dt.timedelta(days=30),
        external_ip="203.0.113.7",
        external_port=8091,
        now_ns=lambda: NOW,
        today=today,
    )


def encode(
    synapse: BaseModel,
    *,
    signer: crypto.HotkeySigner = ALICE_SIGNER,
    nonce: int = NOW,
    uuid: str = UUID,
) -> wire.EncodedRequest:
    return wire.encode_request(
        synapse,
        signer=signer,
        axon_hotkey=BOB,
        axon_ip="203.0.113.7",
        axon_port=8091,
        nonce=nonce,
        uuid=uuid,
        timeout=12.0,
    )


def verify(
    srv: LegacyServer,
    headers: list[tuple[str, str]],
    body: bytes,
    cls: type[BaseModel],
) -> Any:
    return srv.verify_sync(headers, body, synapse_cls=cls, body_hash=None)


def set_header(
    headers: list[tuple[str, str]], name: str, value: str
) -> list[tuple[str, str]]:
    return [(k, value if k.lower() == name else v) for k, v in headers]


def rule(values: list[Any]) -> str:
    """Spec 8.11.1, written out independently of ``wire.hash_values``."""
    inner = "".join(hashlib.sha3_256(str(v).encode()).hexdigest() for v in values)
    return hashlib.sha3_256(inner.encode()).hexdigest()


# ------------------------------------------------------------------ 1. header parser


@settings(max_examples=500)
@given(headers=header_lists)
def test_header_parser_raises_only_wire_error(headers: list[tuple[str, str]]) -> None:
    try:
        parsed = wire.parse_request_headers(headers)
    except wire.WireError:
        return
    # Whatever got through has the shapes the docstring promises.
    crypto.public_key_from_ss58(parsed.sender)
    assert len(parsed.signature) == 64
    assert len(parsed.computed_body_hash) == 64
    assert "." not in parsed.uuid
    assert 0 < parsed.timeout <= 3600


# ------------------------------------------------------------------ 2. verify


@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
@given(
    headers=header_lists,
    body=bodies,
    cls=st.sampled_from(SYNAPSE_CLASSES),
    native=st.booleans(),
    store_down=st.booleans(),
    disabled=st.booleans(),
)
def test_verify_on_arbitrary_input_only_rejects(
    headers: list[tuple[str, str]],
    body: bytes,
    cls: type[BaseModel],
    native: bool,
    store_down: bool,
    disabled: bool,
) -> None:
    day = [TODAY]
    srv = server(store=FlakyStore(store_down), today=lambda: day[0])
    if disabled:
        day[0] = TODAY + dt.timedelta(days=30)  # the end date itself

    def call() -> Any:
        if native:
            return srv.verify_sync(
                headers,
                body,
                synapse_cls=None,
                body_hash=lambda raw: hashlib.sha3_256(raw).hexdigest(),
            )
        return verify(srv, headers, body, cls)

    with pytest.raises(ALLOWED):
        call()


@st.composite
def mutated_requests(
    draw: st.DrawFn,
) -> tuple[list[tuple[str, str]], bytes, type[BaseModel]]:
    """A valid request, then edits to the signed headers and the body."""
    synapse = draw(st.one_of(text_ops, legacy_field_hash, blobs))
    req = encode(synapse)
    headers = list(req.headers)
    signed = [
        "bt_header_dendrite_hotkey",
        "bt_header_dendrite_nonce",
        "bt_header_dendrite_uuid",
        "bt_header_dendrite_signature",
        "computed_body_hash",
    ]
    for _ in range(draw(st.integers(min_value=1, max_value=3))):
        kind = draw(st.sampled_from(["set", "drop", "dup", "body"]))
        if kind == "body":
            raw = draw(st.binary(max_size=40))
            at = draw(st.integers(min_value=0, max_value=len(req.body)))
            body = req.body[:at] + raw + req.body[at + len(raw) :]
            assume(body != req.body)
            req = wire.EncodedRequest(
                req.path, headers, body, req.computed_body_hash, req.nonce
            )
            continue
        name = draw(st.sampled_from(signed))
        if kind == "set":
            value = draw(header_values)
            assume(value != {k.lower(): v for k, v in headers}.get(name))
            headers = set_header(headers, name, value)
        elif kind == "drop":
            headers = [(k, v) for k, v in headers if k.lower() != name]
        else:
            headers = [*headers, (name.upper(), draw(header_values))]
    return headers, req.body, type(synapse)


@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(case=mutated_requests(), store_down=st.booleans())
def test_verify_on_mutated_valid_requests_only_rejects(
    case: tuple[list[tuple[str, str]], bytes, type[BaseModel]], store_down: bool
) -> None:
    headers, body, cls = case
    srv = server(store=FlakyStore(store_down))
    try:
        verify(srv, headers, body, cls)
    except ALLOWED:
        return
    # Accepted: only a body edit that leaves every hashed value as it was
    # (whitespace, a non-hashed field) may pass; the signed headers are intact.
    parsed = wire.parse_request_headers(headers)
    assert wire.body_hash(wire.decode_request_body(cls, body)) == (
        parsed.computed_body_hash
    )
    assert not store_down


# ------------------------------------------------------------------ 3. body hash


@settings(max_examples=300, deadline=None)
@given(synapse=st.one_of(text_ops, legacy_field_hash, blobs))
def test_body_hash_matches_the_v10_rule(synapse: BaseModel) -> None:
    dumped = synapse.model_dump()
    if isinstance(synapse, TextOps):
        order = list(TextOps.required_hash_fields)
    elif isinstance(synapse, LegacyFieldHash):
        order = ["a_field", "b_field"]  # model order, not the declared list (V4)
    else:
        order = ["data"]
    expected = rule([dumped[name] for name in order])
    assert wire.body_hash(synapse) == expected
    # The receiver computes the same hash from the bytes on the wire.
    req = encode(synapse)
    received = wire.decode_request_body(type(synapse), req.body)
    assert wire.body_hash(received) == expected == req.computed_body_hash
    assert wire.body_hash(NoHash(payload=str(dumped))) == wire.EMPTY_BODY_HASH


# ------------------------------------------------------------------ 4. one change


def other_value(draw: st.DrawFn, synapse: TextOps, field: str) -> Any:
    strategies: dict[str, st.SearchStrategy[Any]] = {
        "text": st.text(max_size=40),
        "op": st.text(max_size=12),
        "count": st.integers(),
        "ratio": st.floats(),
        "tags": st.lists(st.text(max_size=10), max_size=5),
        "weights": st.dictionaries(st.text(max_size=8), st.floats(), max_size=4),
        "flag": st.booleans(),
        "maybe": st.none() | st.integers(),
    }
    old = str(getattr(synapse, field))
    return draw(strategies[field].filter(lambda v: str(v) != old))


@st.composite
def one_change(draw: st.DrawFn) -> tuple[wire.EncodedRequest, wire.EncodedRequest]:
    synapse = draw(text_ops)
    valid = encode(synapse)
    what = draw(
        st.sampled_from(["field", "field+hash", "nonce", "uuid", "hotkey", "receiver"])
    )
    headers = list(valid.headers)
    body = valid.body
    if what in ("field", "field+hash"):
        field = draw(st.sampled_from(TextOps.required_hash_fields))
        data = json.loads(valid.body)
        data[field] = other_value(draw, synapse, field)
        changed = TextOps.model_validate(data)
        body = json.dumps(data).encode()
        if what == "field+hash":
            # The header follows the body; the signature covers the old hash.
            headers = set_header(headers, "computed_body_hash", wire.body_hash(changed))
    elif what == "nonce":
        nonce = draw(
            st.integers(min_value=NOW - 9 * 10**9, max_value=NOW + 10**9).filter(
                lambda n: n != NOW
            )
        )
        headers = set_header(headers, "bt_header_dendrite_nonce", str(nonce))
    elif what == "uuid":
        uuid = draw(
            st.from_regex(r"[0-9A-Za-z-]{1,64}", fullmatch=True).filter(
                lambda u: u != UUID
            )
        )
        headers = set_header(headers, "bt_header_dendrite_uuid", uuid)
    elif what == "hotkey":
        other = draw(
            st.sampled_from([BOB, CHARLIE])
            | st.binary(min_size=32, max_size=32).map(
                lambda key: sp_core.ss58_encode(key, crypto.SS58_FORMAT)
            )
        )
        assume(other != ALICE)
        headers = set_header(headers, "bt_header_dendrite_hotkey", other)
    else:
        # Signed by Alice for Charlie, replayed to Bob.
        foreign = wire.encode_request(
            synapse,
            signer=ALICE_SIGNER,
            axon_hotkey=CHARLIE,
            axon_ip="203.0.113.7",
            axon_port=8091,
            nonce=NOW,
            uuid=UUID,
            timeout=12.0,
        )
        headers, body = list(foreign.headers), foreign.body
    changed_req = wire.EncodedRequest(
        valid.path, headers, body, valid.computed_body_hash, valid.nonce
    )
    note(f"changed: {what}")
    return valid, changed_req


@settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(case=one_change())
def test_any_single_change_is_rejected(
    case: tuple[wire.EncodedRequest, wire.EncodedRequest],
) -> None:
    valid, changed = case
    accepted = verify(server(), valid.headers, valid.body, TextOps)
    assert accepted.caller.hotkey_ss58 == ALICE
    with pytest.raises(LegacyAuthFailed):
        verify(server(), changed.headers, changed.body, TextOps)
