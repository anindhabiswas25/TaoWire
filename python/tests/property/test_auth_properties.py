"""Property tests for btauth/1 on the miner side (spec 13.3).

1. ``RequestVerifier`` never raises anything but kit errors (``TWError``) for
   arbitrary header maps and bodies.
2. Sign then verify succeeds for random method / target / body / nonce, and
   changing any one input makes it fail.
3. Random percent-encoded targets survive client build → server rebuild.
"""

from __future__ import annotations

import asyncio
import contextlib
import string
from typing import Any

import httpx
from bittensor import http_auth
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tensorwire.auth.nonce_store import MemoryNonceStore
from tensorwire.auth.verifier import RequestVerifier
from tensorwire.errors import AuthFailed, TWError
from tensorwire.miner.pipeline import raw_target
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.keys import dev_key

ALICE = dev_key("alice")
ALICE_ED = dev_key("alice", "ed25519")
BOB = dev_key("bob")
NOW_NS = 1_752_076_800_000_000_000

AUTH_NAMES = [
    http_auth.HEADER_VERSION,
    http_auth.HEADER_HOTKEY,
    http_auth.HEADER_RECEIVER,
    http_auth.HEADER_NONCE,
    http_auth.HEADER_CRYPTO,
    http_auth.HEADER_SIGNATURE,
]

header_names = st.one_of(
    st.sampled_from(AUTH_NAMES),
    st.sampled_from([n.lower() for n in AUTH_NAMES]),
    st.text(min_size=1, max_size=20),
)
header_values = st.one_of(
    st.text(max_size=120),
    st.sampled_from(["1", "0x", "ed25519", "sr25519", ALICE.ss58, BOB.ss58]),
    st.integers(min_value=-(10**25), max_value=10**25).map(str),
    st.binary(max_size=64).map(lambda b: "0x" + b.hex()),
)

unreserved = string.ascii_letters + string.digits + "-._~"
segment = st.text(alphabet=unreserved + "!$&'()*+,;=:@", max_size=12).map(
    lambda s: s
) | st.binary(min_size=1, max_size=4).map(lambda b: "".join(f"%{x:02X}" for x in b))
paths = st.lists(segment, min_size=1, max_size=5).map(
    lambda parts: "/" + "/".join(parts)
)
queries = st.one_of(
    st.just(""),
    st.text(alphabet=unreserved + "=&", min_size=1, max_size=20).map(lambda q: "?" + q),
)
targets = st.builds(lambda p, q: p + q, paths, queries)
methods = st.sampled_from(["POST", "GET", "PUT", "DELETE", "PATCH"])
bodies = st.binary(max_size=256)


def verifier(clock: FakeClock) -> RequestVerifier:
    return RequestVerifier(
        BOB.ss58, MemoryNonceStore(60, clock=clock.monotonic), now_ns=clock.now_ns
    )


@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
@given(
    headers=st.dictionaries(header_names, header_values, max_size=8),
    body=bodies,
    method=methods,
    target=targets,
)
def test_verify_only_raises_kit_errors(
    headers: dict[str, str], body: bytes, method: str, target: str
) -> None:
    clock = FakeClock(start_ns=NOW_NS)
    with contextlib.suppress(TWError):
        verifier(clock).verify_sync(headers, body, method=method, target=target)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(
    field=st.sampled_from(AUTH_NAMES),
    value=header_values,
    body=bodies,
)
def test_tampering_with_one_valid_header_only_raises_auth_failed(
    field: str, value: str, body: bytes
) -> None:
    clock = FakeClock(start_ns=NOW_NS)
    headers = ALICE.signer(clock_ns=clock.now_ns).sign(
        method="POST", target="/v1/x", body=body, receiver_ss58=BOB.ss58
    )
    original = headers.get(field)
    headers[field] = value
    try:
        verifier(clock).verify_sync(headers, body, method="POST", target="/v1/x")
    except AuthFailed:
        return
    # Accepted: only possible when nothing that is signed actually changed.
    assert value == original or (
        field == http_auth.HEADER_CRYPTO and value == "sr25519"
    )


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
@given(
    method=methods,
    target=targets,
    body=bodies,
    skew_ms=st.integers(min_value=-9_000, max_value=1_900),
    ed25519=st.booleans(),
    change=st.sampled_from(["none", "method", "target", "body", "nonce", "receiver"]),
)
def test_sign_verify_round_trip_and_single_changes_fail(
    method: str, target: str, body: bytes, skew_ms: int, ed25519: bool, change: str
) -> None:
    clock = FakeClock(start_ns=NOW_NS)
    key = ALICE_ED if ed25519 else ALICE
    sign_clock = FakeClock(start_ns=NOW_NS + skew_ms * 1_000_000)
    headers = key.signer(clock_ns=sign_clock.now_ns).sign(
        method=method, target=target, body=body, receiver_ss58=BOB.ss58
    )
    v = verifier(clock)
    args: dict[str, Any] = {"method": method, "target": target}
    if change == "method":
        args["method"] = "OPTIONS"
    elif change == "target":
        args["target"] = target + ("&" if "?" in target else "?") + "z"
    elif change == "body":
        body += b"\x00"
    elif change == "nonce":
        headers[http_auth.HEADER_NONCE] = str(int(headers[http_auth.HEADER_NONCE]) + 1)
    elif change == "receiver":
        headers[http_auth.HEADER_RECEIVER] = dev_key("eve").ss58
    if change == "none":
        caller = v.verify_sync(headers, body, **args)
        assert caller.hotkey_ss58 == key.ss58
    else:
        try:
            v.verify_sync(headers, body, **args)
        except AuthFailed:
            return
        raise AssertionError(f"changing the {change} was accepted")


async def _round_trip(target: str) -> str:
    seen: list[str] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        seen.append(raw_target(scope))
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://m") as client:
        await client.post("http://m" + target)
    return seen[0]


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
@given(target=targets)
def test_percent_encoded_targets_survive_client_and_server(target: str) -> None:
    sent = httpx.URL("http://m" + target).raw_path.decode("ascii")
    assert asyncio.run(_round_trip(target)) == sent
