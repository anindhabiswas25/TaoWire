"""auth/verifier.py: error mapping, retention, thread offload, F2 (8.4.2, A11)."""

from __future__ import annotations

import threading
from typing import Any

import anyio
import pytest
from bittensor import http_auth, sp_core

from tensorwire.auth.nonce_store import MemoryNonceStore
from tensorwire.auth.verifier import RequestVerifier
from tensorwire.errors import AuthFailed, ReplayStoreUnavailable
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.keys import dev_key

ALICE = dev_key("alice")
BOB = dev_key("bob")
TARGET = "/v1/echo?x=1"
BODY = b'{"text":"hi"}'


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def verifier(clock: FakeClock) -> RequestVerifier:
    return RequestVerifier(
        BOB.ss58, MemoryNonceStore(60, clock=clock.monotonic), now_ns=clock.now_ns
    )


def signed(clock: FakeClock, **overrides: Any) -> dict[str, str]:
    signer = (overrides.pop("key", ALICE)).signer(clock_ns=clock.now_ns)
    args: dict[str, Any] = {
        "method": "POST",
        "target": TARGET,
        "body": BODY,
        "receiver_ss58": BOB.ss58,
    }
    args.update(overrides)
    return signer.sign(**args)


def verify(v: RequestVerifier, headers: Any, body: bytes = BODY) -> Any:
    return v.verify_sync(headers, body, method="POST", target=TARGET)


def code(v: RequestVerifier, headers: Any, body: bytes = BODY) -> str:
    with pytest.raises(AuthFailed) as info:
        verify(v, headers, body)
    assert info.value.http_status == 401
    return info.value.code


def alt_encoding(ss58: str, prefix: int) -> str:
    return str(sp_core.ss58_encode(bytes(sp_core.ss58_decode(ss58)), prefix))


# ---------------------------------------------------------------- happy path


@pytest.mark.parametrize("scheme", ["sr25519", "ed25519"])
def test_valid_request_returns_kit_caller(
    verifier: RequestVerifier, clock: FakeClock, scheme: str
) -> None:
    key = dev_key("alice", scheme)  # type: ignore[arg-type]
    caller = verify(verifier, signed(clock, key=key))
    assert caller.hotkey_ss58 == key.ss58
    assert caller.scheme == scheme
    assert caller.nonce_ns >= clock.now_ns()


async def test_verify_runs_in_a_worker_thread(clock: FakeClock) -> None:
    threads: list[int] = []

    class RecordingStore(MemoryNonceStore):
        def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
            threads.append(threading.get_ident())
            return super().check_and_store(hotkey_ss58, nonce_ns)

    limiter = anyio.CapacityLimiter(1)
    v = RequestVerifier(
        BOB.ss58, RecordingStore(60), now_ns=clock.now_ns, limiter=limiter
    )
    caller = await v.verify(signed(clock), BODY, method="POST", target=TARGET)
    assert caller.hotkey_ss58 == ALICE.ss58
    assert threads
    assert threads[0] != threading.get_ident()
    assert limiter.borrowed_tokens == 0
    assert v.self_hotkey == BOB.ss58
    assert isinstance(v.store, RecordingStore)


def test_starlette_style_item_lists_are_accepted(
    verifier: RequestVerifier, clock: FakeClock
) -> None:
    items = [(k.lower(), v) for k, v in signed(clock).items()] + [("accept", "*/*")]
    assert verify(verifier, items).hotkey_ss58 == ALICE.ss58


# ---------------------------------------------------------------- error mapping


def test_missing_headers_are_malformed(verifier: RequestVerifier) -> None:
    assert code(verifier, {}) == "tw.auth_malformed"


def test_wrong_receiver(verifier: RequestVerifier, clock: FakeClock) -> None:
    headers = signed(clock, receiver_ss58=dev_key("eve").ss58)
    assert code(verifier, headers) == "tw.auth_wrong_receiver"


def test_missing_receiver_is_always_rejected(
    verifier: RequestVerifier, clock: FakeClock
) -> None:
    headers = signed(clock)
    del headers[http_auth.HEADER_RECEIVER]
    assert code(verifier, headers) == "tw.auth_wrong_receiver"


@pytest.mark.parametrize("shift_s", [-10.001, 2.001])
def test_stale_and_future_nonces(
    verifier: RequestVerifier, clock: FakeClock, shift_s: float
) -> None:
    headers = signed(clock)
    clock.step_wall(-shift_s)  # the receiver's clock moves the other way
    assert code(verifier, headers) == "tw.auth_stale"


def test_bad_signature_on_tampered_body(
    verifier: RequestVerifier, clock: FakeClock
) -> None:
    assert (
        code(verifier, signed(clock), body=b'{"text":"ho"}') == "tw.auth_bad_signature"
    )


def test_replay(verifier: RequestVerifier, clock: FakeClock) -> None:
    headers = signed(clock)
    verify(verifier, headers)
    assert code(verifier, headers) == "tw.auth_replayed"


def test_unknown_auth_error_subclass_maps_to_generic_code(
    verifier: RequestVerifier, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    class NewAuthError(http_auth.AuthError):
        pass

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise NewAuthError("something new")

    monkeypatch.setattr(http_auth, "verify", boom)
    with pytest.raises(AuthFailed) as info:
        verify(verifier, signed(clock))
    assert info.value.code == "tw.auth_failed"
    assert info.value.public_message == "something new"


def test_replay_store_outage_fails_closed(clock: FakeClock) -> None:
    class DownStore:
        retention = 60.0

        def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
            raise ReplayStoreUnavailable()

    v = RequestVerifier(BOB.ss58, DownStore(), now_ns=clock.now_ns)
    with pytest.raises(ReplayStoreUnavailable) as info:
        verify(v, signed(clock))
    assert info.value.http_status == 503


def test_messages_never_echo_the_signature(
    verifier: RequestVerifier, clock: FakeClock
) -> None:
    headers = signed(clock)
    sig = headers[http_auth.HEADER_SIGNATURE]
    with pytest.raises(AuthFailed) as info:
        verify(verifier, headers, body=b"tampered")
    assert sig not in info.value.public_message
    assert sig.encode() not in info.value.response_body()


# ---------------------------------------------------------------- kit shape checks


@pytest.mark.parametrize("prefix", [0, 2, 7, 63, 64, 1000, 16383])
def test_f2_sender_must_be_prefix_42(
    verifier: RequestVerifier, clock: FakeClock, prefix: int
) -> None:
    alt = alt_encoding(ALICE.ss58, prefix)
    assert alt != ALICE.ss58
    payload = http_auth.build_payload(
        scheme="sr25519",
        method="POST",
        path=TARGET,
        body=BODY,
        nonce_ns=clock.now_ns(),
        sender_ss58=alt,
        receiver_ss58=BOB.ss58,
    )
    headers = {
        http_auth.HEADER_VERSION: "1",
        http_auth.HEADER_HOTKEY: alt,
        http_auth.HEADER_RECEIVER: BOB.ss58,
        http_auth.HEADER_NONCE: str(clock.now_ns()),
        http_auth.HEADER_SIGNATURE: "0x" + bytes(ALICE.keypair.sign(payload)).hex(),
    }
    if prefix < 64:
        # The SDK alone accepts a one-byte alternate prefix (fact A11): the
        # request is genuinely signed, under another address string.
        sdk_caller = http_auth.verify(
            headers,
            BODY,
            method="POST",
            path=TARGET,
            self_hotkey_ss58=BOB.ss58,
            nonce_store=http_auth.InMemoryNonceStore(),
            now_ns=clock.now_ns(),
        )
        assert sdk_caller.hotkey_ss58 == alt
    # The kit refuses it before anything keyed by the address string runs.
    assert code(verifier, headers) == "tw.auth_malformed"
    assert len(verifier.store) == 0  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["not-an-address", "5" * 48, "é" * 48])
def test_undecodable_sender_is_malformed(
    verifier: RequestVerifier, clock: FakeClock, bad: str
) -> None:
    headers = signed(clock)
    headers[http_auth.HEADER_HOTKEY] = bad
    assert code(verifier, headers) == "tw.auth_malformed"


def test_duplicate_auth_headers_are_malformed(
    verifier: RequestVerifier, clock: FakeClock
) -> None:
    headers = list(signed(clock).items())
    headers.append((http_auth.HEADER_HOTKEY.lower(), dev_key("eve").ss58))
    with pytest.raises(AuthFailed, match="duplicate") as info:
        verify(verifier, headers)
    assert info.value.code == "tw.auth_malformed"


def test_duplicate_unrelated_headers_are_fine(
    verifier: RequestVerifier, clock: FakeClock
) -> None:
    headers = [*signed(clock).items(), ("accept", "a"), ("accept", "b")]
    assert verify(verifier, headers).hotkey_ss58 == ALICE.ss58


@pytest.mark.parametrize("nonce", ["+1", " 1", "1_000", "١٢٣", "-5", "1" * 21, ""])
def test_non_canonical_nonce_is_malformed(
    verifier: RequestVerifier, clock: FakeClock, nonce: str
) -> None:
    headers = signed(clock)
    headers[http_auth.HEADER_NONCE] = nonce
    assert code(verifier, headers) == "tw.auth_malformed"


# ---------------------------------------------------------------- construction


def test_retention_shorter_than_window_is_refused() -> None:
    with pytest.raises(ValueError, match="retention too short"):
        RequestVerifier(BOB.ss58, MemoryNonceStore(11.9), max_age=10, allowed_skew=2)
    RequestVerifier(BOB.ss58, MemoryNonceStore(12), max_age=10, allowed_skew=2)


def test_store_without_retention_is_refused() -> None:
    class NoRetention:
        def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
            return True

    with pytest.raises(ValueError, match="retention too short"):
        RequestVerifier(BOB.ss58, NoRetention())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"max_age": 0}, "max_age"),
        ({"max_age": float("nan")}, "max_age"),
        ({"allowed_skew": -1}, "allowed_skew"),
    ],
)
def test_window_must_be_positive(kwargs: dict[str, float], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        RequestVerifier(BOB.ss58, MemoryNonceStore(60), **kwargs)


def test_self_hotkey_must_be_prefix_42() -> None:
    with pytest.raises(ValueError, match="prefix-42"):
        RequestVerifier(alt_encoding(BOB.ss58, 0), MemoryNonceStore(60))


@pytest.mark.parametrize(
    "value", ["1", "0", "ED25519", " ed25519", "sr25519 ", "ecdsa"]
)
def test_crypto_header_must_be_an_exact_scheme_name(
    verifier: RequestVerifier, clock: FakeClock, value: str
) -> None:
    headers = signed(clock)
    headers[http_auth.HEADER_CRYPTO] = value
    assert code(verifier, headers) == "tw.auth_malformed"


def test_explicit_sr25519_crypto_header_is_accepted(
    verifier: RequestVerifier, clock: FakeClock
) -> None:
    headers = signed(clock)
    headers[http_auth.HEADER_CRYPTO] = "sr25519"
    assert verify(verifier, headers).scheme == "sr25519"
