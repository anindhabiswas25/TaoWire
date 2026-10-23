"""auth/verifier.py: error mapping, retention, thread offload, F2 (8.4.2, A11)."""

from __future__ import annotations

import threading
import time
from typing import Any

import anyio
import fakeredis
import pytest
from bittensor import http_auth, sp_core

from tensorwire.auth.nonce_store import MemoryNonceStore, RedisNonceStore
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


def test_huge_sender_is_refused_before_decoding(
    verifier: RequestVerifier, clock: FakeClock
) -> None:
    """G4-2 (D19): base58 decoding is quadratic and runs before authentication."""
    headers = signed(clock)
    headers[http_auth.HEADER_HOTKEY] = "z" * 64 * 1024
    start = time.perf_counter()
    assert code(verifier, headers) == "tw.auth_malformed"
    assert time.perf_counter() - start < 0.05
    assert len(verifier.store) == 0  # type: ignore[arg-type]


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


@pytest.mark.parametrize(
    "mangle",
    [
        lambda sig: sig[:10] + " " + sig[10:],
        lambda sig: sig + " ",
        lambda sig: sig[:10] + "\t" + sig[10:],
        lambda sig: "0X" + sig[2:],
    ],
    ids=["inner-space", "trailing-space", "tab", "0X"],
)
def test_signature_must_be_hex_digits_only(
    verifier: RequestVerifier, clock: FakeClock, mangle: Any
) -> None:
    """``bytes.fromhex`` in the SDK skips whitespace; the kit does not (4.3 step 1)."""
    headers = signed(clock)
    headers[http_auth.HEADER_SIGNATURE] = mangle(headers[http_auth.HEADER_SIGNATURE])
    with pytest.raises(AuthFailed, match="not hex") as info:
        verify(verifier, headers)
    assert info.value.code == "tw.auth_malformed"


def test_upper_case_hex_and_no_prefix_are_accepted(
    verifier: RequestVerifier, clock: FakeClock
) -> None:
    headers = signed(clock)
    headers[http_auth.HEADER_SIGNATURE] = headers[http_auth.HEADER_SIGNATURE][
        2:
    ].upper()
    assert verify(verifier, headers).hotkey_ss58 == ALICE.ss58


class _CountingStore(MemoryNonceStore):
    def __init__(self) -> None:
        super().__init__(60)
        self.calls = 0

    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        self.calls += 1
        return super().check_and_store(hotkey_ss58, nonce_ns)


def _sdk_accepts(headers: dict[str, str], clock: FakeClock) -> bool:
    return bool(
        http_auth.verify(
            headers,
            BODY,
            method="POST",
            path=TARGET,
            self_hotkey_ss58=BOB.ss58,
            nonce_store=MemoryNonceStore(60),
            now_ns=clock.now_ns(),
        )
    )


@pytest.mark.parametrize(
    ("scheme", "public_key", "signature"),
    [
        ("sr25519", bytes(32), bytes(63) + b"\x80"),
        ("ed25519", b"\x01" + bytes(31), b"\x01" + bytes(63)),
    ],
)
def test_weak_key_universal_signature_is_refused_before_the_store(
    clock: FakeClock, scheme: str, public_key: bytes, signature: bytes
) -> None:
    """The SDK accepts these; the kit refuses them as a bad signature (D20)."""
    store = _CountingStore()
    verifier = RequestVerifier(BOB.ss58, store, now_ns=clock.now_ns)
    sender = str(sp_core.ss58_encode(public_key, 42))
    headers = {
        http_auth.HEADER_VERSION: "1",
        http_auth.HEADER_HOTKEY: sender,
        http_auth.HEADER_RECEIVER: BOB.ss58,
        http_auth.HEADER_NONCE: str(clock.now_ns()),
        http_auth.HEADER_SIGNATURE: "0x" + signature.hex(),
    }
    if scheme == "ed25519":
        headers[http_auth.HEADER_CRYPTO] = "ed25519"
    assert _sdk_accepts(headers, clock)  # the SDK alone accepts it
    assert code(verifier, headers) == "tw.auth_bad_signature"
    assert store.calls == 0


@pytest.mark.parametrize("scheme", ["sr25519", "ed25519"])
def test_bytes_wrapped_signature_is_refused_before_the_store(
    clock: FakeClock, scheme: str
) -> None:
    """D22 (A10, 11.7): the Python verifier is strict on ``<Bytes>`` too."""
    key = dev_key("alice", scheme)
    store = _CountingStore()
    verifier = RequestVerifier(BOB.ss58, store, now_ns=clock.now_ns)
    nonce = clock.now_ns()
    payload = http_auth.build_payload(
        scheme=scheme,
        method="POST",
        path=TARGET,
        body=BODY,
        nonce_ns=nonce,
        sender_ss58=key.ss58,
        receiver_ss58=BOB.ss58,
    )
    wrapped = bytes(key.keypair.sign(b"<Bytes>" + payload + b"</Bytes>"))
    headers = {
        http_auth.HEADER_VERSION: "1",
        http_auth.HEADER_HOTKEY: key.ss58,
        http_auth.HEADER_RECEIVER: BOB.ss58,
        http_auth.HEADER_NONCE: str(nonce),
        http_auth.HEADER_SIGNATURE: "0x" + wrapped.hex(),
        http_auth.HEADER_CRYPTO: scheme,
    }
    assert _sdk_accepts(headers, clock)  # the SDK alone accepts it (fact A10)
    with pytest.raises(AuthFailed) as info:
        verify(verifier, headers)
    assert info.value.code == "tw.auth_bad_signature"
    assert "Bytes" not in str(info.value)
    assert store.calls == 0


@pytest.mark.parametrize("scheme", ["sr25519", "ed25519"])
def test_real_keys_still_reach_the_store(clock: FakeClock, scheme: str) -> None:
    store = _CountingStore()
    verifier = RequestVerifier(BOB.ss58, store, now_ns=clock.now_ns)
    caller = verify(verifier, signed(clock, key=dev_key("alice", scheme)))
    assert caller.scheme == scheme
    assert store.calls == 1


# ---------------------------------------------------------------- construction


def test_retention_shorter_than_twice_the_window_is_refused() -> None:
    # spec 8.4.3, D21: retention >= 2 x (max_age + allowed_skew), any store.
    with pytest.raises(ValueError, match="retention too short"):
        RequestVerifier(BOB.ss58, MemoryNonceStore(23.9), max_age=10, allowed_skew=2)
    with pytest.raises(ValueError, match="retention too short"):
        RequestVerifier(BOB.ss58, MemoryNonceStore(12), max_age=10, allowed_skew=2)
    redis_store = RedisNonceStore(
        "redis://unused", retention=23.9, client=fakeredis.FakeRedis()
    )
    with pytest.raises(ValueError, match="retention too short"):
        RequestVerifier(BOB.ss58, redis_store, max_age=10, allowed_skew=2)
    RequestVerifier(BOB.ss58, MemoryNonceStore(24), max_age=10, allowed_skew=2)


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
