"""auth/signer.py: monotonic nonces (13.2) and receiver-bound signing."""

from __future__ import annotations

import itertools
import threading
from typing import Any

import pytest
from bittensor import http_auth
from bittensor.keyfiles import Keypair
from bittensor.wallets import CRYPTO_ED25519

from tensorwire.auth.signer import MonotonicNonce, RequestSigner

GOLDEN_NONCE = 1752076800000000000
GOLDEN_BODY = b'{"prompt": "hello"}'
GOLDEN_TARGET = "/generate?stream=false"
GOLDEN_ED25519_SIG = (
    "0x1a6b631988bf1f7ea093ab9d5acf61f05c316d0b0e428b24b487b75a5f6ee0e1"
    "a56a26918fdf871b6cf09437e6588023a4ce423cf622621b2a7feee17612f704"
)


def test_nonces_strictly_increase_under_8_threads_x_100k() -> None:
    nonce = MonotonicNonce()
    per_thread: list[list[int]] = [[] for _ in range(8)]
    start = threading.Barrier(8)

    def work(out: list[int]) -> None:
        start.wait()
        for _ in range(100_000):
            out.append(nonce.next())

    threads = [threading.Thread(target=work, args=(out,)) for out in per_thread]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    everything = [n for out in per_thread for n in out]
    assert len(everything) == 800_000
    assert len(set(everything)) == 800_000  # no nonce handed out twice
    for out in per_thread:
        assert all(a < b for a, b in itertools.pairwise(out))  # each caller sees increasing values


def test_frozen_clock_still_increases() -> None:
    nonce = MonotonicNonce(clock_ns=lambda: 1_000)
    assert [nonce.next() for _ in range(3)] == [1_000, 1_001, 1_002]


def test_clock_stepping_back_never_repeats() -> None:
    times = iter([5_000, 4_000, 4_000, 6_000])
    nonce = MonotonicNonce(clock_ns=lambda: next(times))
    assert [nonce.next() for _ in range(4)] == [5_000, 5_001, 5_002, 6_000]


def test_receiver_required(alice: Keypair) -> None:
    signer = RequestSigner(alice)
    with pytest.raises(ValueError, match="receiver is required"):
        signer.sign(method="POST", target="/x", body=b"", receiver_ss58="")


def test_signed_request_verifies(alice: Keypair, bob: Keypair) -> None:
    signer = RequestSigner(alice)
    assert signer.hotkey_ss58 == alice.ss58_address
    headers = signer.sign(
        method="POST", target=GOLDEN_TARGET, body=GOLDEN_BODY, receiver_ss58=bob.ss58_address
    )
    assert headers[http_auth.HEADER_RECEIVER] == bob.ss58_address
    assert http_auth.HEADER_CRYPTO not in headers  # sr25519 sends no crypto header (A7)
    caller = http_auth.verify(
        headers,
        GOLDEN_BODY,
        method="POST",
        path=GOLDEN_TARGET,
        self_hotkey_ss58=bob.ss58_address,
        nonce_store=http_auth.InMemoryNonceStore(),
    )
    assert caller.hotkey_ss58 == alice.ss58_address


def test_each_call_uses_a_fresh_nonce(alice: Keypair, bob: Keypair) -> None:
    signer = RequestSigner(alice, nonce=MonotonicNonce(clock_ns=lambda: GOLDEN_NONCE))
    first = signer.sign(method="POST", target="/x", body=b"", receiver_ss58=bob.ss58_address)
    second = signer.sign(method="POST", target="/x", body=b"", receiver_ss58=bob.ss58_address)
    assert int(second[http_auth.HEADER_NONCE]) == int(first[http_auth.HEADER_NONCE]) + 1


def test_ed25519_golden_vector(bob: Keypair) -> None:
    """Appendix C: the ed25519 signature is deterministic and fixed."""
    alice_ed = Keypair.create_from_uri("//Alice", crypto_type=CRYPTO_ED25519)
    signer = RequestSigner(alice_ed, nonce=MonotonicNonce(clock_ns=lambda: GOLDEN_NONCE))
    assert signer.hotkey_ss58 == "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu"
    headers = signer.sign(
        method="POST", target=GOLDEN_TARGET, body=GOLDEN_BODY, receiver_ss58=bob.ss58_address
    )
    assert headers == {
        "X-Bittensor-Version": "1",
        "X-Bittensor-Hotkey": "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu",
        "X-Bittensor-Nonce": str(GOLDEN_NONCE),
        "X-Bittensor-Signature": GOLDEN_ED25519_SIG,
        "X-Bittensor-Crypto": "ed25519",
        "X-Bittensor-Receiver": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
    }


class _HotkeyOnlyWallet:
    """Wallet-shaped object whose coldkey must never be touched."""

    def __init__(self, hotkey: Keypair) -> None:
        self._hotkey = hotkey

    @property
    def hotkey(self) -> Keypair:
        return self._hotkey

    @property
    def coldkey(self) -> Any:
        raise AssertionError("coldkey accessed")

    @property
    def coldkeypub(self) -> Any:
        raise AssertionError("coldkeypub accessed")


def test_wallet_uses_hotkey_only(alice: Keypair, bob: Keypair) -> None:
    signer = RequestSigner(_HotkeyOnlyWallet(alice))
    assert signer.hotkey_ss58 == alice.ss58_address
    signer.sign(method="GET", target="/", body=b"", receiver_ss58=bob.ss58_address)


class _OddSigner:
    ss58_address = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
    public_key = b"\x00" * 32
    crypto_type = 2  # ecdsa: not a btauth scheme

    def sign(self, payload: bytes) -> bytes:
        return b""


def test_rejects_non_btauth_crypto_type() -> None:
    with pytest.raises(ValueError, match="cannot sign btauth/1"):
        RequestSigner(_OddSigner())
