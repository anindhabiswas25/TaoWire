"""Request signing with strictly increasing nonces (spec 8.4.1).

btauth/1 replay protection keys on ``(hotkey, nonce)``. ``bittensor.http_auth.sign``
uses ``time.time_ns()`` when no nonce is given, which can repeat on coarse
clocks (fact A5), so the kit always passes its own monotonic nonce.

Rule: one validator hotkey = one signing process. Two processes signing with
the same hotkey can produce the same nonce, and the second request is then
rejected as a replay.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from bittensor import http_auth
from bittensor.signing import WalletLike

from tensorwire.crypto import HotkeySigner, public_key_from_ss58

__all__ = ["MonotonicNonce", "RequestSigner"]


class _BtauthSigner:
    """Presents a :class:`HotkeySigner` as a ``bittensor.signing.Signer``.

    ``http_auth.sign`` passes a ``Signer`` straight through, so the SDK never
    inspects the original wallet object (and never reads its coldkey).
    """

    def __init__(self, hotkey: HotkeySigner) -> None:
        self._hotkey = hotkey
        self.ss58_address = hotkey.ss58_address
        self.crypto_type = hotkey.crypto_type
        self.public_key = public_key_from_ss58(hotkey.ss58_address)

    def sign(self, payload: bytes) -> bytes:
        return self._hotkey.sign(payload)


class MonotonicNonce:
    """Strictly increasing nanosecond nonces per process.

    ``time.time_ns()`` can repeat on coarse clocks, so take
    ``max(now, last + 1)``. Thread-safe. If the wall clock steps backwards,
    nonces keep increasing from the last value and catch up with the clock
    once it passes them again.
    """

    def __init__(self, clock_ns: Callable[[], int] = time.time_ns) -> None:
        self._clock_ns = clock_ns
        self._last = 0
        self._lock = threading.Lock()

    def next(self) -> int:
        """Return a nonce larger than every nonce returned before."""
        with self._lock:
            n = max(self._clock_ns(), self._last + 1)
            self._last = n
            return n


class RequestSigner:
    """Signs btauth/1 requests with a hotkey; never sends unbound requests.

    ``wallet`` is anything the SDK accepts as a wallet (a ``bt.Wallet``, a
    keypair, a ``Signer``). Only the **hotkey** is used; the coldkey is never
    touched. The hotkey is loaded at construction so a missing or unreadable
    keyfile fails at startup rather than on the first request.
    """

    def __init__(
        self, wallet: WalletLike, *, nonce: MonotonicNonce | None = None
    ) -> None:
        # HotkeySigner resolves the hotkey only and rejects async signers (fact A6)
        # and schemes other than sr25519/ed25519 (fact A7).
        self._signer = _BtauthSigner(HotkeySigner(wallet))
        self._nonce = MonotonicNonce() if nonce is None else nonce
        #: The SS58 address requests are signed as.
        self.hotkey_ss58: str = self._signer.ss58_address

    def sign(
        self, *, method: str, target: str, body: bytes, receiver_ss58: str
    ) -> dict[str, str]:
        """Return the btauth/1 headers for one attempt of one request.

        ``target`` is the request target exactly as it goes on the wire
        (percent-encoded path plus ``?query``). Call once per attempt: every
        retry needs a fresh nonce.
        """
        if not receiver_ss58:
            raise ValueError("receiver is required")  # never send unbound requests
        return http_auth.sign(
            self._signer,
            method=method,
            path=target,
            body=body,
            receiver_ss58=receiver_ss58,
            nonce_ns=self._nonce.next(),
        )
