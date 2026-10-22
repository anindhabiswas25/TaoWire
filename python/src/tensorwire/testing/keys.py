"""Deterministic test keys (spec 8.13).

The well-known Substrate development accounts (``//Alice`` ... ``//Eve``) in
sr25519 and ed25519. Their seeds are public: use them in tests and on
localnet only. Nothing here reads or writes ``~/.bittensor``.

A :class:`DevKey` can be passed anywhere the SDK or the kit expects a
wallet (its ``keypair``), and can sign btauth/1 requests directly::

    alice = dev_key("alice")
    headers = alice.signer().sign(method="POST", target="/v1/x", body=b"{}",
                                  receiver_ss58=dev_key("bob").ss58)
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from tensorwire.auth.signer import MonotonicNonce, RequestSigner
from tensorwire.crypto import CRYPTO_ED25519, CRYPTO_SR25519, Keypair, keypair_from_uri

__all__ = ["DEV_NAMES", "DevKey", "Scheme", "dev_key"]

DEV_NAMES = ("alice", "bob", "charlie", "dave", "eve")
"""The development accounts available through :func:`dev_key`."""

Scheme = Literal["sr25519", "ed25519"]


@dataclass(frozen=True)
class DevKey:
    """One development keypair."""

    name: str
    scheme: Scheme
    keypair: Keypair

    @property
    def ss58(self) -> str:
        """The SS58 address (prefix 42)."""
        return str(self.keypair.ss58_address)

    def signer(self, *, clock_ns: Callable[[], int] | None = None) -> RequestSigner:
        """A btauth/1 request signer for this key.

        ``clock_ns`` sets the nonce clock (pass ``FakeClock.now_ns`` in
        freshness tests); nonces still strictly increase.
        """
        nonce = None if clock_ns is None else MonotonicNonce(clock_ns)
        return RequestSigner(self.keypair, nonce=nonce)


@functools.cache
def dev_key(name: str, scheme: Scheme = "sr25519") -> DevKey:
    """The development key ``//<Name>`` (``alice`` ... ``eve``) in ``scheme``."""
    if name not in DEV_NAMES:
        raise ValueError(
            f"unknown test key {name!r}; use one of {', '.join(DEV_NAMES)}"
        )
    if scheme not in ("sr25519", "ed25519"):
        raise ValueError(f"unsupported scheme {scheme!r}")
    crypto_type = CRYPTO_ED25519 if scheme == "ed25519" else CRYPTO_SR25519
    keypair = keypair_from_uri(f"//{name.capitalize()}", crypto_type=crypto_type)
    return DevKey(name=name, scheme=scheme, keypair=keypair)
