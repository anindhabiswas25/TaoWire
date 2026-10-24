"""The sidecar for non-Python miners (spec 11.6): ``taowire sidecar``.

A TypeScript, Go or Rust miner asks this loopback-only service for its caller
policy and its chain writes. The wire contract is the "Sidecar API" section of
``docs/multi-language.md``; the clients are ``@taowire/btauth/sidecar``,
``go/sidecar`` and the Rust ``sidecar`` feature.
"""

from taowire.sidecar.app import MAX_BODY_BYTES, create_app, parse_serve_axon
from taowire.sidecar.server import LOOPBACK_HOSTS, Sidecar
from taowire.sidecar.token import TOKEN_LENGTH, load_or_create_token, token_matches

__all__ = [
    "LOOPBACK_HOSTS",
    "MAX_BODY_BYTES",
    "TOKEN_LENGTH",
    "Sidecar",
    "create_app",
    "load_or_create_token",
    "parse_serve_axon",
    "token_matches",
]
