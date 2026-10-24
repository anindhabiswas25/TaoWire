#!/usr/bin/env python3
"""Check that the installed ``bittensor`` provides the SDK surface TaoWire uses.

Every item of spec Section 3 is checked against the SDK installed in the
interpreter running this script: names, signatures, constants, and the
behaviours the kit relies on (golden vectors from Appendix C, nonce-store
rules, error mapping, removed symbols). Nothing touches the network or the
user's wallets; temporary files go to a temporary directory.

Usage:
    python scripts/check_sdk_surface.py [--json REPORT.json]

Exit code 0 when every check passes, 1 otherwise. Run it for every SDK
release before listing it as tested (spec 18.3).
"""

from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import importlib
import importlib.metadata
import inspect
import json
import re
import sys
import tempfile
import time
import traceback
from collections.abc import Callable, Iterable, Mapping
from typing import Any

SUPPORTED_RANGE = ((11, 3, 0), (12, 0, 0))
SUPPORTED_PYTHON = ((3, 10), (3, 15))

# Appendix C fixtures.
ALICE_SR = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
ALICE_ED = "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu"
BOB_SR = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
GOLDEN_NONCE = 1752076800000000000
GOLDEN_BODY = b'{"prompt": "hello"}'
GOLDEN_TARGET = "/generate?stream=false"
GOLDEN_BODY_SHA256 = "341c57448e531310fbbe83f44cea2a5e838bd9e8a6b82b269f01d0dbbc23c3cc"
GOLDEN_ED25519_SIGNATURE = (
    "0x1a6b631988bf1f7ea093ab9d5acf61f05c316d0b0e428b24b487b75a5f6ee0e1"
    "a56a26918fdf871b6cf09437e6588023a4ce423cf622621b2a7feee17612f704"
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class CheckFailed(Exception):
    """A check found the SDK different from what the kit expects."""


def expect(condition: object, message: str) -> None:
    """Fail the current check with ``message`` unless ``condition`` holds."""
    if not condition:
        raise CheckFailed(message)


@dataclasses.dataclass(frozen=True)
class Check:
    section: str
    name: str
    func: Callable[[], None]


@dataclasses.dataclass
class Result:
    section: str
    name: str
    ok: bool
    detail: str = ""


CHECKS: list[Check] = []


def check(
    section: str, name: str
) -> Callable[[Callable[[], None]], Callable[[], None]]:
    """Register a check for spec ``section``."""

    def register(func: Callable[[], None]) -> Callable[[], None]:
        CHECKS.append(Check(section, name, func))
        return func

    return register


_METAGRAPH_FIELDS = (
    "netuid", "mechid", "name", "symbol", "block", "tempo", "last_step",
    "blocks_since_last_step", "owner_hotkey", "owner_coldkey", "network_registered_at",
    "num_uids", "max_uids", "price", "moving_price", "identity", "neurons",
    "commitments", "unregistered_commitments", "raw",
)  # fmt: skip
_NEURON_FIELDS = (
    "uid", "hotkey", "coldkey", "active", "validator_permit", "last_update",
    "block_at_registration", "rank", "trust", "consensus", "incentive", "dividends",
    "pruning_score", "emission", "alpha_stake", "tao_stake", "total_stake", "axon",
    "identity", "commitment", "collateral_locked", "collateral_min",
    "collateral_earned",
)  # fmt: skip
_ERROR_CODES = frozenset({
    "insufficient_balance", "insufficient_liquidity", "rate_limited",
    "not_registered", "not_authorized", "already_exists", "not_found",
    "subnet_not_exists", "subtoken_disabled", "disabled", "too_early", "expired",
    "limit_exceeded", "unit_mismatch", "invalid_argument", "policy_violation",
    "internal", "unknown",
})  # fmt: skip


# -- helpers ------------------------------------------------------------------


def _bt() -> Any:
    return importlib.import_module("bittensor")


def _http_auth() -> Any:
    return importlib.import_module("bittensor.http_auth")


def _version_tuple(text: str) -> tuple[int, int, int]:
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", text)
    expect(match is not None, f"unparseable version {text!r}")
    assert match is not None
    major, minor, patch = (int(g) for g in match.groups())
    return major, minor, patch


def _params(func: Callable[..., Any]) -> Mapping[str, inspect.Parameter]:
    return inspect.signature(func).parameters


def expect_params(
    func: Callable[..., Any],
    expected: Iterable[tuple[str, inspect._ParameterKind | None, object]],
    *,
    skip_self: bool = False,
) -> None:
    """Check that ``func`` has each ``(name, kind, default)``.

    ``kind`` ``None`` accepts positional-or-keyword and keyword-only.
    ``default`` ``inspect.Parameter.empty`` means "required"; ``...`` means
    "any default or none".
    """
    params = dict(_params(func))
    if skip_self:
        params.pop("self", None)
    label = getattr(func, "__qualname__", repr(func))
    for name, kind, default in expected:
        expect(name in params, f"{label}: missing parameter {name!r}")
        param = params[name]
        if kind is None:
            expect(
                param.kind in (param.POSITIONAL_OR_KEYWORD, param.KEYWORD_ONLY),
                f"{label}: {name!r} cannot be passed by keyword",
            )
        else:
            expect(
                param.kind == kind,
                f"{label}: {name!r} is {param.kind.name}, expected {kind.name}",
            )
        if default is not ...:
            expect(
                param.default == default,
                f"{label}: {name!r} default is {param.default!r}, expected {default!r}",
            )


def expect_fields(cls: type, names: Iterable[str]) -> None:
    """Check that dataclass ``cls`` has every field in ``names``."""
    expect(dataclasses.is_dataclass(cls), f"{cls.__name__} is not a dataclass")
    have = {f.name for f in dataclasses.fields(cls)}
    missing = [n for n in names if n not in have]
    expect(not missing, f"{cls.__name__} lacks fields {missing}")


def _keypair(uri: str, *, ed25519: bool = False) -> Any:
    keyfiles = importlib.import_module("bittensor.keyfiles")
    if ed25519:
        wallets = importlib.import_module("bittensor.wallets")
        return keyfiles.Keypair.create_from_uri(uri, crypto_type=wallets.CRYPTO_ED25519)
    return keyfiles.Keypair.create_from_uri(uri)


def _golden_payload(scheme: str, sender: str) -> bytes:
    payload: bytes = _http_auth().build_payload(
        scheme=scheme,
        method="POST",
        path=GOLDEN_TARGET,
        body=GOLDEN_BODY,
        nonce_ns=GOLDEN_NONCE,
        sender_ss58=sender,
        receiver_ss58=BOB_SR,
    )
    return payload


class _RecordingStore:
    """A nonce store that records every call."""

    def __init__(self, retention: float = 60.0) -> None:
        self.retention = retention
        self.calls: list[tuple[str, int]] = []
        self._seen: set[tuple[str, int]] = set()

    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        self.calls.append((hotkey_ss58, nonce_ns))
        key = (hotkey_ss58, nonce_ns)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True


def _signed_request(
    *, ed25519: bool = False, nonce_ns: int | None = None
) -> tuple[dict[str, str], bytes]:
    alice = _keypair("//Alice", ed25519=ed25519)
    body = b'{"x": 1}'
    headers: dict[str, str] = _http_auth().sign(
        alice,
        method="POST",
        path="/v1/transform?a=%2F",
        body=body,
        receiver_ss58=BOB_SR,
        nonce_ns=nonce_ns,
    )
    return headers, body


def _verify(headers: Mapping[str, str], body: bytes, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = {
        "method": "POST",
        "path": "/v1/transform?a=%2F",
        "self_hotkey_ss58": BOB_SR,
        "nonce_store": _RecordingStore(),
    }
    kwargs.update(overrides)
    return _http_auth().verify(headers, body, **kwargs)


def _raises(exc_type: type[BaseException], func: Callable[[], object]) -> BaseException:
    try:
        func()
    except exc_type as e:
        return e
    except Exception as e:  # noqa: BLE001 - report the unexpected type
        raise CheckFailed(
            f"expected {exc_type.__name__}, got {type(e).__name__}: {e}"
        ) from None
    raise CheckFailed(f"expected {exc_type.__name__}, nothing was raised")


# -- 3.1 package facts --------------------------------------------------------


@check("3.1", "installed bittensor version is inside the supported range")
def _version_in_range() -> None:
    version = importlib.metadata.version("bittensor")
    low, high = SUPPORTED_RANGE
    expect(
        low <= _version_tuple(version) < high,
        f"bittensor {version} is outside >=11.3.0,<12",
    )


@check("3.1", "Python version is inside >=3.10,<3.15")
def _python_in_range() -> None:
    low, high = SUPPORTED_PYTHON
    expect(
        low <= sys.version_info[:2] < high,
        f"Python {sys.version.split()[0]} unsupported",
    )


@check("3.1", "bittensor-cli and bittensor-wallet are not installed alongside")
def _no_conflicting_packages() -> None:
    for dist in ("bittensor-cli", "bittensor-wallet"):
        try:
            importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            continue
        raise CheckFailed(f"{dist} is installed and conflicts with bittensor 11")


@check("3.1", "the SDK has no HTTP server or client dependency")
def _no_http_dependency() -> None:
    requires = importlib.metadata.requires("bittensor") or []
    base = [r for r in requires if "extra ==" not in r]
    names = {re.split(r"[<>=!~;\[ ]", r, maxsplit=1)[0].lower() for r in base}
    http = names & {"fastapi", "starlette", "uvicorn", "httpx", "aiohttp", "requests"}
    expect(not http, f"bittensor now depends on {sorted(http)}")


# -- 3.2 http_auth ------------------------------------------------------------


@check("3.2", "http_auth constants have the documented values")
def _http_auth_constants() -> None:
    ha = _http_auth()
    expected = {
        "PROTOCOL": "btauth/1",
        "VERSION": "1",
        "HEADER_VERSION": "X-Bittensor-Version",
        "HEADER_HOTKEY": "X-Bittensor-Hotkey",
        "HEADER_RECEIVER": "X-Bittensor-Receiver",
        "HEADER_NONCE": "X-Bittensor-Nonce",
        "HEADER_CRYPTO": "X-Bittensor-Crypto",
        "HEADER_SIGNATURE": "X-Bittensor-Signature",
        "DEFAULT_MAX_AGE": 10.0,
        "DEFAULT_ALLOWED_SKEW": 2.0,
    }
    for name, value in expected.items():
        expect(hasattr(ha, name), f"http_auth.{name} is missing")
        expect(
            getattr(ha, name) == value,
            f"http_auth.{name} = {getattr(ha, name)!r}, expected {value!r}",
        )


@check(
    "3.2",
    "scheme names are exactly sr25519 and ed25519 (A7; mirrored in taowire.crypto)",
)
def _scheme_names() -> None:
    ha = _http_auth()
    sp_core = importlib.import_module("bittensor.sp_core")
    expected = {sp_core.CRYPTO_ED25519: "ed25519", sp_core.CRYPTO_SR25519: "sr25519"}
    expect(
        dict(ha.CRYPTO_TYPE_NAMES) == expected,
        f"CRYPTO_TYPE_NAMES = {ha.CRYPTO_TYPE_NAMES!r}",
    )


@check("3.2", "error classes exist and subclass AuthError, itself a BittensorError")
def _auth_errors() -> None:
    ha = _http_auth()
    result = importlib.import_module("bittensor.result")
    expect(
        issubclass(ha.AuthError, result.BittensorError),
        "AuthError is not a BittensorError",
    )
    for name in (
        "MalformedAuth",
        "WrongReceiver",
        "StaleRequest",
        "ReplayedRequest",
        "BadSignature",
    ):
        expect(
            issubclass(getattr(ha, name), ha.AuthError), f"{name} is not an AuthError"
        )


@check("3.2", "Caller is a frozen dataclass (hotkey_ss58, nonce_ns, crypto_type)")
def _caller_shape() -> None:
    caller = _http_auth().Caller
    expect_fields(caller, ("hotkey_ss58", "nonce_ns", "crypto_type"))
    params = caller.__dataclass_params__
    expect(params.frozen, "Caller is not frozen")


@check("3.2", "NonceStore protocol and InMemoryNonceStore(retention=60.0)")
def _nonce_store_shape() -> None:
    ha = _http_auth()
    expect(
        callable(getattr(ha.NonceStore, "check_and_store", None)),
        "NonceStore.check_and_store missing",
    )
    expect_params(
        ha.InMemoryNonceStore.__init__, [("retention", None, 60.0)], skip_self=True
    )
    store = ha.InMemoryNonceStore(retention=30.0)
    expect(store.retention == 30.0, "InMemoryNonceStore.retention not exposed")
    expect(store.check_and_store(ALICE_SR, 1) is True, "first nonce not accepted")
    expect(store.check_and_store(ALICE_SR, 1) is False, "replayed nonce accepted")


@check("3.2", "build_payload, sign and verify signatures")
def _http_auth_signatures() -> None:
    ha = _http_auth()
    kw = inspect.Parameter.KEYWORD_ONLY
    empty = inspect.Parameter.empty
    expect_params(
        ha.build_payload,
        [
            ("scheme", kw, empty),
            ("method", kw, empty),
            ("path", kw, empty),
            ("body", kw, empty),
            ("nonce_ns", kw, empty),
            ("sender_ss58", kw, empty),
            ("receiver_ss58", kw, empty),
        ],
    )
    expect_params(
        ha.sign,
        [
            ("wallet", None, empty),
            ("method", kw, empty),
            ("path", kw, empty),
            ("body", kw, b""),
            ("receiver_ss58", kw, None),
            ("nonce_ns", kw, None),
        ],
    )
    expect_params(
        ha.verify,
        [
            ("headers", None, empty),
            ("body", None, empty),
            ("method", kw, empty),
            ("path", kw, empty),
            ("self_hotkey_ss58", kw, empty),
            ("max_age", kw, 10.0),
            ("allowed_skew", kw, 2.0),
            ("require_receiver", kw, True),
            ("nonce_store", kw, None),
            ("now_ns", kw, None),
        ],
    )


@check("3.2", "verify and check_and_store are synchronous (A1)")
def _synchronous() -> None:
    ha = _http_auth()
    expect(not inspect.iscoroutinefunction(ha.verify), "verify is a coroutine function")
    expect(not inspect.iscoroutinefunction(ha.sign), "sign is a coroutine function")
    expect(
        not inspect.iscoroutinefunction(ha.InMemoryNonceStore.check_and_store),
        "check_and_store is a coroutine function",
    )


@check("4.2/App. C", "golden sr25519 payload bytes are exact")
def _golden_payload_bytes() -> None:
    expect(
        hashlib.sha256(GOLDEN_BODY).hexdigest() == GOLDEN_BODY_SHA256,
        "body hash fixture",
    )
    expected = "\n".join(
        [
            "btauth/1",
            "sr25519",
            "POST",
            GOLDEN_TARGET,
            GOLDEN_BODY_SHA256,
            str(GOLDEN_NONCE),
            ALICE_SR,
            BOB_SR,
        ]
    ).encode()
    expect(_golden_payload("sr25519", ALICE_SR) == expected, "golden payload differs")
    unbound = _http_auth().build_payload(
        scheme="sr25519",
        method="post",
        path="/a%20b",
        body=b"",
        nonce_ns=1,
        sender_ss58=ALICE_SR,
        receiver_ss58=None,
    )
    expect(
        unbound
        == "\n".join(
            ["btauth/1", "sr25519", "POST", "/a%20b", EMPTY_SHA256, "1", ALICE_SR, "-"]
        ).encode(),
        "method upper-casing, raw target, empty-body hash or '-' receiver differ",
    )


@check("4.5/App. C", "golden ed25519 signature is exact")
def _golden_ed25519() -> None:
    alice = _keypair("//Alice", ed25519=True)
    expect(alice.ss58_address == ALICE_ED, f"//Alice ed25519 is {alice.ss58_address}")
    signature = "0x" + bytes(alice.sign(_golden_payload("ed25519", ALICE_ED))).hex()
    expect(signature == GOLDEN_ED25519_SIGNATURE, f"signature differs: {signature}")


@check("4.5/App. C", "golden sr25519 payload signs and verifies; //Alice address")
def _golden_sr25519() -> None:
    alice = _keypair("//Alice")
    expect(alice.ss58_address == ALICE_SR, f"//Alice is {alice.ss58_address}")
    sp_core = importlib.import_module("bittensor.sp_core")
    payload = _golden_payload("sr25519", ALICE_SR)
    signature = bytes(alice.sign(payload))
    expect(
        sp_core.verify(payload, signature, ALICE_SR, sp_core.CRYPTO_SR25519),
        "verify failed",
    )


@check("3.2", "sign headers: 0x lowercase hex, crypto header only for ed25519 (A7)")
def _sign_headers() -> None:
    ha = _http_auth()
    headers, _ = _signed_request(nonce_ns=GOLDEN_NONCE)
    expect(ha.HEADER_CRYPTO not in headers, "X-Bittensor-Crypto sent for sr25519")
    expect(headers[ha.HEADER_VERSION] == "1", "version header")
    expect(headers[ha.HEADER_HOTKEY] == ALICE_SR, "hotkey header")
    expect(headers[ha.HEADER_RECEIVER] == BOB_SR, "receiver header")
    expect(headers[ha.HEADER_NONCE] == str(GOLDEN_NONCE), "nonce header")
    expect(
        re.fullmatch(r"0x[0-9a-f]{128}", headers[ha.HEADER_SIGNATURE]) is not None,
        "signature format",
    )
    ed_headers, _ = _signed_request(ed25519=True)
    expect(
        ed_headers.get(ha.HEADER_CRYPTO) == "ed25519",
        "X-Bittensor-Crypto missing for ed25519",
    )


@check("3.2", "sign uses time.time_ns() when no nonce is given (A5)")
def _sign_default_nonce() -> None:
    before = time.time_ns()
    headers, _ = _signed_request()
    after = time.time_ns()
    nonce = int(headers[_http_auth().HEADER_NONCE])
    expect(before <= nonce <= after, "default nonce is not the current time in ns")


@check("3.2", "a Keypair can be passed as the wallet to sign and verifies with //Alice")
def _sign_verify_round_trip() -> None:
    headers, body = _signed_request()
    caller = _verify(headers, body)
    expect(caller.hotkey_ss58 == ALICE_SR, "caller hotkey")
    expect(caller.nonce_ns == int(headers[_http_auth().HEADER_NONCE]), "caller nonce")
    expect(caller.crypto_type == 1, "caller crypto type")
    ed_headers, ed_body = _signed_request(ed25519=True)
    expect(_verify(ed_headers, ed_body).crypto_type == 0, "ed25519 caller crypto type")


@check("3.2", "verify accepts header names in any case (A8)")
def _header_case() -> None:
    headers, body = _signed_request()
    _verify({k.upper(): v for k, v in headers.items()}, body)
    _verify({k.lower(): v for k, v in headers.items()}, body)


@check("4.3", "verify maps each failure to its AuthError subclass")
def _error_mapping() -> None:
    ha = _http_auth()
    headers, body = _signed_request()
    missing = dict(headers)
    del missing[ha.HEADER_NONCE]
    _raises(ha.MalformedAuth, lambda: _verify(missing, body))
    _raises(
        ha.MalformedAuth, lambda: _verify({**headers, ha.HEADER_VERSION: "2"}, body)
    )
    _raises(
        ha.MalformedAuth, lambda: _verify({**headers, ha.HEADER_CRYPTO: "ecdsa"}, body)
    )
    _raises(
        ha.MalformedAuth,
        lambda: _verify({**headers, ha.HEADER_SIGNATURE: "0xzz"}, body),
    )
    _raises(ha.WrongReceiver, lambda: _verify(headers, body, self_hotkey_ss58=ALICE_SR))
    unbound = dict(headers)
    del unbound[ha.HEADER_RECEIVER]
    _raises(ha.WrongReceiver, lambda: _verify(unbound, body))
    _raises(ha.BadSignature, lambda: _verify(headers, body + b" "))
    _raises(ha.BadSignature, lambda: _verify(headers, body, path="/v1/transform?a=/"))
    _raises(ha.BadSignature, lambda: _verify(headers, body, method="PUT"))
    store = _RecordingStore()
    _verify(headers, body, nonce_store=store)
    _raises(ha.ReplayedRequest, lambda: _verify(headers, body, nonce_store=store))


@check("3.2", "an ed25519 signature without X-Bittensor-Crypto is not tried as ed25519")
def _declared_scheme_only() -> None:
    ha = _http_auth()
    headers, body = _signed_request(ed25519=True)
    stripped = {k: v for k, v in headers.items() if k != ha.HEADER_CRYPTO}
    _raises(ha.AuthError, lambda: _verify(stripped, body))


@check("3.2", "freshness window uses injectable now_ns (A9)")
def _freshness() -> None:
    ha = _http_auth()
    headers, body = _signed_request(nonce_ns=GOLDEN_NONCE)
    _verify(headers, body, now_ns=GOLDEN_NONCE + 10 * 10**9)
    _raises(
        ha.StaleRequest,
        lambda: _verify(headers, body, now_ns=GOLDEN_NONCE + 11 * 10**9),
    )
    _verify(headers, body, now_ns=GOLDEN_NONCE - 2 * 10**9)
    _raises(
        ha.StaleRequest, lambda: _verify(headers, body, now_ns=GOLDEN_NONCE - 3 * 10**9)
    )


@check("3.2", "verify rejects a store whose retention is shorter than the window (A3)")
def _retention_check() -> None:
    headers, body = _signed_request()
    _raises(
        ValueError,
        lambda: _verify(headers, body, nonce_store=_RecordingStore(retention=11.9)),
    )
    _verify(headers, body, nonce_store=_RecordingStore(retention=12.0))


@check("3.2", "the nonce store is written only after the signature verifies (A4)")
def _store_after_signature() -> None:
    ha = _http_auth()
    headers, body = _signed_request()
    store = _RecordingStore()
    _raises(ha.BadSignature, lambda: _verify(headers, body + b"!", nonce_store=store))
    _raises(
        ha.StaleRequest, lambda: _verify(headers, body, nonce_store=store, now_ns=0)
    )
    expect(not store.calls, "store was consulted before signature verification")
    _verify(headers, body, nonce_store=store)
    expect(len(store.calls) == 1, "store not consulted after a valid signature")


@check("3.2", "without nonce_store, verify uses a module-level store (A2)")
def _global_store() -> None:
    ha = _http_auth()
    headers, body = _signed_request()
    _verify(headers, body, nonce_store=None)
    _raises(ha.ReplayedRequest, lambda: _verify(headers, body, nonce_store=None))


@check("3.2", "<Bytes>-wrapped signatures are accepted by the SDK verifier (A10)")
def _wrapped_accepted() -> None:
    ha = _http_auth()
    alice = _keypair("//Alice")
    nonce = time.time_ns()
    payload = ha.build_payload(
        scheme="sr25519",
        method="POST",
        path="/w",
        body=b"",
        nonce_ns=nonce,
        sender_ss58=ALICE_SR,
        receiver_ss58=BOB_SR,
    )
    signature = bytes(alice.sign(b"<Bytes>" + payload + b"</Bytes>"))
    headers = {
        ha.HEADER_VERSION: "1",
        ha.HEADER_HOTKEY: ALICE_SR,
        ha.HEADER_RECEIVER: BOB_SR,
        ha.HEADER_NONCE: str(nonce),
        ha.HEADER_SIGNATURE: "0x" + signature.hex(),
    }
    _verify(headers, b"", path="/w")


@check("3.2", "error messages never echo the signature")
def _messages_safe() -> None:
    ha = _http_auth()
    headers, body = _signed_request()
    error = _raises(ha.BadSignature, lambda: _verify(headers, body + b"x"))
    signature = headers[ha.HEADER_SIGNATURE]
    expect(signature[2:20] not in str(error), "error message contains the signature")


# -- 3.3 client and reads -----------------------------------------------------


@check(
    "3.3",
    "bt.Subtensor(network, fallback/archive endpoints, retry_forever, policy)",
)
def _subtensor_signature() -> None:
    bt = _bt()
    expect_params(
        bt.Subtensor.__init__,
        [
            ("network", None, "finney"),
            ("fallback_endpoints", None, ...),
            ("archive_endpoints", None, ...),
            ("retry_forever", None, ...),
            ("policy", None, ...),
        ],
        skip_self=True,
    )
    expect(
        hasattr(bt.Subtensor, "__aenter__"),
        "bt.Subtensor is not an async context manager",
    )
    expect(hasattr(bt.Subtensor, "__await__"), "bt.Subtensor is not awaitable")


@check("2/3.3", "network names finney, test, local resolve to the documented endpoints")
def _networks() -> None:
    settings = importlib.import_module("bittensor.settings")
    text = repr(vars(settings))
    for endpoint in (
        "wss://entrypoint-finney.opentensor.ai:443",
        "wss://test.finney.opentensor.ai:443",
        "ws://127.0.0.1:9944",
    ):
        expect(endpoint in text, f"bittensor.settings does not mention {endpoint}")


@check("3.3", "client.block() and client.subnets.metagraph(netuid, commitments=)")
def _client_methods() -> None:
    client = importlib.import_module("bittensor.client").Client
    ns = importlib.import_module("bittensor.namespaces")
    expect(inspect.iscoroutinefunction(client.block), "Client.block is not async")
    for name in ("execute", "plan"):
        expect(
            inspect.iscoroutinefunction(getattr(client, name, None)),
            f"Client.{name} is not async",
        )
    expect_params(
        ns.Subnets.metagraph,
        [
            ("netuid", None, inspect.Parameter.empty),
            ("commitments", inspect.Parameter.KEYWORD_ONLY, ...),
        ],
        skip_self=True,
    )


@check(
    "3.3", "registry reads: neurons.uid, hyperparameters.weights_rate_limit, epochs.*"
)
def _registry_reads() -> None:
    ns = importlib.import_module("bittensor.namespaces")
    wanted = [
        ("Neurons", "uid", ("hotkey_ss58", "netuid")),
        ("Hyperparameters", "weights_rate_limit", ("netuid",)),
        ("Epochs", "blocks_since_last_update", ("netuid", "uid")),
        ("Epochs", "blocks_until_next_epoch", ("netuid",)),
    ]
    for namespace, read, params in wanted:
        cls = getattr(ns, namespace)
        if read in vars(cls):
            func = vars(cls)[read]
        else:
            spec = ns.REGISTRY.get(read)
            expect(spec is not None, f"read {read!r} is not registered")
            expect(
                spec.category == cls._category, f"read {read!r} is not in {namespace}"
            )
            func = spec.fetch
        have = _params(func)
        missing = [p for p in params if p not in have]
        expect(not missing, f"{namespace}.{read} lacks parameters {missing}")


# -- 3.4 metagraph types ------------------------------------------------------


@check("3.4", "Metagraph fields and helpers")
def _metagraph_fields() -> None:
    bt = _bt()
    expect_fields(
        bt.Metagraph,
        _METAGRAPH_FIELDS,
    )
    for helper in (
        "hotkeys",
        "coldkeys",
        "validators",
        "neuron",
        "by_hotkey",
        "__len__",
        "__iter__",
    ):
        expect(hasattr(bt.Metagraph, helper), f"Metagraph.{helper} missing")


@check("3.4", "MetagraphNeuron fields")
def _neuron_fields() -> None:
    expect_fields(
        _bt().MetagraphNeuron,
        _NEURON_FIELDS,
    )


@check(
    "3.4",
    "axon strings: 'a.b.c.d:port', '[v6]:port', None when IP is 0 (private helper)",
)
def _axon_format() -> None:
    metagraph = importlib.import_module("bittensor.metagraph")
    fmt = metagraph._axon_endpoint
    expect(
        fmt({"ip": 3405803783, "port": 8091, "ip_type": 4}) == "203.0.113.7:8091",
        "IPv4 form",
    )
    v6 = int.from_bytes(bytes.fromhex("20010db8000000000000000000000001"), "big")
    expect(
        fmt({"ip": v6, "port": 8091, "ip_type": 6}) == "[2001:db8::1]:8091", "IPv6 form"
    )
    expect(
        fmt({"ip": 0, "port": 8091, "ip_type": 4}) is None, "unserved axon is not None"
    )
    expect(fmt(None) is None, "missing axon is not None")


@check(
    "3.4/8.3",
    "total_stake and alpha_stake are subnet alpha, tao_stake is TAO (private helper)",
)
def _stake_units() -> None:
    metagraph = importlib.import_module("bittensor.metagraph")
    graph = {
        "hotkeys": [ALICE_SR],
        "coldkeys": [BOB_SR],
        "axons": [{"ip": 0, "port": 0, "ip_type": 4, "protocol": 0}],
        "alpha_stake": [2 * 10**9],
        "tao_stake": [3 * 10**9],
        "total_stake": [5 * 10**9],
        "block": 1,
        "tempo": 360,
        "last_step": 0,
        "blocks_since_last_step": 1,
        "owner_hotkey": ALICE_SR,
        "owner_coldkey": BOB_SR,
        "network_registered_at": 0,
    }
    mg = metagraph._build(7, graph, {})
    neuron = mg.neurons[0]
    expect(
        neuron.total_stake.netuid == 7,
        "total_stake is not tagged with the subnet netuid",
    )
    expect(
        neuron.alpha_stake.netuid == 7,
        "alpha_stake is not tagged with the subnet netuid",
    )
    expect(neuron.tao_stake.netuid == 0, "tao_stake is not TAO")
    expect(neuron.total_stake.rao == 5 * 10**9, "total_stake rao")
    expect(
        mg.raw["axons"][0]["protocol"] == 0,
        "raw axon entries no longer carry 'protocol'",
    )


@check("3.4", "Balance: bt.tao(), no bare-float comparison, no TAO/alpha mixing")
def _balance_rules() -> None:
    bt = _bt()
    one = bt.tao(1.0)
    expect(one.rao == 10**9 and one.netuid == 0, "bt.tao(1.0) is not 1e9 rao of TAO")
    expect(bt.Balance.from_rao(10**9).tao == 1.0, "Balance.tao")
    expect(bt.Balance.from_rao(10**9, 3).alpha == 1.0, "Balance.alpha")
    _raises(TypeError, lambda: one < 1.0)
    _raises(bt.UnitMismatchError, lambda: one < bt.Balance.from_rao(1, 3))
    _raises(bt.UnitMismatchError, lambda: bt.Balance.from_rao(1, 3).tao)


# -- 3.5 intents --------------------------------------------------------------


@check("3.5", "intent constructors and defaults")
def _intents() -> None:
    bt = _bt()
    empty = inspect.Parameter.empty
    expect_params(
        bt.ServeAxon,
        [
            ("netuid", None, empty),
            ("ip", None, empty),
            ("port", None, empty),
            ("protocol", None, 4),
            ("version", None, 1),
        ],
    )
    expect_params(
        bt.ServeAxonTls,
        [
            ("netuid", None, empty),
            ("ip", None, empty),
            ("port", None, empty),
            ("certificate", None, empty),
            ("protocol", None, 4),
            ("version", None, 1),
        ],
    )
    expect_params(
        bt.SetWeights,
        [
            ("netuid", None, empty),
            ("uids", None, None),
            ("weights", None, None),
            ("mechid", None, 0),
            ("version_key", None, 0),
            ("raw_u16", None, False),
        ],
    )
    expect_params(
        bt.BurnedRegister, [("netuid", None, empty), ("hotkey_ss58", None, None)]
    )


@check("3.5", "SetWeights accepts a {uid: weight} mapping")
def _set_weights_mapping() -> None:
    intent = _bt().SetWeights(netuid=2, weights={3: 0.25, 1: 0.75})
    expect(
        sorted(zip(intent.uids, intent.weights, strict=True)) == [(1, 0.75), (3, 0.25)],
        "mapping not split into uids/weights",
    )


@check(
    "3.5/8.7.2",
    "on-chain serve_axon 'protocol' is a u8: TW_PROTOCOL_TAG must be 0..255",
)
def _protocol_is_u8() -> None:
    calls = importlib.import_module("bittensor._generated.calls")
    holder = next(
        (
            obj
            for obj in vars(calls).values()
            if inspect.isclass(obj) and hasattr(obj, "serve_axon")
        ),
        None,
    )
    if holder is None:
        raise CheckFailed("generated serve_axon call not found")
    annotation = _params(holder.serve_axon)["protocol"].annotation
    expect(
        annotation in ("u8", "'u8'"), f"serve_axon protocol is {annotation!r}, not u8"
    )


@check("3.5", "ErrorCode values")
def _error_codes() -> None:
    expected = _ERROR_CODES
    have = {e.value for e in _bt().ErrorCode}
    expect(expected <= have, f"ErrorCode lacks {sorted(expected - have)}")
    expect(
        have <= expected,
        f"ErrorCode has new values {sorted(have - expected)}: update Appendix A",
    )


@check("3.5", "ExtrinsicResult fields and ChainError.code/.remediation")
def _extrinsic_result() -> None:
    result = importlib.import_module("bittensor.result")
    expect_fields(
        result.ExtrinsicResult, ("success", "error", "block_hash", "explorer_url")
    )
    error = result.ChainError("SettingWeightsTooFast", "SettingWeightsTooFast")
    expect(
        error.code.value == "rate_limited",
        f"SettingWeightsTooFast classified as {error.code}",
    )
    expect(
        isinstance(error.remediation, str) and error.remediation, "remediation empty"
    )


# -- 3.6 wallet and keys ------------------------------------------------------


@check("3.6", "bt.Wallet(name, hotkey, path); hotkey loads without any coldkey file")
def _wallet_hotkey_only() -> None:
    bt = _bt()
    expect_params(
        bt.Wallet.__init__,
        [("name", None, "default"), ("hotkey", None, "default"), ("path", None, ...)],
        skip_self=True,
    )
    signing = importlib.import_module("bittensor.signing")
    with tempfile.TemporaryDirectory() as path:
        bt.Wallet(name="probe", hotkey="hk", path=path).create_new_hotkey(
            use_password=False, overwrite=True, suppress=True
        )
        wallet = bt.Wallet(name="probe", hotkey="hk", path=path)
        address = wallet.hotkey.ss58_address
        signer = signing.resolve_signer(wallet, role="hotkey")
        expect(signer.ss58_address == address, "resolve_signer(role='hotkey') address")
        expect(len(bytes(signer.sign(b"x"))) == 64, "hotkey signer signature length")
        _raises(FileNotFoundError, lambda: wallet.coldkey)


@check(
    "3.6",
    "signing.resolve_signer(role=) and sp_core.verify(payload, sig, ss58, crypto_type)",
)
def _signing_primitives() -> None:
    signing = importlib.import_module("bittensor.signing")
    sp_core = importlib.import_module("bittensor.sp_core")
    expect_params(
        signing.resolve_signer,
        [("wallet", None, inspect.Parameter.empty), ("role", None, "coldkey")],
    )
    alice = _keypair("//Alice")
    expect(
        signing.resolve_signer(alice, role="hotkey") is alice,
        "a Keypair is not passed through",
    )
    signature = bytes(alice.sign(b"m"))
    expect(
        sp_core.verify(b"m", signature, ALICE_SR, sp_core.CRYPTO_SR25519) is True,
        "sp_core.verify",
    )
    expect(
        sp_core.verify(b"n", signature, ALICE_SR, sp_core.CRYPTO_SR25519) is False,
        "sp_core.verify false",
    )
    _raises(
        ValueError,
        lambda: sp_core.verify(b"m", signature[:10], ALICE_SR, sp_core.CRYPTO_SR25519),
    )
    _raises(
        ValueError,
        lambda: sp_core.verify(b"m", signature, "5bad", sp_core.CRYPTO_SR25519),
    )
    expect(sp_core.ss58_decode(ALICE_SR).hex().startswith("d43593c7"), "ss58_decode")
    expect(
        sp_core.ss58_encode(sp_core.ss58_decode(ALICE_SR), 42) == ALICE_SR,
        "ss58_encode",
    )


@check("3.6", "test keys: keyfiles.Keypair.create_from_uri and wallets.CRYPTO_ED25519")
def _test_keys() -> None:
    wallets = importlib.import_module("bittensor.wallets")
    sp_core = importlib.import_module("bittensor.sp_core")
    expect(
        wallets.CRYPTO_ED25519 == sp_core.CRYPTO_ED25519 == 0, "CRYPTO_ED25519 is not 0"
    )
    expect(sp_core.CRYPTO_SR25519 == 1, "CRYPTO_SR25519 is not 1")
    expect(_keypair("//Bob").ss58_address == BOB_SR, "//Bob address")


# -- 3.7 timelock -------------------------------------------------------------


@check(
    "3.7",
    "timelock: local encrypt, Timelocked fields, parse, TimelockNotReady when early",
)
def _timelock() -> None:
    bt = _bt()
    for name in ("encrypt", "decrypt", "current_round"):
        expect(
            callable(getattr(bt.timelock, name, None)), f"bt.timelock.{name} missing"
        )
    expect_params(
        bt.timelock.encrypt,
        [
            ("reveal_in", None, None),
            ("reveal_at", inspect.Parameter.KEYWORD_ONLY, None),
            ("reveal_round", inspect.Parameter.KEYWORD_ONLY, None),
        ],
    )
    expect_params(
        bt.timelock.decrypt,
        [
            ("wait", inspect.Parameter.KEYWORD_ONLY, False),
            ("timeout", inspect.Parameter.KEYWORD_ONLY, None),
        ],
    )
    sealed = bt.timelock.encrypt(b"payload", reveal_in="1h")
    expect(isinstance(sealed, bt.Timelocked), "encrypt does not return Timelocked")
    expect(sealed.revealed is False, "sealed.revealed")
    expect(
        isinstance(sealed.reveal_round, int) and sealed.reveal_at is not None,
        "reveal fields",
    )
    expect(
        bt.Timelocked.parse(sealed.hex()).reveal_round == sealed.reveal_round,
        "parse(hex)",
    )
    _raises(bt.TimelockNotReady, lambda: bt.timelock.decrypt(sealed, wait=False))


# -- 3.8 removed names --------------------------------------------------------


@check("3.8", "removed v10 names raise AttributeError naming the replacement")
def _removed() -> None:
    bt = _bt()
    for name in (
        "Axon", "Dendrite", "Synapse", "StreamingSynapse", "SubnetsAPI", "Tensor",
        "AsyncSubtensor", "MockSubtensor", "Config", "logging", "Keypair",
    ):  # fmt: skip
        error = _raises(AttributeError, functools.partial(getattr, bt, name))
        expect(
            "removed" in str(error),
            f"bt.{name} error does not explain the removal: {error}",
        )
    _raises(
        ModuleNotFoundError,
        lambda: importlib.import_module("bittensor.utils.weight_utils"),
    )


# -- runner -------------------------------------------------------------------


def run() -> list[Result]:
    """Run every registered check and return the results."""
    results = []
    for item in CHECKS:
        try:
            item.func()
        except CheckFailed as e:
            results.append(Result(item.section, item.name, False, str(e)))
        except Exception as e:  # noqa: BLE001 - one broken check must not stop the report
            detail = f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}"
            results.append(Result(item.section, item.name, False, detail))
        else:
            results.append(Result(item.section, item.name, True))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", metavar="PATH", help="also write a JSON report")
    args = parser.parse_args(argv)
    try:
        version = importlib.metadata.version("bittensor")
    except importlib.metadata.PackageNotFoundError:
        print("bittensor is not installed in this interpreter", file=sys.stderr)
        return 1
    results = run()
    failed = [r for r in results if not r.ok]
    print(
        f"bittensor {version} · Python {sys.version.split()[0]} · {len(results)} checks"
    )
    for r in results:
        print(f"  {'PASS' if r.ok else 'FAIL'}  [{r.section}] {r.name}")
        if not r.ok:
            for line in r.detail.rstrip().splitlines():
                print(f"          {line}")
    print(f"{len(results) - len(failed)} passed, {len(failed)} failed")
    if args.json:
        report = {
            "bittensor": version,
            "python": sys.version.split()[0],
            "passed": len(results) - len(failed),
            "failed": len(failed),
            "checks": [dataclasses.asdict(r) for r in results],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
