"""What the MCP server knows without touching the network.

Error codes come from :mod:`taowire.errors` (spec Appendix A) with a cause
and a fix for each; settings come from the :mod:`taowire.config` models with
the comments of the bundled ``.env.example``; docs are the Markdown files
bundled under ``data/docs`` (``scripts/sync_mcp_data.py`` copies them from
the repository's ``docs/``).
"""

from __future__ import annotations

import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import TYPE_CHECKING, Any, Literal

from pydantic.fields import FieldInfo

from taowire.config import (
    ENV_PREFIX,
    CommonSettings,
    MinerSettings,
    SidecarSettings,
    ValidatorSettings,
)
from taowire.errors import CLIENT_ERROR_CODES, ERROR_CODES

if TYPE_CHECKING:
    if sys.version_info >= (3, 11):
        from importlib.resources.abc import Traversable
    else:
        from importlib.abc import Traversable

__all__ = [
    "ERROR_HINTS",
    "Doc",
    "ErrorExplanation",
    "Role",
    "SettingInfo",
    "doc_names",
    "explain_error",
    "list_settings",
    "read_doc",
    "search_docs",
]

Role = Literal["common", "miner", "validator", "sidecar"]

_MODELS: Mapping[Role, type[CommonSettings]] = {
    "common": CommonSettings,
    "miner": MinerSettings,
    "validator": ValidatorSettings,
    "sidecar": SidecarSettings,
}

#: ``code -> (where it comes from, likely cause, how to fix it)``. Every code of
#: :data:`taowire.errors.ERROR_CODES` and ``CLIENT_ERROR_CODES`` has a row
#: (tests/unit/test_mcp_knowledge.py checks it).
ERROR_HINTS: Mapping[str, tuple[str, str, str]] = {
    "tw.internal": (
        "miner",
        "An unexpected error inside the kit (not your handler).",
        "Read the miner's log for the traceback; report it as a GitHub issue.",
    ),
    "tw.config_invalid": (
        "miner",
        "The process started with settings the kit refuses at runtime.",
        "Run `taowire doctor --role miner`; it names the setting to fix.",
    ),
    "tw.rate_limited": (
        "miner",
        "The caller's IP bucket (before auth, not signed) or hotkey bucket "
        "(after auth, signed) is empty; the response carries Retry-After.",
        "Wait for Retry-After. Raise TW_RATE_IP_PER_S / TW_RATE_IP_BURST or "
        "TW_RATE_HOTKEY_PER_S / TW_RATE_HOTKEY_BURST only if the traffic is "
        "legitimate. On streaming routes, TW_STREAM_MAX_PER_CALLER caps open streams.",
    ),
    "tw.payload_too_large": (
        "miner",
        "The request body is over the size limit (checked before auth).",
        "Send less, or raise TW_MAX_BODY_BYTES (or the route's max_body_bytes).",
    ),
    "tw.auth_failed": (
        "miner",
        "Generic btauth/1 failure not covered by a more specific code.",
        "Sign every request with the kit's client (or a btauth/1 library) and "
        "use inspect_request on a captured request to see which step fails.",
    ),
    "tw.auth_malformed": (
        "miner",
        "The X-Bittensor-* headers have the wrong shape: a missing or duplicate "
        "header, a sender that is not a 48-character SS58 prefix-42 address, a "
        "nonce that is not plain digits, an unknown crypto value or a "
        "non-hex signature.",
        "Use inspect_request on the request; it names the bad header.",
    ),
    "tw.auth_wrong_receiver": (
        "miner",
        "X-Bittensor-Receiver is not this miner's hotkey: the request was "
        "signed for another miner (or forwarded).",
        "Sign each request for the hotkey of the miner you send it to; check "
        "the axon you looked up belongs to that hotkey.",
    ),
    "tw.auth_stale": (
        "miner",
        "The nonce (a nanosecond timestamp) is older than the max age (10 s by "
        "default) or too far in the future: a slow or retried request, or a "
        "clock that is off on either side.",
        "Sync both clocks (NTP; `taowire doctor` checks the offset), sign a "
        "fresh request per attempt, and keep queues short. TW_AUTH_MAX_AGE_S "
        "and TW_AUTH_ALLOWED_SKEW_S tune the window.",
    ),
    "tw.auth_bad_signature": (
        "miner",
        "The signature does not verify for the claimed hotkey over the 8-line "
        "payload: the body, method or target changed after signing, the wrong "
        "key signed, a weak key, or a <Bytes>-wrapped (signRaw) signature.",
        "Sign the exact bytes you send, with the exact path and query; do not "
        "re-serialize JSON after signing. inspect_request shows the payload.",
    ),
    "tw.auth_replayed": (
        "miner",
        "This (hotkey, nonce) pair was already accepted: a resent request.",
        "Sign again for every retry (the kit's client does). With several "
        "workers or instances, TW_REDIS_URL must point at one shared Redis.",
    ),
    "tw.forbidden_denied": (
        "miner",
        "The caller is on TW_DENY_HOTKEYS.",
        "Remove the hotkey from TW_DENY_HOTKEYS if that is a mistake.",
    ),
    "tw.forbidden_not_registered": (
        "miner",
        "The caller's hotkey is not registered on this subnet (not in the metagraph).",
        "Register the hotkey on the subnet (btcli), or check TW_NETUID and "
        "TW_NETWORK point at the same subnet on both sides.",
    ),
    "tw.forbidden_not_validator": (
        "miner",
        "The caller is registered but has no validator permit.",
        "Stake enough for a validator permit (the subnet's top hotkeys by stake), "
        "or allow "
        "non-validators on that route with TW_REQUIRE_PERMIT=0 or a route policy.",
    ),
    "tw.forbidden_low_stake": (
        "miner",
        "The caller's stake is below TW_MIN_CALLER_STAKE_TAO.",
        "Add stake, or lower TW_MIN_CALLER_STAKE_TAO.",
    ),
    "tw.forbidden_blacklisted": (
        "miner",
        "A compat (v10-style) blacklist_fn returned True for this caller.",
        "Check the subnet's blacklist function.",
    ),
    "tw.invalid_request": (
        "miner",
        "The body is not valid for the route's request model (pydantic).",
        "Send JSON matching the route's request model; the miner log has the field.",
    ),
    "tw.handler_error": (
        "miner",
        "Your route handler raised an exception.",
        "Read the miner log for the traceback and fix the handler.",
    ),
    "tw.handler_timeout": (
        "miner",
        "Your handler ran longer than its timeout.",
        "Make the handler faster, or raise the route's timeout_s / "
        "TW_HANDLER_TIMEOUT_S "
        "(keep it below the validator's TW_QUERY_TIMEOUT_S).",
    ),
    "tw.metagraph_stale": (
        "miner",
        "The miner's metagraph snapshot is older than its max age (the chain "
        "was unreachable), and the caller had not been verified before; or "
        "TW_METAGRAPH_STRICT=1.",
        "Restore chain access (TW_NETWORK / TW_CHAIN_FALLBACKS, own lite node); "
        "the miner recovers on the next refresh.",
    ),
    "tw.replay_store_unavailable": (
        "miner",
        "The shared replay store (Redis) is unreachable or timed out, or the "
        "wall clock stepped backwards; the miner fails closed.",
        "Check TW_REDIS_URL and that Redis is up and close to the miner; check NTP.",
    ),
    "tw.legacy_auth_failed": (
        "miner",
        "A v10 (Dendrite) request failed the bridge's signature, hash, "
        "freshness or replay check, or did not parse into the route's Synapse.",
        "Check the v10 caller's clock and Synapse shape; see "
        "read_doc('protocol/legacy-v10').",
    ),
    "tw.legacy_disabled": (
        "miner",
        "A v10 request arrived after TW_LEGACY_V10_UNTIL: the bridge has ended.",
        "Move the caller to btauth/1 (taowire migrate), or extend the end date "
        "(at most 180 days ahead).",
    ),
    "tw.sidecar_unauthorized": (
        "sidecar",
        "A sidecar request without exactly `Authorization: Bearer <token>`.",
        "Read the token from TW_SIDECAR_TOKEN_FILE (mode 0600) in the miner and "
        "send it on every sidecar call.",
    ),
    "tw.timeout": (
        "validator",
        "The miner did not answer within the query's time budget.",
        "Check the miner is up and reachable; raise TW_QUERY_TIMEOUT_S if the "
        "task is slow.",
    ),
    "tw.connect_error": (
        "validator",
        "No connection to the miner's published axon.",
        "Check the miner's TW_EXTERNAL_IP / port, its firewall, and that it "
        "is running.",
    ),
    "tw.bad_response_signature": (
        "validator",
        "The answer's twresp/1 signature is missing or invalid, or does not "
        "bind this request's nonce and sender, or a stream ended without a "
        "valid tw-end. Scoring counts it as a failed answer.",
        "Keep TW_SIGN_RESPONSES=1 on the miner and do not change the body after "
        "the handler; inspect_response shows which part fails.",
    ),
    "tw.response_too_large": (
        "validator",
        "The miner's answer is over TW_MAX_RESPONSE_BYTES.",
        "Return less, or raise TW_MAX_RESPONSE_BYTES on the validator.",
    ),
    "tw.invalid_response": (
        "validator",
        "The answer does not parse into the task's response model (or a "
        "stream chunk is not a JSON object or array, or nests too deep).",
        "Return the route's response model exactly.",
    ),
    "tw.no_axon": (
        "validator",
        "The miner has no usable published axon (none, or a private address "
        "without TW_ALLOW_PRIVATE_AXONS=1 on localnet).",
        "Start the miner (it publishes with ServeAxon), or set "
        "TW_ALLOW_PRIVATE_AXONS=1 "
        "on localnet only.",
    ),
    "tw.timelock_unavailable": (
        "validator",
        "A sealed (timelocked) answer could not be opened: drand unreachable "
        "or rate-limited, or not revealed within TW_TIMELOCK_TIMEOUT_S.",
        "Check outbound access to the drand API; raise TW_TIMELOCK_TIMEOUT_S.",
    ),
    "tw.tls_pin_mismatch": (
        "validator",
        "The miner's TLS key differs from the key it published with ServeAxonTls.",
        "Re-publish the axon after changing the certificate (the miner does it "
        "on start), or check for a man in the middle.",
    ),
}

_HTTP_CODE = re.compile(r"tw\.http_([1-5][0-9]{2})")


@dataclass(frozen=True)
class ErrorExplanation:
    """One code, explained."""

    code: str
    known: bool
    raised_by: str
    http_status: int | None
    public_message: str | None
    response_signed: str
    cause: str
    fix: str


def explain_error(code: str) -> ErrorExplanation:
    """Explain a ``tw.*`` code (Appendix A, client codes and ``tw.http_<status>``)."""
    code = code.strip()
    spec = ERROR_CODES.get(code)
    hint = ERROR_HINTS.get(code)
    if spec is not None and hint is not None:
        signed = {True: "yes", False: "no", None: "depends on the layer"}[spec.signed]
        return ErrorExplanation(
            code,
            True,
            hint[0],
            spec.http_status,
            spec.public_message,
            signed,
            *hint[1:],
        )
    if code in CLIENT_ERROR_CODES and hint is not None:
        return ErrorExplanation(
            code, True, hint[0], None, None, "n/a (client side)", *hint[1:]
        )
    m = _HTTP_CODE.fullmatch(code)
    if m is not None:
        return ErrorExplanation(
            code,
            True,
            "validator",
            int(m.group(1)),
            None,
            "n/a (client side)",
            f"The miner answered HTTP {m.group(1)} without a TaoWire error body: "
            "something in front of it (proxy, load balancer) or a non-TaoWire server.",
            "Check what listens on the miner's published address and port.",
        )
    return ErrorExplanation(
        code,
        False,
        "unknown",
        None,
        None,
        "unknown",
        "Not a TaoWire code. Chain outcomes (weights, ServeAxon) use bittensor "
        "ErrorCode values instead.",
        "Call list_error_codes for every code the kit uses.",
    )


def all_error_codes() -> list[str]:
    """Every server-side and client-side code, sorted."""
    return sorted(set(ERROR_CODES) | CLIENT_ERROR_CODES)


# ------------------------------------------------------------------ settings


@dataclass(frozen=True)
class SettingInfo:
    """One ``TW_*`` setting."""

    name: str
    roles: tuple[str, ...]
    required: bool
    default: str
    type: str
    limits: str
    description: str


def _env_comments() -> dict[str, str]:
    """``TW_NAME -> comment`` from the bundled ``.env.example``."""
    text = _data().joinpath("env.example").read_text(encoding="utf-8")
    out: dict[str, str] = {}
    pending: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        setting = re.match(r"#?\s*(TW_[A-Z0-9_]+)=", line)
        if setting:
            name = setting.group(1)
            if pending and name not in out:
                out[name] = " ".join(pending)
            if not line.startswith("#"):
                pending = []
            continue
        if line.startswith("# ----") or not line:
            pending = []
        elif line.startswith("#"):
            pending.append(line.lstrip("# ").strip())
    return out


def _limits(field: FieldInfo) -> str:
    parts = []
    for item in field.metadata:
        for attr, sign in (("ge", ">="), ("gt", ">"), ("le", "<="), ("lt", "<")):
            value = getattr(item, attr, None)
            if value is not None:
                parts.append(f"{sign} {value}")
    return ", ".join(parts)


def _type_name(annotation: Any) -> str:
    text = getattr(annotation, "__name__", None) or str(annotation)
    return text.replace("typing.", "").replace("pathlib.", "")


def _default(field: FieldInfo) -> str:
    if field.is_required():
        return ""
    value = field.get_default(call_default_factory=True)
    if value is None:
        return "unset"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, tuple):
        return ",".join(str(v) for v in value)
    return str(value)


def list_settings(role: Role | Literal["all"] = "all") -> list[SettingInfo]:
    """Every ``TW_*`` setting a process type reads, with defaults and limits."""
    roles: list[Role] = list(_MODELS) if role == "all" else [role]
    comments = _env_comments()
    found: dict[str, SettingInfo] = {}
    for r in roles:
        for key, field in _MODELS[r].model_fields.items():
            name = f"{ENV_PREFIX}{key.upper()}"
            if name in found:
                old = found[name]
                if r not in old.roles:
                    found[name] = SettingInfo(
                        name,
                        (*old.roles, r),
                        old.required,
                        old.default,
                        old.type,
                        old.limits,
                        old.description,
                    )
                continue
            found[name] = SettingInfo(
                name=name,
                roles=(r,),
                required=field.is_required(),
                default=_default(field),
                type=_type_name(field.annotation),
                limits=_limits(field),
                description=comments.get(name, ""),
            )
    return sorted(found.values(), key=lambda s: s.name)


# ------------------------------------------------------------------ docs


@dataclass(frozen=True)
class Doc:
    """One bundled document."""

    name: str
    title: str
    size: int


def _data() -> Traversable:
    return files("taowire.mcp_server").joinpath("data")


def _walk(node: Traversable, prefix: str = "") -> list[tuple[str, Traversable]]:
    out: list[tuple[str, Traversable]] = []
    for child in sorted(node.iterdir(), key=lambda c: c.name):
        rel = f"{prefix}{child.name}"
        if child.is_dir():
            out.extend(_walk(child, rel + "/"))
        elif child.name.endswith(".md"):
            out.append((rel[: -len(".md")], child))
    return out


def _docs() -> dict[str, Traversable]:
    return dict(_walk(_data().joinpath("docs")))


def doc_names() -> list[Doc]:
    """The bundled docs: name (``quickstart``, ``protocol/twresp-1``, ...) and title."""
    out = []
    for name, node in _docs().items():
        text = node.read_text(encoding="utf-8")
        title = next(
            (
                ln.lstrip("# ").strip()
                for ln in text.splitlines()
                if ln.startswith("# ")
            ),
            name,
        )
        out.append(Doc(name, title, len(text)))
    return out


def read_doc(name: str) -> str:
    """The Markdown text of one bundled doc. Raises :class:`KeyError` if unknown."""
    key = name.strip().removesuffix(".md").removeprefix("docs/")
    docs = _docs()
    if key not in docs:
        raise KeyError(key)
    text: str = docs[key].read_text(encoding="utf-8")
    return text


def search_docs(query: str, limit: int = 20) -> list[dict[str, Any]]:
    """Lines of the bundled docs that contain every word of ``query`` (any case)."""
    words = [w for w in query.lower().split() if w]
    if not words:
        return []
    hits: list[dict[str, Any]] = []
    for name, node in _docs().items():
        lines = node.read_text(encoding="utf-8").splitlines()
        heading = ""
        for i, line in enumerate(lines):
            if line.startswith("#"):
                heading = line.lstrip("# ").strip()
            low = line.lower()
            if all(w in low for w in words):
                hits.append(
                    {
                        "doc": name,
                        "line": i + 1,
                        "section": heading,
                        "text": line.strip(),
                    }
                )
                if len(hits) >= limit:
                    return hits
    return hits
