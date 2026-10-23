"""The bittensor v10 Dendrite/Axon wire format (spec 8.11.1).

Built from ``conformance/vectors/legacy_v10.json``: bytes captured from a
real ``bittensor==10.5.0`` Dendrite and Axon. This module is a leaf: it
needs the standard library, pydantic and :mod:`tensorwire.crypto`, never the
v10 SDK (ADR-0008) and never the rest of the kit. ``compat.Synapse`` builds
its ``body_hash`` on :func:`body_hash`.

A v10 *Synapse* here is any pydantic model shaped like v10's: an optional
``required_hash_fields`` (a ``ClassVar`` tuple, or the deprecated pydantic
field), and the v10 envelope fields (``name``, ``timeout``, ``dendrite``,
``axon``...) if it declares them. The envelope is written by this module,
not taken from the model.

What the format protects, and what it does not, is in spec 8.11.1: the
request signature binds sender, receiver, nonce and the hash fields only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import pydantic_core
from pydantic import BaseModel, ValidationError

from tensorwire import crypto

__all__ = [
    "EMPTY_BODY_HASH",
    "ENVELOPE_FIELDS",
    "FRESHNESS_RULES_MIN_VERSION",
    "STATUS_HEADER",
    "TERMINAL_FIELDS",
    "V10_VERSION",
    "DecodedResponse",
    "EncodedRequest",
    "NonFiniteAnswer",
    "RequestHeaders",
    "SignerLike",
    "WireError",
    "body_hash",
    "check_synapse_class",
    "decode_request_body",
    "decode_response",
    "encode_request",
    "encode_response",
    "hash_fields",
    "hash_values",
    "is_legacy_request",
    "is_synapse_name",
    "is_v10_response",
    "non_finite_field",
    "parse_request_headers",
    "request_message",
    "response_message",
    "synapse_name",
]

#: ``bt_header_dendrite_version`` / ``bt_header_axon_version`` the kit sends:
#: bittensor 10.5.0 as v10 encodes versions (major * 10**6 + minor * 10**3 + patch).
V10_VERSION = 10_005_000

#: v10 Axons apply their nonce rules only from this Dendrite version on.
FRESHNESS_RULES_MIN_VERSION = 7_002_000

#: ``computed_body_hash`` of a Synapse without hash fields: ``sha3_256("")``.
EMPTY_BODY_HASH = hashlib.sha3_256(b"").hexdigest()

#: The header every v10 Axon response carries (vector N7): the v10 marker.
STATUS_HEADER = "bt_header_axon_status_code"

#: v10 ``Synapse`` base fields, in v10 declaration (and body) order.
ENVELOPE_FIELDS = (
    "name",
    "timeout",
    "total_size",
    "header_size",
    "dendrite",
    "axon",
    "computed_body_hash",
)

#: v10 ``TerminalInfo`` fields, in v10 declaration order.
TERMINAL_FIELDS = (
    "status_code",
    "status_message",
    "process_time",
    "ip",
    "port",
    "version",
    "nonce",
    "uuid",
    "hotkey",
    "signature",
)

_AXON = "bt_header_axon_"
_DENDRITE = "bt_header_dendrite_"
_INPUT_OBJ = "bt_header_input_obj_"
_SIGNATURE = _DENDRITE + "signature"
_BTAUTH_SIGNATURE = "x-bittensor-signature"
# Every header the v10 format defines; a duplicate of any of them is ambiguous.
_V10_PLAIN = frozenset(
    {"name", "timeout", "header_size", "total_size", "computed_body_hash"}
)

_DIGITS = re.compile(r"[0-9]{1,20}")
_UUID = re.compile(r"[0-9A-Za-z-]{1,64}")  # never a "." (the signed message is dotted)
_HEX_SIG = re.compile(r"(?:0x)?[0-9a-fA-F]{128}")
_HEX_HASH = re.compile(r"[0-9a-f]{64}")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_B64 = re.compile(r"[A-Za-z0-9+/]{0,4096}={0,2}")
_SYNAPSE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_MAX_TIMEOUT_S = 3600.0
_MAX_INPUT_OBJ_HEADERS = 64

Headers = Mapping[str, str] | Iterable[tuple[str, str]]


class WireError(ValueError):
    """A v10 message that does not follow the format. The text is safe to log."""


class NonFiniteAnswer(WireError):
    """A Synapse answer holding ``inf`` / ``nan`` that JSON would turn into ``null``."""

    def __init__(self, field: str) -> None:
        super().__init__(f"non-finite float in answer field {field!r}")
        self.field = field
        """Where the value sits (``meta.r``, ``w[0]``)."""


class SignerLike(Protocol):
    """What signing needs: :class:`tensorwire.crypto.HotkeySigner` satisfies it."""

    @property
    def ss58_address(self) -> str:
        """The signer's SS58 address."""
        ...

    @property
    def crypto_type(self) -> int:
        """``crypto.CRYPTO_SR25519`` or ``crypto.CRYPTO_ED25519``."""
        ...

    def sign(self, payload: bytes) -> bytes:
        """The raw signature over exactly ``payload``."""
        ...


# --------------------------------------------------------------------- hashing


def _sha3_hex(text: str) -> str:
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()


def hash_fields(synapse_cls: type[BaseModel]) -> tuple[str, ...]:
    """The fields ``computed_body_hash`` covers, in hashing order.

    A ``required_hash_fields`` class variable is hashed in declared order. The
    deprecated v10 style, ``required_hash_fields`` declared as a pydantic
    field, is hashed in model order whatever order its default lists (vector
    V4). No hash fields: ``()``.
    """
    field = synapse_cls.model_fields.get("required_hash_fields")
    if field is not None:
        declared = set(field.default or ())
        return tuple(name for name in synapse_cls.model_fields if name in declared)
    return tuple(getattr(synapse_cls, "required_hash_fields", ()) or ())


def check_synapse_class(synapse_cls: type[BaseModel]) -> None:
    """Refuse a Synapse class the v10 format cannot carry. Call it at startup.

    Raises ``TypeError`` for a non-pydantic class and ``ValueError`` for a
    class name v10 cannot route, or hash fields that are not model fields
    (a v10 Axon answers every such request with 500).
    """
    if not (isinstance(synapse_cls, type) and issubclass(synapse_cls, BaseModel)):
        raise TypeError("a v10 Synapse must be a pydantic model class")
    synapse_name(synapse_cls)
    declared = synapse_cls.model_fields.get("required_hash_fields")
    names = (
        tuple(declared.default or ())
        if declared is not None
        else tuple(getattr(synapse_cls, "required_hash_fields", ()) or ())
    )
    missing = [n for n in names if n not in synapse_cls.model_fields]
    if missing:
        raise ValueError(
            f"{synapse_cls.__name__}.required_hash_fields names unknown "
            f"fields: {missing}"
        )


def synapse_name(synapse_cls: type[BaseModel]) -> str:
    """The v10 route name: the class name, also the request path ``/<name>``."""
    name = synapse_cls.__name__
    if not is_synapse_name(name):
        raise ValueError(f"{name!r} is not a usable v10 Synapse name")
    return name


def is_synapse_name(name: str) -> bool:
    """Whether ``name`` can be a v10 Synapse name (an identifier, at most 128 chars)."""
    return _SYNAPSE_NAME.fullmatch(name) is not None


def hash_values(values: Iterable[Any]) -> str:
    """``sha3_256_hex(concat(sha3_256_hex(str(value)) for value in values))``.

    ``str()`` is Python's: ``True``, ``None``, ``0.1``, ``1e-07``,
    ``['a', 'b c']``. Values must come from ``model_dump()`` of the parsed
    model, never from the JSON text (spec 8.11.1).
    """
    return _sha3_hex("".join(_sha3_hex(str(value)) for value in values))


def body_hash(synapse: BaseModel) -> str:
    """The v10 ``computed_body_hash`` of a Synapse instance."""
    fields = hash_fields(type(synapse))
    if not fields:
        return EMPTY_BODY_HASH
    dumped = synapse.model_dump()
    return hash_values(dumped[name] for name in fields)


def request_message(
    nonce: int, sender: str, receiver: str, uuid: str, computed_body_hash: str
) -> str:
    """The string a v10 Dendrite signs: ``nonce.sender.receiver.uuid.body_hash``."""
    return f"{nonce}.{sender}.{receiver}.{uuid}.{computed_body_hash}"


def response_message(nonce: int, sender: str, receiver: str, uuid: str) -> str:
    """The string a v10 Axon signs on a rejection: ``nonce.dendrite.axon.uuid``.

    Covers neither body nor status; v10 Dendrites never check it.
    """
    return f"{nonce}.{sender}.{receiver}.{uuid}"


# --------------------------------------------------------------------- detection


def _pairs(headers: Headers) -> Iterable[tuple[str, str]]:
    return headers.items() if isinstance(headers, Mapping) else headers


def is_legacy_request(headers: Headers) -> bool:
    """A v10 Dendrite request: a ``bt_header_dendrite_signature`` header and no
    ``X-Bittensor-Signature`` (names compared case-insensitively)."""
    names = {name.lower() for name, _ in _pairs(headers)}
    return _SIGNATURE in names and _BTAUTH_SIGNATURE not in names


def is_v10_response(status: int, headers: Headers) -> bool:
    """The v10 marker (spec 8.11.3): HTTP 500 carrying ``bt_header_axon_status_code``.

    That is how a v10 Axon answers a btauth/1 request (vector N7).
    """
    return status == 500 and any(
        name.lower() == STATUS_HEADER for name, _ in _pairs(headers)
    )


# --------------------------------------------------------------------- requests


@dataclass(frozen=True, slots=True)
class RequestHeaders:
    """The v10 headers of one request, shape-checked. Nothing here is verified."""

    sender: str
    """``bt_header_dendrite_hotkey``: a prefix-42 SS58 address."""
    nonce: int
    """``bt_header_dendrite_nonce``: Unix time in nanoseconds."""
    uuid: str
    """``bt_header_dendrite_uuid``: fixed per v10 Dendrite instance."""
    signature: bytes
    """``bt_header_dendrite_signature``, decoded (64 bytes)."""
    computed_body_hash: str
    """The ``computed_body_hash`` header (64 lowercase hex)."""
    timeout: float
    """``timeout`` (seconds); 12.0 when absent."""
    version: int | None
    """``bt_header_dendrite_version``."""
    axon_hotkey: str | None
    """``bt_header_axon_hotkey``: who the sender meant. Never used for checks."""
    dendrite_ip: str | None
    """``bt_header_dendrite_ip``, as sent (informational)."""
    input_obj: tuple[tuple[str, str], ...]
    """``bt_header_input_obj_*`` headers as ``(field, base64)``, echoed on answers."""
    raw: tuple[tuple[str, str], ...]
    """Every v10 header as ``(lower-case name, value)``, for echoing."""


def _lowered_v10(headers: Headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in _pairs(headers):
        key = name.lower()
        if not (key.startswith("bt_header_") or key in _V10_PLAIN):
            continue
        if key in out:
            raise WireError(f"duplicate {key} header")
        out[key] = value
    return out


def _required(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name)
    if value is None or value == "":
        raise WireError(f"missing {name} header")
    return value


def _version(value: str | None) -> int | None:
    if value is None:
        return None
    if not _DIGITS.fullmatch(value):
        raise WireError("bt_header_dendrite_version is not a decimal integer")
    return int(value)


def _timeout(value: str | None) -> float:
    if value is None:
        return 12.0
    try:
        timeout = float(value)
    except ValueError:
        raise WireError("timeout is not a number") from None
    if not math.isfinite(timeout) or not 0 < timeout <= _MAX_TIMEOUT_S:
        raise WireError("timeout is out of range")
    return timeout


def _input_obj(v10: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    for key, value in v10.items():
        if key.startswith(_INPUT_OBJ):
            field = key[len(_INPUT_OBJ) :]
            if not (_FIELD.fullmatch(field) and _B64.fullmatch(value)):
                raise WireError(f"malformed {key} header")
            out.append((field, value))
    if len(out) > _MAX_INPUT_OBJ_HEADERS:
        raise WireError("too many bt_header_input_obj_* headers")
    return tuple(out)


def parse_request_headers(headers: Headers) -> RequestHeaders:
    """Parse and shape-check the v10 headers of a request. Raises :class:`WireError`.

    Stricter than v10 where v10 is sloppy: the sender must be a prefix-42
    address, the nonce plain digits, the uuid free of dots, the signature
    ``0x`` + 128 hex, the body hash 64 lowercase hex, the timeout finite.
    """
    v10 = _lowered_v10(headers)
    sender = _required(v10, _DENDRITE + "hotkey")
    try:
        crypto.public_key_from_ss58(sender)
    except ValueError:
        raise WireError(
            "bt_header_dendrite_hotkey is not a prefix-42 address"
        ) from None
    nonce = _required(v10, _DENDRITE + "nonce")
    if not _DIGITS.fullmatch(nonce):
        raise WireError("bt_header_dendrite_nonce is not a decimal integer")
    uuid = _required(v10, _DENDRITE + "uuid")
    if not _UUID.fullmatch(uuid):
        raise WireError("bt_header_dendrite_uuid has unexpected characters")
    signature = _required(v10, _SIGNATURE)
    if not _HEX_SIG.fullmatch(signature):
        raise WireError("bt_header_dendrite_signature is not a 64-byte hex signature")
    claimed_hash = _required(v10, "computed_body_hash")
    if not _HEX_HASH.fullmatch(claimed_hash):
        raise WireError("computed_body_hash is not 64 lowercase hex characters")
    input_obj = _input_obj(v10)
    return RequestHeaders(
        sender=sender,
        nonce=int(nonce),
        uuid=uuid,
        signature=crypto.signature_from_hex(signature),
        computed_body_hash=claimed_hash,
        timeout=_timeout(v10.get("timeout")),
        version=_version(v10.get(_DENDRITE + "version")),
        axon_hotkey=v10.get(_AXON + "hotkey"),
        dendrite_ip=v10.get(_DENDRITE + "ip"),
        input_obj=input_obj,
        raw=tuple(v10.items()),
    )


def decode_request_body(synapse_cls: type[BaseModel], body: bytes) -> BaseModel:
    """Parse a v10 request body (the whole Synapse as JSON) into ``synapse_cls``.

    The same parse a v10 Axon does (``json.loads`` then the model), so the
    hash is computed from the same values the sender hashed. Raises
    :class:`WireError`; pydantic details are not included.
    """
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        raise WireError("body is not JSON") from None
    if not isinstance(data, dict):
        raise WireError("body is not a JSON object")
    try:
        return synapse_cls.model_validate(data)
    except (ValidationError, RecursionError):
        raise WireError(f"body does not parse as {synapse_cls.__name__}") from None


def _terminal(**values: Any) -> dict[str, Any]:
    return {name: values.get(name) for name in TERMINAL_FIELDS}


def _user_fields(synapse: BaseModel) -> dict[str, Any]:
    # Python mode, as a v10 Dendrite sends it (``json=synapse.model_dump()``):
    # JSON mode would turn inf / nan into null and break the hash (8.11.1).
    dumped = synapse.model_dump()
    return {k: v for k, v in dumped.items() if k not in ENVELOPE_FIELDS}


def _dumps(data: Any) -> str:
    # Types plain JSON lacks (bytes, dates...) as pydantic writes them; the
    # receiver parses them back to the same values.
    return json.dumps(data, default=pydantic_core.to_jsonable_python)


def _input_obj_headers(synapse: BaseModel) -> list[tuple[str, str]]:
    # v10 sends, for every required field with a value, base64 of the JSON of a
    # default instance of the value's type (int -> 0 -> "MA=="), not the value.
    out: list[tuple[str, str]] = []
    values = synapse.model_dump()
    for name, info in type(synapse).model_fields.items():
        if name in ENVELOPE_FIELDS or not info.is_required():
            continue
        value = values.get(name)
        if value is None:
            continue
        try:
            placeholder = json.dumps(type(value)())
        except (TypeError, ValueError):
            raise ValueError(
                f"required field {name!r} has a type v10 cannot announce in headers"
            ) from None
        out.append((_INPUT_OBJ + name, base64.b64encode(placeholder.encode()).decode()))
    return out


@dataclass(frozen=True, slots=True)
class EncodedRequest:
    """A v10 request ready to send: ``POST http://{ip}:{port}{path}``."""

    path: str
    headers: list[tuple[str, str]]
    body: bytes
    computed_body_hash: str
    nonce: int


def encode_request(
    synapse: BaseModel,
    *,
    signer: SignerLike,
    axon_hotkey: str,
    axon_ip: str,
    axon_port: int,
    nonce: int,
    uuid: str,
    timeout: float,
    dendrite_ip: str | None = None,
) -> EncodedRequest:
    """Build the request a v10 Dendrite would send for ``synapse``.

    Headers in v10 order, the body as the whole Synapse in ``json.dumps``
    default formatting, the signature by ``signer`` (sr25519 only: v10 Axons
    verify nothing else) over :func:`request_message`.
    """
    if signer.crypto_type != crypto.CRYPTO_SR25519:
        raise ValueError("v10 Axons verify sr25519 signatures only")
    if not _UUID.fullmatch(uuid):
        raise ValueError("uuid must be letters, digits and dashes")
    if not math.isfinite(timeout) or not 0 < timeout <= _MAX_TIMEOUT_S:
        raise ValueError("timeout must be a positive number of seconds")
    name = synapse_name(type(synapse))
    digest = body_hash(synapse)
    sender = signer.ss58_address
    message = request_message(nonce, sender, axon_hotkey, uuid, digest)
    signature = crypto.signature_to_hex(signer.sign(message.encode("utf-8")))
    dendrite = _terminal(
        ip=dendrite_ip,
        version=V10_VERSION,
        nonce=nonce,
        uuid=uuid,
        hotkey=sender,
        signature=signature,
    )
    axon = _terminal(ip=axon_ip, port=axon_port, hotkey=axon_hotkey)
    headers: list[tuple[str, str]] = [("name", name), ("timeout", repr(float(timeout)))]
    headers += [(_AXON + k, str(v)) for k, v in axon.items() if v is not None]
    headers += [(_DENDRITE + k, str(v)) for k, v in dendrite.items() if v is not None]
    headers += _input_obj_headers(synapse)
    header_size = sum(len(k) + len(v) for k, v in headers)
    user = _user_fields(synapse)
    total_size = header_size + len(_dumps(user))
    body: dict[str, Any] = {
        "name": name,
        "timeout": float(timeout),
        "total_size": total_size,
        "header_size": 0,
        "dendrite": dendrite,
        "axon": axon,
        "computed_body_hash": "",
        **user,
    }
    headers += [
        ("header_size", str(header_size)),
        ("total_size", str(total_size)),
        ("computed_body_hash", digest),
        ("Content-Type", "application/json"),
    ]
    return EncodedRequest(
        path="/" + name,
        headers=headers,
        body=_dumps(body).encode("utf-8"),
        computed_body_hash=digest,
        nonce=nonce,
    )


# --------------------------------------------------------------------- responses


def encode_response(
    request: RequestHeaders | None,
    *,
    status: int,
    status_message: str,
    process_time_s: float,
    axon_ip: str,
    axon_port: int,
    axon_hotkey: str,
    name: str | None,
    synapse: BaseModel | None = None,
    raw_body: bytes | None = None,
    signer: SignerLike | None = None,
    axon_nonce: int | None = None,
    axon_uuid: str | None = None,
) -> tuple[bytes, list[tuple[str, str]]]:
    """Build a v10-shaped answer: ``(body, headers)``; the HTTP status is ``status``.

    On 200 the body is the whole Synapse (``synapse`` dumped, or ``raw_body``
    as given) with ``axon`` filled in, compact JSON. Otherwise it is
    ``{"message": status_message}``. ``request`` (when the headers parsed)
    is echoed as v10 does. With ``signer`` (plus ``axon_nonce`` and
    ``axon_uuid``) the answer carries the v10 axon signature over
    :func:`response_message`, using ``axon_hotkey`` as the receiver.

    Raises :class:`NonFiniteAnswer` when a 200 ``synapse`` holds a value the
    JSON answer would change (see :func:`non_finite_field`).
    """
    axon = _terminal(
        status_code=status,
        status_message=status_message,
        process_time=process_time_s,
        ip=axon_ip,
        port=axon_port,
        hotkey=axon_hotkey,
    )
    if signer is not None:
        if request is None or axon_nonce is None or axon_uuid is None:
            raise ValueError(
                "a signed answer needs the request, axon_nonce and axon_uuid"
            )
        message = response_message(axon_nonce, request.sender, axon_hotkey, axon_uuid)
        axon.update(
            version=V10_VERSION,
            nonce=axon_nonce,
            uuid=axon_uuid,
            signature=crypto.signature_to_hex(signer.sign(message.encode("utf-8"))),
        )
    if status == 200 and raw_body is not None:
        body = raw_body
    elif status == 200 and synapse is not None:
        field = non_finite_field(synapse)
        if field is not None:
            raise NonFiniteAnswer(field)
        dumped = synapse.model_dump(mode="json")
        dumped["axon"] = axon
        if request is not None:
            dumped["dendrite"] = _request_dendrite(request)
        body = json.dumps(dumped, separators=(",", ":"), ensure_ascii=False).encode()
    else:
        body = json.dumps({"message": status_message}, separators=(",", ":")).encode()
    headers: list[tuple[str, str]] = []
    if name is not None:
        headers.append(("name", name))
        if request is not None:
            headers.append(("timeout", repr(request.timeout)))
    headers += [(_AXON + k, str(v)) for k, v in axon.items() if v is not None]
    if request is not None:
        headers += [(k, v) for k, v in request.raw if k.startswith(_DENDRITE)]
        headers += [(_INPUT_OBJ + f, v) for f, v in request.input_obj]
    header_size = sum(len(k) + len(v) for k, v in headers)
    headers += [
        ("header_size", str(header_size)),
        ("total_size", str(header_size + len(body))),
    ]
    if request is not None:
        headers.append(("computed_body_hash", request.computed_body_hash))
    headers.append(("Content-Type", "application/json"))
    return body, headers


_MISSING = object()


def _child(container: Any, key: str | int) -> Any:
    # JSON mode turns tuples into lists and dict keys into strings.
    if isinstance(container, dict):
        if key in container:
            return container[key]
        return container.get(str(key), _MISSING)
    if isinstance(container, list) and isinstance(key, int) and key < len(container):
        return container[key]
    return _MISSING


def _non_finite_paths(value: Any, path: str) -> Iterable[tuple[str, list[Any]]]:
    # Yields (printable path, key list) for every non-finite float in a
    # Python-mode dump, depth first, in field order.
    if isinstance(value, float) and not math.isfinite(value):
        yield path, []
    elif isinstance(value, dict):
        for key, item in value.items():
            step = (
                f".{key}"
                if isinstance(key, str) and _FIELD.fullmatch(key)
                else f"[{key!r}]"
            )
            for sub, keys in _non_finite_paths(item, path + step):
                yield sub, [key, *keys]
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            for sub, keys in _non_finite_paths(item, f"{path}[{index}]"):
                yield sub, [index, *keys]
    elif isinstance(value, (set, frozenset)) and any(
        isinstance(v, float) and not math.isfinite(v) for v in value
    ):
        yield path, [_MISSING]  # no stable position to compare: counted as changed


def non_finite_field(
    synapse: BaseModel,
    *,
    rendered: Any = _MISSING,
    skip: Collection[str] = ENVELOPE_FIELDS,
) -> str | None:
    """The first field where ``synapse`` holds an ``inf`` / ``nan`` that the
    JSON answer would turn into ``null`` (``meta.r``, ``w[0]``, ``by_uid[7]``,
    ``m['a b']``), or ``None``.

    v10 answers are JSON-mode dumps. Pydantic keeps a value of a ``float``
    field as is (sent as ``Infinity`` / ``NaN``, which v10 Dendrites parse
    back), but writes one held under ``Any`` (``dict[str, Any]``, ...) as
    ``null``. The answer must never silently change a value (8.11.2), so such
    a Synapse is refused. Values in a set have no position to compare and are
    always refused.

    ``rendered`` is the answer as it will be sent, parsed back (default: the
    JSON-mode dump, which is what a Synapse answer is built from). A plain
    model answered with ``model_dump_json()`` passes ``json.loads`` of those
    bytes: without ``ser_json_inf_nan="constants"`` it writes even a
    ``float`` field's ``inf`` as ``null``. ``skip`` names top-level fields not
    checked (the Synapse envelope by default; ``()`` for a plain model).
    """
    python = synapse.model_dump()
    json_mode: Any = None if rendered is _MISSING else rendered
    for path, keys in _non_finite_paths(
        {k: v for k, v in python.items() if k not in skip}, ""
    ):
        if json_mode is None:
            json_mode = synapse.model_dump(mode="json")
        node: Any = json_mode
        for key in keys:
            node = _MISSING if key is _MISSING else _child(node, key)
            if node is _MISSING:
                break
        if node is _MISSING or node is None:
            return path.lstrip(".")
    return None


def _request_dendrite(request: RequestHeaders) -> dict[str, Any]:
    return _terminal(
        ip=request.dendrite_ip,
        version=request.version,
        nonce=request.nonce,
        uuid=request.uuid,
        hotkey=request.sender,
        signature=crypto.signature_to_hex(request.signature),
    )


@dataclass(frozen=True, slots=True)
class DecodedResponse:
    """A v10 Axon's answer, parsed. Nothing in it is authenticated."""

    status: int
    """The HTTP status (v10 sets it equal to ``bt_header_axon_status_code``)."""
    synapse: BaseModel | None
    """On 200: the body parsed into the request's Synapse class."""
    status_message: str | None
    """The body's ``message`` or ``bt_header_axon_status_message``."""
    axon: dict[str, str]
    """``bt_header_axon_*`` headers, without the prefix."""


def decode_response(
    synapse_cls: type[BaseModel], status: int, headers: Headers, body: bytes
) -> DecodedResponse:
    """Parse a v10 answer. Raises :class:`WireError` when a 200 body is not a
    ``synapse_cls`` (a v10 Dendrite fails the same way)."""
    axon = {
        name.lower()[len(_AXON) :]: value
        for name, value in _pairs(headers)
        if name.lower().startswith(_AXON)
    }
    if status == 200:
        return DecodedResponse(
            status=status,
            synapse=decode_request_body(synapse_cls, body),
            status_message=axon.get("status_message"),
            axon=axon,
        )
    message = axon.get("status_message")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        data = None
    if isinstance(data, dict) and isinstance(data.get("message"), str):
        message = data["message"]
    return DecodedResponse(
        status=status, synapse=None, status_message=message, axon=axon
    )
