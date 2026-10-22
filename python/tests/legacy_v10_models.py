"""v10-shaped Synapse models and vector helpers for the legacy bridge tests.

The models mirror the ones ``scripts/capture_v10_vectors.py`` captured with
bittensor 10.5.0, on a plain pydantic base that has the v10 envelope fields
(the shape ``tensorwire.compat.Synapse`` has). ``legacy_v10`` types Synapses
structurally, so these stand in for ``compat.Synapse`` on ``eng-b/chain``.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, ClassVar

import pydantic
from pydantic import BaseModel

VECTORS_PATH = (
    Path(__file__).resolve().parents[2] / "conformance" / "vectors" / "legacy_v10.json"
)
VECTORS: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
BY_ID: dict[str, dict[str, Any]] = {v["id"]: v for v in VECTORS["vectors"]}
ALICE: str = VECTORS["keys"]["dendrite"]["ss58"]
BOB: str = VECTORS["keys"]["axon"]["ss58"]
CHARLIE: str = VECTORS["keys"]["foreign_axon"]["ss58"]


class TerminalInfo(BaseModel):
    status_code: int | None = None
    status_message: str | None = None
    process_time: float | None = None
    ip: str | None = None
    port: int | None = None
    version: int | None = None
    nonce: int | None = None
    uuid: str | None = None
    hotkey: str | None = None
    signature: str | None = None


class V10Synapse(BaseModel):
    name: str | None = None
    timeout: float = 12.0
    total_size: int = 0
    header_size: int = 0
    dendrite: TerminalInfo = pydantic.Field(default_factory=TerminalInfo)
    axon: TerminalInfo = pydantic.Field(default_factory=TerminalInfo)
    computed_body_hash: str = ""


class Dummy(V10Synapse):
    dummy_input: int
    dummy_output: int | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)


class TextOps(V10Synapse):
    text: str
    op: str
    count: int = 1
    ratio: float = 0.5
    tags: list[str] = pydantic.Field(default_factory=list)
    weights: dict[str, float] = pydantic.Field(default_factory=dict)
    flag: bool = False
    maybe: int | None = None
    result: str | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = (
        "op",
        "text",
        "count",
        "ratio",
        "tags",
        "weights",
        "flag",
        "maybe",
    )


class NoHash(V10Synapse):
    payload: str
    answer: str | None = None


class LegacyFieldHash(V10Synapse):
    # Declared first: in v10 the field sits right after the envelope.
    required_hash_fields: list[str] = pydantic.Field(default=["b_field", "a_field"])
    a_field: int
    b_field: str
    out: str | None = None


class PlainDummy(BaseModel):
    """A Synapse without the v10 envelope fields (a minimal native model)."""

    dummy_input: int
    dummy_output: int | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)


SYNAPSES: dict[str, type[BaseModel]] = {
    "Dummy": Dummy,
    "TextOps": TextOps,
    "NoHash": NoHash,
    "LegacyFieldHash": LegacyFieldHash,
}


def header(message: dict[str, Any], name: str) -> str | None:
    """A header of a captured message (case-insensitive), or ``None``."""
    for key, value in message["headers"]:
        if key.lower() == name.lower():
            return str(value)
    return None


def body_bytes(message: dict[str, Any]) -> bytes:
    """The exact captured body."""
    return base64.b64decode(message["body_base64"])


def request_headers(vector: dict[str, Any]) -> list[tuple[str, str]]:
    """The captured request headers as pairs."""
    return [(str(k), str(v)) for k, v in vector["request"]["headers"]]


def nonce_of(vector: dict[str, Any]) -> int:
    """The captured ``bt_header_dendrite_nonce``."""
    value = header(vector["request"], "bt_header_dendrite_nonce")
    assert value is not None
    return int(value)
