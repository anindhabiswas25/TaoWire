"""compat.Synapse against the captured v10 vectors (spec 10b.2.1, 8.11.1).

The four Synapses below are the ones ``scripts/capture_v10_vectors.py`` ran
on a real bittensor 10.5.0 Dendrite and Axon, re-declared on
``taowire.compat.Synapse``. Their ``body_hash`` must equal the
``computed_body_hash`` header the v10 Dendrite sent, and every captured body
(request and 200 response) must parse back into the same class.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pydantic import Field

from taowire.compat.synapse import BASE_FIELDS, Synapse, TerminalInfo, hash_values

VECTORS_PATH = (
    Path(__file__).resolve().parents[3] / "conformance" / "vectors" / "legacy_v10.json"
)
VECTORS: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
EMPTY_HASH = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"


class Dummy(Synapse):
    dummy_input: int
    dummy_output: int | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)

    def deserialize(self) -> int | None:
        return self.dummy_output


class TextOps(Synapse):
    text: str
    op: str
    count: int = 0
    ratio: float = 0.0
    tags: list[str] = Field(default_factory=list)
    weights: dict[str, float] = Field(default_factory=dict)
    flag: bool = False
    maybe: str | None = None
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


class NoHash(Synapse):
    payload: str
    answer: str | None = None


with warnings.catch_warnings():
    warnings.simplefilter("ignore", UserWarning)  # pydantic: field shadows a ClassVar

    class LegacyFieldHash(Synapse):
        # Deprecated v10 style: required_hash_fields as a pydantic field.
        required_hash_fields: list[str] = Field(default=["b_field", "a_field"])  # type: ignore[assignment]
        a_field: int
        b_field: str
        out: str | None = None


CLASSES: dict[str, type[Synapse]] = {
    "Dummy": Dummy,
    "TextOps": TextOps,
    "NoHash": NoHash,
    "LegacyFieldHash": LegacyFieldHash,
}


def header(message: dict[str, Any], name: str) -> str | None:
    for key, value in message["headers"]:
        if key.lower() == name:
            return str(value)
    return None


def accepted_vectors() -> list[dict[str, Any]]:
    return [
        v
        for v in VECTORS["vectors"]
        if v["synapse"] in CLASSES and v["accepted_by_v10_axon"]
    ]


@pytest.mark.parametrize("vector", accepted_vectors(), ids=lambda v: v["id"])
def test_body_hash_matches_the_v10_dendrite(vector: dict[str, Any]) -> None:
    cls = CLASSES[vector["synapse"]]
    request = vector["request"]
    synapse = cls.model_validate_json(request["body_utf8"])
    assert synapse.name == vector["synapse"]
    assert synapse.body_hash == header(request, "computed_body_hash")
    if "dendrite" in json.loads(request["body_utf8"]):  # N8 sends a tampered body
        assert synapse.dendrite is not None
        assert synapse.dendrite.hotkey == VECTORS["keys"]["dendrite"]["ss58"]


@pytest.mark.parametrize("vector", accepted_vectors(), ids=lambda v: v["id"])
def test_v10_response_parses(vector: dict[str, Any]) -> None:
    response = vector["response"]
    assert response["status"] == 200
    synapse = CLASSES[vector["synapse"]].model_validate_json(response["body_utf8"])
    assert synapse.user_fields()  # output fields present


def test_hash_field_order() -> None:
    assert Dummy.hash_field_names() == ("dummy_input",)
    assert TextOps.hash_field_names()[:2] == ("op", "text")  # declared order
    assert LegacyFieldHash.hash_field_names() == ("a_field", "b_field")  # model order
    assert NoHash.hash_field_names() == ()
    assert NoHash(payload="x").body_hash == EMPTY_HASH == hash_values([])


def test_falsy_values_are_hashed() -> None:
    assert Dummy(dummy_input=0).body_hash != EMPTY_HASH


def test_base_fields_keep_v10_order_and_defaults() -> None:
    names = tuple(Synapse.model_fields)
    assert names == BASE_FIELDS
    s = Dummy(dummy_input=1)
    assert (s.name, s.timeout, s.total_size, s.header_size) == ("Dummy", 12.0, 0, 0)
    assert s.computed_body_hash == ""
    assert s.dendrite == TerminalInfo()


def test_name_is_always_the_class_name() -> None:
    assert Dummy(dummy_input=1, name="Other").name == "Dummy"
    assert Dummy.model_validate_json('{"dummy_input": 1, "name": "X"}').name == "Dummy"


def test_user_fields_exclude_v10_base_fields() -> None:
    s = LegacyFieldHash(a_field=1, b_field="b")
    assert s.user_fields() == {"a_field": 1, "b_field": "b", "out": None}
    assert json.loads(s.user_json()) == s.user_fields()
    assert Dummy.user_field_names() == ("dummy_input", "dummy_output")


def test_required_fields_are_the_input_obj_fields() -> None:
    assert Dummy(dummy_input=1).get_required_fields() == ["dummy_input"]
    assert TextOps(text="a", op="b").get_required_fields() == ["text", "op"]


@pytest.mark.parametrize(
    ("status", "flags"),
    [
        (200, {"is_success"}),
        (408, {"is_failure", "is_timeout"}),
        (403, {"is_failure", "is_blacklist"}),
        (401, {"is_failure", "failed_verification"}),
        (None, {"is_failure"}),
    ],
)
def test_status_properties(status: int | None, flags: set[str]) -> None:
    s = Dummy(dummy_input=1)
    assert s.dendrite is not None
    s.dendrite.status_code = status
    names = {"is_success", "is_failure", "is_timeout", "is_blacklist"}
    names.add("failed_verification")
    assert {n for n in names if getattr(s, n)} == flags


def test_status_properties_without_dendrite() -> None:
    s = Dummy(dummy_input=1, dendrite=None)
    assert s.is_failure
    assert not s.is_timeout
    assert not s.is_blacklist
    assert not s.failed_verification


def test_deserialize_and_total_size() -> None:
    s = Dummy(dummy_input=1, dummy_output=5)
    assert s.deserialize() == 5
    assert NoHash(payload="p").deserialize() == NoHash(payload="p")
    size = s.get_total_size()
    assert size > 0
    assert s.total_size == size
