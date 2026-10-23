"""v10-shaped ``Synapse`` and ``TerminalInfo`` (spec 10b.2.1).

A drop-in for ``bittensor.Synapse`` (v10) in template-style code::

    from typing import ClassVar
    from tensorwire.compat import Synapse

    class Dummy(Synapse):
        dummy_input: int
        dummy_output: int | None = None
        required_hash_fields: ClassVar[tuple[str, ...]] = ("dummy_input",)

        def deserialize(self) -> int | None:
            return self.dummy_output

The base fields (``name``, ``timeout``, ``total_size``, ``header_size``,
``dendrite``, ``axon``, ``computed_body_hash``) keep their v10 names, order
and defaults, so a v10 request body parses into the same class.

On the btauth/1 path only the subclass's own fields go on the wire
(:meth:`Synapse.user_fields`); ``dendrite`` and ``axon`` are filled locally
from the verified caller (miner side) or the HTTP result (validator side).
On the v10 path the whole Synapse is the body (spec 8.11.1).

:attr:`Synapse.body_hash` is v10's ``computed_body_hash``. It delegates to
:func:`tensorwire.extensions.legacy_v10.wire.body_hash`, the one
implementation the kit has (spec 5.2, D7).
"""

from __future__ import annotations

import sys
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tensorwire.extensions.legacy_v10 import wire
from tensorwire.extensions.legacy_v10.wire import hash_values

__all__ = ["BASE_FIELDS", "Synapse", "TerminalInfo", "hash_values"]

#: The v10 base fields, in v10 model order. Never sent on the btauth/1 path.
BASE_FIELDS: tuple[str, ...] = (
    "name",
    "timeout",
    "total_size",
    "header_size",
    "dendrite",
    "axon",
    "computed_body_hash",
)

_DEFAULT_TIMEOUT_S = 12.0


class TerminalInfo(BaseModel):
    """One end of a call, as v10 code reads it (``synapse.dendrite``, ``.axon``)."""

    model_config = ConfigDict(validate_assignment=True)

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


class Synapse(BaseModel):
    """The v10 ``Synapse`` shape over TensorWire.

    Subclasses add their request and response fields. ``required_hash_fields``
    lists the fields a v10 request signature covers (through
    ``computed_body_hash``). It matters only on the legacy v10 path; on
    btauth/1 the signature covers the whole body. ``tensorwire migrate scan``
    warns when it is empty or partial.
    """

    model_config = ConfigDict(validate_assignment=True)

    name: str | None = None
    timeout: float | None = _DEFAULT_TIMEOUT_S
    total_size: int | None = 0
    header_size: int | None = 0
    dendrite: TerminalInfo | None = Field(default_factory=TerminalInfo)
    axon: TerminalInfo | None = Field(default_factory=TerminalInfo)
    computed_body_hash: str | None = ""

    required_hash_fields: ClassVar[tuple[str, ...]] = ()

    @model_validator(mode="before")
    @classmethod
    def _set_name(cls, values: Any) -> Any:
        if isinstance(values, dict):
            values = {**values, "name": cls.__name__}
        return values

    # ------------------------------------------------------------ v10 API

    def deserialize(self) -> Any:
        """What ``Dendrite(..., deserialize=True)`` returns. Override in subclasses."""
        return self

    def get_total_size(self) -> int:
        """Set and return ``total_size`` (an estimate; v10 never checked it)."""
        size = sys.getsizeof(self) + len(self.model_dump_json())
        self.total_size = size
        return size

    @property
    def is_success(self) -> bool:
        """The call returned 200."""
        return self.dendrite is not None and self.dendrite.status_code == 200

    @property
    def is_failure(self) -> bool:
        """The call did not return 200."""
        return not self.is_success

    @property
    def is_timeout(self) -> bool:
        """The call timed out (408)."""
        return self.dendrite is not None and self.dendrite.status_code == 408

    @property
    def is_blacklist(self) -> bool:
        """The miner refused the caller (403)."""
        return self.dendrite is not None and self.dendrite.status_code == 403

    @property
    def failed_verification(self) -> bool:
        """The miner rejected the request signature (401)."""
        return self.dendrite is not None and self.dendrite.status_code == 401

    def get_required_fields(self) -> list[str]:
        """Fields without a default (v10 sends one ``bt_header_input_obj_*`` each)."""
        return [
            name
            for name, info in type(self).model_fields.items()
            if info.is_required() and name not in BASE_FIELDS
        ]

    # ------------------------------------------------------------ hashing

    @classmethod
    def hash_field_names(cls) -> tuple[str, ...]:
        """The fields ``computed_body_hash`` covers, in hashing order (spec 8.11.1).

        Normally ``required_hash_fields`` in declared order. A subclass that
        still declares ``required_hash_fields`` as a pydantic field (deprecated
        in v10) is hashed in model order, whatever order its list has.
        """
        return wire.hash_fields(cls)

    @property
    def body_hash(self) -> str:
        """v10's ``computed_body_hash`` of this instance (``wire.body_hash``)."""
        return wire.body_hash(self)

    # ------------------------------------------------------------ wire helpers

    @classmethod
    def user_field_names(cls) -> tuple[str, ...]:
        """The subclass's own fields (no v10 base fields), in model order."""
        return tuple(
            name
            for name in cls.model_fields
            if name not in BASE_FIELDS and name != "required_hash_fields"
        )

    def user_fields(self) -> dict[str, Any]:
        """The subclass's own field values (``model_dump`` form)."""
        return self.model_dump(include=set(self.user_field_names()))

    def user_json(self) -> bytes:
        """The btauth/1 wire body: the subclass's own fields as compact JSON."""
        return self.model_dump_json(include=set(self.user_field_names())).encode()
