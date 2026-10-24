"""Weights in the shape v11 ``SetWeights`` accepts (spec 10b.2.5).

v11 ``SetWeights`` normalises, clips and quantises itself, so v10's
``process_weights_for_netuid`` and ``convert_weights_and_uids_for_emit``
are not needed. Template code that holds parallel ``uids`` / ``weights``
arrays (lists or numpy) converts them with :func:`to_mapping`::

    from taowire.compat import weights
    mapping = weights.to_mapping(uids, raw_weights)     # {uid: weight}
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any

__all__ = ["to_mapping"]


def _as_list(values: Any) -> list[Any]:
    tolist = getattr(values, "tolist", None)  # numpy / torch arrays
    if callable(tolist):
        values = tolist()
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise TypeError("expected a list or array")
    return list(values)


def to_mapping(uids: Any, weights: Any) -> dict[int, float]:
    """``{uid: weight}`` from parallel arrays.

    Raises ``ValueError`` for different lengths, a duplicate or negative UID,
    or a weight that is negative, NaN or infinite. Zero weights are kept;
    the kit's weight scheduler drops them before submitting.
    """
    uid_list = _as_list(uids)
    weight_list = _as_list(weights)
    if len(uid_list) != len(weight_list):
        raise ValueError(
            f"{len(uid_list)} uids but {len(weight_list)} weights; they must match"
        )
    mapping: dict[int, float] = {}
    for raw_uid, raw_weight in zip(uid_list, weight_list, strict=True):
        uid = int(raw_uid)
        if uid != raw_uid or uid < 0:
            raise ValueError(f"invalid uid {raw_uid!r}")
        if uid in mapping:
            raise ValueError(f"uid {uid} appears twice")
        weight = float(raw_weight)
        if not math.isfinite(weight) or weight < 0:
            raise ValueError(f"invalid weight for uid {uid}")
        mapping[uid] = weight
    return mapping
