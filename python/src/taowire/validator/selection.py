"""Which miners a validator queries each round (spec 8.9 step 1).

Default: every neuron with a usable axon and no validator permit, except
this validator itself, then a uniform random sample of ``sample_size``.
``include_validators=True`` (``TW_QUERY_VALIDATORS=1``) also queries permit
holders. The result is in UID order.
"""

from __future__ import annotations

import random
from collections.abc import Collection

from taowire.chain.gateway import MetagraphView, NeuronView

__all__ = ["eligible_miners", "select_miners"]


def eligible_miners(
    mg: MetagraphView,
    *,
    include_validators: bool = False,
    exclude_hotkeys: Collection[str] = (),
) -> list[NeuronView]:
    """Queryable neurons: an axon, not excluded, and (by default) no permit."""
    return [
        n
        for n in mg.neurons
        if n.axon is not None
        and n.hotkey not in exclude_hotkeys
        and (include_validators or not n.validator_permit)
    ]


def select_miners(
    mg: MetagraphView,
    *,
    sample_size: int,
    include_validators: bool = False,
    exclude_hotkeys: Collection[str] = (),
    rng: random.Random | None = None,
) -> list[NeuronView]:
    """A random sample of at most ``sample_size`` eligible miners, in UID order."""
    if sample_size < 1:
        raise ValueError("sample_size must be at least 1")
    pool = eligible_miners(
        mg, include_validators=include_validators, exclude_hotkeys=exclude_hotkeys
    )
    if len(pool) > sample_size:
        chooser = rng if rng is not None else random.SystemRandom()
        pool = chooser.sample(pool, sample_size)
    return sorted(pool, key=lambda n: n.uid)
