# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# TaoWire port: the template's miner and validator, in process on FakeChain.

import sys
import types

import pytest

from taowire import Miner as KitMiner, ValidatorSettings
from taowire.testing.keys import dev_key
from taowire.testing.metagraph import FakeMetagraphSource
from taowire.testing.pytest_plugin import TEST_NETUID
from taowire.testing.transport import AppRouter

import template.validator  # noqa: F401 - loads template.validator.forward
from neurons.miner import Miner
from neurons.validator import Validator

MINER_AXON = "44.1.2.3:8091"  # published by the TaoWire miner at startup


async def _no_pause(seconds):
    return None


@pytest.mark.asyncio
async def test_template_miner_and_validator(
    tw_miner_kwargs, fake_chain, tw_clock, tmp_path, monkeypatch
):
    monkeypatch.setenv("TW_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(sys, "argv", ["neuron", "--netuid", str(TEST_NETUID)])
    monkeypatch.setattr(
        sys.modules["template.validator.forward"],
        "asyncio",
        types.SimpleNamespace(sleep=_no_pause),
    )
    kit_miner = KitMiner(**tw_miner_kwargs)
    Miner(miner=kit_miner)  # attaches forward / blacklist / priority

    async with kit_miner.running() as app:
        gateway = fake_chain.with_signer(dev_key("alice").ss58)
        validator = Validator(
            settings=ValidatorSettings(
                netuid=TEST_NETUID,
                wallet_name="validator",
                wallet_path=tmp_path / "wallets",
                state_dir=tmp_path / "state",
            ),
            hotkey=dev_key("alice").keypair,
            gateway=gateway,
            metagraph_source=FakeMetagraphSource(
                gateway, TEST_NETUID, clock=tw_clock.monotonic
            ),
            transport=AppRouter({MINER_AXON: app}),
        )
        await validator.start()
        try:
            await validator.step_once()  # query, score; no weights at step 0
            miner_uid = validator.metagraph.hotkeys.index(dev_key("bob").ss58)
            assert validator.scores[miner_uid] == pytest.approx(0.1)
            assert fake_chain.weight_submissions() == ()

            fake_chain.advance(100)  # weights rate limit and neuron.epoch_length
            await validator.step_once()
            (submission,) = fake_chain.weight_submissions()
            assert submission.hotkey == dev_key("alice").ss58
            assert set(submission.weights) == {miner_uid}
        finally:
            await validator.stop()
