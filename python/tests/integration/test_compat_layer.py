"""Integration tests 14 and 15 (spec 13.4): the compat layer.

14. The archived template's ``Dummy`` Synapse and its miner's ``forward``,
    ``blacklist`` and ``priority`` run unchanged on ``compat.Axon``
    (only ``bt.logging`` -> ``logging``, spec 10b.3); ``compat.Dendrite``
    returns the v10 result shapes, including ``dendrite.status_code`` on
    timeout.
15. A ``blacklist_fn`` cannot widen access: one that admits everyone still
    leaves an unregistered caller with 403 ``tw.forbidden_not_registered``.

Template source: https://github.com/latent-to/bittensor-subnet-template
(MIT), ``template/protocol.py`` and ``neurons/miner.py`` at 539b77c.
"""

# The template's code is kept as written (only bt.logging -> logging); its style
# is not ours to fix here.
# ruff: noqa: LOG015, G004, SIM102

from __future__ import annotations

import asyncio
import logging
import typing
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import Field

from tensorwire.chain.gateway import MetagraphView
from tensorwire.compat import Axon, AxonInfo, Dendrite, Metagraph, Synapse, axons_from
from tensorwire.miner.app import Miner
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.pytest_plugin import TEST_NETUID
from tensorwire.testing.transport import AppRouter
from tensorwire.validator.client import ValidatorClient

MINER_ADDRESS = "44.1.2.3:8091"  # the plugin miner's TW_EXTERNAL_IP:TW_BIND_PORT
SLOW_ADDRESS = "44.0.0.9:8091"
DEAD_ADDRESS = "44.0.0.10:8091"


# ---- template/protocol.py (unchanged apart from the import) -----------------
class Dummy(Synapse):
    """
    A simple dummy protocol representation which uses bt.Synapse as its base.
    """

    # Required request input, filled by sending dendrite caller.
    dummy_input: int

    # Optional request output, filled by receiving axon.
    dummy_output: typing.Optional[int] = None  # noqa: UP045 - template code as is

    def deserialize(self) -> int:  # type: ignore[override]
        return self.dummy_output  # type: ignore[return-value]


# ---- neurons/miner.py (bodies unchanged; bt.logging -> logging) -------------
class TemplateMiner:
    def __init__(self, metagraph: Metagraph, *, force_validator_permit: bool) -> None:
        self.metagraph = metagraph
        self.config = SimpleNamespace(
            blacklist=SimpleNamespace(
                allow_non_registered=False,
                force_validator_permit=force_validator_permit,
            )
        )
        self.priorities: list[float] = []

    async def forward(self, synapse: Dummy) -> Dummy:
        synapse.dummy_output = synapse.dummy_input * 2
        return synapse

    async def blacklist(self, synapse: Dummy) -> typing.Tuple[bool, str]:  # noqa: UP006
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            logging.warning("Received a request without a dendrite or hotkey.")
            return True, "Missing dendrite or hotkey"

        uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        if (
            not self.config.blacklist.allow_non_registered
            and synapse.dendrite.hotkey not in self.metagraph.hotkeys
        ):
            logging.debug(
                f"Blacklisting un-registered hotkey {synapse.dendrite.hotkey}"
            )
            return True, "Unrecognized hotkey"

        if self.config.blacklist.force_validator_permit:
            if not self.metagraph.validator_permit[uid]:
                logging.warning(
                    f"Blacklisting a request from non-validator hotkey "
                    f"{synapse.dendrite.hotkey}"
                )
                return True, "Non-validator hotkey"

        logging.debug(f"Not Blacklisting recognized hotkey {synapse.dendrite.hotkey}")
        return False, "Hotkey recognized!"

    async def priority(self, synapse: Dummy) -> float:
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            logging.warning("Received a request without a dendrite or hotkey.")
            return 0.0

        caller_uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        priority = float(self.metagraph.S[caller_uid])
        logging.debug(f"Prioritizing {synapse.dendrite.hotkey} with value: {priority}")
        self.priorities.append(priority)
        return priority


async def slow_app(scope: Any, receive: Any, send: Any) -> None:
    await asyncio.sleep(5)


def make_axon(kwargs: dict[str, Any], **settings: Any) -> tuple[Axon, TemplateMiner]:
    kw = dict(kwargs)
    kw["settings"] = kw["settings"].model_copy(update=settings)
    miner = Miner(**kw)
    template = TemplateMiner(Metagraph(kw["metagraph"]), force_validator_permit=True)
    axon = Axon(miner=miner)
    axon.attach(
        forward_fn=template.forward,
        blacklist_fn=template.blacklist,
        priority_fn=template.priority,
    ).serve(netuid=TEST_NETUID)
    return axon, template


@pytest.fixture
async def setup(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain
) -> AsyncIterator[tuple[AppRouter, TemplateMiner, Any]]:
    fake_chain.register(TEST_NETUID, dev_key("eve").ss58)  # registered, no axon
    axon, template = make_axon(tw_miner_kwargs, require_permit=False)
    router = AppRouter()
    async with axon.miner.running() as app:
        router.add(MINER_ADDRESS, app)
        router.add(SLOW_ADDRESS, slow_app)
        yield router, template, axon.miner


async def metagraph(fake_chain: FakeChain) -> MetagraphView:
    await fake_chain.connect()
    return await fake_chain.metagraph(TEST_NETUID)


def dendrite(router: AppRouter, clock: FakeClock, key: str = "alice") -> Dendrite:
    signer = dev_key(key).signer(clock_ns=clock.now_ns)  # type: ignore[arg-type]
    return Dendrite(client=ValidatorClient(signer, transport=router))


# 14 ---------------------------------------------------------------------------
async def test_14_template_code_runs_on_compat(
    setup: tuple[AppRouter, TemplateMiner, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
) -> None:
    router, template, _ = setup
    fake_chain.set_axon(TEST_NETUID, dev_key("charlie").ss58, SLOW_ADDRESS)
    mg = await metagraph(fake_chain)
    bob = mg.by_hotkey(dev_key("bob").ss58)
    charlie = mg.by_hotkey(dev_key("charlie").ss58)
    eve = mg.by_hotkey(dev_key("eve").ss58)
    assert bob is not None
    assert charlie is not None
    assert eve is not None
    axons = axons_from(mg, uids=[bob.uid, charlie.uid, eve.uid])
    assert [a.is_serving for a in axons] == [True, True, False]

    async with dendrite(router, tw_clock) as d:
        values = await d(axons=axons, synapse=Dummy(dummy_input=21), timeout=0.3)
        full = await d(axons, Dummy(dummy_input=4), timeout=0.3, deserialize=False)
        single = await d(axons=axons[0], synapse=Dummy(dummy_input=1), timeout=2)

    assert values == [42, None, None]
    assert single == 2
    ok, timed_out, unserved = full
    assert ok.dummy_output == 8
    assert ok.dendrite.status_code == 200
    assert ok.is_success
    assert ok.dendrite.status_message == "Success"
    assert ok.dendrite.process_time is not None
    assert ok.dendrite.hotkey == dev_key("alice").ss58
    assert ok.axon.hotkey == dev_key("bob").ss58
    assert (ok.axon.ip, ok.axon.port) == ("44.1.2.3", 8091)
    assert timed_out.dendrite.status_code == 408
    assert timed_out.is_timeout
    assert timed_out.dendrite.status_message == "tw.timeout"
    assert timed_out.dummy_output is None
    assert unserved.dendrite.status_code == 503
    assert unserved.dendrite.status_message == "tw.no_axon"
    assert template.priorities == [1000.0, 1000.0, 1000.0]  # alice's stake


async def test_14_template_blacklist_still_runs(
    setup: tuple[AppRouter, TemplateMiner, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
) -> None:
    # TW_REQUIRE_PERMIT=0 here, so the kit admits charlie (registered); the
    # template's own blacklist (force_validator_permit) then refuses him.
    router, _, _ = setup
    mg = await metagraph(fake_chain)
    async with dendrite(router, tw_clock, key="charlie") as d:
        (item,) = await d(
            axons_from(mg, uids=[0]), Dummy(dummy_input=1), deserialize=False
        )
    assert item.dendrite.status_code == 403
    assert item.is_blacklist
    assert item.dendrite.status_message == "tw.forbidden_blacklisted"


async def test_14_connect_error_is_503(
    setup: tuple[AppRouter, TemplateMiner, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
) -> None:
    router, _, _ = setup
    fake_chain.set_axon(TEST_NETUID, dev_key("charlie").ss58, DEAD_ADDRESS)
    mg = await metagraph(fake_chain)
    charlie = mg.by_hotkey(dev_key("charlie").ss58)
    assert charlie is not None
    async with dendrite(router, tw_clock) as d:
        item = await d(
            AxonInfo.from_neuron(charlie), Dummy(dummy_input=1), deserialize=False
        )
    assert item.dendrite.status_code == 503
    assert item.dendrite.status_message == "tw.connect_error"


async def test_14_wire_body_is_only_the_synapse_fields(
    setup: tuple[AppRouter, TemplateMiner, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
) -> None:
    router, _, _ = setup
    seen: list[bytes] = []
    inner = router.handle_async_request

    async def spy(request: Any) -> Any:
        seen.append(request.content)
        return await inner(request)

    router.handle_async_request = spy  # type: ignore[method-assign]
    mg = await metagraph(fake_chain)
    async with dendrite(router, tw_clock) as d:
        await d(axons_from(mg, uids=[0]), Dummy(dummy_input=3))
    assert seen == [b'{"dummy_input":3,"dummy_output":null}']


class Frozen(Synapse):
    text: str = Field(frozen=True)  # v10 code: Field(..., allow_mutation=False)
    answer: str | None = None


async def test_14_frozen_request_fields_keep_their_value(
    setup: tuple[AppRouter, TemplateMiner, Any],  # publishes the axon
    fake_chain: FakeChain,
    tw_clock: FakeClock,
) -> None:
    async def app(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        body = b'{"text": "changed by the miner", "answer": "ok"}'
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    signer = dev_key("alice").signer(clock_ns=tw_clock.now_ns)  # type: ignore[arg-type]
    client = ValidatorClient(
        signer, transport=AppRouter({MINER_ADDRESS: app}), verify_responses=False
    )
    mg = await metagraph(fake_chain)
    async with Dendrite(client=client) as d:
        (item,) = await d(
            axons_from(mg, uids=[0]), Frozen(text="mine"), deserialize=False
        )
    assert item.dendrite.status_code == 200
    assert (item.text, item.answer) == ("mine", "ok")


# 15 ---------------------------------------------------------------------------
async def test_15_blacklist_cannot_widen_access(
    tw_miner_kwargs: dict[str, Any], fake_chain: FakeChain, tw_clock: FakeClock
) -> None:
    miner = Miner(**tw_miner_kwargs)
    calls: list[str] = []

    async def forward(synapse: Dummy) -> Dummy:
        synapse.dummy_output = 1
        return synapse

    def allow_everyone(synapse: Dummy) -> tuple[bool, str]:
        calls.append(str(synapse.dendrite.hotkey if synapse.dendrite else None))
        return False, "everyone is welcome"

    Axon(miner=miner).attach(forward_fn=forward, blacklist_fn=allow_everyone)
    router = AppRouter()
    async with miner.running() as app:
        router.add(MINER_ADDRESS, app)
        mg = await metagraph(fake_chain)
        for key, code in (
            ("dave", "tw.forbidden_not_registered"),
            ("charlie", "tw.forbidden_not_validator"),
        ):
            async with dendrite(router, tw_clock, key=key) as d:
                (item,) = await d(
                    axons_from(mg, uids=[0]), Dummy(dummy_input=1), deserialize=False
                )
            assert item.dendrite.status_code == 403
            assert item.dendrite.status_message == code
        async with dendrite(router, tw_clock) as d:
            assert await d(axons_from(mg, uids=[0]), Dummy(dummy_input=1)) == [1]
    assert calls == [dev_key("alice").ss58]  # only the admitted caller reached it
