"""D16 (spec v1.5, 8.11.3 step 5): a miner that rolls back to v10 is reached
over v10 again after the next metagraph refresh, with no validator restart.

Uses Engineer B's real ``ProtocolSelector``; the runner's refresh path is
what decides when it forgets.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import structlog

from taowire.config import ValidatorSettings
from taowire.extensions.legacy_v10.client import ProtocolSelector
from taowire.testing.clock import FakeClock
from taowire.testing.fake_chain import FakeChain
from taowire.testing.keys import dev_key
from taowire.testing.metagraph import FakeMetagraphSource
from taowire.testing.pytest_plugin import TEST_NETUID
from taowire.validator.client import MinerResult
from taowire.validator.loop import SubnetValidator, Task, ValidatorRunner

V10_MARKER = (500, [("bt_header_axon_status_code", "500")])  # vector N7
AXON = "44.1.2.3:8091"


class Idle(SubnetValidator):
    async def make_task(self, round_id: int) -> Task:
        return Task(route="/v1/x", body=b"{}")

    async def score(
        self, task: Task, results: dict[int, MinerResult]
    ) -> dict[int, float]:
        return {}


async def test_tag_change_away_from_the_kit_allows_v10_again(
    fake_chain: FakeChain, tw_clock: FakeClock, tmp_path: Path
) -> None:
    until = dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=28)
    s = ValidatorSettings(
        netuid=TEST_NETUID,
        wallet_name="v",
        wallet_path=tmp_path / "w",
        state_dir=tmp_path / "s",
        legacy_v10_client="auto",
        legacy_v10_client_until=until,
    )
    selector = ProtocolSelector(s.protocol_tag, until=until)
    bob = dev_key("bob").ss58
    fake_chain.set_axon(TEST_NETUID, bob, AXON, protocol=s.protocol_tag)
    gateway = fake_chain.with_signer(dev_key("alice").ss58)
    source = FakeMetagraphSource(gateway, TEST_NETUID, clock=tw_clock.monotonic)
    legacy_client: Any = object()
    runner = ValidatorRunner(
        Idle(),
        s,
        gateway=gateway,
        metagraph=source,
        hotkey=dev_key("alice").keypair,
        legacy=lambda settings, signer: (legacy_client, selector),
        check_sdk=False,
    )

    async def refresh() -> Any:
        mg = await source.refresh_now()
        await runner.begin_round(mg)
        return mg.by_hotkey(bob)

    async with runner.running():
        neuron = await refresh()
        # Bob answers over btauth/1 (verified): from now on, no downgrade.
        selector.after_btauth(neuron, status=200, headers=None, verified=True)
        assert selector.known(bob) == "btauth/1"

        # No tag change: a v10-shaped answer still never downgrades.
        neuron = await refresh()
        assert selector.known(bob) == "btauth/1"
        assert not selector.after_btauth(
            neuron, status=V10_MARKER[0], headers=V10_MARKER[1], verified=False
        )

        # Bob rolls back: his own ServeAxon publishes the v10 tag (4).
        fake_chain.set_axon(TEST_NETUID, bob, AXON, protocol=4)
        with structlog.testing.capture_logs() as logs:
            neuron = await refresh()
        assert selector.known(bob) is None
        assert any(
            e["event"] == "legacy_v10_protocol_tag_changed"
            and e["before"] == s.protocol_tag
            and e["now"] == 4
            for e in logs
        )
        assert selector.after_btauth(  # the next query falls back to v10
            neuron, status=V10_MARKER[0], headers=V10_MARKER[1], verified=False
        )
        assert selector.choose(neuron) == "v10"

        # A tag change between two non-kit values forgets nothing.
        fake_chain.set_axon(TEST_NETUID, bob, AXON, protocol=5)
        await refresh()
        assert selector.known(bob) == "v10"
