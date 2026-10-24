"""text-ops-subnet tests: run in process on TaoWire's FakeChain, no network.

The ``tw_miner_kwargs``, ``fake_chain`` and ``tw_clock`` fixtures come from
TaoWire's pytest plugin (installed with ``taowire``).
"""

from __future__ import annotations

import hashlib
import random
from pathlib import Path
from typing import Any

import pytest
from taowire import Miner, MinerResult, ValidatorSettings
from taowire.testing.clock import FakeClock
from taowire.testing.fake_chain import FakeChain
from taowire.testing.keys import dev_key
from taowire.testing.metagraph import FakeMetagraphSource
from taowire.testing.pytest_plugin import TEST_NETUID
from taowire.testing.transport import AppRouter
from taowire.validator.loop import ValidatorRunner

from text_ops.miner import register
from text_ops.protocol import (
    ALPHABET,
    ROUTE,
    STREAM_ROUTE,
    TransformRequest,
    TransformResponse,
    expected,
    pieces,
    random_request,
)
from text_ops.scoring import latency_factor, score
from text_ops.validator import TextOpsValidator

MINER_ADDRESS = "44.1.2.3:8091"  # the plugin miner's published axon


@pytest.fixture
def tw_miner(tw_miner_kwargs: dict[str, Any]) -> Miner:
    return register(Miner(**tw_miner_kwargs))


@pytest.mark.parametrize(
    ("op", "result"),
    [
        ("upper", "HELLO WORLD"),
        ("reverse", "dlrow olleh"),
        ("sha256", hashlib.sha256(b"hello world").hexdigest()),
    ],
)
async def test_miner_answers(signed_client: Any, op: str, result: str) -> None:
    r = await signed_client.post(ROUTE, json={"text": "hello world", "op": op})
    assert r.status_code == 200
    assert r.json() == {"result": result}


async def test_miner_streams_the_result_in_pieces(signed_client: Any) -> None:
    text = "abc " * 20
    r = await signed_client.post(STREAM_ROUTE, json={"text": text, "op": "upper"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    chunks = [
        line.removeprefix("data: ")
        for line in r.text.split("\n")
        if line.startswith('data: {"i"')
    ]
    assert "".join(chunks) != ""
    assert chunks == [
        p.model_dump_json() for p in pieces(TransformRequest(text=text, op="upper"))
    ]
    assert "event: tw-end" in r.text


def test_pieces_join_to_the_result() -> None:
    req = TransformRequest(text="x" * 100, op="sha256")
    got = pieces(req)
    assert [p.i for p in got] == [0, 1]
    assert "".join(p.piece for p in got) == expected(req)


async def test_miner_rejects_bad_requests(signed_client: Any) -> None:
    r = await signed_client.post(ROUTE, json={"text": "", "op": "upper"})
    assert r.status_code == 422
    unsigned = await signed_client.http.post(ROUTE, json={"text": "a", "op": "upper"})
    assert unsigned.status_code == 401


def test_tasks_are_ascii_and_in_range() -> None:
    rng = random.Random(7)
    for _ in range(50):
        req = random_request(rng)
        assert 64 <= len(req.text) <= 512
        assert set(req.text) <= set(ALPHABET)


def result(ok: bool = True, answer: str = "", latency_ms: float = 0.0) -> MinerResult:
    return MinerResult(
        uid=0,
        hotkey="hk",
        ok=ok,
        status=200 if ok else None,
        latency_ms=latency_ms,
        data=TransformResponse(result=answer) if ok else None,
        error_code=None if ok else "tw.timeout",
        attempts=1,
    )


def test_scoring() -> None:
    req = TransformRequest(text="abc", op="upper")
    assert score(req, result(answer="ABC"), 1000) == 1.0
    assert score(req, result(answer="ABC", latency_ms=500), 1000) == 0.5
    assert score(req, result(answer="ABC", latency_ms=5000), 1000) == 0.2
    assert score(req, result(answer="abc"), 1000) == 0.0
    assert score(req, result(ok=False), 1000) == 0.0
    assert latency_factor(None, 1000) == 0.2
    assert expected(TransformRequest(text="ab", op="reverse")) == "ba"


async def test_validator_round_scores_the_miner(
    miner_app: Any,
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    tmp_path: Path,
) -> None:
    gateway = fake_chain.with_signer(dev_key("alice").ss58)
    runner = ValidatorRunner(
        TextOpsValidator(rng=random.Random(1)),
        ValidatorSettings(
            netuid=TEST_NETUID,
            wallet_name="validator",
            wallet_path=tmp_path / "wallets",
            state_dir=tmp_path / "state",
        ),
        gateway=gateway,
        metagraph=FakeMetagraphSource(gateway, TEST_NETUID, clock=tw_clock.monotonic),
        hotkey=dev_key("alice").keypair,
        transport=AppRouter({MINER_ADDRESS: miner_app}),
        clock_ns=tw_clock.now_ns,
        check_sdk=False,
    )
    async with runner.running():
        report = await runner.run_round()
    assert report is not None
    assert report.n_ok == 1
    miner_uid = 0
    assert report.scores[miner_uid] > 0.2
