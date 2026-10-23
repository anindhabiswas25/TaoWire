"""``compat.StreamingSynapse`` end to end (spec 10b.2.1, 9.2; WP4).

The Synapse is the archived template's ``StreamPrompting``, loaded unchanged
from ``after/docs/stream_tutorial/protocol.py`` (the ``migrate apply``
output of the v10 original). The miner's forward has the template's shape
(``synapse.create_streaming_response(token_streamer)``, the streamer sends
body frames of ``N`` tokens); the validator calls ``compat.Dendrite`` as the
template's ``client.py`` does (``streaming=True``, one async generator per
axon, chunks then the final Synapse).
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from collections.abc import MutableMapping
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from tensorwire.compat import Axon, AxonInfo, Dendrite
from tensorwire.miner.app import Miner
from tensorwire.testing.clock import FakeClock
from tensorwire.testing.fake_chain import FakeChain
from tensorwire.testing.keys import dev_key
from tensorwire.testing.pytest_plugin import MINER_KEY, TEST_NETUID
from tensorwire.testing.transport import AppRouter

# The template's protocol uses pydantic v1's Field(allow_mutation=False): pydantic 2
# warns about it (under bittensor 10.5.0 too). Not a kit warning, so ignored here.
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.filterwarnings("ignore::pydantic.warnings.PydanticDeprecatedSince20"),
]

PROTOCOL = (
    Path(__file__).resolve().parents[3]
    / "examples/migrations/template-v10-to-v11/after/docs/stream_tutorial/protocol.py"
)
ADDRESS = "44.1.2.3:8091"
TOKENS = ["Hello", " stream", "ing", " world", "!", " ☃"]


def load_protocol() -> Any:
    spec = importlib.util.spec_from_file_location("stream_protocol", PROTOCOL)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["stream_protocol"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def protocol() -> Any:
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # see pytestmark
        return load_protocol()


def make_forward(protocol: Any, *, stall_s: float = 0.0) -> Any:
    """The template's ``prompt`` shape (docs/stream_tutorial/miner.py), no model."""

    def prompt(synapse: Any) -> Any:  # a plain def, as in the template
        async def _prompt(text: str, send: Any) -> None:
            buffer = []
            n = 3  # tokens per frame, as the template does
            for token in TOKENS:
                buffer.append(token)
                if len(buffer) == n:
                    await send(
                        {
                            "type": "http.response.body",
                            "body": "".join(buffer).encode("utf-8"),
                            "more_body": True,
                        }
                    )
                    buffer = []
                    await asyncio.sleep(stall_s)
            await send(
                {
                    "type": "http.response.body",
                    "body": "".join(buffer).encode("utf-8"),
                    "more_body": False,
                }
            )

        token_streamer = partial(_prompt, synapse.messages[0])
        return synapse.create_streaming_response(token_streamer)

    # As the template writes it: def _prompt(self, synapse: StreamPrompting)
    prompt.__annotations__ = {"synapse": protocol.StreamPrompting}
    return prompt


@pytest.fixture
def tw_miner(tw_miner_kwargs: dict[str, Any], protocol: Any) -> Miner:
    miner = Miner(**tw_miner_kwargs)
    Axon(miner=miner).attach(forward_fn=make_forward(protocol))
    return miner


@pytest.fixture
async def axon(
    miner_app: Any, fake_chain: FakeChain
) -> tuple[AppRouter, AxonInfo, Any]:
    fake_chain.set_axon(TEST_NETUID, dev_key(MINER_KEY).ss58, ADDRESS, protocol=87)
    mg = await fake_chain.metagraph(TEST_NETUID)
    neuron = mg.by_hotkey(dev_key(MINER_KEY).ss58)
    assert neuron is not None
    return AppRouter({ADDRESS: miner_app}), AxonInfo.from_neuron(neuron), miner_app


def dendrite(router: AppRouter, clock: FakeClock) -> Dendrite:
    return Dendrite(dev_key("alice").signer(clock_ns=clock.now_ns), transport=router)


def request(protocol: Any) -> Any:
    return protocol.StreamPrompting(roles=["user"], messages=["hello, stream"])


async def collect(generator: Any) -> tuple[list[Any], Any]:
    """The template client's loop: lists are token chunks, the rest is final."""
    chunks, final = [], None
    async for chunk in generator:
        if isinstance(chunk, list):
            chunks.append(chunk)
        else:
            final = chunk
    return chunks, final


async def test_the_template_stream_runs_unchanged(
    axon: tuple[AppRouter, AxonInfo, Any], tw_clock: FakeClock, protocol: Any
) -> None:
    router, info, _ = axon
    async with dendrite(router, tw_clock) as d:
        responses = await d(
            [info], request(protocol), deserialize=False, streaming=True
        )
        assert len(responses) == 1  # one async generator per axon, as in v10
        chunks, final = await collect(responses[0])
    assert ["".join(c) for c in chunks] == ["Hello streaming", " world! ☃"]
    assert isinstance(final, protocol.StreamPrompting)
    assert final.completion == "".join(TOKENS)
    assert final.dendrite.status_code == 200
    assert final.dendrite.process_time is not None
    assert final.axon.hotkey == dev_key(MINER_KEY).ss58
    assert final.messages == ["hello, stream"]


async def test_deserialize_and_a_single_axon(
    axon: tuple[AppRouter, AxonInfo, Any], tw_clock: FakeClock, protocol: Any
) -> None:
    router, info, _ = axon
    async with dendrite(router, tw_clock) as d:
        generator = await d(info, request(protocol), deserialize=True)
        _, final = await collect(generator)
    assert final == "".join(TOKENS)  # StreamPrompting.deserialize() -> completion


def tamper(app: Any) -> Any:
    """Flip one byte of the streamed frames (the trailer then fails)."""

    async def wrapped(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        async def send_tampered(message: MutableMapping[str, Any]) -> None:
            body = message.get("body", b"")
            if message["type"] == "http.response.body" and b'"b":"' in body:
                message["body"] = body.replace(b'"b":"S', b'"b":"T', 1)
            await send(message)

        await app(scope, receive, send_tampered)

    return wrapped


async def test_a_rejected_trailer_gives_back_the_request_with_an_error(
    axon: tuple[AppRouter, AxonInfo, Any], tw_clock: FakeClock, protocol: Any
) -> None:
    router, info, app = axon
    router.add(ADDRESS, tamper(app))
    async with dendrite(router, tw_clock) as d:
        generator = await d(info, request(protocol), deserialize=False)
        chunks, final = await collect(generator)
    assert chunks  # the user code saw (unverified) chunks on the way ...
    assert final.completion == ""  # ... but the final item has none of them
    assert final.dendrite.status_code == 500
    assert final.dendrite.status_message == "tw.bad_response_signature"
    assert final.dendrite.process_time is not None


async def test_a_timeout_sets_408_and_process_time(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    protocol: Any,
) -> None:
    miner = Miner(**tw_miner_kwargs)
    Axon(miner=miner).attach(forward_fn=make_forward(protocol, stall_s=5.0))
    fake_chain.set_axon(TEST_NETUID, dev_key(MINER_KEY).ss58, ADDRESS, protocol=87)
    await fake_chain.connect()
    neuron = (await fake_chain.metagraph(TEST_NETUID)).by_hotkey(
        dev_key(MINER_KEY).ss58
    )
    assert neuron is not None
    async with miner.running() as app:
        d = dendrite(AppRouter({ADDRESS: app}), tw_clock)
        async with d:
            # The ASGI transport hands over a response once the app ends; the
            # miner cuts this one at its idle limit (TW_STREAM_IDLE_S), so give
            # the dendrite a shorter timeout than that.
            generator = await d(
                AxonInfo.from_neuron(neuron),
                request(protocol),
                timeout=1.0,
                deserialize=False,
            )
            _, final = await collect(generator)
    assert final.dendrite.status_code == 408
    assert final.dendrite.status_message == "tw.timeout"
    assert final.completion == ""


async def test_a_forward_that_does_not_stream_is_a_500(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    protocol: Any,
) -> None:
    miner = Miner(**tw_miner_kwargs)

    def forward(synapse: Any) -> Any:
        return synapse  # forgot create_streaming_response

    forward.__annotations__ = {"synapse": protocol.StreamPrompting}

    Axon(miner=miner).attach(forward_fn=forward)
    fake_chain.set_axon(TEST_NETUID, dev_key(MINER_KEY).ss58, ADDRESS, protocol=87)
    await fake_chain.connect()
    neuron = (await fake_chain.metagraph(TEST_NETUID)).by_hotkey(
        dev_key(MINER_KEY).ss58
    )
    assert neuron is not None
    async with (
        miner.running() as app,
        dendrite(AppRouter({ADDRESS: app}), tw_clock) as d,
    ):
        generator = await d(
            AxonInfo.from_neuron(neuron), request(protocol), deserialize=False
        )
        _, final = await collect(generator)
    assert final.dendrite.status_code == 500
    assert final.dendrite.status_message == "tw.handler_error"


async def test_a_failure_in_the_users_stream_code_is_the_final_status(
    axon: tuple[AppRouter, AxonInfo, Any], tw_clock: FakeClock, protocol: Any
) -> None:
    router, info, _ = axon

    # Same class name, so the same route /StreamPrompting; its reader breaks.
    class StreamPrompting(protocol.StreamPrompting):  # type: ignore[misc, name-defined]
        async def process_streaming_response(self, response: Any) -> Any:
            async for chunk in response.content.iter_any():
                yield chunk
                raise ValueError("bad token")

    seen: list[Any] = []
    req = StreamPrompting(roles=["user"], messages=["hi"])
    async with dendrite(router, tw_clock) as d:
        d._on_results = seen.append
        generator = await d(info, req, deserialize=False)
        chunks, final = await collect(generator)
    assert chunks == []  # the generator yielded bytes, not the template's lists
    assert final.dendrite.status_code == 500
    assert final.dendrite.status_message == "tw.invalid_response"
    assert final.completion == ""
    (results,) = seen
    # The round report gets the miner's real outcome (its stream verified);
    # only the final item says the validator's own code failed.
    assert next(iter(results.values())).ok


async def test_extract_response_json_fills_the_final_synapse_as_v10(
    axon: tuple[AppRouter, AxonInfo, Any], tw_clock: FakeClock, protocol: Any
) -> None:
    router, info, _ = axon

    class StreamPrompting(protocol.StreamPrompting):  # type: ignore[misc, name-defined]
        async def process_streaming_response(self, response: Any) -> Any:
            async for chunk in response.content.iter_any():
                yield [chunk.decode()]  # completion left empty on purpose

        def extract_response_json(self, response: Any) -> dict[str, Any]:
            return {"roles": self.roles, "messages": self.messages, "completion": "X"}

    async with dendrite(router, tw_clock) as d:
        _, final = await collect(
            await d(
                info, StreamPrompting(roles=["u"], messages=["m"]), deserialize=False
            )
        )
    assert final.dendrite.status_code == 200
    assert final.completion == "X"  # v10's process_server_response merge


async def test_a_failing_extract_response_json_is_a_status_not_a_crash(
    axon: tuple[AppRouter, AxonInfo, Any], tw_clock: FakeClock, protocol: Any
) -> None:
    router, info, _ = axon

    class StreamPrompting(protocol.StreamPrompting):  # type: ignore[misc, name-defined]
        def extract_response_json(self, response: Any) -> dict[str, Any]:
            return {
                "x": response.headers["Content-Type"]
            }  # aiohttp-style key: KeyError

    seen: list[Any] = []
    async with dendrite(router, tw_clock) as d:
        d._on_results = seen.append
        _, final = await collect(
            await d(
                info, StreamPrompting(roles=["u"], messages=["m"]), deserialize=False
            )
        )
    assert final.dendrite.status_code == 500
    assert final.completion == ""
    (results,) = seen
    assert next(iter(results.values())).ok  # the miner's stream was fine


async def test_v10_timeout_never_loosens_tw_stream_max_s(
    axon: tuple[AppRouter, AxonInfo, Any], tw_clock: FakeClock, protocol: Any
) -> None:
    from tensorwire.extensions.streaming import StreamLimits

    router, info, _ = axon
    d = Dendrite(
        dev_key("alice").signer(clock_ns=tw_clock.now_ns),
        transport=router,
        stream_limits=StreamLimits(max_s=5),
    )
    calls: list[dict[str, Any]] = []
    original = d.client.stream

    def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs)
        return original(*args, **kwargs)

    d.client.stream = spy  # type: ignore[method-assign]
    async with d:
        await collect(await d(info, request(protocol), timeout=300))
    assert calls[0]["max_s"] == 5


async def test_the_priority_slot_covers_the_whole_stream(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    protocol: Any,
) -> None:
    miner = Miner(**tw_miner_kwargs)
    running = peak = 0

    def forward(synapse: Any) -> Any:
        async def streamer(send: Any) -> None:
            nonlocal running, peak
            running += 1
            peak = max(peak, running)
            await asyncio.sleep(0.2)
            await send({"type": "http.response.body", "body": b"tok"})
            running -= 1

        return synapse.create_streaming_response(streamer)

    forward.__annotations__ = {"synapse": protocol.StreamPrompting}
    Axon(miner=miner).attach(
        forward_fn=forward, priority_fn=lambda s: 1.0, max_concurrency=1
    )
    fake_chain.set_axon(TEST_NETUID, dev_key(MINER_KEY).ss58, ADDRESS, protocol=87)
    await fake_chain.connect()
    neuron = (await fake_chain.metagraph(TEST_NETUID)).by_hotkey(
        dev_key(MINER_KEY).ss58
    )
    assert neuron is not None
    async with (
        miner.running() as app,
        dendrite(AppRouter({ADDRESS: app}), tw_clock) as d,
    ):
        info = AxonInfo.from_neuron(neuron)
        finals = await asyncio.gather(
            *[
                collect(await d(info, request(protocol), deserialize=False))
                for _ in range(3)
            ]
        )
    assert all(f.dendrite.status_code == 200 for _, f in finals)
    assert peak == 1  # max_concurrency held while each token streamer ran


async def test_the_priority_slot_also_covers_forward_and_never_leaks(
    tw_miner_kwargs: dict[str, Any],
    fake_chain: FakeChain,
    tw_clock: FakeClock,
    protocol: Any,
) -> None:
    """forward_fn runs under the slot too; a failing forward gives it back."""
    miner = Miner(**tw_miner_kwargs)
    in_forward = peak = 0
    fail_next = [True]

    async def forward(synapse: Any) -> Any:
        nonlocal in_forward, peak
        in_forward += 1
        peak = max(peak, in_forward)
        await asyncio.sleep(0.1)  # heavy set-up before streaming
        in_forward -= 1
        if fail_next and fail_next.pop():
            raise RuntimeError("model not loaded")

        async def streamer(send: Any) -> None:
            await send({"type": "http.response.body", "body": b"tok"})

        return synapse.create_streaming_response(streamer)

    forward.__annotations__ = {"synapse": protocol.StreamPrompting}
    axon = Axon(miner=miner)
    axon.attach(forward_fn=forward, priority_fn=lambda s: 1.0, max_concurrency=1)
    fake_chain.set_axon(TEST_NETUID, dev_key(MINER_KEY).ss58, ADDRESS, protocol=87)
    await fake_chain.connect()
    neuron = (await fake_chain.metagraph(TEST_NETUID)).by_hotkey(
        dev_key(MINER_KEY).ss58
    )
    assert neuron is not None
    async with (
        miner.running() as app,
        dendrite(AppRouter({ADDRESS: app}), tw_clock) as d,
    ):
        info = AxonInfo.from_neuron(neuron)
        finals = await asyncio.gather(
            *[
                collect(await d(info, request(protocol), deserialize=False))
                for _ in range(3)
            ]
        )
    codes = sorted(f.dendrite.status_code for _, f in finals)
    assert codes == [200, 200, 500]  # the first forward failed, the slot came back
    assert peak == 1  # forward_fn itself ran under the gate
    assert axon.gates["/StreamPrompting"].queued == 0
