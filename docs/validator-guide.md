# Validator guide

A TensorWire validator is a class with two methods, the task and the score.
The kit runs everything else: miner selection, signed queries, response
checks, the score store, and setting weights on the chain's schedule.

## Minimal validator

```python
from tensorwire import MinerResult, SubnetValidator, Task, ValidatorRunner, ValidatorSettings

class MyValidator(SubnetValidator):
    async def make_task(self, round_id: int) -> Task:
        return Task(
            route="/v1/transform",
            body=b'{"text":"hi","op":"upper"}',     # serialized once, signed per miner
            response_model=TransformResponse,
            expected="HI",
        )

    async def score(self, task: Task, results: dict[int, MinerResult]) -> dict[int, float]:
        return {
            uid: 1.0 if r.ok and r.data.result == task.expected else 0.0
            for uid, r in results.items()
        }

if __name__ == "__main__":
    ValidatorRunner(MyValidator(), ValidatorSettings.from_env()).run()
```

`tensorwire init` scaffolds a complete project around this (the text-ops
example, `examples/text-ops-subnet`), with tests that pass out of the box.

## The round

Every `TW_ROUND_INTERVAL_S` (60 s) the runner:

1. reads the metagraph snapshot (refreshed in the background) and resets the
   score of every UID whose hotkey changed (a new owner never inherits a
   score);
2. calls `select_miners(mg)`: by default every neuron with a usable axon and
   no validator permit, except this validator, sampled down to
   `TW_SAMPLE_SIZE` (64), in UID order. `TW_QUERY_VALIDATORS=1` includes
   permit holders. Override `select_miners` for your own rule;
3. calls `make_task(round_id)` and sends it to every selected miner
   (`ValidatorClient.query_many`, below);
4. calls `score(task, results)`; scores are clamped to [0, 1];
5. folds the scores into an EMA per UID, `s = α·new + (1−α)·s`,
   `α = TW_SCORE_ALPHA` (0.1), stored in SQLite (`TW_STATE_DIR/scores.db`);
6. asks the weight scheduler whether weights are due (below).

It logs one `round ok` line per round with `n_queried`, `n_ok`, `n_btauth`,
`n_v10`, `p50_ms`, `p95_ms` and what happened to weights.

`Task` fields: `route`, `body` (bytes), `response_model` (a Pydantic model,
or `None` for raw bytes), `legacy_synapse` (the same request as a v10
Synapse, to reach v10 miners), `method` (`POST`/`GET`), `idempotent` (whether
a timed-out attempt may be retried), `expected` (anything `score` needs).

## `MinerResult`

| Field | Meaning |
|---|---|
| `uid`, `hotkey` | who |
| `ok` | a 200 that passed every check (signature, size, response model) |
| `status` | HTTP status, `None` when nothing came back |
| `latency_ms` | time to the full response |
| `data` | the parsed `response_model`, or raw bytes |
| `error_code` | why it failed (table below) |
| `attempts` | requests sent (each freshly signed) |
| `protocol` | `btauth/1`, or `v10` for a legacy miner |
| `response_verified` | `True` only for a valid `twresp/1` signature |
| `status_message` | the v10 Axon's message (v10 answers) |

Error codes: the miner's own `tw.*` code when it sent one (`tw.forbidden_*`,
`tw.invalid_request`, `tw.handler_timeout`, ...), otherwise
`tw.timeout`, `tw.connect_error`, `tw.http_<status>`,
`tw.bad_response_signature`, `tw.response_too_large`, `tw.invalid_response`,
`tw.no_axon`. **Score every failure as 0**, in particular
`tw.bad_response_signature`: the answer may not be the miner's.

## The client: `ValidatorClient`

`query(neuron, route, body, ...)` and `query_many(neurons, route, body, ...)`
never raise for one miner's failure. Rules (spec 8.8):

- The body is serialized once by you; each miner and each attempt gets its
  own btauth/1 signature, bound to that miner's hotkey, with a fresh nonce.
- The signed target is exactly the raw path httpx sends.
- No transport retries and no redirects. The client retries itself, with a
  new signature, on connect errors, on timeouts (`idempotent=True` only) and
  on 502/503/504; never on 4xx. `TW_MAX_ATTEMPTS` (2).
- Each attempt has a deadline (`TW_QUERY_TIMEOUT_S`, 12 s; `timeout_s=` per
  call) and the response is read with a cap (`TW_MAX_RESPONSE_BYTES`, 4 MiB).
- With `TW_VERIFY_RESPONSES=1` (default) a 200 counts only with a valid
  `twresp/1` signature from that miner, over that request's nonce and
  sender. Signed error answers are verified too.
- Neurons without a usable axon are never contacted (`tw.no_axon`); private
  and loopback axons are refused unless `TW_ALLOW_PRIVATE_AXONS=1` (localnet).

Use it directly when you run your own loop:

```python
from tensorwire import RequestSigner, ValidatorClient

async with ValidatorClient(RequestSigner(hotkey_keypair)) as client:
    results = await client.query_many(neurons, "/v1/transform", body,
                                      response_model=TransformResponse)
```

## Weights

The scheduler submits `SetWeights({uid: score})` for UIDs with a positive
score when the chain says `blocks_since_last_update ≥ weights_rate_limit`
(re-read once per tempo) **and** `TW_MIN_WEIGHT_INTERVAL_BLOCKS` (100) have
passed since its last submission, with `version_key=TW_WEIGHTS_VERSION_KEY`
and `mechid=TW_MECHID`. v11 `SetWeights` normalises, clips and quantises; the
gateway runs the SDK preflight first.

- **What "submitted" means.** On commit-reveal subnets (the default) a
  successful submission is a timelocked **commit included in a block**. The
  weights apply when the commit reveals; until then the chain shows the old
  row. The chain accepts a commit even from a hotkey without a permit; it
  counts only if the hotkey holds one. `tensorwire doctor --role validator`
  shows the permit.
- `rate_limited`: waits the blocks named by the chain, or one tempo.
- `not_registered` / `not_authorized`: logged at ERROR, submissions stop
  (querying continues) until the metagraph shows the hotkey registered with
  a permit again; `/readyz` reports `weights_stopped`.
- All scores zero: nothing is submitted (`tw.no_scores`), so weights are
  never burned on an empty vector.

Every submission is stored in `scores.db` (`weight_submissions`) and counted
in `tw_validator_weight_submissions_total{ok,code}`;
`tw_validator_last_weights_block` is the block of the last commit.

## Reaching v10 miners

While miners migrate, set `TW_LEGACY_V10_CLIENT=auto` and
`TW_LEGACY_V10_CLIENT_UNTIL=<YYYY-MM-DD>` and give tasks a
`legacy_synapse`. A miner advertising `TW_PROTOCOL_TAG` (87) always gets
btauth/1. Others get btauth/1 first; if the answer has the v10 shape the
client sends one v10 request at once and remembers that miner as v10. Once
per tempo those miners are probed with btauth/1 again, so upgraded miners
switch back by themselves. A miner that has answered with a verified
btauth/1 response is never sent v10 again (no downgrade).

v10 answers are never signed: `result.protocol == "v10"` and
`response_verified` is `False`. The default policy counts them; decide in
`score` whether your subnet does. `n_btauth` / `n_v10` per round and
`tw_validator_miners_by_protocol` tell the subnet owner when the transition
can end (`docs/migration-from-v10.md`).

## Running

- **One process per hotkey.** Two processes signing with one hotkey can
  produce the same nonce, and miners reject the second request as a replay.
  The runner holds a lock (`TW_STATE_DIR/locks/<hotkey>.lock`) and refuses
  to start a second time on the same host.
- **Hotkey only.** The runner reads
  `<TW_WALLET_PATH>/<TW_WALLET_NAME>/hotkeys/<TW_WALLET_HOTKEY>` and refuses
  to start next to a readable unencrypted coldkey
  (`TW_REFUSE_IF_COLDKEY_PRESENT=1`).
- **Exit codes.** 3: the hotkey is not registered; 2: invalid settings;
  130: Ctrl-C.
- **Health and metrics** on `TW_METRICS_BIND` (127.0.0.1:9100):
  `/healthz`, `/readyz` (`starting`, `metagraph_stale`, `rounds_stalled`,
  `weights_stopped`), `/metrics`.
- **Shared public IP.** Miners rate-limit per source IP before checking
  signatures (`TW_RATE_IP_PER_S` 50/s, burst 100 by default). Several
  validators behind one NAT address share that budget at every miner; give
  each validator its own address, or keep their combined rate well below it.
- **Check the host** with `tensorwire doctor --role validator`.

## Settings

| Variable | Default | |
|---|---|---|
| `TW_ROUND_INTERVAL_S` | 60 | seconds between rounds |
| `TW_SAMPLE_SIZE` | 64 | miners per round |
| `TW_QUERY_VALIDATORS` | 0 | also query permit holders |
| `TW_QUERY_TIMEOUT_S` | 12 | per attempt |
| `TW_MAX_CONCURRENCY` | 64 | parallel requests |
| `TW_MAX_ATTEMPTS` | 2 | per miner per round |
| `TW_VERIFY_RESPONSES` | 1 | require `twresp/1` |
| `TW_MAX_RESPONSE_BYTES` | 4194304 | |
| `TW_SCORE_ALPHA` | 0.1 | EMA |
| `TW_MIN_WEIGHT_INTERVAL_BLOCKS` | 100 | |
| `TW_WEIGHTS_VERSION_KEY` | 0 | must be ≥ the subnet's stored key |
| `TW_MECHID` | 0 | |
| `TW_LEGACY_V10_CLIENT` | off | `auto` reaches v10 miners |
| `TW_LEGACY_V10_CLIENT_UNTIL` | | required with `auto` |

Plus the common settings (network, netuid, wallet, state dir, metrics bind)
in spec Section 12.1.

## Testing your validator

Run rounds in process against real miners on FakeChain: start each miner
with `miner.running()`, route requests to them with
`tensorwire.testing.transport.AppRouter`, and pass `gateway=`, `metagraph=`,
`hotkey=`, `transport=` and `clock_ns=` to `ValidatorRunner`. The scaffolded
project's `tests/` has a complete example (`test_validator_round_scores_the_miner`).
