# Timelock: sealed challenges and sealed responses

Data sealed to a future drand round can be opened by anyone once that round
is published (every 3 s, worldwide, the same beacon the chain uses for
commit-reveal weights), and by nobody before (spec 8.10). TaoWire offers
two opt-in patterns on top of it.

- **Sealed challenge.** The validator seals the task to open in `reveal_in`
  (default 30 s) and sends it to every miner ahead of time. Miners open it at
  the reveal moment, so none gets a head start from network placement.
- **Sealed response.** The miner answers with its result sealed to a short
  reveal (default 12 s). The validator holds the ciphertext, inside the
  `twresp/1`-signed body, before anyone can read it: a colluding validator
  cannot leak answers before scoring (spec 16.1 row 11).

## Validator

```python
from pydantic import BaseModel
from taowire import SubnetValidator, Task

class Question(BaseModel):
    a: int
    b: int

class Answer(BaseModel):
    total: int

class MyValidator(SubnetValidator):
    # self.timelock is set by the runner (TW_TIMELOCK_*)
    async def make_task(self, round_id: int) -> Task:
        challenge = await self.timelock.seal_challenge(Question(a=2, b=40), reveal_in="10s")
        return Task(route="/v1/solve", body=challenge.model_dump_json().encode(),
                    response_model=Answer, sealed=True, expected=42)

    async def score(self, task, results):
        # results[uid].data is the opened Answer, or ok=False with
        # tw.timelock_unavailable / tw.invalid_response
        return {uid: float(r.ok and r.data.total == task.expected) for uid, r in results.items()}
```

`Task(sealed=True)` tells the runner that miners answer a `SealedResponse`
which opens to `response_model` (required); it opens them before `score`,
refusing any answer that reveals before the query was sent (it was not sealed
for this query: `tw.invalid_response`). Outside the runner:
`await timelock.open_results(results, Answer, not_before=sent_at)`.

**Timeouts.** Miners answer only after the challenge reveals, so
`TW_QUERY_TIMEOUT_S` (default 12 s) must be longer than the challenge's
`reveal_in` plus the miner's work: with the default, keep `reveal_in` around
10 s or raise `TW_QUERY_TIMEOUT_S`. Send the challenge ahead of time (an
earlier round) when the reveal must be longer.

## Miner

```python
from taowire.extensions.timelock import SealedChallenge, SealedResponse

@miner.route("/v1/solve", request=SealedChallenge, response=SealedResponse, timeout_s=60)
async def solve(challenge: SealedChallenge, ctx) -> SealedResponse:
    question = await miner.timelock.open_challenge(challenge, Question)   # waits for the reveal
    return await miner.timelock.seal_response(Answer(total=question.a + question.b), reveal_in="12s")
```

Give the route a `timeout_s` longer than the challenge's reveal (and the
validator a `TW_QUERY_TIMEOUT_S` longer still).

`seal_response` binds the answer to the miner: the sealed plaintext is
`{"hotkey": <the miner>, "answer": ...}`, and `open_results` refuses an answer
sealed by another hotkey, and refuses for every UID a ciphertext that more than
one UID returned (`tw.invalid_response`). A miner cannot pass off another
miner's sealed answer it could not compute itself. `open_challenge` refuses a
challenge whose reveal is more than 60 s in the past (no drand fetch for a
round outside the cache).
`open_challenge` waits until the reveal (at most `max_wait_s`, default 300 s,
because the reveal time comes from the peer) and then allows `timeout_s` for
the drand fetch.

## Opening, limits and failures

`Timelock.open(hex, wait=True, timeout_s=None)`:

- **one drand fetch per round** (the spec's drand cache): every ciphertext
  sealed to the same round opens with that round's signature. It is fetched
  once (concurrent opens wait for the fetch in flight), checked by the
  gateway against a probe sealed locally to the same round (a bad relay
  answer is never used), and kept for the last 64 rounds. Opening is then
  local;
- because the signature is checked, a ciphertext that does not open with it
  is junk: `TimelockMalformed` (`tw.invalid_response` for a miner's answer) at
  once, with no retry and no further drand call. A hostile miner cannot use
  bad answers to hold the limiter or to make the validator hammer drand;
- one deadline per call (`TW_TIMELOCK_TIMEOUT_S`, default 30 s, 1–300). With
  `wait` it sleeps until the reveal first; a reveal later than the deadline
  is `tw.timelock_unavailable` at once, never an unbounded wait. Without
  `wait` an early call raises `TimelockNotReady`;
- the fetch runs in a worker thread under a **process-wide limiter**
  (`TW_TIMELOCK_CONCURRENCY`, default 8, 1–64), each try at most 10 s, with up
  to `TW_TIMELOCK_RETRIES` (default 3, 0–10) retries backing off from 0.5 s.
  Waiting for a beacon that is a moment late is not a retry. A fetch that
  hangs is abandoned at its deadline; live drand threads are capped at 64;
- drand unreachable, rate-limited (HTTP 429), failing (5xx) or timing out
  after the retries is `TimelockUnavailable`: `tw.timelock_unavailable` in
  `MinerResult.error_code`, a WARNING `timelock_unavailable`, and
  `tw_timelock_open_total{result="unavailable"}` (`ok` / `not_ready` too);
- junk that is not a timelock envelope, including one naming a round too far
  away to be a date, is `TimelockMalformed` with no drand call.

Use one `Timelock` per process (`runner.timelock`, `miner.timelock`): its
limiter is what protects the drand API, which the chain's own reveals also
depend on (a localnet chain already sees HTTP 429 from it).

`bt.timelock` and the SDK's compiled core (`bittensor_core`, for the round
signatures) are called only by the chain gateway (`timelock_seal`,
`timelock_parse`, `timelock_signature`, `timelock_decrypt`; ADR-0001, D30);
`FakeChain` provides a fake round clock for tests. Tests that call the real drand API carry the
pytest marker `drand` and run with `just drand-test`, never in `just test`.

## Settings (validator, spec 12.3)

| Variable | Default | Range |
|---|---|---|
| `TW_TIMELOCK_CONCURRENCY` | `8` | 1–64 |
| `TW_TIMELOCK_RETRIES` | `3` | 0–10 |
| `TW_TIMELOCK_TIMEOUT_S` | `30` | 1–300 |

The miner's `miner.timelock` uses the same defaults.
