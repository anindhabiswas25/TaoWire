# Miner guide

A TensorWire miner is a FastAPI app whose routes are protected by the kit:
every request must be signed with btauth/1, addressed to your hotkey, fresh,
not replayed, and sent by a caller your policy allows. This guide covers the
Python miner (`tensorwire.Miner`).

## Minimal miner

```python
from typing import Literal

from pydantic import BaseModel
from tensorwire import Miner, RouteContext


class TransformRequest(BaseModel):
    text: str
    op: Literal["upper", "reverse"]


class TransformResponse(BaseModel):
    result: str


miner = Miner.from_env()  # reads TW_* variables (and .env)


@miner.route("/v1/transform", request=TransformRequest, response=TransformResponse,
             timeout_s=5.0, max_body_bytes=64_000)
async def transform(req: TransformRequest, ctx: RouteContext) -> TransformResponse:
    text = req.text.upper() if req.op == "upper" else req.text[::-1]
    return TransformResponse(result=text)


if __name__ == "__main__":
    miner.run()
```

Required settings: `TW_NETUID`, `TW_WALLET_NAME` (plus `TW_WALLET_HOTKEY` /
`TW_WALLET_PATH` if not the defaults) and `TW_EXTERNAL_IP`, the public address
validators will reach. All settings are listed in `.env.example`.

## Routes

`@miner.route(path, *, request=None, response=None, method="POST", timeout_s=None, max_body_bytes=None, policy=None, legacy_synapse=None, legacy_body_hash=None, encode=None)`

- **Handler**: `async def` or plain `def` (runs in a worker thread), called as
  `handler(request, ctx)`. Return an instance of the response model, or `bytes`.
- **`request`**: a Pydantic model parsed from the verified raw body (422
  `tw.invalid_request` if it does not fit). Without it the handler gets the raw
  body bytes.
- **`method`**: `POST` (default) or `GET`. `GET` routes take no body but are
  signed like any other route.
- **`timeout_s`** / **`max_body_bytes`**: default to `TW_HANDLER_TIMEOUT_S`
  (504 `tw.handler_timeout`) and `TW_MAX_BODY_BYTES` (413).
- **`policy`**: a `CallerPolicy`; default is the strict policy from settings.
- **`legacy_synapse`** / **`legacy_body_hash`**: also accept requests from
  unmodified v10 validators while `TW_LEGACY_V10_UNTIL` is set (see
  "v10 validators" below). Routes declared with `tensorwire.compat.Axon`
  set this themselves.
- **`encode`**: turns the handler's result into the response body (default:
  `model_dump_json` of the response model, or the bytes as returned).

`RouteContext` gives the handler `caller` (`hotkey_ss58`, `nonce_ns`,
`crypto_type`, `scheme`), `caller_neuron` (the caller's `NeuronView`, or
`None` for an allow-listed unregistered hotkey), `request_id` and `route`.

A handler exception becomes 500 `tw.handler_error`; the exception is logged,
never sent. Raising a `tensorwire.errors.TWError` sends that error as is.

Paths `/healthz`, `/readyz` and `/metrics` are reserved. `miner.app` is a
normal FastAPI app; routes you add to it directly are **not** protected.

## Who may call: `CallerPolicy`

```python
from tensorwire import CallerPolicy

CallerPolicy(
    require_registered=True,        # caller must be in the metagraph
    require_validator_permit=True,  # TW_REQUIRE_PERMIT
    min_stake_tao=0.0,              # TW_MIN_CALLER_STAKE_TAO (TAO value at spot price)
    allow_hotkeys=frozenset(),      # TW_ALLOW_HOTKEYS: always allowed
    deny_hotkeys=frozenset(),       # TW_DENY_HOTKEYS: always denied, checked first
)
```

Order: deny list, allow list, registered, validator permit, stake. Each
rejection is 403 with its own code (`tw.forbidden_denied`,
`tw.forbidden_not_registered`, `tw.forbidden_not_validator`,
`tw.forbidden_low_stake`). `TW_DENY_HOTKEYS` applies to every route, including
routes with their own policy.

## What happens to a request

0. The HTTP layer (httptools): the request must arrive completely within
   `TW_AUTH_MAX_AGE_S + TW_AUTH_ALLOWED_SKEW_S` of its first byte (silent and
   slow connections are closed); request line plus headers at most 16 KiB and
   100 fields; ambiguous framing (`Content-Length` with `Transfer-Encoding`,
   two lengths) refused. Each of these answers 400 and closes the connection.
1. Per-IP rate limit (`TW_RATE_IP_PER_S` / `TW_RATE_IP_BURST`): 429. This is
   the outermost layer, so a flood costs as little as possible. Refusals are
   counted in the metrics and logged as one `ip_rate_limited` WARNING per
   client per 10 s with the count, not one line per request.
2. Body size cap, declared and streamed: 413, before any signature work.
3. Route lookup: 404 / 405.
4. Metagraph check: with `TW_METAGRAPH_STRICT=1` and a snapshot past its max
   age, 503 for everyone.
5. btauth/1 verification in a worker thread: 401 `tw.auth_*`. The sender must
   be a prefix-42 SS58 address.
6. Caller policy (or, past the max age, known callers only): 403 / 503.
7. Per-hotkey, per-route rate limit (`TW_RATE_HOTKEY_PER_S` / `_BURST`): 429.
8. Body parsed into the request model: 422.
9. Handler with its timeout: 504 / 500.
10. The response is signed (`twresp/1`, below) and sent.

Every response carries `X-TW-Request-Id`; error bodies are
`{"error": {"code", "message", "request_id"}}`.

## Streaming routes

`@miner.route(..., stream=True)` answers with Server-Sent Events and a signed
`tw-end` trailer (spec 9.2): the handler yields chunks (JSON objects or
arrays). The whole request path runs first, the first chunk is fetched within
`timeout_s`, and `TW_STREAM_MAX_S` / `_MAX_BYTES` / `_IDLE_S` (or
`stream_max_s` / `stream_max_bytes` / `stream_idle_s` per route) bound the
stream; anything that cannot finish ends without a trailer. See
[streaming.md](streaming.md).

## Sealed challenges and answers (timelock)

A validator can send a challenge nobody can read before a drand round, and
ask for an answer sealed the same way, so a leaked answer is useless to other
miners until scoring (spec 8.10). On the miner: `miner.timelock.open_challenge`
waits for the reveal and opens the challenge; `miner.timelock.seal_response`
seals the answer, bound to your hotkey. Give the route a `timeout_s` longer
than the reveal. Drand trouble is `tw.timelock_unavailable`, never a hang. See
[timelock.md](timelock.md#miner).

## Signed responses (`twresp/1`)

With `TW_SIGN_RESPONSES=1` (the default) the miner signs every 200 and every
error raised after the caller was authenticated (403, 422, 429 per-hotkey,
500, 504): headers `X-TW-Resp-Version: 1`, `X-TW-Resp-Hotkey`,
`X-TW-Resp-Signature` (and `X-TW-Resp-Crypto: ed25519` for ed25519 hotkeys).
The signature covers the request's nonce and sender, the miner's hotkey, the
status and the sha256 of the body, so a validator can prove the answer came
from this miner, unchanged, for its own request. Errors before
authentication (401, 413, per-IP 429, 503) are never signed. TensorWire
validators reject unsigned or wrongly signed 200s
(`tw.bad_response_signature`), so turning this off makes your answers count
as failures there. Format: ADR-0004 and `tensorwire.extensions.response_sig`.

## v10 validators (legacy bridge)

During a migration some validators still run the v10 SDK. Set
`TW_LEGACY_V10_UNTIL=<YYYY-MM-DD>` (UTC, at most 180 days ahead; there is no
"forever") and declare the v10 Synapse on the route:

```python
from tensorwire.compat import Synapse

class Transform(Synapse):                     # the v10 class, now on compat
    text: str
    op: str
    result: str | None = None
    required_hash_fields: ClassVar[tuple[str, ...]] = ("text", "op")

@miner.route("/v1/transform", request=TransformRequest, response=TransformResponse,
             legacy_synapse=Transform)
async def transform(req: TransformRequest, ctx: RouteContext) -> TransformResponse: ...
```

v10 requests arrive at `POST /<SynapseName>` (also mounted for you). They go
through the same pipeline with the v10 signature check at step 5, plus the
kit's own freshness window and replay store, then the same caller policy and
rate limits; the answer is in v10 shape (Synapse JSON + `bt_header_axon_*`
headers). A v10 signature covers only `required_hash_fields`, so list every
field that matters there (`tensorwire migrate scan` warns otherwise). After
the end date v10 requests get 410 `tw.legacy_disabled`. Each one is counted
in `tw_legacy_v10_requests_total{direction="inbound"}`; the days left are in
`tw_legacy_v10_days_remaining`. Wire details: `docs/protocol/legacy-v10.md`.

## Chain outages: staged staleness

The miner keeps the latest metagraph snapshot and measures its age:

| Stage | Snapshot age | Behaviour | `/readyz` |
|---|---|---|---|
| Fresh | below `TW_METAGRAPH_SOFT_AGE_S` (900 s; half the max age on short tempos) | normal | 200 |
| Degraded | up to `TW_METAGRAPH_MAX_AGE_S` (2 × tempo) | normal policy on the last snapshot, WARNING every 5 min | 200, `"degraded": ["metagraph_stale"]` |
| Known callers only | beyond the max age | callers that passed policy while fresh or degraded are served; others get 503 `tw.metagraph_stale` | 503 |

A new snapshot clears the known-callers set. Trade-off: a validator that loses
its permit during a long outage keeps access until the chain is readable
again; unknown callers are never admitted on stale data. Set at least one
`TW_CHAIN_FALLBACKS` endpoint (or run your own lite node).

## Startup

`miner.run()` (or any ASGI server running `miner.app`) does, in order:

1. Check the installed `bittensor` SDK; log every weakening setting at WARNING
   (also exported as `tw_unsafe_settings_active`). With TLS, check the
   certificate and key (see [HTTPS](#https) below).
2. Refuse to start if an **unencrypted coldkey** is readable in the wallet
   directory (`TW_REFUSE_IF_COLDKEY_PRESENT=1`, the default). Only the hotkey
   file is read: `<TW_WALLET_PATH>/<TW_WALLET_NAME>/hotkeys/<TW_WALLET_HOTKEY>`,
   unencrypted.
3. Connect to the chain and fetch the metagraph (`TW_STARTUP_TIMEOUT_S`).
4. Exit with **code 3** if the hotkey is not registered on `TW_NETUID`.
5. Build the replay store and both rate limiters (per IP before auth, per
   hotkey and route after it): memory for one process, Redis
   (`TW_REDIS_URL`) when `TW_WORKERS > 1` or `TW_INSTANCE_COUNT > 1`. A
   per-process store or limiter is refused in that case (the
   `TW_UNSAFE_ALLOW_MEMORY_NONCE_MULTIWORKER=1` override covers both and is
   logged as unsafe). The Redis limiter is one atomic Lua token bucket per
   key on Redis's clock, so all workers and hosts share one limit. If Redis
   is unreachable, protected routes answer 503 `tw.replay_store_unavailable`
   (fail closed); `/healthz` and `/readyz` still answer.
   The replay store must keep pairs for at least
   `2 × (TW_AUTH_MAX_AGE_S + TW_AUTH_ALLOWED_SKEW_S)`; `TW_NONCE_RETENTION_S`
   below that refuses to start (D21).
6. Check the clock against NTP (`TW_NTP_SERVERS`).
7. Publish the axon (`TW_EXTERNAL_IP:TW_EXTERNAL_PORT`, protocol
   `TW_PROTOCOL_TAG`) when the chain shows something else and
   `TW_AUTO_SERVE_AXON=1` and `TW_AXON_PUBLISHER=1`. Re-checked every 30 min.
   If the chain answers `rate_limited`, the miner retries after the subnet's
   `serving_rate_limit` blocks (read from the chain).
   With TLS the certificate's key is published too (`ServeAxonTls`) and read
   back; a key the chain did not store refuses startup.

The axon is published before the server starts listening, so a validator
that reads it from the metagraph can reach the miner a moment before it
accepts connections. Clients and deployment checks should wait for `/readyz`
to return 200 rather than for the axon to appear on chain.

On SIGTERM or Ctrl-C the server stops accepting new connections, gives
in-flight requests up to `TW_DRAIN_S` (10 s) to finish, cancels whatever is
still running after that, then closes the chain connection, the replay store
and the rate limiters (`miner_stopped` in the log). Ctrl-C exits with status
130. Give your process manager a stop timeout longer than `TW_DRAIN_S`
(systemd `TimeoutStopSec`, Kubernetes `terminationGracePeriodSeconds`).

`TW_EXTERNAL_IP` is never `0.0.0.0`, `::` or `127.0.0.1` (the chain rejects or
un-serves them). On localnet use `127.0.0.2` (Linux) or the LAN IP with
`TW_ALLOW_PRIVATE_AXONS=1`.

With `TW_WORKERS > 1`, pass the import path:
`miner.run(app_import="my_miner:miner.app")`, and guard the call with
`if __name__ == "__main__":` (each worker imports the module). The
supervising process runs the startup checks once first, so a refusal still
exits with its code (3 = not registered); then every worker starts. Metrics
from all workers are served together on `TW_METRICS_BIND` (counters and
histograms summed, gauges most recent).

## HTTPS

Validators can pin the TLS key a miner publishes on chain
([security.md](security.md#tls-spec-163-d31-adr-0011), ADR-0011). Use an
**Ed25519 or EC P-256** certificate (RSA keys cannot be published); a
self-signed one is fine, the pinned key is the trust anchor:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj "/CN=miner" -addext "subjectAltName=IP:203.0.113.7" \
  -keyout key.pem -out cert.pem && chmod 600 key.pem
```

- TLS in the miner: `TW_TLS_CERT_FILE=cert.pem TW_TLS_KEY_FILE=key.pem`.
- TLS at a reverse proxy: `TW_TLS_PUBLISHED_CERT_FILE=` the proxy's
  certificate, `TW_TRUSTED_PROXIES=` its address, `TW_BIND_HOST=127.0.0.1`,
  `TW_EXTERNAL_PORT=` the proxy's port. Start from
  [`deploy/proxy/`](../deploy/proxy/) (Caddy, nginx): the proxy must pass the
  request target and body unchanged, or every request fails verification.

The miner publishes the key and reads it back at startup. To rotate, restart
with the new certificate (validators refuse the new certificate until its key
is on chain). `tensorwire doctor` checks the certificate, compares it with the
key on chain and probes the port over pinned TLS.

## Health and metrics

- `GET /healthz`: `{"status": "ok"}` while alive.
- `GET /readyz`: `{"status": "ready", "degraded": [...]}` or 503
  `{"status": "not_ready", "reasons": [...]}`; reasons are `starting`,
  `stopping`, `not_registered`, `metagraph_stale`, `nonce_store_unreachable`,
  `rate_limiter_unreachable`, `clock_skew`, `clock_step`; degraded entries
  `metagraph_stale`, `axon_not_published`. The clock is checked at startup
  and every 10 minutes; `clock_skew` clears at the first check that finds
  the clock back within `TW_AUTH_ALLOWED_SKEW_S`.
- **Operator note: wall-clock steps.** If the host's wall clock jumps
  **back** by more than `TW_NONCE_RETENTION_S − (TW_AUTH_MAX_AGE_S +
  TW_AUTH_ALLOWED_SKEW_S)` (48 s with the defaults), the miner logs
  `clock_step_detected` (ERROR, with the size of the step), sets
  `tw_clock_step_seconds`, and for `TW_NONCE_RETENTION_S` seconds answers
  authenticated requests with 503 `tw.replay_store_unavailable` and
  `/readyz` with 503 `clock_step`. This is deliberate: during that time the
  replay store could not tell a replayed request from a new one. It ends on
  its own. To avoid it, let chrony slew the clock instead of stepping it
  after startup (`makestep 1 3` steps only during the first three updates),
  and alert on `clock_step_detected`. A larger `TW_NONCE_RETENTION_S` widens
  the margin (and the length of the window).
- Prometheus metrics on `TW_METRICS_BIND` (127.0.0.1:9100), never on the
  public port. See [metrics.md](metrics.md).

## Testing your miner

The kit's pytest plugin is active once `tensorwire` is installed. Override
`tw_miner` in your `conftest.py` and use `signed_client`:

```python
import pytest
from tensorwire import Miner

from my_subnet.miner import register_routes


@pytest.fixture
def tw_miner(tw_miner_kwargs) -> Miner:
    miner = Miner(**tw_miner_kwargs)   # FakeChain, dev keys, frozen clock
    register_routes(miner)
    return miner


async def test_transform(signed_client):
    r = await signed_client.post("/v1/transform", json={"text": "hi", "op": "upper"})
    assert r.json() == {"result": "HI"}
    r = await signed_client.as_key("charlie").post("/v1/transform", json={})
    assert r.status_code == 403        # charlie has no validator permit
```

Fixture world: `bob` is the miner, `alice` a validator with a permit,
`charlie` registered without a permit, `dave` unregistered, all on netuid 1.
`tw_clock.advance(seconds)` moves time for freshness and staleness tests.

## Debugging: `tensorwire sign-request`

```bash
tensorwire sign-request http://1.2.3.4:8091/v1/transform \
    -r <miner hotkey ss58> -w <wallet> -H <hotkey> \
    -d '{"text": "hi", "op": "upper"}' --send
```

Without `--send` it prints a `curl` command; the signature is valid for
`TW_AUTH_MAX_AGE_S` (10 s), so run it at once.
