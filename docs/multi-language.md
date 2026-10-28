# Multi-language support

TaoWire's Python package is the reference implementation. Miners written in other languages use a
btauth/1 package for their language (spec 11). Every row of spec 11.1 is built:

| Capability (spec 11.1) | Python | Go (`go/btauth`) | Rust (`taowire-btauth`) | TypeScript (`@taowire/btauth`) |
|---|---|---|---|---|
| btauth/1 sign + verify | ✅ | ✅ | ✅ | ✅ (`sr25519Verify` / `ed25519Verify`, WASM) |
| Monotonic nonce | ✅ | ✅ `NonceSource` (atomic CAS) | ✅ `NonceSource` (`AtomicU64`) | ✅ `NonceSource` (`bigint`) |
| Memory + Redis nonce store | ✅ | ✅ `MemoryStore`, `redisstore` | ✅ `MemoryStore`, `redis_store` (feature) | ✅ `MemoryStore`, `RedisNonceStore` (`/redis`, ioredis) |
| Server adapter | FastAPI | `net/http` `Middleware` | axum `protect` (feature) | Fastify plugin `btauth` (`/fastify`) |
| Client | httpx | `Client` (`net/http`) | `client::Client` (reqwest, feature) | `Client` (fetch / undici) |
| twresp/1 sign + verify | ✅ | ✅ | ✅ | ✅ |
| SSE streaming with signed trailer | ✅ | ✅ `ServeStream`, `(*Client).Stream` | ✅ `axum::stream_response`, `Client::stream` | ✅ `streamReply` (`/fastify`), `Client.stream` |
| Caller policy | ✅ native | ✅ via sidecar: `go/sidecar` + `MiddlewareConfig.Policy` | ✅ via sidecar: `sidecar` (feature) + `MinerAuth::with_policy` | ✅ via sidecar: `@taowire/btauth/sidecar` + the `policy` hook |
| Chain writes (serve axon, set weights) | ✅ (v11) | ✅ serve axon via sidecar (`ServeAxon`); set weights ❌ by design | ✅ serve axon via sidecar (`serve_axon`); set weights ❌ by design | ✅ serve axon via sidecar (`serveAxon`); set weights ❌ by design |
| Full validator loop | ✅ | ❌ not in scope (11.1) | ❌ not in scope | ❌ not in scope |
| Per-IP / per-hotkey rate limits | ✅ | ✅ `TokenBuckets` | ✅ `TokenBuckets` | ✅ `TokenBuckets` |
| Hotkey file | ✅ | ✅ `LoadHotkeyFile` (`secretSeed`) | ✅ `Keypair::from_hotkey_file` (`secretSeed`) | ✅ `Keypair.fromHotkeyFile` (`secretSeed` or `secretPhrase`) |
| Example miner (text-ops, spec 10) | ✅ `examples/text-ops-subnet` | ✅ `go/examples/textops-miner` | ✅ `rust/examples/textops_miner.rs` | ✅ `typescript/examples/textops-miner.ts` |

The two ❌ are spec 11.1's scope: non-Python validators are out of scope in v1, so the sidecar has no weight
setting (11.6). The example miners: [examples/text-ops-miners](../examples/text-ops-miners/README.md).

Package docs and quickstarts: [`go/README.md`](../go/README.md), [`rust/README.md`](../rust/README.md),
[`typescript/README.md`](../typescript/README.md).

## One protocol, one set of answers

Every implementation builds the payload of spec 4.2 byte for byte, hashes the raw body, uses the raw
request target (percent-encoding kept), verifies under the declared scheme only, checks freshness before
the signature and stores the nonce only after it (spec 11.2). The verifiers are also stricter than the
Bittensor SDK, in the same ways everywhere:

| Rule | Code | Vectors |
|---|---|---|
| Sender is an SS58 prefix-42 address (48 characters, checked before base58 decoding) | `tw.auth_malformed` | N10, N23–N26, N65 |
| No repeated `X-Bittensor-*` header, in any spelling of its name | `tw.auth_malformed` | N27, N28 |
| Nonce is 1 to 20 ASCII digits; 20 digits above `u64::MAX` are stale, not malformed | malformed / stale | N29–N33, N51 |
| `X-Bittensor-Crypto` is exactly `ed25519` or `sr25519` | `tw.auth_malformed` | N7, N34–N37 |
| Signature is hex digits only (optional `0x`); odd length is shape, wrong byte length is step 4 | `tw.auth_malformed` | N8, N9, N40–N46 |
| Never a `<Bytes>`-wrapped signature, Python included | `tw.auth_bad_signature` | N19, N20 |
| Weak public keys refused (ADR-0010) | `tw.auth_bad_signature` | N63, N64 |

Replay stores follow the same rules everywhere (spec 8.4.3-8.4.4): a verifier refuses a store whose
retention is below `2 × (max_age + allowed_skew)`; the memory stores forget a pair only when both the
monotonic and the wall clock say it is old; and every verifier watches `wall − monotonic` on the requests
that reach the replay check. A backwards wall-clock step larger than `retention − (max_age +
allowed_skew)` makes those requests fail with `tw.replay_store_unavailable` (503) for `retention`, which
covers Redis stores too (Redis cannot see a step on the miner). Python reports it in `/readyz`
(`clock_step`) and `tw_clock_step_seconds`; Go has `(*Verifier).FailingClosed()` /
`LastClockStep()`, Rust `Verifier::failing_closed()` / `last_clock_step()` for a server's readiness probe
and metrics.

## Streaming (spec 9.2)

Every package has the same four pieces as the Python reference (`taowire.extensions.streaming`): an
incremental SSE parser (WHATWG rules, linear in the input, never fails), the chunk rule (JSON objects or
arrays only; nesting deeper than 128 is refused on both sides, see below), the strict `tw-end` parser and the
running digest. Miner side, in this order: a stream slot for the caller (16 per process by default, 1–256;
full → signed 429 `tw.rate_limited` with `Retry-After: 1`), the first chunk within the handler timeout (else the
signed JSON 500 / 504), then `200 text/event-stream` with the `X-TW-Resp-*` identity headers, the chunks and the
signed trailer. A handler error, a bad chunk, the idle limit, `max_s`, `max_bytes` or a disconnect ends the
stream without `tw-end`; an abort hook reports the reason (`handler_error`, `idle_timeout`, `max_duration`,
`max_bytes`, `bad_chunk`, `cancelled`). Client side: the three limits, with the idle clock restarting when the
caller asks for the next chunk and no other read timeout on the open stream; chunks are handed out unverified
until the trailer verifies.

| | Go | Rust | TypeScript |
|---|---|---|---|
| Miner | `btauth.ServeStream(w, r, next ChunkFunc, StreamConfig)` inside a `Middleware` handler (the stream bypasses the signing buffer) | `axum::stream_response(&StreamContext, &StreamConfig, stream)`; `protect` passes it through unbuffered | `streamReply(request, reply, chunks, options)` in a `btauth` route |
| Client | `(*Client).Stream(...)`, then `Next` / `Chunk` / `Err` | `Client::stream(...)`, then `next().await` / `finish()` | `client.stream(...)`, then `for await` / `result()` |
| Slots | `StreamSlots`, `DefaultStreamSlots` | `sse::StreamSlots` (a dropped `StreamSlot` releases) | `StreamSlots`, `DEFAULT_STREAM_SLOTS` |
| A client that stops reading | `max_s` is a write deadline (`http.ResponseController`) | the producer stops at `max_s`; hyper has no write deadline, so the socket stays until TCP gives up (bounded by the slots) | the socket is destroyed at `max_s` |

Chunk and trailer rules are the same in all four languages, Python included (spec 9.2): a chunk nests at
most 128 levels (arrays and objects counted together; the miner never emits a deeper one, the client rejects one as
`tw.invalid_response`); in `tw-end`, `count` is a plain non-negative integer literal that fits a u64 (`-0`, a
fraction or an exponent is refused) and no string holds a lone UTF-16 surrogate escape (an escaped high + low pair
is one character and is fine). There are no differences from the Python reference here.

Interop without a chain: `conformance/interop/stream_check.py` (every language's stream client against the Python
miner and the Python client against every language's miner, through a relay that tampers with, reorders, drops
or adds chunks, tampers with, duplicates or removes the trailer, or adds an event after it; it checks that each
case is refused as spec 9.2 says).

## Sidecar API (spec 11.6)

Non-Python miners get their caller policy and their chain writes from the Python sidecar, `taowire sidecar`
(127.0.0.1:`TW_SIDECAR_PORT`, default 9910; it runs with the miner's own hotkey, `TW_WALLET_*`). This table is
the contract: the server (`python/src/taowire/sidecar/`) implements exactly it and the three clients parse
exactly it.

Every request carries `Authorization: Bearer <token>` (the token is in `TW_SIDECAR_TOKEN_FILE`, default
`$TW_STATE_DIR/sidecar.token`, mode 0600, generated on first run). Missing or wrong → `401` with the error body
`{"error":{"code":"tw.sidecar_unauthorized","message":…,"request_id":null}}`. Answers are `application/json`;
request bodies are capped at 64 KiB (`413 tw.payload_too_large`); bad parameters are `422 tw.invalid_request`.

| Method & path | 200 body | Errors |
|---|---|---|
| `GET /v1/health` | `{"ok":true,"hotkey":"5…","netuid":2,"block":123,"metagraph_age_s":42.5,"stage":"fresh"}`. `ok` is false (still 200) without a snapshot or past the max age; `block` / `metagraph_age_s` are `null` before the first snapshot; `stage` is `fresh`, `degraded` or `known_callers_only` | 401 |
| `GET /v1/metagraph?netuid=N` | `{"netuid":N,"block":B,"tempo":T,"age_s":A,"neurons":[{"uid":0,"hotkey":"5…","validator_permit":true,"total_stake_tao":1000.0,"axon":"203.0.113.7:8091"},…]}`. Neurons in UID order; `axon` is `host:port` / `[v6]:port` or `null`; `age_s` is the snapshot's age when answered | 401; 422 (netuid missing or not the configured one); 503 `tw.metagraph_stale` before the first snapshot |
| `GET /v1/caller/{hotkey}?netuid=N` | `{"allowed":true}` or `{"allowed":false,"code":C}`, `C` one of `tw.forbidden_denied`, `tw.forbidden_not_registered`, `tw.forbidden_not_validator`, `tw.forbidden_low_stake`, `tw.metagraph_stale` (the sidecar's own `CallerGate`, from `TW_REQUIRE_PERMIT`, `TW_MIN_CALLER_STAKE_TAO`, `TW_ALLOW_HOTKEYS`, `TW_DENY_HOTKEYS`, `TW_METAGRAPH_STRICT`) | 401; 422 (netuid; not an SS58 prefix-42 address) |
| `POST /v1/serve-axon` with `{"netuid":N,"ip":"203.0.113.7","port":8091,"tls_cert_hex":null}` (`tls_cert_hex`: optional, `0x` + 1 algorithm byte + 1–64 key bytes, ADR-0011) | `{"ok":true,"block_hash":"0x<64 hex>"}` | 401; 413; 422 (netuid not the configured one, an address `parse_axon` refuses under `TW_ALLOW_PRIVATE_AXONS`, port, certificate hex); 409 `{"ok":false,"code":"<bt.ErrorCode>","error_name":…,"remediation":…}` when the chain refuses; 503 `{"ok":false,"code":"chain_unavailable",…}` when it cannot be reached |

No weight setting through the sidecar (11.6).

**The clients** (`@taowire/btauth/sidecar` `SidecarClient`, Go `sidecar.Client`, Rust `sidecar::SidecarClient`)
read the token file with the TLS-key rule (regular file, no group/other access, 16–1024 printable ASCII; never
printed), refuse a non-loopback URL unless told otherwise (`unsafeAllowRemote` / `UnsafeAllowRemote` /
`unsafe_allow_remote`: the token travels in clear), check at start that the sidecar follows their netuid and,
with `expectedHotkey`, runs with the miner's hotkey, cache `/v1/metagraph` (refresh 60 s ± 10%) and apply the
Python `CallerPolicy` + `CallerGate` locally:

- stages from the reported age and tempo: max age = `TW_METAGRAPH_MAX_AGE_S` or 2 tempos × 12 s, soft age =
  `TW_METAGRAPH_SOFT_AGE_S` or min(900 s, max / 2); no snapshot is known-callers-only (fail closed); a failed
  refresh keeps the snapshot, which keeps aging;
- known callers (per route pattern in TS, as in Python; one scope for the Go and Rust policy hooks, which guard
  every route with one policy — never the raw request path, which a caller could vary to fill the bounded set)
  are kept past the max age and cleared only when a **newer** snapshot arrives (a
  sidecar repeating its own stale snapshot does not clear them); strict mode refuses everyone past the max age;
- every answer is parsed strictly: a wrong type, a missing field, a duplicate key at any depth, a duplicate uid
  or hotkey, an invalid SS58 address, a non-finite or negative number, a body over 32 MiB rejects the whole
  answer; `/v1/caller` allows only exactly `{"allowed": true}`. Property / fuzz tests in each language check that
  arbitrary JSON never admits a caller;
- `serveAxon` is sent once (a chain write is never resent blindly); a chain refusal is a typed error with the
  `bt.ErrorCode` value.

The adapters' policy hooks (Go `MiddlewareConfig.Policy`, Rust `MinerAuth::with_policy`, the Fastify `policy`
option) answer a refusal signed with twresp/1, except the codes Appendix A marks unsigned (`tw.metagraph_stale`,
`tw.replay_store_unavailable`, `tw.internal`), as the Python pipeline does.

## Server timeouts

| | Headers | Body | Note |
|---|---|---|---|
| Go | set `http.Server.ReadHeaderTimeout` | read the body under a deadline (`http.ResponseController.SetReadDeadline`), then clear it | do **not** set `http.Server.ReadTimeout` on a server with streaming routes: when it fires, net/http cancels the request context, which ends a stream running past it |
| Rust | `axum::serve` has none: serve with hyper's `http1::Builder`, `.timer(TokioTimer::new())` and `.header_read_timeout(...)`, as `rust/examples/textops_miner.rs` does (`TW_AUTH_MAX_AGE_S + TW_AUTH_ALLOWED_SKEW_S`; it also closes a silent connection), or put a reverse proxy in front | `MinerAuth::with_body_timeout` (default 10 s; 401 `tw.auth_malformed`) | |
| TypeScript | Node's `headersTimeout`, with `connectionsCheckingInterval` lowered (Fastify `http` option) | Fastify `requestTimeout` | Node checks both timeouts only every `connectionsCheckingInterval` (30 s by default), so a slow client keeps its connection up to 30 s longer unless it is lowered; not `connectionTimeout` (socket inactivity), which can cut a stream between chunks |

`conformance/interop/miners_check.py` checks each example miner: a client sending its headers one byte per second, and
a silent one, are both cut within 15 s (Go 5 s, TypeScript 10 s, Rust 12 s with the default settings).

## TypeScript notes

- **Headers.** The verifier takes `[name, value]` pairs or Node's flat `rawHeaders` (the Fastify adapter passes
  `request.raw.rawHeaders`). Node's `IncomingHttpHeaders` and fetch `Headers` join a repeated header into one
  `", "` value, which would hide the duplicates every verifier refuses.
- **Nonces** are `bigint` everywhere (spec 11.2 rule 4); nothing converts them to `Number`.
- **sr25519 in WASM.** `@polkadot/util-crypto` 14 runs sr25519 in pure JS (`@scure/sr25519`, about 4 ms per
  verification on the reference host); the package calls `@polkadot/wasm-crypto` (schnorrkel) directly, about
  0.5 ms. ed25519 uses util-crypto's WASM path. `signatureVerify` is never used (it also tries `<Bytes>`).
- **Fastify order.** Verify, policy and the per-hotkey limit run in `preValidation`: after the raw body is
  read, before any route schema, so nothing validates an unauthenticated body. The target is
  `request.originalUrl` (as sent, even with `rewriteUrl`).
- **Replay store outage.** `RedisNonceStore` fails closed after 250 ms per check, like the Python store's socket
  timeout.

## Conformance vectors

`conformance/vectors/` (spec 11.7), generated by `conformance/generate.py` from the Python reference.
Generation checks every vector against the Python verifier and stops on a disagreement; it never
overwrites a file without `--force`.

| File | Contents |
|---|---|
| `payload.json` | P1–P9 payload builds (P5 as P5a/P5b) and the pinned dev keys (`//Alice`, `//Bob`; sr25519 mini secrets and ed25519 seeds, public) |
| `ed25519.json` | Appendix C plus five deterministic signatures, each also a full request that must verify |
| `sr25519_verify.json` | Ten requests pre-signed by Python with `//Alice` / `//Bob` |
| `negative.json` | 63 refusals with their `tw.*` code and status (every case of spec 11.7, the stricter rules, check order, boundaries) and 15 accept controls (A1–A13) |
| `twresp.json` | twresp/1 builds, signatures, a 3-chunk stream digest and verify cases |
| `legacy_v10.json` | Captured v10 traffic (Python only) |

Verify vectors carry `now_ns`, `max_age_s` and `allowed_skew_s`, headers as `[name, value]` pairs (so
duplicates can be expressed) and an optional `prior` request that must be accepted first with the same
store (replay cases). `expected` is the normative answer; `python_reference`, where present, records what
the Python verifier does instead and why.

Runners (`just conformance` runs all of them):

```bash
cd python && uv run taowire conformance --vectors ../conformance/vectors   # exit 1 on any failure
cd go && go test ./btauth -run Conformance
cd rust && cargo test --test conformance
cd typescript && npm run conformance
```

## Interoperability

Live checks without a chain: `conformance/interop/live_check.py` runs Go, Rust and TypeScript signers against
the Python miner, and the Python signer against the Go and Rust middleware and the TypeScript Fastify adapter.
The localnet matrix of spec 13.5 is `conformance/interop/run_matrix.py` (`just interop`, after `just
localnet-up`): the four text-ops miners with their own registered hotkeys (the TS / Go / Rust ones publish
their axons through their own sidecars), the Python validator querying all four (transform and streaming
routes), the TS / Go / Rust client signers calling the Python miner, and weights set and revealed in the same
run. Without a chain: `live_check.py` (signers), `stream_check.py` (streams and tampering),
`sidecar_check.py` (the clients against the real sidecar), `miners_check.py` (the example miners).
