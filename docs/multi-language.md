# Multi-language support

TensorWire's Python package is the reference implementation. Miners written in other languages use a
btauth/1 package for their language (spec 11). Status on `eng/lang` (Phase 5 Part 1):

| Capability (spec 11.1) | Python | Go (`go/btauth`) | Rust (`tensorwire-btauth`) | TypeScript (`@tensorwire/btauth`) |
|---|---|---|---|---|
| btauth/1 sign + verify | ✅ | ✅ | ✅ | ✅ (`sr25519Verify` / `ed25519Verify`, WASM) |
| Monotonic nonce | ✅ | ✅ `NonceSource` (atomic CAS) | ✅ `NonceSource` (`AtomicU64`) | ✅ `NonceSource` (`bigint`) |
| Memory + Redis nonce store | ✅ | ✅ `MemoryStore`, `redisstore` | ✅ `MemoryStore`, `redis_store` (feature) | ✅ `MemoryStore`, `RedisNonceStore` (`/redis`, ioredis) |
| Server adapter | FastAPI | `net/http` `Middleware` | axum `protect` (feature) | Fastify plugin `btauth` (`/fastify`) |
| Client | httpx | `Client` (`net/http`) | `client::Client` (reqwest, feature) | `Client` (fetch / undici) |
| twresp/1 sign + verify | ✅ | ✅ | ✅ | ✅ |
| SSE streaming with signed trailer | ✅ | ✅ `ServeStream`, `(*Client).Stream` | ✅ `axum::stream_response`, `Client::stream` | ✅ `streamReply` (`/fastify`), `Client.stream` |
| Caller policy / chain writes | native | via sidecar (not built yet) | via sidecar (not built yet) | `policy` hook; sidecar client not built yet |

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
| Never a `<Bytes>`-wrapped signature, Python included (D22) | `tw.auth_bad_signature` | N19, N20 |
| Weak public keys refused (ADR-0010, D20) | `tw.auth_bad_signature` | N63, N64 |

Replay stores follow the same rules everywhere (spec 8.4.3-8.4.4, D21): a verifier refuses a store whose
retention is below `2 × (max_age + allowed_skew)`; the memory stores forget a pair only when both the
monotonic and the wall clock say it is old; and every verifier watches `wall − monotonic` on the requests
that reach the replay check. A backwards wall-clock step larger than `retention − (max_age +
allowed_skew)` makes those requests fail with `tw.replay_store_unavailable` (503) for `retention`, which
covers Redis stores too (Redis cannot see a step on the miner). Python reports it in `/readyz`
(`clock_step`) and `tw_clock_step_seconds`; Go has `(*Verifier).FailingClosed()` /
`LastClockStep()`, Rust `Verifier::failing_closed()` / `last_clock_step()` for a server's readiness probe
and metrics.

## Streaming (spec 9.2, D29, D35, D36)

Every package has the same four pieces as the Python reference (`tensorwire.extensions.streaming`): an
incremental SSE parser (WHATWG rules, linear in the input, never fails), the chunk rule (D35: JSON objects or
arrays only; nesting deeper than 128 is refused on both sides, see below), the strict `tw-end` parser and the
running digest. Miner side, in this order: a stream slot for the caller (D36, 16 per process by default, 1–256;
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

Differences from the Python reference, all stricter: chunks nested deeper than 128 are refused (Python: about
1000, its recursion limit; spec question in COORDINATION.md); a `tw-end` count written `-0` is refused (Python
reads it as 0). Rust's `serde_json` refuses lone UTF-16 surrogate escapes in a trailer's strings (Python
accepts them; a trailer never contains any).

Interop without a chain: `conformance/interop/stream_check.py` (every language's stream client against the Python
miner and the Python client against every language's miner, through a relay that tampers with, reorders, drops
or adds chunks, tampers with, duplicates or removes the trailer, or adds an event after it; evidence in
`reports/phase-5/stream-interop/`).

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
cd python && uv run tensorwire conformance --vectors ../conformance/vectors   # exit 1 on any failure
cd go && go test ./btauth -run Conformance
cd rust && cargo test --test conformance
cd typescript && npm run conformance
```

## Interoperability

Live checks without a chain: `conformance/interop/live_check.py` runs Go, Rust and TypeScript signers against
the Python miner, and the Python signer against the Go and Rust middleware and the TypeScript Fastify adapter
(evidence in `reports/phase-5/interop-ts/`).
The localnet matrix of spec 13.5 (`conformance/interop/run_matrix.py`, `just interop`) and the sidecar
(11.6) come with the rest of Phase 5.
