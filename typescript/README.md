# @taowire/btauth (TypeScript)

btauth/1 signed requests and twresp/1 signed responses for Bittensor v11 subnets: the TypeScript package of
[TaoWire](../README.md) (spec 11.3). Node.js ≥ 20, ESM and CommonJS builds. Not published (`"private": true`).

Entry points: `@taowire/btauth`, `/fastify`, `/redis`, `/sidecar`.

Dependencies: `@polkadot/util-crypto`, `@polkadot/util` and `@polkadot/wasm-crypto` (sr25519 / ed25519 in
WASM, SS58). Optional peers: `fastify` (the adapter, `@taowire/btauth/fastify`) and `ioredis` (the shared
replay store, `@taowire/btauth/redis`).

## Quickstart (miner, Fastify)

```ts
import Fastify from "fastify";
import { Keypair, MemoryStore, Verifier, initCrypto } from "@taowire/btauth";
import { btauth, rawBody } from "@taowire/btauth/fastify";

await initCrypto(); // once: loads the WASM crypto
const key = Keypair.fromHotkeyFile(process.env.HOTKEY_FILE!); // secretSeed or secretPhrase; chmod 600
const app = Fastify();
await app.register(btauth, {
  verifier: new Verifier({ selfHotkey: key.ss58, store: new MemoryStore(60) }),
  responseKey: key, // twresp/1 on every answer after authentication
  routes: (scope) => {
    scope.post("/v1/echo", (request) => ({
      caller: request.btauthCaller?.hotkey, // the verified sender
      body: rawBody(request).toString(), // the raw bytes that were verified
    }));
  },
});
await app.listen({ host: "0.0.0.0", port: 8091 });
```

A full miner (caller policy and `ServeAxon` through the [sidecar](../docs/sidecar.md), per-IP and per-hotkey
limits, a streaming route): [`examples/textops-miner.ts`](examples/textops-miner.ts)
(`npm run build:examples && node build/examples/textops-miner.js`; settings in
[examples/text-ops-miners](../examples/text-ops-miners/README.md)).

Validator side: `new Client({ signer: new Signer(validatorKey) }).request("POST", url, body, minerHotkey)`
resolves only when the answer's twresp/1 signature verified for this request.

## API

| Name                                                                                                         | What it does                                                                                                                                                                                                                              |
| ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `initCrypto()`                                                                                               | Loads the WASM crypto; await it once before anything signs or verifies                                                                                                                                                                    |
| `buildPayload`, `bodySha256`                                                                                 | The 8-line btauth/1 payload (spec 4.2); nonces are `bigint`                                                                                                                                                                               |
| `Verifier`, `verifyRequest`                                                                                  | Spec 4.3 in order; resolves a `Caller` or rejects with `TWError` (Appendix A code and status). Refuses a store with retention below `2 × (maxAgeS + allowedSkewS)` (D21)                                                                  |
| `Verifier.failingClosed()`, `lastClockStepNs()`                                                              | Clock-step guard (D21): after a backwards wall-clock step larger than the store's margin, requests get `tw.replay_store_unavailable` for the retention; report not-ready (`clock_step`)                                                   |
| `Keypair`                                                                                                    | `sr25519FromSeed`, `ed25519FromSeed`, `fromSeed`, `fromHotkeyFile`; `sign` signs exact bytes; never prints key material                                                                                                                   |
| `isWeakPublicKey`, `verifySignature`                                                                         | ADR-0010 weak keys; scheme-only verification (`sr25519Verify` / `ed25519Verify`, never `signatureVerify`)                                                                                                                                 |
| `NonceSource`, `Signer`                                                                                      | `max(now_ns, last + 1)` nonces; btauth/1 headers with a fresh nonce on every call                                                                                                                                                         |
| `MemoryStore`, `NonceStore`; `RedisNonceStore` (`/redis`)                                                    | Replay stores; Redis keys match the Python kit (`tw:n:<hotkey>:<nonce>`)                                                                                                                                                                  |
| `responsePayload`, `signResponse`, `verifyResponse`, `verifyResponseDigest`, `identityHeaders`, `signDigest` | twresp/1 (spec 9.1; digest form for 9.2 streams)                                                                                                                                                                                          |
| `Client`, `ClientError`, `requestTarget`                                                                     | fetch client: signs every attempt anew, one time budget, `maxResponseBytes`, verifies twresp/1; client codes `tw.timeout`, `tw.connect_error`, `tw.response_too_large`, `tw.bad_response_signature`                                       |
| `btauth` (`/fastify`), `rawBody`                                                                             | Fastify plugin: raw `Buffer` body for every content type, `bodyLimit` (413), `request.raw.url` as target, verify → `policy` → per-hotkey limit in `preValidation` (before any route schema), twresp/1 on every reply after authentication |
| `streamReply` (`/fastify`), `StreamSlots`, `StreamLimits`                                                    | SSE stream with a signed `tw-end` from a `btauth` route (spec 9.2): per-caller slots (D36), first chunk before any byte, limits, `onAbort`                                                                                                |
| `Client.stream`, `MinerStream`, `UnverifiedChunk`                                                            | Streaming query: unverified chunks, `result()` resolves only after the trailer verified                                                                                                                                                   |
| `SSEParser`, `decodeChunk`, `encodeChunk`, `parseTrailer`, `encodeTrailer`, `encodeEvent`, `StreamDigest`    | The shared stream pieces (WHATWG SSE parser, D35 chunk rule, strict trailer)                                                                                                                                                              |
| `SidecarClient`, `CallerPolicy`, `readTokenFile` (`/sidecar`)                                                | The sidecar client (spec 11.6, `docs/multi-language.md` "Sidecar API"): cached metagraph with the 8.5.1 stages, the Python caller policy (`policyHook()` for the plugin), `serveAxon`                                                     |
| `TokenBuckets`                                                                                               | Per-hotkey, per-route token bucket (8.6.2 defaults 20/s, burst 40)                                                                                                                                                                        |
| `TWError`, `errorBody`, `statusOf`, `decodeSS58`, `encodeSS58`                                               | Appendix A codes / statuses / JSON error body; Appendix D (prefix 42 only, 48 characters checked before base58)                                                                                                                           |

Headers: pass Node's `request.raw.rawHeaders` or `[name, value]` pairs. `IncomingHttpHeaders` and fetch
`Headers` join a repeated header into one value, which hides the duplicates the verifier must refuse.

API docs: `npm run docs` (TypeDoc, into `docs-api/`).

## Checks

```bash
npm ci
npm run lint && npm run typecheck     # eslint (strict type-checked) + prettier; tsc --noEmit
npm test                              # vitest; TAOWIRE_TEST_REDIS_URL=redis://... for the Redis store
npm run conformance                   # every vector in conformance/vectors (except legacy_v10, Python only)
npm run coverage                      # thresholds: >= 90% on the btauth modules
TW_FUZZ_SECONDS=300 npm run fuzz      # fast-check properties, time-boxed
npm run bench                         # verifyRequest per scheme
npm run build && npm pack --dry-run   # ESM + CJS; never published
```
