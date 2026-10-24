# btauth (Go)

btauth/1 signed requests and twresp/1 signed responses for Bittensor v11 subnets: the Go package of
[TaoWire](../README.md) (spec 11.4). Module `github.com/anindhabiswas25/TaoWire/go` (working name,
not published), package `btauth`. Go ≥ 1.22; build releases with a supported Go toolchain.

## Quickstart (miner)

```go
package main

import (
	"net/http"
	"time"

	"github.com/anindhabiswas25/TaoWire/go/btauth"
)

func main() {
	key, _ := btauth.NewSr25519FromSeed(minerSeed) // 32-byte secretSeed of the miner hotkey
	v, _ := btauth.NewVerifier(btauth.Config{SelfHotkey: key.SS58(), Store: btauth.NewMemoryStore(time.Minute, nil)})
	protect := btauth.Middleware(btauth.MiddlewareConfig{Verifier: v, ResponseKey: key})
	http.Handle("/v1/echo", protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, _ := btauth.CallerFrom(r.Context()) // verified sender
		body, _ := btauth.BodyFrom(r.Context())     // the raw bytes that were verified
		_, _ = w.Write(append([]byte(caller.Hotkey+": "), body...))
	})))
	_ = http.ListenAndServe("127.0.0.2:8091", nil)
}
```

A full miner (caller policy and `ServeAxon` through the [sidecar](../docs/sidecar.md), per-IP and per-hotkey
limits, a streaming route): [`examples/textops-miner`](examples/textops-miner/main.go)
(`go run ./examples/textops-miner`; settings in [examples/text-ops-miners](../examples/text-ops-miners/README.md)).

A runnable version with dev keys is `ExampleMiddleware` in `btauth/example_test.go` (`go test ./btauth -run Example`).

Validator side: `c := &btauth.Client{Signer: btauth.NewSigner(validatorKey), HTTP: &http.Client{Timeout: 12 * time.Second}}`,
then `resp, err := c.Do(ctx, "POST", "http://miner:8091/v1/echo", body, minerHotkey)`; `err == nil` means the
answer's twresp/1 signature verified.

## API

| Name | What it does |
|---|---|
| `BuildPayload(scheme, method, target, body, nonce, sender, receiver)` | The 8-line btauth/1 payload (spec 4.2); `receiver == ""` writes `-` |
| `NewVerifier(Config)`, `(*Verifier).Verify(ctx, http.Header, body, method, target)` | Spec 4.3 in order; returns `*Caller` or `*Error` with the Appendix A code and status. Refuses a store with retention below `2 × (MaxAge + AllowedSkew)` (D21) |
| `(*Verifier).FailingClosed()`, `LastClockStep()` | Clock-step guard (D21): after a backwards wall-clock step larger than the store's margin, requests get `tw.replay_store_unavailable` for the retention; report it as not-ready (`clock_step`). Tests inject `Config.NowNs` and `Config.MonotonicNs` |
| `Middleware(MiddlewareConfig)` | `net/http` middleware: `MaxBytesReader` (413), target = `r.RequestURI` (absolute form refused), verify, handler; signs answers with twresp/1 when `ResponseKey` is set |
| `CallerFrom(ctx)`, `BodyFrom(ctx)` | The verified caller and the raw body inside a protected handler |
| `NewSr25519FromSeed`, `NewEd25519FromSeed`, `(*Keypair).Sign` | Hotkeys from 32-byte seeds; sr25519 via go-schnorrkel v1.1.0 (wrapped in `sr25519.go`), ed25519 via the standard library |
| `NewSigner(key)`, `(*Signer).Sign(method, target, body, receiver)` | Request headers with a fresh nonce every call |
| `NonceSource` | Strictly increasing nonces `max(now_ns, last+1)` with an atomic CAS loop |
| `NewMemoryStore`, `NonceStore`; `redisstore.New` | Replay stores; the Redis one shares keys (`tw:n:<hotkey>:<nonce>`) with the Python kit |
| `SignResponse`, `VerifyResponse`, `VerifyResponseDigest` | twresp/1 (spec 9.1; digest form for 9.2 streams) |
| `Client.Do` | Signed request + verified answer; client codes `tw.timeout`, `tw.connect_error`, `tw.response_too_large`, `tw.bad_response_signature` |
| `ServeStream`, `StreamConfig`, `ChunkFunc`, `StreamSlots` | SSE stream with a signed `tw-end` inside a `Middleware` handler (spec 9.2): per-caller slots (D36), first chunk before any byte, limits, abort hook |
| `(*Client).Stream`, `Stream`, `StreamOptions`, `UnverifiedChunk` | Streaming query: unverified chunks, `Err() == nil` only after the trailer verified; `tw.invalid_response` for a chunk that is not a JSON object or array |
| `NewTokenBuckets`, `RateLimit`, `DefaultIPLimit`, `DefaultHotkeyLimit` | Per-IP / per-hotkey token buckets (spec 8.6.2) |
| `LoadHotkeyFile(path, scheme)` | A Bittensor hotkey file (owner-only, `secretSeed`, `ss58Address` checked) |
| `MiddlewareConfig.Policy` | Caller policy after verification (spec 8.5); refusals signed except `UnsignedCodes` |
| `sidecar.New`, `(*sidecar.Client).Start`, `Check`, `Policy`, `Health`, `Metagraph`, `Caller`, `ServeAxon`, `sidecar.ReadTokenFile`, `sidecar.NewPolicy` | Package `go/sidecar`: the sidecar client (spec 11.6, `docs/multi-language.md` "Sidecar API") — cached metagraph with the 8.5.1 stages, the Python caller policy, serve-axon |
| `SSEParser`, `DecodeChunk`, `EncodeChunk`, `ParseTrailer`, `EncodeTrailer`, `EncodeEvent`, `StreamDigest`, `StreamLimits` | The shared stream pieces (WHATWG SSE parser, D35 chunk rule, strict trailer) |
| `DecodeSS58`, `EncodeSS58`, `IsWeakPublicKey` | Appendix D (prefix 42 only), weak-key rule (ADR-0010) |
| `NewError`, `StatusOf`, `ErrorBody`, `WriteError` | Appendix A codes, statuses and the JSON error body |

Full doc comments: `go doc -all ./btauth`.

## Checks

`just lint`, `just test`, `just conformance` and `just audit` run these with the pinned Go SDK and
tools (`scripts/go_tools.sh`; a missing SDK fails, missing or stale tools are built). By hand, from the
repository root, after `./scripts/go_tools.sh ensure`:

```bash
export PATH="$(./scripts/go_tools.sh sdk-path)/bin:$PATH" GOTOOLCHAIN=local
cd go
go test ./btauth -run Conformance      # every vector in conformance/vectors (except legacy_v10, Python only)
go test -race ./...                    # unit tests; TAOWIRE_TEST_REDIS_URL=redis://... for the Redis store
go vet ./... && ../scripts/go_tools.sh run staticcheck ./...
go test ./btauth -run '^$' -fuzz FuzzVerify -fuzztime 5m
../scripts/go_tools.sh run govulncheck ./...
```

Fuzz targets: `FuzzVerify`, `FuzzSSEParser`, `FuzzParseTrailer`, `FuzzDecodeChunk`; `sidecar`: `FuzzParseSnapshot`, `FuzzParseDecision`
(`go test ./btauth -run '^$' -fuzz '^FuzzSSEParser$' -fuzztime 5m`).
