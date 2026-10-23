# btauth (Go)

btauth/1 signed requests and twresp/1 signed responses for Bittensor v11 subnets: the Go package of
[TensorWire](../README.md) (spec 11.4). Module `github.com/tensorwire/tensorwire/go` (working name,
not published), package `btauth`. Go ≥ 1.22; build releases with a supported Go toolchain.

## Quickstart (miner)

```go
package main

import (
	"net/http"
	"time"

	"github.com/tensorwire/tensorwire/go/btauth"
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
| `DecodeSS58`, `EncodeSS58`, `IsWeakPublicKey` | Appendix D (prefix 42 only), weak-key rule (ADR-0010) |
| `NewError`, `StatusOf`, `ErrorBody`, `WriteError` | Appendix A codes, statuses and the JSON error body |

Full doc comments: `go doc -all ./btauth`.

## Checks

```bash
cd go
go test ./btauth -run Conformance      # every vector in conformance/vectors (except legacy_v10, Python only)
go test -race ./...                    # unit tests; TENSORWIRE_TEST_REDIS_URL=redis://... for the Redis store
go vet ./... && staticcheck ./...
go test ./btauth -run '^$' -fuzz FuzzVerify -fuzztime 5m
govulncheck ./...
```

Not yet in this package: SSE streaming helpers (spec 9.2) and the sidecar client (11.6).
