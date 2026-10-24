package btauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/anindhabiswas25/TaoWire/go/btauth"
)

// The README quickstart: a protected miner route and a validator calling it.
// Seeds are the public //Bob and //Alice dev keys.
func ExampleMiddleware() {
	minerKey, _ := btauth.NewSr25519FromSeed([32]byte{0x39, 0x8f, 0x0c, 0x28, 0xf9, 0x88, 0x85, 0xe0, 0x46, 0x33, 0x3d, 0x4a, 0x41, 0xc1, 0x9c, 0xee, 0x4c, 0x37, 0x36, 0x8a, 0x98, 0x32, 0xc6, 0x50, 0x2f, 0x6c, 0xfd, 0x18, 0x2e, 0x2a, 0xef, 0x89})
	v, _ := btauth.NewVerifier(btauth.Config{SelfHotkey: minerKey.SS58(), Store: btauth.NewMemoryStore(time.Minute, nil)})
	protect := btauth.Middleware(btauth.MiddlewareConfig{Verifier: v, ResponseKey: minerKey})
	miner := httptest.NewServer(protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, _ := btauth.CallerFrom(r.Context())
		body, _ := btauth.BodyFrom(r.Context())
		_, _ = w.Write(append([]byte(caller.Hotkey[:8]+": "), body...))
	})))
	defer miner.Close()

	validatorKey, _ := btauth.NewSr25519FromSeed([32]byte{0xe5, 0xbe, 0x9a, 0x50, 0x92, 0xb8, 0x1b, 0xca, 0x64, 0xbe, 0x81, 0xd2, 0x12, 0xe7, 0xf2, 0xf9, 0xeb, 0xa1, 0x83, 0xbb, 0x7a, 0x90, 0x95, 0x4f, 0x7b, 0x76, 0x36, 0x1f, 0x6e, 0xdb, 0x5c, 0x0a})
	c := &btauth.Client{Signer: btauth.NewSigner(validatorKey), HTTP: &http.Client{Timeout: 5 * time.Second}}
	resp, err := c.Do(context.Background(), "POST", miner.URL+"/v1/echo", []byte("hi"), minerKey.SS58())
	fmt.Println(resp.Status, string(resp.Body), resp.Verified, err)
	// Output: 200 5GrwvaEF: hi true <nil>
}
