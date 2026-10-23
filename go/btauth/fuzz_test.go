package btauth

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// FuzzVerify feeds arbitrary header values, bodies, methods and targets to
// Verify (spec 16.5 item 3). It must never panic, must only ever answer with
// an Appendix A auth code, and must never accept a request that was not
// signed by the claimed sender (only the seed corpus's genuine request can
// pass). Crashes found become seeds in testdata/fuzz/FuzzVerify.
func FuzzVerify(f *testing.F) {
	now := uint64(1752076800000000000)
	alice, _ := NewSr25519FromSeed([32]byte{0xe5, 0xbe, 0x9a, 0x50, 0x92, 0xb8, 0x1b, 0xca, 0x64, 0xbe, 0x81, 0xd2, 0x12, 0xe7, 0xf2, 0xf9, 0xeb, 0xa1, 0x83, 0xbb, 0x7a, 0x90, 0x95, 0x4f, 0x7b, 0x76, 0x36, 0x1f, 0x6e, 0xdb, 0x5c, 0x0a})
	bobSS58 := "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
	signer := &Signer{Key: alice, Nonce: NonceSource{NowNs: func() uint64 { return now }}}
	good, _, _ := signer.Sign("POST", "/generate?stream=false", []byte(`{"prompt": "hello"}`), bobSS58)
	f.Add("1", good.Get(HeaderHotkey), good.Get(HeaderReceiver), good.Get(HeaderNonce), "", good.Get(HeaderSignature),
		"POST", "/generate?stream=false", []byte(`{"prompt": "hello"}`))
	f.Add("1", good.Get(HeaderHotkey), bobSS58, "99999999999999999999", "ed25519", "0x", "post", "/a b", []byte{})
	f.Add("2", "", "", "", "ecdsa", "zz", "", "", []byte(nil))
	f.Fuzz(func(t *testing.T, version, hotkey, receiver, nonce, crypto, sig, method, target string, body []byte) {
		v, err := NewVerifier(Config{
			SelfHotkey: bobSS58, Store: NewMemoryStore(time.Minute, nil),
			NowNs: func() uint64 { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		h := http.Header{}
		h.Set(HeaderVersion, version)
		h.Set(HeaderHotkey, hotkey)
		h.Set(HeaderReceiver, receiver)
		h.Set(HeaderNonce, nonce)
		if crypto != "" {
			h.Set(HeaderCrypto, crypto)
		}
		h.Set(HeaderSignature, sig)
		caller, err := v.Verify(context.Background(), h, body, method, target)
		if err != nil {
			e, ok := err.(*Error)
			if !ok || e.Status != 401 || !strings.HasPrefix(e.Code, "tw.auth_") {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		// Accepted: it must be exactly the genuine request (modulo the
		// encodings the spec allows: method case, 0x prefix, hex case).
		if caller.Hotkey != alice.SS58() || strings.ToUpper(method) != "POST" ||
			target != "/generate?stream=false" || string(body) != `{"prompt": "hello"}` {
			t.Fatalf("accepted a request that was not signed: %q %q %q", method, target, body)
		}
	})
}
