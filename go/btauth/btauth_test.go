package btauth

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func seed(t *testing.T, h string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 32 {
		t.Fatal("bad seed")
	}
	var s [32]byte
	copy(s[:], raw)
	return s
}

// Public dev keys (conformance/vectors keys): //Alice and //Bob.
func alice(t *testing.T) *Keypair {
	kp, err := NewSr25519FromSeed(seed(t, "e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func bob(t *testing.T) *Keypair {
	kp, err := NewSr25519FromSeed(seed(t, "398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89"))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func aliceEd(t *testing.T) *Keypair {
	return NewEd25519FromSeed(seed(t, "abf8e5bdbe30c65656c0a3cbd181ff8a56294a69dfedd27982aace4a76909115"))
}

func TestAppendixCAndD(t *testing.T) {
	if a := alice(t).SS58(); a != "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" {
		t.Fatal(a)
	}
	if a := aliceEd(t).SS58(); a != "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu" {
		t.Fatal(a)
	}
	pub := alice(t).PublicKey()
	if hex.EncodeToString(pub[:]) != "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d" {
		t.Fatal("Appendix D key")
	}
	payload := BuildPayload(Ed25519, "POST", "/generate?stream=false", []byte(`{"prompt": "hello"}`),
		1752076800000000000, aliceEd(t).SS58(), bob(t).SS58())
	sig, _ := aliceEd(t).Sign(payload)
	if hex.EncodeToString(sig[:]) != "1a6b631988bf1f7ea093ab9d5acf61f05c316d0b0e428b24b487b75a5f6ee0e1a56a26918fdf871b6cf09437e6588023a4ce423cf622621b2a7feee17612f704" {
		t.Fatal("Appendix C ed25519 signature")
	}
	if !strings.Contains(alice(t).String(), alice(t).SS58()) || strings.Contains(alice(t).String(), "e5be") {
		t.Fatal("String must name the key, never the seed")
	}
}

func TestSS58Rejections(t *testing.T) {
	for _, a := range []string{"", "0abc", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ",
		"15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKut"} {
		if _, err := DecodeSS58(a); err == nil {
			t.Errorf("accepted %q", a)
		}
	}
}

func TestWeakKeys(t *testing.T) {
	if !IsWeakPublicKey(Sr25519, [32]byte{}) || IsWeakPublicKey(Sr25519, alice(t).PublicKey()) {
		t.Fatal("sr25519")
	}
	identity := [32]byte{1}
	if !IsWeakPublicKey(Ed25519, identity) || IsWeakPublicKey(Ed25519, aliceEd(t).PublicKey()) {
		t.Fatal("ed25519")
	}
	var notAPoint [32]byte
	for i := range notAPoint {
		notAPoint[i] = 0xff
	}
	if IsWeakPublicKey(Ed25519, notAPoint) {
		t.Fatal("non-point is not weak")
	}
}

func TestNonceSourceIsStrictlyIncreasing(t *testing.T) {
	n := &NonceSource{NowNs: func() uint64 { return 1000 }}
	if a, b := n.Next(), n.Next(); a != 1000 || b != 1001 {
		t.Fatal(a, b)
	}
	var wg sync.WaitGroup
	seen := sync.Map{}
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if _, dup := seen.LoadOrStore(n.Next(), true); dup {
					t.Error("duplicate nonce")
				}
			}
		}()
	}
	wg.Wait()
	var wall NonceSource
	if wall.Next() < uint64(time.Now().Add(-time.Minute).UnixNano()) {
		t.Fatal("wall clock")
	}
}

func TestMemoryStoreExpires(t *testing.T) {
	now := time.Unix(0, 1)
	s := NewMemoryStore(10*time.Second, func() time.Time { return now })
	ctx := context.Background()
	if ok, _ := s.CheckAndStore(ctx, "a", 1); !ok {
		t.Fatal("first")
	}
	if ok, _ := s.CheckAndStore(ctx, "a", 1); ok {
		t.Fatal("replay")
	}
	if ok, _ := s.CheckAndStore(ctx, "b", 1); !ok || s.Len() != 2 {
		t.Fatal("other hotkey")
	}
	now = now.Add(11 * time.Second)
	if s.Len() != 0 {
		t.Fatal("not expired")
	}
	if ok, _ := s.CheckAndStore(ctx, "a", 1); !ok {
		t.Fatal("after expiry")
	}
	if NewMemoryStore(time.Second, nil).now == nil {
		t.Fatal("default clock")
	}
}

func TestNewVerifierValidates(t *testing.T) {
	store := NewMemoryStore(time.Minute, nil)
	cases := []Config{
		{SelfHotkey: "nope", Store: store},
		{SelfHotkey: bob(t).SS58()},
		{SelfHotkey: bob(t).SS58(), Store: NewMemoryStore(5*time.Second, nil)},
		{SelfHotkey: bob(t).SS58(), Store: store, MaxAge: -time.Second},
	}
	for i, c := range cases {
		if _, err := NewVerifier(c); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	v, err := NewVerifier(Config{SelfHotkey: bob(t).SS58(), Store: store})
	if err != nil || v.maxAge != uint64(DefaultMaxAge) || v.allowedSkew != uint64(DefaultAllowedSkew) {
		t.Fatal("defaults")
	}
	if v.nowNs() < uint64(time.Now().Add(-time.Minute).UnixNano()) {
		t.Fatal("wall clock")
	}
}

type failingStore struct{}

func (failingStore) CheckAndStore(context.Context, string, uint64) (bool, error) {
	return false, errors.New("redis down")
}
func (failingStore) Retention() time.Duration { return time.Minute }

func TestStoreOutageFailsClosed(t *testing.T) {
	v, _ := NewVerifier(Config{SelfHotkey: bob(t).SS58(), Store: failingStore{}})
	h, _, _ := NewSigner(alice(t)).Sign("POST", "/x", nil, bob(t).SS58())
	_, err := v.Verify(context.Background(), h, nil, "POST", "/x")
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeReplayStoreUnavailable || e.Status != 503 {
		t.Fatalf("%v", err)
	}
}

func TestErrors(t *testing.T) {
	e := NewError("tw.nonsense", "x")
	if e.Code != CodeInternal || e.Status != 500 {
		t.Fatal(e)
	}
	if c := NewError(CodeTimeout, ""); c.Status != 0 || c.Error() != "tw.timeout: tw.timeout" {
		t.Fatal(c.Error())
	}
	if StatusOf("tw.forbidden_low_stake") != 403 || StatusOf("x") != 500 {
		t.Fatal("status")
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(ErrorBody(NewError(CodeStale, "d"), "01J"), &body); err != nil ||
		body["error"]["code"] != CodeStale || body["error"]["request_id"] != "01J" {
		t.Fatal(body)
	}
	if !strings.Contains(string(ErrorBody(NewError(CodeStale, ""), "")), `"request_id":null`) {
		t.Fatal("null request id")
	}
	if !strings.Contains(NewError(CodeStale, "detail").Error(), "detail") {
		t.Fatal("detail")
	}
}

// ------------------------------------------------------------- middleware

func miner(t *testing.T, cfg MiddlewareConfig, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	if cfg.Verifier == nil {
		v, err := NewVerifier(Config{SelfHotkey: bob(t).SS58(), Store: NewMemoryStore(time.Minute, nil)})
		if err != nil {
			t.Fatal(err)
		}
		cfg.Verifier = v
	}
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(Middleware(cfg)(handler))
	t.Cleanup(srv.Close)
	return srv
}

func echo(w http.ResponseWriter, r *http.Request) {
	caller, _ := CallerFrom(r.Context())
	raw, _ := BodyFrom(r.Context())
	again, _ := io.ReadAll(r.Body)
	if !bytes.Equal(raw, again) {
		http.Error(w, "body mismatch", 500)
		return
	}
	w.Header().Set("X-Caller", caller.Hotkey)
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(append([]byte("echo:"), raw...))
}

func TestClientAndMiddlewareRoundTrip(t *testing.T) {
	srv := miner(t, MiddlewareConfig{ResponseKey: bob(t)}, echo)
	c := &Client{Signer: NewSigner(alice(t))}
	for _, target := range []string{"/a%20b?x=%2F", "/p?", "/plain"} {
		resp, err := c.Do(context.Background(), "POST", srv.URL+target, []byte(`{"q":"ü"}`), bob(t).SS58())
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if resp.Status != 201 || !resp.Verified || resp.Scheme != Sr25519 ||
			string(resp.Body) != `echo:{"q":"ü"}` || resp.Header.Get("X-Caller") != alice(t).SS58() {
			t.Fatalf("%s: %+v", target, resp)
		}
	}
}

func TestEd25519ClientAndUnsignedMiner(t *testing.T) {
	srv := miner(t, MiddlewareConfig{}, echo)
	c := &Client{Signer: NewSigner(aliceEd(t)), HTTP: &http.Client{Timeout: 5 * time.Second}}
	resp, err := c.Do(context.Background(), "PUT", srv.URL+"/e", nil, bob(t).SS58())
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeBadResponseSignature || resp.Status != 201 || resp.Verified {
		t.Fatalf("unsigned answer must not verify: %v %+v", err, resp)
	}
}

func signedRequest(t *testing.T, url string, body []byte, mutate func(http.Header)) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	h, _, _ := NewSigner(alice(t)).Sign("POST", req.URL.RequestURI(), body, bob(t).SS58())
	for k, v := range h {
		req.Header[k] = v
	}
	if mutate != nil {
		mutate(req.Header)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get(RespHeaderSignature) != "" {
		t.Fatal("refusals before authentication are never signed")
	}
	return body.Error.Code
}

func TestMiddlewareRefusals(t *testing.T) {
	srv := miner(t, MiddlewareConfig{MaxBodyBytes: 16, ResponseKey: bob(t)}, echo)
	cases := []struct {
		name   string
		body   []byte
		mutate func(http.Header)
		status int
		code   string
	}{
		{"no headers", nil, func(h http.Header) {
			for k := range h {
				delete(h, k)
			}
		}, 401, CodeMalformed},
		{"ancient nonce", nil, func(h http.Header) { h.Set(HeaderNonce, "1") }, 401, CodeStale},
		{"tampered", []byte("x"), func(h http.Header) {
			h2, _, _ := NewSigner(alice(t)).Sign("POST", "/v", []byte("y"), bob(t).SS58())
			for k, v := range h2 {
				h[k] = v
			}
		}, 401, CodeBadSignature},
		{"too large", bytes.Repeat([]byte("a"), 17), nil, 413, CodePayloadTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := signedRequest(t, srv.URL+"/v", c.body, c.mutate)
			if resp.StatusCode != c.status || errorCode(t, resp) != c.code {
				t.Fatalf("got %d", resp.StatusCode)
			}
		})
	}
}

func TestMiddlewareChunkedBodyOverLimit(t *testing.T) {
	srv := miner(t, MiddlewareConfig{MaxBodyBytes: 8}, echo)
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(bytes.Repeat([]byte("z"), 64))
		pw.Close()
	}()
	req, _ := http.NewRequest("POST", srv.URL+"/c", pr) // no Content-Length: chunked
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 413 || errorCode(t, resp) != CodePayloadTooLarge {
		t.Fatal(resp.StatusCode)
	}
}

func TestMiddlewareRejectsAbsoluteFormTarget(t *testing.T) {
	srv := miner(t, MiddlewareConfig{}, echo)
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET http://evil/x HTTP/1.1\r\nHost: evil\r\nConnection: close\r\n\r\n")
	out, _ := io.ReadAll(conn)
	if !strings.HasPrefix(string(out), "HTTP/1.1 401") || !strings.Contains(string(out), CodeMalformed) {
		t.Fatalf("%s", out)
	}
}

func TestMiddlewareSignsHandlerErrors(t *testing.T) {
	srv := miner(t, MiddlewareConfig{ResponseKey: bob(t)}, func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, NewError("tw.forbidden_not_validator", ""))
	})
	c := &Client{Signer: NewSigner(alice(t))}
	resp, err := c.Do(context.Background(), "POST", srv.URL+"/f", nil, bob(t).SS58())
	if err != nil || resp.Status != 403 || !resp.Verified {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestMiddlewareConfigPanics(t *testing.T) {
	for i, cfg := range []MiddlewareConfig{{}, {ResponseKey: alice(t)}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("case %d did not panic", i)
				}
			}()
			if cfg.ResponseKey != nil {
				cfg.Verifier, _ = NewVerifier(Config{SelfHotkey: bob(t).SS58(), Store: NewMemoryStore(time.Minute, nil)})
			}
			Middleware(cfg)
		}()
	}
}

func TestClientErrors(t *testing.T) {
	c := &Client{Signer: NewSigner(alice(t)), HTTP: &http.Client{Timeout: 200 * time.Millisecond}, MaxResponseBytes: 4}
	ctx := context.Background()
	code := func(err error) string {
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("not an *Error: %v", err)
		}
		return e.Code
	}
	if _, err := c.Do(ctx, "GET", "http://127.0.0.1:1/x", nil, bob(t).SS58()); code(err) != CodeConnectError {
		t.Fatal(err)
	}
	if _, err := c.Do(ctx, "GET", "::bad", nil, ""); code(err) != CodeConnectError {
		t.Fatal(err)
	}
	if _, err := c.Do(ctx, "BAD METHOD", "http://127.0.0.1:1/", nil, ""); code(err) != CodeConnectError {
		t.Fatal(err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
	}))
	defer slow.Close()
	if _, err := c.Do(ctx, "GET", slow.URL, nil, ""); code(err) != CodeTimeout {
		t.Fatal(err)
	}
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer big.Close()
	if _, err := c.Do(ctx, "GET", big.URL, nil, ""); code(err) != CodeResponseTooLarge {
		t.Fatal(err)
	}
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("ab"))
		w.(http.Flusher).Flush()
		time.Sleep(time.Second)
	}))
	defer stall.Close()
	c.MaxResponseBytes = 0
	if _, err := c.Do(ctx, "GET", stall.URL, nil, ""); code(err) != CodeTimeout {
		t.Fatal(err)
	}
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("ab"))
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer cut.Close()
	if _, err := c.Do(ctx, "GET", cut.URL, nil, ""); code(err) != CodeConnectError {
		t.Fatal(err)
	}
}

func TestVerifyResponseRejections(t *testing.T) {
	key := bob(t)
	h, _ := SignResponse(key, 7, alice(t).SS58(), 200, []byte("ok"))
	check := func(name string, h http.Header, responder string) {
		if _, err := VerifyResponse(h, responder, 7, alice(t).SS58(), 200, []byte("ok")); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	bad := h.Clone()
	bad.Set(RespHeaderCrypto, "ecdsa")
	check("scheme", bad, key.SS58())
	check("responder not ss58", h, "nope")
	dup := h.Clone()
	dup["x-tw-resp-signature"] = []string{h.Get(RespHeaderSignature)}
	check("duplicate in another spelling", dup, key.SS58())
	if _, err := VerifyResponse(h, key.SS58(), 7, alice(t).SS58(), 200, []byte("ok")); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyHeaderSpellingsCannotDodgeDuplicates(t *testing.T) {
	v, _ := NewVerifier(Config{SelfHotkey: bob(t).SS58(), Store: NewMemoryStore(time.Minute, nil)})
	h, _, _ := NewSigner(alice(t)).Sign("POST", "/x", nil, bob(t).SS58())
	h["x-bittensor-nonce"] = []string{h.Get(HeaderNonce)}
	_, err := v.Verify(context.Background(), h, nil, "POST", "/x")
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeMalformed {
		t.Fatal(err)
	}
}

// Base58 decoding is quadratic and the sender header is decoded before any
// signature check: found while fuzzing Verify (a long hotkey stalled it).
func TestHugeSenderIsRefusedBeforeDecoding(t *testing.T) {
	v, _ := NewVerifier(Config{SelfHotkey: bob(t).SS58(), Store: NewMemoryStore(time.Minute, nil)})
	h, _, _ := NewSigner(alice(t)).Sign("POST", "/x", nil, bob(t).SS58())
	h.Set(HeaderHotkey, strings.Repeat("z", 1<<20))
	start := time.Now()
	_, err := v.Verify(context.Background(), h, nil, "POST", "/x")
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeMalformed {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("took %v", d)
	}
}

// A backwards wall-clock step must not make a forgotten nonce fresh again:
// the pair stays until its nonce is stale on the wall clock too.
func TestMemoryStoreSurvivesWallClockStepBack(t *testing.T) {
	start := time.Unix(1000, 0)
	now := start
	s := NewMemoryStore(12*time.Second, func() time.Time { return now })
	nonce := uint64(start.UnixNano())
	ctx := context.Background()
	if ok, _ := s.CheckAndStore(ctx, "a", nonce); !ok {
		t.Fatal("first")
	}
	// 20 s later on the monotonic clock, but the wall clock was stepped back
	// 15 s: the nonce is only 5 s old, so it must still be remembered.
	now = start.Add(5 * time.Second)
	s.queue[0].at = start.Add(12 * time.Second).Add(-20 * time.Second)
	if ok, _ := s.CheckAndStore(ctx, "a", nonce); ok {
		t.Fatal("replay accepted after a wall-clock step back")
	}
	now = start.Add(13 * time.Second)
	if ok, _ := s.CheckAndStore(ctx, "a", nonce); !ok {
		t.Fatal("stale on both clocks: forgotten")
	}
}
