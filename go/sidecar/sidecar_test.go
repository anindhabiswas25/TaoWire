package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anindhabiswas25/TaoWire/go/btauth"
)

// Public dev keys: //Alice and //Bob (sr25519), //Alice (ed25519), //Dave.
const (
	alice   = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
	bob     = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
	charlie = "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu"
	dave    = "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy"
	token   = "tttttttttttttttttttttttttttttttt"
)

func neuron(uid int, hotkey string, permit bool, stake float64) map[string]any {
	var axon any
	if uid > 0 {
		axon = "203.0.113.7:8091"
	}
	return map[string]any{"uid": uid, "hotkey": hotkey, "validator_permit": permit, "total_stake_tao": stake, "axon": axon}
}

func snapshotBody(age float64, tempo int) map[string]any {
	return map[string]any{
		"netuid": 2, "block": 100, "tempo": tempo, "age_s": age,
		"neurons": []any{neuron(0, alice, true, 1000), neuron(1, bob, false, 5), neuron(2, charlie, true, 10)},
	}
}

func mustJSON(v any) []byte {
	if b, ok := v.([]byte); ok {
		return b
	}
	b, _ := json.Marshal(v)
	return b
}

type seen struct {
	auth, path, body string
}

type fake struct {
	mu      sync.Mutex
	seen    []seen
	handler func(r *http.Request) (int, any)
	srv     *httptest.Server
}

func newFake(t *testing.T, handler func(r *http.Request) (int, any)) *fake {
	t.Helper()
	f := &fake{handler: handler}
	if f.handler == nil {
		f.handler = func(r *http.Request) (int, any) {
			switch {
			case strings.HasPrefix(r.URL.Path, "/v1/health"):
				return 200, map[string]any{"ok": true, "hotkey": bob, "netuid": 2, "block": 100, "metagraph_age_s": 1, "stage": "fresh"}
			case strings.HasPrefix(r.URL.Path, "/v1/metagraph"):
				return 200, snapshotBody(1, 360)
			}
			return 404, "nope"
		}
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.seen = append(f.seen, seen{r.Header.Get("Authorization"), r.URL.RequestURI(), string(body)})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			_, _ = w.Write(btauth.ErrorBody(btauth.NewError(CodeUnauthorized, ""), ""))
			return
		}
		status, answer := f.handler(r)
		w.WriteHeader(status)
		_, _ = w.Write(mustJSON(answer))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) calls() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seen(nil), f.seen...)
}

func client(t *testing.T, f *fake, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{NetUID: 2, URL: f.srv.URL, Token: token}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func codeOf(err error) string {
	var e *btauth.Error
	var ce *ChainError
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &e):
		return e.Code
	case errors.As(err, &ce):
		return ce.Code
	}
	return err.Error()
}

func TestTokenFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	_ = os.WriteFile(good, []byte(token+"\n"), 0o600)
	if got, err := ReadTokenFile(good); err != nil || got != token {
		t.Fatal(got, err)
	}
	cases := map[string]string{filepath.Join(dir, "missing"): "cannot open", dir: "not a regular file"}
	open := filepath.Join(dir, "open")
	_ = os.WriteFile(open, []byte(token), 0o644)
	_ = os.Chmod(open, 0o644)
	cases[open] = "group or others"
	for name, content := range map[string]string{"empty": "", "short": "short", "long": strings.Repeat("x", 1025), "space": strings.Repeat("x", 20) + " y", "latin": strings.Repeat("x", 20) + "\xe9"} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(content), 0o600)
		cases[p] = "printable ASCII"
	}
	for path, want := range cases {
		_, err := ReadTokenFile(path)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), token) {
			t.Errorf("%s: %v", path, err)
		}
	}
	c, err := New(Config{NetUID: 2, TokenFile: good})
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprintf("%v %+v %#v %s", c, c, c, c); strings.Contains(s, token) {
		t.Fatal("token printed")
	}
	t.Setenv("TW_SIDECAR_TOKEN_FILE", good)
	if _, err := New(Config{NetUID: 2}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TW_SIDECAR_TOKEN_FILE", "")
	if _, err := New(Config{NetUID: 2}); err == nil {
		t.Fatal("no token source")
	}
}

func TestURLAndSettings(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:9910", "http://127.0.0.2:1", "http://[::1]:9910", "http://localhost:9910"} {
		p, _ := url.Parse(u)
		if !IsLoopback(p) {
			t.Error(u)
		}
	}
	for _, u := range []string{"http://10.0.0.1:9910", "http://example.com", "http://[::2]"} {
		p, _ := url.Parse(u)
		if IsLoopback(p) {
			t.Error(u)
		}
		if _, err := New(Config{NetUID: 2, URL: u, Token: token}); err == nil {
			t.Error("remote accepted", u)
		}
	}
	if _, err := New(Config{NetUID: 2, URL: "http://10.0.0.1", Token: token, UnsafeAllowRemote: true}); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{
		{NetUID: -1, Token: token}, {NetUID: 2, URL: "ftp://127.0.0.1", Token: token},
		{NetUID: 2, Token: "short"}, {NetUID: 2, Token: token, SoftAge: time.Minute, MaxAge: time.Second},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
}

func TestPolicy(t *testing.T) {
	snap, err := ParseSnapshot(mustJSON(snapshotBody(1, 360)), 2)
	if err != nil {
		t.Fatal(err)
	}
	strict := StrictPolicy()
	check := func(p *Policy, hotkey, want string) {
		t.Helper()
		if _, err := p.Check(hotkey, snap); codeOf(err) != want {
			t.Errorf("%s: %v want %s", hotkey, err, want)
		}
	}
	check(strict, alice, "ok")
	check(strict, bob, "tw.forbidden_not_validator")
	check(strict, dave, "tw.forbidden_not_registered")
	open, _ := NewPolicy(false, 0, nil, nil)
	check(open, bob, "ok")
	staked, _ := NewPolicy(true, 100, nil, nil)
	check(staked, charlie, "tw.forbidden_low_stake")
	check(staked, alice, "ok")
	lists, _ := NewPolicy(true, 0, []string{dave}, []string{alice})
	check(lists, dave, "ok")
	check(lists, alice, "tw.forbidden_denied")
	for _, bad := range []float64{-1, nanValue(), infValue()} {
		if _, err := NewPolicy(true, bad, nil, nil); err == nil {
			t.Error(bad)
		}
	}
	if _, err := NewPolicy(true, 0, []string{alice}, []string{alice}); err == nil {
		t.Error("both lists")
	}
}

func nanValue() float64 { z := 0.0; return z / z }
func infValue() float64 { z := 0.0; return 1 / z }

func TestCalls(t *testing.T) {
	f := newFake(t, nil)
	c := client(t, f, nil)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Stop()
	c.Stop()
	calls := f.calls()
	if len(calls) != 2 || calls[0].path != "/v1/health" || calls[1].path != "/v1/metagraph?netuid=2" {
		t.Fatal(calls)
	}
	for _, s := range calls {
		if s.auth != "Bearer "+token {
			t.Fatal(s.auth)
		}
	}
	wrong := client(t, f, func(cfg *Config) { cfg.Token = strings.Repeat("w", 32) })
	if _, err := wrong.Health(context.Background()); codeOf(err) != CodeUnauthorized {
		t.Fatal(err)
	}
	if err := client(t, f, func(cfg *Config) { cfg.ExpectedHotkey = alice }).Start(context.Background()); err == nil || !strings.Contains(err.Error(), "hotkey") {
		t.Fatal(err)
	}
	if err := client(t, f, func(cfg *Config) { cfg.NetUID = 3 }).Start(context.Background()); err == nil || !strings.Contains(err.Error(), "netuid") {
		t.Fatal(err)
	}
	ok := client(t, f, func(cfg *Config) { cfg.ExpectedHotkey = bob })
	if err := ok.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ok.Stop()
}

func TestCallerAndServeAxon(t *testing.T) {
	hash := "0x" + strings.Repeat("ab", 32)
	answers := []struct {
		status int
		body   any
	}{
		{200, map[string]any{"allowed": true}},
		{200, map[string]any{"allowed": false, "code": "tw.forbidden_low_stake"}},
		{200, map[string]any{"ok": true, "block_hash": hash}},
		{409, map[string]any{"ok": false, "code": "rate_limited", "error_name": nil, "remediation": "wait 50 blocks"}},
		{503, map[string]any{"ok": false, "code": "chain_unavailable"}},
		{422, btauth.ErrorBody(btauth.NewError("tw.invalid_request", ""), "")},
		{200, map[string]any{"ok": true, "block_hash": "0x12"}},
		{409, "garbage"},
		{503, btauth.ErrorBody(btauth.NewError("tw.forbidden_denied", ""), "")},
	}
	var mu sync.Mutex
	f := newFake(t, func(*http.Request) (int, any) {
		mu.Lock()
		defer mu.Unlock()
		a := answers[0]
		answers = answers[1:]
		return a.status, a.body
	})
	c := client(t, f, nil)
	ctx := context.Background()
	if d, err := c.Caller(ctx, alice); err != nil || !d.Allowed {
		t.Fatal(d, err)
	}
	if d, err := c.Caller(ctx, "a/b"); err != nil || d.Allowed || d.Code != "tw.forbidden_low_stake" {
		t.Fatal(d, err)
	}
	if got, err := c.ServeAxon(ctx, "203.0.113.7", 8091, ""); err != nil || got != hash {
		t.Fatal(got, err)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(f.calls()[2].body), &body)
	if body["tls_cert_hex"] != nil || body["ip"] != "203.0.113.7" || body["netuid"] != 2.0 {
		t.Fatal(body)
	}
	_, err := c.ServeAxon(ctx, "x", 1, "0x01ab")
	var ce *ChainError
	if !errors.As(err, &ce) || ce.Code != "rate_limited" || ce.Remediation != "wait 50 blocks" || !strings.Contains(ce.Error(), "rate_limited") {
		t.Fatal(err)
	}
	for _, want := range []string{"chain_unavailable", "tw.invalid_request", btauth.CodeInvalidResponse, btauth.CodeInvalidResponse, btauth.CodeInvalidResponse} {
		if _, err := c.ServeAxon(ctx, "x", 1, ""); codeOf(err) != want {
			t.Errorf("%v want %s", err, want)
		}
	}
	if f.calls()[1].path != "/v1/caller/a%2Fb?netuid=2" {
		t.Fatal(f.calls()[1].path)
	}
	if n := len(f.calls()); n != 9 {
		t.Fatalf("%d calls: a write is never resent", n)
	}
}

func TestTransportFailures(t *testing.T) {
	ctx := context.Background()
	dead, _ := New(Config{NetUID: 2, URL: "http://127.0.0.1:1", Token: token})
	if _, err := dead.Health(ctx); codeOf(err) != btauth.CodeConnectError {
		t.Fatal(err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slow.Close()
	quick, _ := New(Config{NetUID: 2, URL: slow.URL, Token: token, Timeout: 200 * time.Millisecond})
	if _, err := quick.Health(ctx); codeOf(err) != btauth.CodeTimeout {
		t.Fatal(err)
	}
	big := newFake(t, func(*http.Request) (int, any) {
		return 200, []byte(`{"x":"` + strings.Repeat("a", MaxAnswerBytes) + `"}`)
	})
	if _, err := client(t, big, nil).Health(ctx); codeOf(err) != btauth.CodeResponseTooLarge {
		t.Fatal(err)
	}
	stale := newFake(t, func(*http.Request) (int, any) {
		return 503, btauth.ErrorBody(btauth.NewError(CodeStale, ""), "")
	})
	if _, err := client(t, stale, nil).Metagraph(ctx); codeOf(err) != CodeStale {
		t.Fatal(err)
	}
	if _, err := client(t, stale, nil).Caller(ctx, alice); codeOf(err) != CodeStale {
		t.Fatal(err)
	}
	if err := client(t, stale, nil).Start(ctx); codeOf(err) != CodeStale {
		t.Fatal(err)
	}
	redirect := httptest.NewServer(http.RedirectHandler("http://127.0.0.1:1/x", http.StatusTemporaryRedirect))
	defer redirect.Close()
	r, _ := New(Config{NetUID: 2, URL: redirect.URL, Token: token})
	if _, err := r.Health(ctx); codeOf(err) != btauth.CodeInvalidResponse {
		t.Fatal(err)
	}
}

func TestStagesAndKnownCallers(t *testing.T) {
	var mu sync.Mutex
	age, fail := 5.0, false
	f := newFake(t, func(r *http.Request) (int, any) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return 500, "down"
		}
		return 200, snapshotBody(age, 10) // tempo 10: max 240 s, soft 120 s
	})
	now := time.Unix(1_000_000, 0)
	c := client(t, f, func(cfg *Config) { cfg.Now = func() time.Time { return now } })
	ctx := context.Background()
	want := func(hotkey, scope, code string) {
		t.Helper()
		if _, err := c.Check(hotkey, scope); codeOf(err) != code {
			t.Fatalf("%s on %s: %v want %s", hotkey, scope, err, code)
		}
	}
	if c.Stage() != KnownCallersOnly || c.Snapshot() != nil {
		t.Fatal("no snapshot must fail closed")
	}
	want(alice, "/r", CodeStale)
	if _, err := c.Metagraph(ctx); err != nil {
		t.Fatal(err)
	}
	if soft, max := c.Thresholds(); soft != 120*time.Second || max != 240*time.Second {
		t.Fatal(soft, max)
	}
	want(alice, "/r", "ok")
	now = now.Add(115 * time.Second)
	if c.Stage() != Degraded {
		t.Fatal(c.Stage())
	}
	now = now.Add(120 * time.Second)
	if c.Stage() != Degraded {
		t.Fatal("exactly the max age is degraded")
	}
	now = now.Add(time.Second)
	if c.Stage() != KnownCallersOnly {
		t.Fatal(c.Stage())
	}
	want(alice, "/r", "ok")
	want(alice, "/other", CodeStale)
	want(charlie, "/r", CodeStale)
	mu.Lock()
	age = 241
	mu.Unlock()
	if _, err := c.Metagraph(ctx); err != nil { // the same stale snapshot again
		t.Fatal(err)
	}
	want(alice, "/r", "ok")
	mu.Lock()
	age = 238 // the same snapshot answered 3 s late (a slow sidecar) is not newer
	mu.Unlock()
	if _, err := c.Metagraph(ctx); err != nil {
		t.Fatal(err)
	}
	want(alice, "/r", "ok")
	mu.Lock()
	fail = true
	mu.Unlock()
	if _, err := c.Metagraph(ctx); err == nil || c.Snapshot() == nil {
		t.Fatal("a failed refresh keeps the snapshot")
	}
	mu.Lock()
	fail, age = false, 0
	mu.Unlock()
	if _, err := c.Metagraph(ctx); err != nil {
		t.Fatal(err)
	}
	if a, _ := c.Age(); c.Stage() != Fresh || a != 0 {
		t.Fatal(c.Stage(), a)
	}
	want(bob, "/r", "tw.forbidden_not_validator")
	strict := client(t, f, func(cfg *Config) {
		cfg.Strict, cfg.MaxAge, cfg.SoftAge = true, 50*time.Second, 10*time.Second
		cfg.Now = func() time.Time { return now }
	})
	if _, err := strict.Metagraph(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Check(alice, "/"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(60 * time.Second)
	if _, err := strict.Check(alice, "/"); codeOf(err) != CodeStale {
		t.Fatal(err)
	}
	denied := client(t, f, func(cfg *Config) { cfg.Policy, _ = NewPolicy(true, 0, nil, []string{alice}) })
	if _, err := denied.Check(alice, "/"); codeOf(err) != "tw.forbidden_denied" {
		t.Fatal(err)
	}
}

func TestBackgroundRefreshAndMiddlewarePolicy(t *testing.T) {
	f := newFake(t, nil)
	c := client(t, f, func(cfg *Config) { cfg.Refresh = 50 * time.Millisecond })
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil { // replaces, never adds a loop
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	c.Stop()
	n := len(f.calls())
	if n < 4 {
		t.Fatal(n)
	}
	time.Sleep(150 * time.Millisecond)
	if len(f.calls()) != n {
		t.Fatal("refresh after Stop")
	}
	hook := c.Policy()
	r := httptest.NewRequest("POST", "/v1/x", nil)
	if err := hook(r, &btauth.Caller{Hotkey: alice}); err != nil {
		t.Fatal(err)
	}
	if err := hook(r, &btauth.Caller{Hotkey: bob}); codeOf(err) != "tw.forbidden_not_validator" {
		t.Fatal(err)
	}
	// Invented paths do not grow the known-callers set (one scope).
	for i := 0; i < 100; i++ {
		if err := hook(httptest.NewRequest("POST", fmt.Sprintf("/x/%d", i), nil), &btauth.Caller{Hotkey: alice}); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	n = len(c.known)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d known-caller entries for one caller", n)
	}
}

func TestHostileSnapshots(t *testing.T) {
	with := func(k string, v any) map[string]any {
		b := snapshotBody(1, 360)
		b[k] = v
		return b
	}
	withNeuron := func(k string, v any) map[string]any {
		n := neuron(0, alice, true, 1)
		n[k] = v
		return with("neurons", []any{n})
	}
	missing := func(k string) map[string]any {
		n := neuron(0, alice, true, 1)
		delete(n, k)
		return with("neurons", []any{n})
	}
	cases := map[string]any{
		"netuid": with("netuid", 3), "netuid string": with("netuid", "2"), "netuid float": with("netuid", 2.5),
		"block": with("block", -1), "block float": with("block", 1.5), "tempo": with("tempo", 0),
		"age": with("age_s", -1), "age string": with("age_s", "1"), "neurons": with("neurons", map[string]any{}),
		"neurons null": with("neurons", nil), "neuron null": with("neurons", []any{nil}),
		"uid dup":    with("neurons", []any{neuron(0, alice, true, 1), neuron(0, bob, true, 1)}),
		"hotkey dup": with("neurons", []any{neuron(0, alice, true, 1), neuron(1, alice, true, 1)}),
		"hotkey bad": withNeuron("hotkey", "5Grw"), "permit": withNeuron("validator_permit", 1),
		"stake": withNeuron("total_stake_tao", -5), "stake string": withNeuron("total_stake_tao", "1e9"),
		"axon": withNeuron("axon", 5), "axon missing": missing("axon"), "uid missing": missing("uid"),
		"array": []any{snapshotBody(1, 360)}, "dup key": []byte(`{"netuid":2,"netuid":2,"block":1,"tempo":1,"age_s":0,"neurons":[]}`),
		"nested dup": []byte(`{"netuid":2,"block":1,"tempo":1,"age_s":0,"neurons":[{"uid":0,"uid":1,"hotkey":"` + alice + `","validator_permit":true,"total_stake_tao":1,"axon":null}]}`),
		"not utf8":   []byte("\xff"), "trailing": []byte(`{}x`),
	}
	for name, body := range cases {
		if _, err := ParseSnapshot(mustJSON(body), 2); codeOf(err) != btauth.CodeInvalidResponse {
			t.Errorf("%s: %v", name, err)
		}
	}
	s, err := ParseSnapshot(mustJSON(snapshotBody(1, 360)), 2)
	if err != nil || len(s.Neurons) != 3 {
		t.Fatal(err)
	}
	if n, ok := s.ByHotkey(bob); !ok || n.UID != 1 || n.Axon == "" {
		t.Fatal(n)
	}
	for _, body := range []string{`{"allowed":"true"}`, `{"allowed":1}`, `{"allowed":true,"code":"tw.forbidden_denied"}`,
		`{"allowed":false}`, `{"allowed":false,"code":"tw.ok"}`, `{"allowed":false,"allowed":true}`, `[true]`} {
		if _, err := ParseDecision([]byte(body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	h := map[string]any{"ok": true, "hotkey": bob, "netuid": 2, "block": nil, "metagraph_age_s": nil, "stage": "known_callers_only"}
	if got, err := ParseHealth(mustJSON(h)); err != nil || got.Block != nil || got.MetagraphAgeS != nil {
		t.Fatal(got, err)
	}
	for k, v := range map[string]any{"ok": "yes", "hotkey": "x", "stage": "stale", "block": -1, "metagraph_age_s": -1, "netuid": "2"} {
		bad := map[string]any{}
		for kk, vv := range h {
			bad[kk] = vv
		}
		bad[k] = v
		if _, err := ParseHealth(mustJSON(bad)); err == nil {
			t.Errorf("health %s accepted", k)
		}
	}
	for _, k := range []string{"block", "metagraph_age_s"} {
		bad := map[string]any{}
		for kk, vv := range h {
			if kk != k {
				bad[kk] = vv
			}
		}
		if _, err := ParseHealth(mustJSON(bad)); err == nil {
			t.Errorf("health without %s accepted", k)
		}
	}
}

// FuzzParseSnapshot: arbitrary sidecar JSON never panics and never admits a
// caller that the answer does not really list with a validator permit.
func FuzzParseSnapshot(f *testing.F) {
	f.Add(mustJSON(snapshotBody(1, 360)))
	f.Add([]byte(`{"netuid":2,"block":1,"tempo":1,"age_s":0,"neurons":[{"uid":0,"hotkey":"` + alice + `","validator_permit":"yes","total_stake_tao":1,"axon":null}]}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		s, err := ParseSnapshot(body, 2)
		if err != nil {
			if codeOf(err) != btauth.CodeInvalidResponse {
				t.Fatal(err)
			}
			return
		}
		n, listed := s.ByHotkey(alice)
		_, err = StrictPolicy().Check(alice, s)
		if (err == nil) != (listed && n.ValidatorPermit) {
			t.Fatalf("admitted=%v listed=%v", err == nil, listed)
		}
	})
}

// FuzzParseDecision: an arbitrary /v1/caller answer allows only when it is
// exactly {"allowed": true}.
func FuzzParseDecision(f *testing.F) {
	f.Add([]byte(`{"allowed":true}`))
	f.Add([]byte(`{"allowed":false,"code":"tw.forbidden_denied"}`))
	f.Add([]byte(`{"allowed":true,"allowed":true}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		d, err := ParseDecision(body)
		if err == nil && d.Allowed {
			var m map[string]any
			if json.Unmarshal(body, &m) != nil || len(m) != 1 || m["allowed"] != true {
				t.Fatalf("allowed %q", body)
			}
		}
	})
}
