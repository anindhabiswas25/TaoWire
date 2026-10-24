package btauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func events(evs []SSEEvent) string {
	var b strings.Builder
	for _, e := range evs {
		fmt.Fprintf(&b, "%s=%q;", e.Event, e.Data)
	}
	return b.String()
}

func parseAll(input string) string {
	var p SSEParser
	out := p.Feed([]byte(input))
	return events(append(out, p.Finish()...))
}

func TestSSEParserCases(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"event: chunk\ndata: {}\n\n", `chunk="{}";`},
		{"event: chunk\r\ndata: {}\r\n\r\n", `chunk="{}";`},
		{"event: chunk\rdata: {}\r\r", `chunk="{}";`},
		{"data: a\ndata: b\n\n", `message="a\nb";`},
		{"data:a\n\n", `message="a";`},
		{"data:  a\n\n", `message=" a";`},
		{"data\n\n", `message="";`},
		{": comment\ndata: x\n\n", `message="x";`},
		{"event:\ndata: x\n\n", `message="x";`},
		{"event: e\n\n", ``},
		{"id: 1\nretry: 5\nfoo: bar\ndata: x\n\n", `message="x";`},
		{"data: unfinished", ``},
		{"data: x\n", ``},
		{"\xef\xbb\xbfdata: x\n\n", `message="x";`},
		{"data: x\n\n\xef\xbb\xbfdata: y\n\n", `message="x";`},
		{"event: a\ndata: 1\n\nevent: b\ndata: 2\n\n", `a="1";b="2";`},
		{"data: x\r", ``},
		{"data: x\r\r", `message="x";`},
	} {
		if got := parseAll(c.in); got != c.want {
			t.Errorf("%q: got %s want %s", c.in, got, c.want)
		}
	}
	// A CR at the end of one feed may be half of a CRLF.
	var p SSEParser
	got := p.Feed([]byte("data: x\r"))
	got = append(got, p.Feed([]byte("\n\r\n"))...)
	if events(got) != `message="x";` {
		t.Fatal(events(got))
	}
	// A BOM split across feeds is still skipped; one later is data.
	p = SSEParser{}
	got = append(p.Feed([]byte{0xef}), p.Feed([]byte{0xbb})...)
	got = append(got, p.Feed([]byte("\xbfdata: y\n\n"))...)
	if events(got) != `message="y";` {
		t.Fatal(events(got))
	}
}

var sseTokens = []string{"event: chunk", "event: tw-end", "data: ", "data:", "{\"a\":1}", ":", " ",
	"\n", "\r", "\r\n", "\xef\xbb\xbf", "x", "id: 3", "é", "\x00"}

func TestSSEParserSplitsAreEquivalent(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for n := 0; n < 3000; n++ {
		var in []byte
		for k := r.Intn(30); k > 0; k-- {
			in = append(in, sseTokens[r.Intn(len(sseTokens))]...)
		}
		want := parseAll(string(in))
		var p SSEParser
		var got []SSEEvent
		for rest := in; len(rest) > 0; {
			cut := 1 + r.Intn(len(rest))
			got = append(got, p.Feed(rest[:cut])...)
			rest = rest[cut:]
		}
		got = append(got, p.Finish()...)
		if events(got) != want {
			t.Fatalf("%q: split %s, whole %s", in, events(got), want)
		}
	}
}

func TestSSEParserIsLinearOnALongLine(t *testing.T) {
	line := bytes.Repeat([]byte("x"), 4<<20)
	for _, step := range []int{1, 7} {
		var p SSEParser
		start := time.Now()
		p.Feed([]byte("data: "))
		for i := 0; i < len(line); i += step {
			p.Feed(line[i:min(i+step, len(line))])
		}
		got := p.Feed([]byte("\n\n"))
		if took := time.Since(start); took > 5*time.Second {
			t.Fatalf("4 MiB line in %d-byte pieces took %v", step, took)
		}
		if len(got) != 1 || len(got[0].Data) != len(line) {
			t.Fatal("event lost")
		}
	}
}

func TestDecodeAndEncodeChunk(t *testing.T) {
	deep := strings.Repeat("[", MaxChunkDepth+1) + strings.Repeat("]", MaxChunkDepth+1)
	ok := strings.Repeat("[", MaxChunkDepth) + strings.Repeat("]", MaxChunkDepth)
	for in, valid := range map[string]bool{
		`{"a":1}`: true, `[1,2]`: true, ` {"a":"\n"} `: true, ok: true, `{"s":"[[[["}`: true,
		`1`: false, `"s"`: false, `null`: false, `true`: false, `{`: false, `NaN`: false,
		`[NaN]`: false, `[Infinity]`: false, "\xff": false, `{"a":1}x`: false, deep: false, ``: false,
	} {
		if _, err := DecodeChunk([]byte(in)); (err == nil) != valid {
			t.Errorf("DecodeChunk(%q) = %v", in, err)
		}
	}
	for _, item := range []any{map[string]int{"a": 1}, []int{1}, json.RawMessage(`{"x":2}`), []byte(` [3]`)} {
		if _, err := EncodeChunk(item); err != nil {
			t.Errorf("EncodeChunk(%v): %v", item, err)
		}
	}
	var nilSlice []int
	for _, item := range []any{1, "s", nil, nilSlice, []byte(`{"a":` + "\n" + `1}`), json.RawMessage(`"s"`),
		[]byte(`{"a"`), func() {}, json.RawMessage(deep)} {
		var ce *ChunkError
		if _, err := EncodeChunk(item); !errors.As(err, &ce) {
			t.Errorf("EncodeChunk(%#v) = %v", item, err)
		}
	}
}

func TestParseTrailer(t *testing.T) {
	d := strings.Repeat("ab", 32)
	good := `{"digest":"` + d + `","count":3,"signature":"0x00"}`
	tr, err := ParseTrailer([]byte(good))
	if err != nil || tr.Count != 3 || tr.Digest != d || tr.Signature != "0x00" {
		t.Fatal(tr, err)
	}
	if string(EncodeTrailer(tr)) != good {
		t.Fatal(string(EncodeTrailer(tr)))
	}
	if tr, err := ParseTrailer([]byte(`{"count":0,"digest":"` + d + `"}`)); err != nil || tr.Signature != "" {
		t.Fatal(err)
	}
	for _, bad := range []string{
		``, `[]`, `"x"`, `{}`, `{"digest":"` + d + `"}`, `{"count":1}`,
		`{"digest":"` + strings.ToUpper(d) + `","count":1}`, `{"digest":"ab","count":1}`,
		`{"digest":"` + d + `","count":1.0}`, `{"digest":"` + d + `","count":1e2}`,
		`{"digest":"` + d + `","count":-1}`, `{"digest":"` + d + `","count":-0}`,
		`{"digest":"` + d + `","count":true}`, `{"digest":"` + d + `","count":"1"}`,
		`{"digest":"` + d + `","count":18446744073709551616}`,
		`{"digest":"` + d + `","count":1,"signature":1}`, `{"digest":"` + d + `","count":1,"x":1}`,
		`{"digest":"` + d + `","count":1,"count":1}`, `{"digest":"` + d + `","digest":"` + d + `","count":1}`,
		`{"digest":"` + d + `","count":1}x`, `{"digest":{},"count":1}`, "\xff",
	} {
		var te *TrailerError
		if _, err := ParseTrailer([]byte(bad)); !errors.As(err, &te) {
			t.Errorf("ParseTrailer(%q) = %v", bad, err)
		}
	}
	if tr, err := ParseTrailer([]byte(`{"digest":"` + d + `","count":18446744073709551615}`)); err != nil || tr.Count != ^uint64(0) {
		t.Fatal(err)
	}
}

func TestEncodeEventAndReserve(t *testing.T) {
	if f, _ := EncodeEvent("chunk", []byte("{}")); string(f) != "event: chunk\ndata: {}\n\n" {
		t.Fatal(string(f))
	}
	if _, err := EncodeEvent("a\nb", nil); err == nil {
		t.Fatal("line break in event name")
	}
	if _, err := EncodeEvent("a", []byte("\r")); err == nil {
		t.Fatal("line break in data")
	}
	if TrailerReserve != 273 {
		t.Fatalf("TrailerReserve = %d (Python: 273)", TrailerReserve)
	}
}

func TestStreamLimitsRanges(t *testing.T) {
	l, err := StreamLimits{}.Resolved()
	if err != nil || l != DefaultStreamLimits() {
		t.Fatal(l, err)
	}
	for _, bad := range []StreamLimits{
		{MaxDuration: 999 * time.Millisecond}, {MaxDuration: 601 * time.Second},
		{MaxBytes: 1023}, {MaxBytes: 64<<20 + 1}, {Idle: 500 * time.Millisecond}, {Idle: 121 * time.Second},
	} {
		if _, err := bad.Resolved(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestStreamSlots(t *testing.T) {
	for _, n := range []int{0, 257} {
		if _, err := NewStreamSlots(n); err == nil {
			t.Fatal(n)
		}
	}
	s, _ := NewStreamSlots(2)
	r1, _ := s.Acquire("a")
	r2, _ := s.Acquire("a")
	if _, err := s.Acquire("a"); err == nil || err.(*Error).Code != CodeRateLimited || err.(*Error).Status != 429 {
		t.Fatal(err)
	}
	if r3, err := s.Acquire("b"); err != nil {
		t.Fatal(err)
	} else {
		r3()
	}
	r1()
	r1()
	if s.Open("a") != 1 {
		t.Fatal(s.Open("a"))
	}
	r2()
	if s.Open("a") != 0 || len(s.open) != 0 {
		t.Fatal("not released")
	}
}

// ---------------------------------------------------------------- miner + client

type abortLog struct {
	mu      sync.Mutex
	reasons []string
}

func (a *abortLog) hook(_, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reasons = append(a.reasons, reason)
}

func (a *abortLog) wait(t *testing.T) []string {
	t.Helper()
	for i := 0; i < 300; i++ {
		a.mu.Lock()
		n := len(a.reasons)
		a.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.reasons...)
}

func list(items ...any) func(context.Context) (any, error) {
	i := 0
	return func(context.Context) (any, error) {
		if i == len(items) {
			return nil, io.EOF
		}
		i++
		if err, ok := items[i-1].(error); ok {
			return nil, err
		}
		return items[i-1], nil
	}
}

func streamMiner(t *testing.T, key *Keypair, cfg StreamConfig, src func() ChunkFunc) *httptest.Server {
	t.Helper()
	v, err := NewVerifier(Config{SelfHotkey: key.SS58(), Store: NewMemoryStore(time.Minute, nil)})
	if err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	mw := MiddlewareConfig{Verifier: v, ResponseKey: key, Logger: quiet}
	h := Middleware(mw)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServeStream(w, r, src(), cfg)
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func readAll(s *Stream) []string {
	var out []string
	for s.Next() {
		out = append(out, string(s.Chunk().Data))
	}
	return out
}

func codeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprint(err)
}

func TestStreamRoundTrip(t *testing.T) {
	for _, key := range []*Keypair{bob(t), NewEd25519FromSeed(seed(t, "398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89"))} {
		srv := streamMiner(t, key, StreamConfig{}, func() ChunkFunc {
			return list(map[string]string{"t": "Hel"}, json.RawMessage(`{"t":"lo ☃"}`), []int{1})
		})
		c := &Client{Signer: NewSigner(alice(t))}
		s, err := c.Stream(context.Background(), "POST", srv.URL+"/v1/s?x=1", []byte(`{}`), key.SS58(), StreamOptions{})
		if err != nil {
			t.Fatal(err)
		}
		got := readAll(s)
		if s.Err() != nil || !s.Verified() || strings.Join(got, "|") != `{"t":"Hel"}|{"t":"lo ☃"}|[1]` || len(s.Chunks()) != 3 {
			t.Fatalf("%v %v %v", got, s.Err(), s.Verified())
		}
		if s.Next() || s.Close() != nil {
			t.Fatal("Next after the end")
		}
	}
	// Zero chunks is a valid stream.
	srv := streamMiner(t, bob(t), StreamConfig{}, func() ChunkFunc { return list() })
	s, err := (&Client{Signer: NewSigner(alice(t))}).Stream(context.Background(), "GET", srv.URL+"/", nil, bob(t).SS58(), StreamOptions{})
	if err != nil || len(readAll(s)) != 0 || !s.Verified() {
		t.Fatal(err, s.Err())
	}
}

func TestStreamBeforeTheFirstByte(t *testing.T) {
	c := &Client{Signer: NewSigner(alice(t))}
	for name, tc := range map[string]struct {
		src  ChunkFunc
		code string
	}{
		"error":   {list(errors.New("boom")), CodeHandlerError},
		"panic":   {func(context.Context) (any, error) { panic("first chunk bug") }, CodeHandlerError},
		"twerror": {list(NewError("tw.forbidden_not_validator", "")), "tw.forbidden_not_validator"},
		"timeout": {func(ctx context.Context) (any, error) { <-ctx.Done(); return nil, ctx.Err() }, "tw.handler_timeout"},
	} {
		srv := streamMiner(t, bob(t), StreamConfig{FirstChunkTimeout: 100 * time.Millisecond}, func() ChunkFunc { return tc.src })
		_, err := c.Stream(context.Background(), "POST", srv.URL+"/", nil, bob(t).SS58(), StreamOptions{})
		if codeOf(err) != tc.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Outside Middleware there is no caller: tw.internal.
	rec := httptest.NewRecorder()
	ServeStream(rec, httptest.NewRequest("GET", "/", nil), list(), StreamConfig{})
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "tw.internal") {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

func TestStreamMinerAborts(t *testing.T) {
	big := map[string]string{"x": strings.Repeat("a", 900)}
	forever := func(ctx context.Context) (any, error) {
		select {
		case <-time.After(200 * time.Millisecond):
			return []int{1}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	stall := func() ChunkFunc {
		n := 0
		return func(ctx context.Context) (any, error) {
			if n++; n == 1 {
				return []int{1}, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	for name, tc := range map[string]struct {
		cfg    StreamConfig
		src    func() ChunkFunc
		reason string
	}{
		"handler_error": {StreamConfig{}, func() ChunkFunc { return list([]int{1}, errors.New("boom")) }, AbortHandlerError},
		"panic": {StreamConfig{}, func() ChunkFunc {
			n := 0
			return func(context.Context) (any, error) {
				if n++; n == 2 {
					panic("chunk source bug")
				}
				return []int{1}, nil
			}
		}, AbortHandlerError},
		"scalar":       {StreamConfig{}, func() ChunkFunc { return list([]int{1}, 5) }, AbortBadChunk},
		"line break":   {StreamConfig{}, func() ChunkFunc { return list([]int{1}, []byte("{\"a\":\n1}")) }, AbortBadChunk},
		"too deep":     {StreamConfig{}, func() ChunkFunc { return list(json.RawMessage(strings.Repeat("[", 129) + strings.Repeat("]", 129))) }, AbortBadChunk},
		"idle":         {StreamConfig{Limits: StreamLimits{Idle: time.Second}}, stall, AbortIdleTimeout},
		"max_bytes":    {StreamConfig{Limits: StreamLimits{MaxBytes: 1024}}, func() ChunkFunc { return list(big) }, AbortMaxBytes},
		"max_duration": {StreamConfig{Limits: StreamLimits{MaxDuration: time.Second}}, func() ChunkFunc { return forever }, AbortMaxDuration},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var log abortLog
			tc.cfg.OnAbort = log.hook
			tc.cfg.Route = "/v1/s"
			slots, _ := NewStreamSlots(1)
			tc.cfg.Slots = slots
			srv := streamMiner(t, bob(t), tc.cfg, tc.src)
			c := &Client{Signer: NewSigner(alice(t))}
			s, err := c.Stream(context.Background(), "POST", srv.URL+"/", nil, bob(t).SS58(), StreamOptions{Timeout: 30 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			readAll(s)
			if codeOf(s.Err()) != CodeBadResponseSignature || s.Verified() {
				t.Fatalf("client: %v", s.Err())
			}
			if got := log.wait(t); len(got) != 1 || got[0] != tc.reason {
				t.Fatalf("aborts %v", got)
			}
			for i := 0; slots.Open(alice(t).SS58()) != 0; i++ {
				if i > 200 {
					t.Fatal("slot not released")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestStreamSlotsPerCaller(t *testing.T) {
	slots, _ := NewStreamSlots(1)
	hold := make(chan struct{})
	srv := streamMiner(t, bob(t), StreamConfig{Slots: slots}, func() ChunkFunc {
		n := 0
		return func(ctx context.Context) (any, error) {
			if n++; n == 1 {
				return []int{1}, nil
			}
			select {
			case <-hold:
				return nil, io.EOF
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	})
	c := &Client{Signer: NewSigner(alice(t))}
	first, err := c.Stream(context.Background(), "POST", srv.URL+"/", nil, bob(t).SS58(), StreamOptions{})
	if err != nil || !first.Next() {
		t.Fatal(err)
	}
	// The second stream of the same caller: signed 429 before any byte.
	resp := signedRequest(t, srv.URL+"/", nil, nil)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "1" || resp.Header.Get(RespHeaderSignature) == "" {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	if _, err := c.Stream(context.Background(), "POST", srv.URL+"/", nil, bob(t).SS58(), StreamOptions{}); codeOf(err) != CodeRateLimited {
		t.Fatal(err)
	}
	// Another caller is not affected.
	other := &Client{Signer: NewSigner(aliceEd(t))}
	s2, err := other.Stream(context.Background(), "POST", srv.URL+"/", nil, bob(t).SS58(), StreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	close(hold)
	readAll(first)
	readAll(s2)
	if !first.Verified() || !s2.Verified() {
		t.Fatal(first.Err(), s2.Err())
	}
	if slots.Open(alice(t).SS58()) != 0 {
		t.Fatal("slot kept")
	}
}

func TestStreamMinerWithoutResponseKey(t *testing.T) {
	v, _ := NewVerifier(Config{SelfHotkey: bob(t).SS58(), Store: NewMemoryStore(time.Minute, nil)})
	h := Middleware(MiddlewareConfig{Verifier: v, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ServeStream(w, r, list([]int{1}), StreamConfig{}) }))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp := signedRequest(t, srv.URL+"/", nil, nil)
	body, _ := io.ReadAll(resp.Body)
	if resp.Header.Get(RespHeaderHotkey) != "" || !strings.Contains(string(body), `event: tw-end`) || strings.Contains(string(body), "signature") {
		t.Fatal(string(body))
	}
}

// ---------------------------------------------------------------- client against a fake miner

// fakeStream answers with a stream built from chunks, signed by bob for the
// request's nonce and sender, after mutate changed the parts.
type fakeParts struct {
	header http.Header
	chunks []string
	before string // sent before the first chunk
	extra  string // appended after tw-end
	end    func(digest string, count int, sig string) string
	delay  time.Duration // before each frame
}

func fakeMiner(t *testing.T, mutate func(*fakeParts)) *httptest.Server {
	t.Helper()
	key := bob(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, _ := strconv.ParseUint(r.Header.Get(HeaderNonce), 10, 64)
		p := &fakeParts{header: http.Header{}, chunks: []string{`{"i":0}`, `{"i":1}`, `{"i":2}`}}
		p.header.Set("Content-Type", "text/event-stream; charset=utf-8")
		p.header.Set(RespHeaderVersion, "1")
		p.header.Set(RespHeaderHotkey, key.SS58())
		p.end = func(digest string, count int, sig string) string {
			return fmt.Sprintf(`{"digest":"%s","count":%d,"signature":"%s"}`, digest, count, sig)
		}
		mutate(p)
		d := NewStreamDigest()
		for _, c := range p.chunks {
			d.Update([]byte(c))
		}
		sig, _ := key.Sign(ResponsePayload(Sr25519, nonce, r.Header.Get(HeaderHotkey), key.SS58(), 200, d.Hex()))
		for k, v := range p.header {
			w.Header()[k] = v
		}
		w.WriteHeader(200)
		frames := []string{p.before}
		for _, c := range p.chunks {
			frames = append(frames, "event: chunk\ndata: "+c+"\n\n")
		}
		if p.end != nil {
			frames = append(frames, "event: tw-end\ndata: "+p.end(d.Hex(), len(p.chunks), "0x"+fmt.Sprintf("%x", sig[:]))+"\n\n")
		}
		frames = append(frames, p.extra)
		for _, f := range frames {
			select {
			case <-time.After(p.delay):
			case <-r.Context().Done():
				return
			}
			if _, err := io.WriteString(w, f); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runFake(t *testing.T, opts StreamOptions, httpc *http.Client, mutate func(*fakeParts)) (*Stream, error) {
	t.Helper()
	srv := fakeMiner(t, mutate)
	c := &Client{Signer: NewSigner(alice(t)), HTTP: httpc}
	s, err := c.Stream(context.Background(), "POST", srv.URL+"/s", []byte(`{}`), bob(t).SS58(), opts)
	if err != nil {
		return nil, err
	}
	readAll(s)
	return s, s.Err()
}

func TestStreamClientRules(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*fakeParts)
		code   string
	}{
		"valid":                 {func(*fakeParts) {}, ""},
		"comment+unknown":       {func(p *fakeParts) { p.before = ": hi\n\nevent: ping\ndata: x\n\nid: 4\n\n" }, ""},
		"no chunks":             {func(p *fakeParts) { p.chunks = nil }, ""},
		"after trailer":         {func(p *fakeParts) { p.extra = "event: chunk\ndata: {}\n\n" }, CodeBadResponseSignature},
		"unknown after trailer": {func(p *fakeParts) { p.extra = "event: other\ndata: x\n\n" }, CodeBadResponseSignature},
		"duplicate trailer": {func(p *fakeParts) {
			inner := p.end
			p.end = func(d string, n int, s string) string {
				return inner(d, n, s) + "\n\nevent: tw-end\ndata: " + inner(d, n, s)
			}
		}, CodeBadResponseSignature},
		"missing trailer": {func(p *fakeParts) { p.end = nil }, CodeBadResponseSignature},
		"count mismatch": {func(p *fakeParts) {
			inner := p.end
			p.end = func(d string, n int, s string) string { return inner(d, n+1, s) }
		}, CodeBadResponseSignature},
		"digest mismatch": {func(p *fakeParts) {
			inner := p.end
			p.end = func(_ string, n int, s string) string { return inner(strings.Repeat("0", 64), n, s) }
		}, CodeBadResponseSignature},
		"bad signature": {func(p *fakeParts) {
			inner := p.end
			p.end = func(d string, n int, _ string) string { return inner(d, n, "0x"+strings.Repeat("00", 64)) }
		}, CodeBadResponseSignature},
		"unsigned trailer": {func(p *fakeParts) {
			p.end = func(d string, n int, _ string) string { return fmt.Sprintf(`{"digest":"%s","count":%d}`, d, n) }
		}, CodeBadResponseSignature},
		"malformed trailer": {func(p *fakeParts) { p.end = func(string, int, string) string { return `{"digest":1}` } }, CodeBadResponseSignature},
		"no version":        {func(p *fakeParts) { p.header.Del(RespHeaderVersion) }, CodeBadResponseSignature},
		"no hotkey":         {func(p *fakeParts) { p.header.Del(RespHeaderHotkey) }, CodeBadResponseSignature},
		"sig at start":      {func(p *fakeParts) { p.header.Set(RespHeaderSignature, "0x00") }, CodeBadResponseSignature},
		"other responder":   {func(p *fakeParts) { p.header.Set(RespHeaderHotkey, alice(t).SS58()) }, CodeBadResponseSignature},
		"encoded":           {func(p *fakeParts) { p.header.Set("Content-Encoding", "gzip") }, CodeInvalidResponse},
		"scalar chunk":      {func(p *fakeParts) { p.chunks[1] = `5` }, CodeInvalidResponse},
		"not json":          {func(p *fakeParts) { p.chunks[1] = `{x` }, CodeInvalidResponse},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := runFake(t, StreamOptions{}, nil, tc.mutate)
			if codeOf(err) != tc.code && !(tc.code == "" && err == nil) {
				t.Fatalf("got %v want %q", err, tc.code)
			}
		})
	}
}

func TestStreamClientDetectsTamperingInTransit(t *testing.T) {
	// The fake signs what it sends; a relay changes it afterwards.
	for name, edit := range map[string]func(string) string{
		"tamper chunk": func(b string) string { return strings.Replace(b, `{"i":1}`, `{"i":7}`, 1) },
		"reorder": func(b string) string {
			return strings.Replace(strings.Replace(b, `{"i":0}`, "#", 1), `{"i":1}`, `{"i":0}`, 1)
		},
		"drop chunk": func(b string) string { return strings.Replace(b, "event: chunk\ndata: {\"i\":1}\n\n", "", 1) },
		"extra chunk": func(b string) string {
			return strings.Replace(b, "event: tw-end", "event: chunk\ndata: {}\n\nevent: tw-end", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := streamMiner(t, bob(t), StreamConfig{}, func() ChunkFunc {
				return list(json.RawMessage(`{"i":0}`), json.RawMessage(`{"i":1}`), json.RawMessage(`{"i":2}`))
			})
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				req, _ := http.NewRequest(r.Method, srv.URL+r.RequestURI, r.Body)
				req.Header = r.Header.Clone()
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				out := edit(string(body))
				if name == "reorder" {
					out = strings.Replace(out, "#", `{"i":1}`, 1)
				}
				for k, v := range resp.Header {
					w.Header()[k] = v
				}
				w.WriteHeader(resp.StatusCode)
				_, _ = io.WriteString(w, out)
			}))
			defer relay.Close()
			c := &Client{Signer: NewSigner(alice(t))}
			s, err := c.Stream(context.Background(), "POST", relay.URL+"/", nil, bob(t).SS58(), StreamOptions{})
			if err != nil {
				t.Fatal(err)
			}
			readAll(s)
			if codeOf(s.Err()) != CodeBadResponseSignature {
				t.Fatal(s.Err())
			}
		})
	}
}

func TestStreamClientLimits(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		t.Parallel()
		_, err := runFake(t, StreamOptions{Limits: StreamLimits{Idle: time.Second}}, nil, func(p *fakeParts) { p.delay = 1500 * time.Millisecond })
		if codeOf(err) != CodeTimeout {
			t.Fatal(err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		t.Parallel()
		_, err := runFake(t, StreamOptions{Timeout: 1200 * time.Millisecond}, nil, func(p *fakeParts) { p.delay = 400 * time.Millisecond })
		if codeOf(err) != CodeTimeout {
			t.Fatal(err)
		}
	})
	t.Run("max_bytes", func(t *testing.T) {
		t.Parallel()
		_, err := runFake(t, StreamOptions{Limits: StreamLimits{MaxBytes: 1024}}, nil, func(p *fakeParts) {
			p.chunks = []string{`{"x":"` + strings.Repeat("a", 2000) + `"}`}
		})
		if codeOf(err) != CodeResponseTooLarge {
			t.Fatal(err)
		}
	})
	t.Run("no read timeout beyond the limits", func(t *testing.T) {
		t.Parallel()
		// An http.Client Timeout shorter than the stream does not cut it.
		_, err := runFake(t, StreamOptions{Timeout: 10 * time.Second}, &http.Client{Timeout: 300 * time.Millisecond},
			func(p *fakeParts) { p.delay = 200 * time.Millisecond })
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the caller's time is not idle", func(t *testing.T) {
		t.Parallel()
		srv := fakeMiner(t, func(*fakeParts) {})
		c := &Client{Signer: NewSigner(alice(t))}
		s, err := c.Stream(context.Background(), "POST", srv.URL+"/", nil, bob(t).SS58(),
			StreamOptions{Limits: StreamLimits{Idle: time.Second}, Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		for s.Next() {
			time.Sleep(1300 * time.Millisecond)
		}
		if !s.Verified() {
			t.Fatal(s.Err())
		}
	})
}

func TestStreamClientNonStreamAnswers(t *testing.T) {
	key := bob(t)
	answer := func(status int, body string, sign bool) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce, _ := strconv.ParseUint(r.Header.Get(HeaderNonce), 10, 64)
			if sign {
				h, _ := SignResponse(key, nonce, r.Header.Get(HeaderHotkey), status, []byte(body))
				for k, v := range h {
					w.Header()[k] = v
				}
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	c := &Client{Signer: NewSigner(alice(t))}
	for _, tc := range []struct {
		status int
		body   string
		sign   bool
		code   string
	}{
		{403, `{"error":{"code":"tw.forbidden_not_validator","message":"x","request_id":null}}`, true, "tw.forbidden_not_validator"},
		{401, `{"error":{"code":"tw.auth_stale","message":"x","request_id":null}}`, false, "tw.auth_stale"},
		{502, `bad gateway`, false, "tw.http_502"},
		{200, `{"a":1}`, true, CodeInvalidResponse},
		{200, `{"a":1}`, false, CodeBadResponseSignature},
	} {
		srv := answer(tc.status, tc.body, tc.sign)
		_, err := c.Stream(context.Background(), "POST", srv.URL+"/", nil, key.SS58(), StreamOptions{})
		if codeOf(err) != tc.code {
			t.Errorf("%d %q: %v", tc.status, tc.body, err)
		}
	}
	redirect := httptest.NewServer(http.RedirectHandler("http://127.0.0.1:1/elsewhere", http.StatusTemporaryRedirect))
	defer redirect.Close()
	if _, err := c.Stream(context.Background(), "POST", redirect.URL, nil, key.SS58(), StreamOptions{}); codeOf(err) != "tw.http_307" {
		t.Fatalf("redirects are not followed: %v", err)
	}
	if _, err := c.Stream(context.Background(), "POST", "http://127.0.0.1:1/", nil, key.SS58(), StreamOptions{}); codeOf(err) != CodeConnectError {
		t.Fatal(err)
	}
	if _, err := c.Stream(context.Background(), "POST", "http://x/", nil, key.SS58(), StreamOptions{Limits: StreamLimits{Idle: time.Hour}}); err == nil {
		t.Fatal("limits out of range")
	}
}

func TestStreamClientErrorPaths(t *testing.T) {
	c := &Client{Signer: NewSigner(alice(t)), MaxResponseBytes: 16}
	if _, err := c.Stream(context.Background(), "POST", "::bad", nil, "x", StreamOptions{}); codeOf(err) != CodeConnectError {
		t.Fatal(err)
	}
	if _, err := c.Stream(context.Background(), "BAD METHOD", "http://127.0.0.2:1/", nil, "x", StreamOptions{}); codeOf(err) != CodeConnectError {
		t.Fatal(err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	if _, err := c.Stream(context.Background(), "POST", slow.URL, nil, "x", StreamOptions{Timeout: 200 * time.Millisecond}); codeOf(err) != CodeTimeout {
		t.Fatal(err)
	}
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = io.WriteString(w, strings.Repeat("x", 100))
	}))
	defer big.Close()
	if _, err := c.Stream(context.Background(), "POST", big.URL, nil, "x", StreamOptions{}); codeOf(err) != CodeResponseTooLarge {
		t.Fatal(err)
	}
	// A body cut mid-stream is a broken stream, not a timeout.
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", StreamContentType)
		w.Header().Set(RespHeaderVersion, "1")
		w.Header().Set(RespHeaderHotkey, bob(t).SS58())
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "event: chunk\ndata: {}\n\n")
	}))
	defer cut.Close()
	s, err := c.Stream(context.Background(), "POST", cut.URL, nil, bob(t).SS58(), StreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	readAll(s)
	if codeOf(s.Err()) != CodeBadResponseSignature {
		t.Fatal(s.Err())
	}
}
