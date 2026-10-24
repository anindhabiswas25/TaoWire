// Command textops-miner is the text-ops example subnet's miner in Go (spec 10,
// 11.1): the same routes and byte-identical answers as the Python miner in
// examples/text-ops-subnet, on btauth.Middleware, with caller policy and
// serve-axon from the TaoWire sidecar (`taowire sidecar`, spec 11.6).
//
//	POST /v1/transform         {"text": s, "op": "upper"|"reverse"|"sha256"} -> {"result": ...}
//	POST /v1/transform/stream  the same, as an SSE stream of {"i": n, "piece": ...} (32 characters each)
//	GET  /healthz, /readyz
//
// Every request runs, in order: the per-IP limit (429, unsigned), btauth/1
// verification, the caller policy from the sidecar's metagraph (403 / 503),
// the per-hotkey limit (429, signed), then the handler; answers after
// authentication are signed with twresp/1. Configuration is the TW_* variables
// of the Python miner that apply (see examples/text-ops-miners/README.md).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/anindhabiswas25/TaoWire/go/btauth"
	"github.com/anindhabiswas25/TaoWire/go/btauth/redisstore"
	"github.com/anindhabiswas25/TaoWire/go/sidecar"
	"github.com/redis/go-redis/v9"
)

// The subnet's contract (examples/text-ops-subnet/text_ops/protocol.py).
const (
	route       = "/v1/transform"
	streamRoute = "/v1/transform/stream"
	pieceChars  = 32
	maxBody     = 64_000
	maxText     = 4096
	timeout     = 5 * time.Second // the Python route's timeout_s
)

type request struct {
	Text string `json:"text"`
	Op   string `json:"op"`
}

// expected is the one correct answer (Python's str.upper, [::-1], sha256 of
// UTF-8). For ASCII, which the validator sends, every language agrees.
func expected(r request) string {
	switch r.Op {
	case "upper":
		return strings.ToUpper(r.Text)
	case "reverse":
		runes := []rune(r.Text)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes)
	}
	sum := sha256.Sum256([]byte(r.Text))
	return hex.EncodeToString(sum[:])
}

// parse validates the body like the Python model: an object with text (a
// string of 1-4096 characters) and op (one of the three); other keys ignored.
func parse(body []byte) (request, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return request{}, errors.New("body is not a JSON object")
	}
	var r request
	if json.Unmarshal(raw["text"], &r.Text) != nil || raw["text"] == nil {
		return request{}, errors.New("text must be a string")
	}
	if json.Unmarshal(raw["op"], &r.Op) != nil || raw["op"] == nil {
		return request{}, errors.New("op must be a string")
	}
	if n := utf8.RuneCountInString(r.Text); n < 1 || n > maxText {
		return request{}, errors.New("text must be 1-4096 characters")
	}
	if r.Op != "upper" && r.Op != "reverse" && r.Op != "sha256" {
		return request{}, errors.New("unknown op")
	}
	return r, nil
}

// ---------------------------------------------------------------- settings

type env struct{ missing []string }

func (e *env) str(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

func (e *env) required(name string) string {
	v := os.Getenv(name)
	if v == "" {
		e.missing = append(e.missing, name)
	}
	return v
}

func (e *env) num(name string, def float64) float64 {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		e.missing = append(e.missing, name+" (not a number)")
	}
	return f
}

func (e *env) flag(name string, def bool) bool {
	switch os.Getenv(name) {
	case "":
		return def
	case "1", "true":
		return true
	case "0", "false":
		return false
	}
	e.missing = append(e.missing, name+" (0 or 1)")
	return def
}

func (e *env) list(name string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(name), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func home(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

func seconds(f float64) time.Duration { return time.Duration(f * float64(time.Second)) }

type config struct {
	netuid                int
	hotkeyFile            string
	bind                  string
	externalIP            string
	externalPort          int
	autoServe             bool
	sidecarURL, tokenFile string
	policy                *sidecar.Policy
	strict                bool
	softAge, maxAge       time.Duration
	ipLimit, hotkeyLimit  btauth.RateLimit
	maxAge2, skew         time.Duration
	retention             time.Duration
	redisURL              string
	stream                btauth.StreamLimits
	streamsPerCaller      int
}

func load() (config, error) {
	e := &env{}
	var c config
	c.netuid = int(e.num("TW_NETUID", -1))
	if c.netuid < 0 {
		e.missing = append(e.missing, "TW_NETUID")
	}
	wallet := e.required("TW_WALLET_NAME")
	c.hotkeyFile = filepath.Join(home(e.str("TW_WALLET_PATH", "~/.bittensor/wallets")), wallet, "hotkeys", e.str("TW_WALLET_HOTKEY", "default"))
	port := int(e.num("TW_BIND_PORT", 8091))
	c.bind = net.JoinHostPort(e.str("TW_BIND_HOST", "0.0.0.0"), strconv.Itoa(port))
	c.externalIP = e.required("TW_EXTERNAL_IP")
	c.externalPort = int(e.num("TW_EXTERNAL_PORT", float64(port)))
	c.autoServe = e.flag("TW_AUTO_SERVE_AXON", true)
	c.sidecarURL = "http://127.0.0.1:" + strconv.Itoa(int(e.num("TW_SIDECAR_PORT", 9910)))
	c.tokenFile = home(e.str("TW_SIDECAR_TOKEN_FILE", filepath.Join(e.str("TW_STATE_DIR", "~/.taowire"), "sidecar.token")))
	policy, err := sidecar.NewPolicy(e.flag("TW_REQUIRE_PERMIT", true), e.num("TW_MIN_CALLER_STAKE_TAO", 0), e.list("TW_ALLOW_HOTKEYS"), e.list("TW_DENY_HOTKEYS"))
	if err != nil {
		e.missing = append(e.missing, err.Error())
	}
	c.policy = policy
	c.strict = e.flag("TW_METAGRAPH_STRICT", false)
	c.softAge, c.maxAge = seconds(e.num("TW_METAGRAPH_SOFT_AGE_S", 0)), seconds(e.num("TW_METAGRAPH_MAX_AGE_S", 0))
	c.ipLimit = btauth.RateLimit{PerS: e.num("TW_RATE_IP_PER_S", 50), Burst: e.num("TW_RATE_IP_BURST", 100)}
	c.hotkeyLimit = btauth.RateLimit{PerS: e.num("TW_RATE_HOTKEY_PER_S", 20), Burst: e.num("TW_RATE_HOTKEY_BURST", 40)}
	c.maxAge2 = seconds(e.num("TW_AUTH_MAX_AGE_S", 10))
	c.skew = seconds(e.num("TW_AUTH_ALLOWED_SKEW_S", 2))
	c.retention = seconds(e.num("TW_NONCE_RETENTION_S", 60))
	c.redisURL = os.Getenv("TW_REDIS_URL")
	c.stream = btauth.StreamLimits{
		MaxDuration: seconds(e.num("TW_STREAM_MAX_S", 60)),
		MaxBytes:    int64(e.num("TW_STREAM_MAX_BYTES", 4<<20)),
		Idle:        seconds(e.num("TW_STREAM_IDLE_S", 10)),
	}
	c.streamsPerCaller = int(e.num("TW_STREAM_MAX_PER_CALLER", 16))
	if len(e.missing) > 0 {
		return c, fmt.Errorf("settings: %s", strings.Join(e.missing, ", "))
	}
	return c, nil
}

// ---------------------------------------------------------------- server

type miner struct {
	log     *slog.Logger
	verify  *btauth.Verifier
	sc      *sidecar.Client
	hotkeys *btauth.TokenBuckets
	stream  btauth.StreamConfig
}

func reply(w http.ResponseWriter, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// admit is the per-hotkey limit (signed 429, inside the middleware) and the
// body checks shared by both routes.
func (m *miner) admit(w http.ResponseWriter, r *http.Request) (request, bool) {
	caller, _ := btauth.CallerFrom(r.Context())
	if wait := m.hotkeys.Take(caller.Hotkey + " " + r.URL.Path); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		btauth.WriteError(w, btauth.NewError(btauth.CodeRateLimited, "per-hotkey limit"))
		return request{}, false
	}
	body, _ := btauth.BodyFrom(r.Context())
	req, err := parse(body)
	if err != nil {
		btauth.WriteError(w, btauth.NewError("tw.invalid_request", err.Error()))
		return request{}, false
	}
	return req, true
}

func (m *miner) transform(w http.ResponseWriter, r *http.Request) {
	if req, ok := m.admit(w, r); ok {
		reply(w, map[string]string{"result": expected(req)})
	}
}

func (m *miner) transformStream(w http.ResponseWriter, r *http.Request) {
	req, ok := m.admit(w, r)
	if !ok {
		return
	}
	runes := []rune(expected(req))
	n := 0
	next := func(context.Context) (any, error) {
		start := n * pieceChars
		if start >= len(runes) {
			return nil, io.EOF
		}
		end := min(start+pieceChars, len(runes))
		piece := map[string]any{"i": n, "piece": string(runes[start:end])}
		n++
		return piece, nil
	}
	btauth.ServeStream(w, r, next, m.stream)
}

func (m *miner) ready(w http.ResponseWriter, _ *http.Request) {
	reasons := []string{}
	if m.sc.Stage() == sidecar.KnownCallersOnly {
		reasons = append(reasons, "metagraph_stale")
	}
	if m.verify.FailingClosed() {
		reasons = append(reasons, "clock_step")
	}
	w.Header().Set("Content-Type", "application/json")
	if len(reasons) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	body, _ := json.Marshal(map[string]any{"ready": len(reasons) == 0, "reasons": reasons, "stage": m.sc.Stage()})
	_, _ = w.Write(body)
}

// bodyReadTimeout bounds reading a request body (slow-drip bodies).
const bodyReadTimeout = 10 * time.Second

// front runs before every route: the pre-auth per-IP limit (spec 8.6.2 layer
// 1; 429, unsigned), then the body read under a deadline. http.Server's
// ReadTimeout is not used for this: it would also cancel the request context
// of a stream running past it.
func front(b *btauth.TokenBuckets, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if wait := b.Take(ip); wait > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(wait))
			btauth.WriteError(w, btauth.NewError(btauth.CodeRateLimited, "per-IP limit"))
			return
		}
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(bodyReadTimeout))
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		_ = rc.SetReadDeadline(time.Time{})
		if err != nil {
			btauth.WriteError(w, btauth.NewError(btauth.CodeMalformed, "body not read in time"))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body)) // Middleware applies the exact cap
		next.ServeHTTP(w, r)
	})
}

func run(log *slog.Logger) error {
	c, err := load()
	if err != nil {
		return err
	}
	key, err := btauth.LoadHotkeyFile(c.hotkeyFile, btauth.Sr25519)
	if err != nil {
		return err
	}
	var store btauth.NonceStore = btauth.NewMemoryStore(c.retention, nil)
	if c.redisURL != "" {
		opts, err := redis.ParseURL(c.redisURL)
		if err != nil {
			return errors.New("TW_REDIS_URL is not a redis:// URL")
		}
		rs, err := redisstore.New(redis.NewClient(opts), c.retention, "")
		if err != nil {
			return err
		}
		store = rs
	}
	v, err := btauth.NewVerifier(btauth.Config{SelfHotkey: key.SS58(), Store: store, MaxAge: c.maxAge2, AllowedSkew: c.skew})
	if err != nil {
		return err
	}
	sc, err := sidecar.New(sidecar.Config{
		NetUID: c.netuid, URL: c.sidecarURL, TokenFile: c.tokenFile, ExpectedHotkey: key.SS58(),
		Policy: c.policy, Strict: c.strict, SoftAge: c.softAge, MaxAge: c.maxAge,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := sc.Start(ctx); err != nil {
		return fmt.Errorf("sidecar at %s: %w", c.sidecarURL, err)
	}
	defer sc.Stop()
	if c.autoServe {
		publish(ctx, log, sc, key.SS58(), c.externalIP, c.externalPort)
	}
	ipBuckets, err := btauth.NewTokenBuckets(c.ipLimit, nil)
	if err != nil {
		return fmt.Errorf("TW_RATE_IP_*: %w", err)
	}
	hotkeyBuckets, err := btauth.NewTokenBuckets(c.hotkeyLimit, nil)
	if err != nil {
		return fmt.Errorf("TW_RATE_HOTKEY_*: %w", err)
	}
	slots, err := btauth.NewStreamSlots(c.streamsPerCaller)
	if err != nil {
		return fmt.Errorf("TW_STREAM_MAX_PER_CALLER: %w", err)
	}
	if _, err := c.stream.Resolved(); err != nil {
		return fmt.Errorf("TW_STREAM_*: %w", err)
	}
	m := &miner{log: log, verify: v, sc: sc, hotkeys: hotkeyBuckets, stream: btauth.StreamConfig{
		Limits: c.stream, FirstChunkTimeout: timeout, Slots: slots, Route: streamRoute,
		OnAbort: func(route, reason string) { log.Warn("stream_aborted", "route", route, "reason", reason) },
	}}
	protect := btauth.Middleware(btauth.MiddlewareConfig{
		Verifier: v, MaxBodyBytes: maxBody, ResponseKey: key, Policy: sc.Policy(), Logger: log,
	})
	mux := http.NewServeMux()
	mux.Handle("POST "+route, protect(http.HandlerFunc(m.transform)))
	mux.Handle("POST "+streamRoute, protect(http.HandlerFunc(m.transformStream)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("GET /readyz", m.ready)
	srv := &http.Server{
		Addr: c.bind, Handler: front(ipBuckets, mux),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("miner_started", "bind", c.bind, "hotkey", key.SS58(), "netuid", c.netuid, "sidecar", c.sidecarURL)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// publish serves the axon through the sidecar unless the snapshot already
// shows it. A refusal is logged; the miner keeps serving.
func publish(ctx context.Context, log *slog.Logger, sc *sidecar.Client, hotkey, ip string, port int) {
	want := net.JoinHostPort(ip, strconv.Itoa(port))
	if s := sc.Snapshot(); s != nil {
		if n, ok := s.ByHotkey(hotkey); ok && n.Axon == want {
			log.Info("axon_in_sync", "external", want)
			return
		}
	}
	hash, err := sc.ServeAxon(ctx, ip, port, "")
	var ce *sidecar.ChainError
	switch {
	case err == nil:
		log.Info("axon_published", "external", want, "block_hash", hash)
	case errors.As(err, &ce):
		log.Warn("serve_axon_rejected", "code", ce.Code, "remediation", ce.Remediation)
	default:
		log.Error("serve_axon_failed", "error", err.Error())
	}
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("startup_refused", "reason", err.Error())
		os.Exit(1)
	}
}
