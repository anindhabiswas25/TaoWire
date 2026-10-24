// Package sidecar is the Go client of the TaoWire sidecar (spec 11.6): a
// Go miner gets its caller policy and its chain writes from the Python
// sidecar (`taowire sidecar`, loopback only, bearer token).
//
//	sc, err := sidecar.New(sidecar.Config{NetUID: 2, TokenFile: path, ExpectedHotkey: key.SS58()})
//	if err := sc.Start(ctx); err != nil { ... } // first metagraph, then a refresh every 60 s
//	protect := btauth.Middleware(btauth.MiddlewareConfig{Verifier: v, ResponseKey: key, Policy: sc.Policy()})
//	hash, err := sc.ServeAxon(ctx, "203.0.113.7", 8091, "")
//
// The snapshot is cached locally and judged with the three staleness stages
// of spec 8.5.1 from the age and tempo the sidecar reports; the caller policy
// is the Python kit's (CallerPolicy, CallerGate). Every answer is parsed
// strictly and fails closed: anything unexpected rejects the answer and never
// admits a caller. The wire shapes are in docs/multi-language.md ("Sidecar
// API").
package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/anindhabiswas25/TaoWire/go/btauth"
)

// Defaults and bounds (spec 11.6, 8.5.1).
const (
	DefaultURL       = "http://127.0.0.1:9910"
	DefaultRefresh   = 60 * time.Second
	DefaultTimeout   = 5 * time.Second
	BlockTime        = 12 * time.Second
	DefaultSoftAge   = 900 * time.Second
	MaxNeurons       = 65536
	MaxKnownCallers  = 65536
	MaxAnswerBytes   = 32 << 20
	MinTokenLength   = 16
	MaxTokenLength   = 1024
	CodeUnauthorized = "tw.sidecar_unauthorized"
	CodeStale        = "tw.metagraph_stale"
)

// Stage is the staleness stage of a snapshot (spec 8.5.1).
type Stage string

// The three stages.
const (
	Fresh            Stage = "fresh"
	Degraded         Stage = "degraded"
	KnownCallersOnly Stage = "known_callers_only"
)

var forbiddenCodes = map[string]bool{
	"tw.forbidden_denied": true, "tw.forbidden_not_registered": true,
	"tw.forbidden_not_validator": true, "tw.forbidden_low_stake": true, CodeStale: true,
}

// Neuron is one neuron of a sidecar snapshot.
type Neuron struct {
	UID             int     // UID on the subnet
	Hotkey          string  // SS58 hotkey
	ValidatorPermit bool    // holds a validator permit
	TotalStakeTAO   float64 // TAO value at spot price (approximate, D2)
	Axon            string  // "host:port", "[v6]:port", or "" when nothing is served
}

// Snapshot is a metagraph snapshot as the sidecar reported it.
type Snapshot struct {
	NetUID   int      // the subnet
	Block    int64    // block the snapshot was read at
	Tempo    int      // subnet tempo in blocks
	AgeS     float64  // age when the sidecar answered
	Neurons  []Neuron // neurons in UID order
	byHotkey map[string]*Neuron
}

// ByHotkey looks a hotkey up.
func (s *Snapshot) ByHotkey(hotkey string) (*Neuron, bool) {
	n, ok := s.byHotkey[hotkey]
	return n, ok
}

// Health is what /v1/health reports.
type Health struct {
	OK            bool     // false without a snapshot or past the max age
	Hotkey        string   // the sidecar's hotkey
	NetUID        int      // its subnet
	Block         *int64   // nil before the first snapshot
	MetagraphAgeS *float64 // nil before the first snapshot
	Stage         Stage    // the sidecar's own stage
}

// Decision is the /v1/caller answer; Code is set when not Allowed.
type Decision struct {
	Allowed bool   // the caller may call
	Code    string // why not (an Appendix A code)
}

// ChainError says the chain refused a write (/v1/serve-axon 409 or 503).
// Code is the bt.ErrorCode value, or "chain_unavailable".
type ChainError struct {
	Code        string // bt.ErrorCode value or "chain_unavailable"
	ErrorName   string // the chain's error name, if any
	Remediation string // the SDK's hint, if any
}

// Error names the chain code.
func (e *ChainError) Error() string { return "sidecar: serve-axon refused by the chain: " + e.Code }

// ---------------------------------------------------------------- token

var printable = regexp.MustCompile(`^[\x21-\x7e]+$`)

// ReadTokenFile reads the bearer token (TW_SIDECAR_TOKEN_FILE): a regular
// file only its owner can read or write (the TLS key rule), 16–1024
// printable ASCII characters after one trailing newline is removed. Errors
// name the file, never its contents. One descriptor is used for the mode
// check and the read.
func ReadTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("sidecar: cannot open token file %s", path)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("sidecar: token file %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("sidecar: token file %s must not be readable or writable by group or others (chmod 600)", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxTokenLength+3))
	if err != nil {
		return "", fmt.Errorf("sidecar: cannot read token file %s", path)
	}
	text := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	return checkToken(text, path)
}

func checkToken(token, where string) (string, error) {
	if len(token) < MinTokenLength || len(token) > MaxTokenLength || !printable.MatchString(token) {
		return "", fmt.Errorf("sidecar: the token from %s must be %d-%d printable ASCII characters", where, MinTokenLength, MaxTokenLength)
	}
	return token, nil
}

// IsLoopback reports whether u points at this host (the token travels in
// clear otherwise).
func IsLoopback(u *url.URL) bool {
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && (ip.To4() != nil || ip.Equal(net.IPv6loopback))
}

// ---------------------------------------------------------------- policy

// Policy decides who may call a route (spec 8.5), in the Python kit's
// order: deny list, allow list (always allowed, even unregistered),
// registered, validator permit, minimum stake. The zero value is NOT the
// strict policy: use NewPolicy.
type Policy struct {
	RequirePermit bool            // validator permit required
	MinStakeTAO   float64         // minimum TotalStakeTAO; 0 disables the check
	Allow         map[string]bool // always allowed, even unregistered
	Deny          map[string]bool // always denied, checked first
}

// NewPolicy returns a policy; it refuses a negative or NaN stake and a
// hotkey in both lists.
func NewPolicy(requirePermit bool, minStakeTAO float64, allow, deny []string) (*Policy, error) {
	if !(minStakeTAO >= 0) || math.IsInf(minStakeTAO, 0) {
		return nil, errors.New("sidecar: minimum stake must be a finite number >= 0")
	}
	p := &Policy{RequirePermit: requirePermit, MinStakeTAO: minStakeTAO, Allow: map[string]bool{}, Deny: map[string]bool{}}
	for _, h := range deny {
		p.Deny[h] = true
	}
	for _, h := range allow {
		if p.Deny[h] {
			return nil, errors.New("sidecar: a hotkey cannot be both allowed and denied")
		}
		p.Allow[h] = true
	}
	return p, nil
}

// StrictPolicy is the default: registered, validator permit, no stake floor.
func StrictPolicy() *Policy {
	p, _ := NewPolicy(true, 0, nil, nil)
	return p
}

// Check returns a 403 *btauth.Error unless hotkey may call; else its neuron
// (nil for an allow-listed unregistered hotkey).
func (p *Policy) Check(hotkey string, s *Snapshot) (*Neuron, error) {
	if p.Deny[hotkey] {
		return nil, btauth.NewError("tw.forbidden_denied", "")
	}
	n, ok := s.ByHotkey(hotkey)
	if p.Allow[hotkey] {
		return n, nil
	}
	switch {
	case !ok:
		return nil, btauth.NewError("tw.forbidden_not_registered", "")
	case p.RequirePermit && !n.ValidatorPermit:
		return nil, btauth.NewError("tw.forbidden_not_validator", "")
	case p.MinStakeTAO > 0 && n.TotalStakeTAO < p.MinStakeTAO:
		return nil, btauth.NewError("tw.forbidden_low_stake", "")
	}
	return n, nil
}

// ---------------------------------------------------------------- strict JSON

func bad(detail string) *btauth.Error {
	return btauth.NewError(btauth.CodeInvalidResponse, "sidecar: "+detail)
}

// decodeStrict decodes a JSON object with no duplicate key at any depth into
// a generic tree (numbers as json.Number).
func decodeStrict(body []byte) (map[string]any, error) {
	if !utf8.Valid(body) || !json.Valid(body) {
		return nil, bad("answer is not JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	v, err := value(dec)
	if err != nil {
		return nil, err
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, bad("answer is not an object")
	}
	return o, nil
}

func value(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, bad("answer is not JSON")
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			o := map[string]any{}
			for dec.More() {
				kt, _ := dec.Token()
				k, _ := kt.(string)
				if _, dup := o[k]; dup {
					return nil, bad("duplicate key")
				}
				v, err := value(dec)
				if err != nil {
					return nil, err
				}
				o[k] = v
			}
			_, _ = dec.Token()
			return o, nil
		}
		var a []any
		for dec.More() {
			v, err := value(dec)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		_, _ = dec.Token()
		return a, nil
	default:
		return tok, nil
	}
}

func asInt(v any, low, high int64) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || i < low || i > high {
		return 0, false
	}
	return i, true
}

func asNonNegative(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	return f, err == nil && f >= 0 && !math.IsInf(f, 0)
}

func asSS58(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	_, err := btauth.DecodeSS58(s)
	return s, err == nil
}

// ParseSnapshot parses a /v1/metagraph answer for netuid; any deviation from
// the documented shape rejects the whole answer (tw.invalid_response).
func ParseSnapshot(body []byte, netuid int) (*Snapshot, error) {
	o, err := decodeStrict(body)
	if err != nil {
		return nil, err
	}
	if n, ok := asInt(o["netuid"], 0, 65535); !ok || int(n) != netuid {
		return nil, bad("snapshot for another netuid")
	}
	block, ok := asInt(o["block"], 0, math.MaxInt64)
	if !ok {
		return nil, bad("block")
	}
	tempo, ok := asInt(o["tempo"], 1, 65535)
	if !ok {
		return nil, bad("tempo")
	}
	age, ok := asNonNegative(o["age_s"])
	if !ok {
		return nil, bad("age_s")
	}
	raw, ok := o["neurons"].([]any) // JSON null is not an array
	if !ok || len(raw) > MaxNeurons {
		return nil, bad("neurons")
	}
	s := &Snapshot{NetUID: netuid, Block: block, Tempo: int(tempo), AgeS: age, byHotkey: map[string]*Neuron{}}
	uids := map[int64]bool{}
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			return nil, bad("neuron")
		}
		uid, ok := asInt(m["uid"], 0, 65535)
		if !ok || uids[uid] {
			return nil, bad("neuron uid")
		}
		hotkey, ok := asSS58(m["hotkey"])
		if _, dup := s.byHotkey[hotkey]; !ok || dup {
			return nil, bad("neuron hotkey")
		}
		permit, ok := m["validator_permit"].(bool)
		if !ok {
			return nil, bad("neuron validator_permit")
		}
		stake, ok := asNonNegative(m["total_stake_tao"])
		if !ok {
			return nil, bad("neuron total_stake_tao")
		}
		axon, isString := m["axon"].(string)
		if a, present := m["axon"]; !present || (a != nil && !isString) {
			return nil, bad("neuron axon")
		}
		uids[uid] = true
		s.Neurons = append(s.Neurons, Neuron{UID: int(uid), Hotkey: hotkey, ValidatorPermit: permit, TotalStakeTAO: stake, Axon: axon})
		s.byHotkey[hotkey] = nil // seen; pointed at below, once the slice no longer moves
	}
	for i := range s.Neurons {
		s.byHotkey[s.Neurons[i].Hotkey] = &s.Neurons[i]
	}
	return s, nil
}

// ParseDecision parses a /v1/caller answer: allowed only for exactly
// {"allowed": true}.
func ParseDecision(body []byte) (Decision, error) {
	o, err := decodeStrict(body)
	if err != nil {
		return Decision{}, err
	}
	if o["allowed"] == true && len(o) == 1 {
		return Decision{Allowed: true}, nil
	}
	if code, ok := o["code"].(string); ok && o["allowed"] == false && len(o) == 2 && forbiddenCodes[code] {
		return Decision{Code: code}, nil
	}
	return Decision{}, bad("caller decision")
}

// ParseHealth parses a /v1/health answer.
func ParseHealth(body []byte) (Health, error) {
	o, err := decodeStrict(body)
	if err != nil {
		return Health{}, err
	}
	var h Health
	var ok bool
	if h.OK, ok = o["ok"].(bool); !ok {
		return h, bad("health ok")
	}
	if h.Hotkey, ok = asSS58(o["hotkey"]); !ok {
		return h, bad("health hotkey")
	}
	n, ok := asInt(o["netuid"], 0, 65535)
	if !ok {
		return h, bad("health netuid")
	}
	h.NetUID = int(n)
	if v, present := o["block"]; !present {
		return h, bad("health block")
	} else if v != nil {
		b, ok := asInt(v, 0, math.MaxInt64)
		if !ok {
			return h, bad("health block")
		}
		h.Block = &b
	}
	if v, present := o["metagraph_age_s"]; !present {
		return h, bad("health age")
	} else if v != nil {
		a, ok := asNonNegative(v)
		if !ok {
			return h, bad("health age")
		}
		h.MetagraphAgeS = &a
	}
	stage, _ := o["stage"].(string)
	switch Stage(stage) {
	case Fresh, Degraded, KnownCallersOnly:
		h.Stage = Stage(stage)
	default:
		return h, bad("health stage")
	}
	return h, nil
}

// ---------------------------------------------------------------- client

// Config configures a Client.
type Config struct {
	NetUID int // the subnet (TW_NETUID)
	// URL of the sidecar (default http://127.0.0.1:9910); it must be loopback
	// unless UnsafeAllowRemote.
	URL string
	// TokenFile (TW_SIDECAR_TOKEN_FILE when empty) or Token (tests).
	TokenFile string
	Token     string // the token itself, instead of TokenFile (tests)
	// ExpectedHotkey: refuse a sidecar whose hotkey is not this one.
	ExpectedHotkey string
	// Policy (default StrictPolicy).
	Policy *Policy
	// Strict (TW_METAGRAPH_STRICT): 503 for everyone past the max age.
	Strict bool
	// SoftAge / MaxAge (TW_METAGRAPH_SOFT_AGE_S / _MAX_AGE_S); zero derives
	// them from the tempo like the Python kit.
	SoftAge, MaxAge time.Duration
	// Refresh of the cached metagraph (default 60 s); Timeout per call (5 s).
	Refresh, Timeout time.Duration
	// UnsafeAllowRemote allows a non-loopback URL (the token crosses a
	// network in clear).
	UnsafeAllowRemote bool
	// HTTP is the client used (default: a new one, no redirects).
	HTTP *http.Client
	// Now replaces the monotonic clock (tests).
	Now func() time.Time
}

type held struct {
	snap *Snapshot
	at   time.Time // when the sidecar read the snapshot (local clock)
}

// Client is the sidecar client: cached metagraph, caller policy,
// serve-axon. Safe for concurrent use.
type Client struct {
	cfg   Config
	base  *url.URL
	token string
	http  *http.Client

	mu     sync.Mutex
	held   *held
	known  map[string]time.Time
	order  []string
	cancel context.CancelFunc
	done   chan struct{}
}

// New returns a client; it refuses a remote URL (without UnsafeAllowRemote),
// a bad token or bad settings.
func New(cfg Config) (*Client, error) {
	if cfg.NetUID < 0 || cfg.NetUID > 65535 {
		return nil, errors.New("sidecar: netuid must be 0-65535")
	}
	if cfg.URL == "" {
		cfg.URL = DefaultURL
	}
	base, err := url.Parse(cfg.URL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, errors.New("sidecar: the URL must be http(s)://host:port")
	}
	if !IsLoopback(base) && !cfg.UnsafeAllowRemote {
		return nil, errors.New("sidecar: the URL must be on loopback (127.0.0.0/8, ::1, localhost)")
	}
	var token string
	switch {
	case cfg.Token != "":
		token, err = checkToken(cfg.Token, "Config.Token")
	default:
		path := cfg.TokenFile
		if path == "" {
			path = os.Getenv("TW_SIDECAR_TOKEN_FILE")
		}
		if path == "" {
			return nil, errors.New("sidecar: set TokenFile (or TW_SIDECAR_TOKEN_FILE) or Token")
		}
		token, err = ReadTokenFile(path)
	}
	if err != nil {
		return nil, err
	}
	cfg.Token = ""
	if cfg.Policy == nil {
		cfg.Policy = StrictPolicy()
	}
	if cfg.SoftAge > 0 && cfg.MaxAge > 0 && cfg.SoftAge >= cfg.MaxAge {
		return nil, errors.New("sidecar: SoftAge must be below MaxAge")
	}
	if cfg.Refresh <= 0 {
		cfg.Refresh = DefaultRefresh
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	httpc := &http.Client{}
	if cfg.HTTP != nil {
		copied := *cfg.HTTP
		httpc = &copied
	}
	httpc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{cfg: cfg, base: base, token: token, http: httpc, known: map[string]time.Time{}}, nil
}

// String never shows the token.
func (c *Client) String() string {
	return fmt.Sprintf("sidecar.Client(%s, netuid %d)", c.base.Host, c.cfg.NetUID)
}

// GoString never shows the token.
func (c *Client) GoString() string { return c.String() }

func (c *Client) call(ctx context.Context, method, path string, body any) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	// path is already escaped (PathEscape for the hotkey segment).
	req, err := http.NewRequestWithContext(ctx, method, c.base.Scheme+"://"+c.base.Host+path, reader)
	if err != nil {
		return 0, nil, btauth.NewError(btauth.CodeConnectError, "sidecar: bad request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, btauth.NewError(btauth.CodeTimeout, "sidecar did not answer in time")
		}
		return 0, nil, btauth.NewError(btauth.CodeConnectError, "sidecar unreachable")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxAnswerBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, btauth.NewError(btauth.CodeTimeout, "sidecar did not answer in time")
		}
		return 0, nil, bad("answer could not be read")
	}
	if len(data) > MaxAnswerBytes {
		return 0, nil, btauth.NewError(btauth.CodeResponseTooLarge, "sidecar answer over the limit")
	}
	return resp.StatusCode, data, nil
}

// errorOf is the sidecar's own tw.* code (Appendix A body with a matching
// status), else tw.invalid_response.
func errorOf(status int, body []byte) error {
	if o, err := decodeStrict(body); err == nil {
		if e, ok := o["error"].(map[string]any); ok {
			if code, ok := e["code"].(string); ok && btauth.StatusOf(code) == status {
				if btauth.NewError(code, "").Code == code {
					return &btauth.Error{Code: code, Status: status, Message: code, Detail: "answered by the sidecar"}
				}
			}
		}
	}
	return bad(fmt.Sprintf("answered %d", status))
}

// Health calls GET /v1/health.
func (c *Client) Health(ctx context.Context) (Health, error) {
	status, body, err := c.call(ctx, "GET", "/v1/health", nil)
	if err != nil {
		return Health{}, err
	}
	if status != http.StatusOK {
		return Health{}, errorOf(status, body)
	}
	return ParseHealth(body)
}

// Metagraph calls GET /v1/metagraph and stores the snapshot for Check. Only
// a newer snapshot (a higher block, or read more than Timeout + 1 s later)
// replaces the held one and clears the known callers: a sidecar repeating its
// own stale snapshot changes nothing.
func (c *Client) Metagraph(ctx context.Context) (*Snapshot, error) {
	status, body, err := c.call(ctx, "GET", "/v1/metagraph?netuid="+strconv.Itoa(c.cfg.NetUID), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errorOf(status, body)
	}
	s, err := ParseSnapshot(body, c.cfg.NetUID)
	if err != nil {
		return nil, err
	}
	at := c.cfg.Now().Add(-time.Duration(s.AgeS * float64(time.Second)))
	c.mu.Lock()
	defer c.mu.Unlock()
	// The block decides; the derived time only when the chain stalls (the
	// answer's own delay, up to the timeout, must not make it look newer).
	if c.held == nil || s.Block > c.held.snap.Block || at.After(c.held.at.Add(c.cfg.Timeout+time.Second)) {
		c.held = &held{snap: s, at: at}
		c.known, c.order = map[string]time.Time{}, nil
	}
	return s, nil
}

// Caller calls GET /v1/caller/{hotkey}: the sidecar's own decision.
func (c *Client) Caller(ctx context.Context, hotkey string) (Decision, error) {
	path := "/v1/caller/" + url.PathEscape(hotkey) + "?netuid=" + strconv.Itoa(c.cfg.NetUID)
	status, body, err := c.call(ctx, "GET", path, nil)
	if err != nil {
		return Decision{}, err
	}
	if status != http.StatusOK {
		return Decision{}, errorOf(status, body)
	}
	return ParseDecision(body)
}

var blockHashRE = regexp.MustCompile(`^0x[0-9a-f]{64}$`)

// ServeAxon calls POST /v1/serve-axon: publish ip:port (and a TLS key,
// ADR-0011, "" for none) for the sidecar's hotkey. Sent once: a chain write
// is never resent blindly. A chain refusal is a *ChainError.
func (c *Client) ServeAxon(ctx context.Context, ip string, port int, tlsCertHex string) (string, error) {
	req := map[string]any{"netuid": c.cfg.NetUID, "ip": ip, "port": port, "tls_cert_hex": nil}
	if tlsCertHex != "" {
		req["tls_cert_hex"] = tlsCertHex
	}
	status, body, err := c.call(ctx, "POST", "/v1/serve-axon", req)
	if err != nil {
		return "", err
	}
	if status == http.StatusOK {
		o, err := decodeStrict(body)
		hash, _ := o["block_hash"].(string)
		if err != nil || o["ok"] != true || !blockHashRE.MatchString(hash) {
			return "", bad("serve-axon answer")
		}
		return hash, nil
	}
	if status == http.StatusConflict || status == http.StatusServiceUnavailable {
		if o, err := decodeStrict(body); err == nil {
			if code, ok := o["code"].(string); ok && o["ok"] == false {
				name, _ := o["error_name"].(string)
				hint, _ := o["remediation"].(string)
				return "", &ChainError{Code: code, ErrorName: name, Remediation: hint}
			}
		}
	}
	return "", errorOf(status, body)
}

// Start checks the sidecar (its netuid, and its hotkey when ExpectedHotkey
// is set), fetches the first snapshot (an error if it cannot), then
// refreshes every Refresh (±10%) until Stop.
func (c *Client) Start(ctx context.Context) error {
	h, err := c.Health(ctx)
	if err != nil {
		return err
	}
	if h.NetUID != c.cfg.NetUID {
		return fmt.Errorf("sidecar: it follows netuid %d, not %d", h.NetUID, c.cfg.NetUID)
	}
	if c.cfg.ExpectedHotkey != "" && h.Hotkey != c.cfg.ExpectedHotkey {
		return errors.New("sidecar: its hotkey is not this miner's hotkey")
	}
	if _, err := c.Metagraph(ctx); err != nil {
		return err
	}
	c.Stop() // a second Start replaces the running refresh, never adds one
	loop, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.cancel, c.done = cancel, make(chan struct{})
	done := c.done
	c.mu.Unlock()
	go func() {
		defer close(done)
		for {
			wait := time.Duration(float64(c.cfg.Refresh) * (0.9 + 0.2*rand.Float64()))
			select {
			case <-loop.Done():
				return
			case <-time.After(wait):
				_, _ = c.Metagraph(loop) // a failure keeps the old snapshot; it keeps aging
			}
		}
	}()
	return nil
}

// Stop ends the background refresh. Safe to call more than once.
func (c *Client) Stop() {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// Snapshot returns the cached snapshot, or nil.
func (c *Client) Snapshot() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held == nil {
		return nil
	}
	return c.held.snap
}

// Age returns the cached snapshot's age now, and false without one.
func (c *Client) Age() (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ageLocked()
}

func (c *Client) ageLocked() (time.Duration, bool) {
	if c.held == nil {
		return 0, false
	}
	return c.cfg.Now().Sub(c.held.at), true
}

// Thresholds returns the soft and max age in force (8.5.1; from the
// snapshot's tempo, 360 before one).
func (c *Client) Thresholds() (soft, max time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.thresholdsLocked()
}

func (c *Client) thresholdsLocked() (soft, max time.Duration) {
	tempo := 360
	if c.held != nil {
		tempo = c.held.snap.Tempo
	}
	max = c.cfg.MaxAge
	if max <= 0 {
		max = 2 * time.Duration(tempo) * BlockTime
	}
	soft = c.cfg.SoftAge
	if soft <= 0 {
		soft = min(DefaultSoftAge, max/2)
	}
	return soft, max
}

// Stage returns the current stage; no snapshot is KnownCallersOnly (fail
// closed).
func (c *Client) Stage() Stage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stageLocked()
}

func (c *Client) stageLocked() Stage {
	age, ok := c.ageLocked()
	soft, max := c.thresholdsLocked()
	switch {
	case !ok || age > max:
		return KnownCallersOnly
	case age >= soft:
		return Degraded
	}
	return Fresh
}

// Check admits hotkey for scope (e.g. the route) or returns a *btauth.Error:
// 403 from the policy, 503 tw.metagraph_stale past the max age for a caller
// not known on this scope (or for everyone with Strict). The Python
// CallerGate.admit.
func (c *Client) Check(hotkey, scope string) (*Neuron, error) {
	if c.cfg.Policy.Deny[hotkey] {
		return nil, btauth.NewError("tw.forbidden_denied", "")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := scope + "\n" + hotkey
	if c.held == nil || c.stageLocked() == KnownCallersOnly {
		if _, known := c.known[key]; c.cfg.Strict || !known {
			return nil, btauth.NewError(CodeStale, "")
		}
		if c.held == nil {
			return nil, nil
		}
		n, _ := c.held.snap.ByHotkey(hotkey)
		return n, nil
	}
	n, err := c.cfg.Policy.Check(hotkey, c.held.snap)
	if err != nil {
		return nil, err
	}
	if _, seen := c.known[key]; !seen {
		c.order = append(c.order, key)
		if len(c.order) > MaxKnownCallers {
			delete(c.known, c.order[0])
			c.order = c.order[1:]
		}
	}
	c.known[key] = c.cfg.Now()
	return n, nil
}

// PolicyScope is the known-callers scope of the Policy hook: one policy
// guards every route, so one scope. Never the raw request path: a caller
// could invent paths to fill the bounded known-callers set and evict the
// other validators during a chain outage.
const PolicyScope = "middleware"

// Policy returns the MiddlewareConfig.Policy hook.
func (c *Client) Policy() func(*http.Request, *btauth.Caller) error {
	return func(_ *http.Request, caller *btauth.Caller) error {
		_, err := c.Check(caller.Hotkey, PolicyScope)
		return err
	}
}
