package btauth

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Request header names (spec 4.1), in Go's canonical form.
const (
	HeaderVersion   = "X-Bittensor-Version"
	HeaderHotkey    = "X-Bittensor-Hotkey"
	HeaderReceiver  = "X-Bittensor-Receiver"
	HeaderNonce     = "X-Bittensor-Nonce"
	HeaderCrypto    = "X-Bittensor-Crypto"
	HeaderSignature = "X-Bittensor-Signature"
)

// Defaults of spec 4.3.
const (
	DefaultMaxAge      = 10 * time.Second
	DefaultAllowedSkew = 2 * time.Second
)

var (
	nonceRE = regexp.MustCompile(`^[0-9]{1,20}$`)
	hexRE   = regexp.MustCompile(`^(?:[0-9a-fA-F]{2})*$`)
)

// Caller is the verified sender of one request.
type Caller struct {
	Hotkey string // canonical prefix-42 SS58 address
	Nonce  uint64 // Unix time in nanoseconds, from X-Bittensor-Nonce
	Scheme Scheme
}

// Config configures a Verifier.
type Config struct {
	// SelfHotkey is this server's hotkey; requests must be addressed to it.
	SelfHotkey string
	// Store remembers accepted nonces; Retention must be >= MaxAge + AllowedSkew.
	Store NonceStore
	// MaxAge and AllowedSkew default to 10 s and 2 s.
	MaxAge, AllowedSkew time.Duration
	// NowNs replaces the wall clock (tests). nil = time.Now().UnixNano().
	NowNs func() uint64
}

// Verifier checks btauth/1 requests addressed to one hotkey.
type Verifier struct {
	self        string
	store       NonceStore
	maxAge      uint64
	allowedSkew uint64
	nowNs       func() uint64
}

// NewVerifier validates cfg. It refuses a store whose retention is shorter
// than the freshness window (spec 11.2 rule 10) and a non-prefix-42 hotkey.
func NewVerifier(cfg Config) (*Verifier, error) {
	if _, err := DecodeSS58(cfg.SelfHotkey); err != nil {
		return nil, errors.New("btauth: SelfHotkey is not a prefix-42 SS58 address")
	}
	if cfg.Store == nil {
		return nil, errors.New("btauth: a NonceStore is required")
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.AllowedSkew == 0 {
		cfg.AllowedSkew = DefaultAllowedSkew
	}
	if cfg.MaxAge < 0 || cfg.AllowedSkew < 0 {
		return nil, errors.New("btauth: MaxAge and AllowedSkew must be positive")
	}
	if cfg.Store.Retention() < cfg.MaxAge+cfg.AllowedSkew {
		return nil, errors.New("btauth: nonce store retention too short")
	}
	now := cfg.NowNs
	if now == nil {
		now = func() uint64 { return uint64(time.Now().UnixNano()) }
	}
	return &Verifier{
		self: cfg.SelfHotkey, store: cfg.Store, nowNs: now,
		maxAge: uint64(cfg.MaxAge), allowedSkew: uint64(cfg.AllowedSkew),
	}, nil
}

// SelfHotkey is the hotkey requests must be addressed to.
func (v *Verifier) SelfHotkey() string { return v.self }

func malformed(detail string) *Error { return NewError(CodeMalformed, detail) }

// fields merges h by lower-case name, so no spelling of a name escapes the
// duplicate check, and reports the first repeated name with prefix.
func fields(h http.Header, prefix string) (map[string][]string, string) {
	m := make(map[string][]string, len(h))
	for name, values := range h {
		key := strings.ToLower(name)
		m[key] = append(m[key], values...)
	}
	for key, values := range m {
		if len(values) > 1 && strings.HasPrefix(key, prefix) {
			return m, key
		}
	}
	return m, ""
}

// one returns the single value of a header and whether it was present.
func one(m map[string][]string, name string) (string, bool) {
	values, ok := m[strings.ToLower(name)]
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// Verify authenticates one request in the order of spec 4.3 and returns the
// caller, or an *Error with its tw.* code: shape (tw.auth_malformed),
// receiver (tw.auth_wrong_receiver), freshness (tw.auth_stale), signature
// (tw.auth_bad_signature; tw.auth_malformed for a wrong-length signature),
// replay (tw.auth_replayed), store outage (tw.replay_store_unavailable).
// body is the raw received bytes, target the request target as received.
// Header names are matched case-insensitively.
func (v *Verifier) Verify(ctx context.Context, h http.Header, body []byte, method, target string) (*Caller, error) {
	// 1. shape
	m, dup := fields(h, "x-bittensor-")
	if dup != "" {
		return nil, malformed("duplicate " + dup + " header")
	}
	if version, _ := one(m, HeaderVersion); version != "1" {
		return nil, malformed("missing or unsupported " + HeaderVersion)
	}
	sender, _ := one(m, HeaderHotkey)
	if sender == "" {
		return nil, malformed("missing " + HeaderHotkey)
	}
	senderKey, err := DecodeSS58(sender)
	if err != nil {
		return nil, malformed(HeaderHotkey + " is not a Bittensor address (SS58 prefix 42)")
	}
	nonceText, ok := one(m, HeaderNonce)
	if !ok || !nonceRE.MatchString(nonceText) {
		return nil, malformed(HeaderNonce + " is not a decimal integer")
	}
	nonce, err := strconv.ParseUint(nonceText, 10, 64)
	overflow := err != nil // 20 digits above 2^64-1: well-formed, far in the future
	scheme := Sr25519
	if c, ok := one(m, HeaderCrypto); ok {
		if c != string(Sr25519) && c != string(Ed25519) {
			return nil, malformed("unsupported " + HeaderCrypto)
		}
		scheme = Scheme(c)
	}
	sigText, ok := one(m, HeaderSignature)
	if !ok {
		return nil, malformed("missing " + HeaderSignature)
	}
	sigText = strings.TrimPrefix(sigText, "0x")
	if !hexRE.MatchString(sigText) {
		return nil, malformed(HeaderSignature + " is not hex")
	}
	sigBytes, _ := hex.DecodeString(sigText) // checked by hexRE

	// 2. receiver (always required)
	receiver, ok := one(m, HeaderReceiver)
	if !ok {
		return nil, NewError(CodeWrongReceiver, "missing "+HeaderReceiver)
	}
	if receiver != v.self {
		return nil, NewError(CodeWrongReceiver, "request was signed for a different receiving hotkey")
	}

	// 3. freshness
	now := v.nowNs()
	switch {
	case overflow || (nonce > now && nonce-now > v.allowedSkew):
		return nil, NewError(CodeStale, "nonce is in the future")
	case nonce <= now && now-nonce > v.maxAge:
		return nil, NewError(CodeStale, "nonce is too old")
	}

	// 4. signature, under the declared scheme only
	if len(sigBytes) != 64 {
		return nil, malformed("signature is not 64 bytes")
	}
	var sig [64]byte
	copy(sig[:], sigBytes)
	payload := BuildPayload(scheme, method, target, body, nonce, sender, receiver)
	if !verifySignature(scheme, senderKey, payload, sig) {
		return nil, NewError(CodeBadSignature, "signature does not verify against the claimed hotkey")
	}

	// 5. replay, only after the signature verified
	fresh, err := v.store.CheckAndStore(ctx, sender, nonce)
	if err != nil {
		return nil, NewError(CodeReplayStoreUnavailable, err.Error())
	}
	if !fresh {
		return nil, NewError(CodeReplayed, "this nonce was already accepted from this hotkey")
	}
	return &Caller{Hotkey: sender, Nonce: nonce, Scheme: scheme}, nil
}
