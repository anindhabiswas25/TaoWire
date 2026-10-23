package btauth

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Scheme is a signature scheme name as it appears in the signed payload.
type Scheme string

// The two btauth/1 schemes. An absent X-Bittensor-Crypto header means sr25519.
const (
	Sr25519 Scheme = "sr25519"
	Ed25519 Scheme = "ed25519"
)

// Protocol is the first line of every btauth/1 payload.
const Protocol = "btauth/1"

// BodySHA256 is the lowercase hex sha256 of the raw body bytes.
func BodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func uintString(n uint64) string { return strconv.FormatUint(n, 10) }

// BuildPayload returns the btauth/1 signed payload (spec 4.2): eight lines
// joined by "\n", no trailing newline. target is the request target exactly
// as sent (percent-encoded path plus "?query"); an empty receiver writes the
// unbound marker "-". The method is upper-cased.
func BuildPayload(scheme Scheme, method, target string, body []byte, nonce uint64, sender, receiver string) []byte {
	if receiver == "" {
		receiver = "-"
	}
	lines := []string{
		Protocol, string(scheme), strings.ToUpper(method), target,
		BodySHA256(body), uintString(nonce), sender, receiver,
	}
	return []byte(strings.Join(lines, "\n"))
}
