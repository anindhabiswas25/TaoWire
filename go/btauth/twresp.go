package btauth

import (
	"encoding/hex"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Response header names of twresp/1 (spec 9.1).
const (
	RespHeaderVersion   = "X-Tw-Resp-Version"
	RespHeaderHotkey    = "X-Tw-Resp-Hotkey"
	RespHeaderCrypto    = "X-Tw-Resp-Crypto"
	RespHeaderSignature = "X-Tw-Resp-Signature"
)

// RespProtocol is the first line of every twresp/1 payload.
const RespProtocol = "twresp/1"

var respSignatureRE = regexp.MustCompile(`^0x[0-9a-fA-F]{128}$`)

// ResponsePayload returns the twresp/1 signed payload (spec 9.1). digest is
// the sha256 hex of the raw response body, or a stream digest (spec 9.2).
func ResponsePayload(scheme Scheme, requestNonce uint64, sender, responder string, status int, digest string) []byte {
	lines := []string{
		RespProtocol, string(scheme), strconv.FormatUint(requestNonce, 10),
		sender, responder, strconv.Itoa(status), digest,
	}
	return []byte(strings.Join(lines, "\n"))
}

// SignResponse returns the twresp/1 headers for an answer to the request with
// requestNonce from sender.
func SignResponse(key *Keypair, requestNonce uint64, sender string, status int, body []byte) (http.Header, error) {
	sig, err := key.Sign(ResponsePayload(key.Scheme(), requestNonce, sender, key.SS58(), status, BodySHA256(body)))
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set(RespHeaderVersion, "1")
	h.Set(RespHeaderHotkey, key.SS58())
	if key.Scheme() == Ed25519 {
		h.Set(RespHeaderCrypto, string(Ed25519))
	}
	h.Set(RespHeaderSignature, "0x"+hex.EncodeToString(sig[:]))
	return h, nil
}

// VerifyResponse checks an answer's twresp/1 signature against what this
// validator sent: the miner it queried (expectedResponder), the request's
// nonce and its own hotkey (sender). Any mismatch, missing or repeated
// header, unknown scheme or bad signature is tw.bad_response_signature.
func VerifyResponse(h http.Header, expectedResponder string, requestNonce uint64, sender string, status int, body []byte) (Scheme, error) {
	return VerifyResponseDigest(h, expectedResponder, requestNonce, sender, status, BodySHA256(body))
}

// VerifyResponseDigest is VerifyResponse with the body digest given directly
// (the tw-end event of a stream, spec 9.2).
func VerifyResponseDigest(h http.Header, expectedResponder string, requestNonce uint64, sender string, status int, digest string) (Scheme, error) {
	bad := func(detail string) (Scheme, error) { return "", NewError(CodeBadResponseSignature, detail) }
	m, dup := fields(h, "x-tw-resp-")
	if dup != "" {
		return bad("duplicate " + dup + " header")
	}
	version, ok := one(m, RespHeaderVersion)
	if !ok {
		return bad("response is not signed")
	}
	if version != "1" {
		return bad("unsupported response signature version")
	}
	if responder, _ := one(m, RespHeaderHotkey); responder != expectedResponder {
		return bad("response signed by another hotkey")
	}
	scheme := Sr25519
	if c, ok := one(m, RespHeaderCrypto); ok {
		if c != string(Sr25519) && c != string(Ed25519) {
			return bad("unsupported response signature scheme")
		}
		scheme = Scheme(c)
	}
	sigText, _ := one(m, RespHeaderSignature)
	if !respSignatureRE.MatchString(sigText) {
		return bad("malformed response signature")
	}
	key, err := DecodeSS58(expectedResponder)
	if err != nil {
		return bad("malformed response signature")
	}
	var sig [64]byte
	_, _ = hex.Decode(sig[:], []byte(sigText[2:])) // checked by respSignatureRE
	payload := ResponsePayload(scheme, requestNonce, sender, expectedResponder, status, digest)
	if !verifySignature(scheme, key, payload, sig) {
		return bad("invalid response signature")
	}
	return scheme, nil
}
