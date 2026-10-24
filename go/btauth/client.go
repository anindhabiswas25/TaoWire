package btauth

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
)

// Signer signs outgoing requests with a hotkey (the validator side).
type Signer struct {
	Key   *Keypair    // the signing hotkey
	Nonce NonceSource // strictly increasing nonces (the zero value is ready)
}

// NewSigner returns a Signer for key with its own strictly increasing nonces.
func NewSigner(key *Keypair) *Signer { return &Signer{Key: key} }

// Sign returns the btauth/1 headers for one request and the nonce it used.
// target is the request target exactly as it will be sent (use
// url.URL.RequestURI). Every call takes a fresh nonce: sign again for every
// retry (spec 4.3).
func (s *Signer) Sign(method, target string, body []byte, receiver string) (http.Header, uint64, error) {
	nonce := s.Nonce.Next()
	sig, err := s.Key.Sign(BuildPayload(s.Key.Scheme(), method, target, body, nonce, s.Key.SS58(), receiver))
	if err != nil {
		return nil, 0, err
	}
	h := http.Header{}
	h.Set(HeaderVersion, "1")
	h.Set(HeaderHotkey, s.Key.SS58())
	if receiver != "" {
		h.Set(HeaderReceiver, receiver)
	}
	h.Set(HeaderNonce, uintString(nonce))
	if s.Key.Scheme() == Ed25519 {
		h.Set(HeaderCrypto, string(Ed25519))
	}
	h.Set(HeaderSignature, "0x"+hex.EncodeToString(sig[:]))
	return h, nonce, nil
}

// Client sends signed requests to miners and verifies their twresp/1 answers.
type Client struct {
	Signer *Signer // signs every request
	// HTTP is the client used; nil = http.DefaultClient. Set a Timeout.
	HTTP *http.Client
	// MaxResponseBytes caps the answer body (default 8 MiB).
	MaxResponseBytes int64
}

// Response is a miner's answer. Verified says the twresp/1 signature checked
// out (it is always true when Do returns no error).
type Response struct {
	Status   int         // HTTP status
	Header   http.Header // response headers
	Body     []byte      // raw body bytes (what the signature covers)
	Verified bool        // the twresp/1 signature checked out
	Scheme   Scheme      // scheme of the miner's signature
}

const defaultMaxResponse = 8 << 20

// Do sends body to rawURL signed for the miner hotkey receiver, reads the
// answer and verifies its twresp/1 signature. Errors are *Error with the
// client codes of Appendix A: tw.timeout, tw.connect_error,
// tw.response_too_large, tw.bad_response_signature.
func (c *Client) Do(ctx context.Context, method, rawURL string, body []byte, receiver string) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, NewError(CodeConnectError, err.Error())
	}
	headers, nonce, err := c.Signer.Sign(method, u.RequestURI(), body, receiver)
	if err != nil {
		return nil, NewError(CodeInternal, err.Error())
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, NewError(CodeConnectError, err.Error())
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	httpc := c.HTTP
	if httpc == nil {
		httpc = http.DefaultClient
	}
	resp, err := httpc.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return nil, NewError(CodeTimeout, err.Error())
		}
		return nil, NewError(CodeConnectError, err.Error())
	}
	defer resp.Body.Close()
	limit := c.MaxResponseBytes
	if limit <= 0 {
		limit = defaultMaxResponse
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		if isTimeout(err) {
			return nil, NewError(CodeTimeout, err.Error())
		}
		return nil, NewError(CodeConnectError, err.Error())
	}
	if int64(len(data)) > limit {
		return nil, NewError(CodeResponseTooLarge, "answer exceeds MaxResponseBytes")
	}
	out := &Response{Status: resp.StatusCode, Header: resp.Header, Body: data}
	scheme, err := VerifyResponse(resp.Header, receiver, nonce, c.Signer.Key.SS58(), resp.StatusCode, data)
	if err != nil {
		return out, err
	}
	out.Verified, out.Scheme = true, scheme
	return out, nil
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}
