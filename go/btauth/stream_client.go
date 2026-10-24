package btauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultQueryTimeout is the default time budget of one query
// (TW_QUERY_TIMEOUT_S, 12 s, spec 8.8).
const DefaultQueryTimeout = 12 * time.Second

// StreamOptions configures Client.Stream.
type StreamOptions struct {
	// Limits of the stream; zero fields take the defaults (spec 12.1).
	Limits StreamLimits
	// Timeout is the query's time budget (default 12 s). It covers the
	// connection and the head; the stream then ends by the budget left or
	// Limits.MaxDuration, whichever comes first.
	Timeout time.Duration
}

// UnverifiedChunk is one chunk as it arrived. It is NOT verified: only a
// Stream whose Err is nil after the last Next can be trusted.
type UnverifiedChunk struct {
	Index int
	// Data is the chunk's exact data bytes (a JSON object or array; what the
	// digest covers).
	Data json.RawMessage
}

// Stream is one streaming query (spec 9.2). Read it like a bufio.Scanner:
//
//	s, err := client.Stream(ctx, "POST", url, body, minerHotkey, btauth.StreamOptions{})
//	if err != nil { ... }
//	defer s.Close()
//	for s.Next() {
//	    c := s.Chunk() // unverified
//	}
//	if err := s.Err(); err != nil { ... } // nil: the trailer matched and verified
//
// The rules: at most Limits.MaxBytes on the wire (tw.response_too_large);
// the deadline and Limits.Idle between two complete events (tw.timeout) —
// the idle clock restarts when Next is called, so the caller's own time with
// a chunk does not count, and no other read timeout applies to the open
// stream; every chunk a JSON object or array (tw.invalid_response); and
// tw.bad_response_signature for the whole stream when tw-end is missing,
// malformed, repeated or followed by another event, when count or digest do
// not match, when the X-TW-Resp-* headers are missing at stream start, or
// when the trailer signature does not verify for this request (responder,
// nonce and sender bound as in 9.1). Unknown events and comments are ignored.
type Stream struct {
	resp      *http.Response
	cancel    context.CancelFunc
	limits    StreamLimits
	deadline  time.Time
	responder string
	sender    string
	nonce     uint64

	parser   SSEParser
	pending  []SSEEvent
	digest   *StreamDigest
	received int64
	trailer  *Trailer
	eof      bool
	chunk    UnverifiedChunk
	chunks   []json.RawMessage
	err      error
	done     bool
	timedOut atomic.Bool
}

// Stream sends one signed streaming request and returns the open stream once
// its head arrived. An answer that is not a 200 event stream is read whole
// and returned as an error: the miner's tw.* code from a verified error body
// (or one that is unsigned because it was refused before authentication),
// tw.http_<status> otherwise, tw.invalid_response for a verified 200 that is
// not a stream, tw.bad_response_signature for a bad signature.
func (c *Client) Stream(ctx context.Context, method, rawURL string, body []byte, receiver string, opts StreamOptions) (*Stream, error) {
	limits, err := opts.Limits.Resolved()
	if err != nil {
		return nil, err
	}
	budget := opts.Timeout
	if budget <= 0 {
		budget = DefaultQueryTimeout
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, NewError(CodeConnectError, err.Error())
	}
	headers, nonce, err := c.Signer.Sign(method, u.RequestURI(), body, receiver)
	if err != nil {
		return nil, NewError(CodeInternal, err.Error())
	}
	started := time.Now()
	reqCtx, cancel := context.WithCancel(ctx)
	s := &Stream{
		cancel: cancel, limits: limits, responder: receiver,
		sender: c.Signer.Key.SS58(), nonce: nonce, digest: NewStreamDigest(),
	}
	head := time.AfterFunc(budget, func() { s.timedOut.Store(true); cancel() })
	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		head.Stop()
		cancel()
		return nil, NewError(CodeConnectError, err.Error())
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", StreamContentType)
	req.Header.Set("Accept-Encoding", "identity") // an encoded stream is refused
	// The stream is bounded by the deadline and the idle limit only: a client
	// Timeout would also cut the body reads of a long, healthy stream.
	httpc := http.Client{}
	if c.HTTP != nil {
		httpc = *c.HTTP
	}
	httpc.Timeout = 0
	// Never follow a redirect: it would send this signed request elsewhere.
	httpc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := httpc.Do(req)
	if err != nil {
		head.Stop()
		cancel()
		if s.timedOut.Load() || errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return nil, NewError(CodeTimeout, err.Error())
		}
		return nil, NewError(CodeConnectError, err.Error())
	}
	if resp.StatusCode != http.StatusOK || !isEventStream(resp.Header) {
		defer head.Stop()
		defer cancel()
		return nil, c.notAStream(resp, s, receiver, nonce)
	}
	head.Stop()
	if s.timedOut.Load() {
		resp.Body.Close()
		cancel()
		return nil, NewError(CodeTimeout, "time budget exhausted")
	}
	s.resp = resp
	left := budget - time.Since(started)
	if left > limits.MaxDuration {
		left = limits.MaxDuration
	}
	s.deadline = time.Now().Add(left)
	if err := s.checkStart(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func isEventStream(h http.Header) bool {
	media, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && strings.EqualFold(media, StreamContentType)
}

// notAStream reads an ordinary answer (non-200, or 200 without a stream)
// and turns it into the client error of the Python reference.
func (c *Client) notAStream(resp *http.Response, s *Stream, receiver string, nonce uint64) error {
	defer resp.Body.Close()
	limit := c.MaxResponseBytes
	if limit <= 0 {
		limit = defaultMaxResponse
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		if s.timedOut.Load() || isTimeout(err) {
			return NewError(CodeTimeout, err.Error())
		}
		return NewError(CodeInvalidResponse, err.Error())
	}
	if int64(len(data)) > limit {
		return NewError(CodeResponseTooLarge, "answer exceeds MaxResponseBytes")
	}
	signed := len(resp.Header.Values(RespHeaderSignature)) > 0
	if signed || resp.StatusCode == http.StatusOK {
		if _, err := VerifyResponse(resp.Header, receiver, nonce, c.Signer.Key.SS58(), resp.StatusCode, data); err != nil {
			return err
		}
	}
	if resp.StatusCode == http.StatusOK {
		return NewError(CodeInvalidResponse, "answer is not an event stream")
	}
	return answerError(resp.StatusCode, data)
}

// answerError is the miner's tw.* code from an error body, else
// tw.http_<status>.
func answerError(status int, body []byte) *Error {
	var b struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &b) == nil {
		if _, known := catalogue[b.Error.Code]; known {
			return NewError(b.Error.Code, "answered by the miner")
		}
	}
	return &Error{Code: "tw.http_" + itoa(status), Message: "tw.http_" + itoa(status)}
}

func itoa(n int) string { return uintString(uint64(n)) }

func (s *Stream) checkStart() error {
	h := s.resp.Header
	if h.Get("Content-Encoding") != "" {
		return NewError(CodeInvalidResponse, "encoded event stream")
	}
	if len(h.Values(RespHeaderSignature)) > 0 {
		return NewError(CodeBadResponseSignature, "signature header at stream start")
	}
	if h.Get(RespHeaderVersion) != "1" || len(h.Values(RespHeaderHotkey)) == 0 {
		return NewError(CodeBadResponseSignature, "X-TW-Resp-* missing at stream start")
	}
	return nil
}

func (s *Stream) fail(err error) {
	if s.err == nil {
		s.err = err
	}
	s.done = true
	s.Close()
}

// Next reads up to the next chunk. It returns false at the end of the stream
// or on the first error; then Err says which.
func (s *Stream) Next() bool {
	if s.done {
		return false
	}
	// The idle clock starts now: the caller's time with the last chunk is
	// not the miner's.
	idleAt := time.Now().Add(s.limits.Idle)
	for {
		for len(s.pending) > 0 {
			ev := s.pending[0]
			s.pending = s.pending[1:]
			ok, err := s.event(ev)
			if err != nil {
				s.fail(err)
				return false
			}
			if ok {
				return true
			}
			idleAt = time.Now().Add(s.limits.Idle)
		}
		if s.eof {
			if s.trailer == nil {
				s.fail(NewError(CodeBadResponseSignature, "stream ended without tw-end"))
			} else {
				s.done = true
				s.Close()
			}
			return false
		}
		if err := s.read(idleAt); err != nil {
			s.fail(err)
			return false
		}
	}
}

// read reads one piece of the body within the deadline and idleAt.
func (s *Stream) read(idleAt time.Time) error {
	until := s.deadline
	if idleAt.Before(until) {
		until = idleAt
	}
	wait := time.Until(until)
	if wait <= 0 {
		return NewError(CodeTimeout, "stream limit reached")
	}
	t := time.AfterFunc(wait, func() { s.timedOut.Store(true); s.cancel() })
	buf := make([]byte, 32<<10)
	n, err := s.resp.Body.Read(buf)
	t.Stop()
	if n > 0 {
		s.received += int64(n)
		if s.received > s.limits.MaxBytes {
			return NewError(CodeResponseTooLarge, "stream over MaxBytes")
		}
		s.pending = append(s.pending, s.parser.Feed(buf[:n])...)
	}
	switch {
	case err == nil:
		return nil
	case s.timedOut.Load():
		return NewError(CodeTimeout, "stream limit reached")
	case errors.Is(err, io.EOF):
		s.eof = true
		s.pending = append(s.pending, s.parser.Finish()...)
		return nil
	default:
		// Cut mid-stream (e.g. the miner aborted): no valid tw-end.
		return NewError(CodeBadResponseSignature, "stream broken before tw-end")
	}
}

// event handles one event; it reports whether it was a chunk.
func (s *Stream) event(ev SSEEvent) (bool, error) {
	if s.trailer != nil {
		return false, NewError(CodeBadResponseSignature, "event after tw-end")
	}
	switch ev.Event {
	case EventChunk:
		data, err := DecodeChunk(ev.Data)
		if err != nil {
			return false, NewError(CodeInvalidResponse, err.Error())
		}
		s.chunk = UnverifiedChunk{Index: int(s.digest.Count), Data: data}
		s.digest.Update(ev.Data)
		s.chunks = append(s.chunks, data)
		return true, nil
	case EventEnd:
		t, err := ParseTrailer(ev.Data)
		if err != nil {
			return false, NewError(CodeBadResponseSignature, err.Error())
		}
		if t.Count != s.digest.Count {
			return false, NewError(CodeBadResponseSignature, "chunk count mismatch")
		}
		if t.Digest != s.digest.Hex() {
			return false, NewError(CodeBadResponseSignature, "stream digest mismatch")
		}
		if t.Signature == "" {
			return false, NewError(CodeBadResponseSignature, "tw-end is not signed")
		}
		h := s.resp.Header.Clone()
		h.Set(RespHeaderSignature, t.Signature)
		if _, err := VerifyResponseDigest(h, s.responder, s.nonce, s.sender, http.StatusOK, t.Digest); err != nil {
			return false, err
		}
		s.trailer = &t
	}
	return false, nil // unknown events are ignored
}

// Chunk returns the chunk Next just read (unverified).
func (s *Stream) Chunk() UnverifiedChunk { return s.chunk }

// Err returns nil when the stream ended with a tw-end that matched and
// verified, else the *Error that ended it. Before the end it is nil.
func (s *Stream) Err() error { return s.err }

// Verified reports whether the stream ended and its trailer verified.
func (s *Stream) Verified() bool { return s.done && s.err == nil && s.trailer != nil }

// Chunks returns every chunk read so far, in order. Trust them only when
// Verified is true.
func (s *Stream) Chunks() []json.RawMessage { return s.chunks }

// Close releases the connection. Calling it more than once is harmless.
func (s *Stream) Close() error {
	s.cancel()
	if s.resp != nil {
		return s.resp.Body.Close()
	}
	return nil
}
