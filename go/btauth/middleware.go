package btauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

// DefaultMaxBodyBytes is the default body cap (TW_MAX_BODY_BYTES, 1 MiB).
const DefaultMaxBodyBytes = 1 << 20

// MiddlewareConfig configures Middleware.
type MiddlewareConfig struct {
	Verifier *Verifier // verifies every request (required)
	// MaxBodyBytes caps the request body (default 1 MiB); larger is 413.
	MaxBodyBytes int64
	// ResponseKey, when set, signs every answer of an authenticated request
	// with twresp/1 (spec 9.1), errors included. It must be the miner's hotkey
	// (the Verifier's SelfHotkey). The handler's answer is buffered to be
	// signed; a handler streaming with ServeStream bypasses the buffer and
	// signs the stream's tw-end trailer instead (spec 9.2).
	ResponseKey *Keypair
	// Policy, when set, decides after verification whether the caller may use
	// the route (spec 8.5; e.g. sidecar.Client.Policy). A returned *Error is
	// answered with its code and status, signed unless the code is one of
	// UnsignedCodes (Appendix A, as in the Python pipeline); any other error
	// is tw.internal.
	Policy func(r *http.Request, c *Caller) error
	// Logger receives one line per refusal (code and detail, never headers).
	// nil = slog.Default().
	Logger *slog.Logger
}

type ctxKey int

const (
	callerKey ctxKey = iota
	bodyKey
	streamKey
)

// streamTarget lets ServeStream write to the connection directly: the
// middleware's buffered writer (if any) is bypassed, and the middleware
// writes nothing after a stream.
type streamTarget struct {
	w   http.ResponseWriter
	key *Keypair
	buf *bufferedWriter // nil when answers are not signed
	log *slog.Logger
}

// CallerFrom returns the verified caller of a request that passed Middleware.
func CallerFrom(ctx context.Context) (*Caller, bool) {
	c, ok := ctx.Value(callerKey).(*Caller)
	return c, ok
}

// BodyFrom returns the raw body bytes that were verified.
func BodyFrom(ctx context.Context) ([]byte, bool) {
	b, ok := ctx.Value(bodyKey).([]byte)
	return b, ok
}

// Middleware protects a handler with btauth/1 (spec 4.3, 5.3): body cap,
// verify, then the handler, whose answer is signed when ResponseKey is set.
// The request target is r.RequestURI exactly as received, never the decoded
// path; absolute-form targets are refused. Refusals are JSON errors with the
// tw.* code and status of Appendix A, unsigned (the caller is not
// authenticated yet). It panics on a nil Verifier or a ResponseKey that is
// not the Verifier's hotkey.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Verifier == nil {
		panic("btauth: MiddlewareConfig.Verifier is required")
	}
	if cfg.ResponseKey != nil && cfg.ResponseKey.SS58() != cfg.Verifier.SelfHotkey() {
		panic("btauth: ResponseKey must be the Verifier's SelfHotkey")
	}
	limit := cfg.MaxBodyBytes
	if limit <= 0 {
		limit = DefaultMaxBodyBytes
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			refuse := func(e *Error) {
				log.Info("btauth_refused", "code", e.Code, "detail", e.Detail, "target", r.URL.Path)
				writeError(w, e)
			}
			target := r.RequestURI
			if !strings.HasPrefix(target, "/") {
				refuse(malformed("request target must be origin-form"))
				return
			}
			if r.ContentLength > limit {
				refuse(NewError(CodePayloadTooLarge, "Content-Length over the limit"))
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
			if err != nil {
				var tooBig *http.MaxBytesError
				if errors.As(err, &tooBig) {
					refuse(NewError(CodePayloadTooLarge, "body over the limit"))
				} else {
					refuse(malformed("body could not be read"))
				}
				return
			}
			caller, err := cfg.Verifier.Verify(r.Context(), r.Header, body, r.Method, target)
			if err != nil {
				var e *Error
				if !errors.As(err, &e) {
					e = NewError(CodeInternal, err.Error())
				}
				refuse(e)
				return
			}
			if cfg.Policy != nil {
				if err := cfg.Policy(r, caller); err != nil {
					var e *Error
					if !errors.As(err, &e) || e.Status == 0 {
						log.Error("btauth_policy_failed", "error", err.Error())
						e = NewError(CodeInternal, "")
					}
					log.Info("btauth_refused", "code", e.Code, "target", r.URL.Path)
					if cfg.ResponseKey == nil || UnsignedCodes[e.Code] {
						writeError(w, e)
						return
					}
					buf := &bufferedWriter{header: http.Header{}, status: http.StatusOK}
					writeError(buf, e)
					writeSigned(w, buf, cfg.ResponseKey, caller, log)
					return
				}
			}
			st := &streamTarget{w: w, key: cfg.ResponseKey, log: log}
			ctx := context.WithValue(context.WithValue(r.Context(), callerKey, caller), bodyKey, body)
			ctx = context.WithValue(ctx, streamKey, st)
			r = r.WithContext(ctx)
			r.Body = io.NopCloser(bytes.NewReader(body))
			if cfg.ResponseKey == nil {
				next.ServeHTTP(w, r)
				return
			}
			buf := &bufferedWriter{header: http.Header{}, status: http.StatusOK}
			st.buf = buf
			next.ServeHTTP(buf, r)
			if buf.streamed {
				return // ServeStream answered on the connection itself
			}
			writeSigned(w, buf, cfg.ResponseKey, caller, log)
		})
	}
}

// UnsignedCodes are answered unsigned even after authentication (Appendix A
// "Response signed? no"), as in the Python pipeline: e.g. a policy's 503
// tw.metagraph_stale.
var UnsignedCodes = map[string]bool{
	CodeInternal: true, "tw.metagraph_stale": true, CodeReplayStoreUnavailable: true,
}

// writeSigned sends the buffered answer with its twresp/1 headers.
func writeSigned(w http.ResponseWriter, buf *bufferedWriter, key *Keypair, caller *Caller, log *slog.Logger) {
	sig, err := SignResponse(key, caller.Nonce, caller.Hotkey, buf.status, buf.body.Bytes())
	if err != nil {
		log.Error("btauth_response_sign_failed", "error", err.Error())
		writeError(w, NewError(CodeInternal, ""))
		return
	}
	for k, v := range buf.header {
		w.Header()[k] = v
	}
	for k, v := range sig {
		w.Header()[k] = v
	}
	w.Header().Set("Content-Length", strconv.Itoa(buf.body.Len()))
	w.WriteHeader(buf.status)
	_, _ = w.Write(buf.body.Bytes())
}

// WriteError writes the JSON error body of e with its Appendix A status.
// Handlers behind Middleware use it for their own refusals (403, 422, ...).
func WriteError(w http.ResponseWriter, e *Error) { writeError(w, e) }

func writeError(w http.ResponseWriter, e *Error) {
	status := e.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(ErrorBody(e, ""))
}

// bufferedWriter holds the handler's answer so it can be signed.
type bufferedWriter struct {
	header      http.Header
	status      int
	wroteHeader bool
	body        bytes.Buffer
	streamed    bool // ServeStream took over the connection
}

func (b *bufferedWriter) Header() http.Header { return b.header }

func (b *bufferedWriter) WriteHeader(status int) {
	if !b.wroteHeader {
		b.status, b.wroteHeader = status, true
	}
}

func (b *bufferedWriter) Write(p []byte) (int, error) {
	b.WriteHeader(http.StatusOK)
	return b.body.Write(p)
}
