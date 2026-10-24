package btauth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ChunkFunc yields a stream's chunks one at a time: (chunk, nil), then
// (nil, io.EOF) at the end, or an error. A chunk is a json.RawMessage or
// []byte holding a JSON object or array (sent as it is), or any value
// encoding/json marshals to an object or array. It must return soon after ctx
// is done; ServeStream never calls it again after an error or io.EOF.
type ChunkFunc func(ctx context.Context) (any, error)

// Abort reasons of a stream that ended without tw-end (spec 9.2, D29).
const (
	AbortHandlerError = "handler_error"
	AbortIdleTimeout  = "idle_timeout"
	AbortMaxDuration  = "max_duration"
	AbortMaxBytes     = "max_bytes"
	AbortBadChunk     = "bad_chunk"
	AbortCancelled    = "cancelled"
)

// DefaultFirstChunkTimeout is the default handler timeout for the first
// chunk (TW_HANDLER_TIMEOUT_S, 10 s).
const DefaultFirstChunkTimeout = 10 * time.Second

// StreamConfig configures ServeStream.
type StreamConfig struct {
	// Limits of the stream; zero fields take the defaults (spec 12.1).
	Limits StreamLimits
	// FirstChunkTimeout bounds the wait for the first chunk (default 10 s).
	FirstChunkTimeout time.Duration
	// Slots limits open streams per caller (nil = DefaultStreamSlots, 16).
	Slots *StreamSlots
	// Route names the route in logs and OnAbort.
	Route string
	// OnAbort, when set, is called once for every stream that ended without
	// tw-end (e.g. to count tw_stream_aborted_total{side="miner",reason}).
	OnAbort func(route, reason string)
}

type pulled struct {
	item any
	err  error
}

// ServeStream answers a request that passed Middleware with an SSE stream
// and a signed tw-end trailer (spec 9.2). In order:
//
//  1. a stream slot for the caller (D36): when the caller holds the maximum,
//     the answer is 429 tw.rate_limited with Retry-After, signed, and nothing
//     is streamed;
//  2. the first chunk within FirstChunkTimeout: an error is the signed JSON
//     500 tw.handler_error (a *Error with a status is answered as it is), a
//     stall the signed JSON 504 tw.handler_timeout;
//  3. 200 text/event-stream with the X-TW-Resp-* identity headers, one chunk
//     event per item and the tw-end trailer (digest, count, signature bound
//     to the request's nonce and sender).
//
// After the first byte, a handler error, a chunk that is not a JSON object or
// array, the idle limit (between two chunks), MaxDuration (writes to a
// client that stopped reading included, through a write deadline), MaxBytes
// (TrailerReserve kept for the trailer) or a client disconnect ends the
// stream without tw-end: the client rejects it, and the miner never signs a
// trailer over partial data. Without Middleware's ResponseKey the trailer
// carries no signature.
func ServeStream(w http.ResponseWriter, r *http.Request, next ChunkFunc, cfg StreamConfig) {
	caller, ok := CallerFrom(r.Context())
	st, _ := r.Context().Value(streamKey).(*streamTarget)
	if !ok || st == nil {
		WriteError(w, NewError(CodeInternal, "ServeStream needs a request that passed Middleware"))
		return
	}
	limits, err := cfg.Limits.Resolved()
	if err != nil {
		st.log.Error("btauth_stream_config", "error", err.Error())
		WriteError(w, NewError(CodeInternal, err.Error()))
		return
	}
	slots := cfg.Slots
	if slots == nil {
		slots = DefaultStreamSlots
	}
	release, err := slots.Acquire(caller.Hotkey)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		WriteError(w, err.(*Error))
		return
	}
	defer release()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	want := make(chan struct{})
	got := make(chan pulled)
	go func() {
		for range want {
			item, err := safeNext(ctx, next)
			select {
			case got <- pulled{item, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer close(want)

	firstTimeout := cfg.FirstChunkTimeout
	if firstTimeout <= 0 {
		firstTimeout = DefaultFirstChunkTimeout
	}
	want <- struct{}{}
	first, err := pull(got, firstTimeout)
	switch {
	case errors.Is(err, errIdle):
		st.log.Warn("handler_timeout", "route", cfg.Route, "timeout_s", firstTimeout.Seconds())
		WriteError(w, NewError(CodeHandlerTimeout, "no first chunk in time"))
		return
	case err != nil && !errors.Is(err, io.EOF):
		var e *Error
		if !errors.As(err, &e) || e.Status == 0 {
			st.log.Error("handler_error", "route", cfg.Route, "error", err.Error())
			e = NewError(CodeHandlerError, "")
		}
		WriteError(w, e)
		return
	}

	s := &sseWriter{st: st, cfg: cfg, limits: limits, caller: caller, digest: NewStreamDigest()}
	s.start()
	reason := s.run(ctx, r.Context(), first, err, want, got)
	if reason != "" {
		cancel()
		st.log.Warn("stream_aborted", "route", cfg.Route, "reason", reason,
			"hint", "ended without tw-end; the client rejects the stream")
		if cfg.OnAbort != nil {
			cfg.OnAbort(cfg.Route, reason)
		}
	}
}

var errIdle = errors.New("idle")

// safeNext calls next, turning a panic into an error: next runs on
// ServeStream's own goroutine, where net/http does not recover panics, so an
// unrecovered one would stop the whole process.
func safeNext(ctx context.Context, next ChunkFunc) (item any, err error) {
	defer func() {
		if p := recover(); p != nil {
			item, err = nil, fmt.Errorf("btauth: chunk source panicked: %v", p)
		}
	}()
	return next(ctx)
}

// pull waits for the next pulled chunk at most d.
func pull(got <-chan pulled, d time.Duration) (any, error) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case p := <-got:
		return p.item, p.err
	case <-t.C:
		return nil, errIdle
	}
}

type sseWriter struct {
	st       *streamTarget
	cfg      StreamConfig
	limits   StreamLimits
	caller   *Caller
	digest   *StreamDigest
	rc       *http.ResponseController
	deadline time.Time
	sent     int64
}

// start sends the head: 200, the SSE headers and the identity headers.
func (s *sseWriter) start() {
	w := s.st.w
	if s.st.buf != nil {
		s.st.buf.streamed = true
	}
	h := w.Header()
	h.Set("Content-Type", StreamContentType)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	h.Del("Content-Length")
	if key := s.st.key; key != nil {
		h.Set(RespHeaderVersion, "1")
		h.Set(RespHeaderHotkey, key.SS58())
		if key.Scheme() == Ed25519 {
			h.Set(RespHeaderCrypto, string(Ed25519))
		}
	}
	s.deadline = time.Now().Add(s.limits.MaxDuration)
	s.rc = http.NewResponseController(w)
	// A client that stops reading cannot hold a write past MaxDuration.
	_ = s.rc.SetWriteDeadline(s.deadline)
	w.WriteHeader(http.StatusOK)
	_ = s.rc.Flush()
}

// run streams every chunk and the trailer; it returns the abort reason, or
// "" when tw-end was handed over.
func (s *sseWriter) run(ctx, reqCtx context.Context, item any, err error, want chan<- struct{}, got <-chan pulled) string {
	budget := s.limits.MaxBytes - TrailerReserve
	total := time.NewTimer(time.Until(s.deadline))
	defer total.Stop()
	for !errors.Is(err, io.EOF) {
		data, cerr := EncodeChunk(item)
		if cerr != nil {
			s.st.log.Error("stream_bad_chunk", "route", s.cfg.Route, "reason", cerr.Error())
			return AbortBadChunk
		}
		frame, _ := EncodeEvent(EventChunk, data) // EncodeChunk refused line breaks
		if s.sent+int64(len(frame)) > budget {
			return AbortMaxBytes
		}
		if reason := s.write(frame, reqCtx); reason != "" {
			return reason
		}
		s.digest.Update(data)
		select {
		case want <- struct{}{}:
		case <-ctx.Done():
			return AbortCancelled
		}
		idle := time.NewTimer(s.limits.Idle)
		select {
		case p := <-got:
			item, err = p.item, p.err
		case <-idle.C:
			return AbortIdleTimeout
		case <-total.C:
			idle.Stop()
			return AbortMaxDuration
		case <-reqCtx.Done():
			idle.Stop()
			return AbortCancelled
		}
		idle.Stop()
		if err != nil && !errors.Is(err, io.EOF) {
			s.st.log.Error("handler_error", "route", s.cfg.Route, "error", err.Error())
			return AbortHandlerError
		}
	}
	trailer := Trailer{Digest: s.digest.Hex(), Count: s.digest.Count}
	if key := s.st.key; key != nil {
		sig, serr := key.Sign(ResponsePayload(key.Scheme(), s.caller.Nonce, s.caller.Hotkey, key.SS58(), http.StatusOK, trailer.Digest))
		if serr != nil {
			s.st.log.Error("btauth_response_sign_failed", "error", serr.Error())
			return AbortHandlerError
		}
		trailer.Signature = "0x" + hex.EncodeToString(sig[:])
	}
	frame, _ := EncodeEvent(EventEnd, EncodeTrailer(trailer))
	// Handed over: a disconnect from here on is no abort.
	_ = s.write(frame, reqCtx)
	return ""
}

func (s *sseWriter) write(frame []byte, reqCtx context.Context) string {
	_, err := s.st.w.Write(frame)
	if err == nil {
		// A writer without Flush keeps the bytes buffered; they are not lost.
		if ferr := s.rc.Flush(); !errors.Is(ferr, http.ErrNotSupported) {
			err = ferr
		}
	}
	if err == nil {
		s.sent += int64(len(frame))
		return ""
	}
	if !time.Now().Before(s.deadline) {
		return AbortMaxDuration
	}
	return AbortCancelled
}
