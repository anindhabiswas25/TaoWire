package btauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Streaming responses over SSE with a signed trailer (spec 9.2, D29, D35):
// what the miner (ServeStream) and the client (Client.Stream) share. The same
// rules as the Python reference (taowire.extensions.streaming):
//
//	event: chunk
//	data: {"token": "Hel"}
//
//	event: tw-end
//	data: {"digest": "<sha256 hex>", "count": 1, "signature": "0x..."}
//
// digest is sha256 over the concatenation of every chunk's exact data bytes;
// the trailer signature is the twresp/1 payload with status 200 and the
// digest as the body hash. Chunks are JSON objects or arrays: they are
// self-delimiting, so a relay cannot move chunk boundaries under a valid
// signature.

// Stream constants (spec 9.2).
const (
	StreamContentType = "text/event-stream"
	EventChunk        = "chunk"
	EventEnd          = "tw-end"
	// MaxChunkDepth is the deepest JSON nesting accepted in a chunk, on both
	// sides. Python refuses deep chunks only through its recursion limit
	// (about 1000); Go, Rust and TypeScript use 128, the stricter value.
	MaxChunkDepth = 128
)

// Ranges of the stream limits (spec 12.1).
const (
	MinStreamDuration = time.Second
	MaxStreamDuration = 600 * time.Second
	MinStreamBytes    = 1 << 10
	MaxStreamBytes    = 64 << 20
	MinStreamIdle     = time.Second
	MaxStreamIdle     = 120 * time.Second
)

// StreamLimits are the per-stream limits (spec 9.2); both the miner and the
// client enforce them. A zero field takes its default (TW_STREAM_MAX_S 60 s,
// TW_STREAM_MAX_BYTES 4 MiB, TW_STREAM_IDLE_S 10 s).
type StreamLimits struct {
	MaxDuration time.Duration // the whole stream
	MaxBytes    int64         // bytes on the wire
	Idle        time.Duration // the longest gap between two events
}

// DefaultStreamLimits returns the spec 12.1 defaults.
func DefaultStreamLimits() StreamLimits {
	return StreamLimits{MaxDuration: 60 * time.Second, MaxBytes: 4 << 20, Idle: 10 * time.Second}
}

// Resolved fills zero fields with the defaults and checks the ranges of
// spec 12.1.
func (l StreamLimits) Resolved() (StreamLimits, error) {
	d := DefaultStreamLimits()
	if l.MaxDuration == 0 {
		l.MaxDuration = d.MaxDuration
	}
	if l.MaxBytes == 0 {
		l.MaxBytes = d.MaxBytes
	}
	if l.Idle == 0 {
		l.Idle = d.Idle
	}
	switch {
	case l.MaxDuration < MinStreamDuration || l.MaxDuration > MaxStreamDuration:
		return l, errors.New("btauth: stream MaxDuration must be between 1 s and 600 s")
	case l.MaxBytes < MinStreamBytes || l.MaxBytes > MaxStreamBytes:
		return l, errors.New("btauth: stream MaxBytes must be between 1 KiB and 64 MiB")
	case l.Idle < MinStreamIdle || l.Idle > MaxStreamIdle:
		return l, errors.New("btauth: stream Idle must be between 1 s and 120 s")
	}
	return l, nil
}

// ChunkError says a chunk is not a JSON object or array (or not JSON at all).
type ChunkError struct {
	Reason string // what is wrong with the chunk
}

// Error describes the chunk problem.
func (e *ChunkError) Error() string { return "btauth: chunk: " + e.Reason }

// TrailerError says the tw-end data is not a well-formed trailer.
type TrailerError struct {
	Reason string // what is wrong with the trailer
}

// Error describes the trailer problem.
func (e *TrailerError) Error() string { return "btauth: tw-end: " + e.Reason }

func firstNonSpace(data []byte, set string) byte {
	for _, b := range data {
		if !bytes.ContainsRune([]byte(set), rune(b)) {
			return b
		}
	}
	return 0
}

// jsonDepth returns the deepest nesting of valid JSON text (strings skipped).
func jsonDepth(data []byte) int {
	depth, deepest := 0, 0
	inString, escaped := false, false
	for _, b := range data {
		switch {
		case inString:
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				inString = false
			}
		case b == '"':
			inString = true
		case b == '{' || b == '[':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case b == '}' || b == ']':
			depth--
		}
	}
	return deepest
}

// DecodeChunk checks one chunk's data (client side): UTF-8, valid JSON, an
// object or array, no deeper than MaxChunkDepth. It returns a copy of the raw
// JSON; numbers are never decoded. Errors are *ChunkError.
func DecodeChunk(data []byte) (json.RawMessage, error) {
	if !utf8.Valid(data) || !json.Valid(data) {
		return nil, &ChunkError{"chunk is not valid JSON"}
	}
	if b := firstNonSpace(data, " \t\r\n"); b != '{' && b != '[' {
		return nil, &ChunkError{"chunk must be a JSON object or array"}
	}
	if jsonDepth(data) > MaxChunkDepth {
		return nil, &ChunkError{"chunk is nested too deeply"}
	}
	return append(json.RawMessage(nil), data...), nil
}

// EncodeChunk returns the data bytes of one chunk (miner side). A []byte or
// json.RawMessage must hold a JSON object or array and is sent as it is; any
// other value is marshalled with encoding/json and must give an object or
// array. Line breaks in the bytes are refused. Errors are *ChunkError.
func EncodeChunk(item any) ([]byte, error) {
	var data []byte
	switch v := item.(type) {
	case json.RawMessage:
		data = v
	case []byte:
		data = v
	default:
		out, err := json.Marshal(item)
		if err != nil {
			return nil, &ChunkError{"chunk is not JSON-serialisable"}
		}
		data = out
	}
	if bytes.ContainsAny(data, "\r\n") {
		return nil, &ChunkError{"chunk contains a line break"}
	}
	if b := firstNonSpace(data, " \t"); b != '{' && b != '[' {
		return nil, &ChunkError{"chunk must be a JSON object or array"}
	}
	if _, err := DecodeChunk(data); err != nil {
		return nil, err
	}
	return data, nil
}

// StreamDigest is the running sha256 over the chunks' data bytes, and their
// count.
type StreamDigest struct {
	h     hash.Hash
	Count uint64 // chunks added so far
}

// NewStreamDigest returns an empty digest.
func NewStreamDigest() *StreamDigest { return &StreamDigest{h: sha256.New()} }

// Update adds one chunk's exact data bytes.
func (d *StreamDigest) Update(data []byte) {
	d.h.Write(data)
	d.Count++
}

// Hex returns the digest so far, lowercase hex (the running hash continues).
func (d *StreamDigest) Hex() string { return hex.EncodeToString(d.h.Sum(nil)) }

// Trailer is the tw-end event's data. Signature is "0x" + hex, or "" when the
// miner does not sign responses.
type Trailer struct {
	Digest    string // sha256 of the chunks, lowercase hex
	Count     uint64 // number of chunks
	Signature string // "0x" + hex, or "" when not signed
}

// EncodeTrailer returns the tw-end data bytes (compact JSON, the Python
// reference's key order).
func EncodeTrailer(t Trailer) []byte {
	var b bytes.Buffer
	b.WriteString(`{"digest":`)
	writeJSONString(&b, t.Digest)
	b.WriteString(`,"count":`)
	b.WriteString(strconv.FormatUint(t.Count, 10))
	if t.Signature != "" {
		b.WriteString(`,"signature":`)
		writeJSONString(&b, t.Signature)
	}
	b.WriteByte('}')
	return b.Bytes()
}

func writeJSONString(b *bytes.Buffer, s string) {
	out, _ := json.Marshal(s) // a string always marshals
	b.Write(out)
}

var (
	hexDigestRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	countLiteral = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)
)

// hasLoneSurrogateEscape reports whether valid JSON text holds a \uXXXX escape
// of a UTF-16 surrogate that is not half of a high+low pair. encoding/json
// turns such an escape into U+FFFD instead of refusing it, so the bytes are
// checked first. In valid JSON every backslash starts an escape in a string.
func hasLoneSurrogateEscape(data []byte) bool {
	unit := func(i int) (rune, bool) {
		if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
			return 0, false
		}
		v, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		return rune(v), err == nil
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		r, ok := unit(i)
		switch {
		case !ok:
			i++ // a one-character escape: skip the escaped character
		case utf16.IsSurrogate(r) && r < 0xDC00:
			low, ok := unit(i + 6)
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return true
			}
			i += 11
		case utf16.IsSurrogate(r):
			return true // a low surrogate with no high one before it
		default:
			i += 5
		}
	}
	return false
}

// ParseTrailer parses tw-end data strictly: a JSON object with exactly digest
// (64 lowercase hex), count (an integer literal >= 0 that fits a uint64) and
// optionally signature (a string), no other key, no key twice, and no lone
// UTF-16 surrogate escape in any string (spec 9.2, D43). Errors are
// *TrailerError.
func ParseTrailer(data []byte) (Trailer, error) {
	var t Trailer
	bad := func(reason string) (Trailer, error) { return Trailer{}, &TrailerError{reason} }
	if !utf8.Valid(data) || !json.Valid(data) {
		return bad("tw-end data is not valid JSON")
	}
	if hasLoneSurrogateEscape(data) {
		return bad("tw-end holds a lone surrogate escape")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if tok, _ := dec.Token(); tok != json.Delim('{') {
		return bad("tw-end data must be a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, _ := dec.Token()
		key, _ := tok.(string)
		if seen[key] {
			return bad("duplicate key in tw-end")
		}
		seen[key] = true
		value, _ := dec.Token()
		switch key {
		case "digest":
			s, ok := value.(string)
			if !ok || !hexDigestRE.MatchString(s) {
				return bad("tw-end digest must be 64 lowercase hex characters")
			}
			t.Digest = s
		case "count":
			n, ok := value.(json.Number)
			if !ok || !countLiteral.MatchString(string(n)) {
				return bad("tw-end count must be an integer >= 0")
			}
			c, err := strconv.ParseUint(string(n), 10, 64)
			if err != nil {
				return bad("tw-end count is out of range")
			}
			t.Count = c
		case "signature":
			s, ok := value.(string)
			if !ok {
				return bad("tw-end signature must be a string")
			}
			t.Signature = s
		default:
			return bad("tw-end needs digest and count, and nothing but signature")
		}
	}
	if !seen["digest"] || !seen["count"] {
		return bad("tw-end needs digest and count, and nothing but signature")
	}
	return t, nil
}

// EncodeEvent returns one SSE frame: "event: <event>", one "data:" line, a
// blank line. Line breaks in either are refused.
func EncodeEvent(event string, data []byte) ([]byte, error) {
	if bytes.ContainsAny([]byte(event), "\r\n") || bytes.ContainsAny(data, "\r\n") {
		return nil, errors.New("btauth: SSE event names and data must not contain line breaks")
	}
	out := make([]byte, 0, len(event)+len(data)+17)
	out = append(out, "event: "...)
	out = append(out, event...)
	out = append(out, "\ndata: "...)
	out = append(out, data...)
	return append(out, "\n\n"...), nil
}

// TrailerReserve is the number of bytes the miner keeps free under MaxBytes
// for the tw-end frame: the largest possible one (a 20-digit count, a 64-byte
// signature), so a stream the miner finishes always fits a client using the
// same limit.
var TrailerReserve = func() int64 {
	frame, _ := EncodeEvent(EventEnd, EncodeTrailer(Trailer{
		Digest: string(bytes.Repeat([]byte("0"), 64)), Count: ^uint64(0),
		Signature: "0x" + string(bytes.Repeat([]byte("0"), 128)),
	}))
	return int64(len(frame))
}()

// SSEEvent is one dispatched event: its type and its data bytes (lines
// joined by LF).
type SSEEvent struct {
	Event string // the event type ("message" when none was given)
	Data  []byte // the data bytes
}

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// SSEParser is an incremental SSE parser over raw bytes (WHATWG "event
// stream" rules), the same as the Python reference's SSEParser. Lines end
// with CRLF, LF or CR; ":" lines are comments; "field[: value]" with one
// leading space removed; a line without a colon is a field with an empty
// value; data lines are joined with LF; event sets the type (empty or absent
// means "message"); id, retry and unknown fields are ignored; a blank line
// dispatches an event that has data. A UTF-8 BOM at the very start is
// skipped. Feed never fails; Finish drops an unfinished event. Each byte is
// scanned once. The zero value is ready to use.
type SSEParser struct {
	buf     []byte
	scanned int
	started bool
	event   string
	data    [][]byte
	hasData bool
}

// Feed adds bytes and returns the events they complete, in order.
func (p *SSEParser) Feed(chunk []byte) []SSEEvent {
	p.buf = append(p.buf, chunk...)
	if !p.started {
		if len(p.buf) < len(utf8BOM) && bytes.HasPrefix(utf8BOM, p.buf) {
			return nil
		}
		p.buf = bytes.TrimPrefix(p.buf, utf8BOM)
		p.started = true
	}
	return p.lines(false)
}

// Finish ends the stream: a final CR ends its line; an unfinished event is
// dropped. The parser is reset.
func (p *SSEParser) Finish() []SSEEvent {
	events := p.lines(true)
	*p = SSEParser{}
	return events
}

func (p *SSEParser) lines(final bool) []SSEEvent {
	var events []SSEEvent
	b := p.buf
	start, i := 0, p.scanned
	for i < len(b) {
		j := bytes.IndexAny(b[i:], "\r\n")
		if j < 0 {
			break
		}
		i += j
		end := i + 1
		if b[i] == '\r' {
			if end == len(b) && !final {
				break // may be the first half of a CRLF split across feeds
			}
			if end < len(b) && b[end] == '\n' {
				end++
			}
		}
		if ev, ok := p.line(b[start:i]); ok {
			events = append(events, ev)
		}
		start, i = end, end
	}
	rest := b[start:]
	if len(rest) == 0 {
		p.buf = p.buf[:0]
	} else if start > 0 {
		// Keep the rest at the front so the backing array is reused.
		p.buf = p.buf[:copy(p.buf, rest)]
	}
	// Scan only new bytes next time; a trailing CR is looked at again.
	p.scanned = len(p.buf)
	if p.scanned > 0 && p.buf[p.scanned-1] == '\r' {
		p.scanned--
	}
	return events
}

func (p *SSEParser) line(line []byte) (SSEEvent, bool) {
	if len(line) == 0 {
		return p.dispatch()
	}
	if line[0] == ':' {
		return SSEEvent{}, false // comment
	}
	name, value := line, []byte(nil)
	if k := bytes.IndexByte(line, ':'); k >= 0 {
		name, value = line[:k], line[k+1:]
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
	}
	switch string(name) {
	case "data":
		p.data = append(p.data, append([]byte(nil), value...))
		p.hasData = true
	case "event":
		p.event = string(bytes.ToValidUTF8(value, []byte("�")))
	}
	return SSEEvent{}, false
}

func (p *SSEParser) dispatch() (SSEEvent, bool) {
	defer func() { p.event, p.data, p.hasData = "", nil, false }()
	if !p.hasData {
		return SSEEvent{}, false
	}
	event := p.event
	if event == "" {
		event = "message"
	}
	return SSEEvent{Event: event, Data: bytes.Join(p.data, []byte("\n"))}, true
}

// Range of StreamSlots limits (TW_STREAM_MAX_PER_CALLER, spec 12.1, D36).
const (
	MinStreamsPerCaller     = 1
	MaxStreamsPerCaller     = 256
	DefaultStreamsPerCaller = 16
)

// StreamSlots counts the open streams per caller hotkey in this process
// (spec 9.2, D36). Streams live up to MaxDuration, far longer than a plain
// request, so without it one permitted validator could fill the server's
// connections and starve the others.
type StreamSlots struct {
	mu    sync.Mutex
	limit int
	open  map[string]int
}

// NewStreamSlots returns slots allowing limit open streams per caller
// (1..256).
func NewStreamSlots(limit int) (*StreamSlots, error) {
	if limit < MinStreamsPerCaller || limit > MaxStreamsPerCaller {
		return nil, fmt.Errorf("btauth: streams per caller must be between %d and %d", MinStreamsPerCaller, MaxStreamsPerCaller)
	}
	return &StreamSlots{limit: limit, open: map[string]int{}}, nil
}

// DefaultStreamSlots is the process-wide default (16 per caller), used when
// StreamConfig.Slots is nil.
var DefaultStreamSlots, _ = NewStreamSlots(DefaultStreamsPerCaller)

// Acquire takes a slot for hotkey, or returns tw.rate_limited (429). The
// returned release gives it back; calling it more than once is harmless.
func (s *StreamSlots) Acquire(hotkey string) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open[hotkey] >= s.limit {
		return nil, NewError(CodeRateLimited, "open streams per caller")
	}
	s.open[hotkey]++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.open[hotkey]--; s.open[hotkey] <= 0 {
				delete(s.open, hotkey)
			}
		})
	}, nil
}

// Open returns how many streams hotkey holds now.
func (s *StreamSlots) Open(hotkey string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open[hotkey]
}
