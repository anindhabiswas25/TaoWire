package btauth

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzSSEParser feeds arbitrary bytes split at an arbitrary point (spec 9.2:
// the parser reads untrusted bytes). It must never panic, and two feeds must
// give the same events as one.
func FuzzSSEParser(f *testing.F) {
	f.Add([]byte("event: chunk\r\ndata: {}\r\n\r\n"), uint16(3))
	f.Add([]byte("\xef\xbb\xbfdata: x\rdata: y\r\r: c\nevent:\ndata\n\n"), uint16(1))
	f.Add([]byte("data: unfinished"), uint16(0))
	f.Fuzz(func(t *testing.T, in []byte, cut uint16) {
		at := int(cut) % (len(in) + 1)
		var whole, split SSEParser
		want := events(append(whole.Feed(in), whole.Finish()...))
		got := split.Feed(in[:at])
		got = append(got, split.Feed(in[at:])...)
		got = append(got, split.Finish()...)
		if events(got) != want {
			t.Fatalf("split at %d: %s != %s", at, events(got), want)
		}
	})
}

// FuzzParseTrailer: arbitrary tw-end data never panics; it is either a
// well-formed trailer that re-encodes to an equivalent one, or a
// *TrailerError (fail closed).
func FuzzParseTrailer(f *testing.F) {
	f.Add([]byte(`{"digest":"` + string(bytes.Repeat([]byte("a"), 64)) + `","count":1,"signature":"0x"}`))
	f.Add([]byte(`{"digest":"x","count":1.0,"count":2}`))
	f.Add([]byte(`[{"digest":1}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		tr, err := ParseTrailer(data)
		if err != nil {
			var te *TrailerError
			if !errors.As(err, &te) {
				t.Fatalf("not a TrailerError: %v", err)
			}
			return
		}
		again, err := ParseTrailer(EncodeTrailer(tr))
		if err != nil || again != tr || !hexDigestRE.MatchString(tr.Digest) {
			t.Fatalf("%+v -> %+v (%v)", tr, again, err)
		}
	})
}

// FuzzDecodeChunk: arbitrary chunk data never panics; anything accepted is
// valid JSON, an object or array, and EncodeChunk agrees when there is no
// line break.
func FuzzDecodeChunk(f *testing.F) {
	f.Add([]byte(`{"a":[1,{"b":"☃"}]}`))
	f.Add([]byte(`[NaN]`))
	f.Add([]byte("\xff{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		raw, err := DecodeChunk(data)
		if err != nil {
			var ce *ChunkError
			if !errors.As(err, &ce) {
				t.Fatalf("not a ChunkError: %v", err)
			}
			return
		}
		if !bytes.Equal(raw, data) {
			t.Fatal("DecodeChunk changed the bytes")
		}
		if !bytes.ContainsAny(data, "\r\n") && firstNonSpace(data, " \t") != 0 {
			if _, err := EncodeChunk([]byte(data)); err != nil {
				t.Fatalf("EncodeChunk refused a decodable chunk: %v", err)
			}
		}
	})
}
