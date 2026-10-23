package btauth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The shared vectors (spec 11.7). Every file except legacy_v10.json (Python
// only) is checked; python_reference notes are ignored: Go gives the
// normative answer in expected.

var vectorsDir = filepath.Join("..", "..", "conformance", "vectors")

type vectorFile struct {
	SchemaVersion int               `json:"schema_version"`
	RawKeys       json.RawMessage   `json:"keys"`
	Vectors       []json.RawMessage `json:"vectors"`
}

// devKeys are the pinned dev keys of the btauth/1 files (twresp.json lists
// addresses only, so its signing keys come from payload.json).
func devKeys(t *testing.T) map[string]devKey {
	t.Helper()
	var keys map[string]devKey
	if err := json.Unmarshal(loadVectors(t, "payload.json").RawKeys, &keys); err != nil {
		t.Fatal(err)
	}
	return keys
}

type devKey struct {
	URI          string `json:"uri"`
	Scheme       string `json:"scheme"`
	SecretSeed   string `json:"secret_seed_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	SS58         string `json:"ss58"`
}

type wireRequest struct {
	Method     string      `json:"method"`
	Target     string      `json:"target"`
	BodyBase64 string      `json:"body_base64"`
	Headers    [][2]string `json:"headers"`
}

type verifyVector struct {
	ID     string `json:"id"`
	Inputs struct {
		wireRequest
		SelfHotkey    string       `json:"self_hotkey"`
		NowNs         string       `json:"now_ns"`
		MaxAgeS       int          `json:"max_age_s"`
		AllowedSkewS  int          `json:"allowed_skew_s"`
		Prior         *wireRequest `json:"prior"`
		Key           string       `json:"key"`
		SignedPayload string       `json:"signed_payload_utf8"`
	} `json:"inputs"`
	Expected struct {
		Valid     bool    `json:"valid"`
		Code      *string `json:"code"`
		Status    *int    `json:"status"`
		Caller    *string `json:"caller_ss58"`
		Signature string  `json:"signature"`
	} `json:"expected"`
}

func loadVectors(t *testing.T, name string) vectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var f vectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if f.SchemaVersion != 1 || len(f.Vectors) == 0 {
		t.Fatalf("%s: schema %d, %d vectors", name, f.SchemaVersion, len(f.Vectors))
	}
	return f
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return out
}

func mustU64(t *testing.T, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("u64 %q: %v", s, err)
	}
	return n
}

func headerOf(pairs [][2]string) http.Header {
	h := http.Header{}
	for _, p := range pairs {
		h.Add(p[0], p[1])
	}
	return h
}

func TestConformancePayload(t *testing.T) {
	f := loadVectors(t, "payload.json")
	for _, raw := range f.Vectors {
		var v struct {
			ID     string `json:"id"`
			Inputs struct {
				Scheme, Method, Target, Nonce string
				BodyBase64                    string  `json:"body_base64"`
				Sender                        string  `json:"sender_ss58"`
				Receiver                      *string `json:"receiver_ss58"`
			} `json:"inputs"`
			Expected struct {
				BodySHA256    string `json:"body_sha256"`
				PayloadBase64 string `json:"payload_base64"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.ID, func(t *testing.T) {
			i := v.Inputs
			body := b64(t, i.BodyBase64)
			if got := BodySHA256(body); got != v.Expected.BodySHA256 {
				t.Fatalf("sha256 %s", got)
			}
			receiver := ""
			if i.Receiver != nil {
				receiver = *i.Receiver
			}
			got := BuildPayload(Scheme(i.Scheme), i.Method, i.Target, body, mustU64(t, i.Nonce), i.Sender, receiver)
			if want := b64(t, v.Expected.PayloadBase64); string(got) != string(want) {
				t.Fatalf("payload\n%q\nwant\n%q", got, want)
			}
		})
	}
}

func TestConformanceKeys(t *testing.T) {
	for name, k := range devKeys(t) {
		t.Run(name, func(t *testing.T) {
			kp := keyFromVector(t, k)
			pub := kp.PublicKey()
			if hex.EncodeToString(pub[:]) != k.PublicKeyHex || kp.SS58() != k.SS58 {
				t.Fatalf("seed derives %s, want %s", kp.SS58(), k.SS58)
			}
			decoded, err := DecodeSS58(k.SS58)
			if err != nil || decoded != pub {
				t.Fatalf("DecodeSS58: %v", err)
			}
		})
	}
}

func keyFromVector(t *testing.T, k devKey) *Keypair {
	t.Helper()
	raw, err := hex.DecodeString(k.SecretSeed)
	if err != nil || len(raw) != 32 {
		t.Fatalf("seed: %v", err)
	}
	var seed [32]byte
	copy(seed[:], raw)
	if Scheme(k.Scheme) == Ed25519 {
		return NewEd25519FromSeed(seed)
	}
	kp, err := NewSr25519FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// runVerify verifies one vector's request (after its prior, with one store).
func runVerify(t *testing.T, v verifyVector) (*Caller, error) {
	t.Helper()
	i := v.Inputs
	now := mustU64(t, i.NowNs)
	verifier, err := NewVerifier(Config{
		SelfHotkey:  i.SelfHotkey,
		Store:       NewMemoryStore(time.Minute, nil),
		MaxAge:      time.Duration(i.MaxAgeS) * time.Second,
		AllowedSkew: time.Duration(i.AllowedSkewS) * time.Second,
		NowNs:       func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if p := i.Prior; p != nil {
		if _, err := verifier.Verify(ctx, headerOf(p.Headers), b64(t, p.BodyBase64), p.Method, p.Target); err != nil {
			t.Fatalf("prior refused: %v", err)
		}
	}
	return verifier.Verify(ctx, headerOf(i.Headers), b64(t, i.BodyBase64), i.Method, i.Target)
}

func checkVerifyFile(t *testing.T, name string) {
	f := loadVectors(t, name)
	for _, raw := range f.Vectors {
		var v verifyVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.ID, func(t *testing.T) {
			caller, err := runVerify(t, v)
			e := v.Expected
			if e.Valid {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if e.Caller == nil || caller.Hotkey != *e.Caller {
					t.Fatalf("caller %s", caller.Hotkey)
				}
				return
			}
			got, ok := err.(*Error)
			if !ok {
				t.Fatalf("accepted or wrong error type: %v", err)
			}
			if got.Code != *e.Code || got.Status != *e.Status {
				t.Fatalf("got %s %d, want %s %d (%s)", got.Code, got.Status, *e.Code, *e.Status, got.Detail)
			}
		})
	}
}

func TestConformanceNegative(t *testing.T) { checkVerifyFile(t, "negative.json") }

func TestConformanceSr25519Verify(t *testing.T) { checkVerifyFile(t, "sr25519_verify.json") }

func TestConformanceEd25519(t *testing.T) {
	checkVerifyFile(t, "ed25519.json")
	f, keys := loadVectors(t, "ed25519.json"), devKeys(t)
	for _, raw := range f.Vectors {
		var v verifyVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.ID+"/sign", func(t *testing.T) {
			kp := keyFromVector(t, keys[v.Inputs.Key])
			sig, err := kp.Sign([]byte(v.Inputs.SignedPayload))
			if err != nil {
				t.Fatal(err)
			}
			if got := "0x" + hex.EncodeToString(sig[:]); got != v.Expected.Signature {
				t.Fatalf("signature %s", got)
			}
		})
	}
}

// Own sr25519 signatures verify (the Python side is the live interop check).
func TestConformanceSr25519SignThenVerify(t *testing.T) {
	f, keys := loadVectors(t, "sr25519_verify.json"), devKeys(t)
	for _, raw := range f.Vectors {
		var v verifyVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.ID, func(t *testing.T) {
			kp := keyFromVector(t, keyBySS58(t, keys, *v.Expected.Caller))
			sig, err := kp.Sign([]byte(v.Inputs.SignedPayload))
			if err != nil {
				t.Fatal(err)
			}
			if !verifySignature(Sr25519, kp.PublicKey(), []byte(v.Inputs.SignedPayload), sig) {
				t.Fatal("own signature does not verify")
			}
		})
	}
}

func TestConformanceTwresp(t *testing.T) {
	f, keys := loadVectors(t, "twresp.json"), devKeys(t)
	for _, raw := range f.Vectors {
		var v struct {
			ID     string `json:"id"`
			Kind   string `json:"kind"`
			Inputs struct {
				Scheme            string          `json:"scheme"`
				RequestNonce      string          `json:"request_nonce"`
				Sender            string          `json:"sender_ss58"`
				Responder         string          `json:"responder_ss58"`
				ExpectedResponder string          `json:"expected_responder"`
				Status            int             `json:"status"`
				BodyBase64        string          `json:"body_base64"`
				Chunks            []string        `json:"chunks_base64"`
				Headers           json.RawMessage `json:"headers"`
			} `json:"inputs"`
			Expected struct {
				Valid      bool              `json:"valid"`
				ErrorCode  *string           `json:"error_code"`
				BodySHA256 string            `json:"body_sha256"`
				Digest     string            `json:"digest"`
				Payload    string            `json:"payload_utf8"`
				Headers    map[string]string `json:"headers"`
				Signature  string            `json:"signature"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.ID, func(t *testing.T) {
			i, e := v.Inputs, v.Expected
			nonce := mustU64(t, i.RequestNonce)
			switch v.Kind {
			case "verify":
				h := http.Header{}
				var asMap map[string]string
				var asPairs [][2]string
				if json.Unmarshal(i.Headers, &asMap) == nil {
					for k, val := range asMap {
						h.Add(k, val)
					}
				} else if err := json.Unmarshal(i.Headers, &asPairs); err == nil {
					h = headerOf(asPairs)
				} else {
					t.Fatal(err)
				}
				_, err := VerifyResponse(h, i.ExpectedResponder, nonce, i.Sender, i.Status, b64(t, i.BodyBase64))
				if e.Valid != (err == nil) {
					t.Fatalf("valid=%v err=%v", e.Valid, err)
				}
				if err != nil && err.(*Error).Code != *e.ErrorCode {
					t.Fatalf("code %v", err)
				}
			case "stream_ed25519":
				var all []byte
				for _, c := range i.Chunks {
					all = append(all, b64(t, c)...)
				}
				digest := BodySHA256(all)
				if digest != e.Digest {
					t.Fatalf("digest %s", digest)
				}
				p := ResponsePayload(Ed25519, nonce, i.Sender, i.Responder, 200, digest)
				if string(p) != e.Payload {
					t.Fatalf("payload %q", p)
				}
				h := http.Header{}
				h.Set(RespHeaderVersion, "1")
				h.Set(RespHeaderHotkey, i.Responder)
				h.Set(RespHeaderCrypto, "ed25519")
				h.Set(RespHeaderSignature, e.Signature)
				if _, err := VerifyResponseDigest(h, i.Responder, nonce, i.Sender, 200, digest); err != nil {
					t.Fatal(err)
				}
			default: // build_sr25519, sign_ed25519
				body := b64(t, i.BodyBase64)
				p := ResponsePayload(Scheme(i.Scheme), nonce, i.Sender, i.Responder, i.Status, BodySHA256(body))
				if string(p) != e.Payload || BodySHA256(body) != e.BodySHA256 {
					t.Fatalf("payload %q", p)
				}
				h := http.Header{}
				for k, val := range e.Headers {
					h.Set(k, val)
				}
				if _, err := VerifyResponse(h, i.Responder, nonce, i.Sender, i.Status, body); err != nil {
					t.Fatal(err)
				}
				if v.Kind == "sign_ed25519" {
					kp := keyFromVector(t, keyBySS58(t, keys, i.Responder))
					got, err := SignResponse(kp, nonce, i.Sender, i.Status, body)
					if err != nil || got.Get(RespHeaderSignature) != e.Headers["X-TW-Resp-Signature"] {
						t.Fatalf("signature %s (%v)", got.Get(RespHeaderSignature), err)
					}
				}
			}
		})
	}
}

func keyBySS58(t *testing.T, keys map[string]devKey, ss58 string) devKey {
	t.Helper()
	for _, k := range keys {
		if k.SS58 == ss58 {
			return k
		}
	}
	t.Fatalf("no key %s", ss58)
	return devKey{}
}
