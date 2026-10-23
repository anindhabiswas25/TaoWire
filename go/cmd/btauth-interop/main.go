// Command btauth-interop is the Go side of the live interop check
// (conformance/interop/live_check.py, spec 13.5 without a chain).
//
//	btauth-interop serve --addr 127.0.0.3:8095 --seed <hex> [--scheme sr25519]
//	btauth-interop sign --url http://127.0.0.2:8094/v1/upper --seed <hex> --receiver <ss58> \
//	    [--scheme ed25519] [--count 200] [--body '{"text":"hello"}']
//
// serve answers POST /v1/upper ({"text": s} -> {"result": upper(s)}) behind
// btauth.Middleware with twresp/1 signing. sign sends count requests with a
// fresh signature each and prints one JSON summary line: every answer must
// be 200 with a verified twresp/1 signature. Seeds are public dev keys only.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tensorwire/tensorwire/go/btauth"
)

func key(seedHex, scheme string) (*btauth.Keypair, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(seedHex, "0x"))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("--seed must be 32 bytes of hex")
	}
	var seed [32]byte
	copy(seed[:], raw)
	if scheme == "ed25519" {
		return btauth.NewEd25519FromSeed(seed), nil
	}
	return btauth.NewSr25519FromSeed(seed)
}

func serve(addr string, k *btauth.Keypair) error {
	v, err := btauth.NewVerifier(btauth.Config{SelfHotkey: k.SS58(), Store: btauth.NewMemoryStore(time.Minute, nil)})
	if err != nil {
		return err
	}
	protect := btauth.Middleware(btauth.MiddlewareConfig{Verifier: v, ResponseKey: k})
	mux := http.NewServeMux()
	mux.Handle("/v1/upper", protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			btauth.WriteError(w, btauth.NewError("tw.invalid_request", err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"result": strings.ToUpper(req.Text)})
	})))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	fmt.Printf("serving %s as %s\n", addr, k.SS58())
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}

func sign(url, receiver, body string, count int, k *btauth.Keypair) error {
	c := &btauth.Client{Signer: btauth.NewSigner(k), HTTP: &http.Client{Timeout: 10 * time.Second}}
	statuses := map[int]int{}
	errs := map[string]int{}
	ok := 0
	for i := 0; i < count; i++ {
		resp, err := c.Do(context.Background(), "POST", url, []byte(body), receiver)
		if resp != nil {
			statuses[resp.Status]++
		}
		if err != nil {
			errs[err.(*btauth.Error).Code]++
			continue
		}
		if resp.Status == 200 && resp.Verified {
			ok++
		}
	}
	out, _ := json.Marshal(map[string]any{
		"language": "go", "signer": k.SS58(), "scheme": k.Scheme(), "count": count, "ok": ok,
		"statuses": statuses, "errors": errs,
	})
	fmt.Println(string(out))
	if ok != count {
		return fmt.Errorf("%d of %d ok", ok, count)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: btauth-interop serve|sign [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.3:8095", "serve: listen address")
	seed := fs.String("seed", "", "32-byte hex seed (public dev key)")
	scheme := fs.String("scheme", "sr25519", "sr25519 or ed25519")
	url := fs.String("url", "", "sign: target URL")
	receiver := fs.String("receiver", "", "sign: miner hotkey")
	count := fs.Int("count", 200, "sign: requests")
	body := fs.String("body", `{"text":"hello"}`, "sign: JSON body")
	_ = fs.Parse(os.Args[2:])
	k, err := key(*seed, *scheme)
	if err == nil {
		switch os.Args[1] {
		case "serve":
			err = serve(*addr, k)
		case "sign":
			err = sign(*url, *receiver, *body, *count, k)
		default:
			err = fmt.Errorf("unknown mode %q", os.Args[1])
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "btauth-interop:", err)
		os.Exit(1)
	}
}
