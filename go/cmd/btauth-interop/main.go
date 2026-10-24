// Command btauth-interop is the Go side of the live interop check
// (conformance/interop/live_check.py, spec 13.5 without a chain).
//
//	btauth-interop serve --addr 127.0.0.3:8095 --seed <hex> [--scheme sr25519]
//	btauth-interop sign --url http://127.0.0.2:8094/v1/upper --seed <hex> --receiver <ss58> \
//	    [--scheme ed25519] [--count 200] [--body '{"text":"hello"}']
//	btauth-interop stream --url http://127.0.0.2:8094/v1/stream --seed <hex> --receiver <ss58> \
//	    [--scheme ed25519] [--count 1] [--body '{"text":"hello"}']
//	btauth-interop sidecar --url http://127.0.0.1:9910 --token-file <path> --netuid 1 --receiver <miner ss58>
//
// serve answers POST /v1/upper ({"text": s} -> {"result": upper(s)}) behind
// btauth.Middleware with twresp/1 signing, and POST /v1/stream with an SSE
// stream of five chunks {"i": n, "text": upper(s)} and a signed tw-end
// (spec 9.2). sign sends count requests with a fresh signature each and
// prints one JSON summary line: every answer must be 200 with a verified
// twresp/1 signature. stream reads count streams the same way (conformance/
// interop/stream_check.py). sidecar runs the sidecar client's calls against a
// real `tensorwire sidecar` and prints what each returned
// (conformance/interop/sidecar_check.py). Seeds are public dev keys only.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tensorwire/tensorwire/go/btauth"
	"github.com/tensorwire/tensorwire/go/sidecar"
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
	mux.Handle("/v1/stream", protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			btauth.WriteError(w, btauth.NewError("tw.invalid_request", err.Error()))
			return
		}
		n := 0
		next := func(context.Context) (any, error) {
			if n == 5 {
				return nil, io.EOF
			}
			n++
			return map[string]any{"i": n - 1, "text": strings.ToUpper(req.Text)}, nil
		}
		btauth.ServeStream(w, r, next, btauth.StreamConfig{Route: "/v1/stream"})
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

func stream(url, receiver, body string, count int, k *btauth.Keypair) error {
	c := &btauth.Client{Signer: btauth.NewSigner(k)}
	errs := map[string]int{}
	ok := 0
	var chunks []json.RawMessage
	for i := 0; i < count; i++ {
		s, err := c.Stream(context.Background(), "POST", url, []byte(body), receiver, btauth.StreamOptions{})
		if err == nil {
			for s.Next() {
			}
			err = s.Err()
			chunks = s.Chunks()
		}
		if err != nil {
			errs[err.(*btauth.Error).Code]++
			continue
		}
		ok++
	}
	out, _ := json.Marshal(map[string]any{
		"language": "go", "signer": k.SS58(), "scheme": k.Scheme(), "count": count, "ok": ok,
		"errors": errs, "chunks": chunks,
	})
	fmt.Println(string(out))
	if ok != count {
		return fmt.Errorf("%d of %d ok", ok, count)
	}
	return nil
}

// sidecarCheck exercises every client call against a real sidecar.
func sidecarCheck(base, tokenFile string, netuid int, miner string, probes []string) error {
	ctx := context.Background()
	out := map[string]any{"language": "go"}
	c, err := sidecar.New(sidecar.Config{NetUID: netuid, URL: base, TokenFile: tokenFile, ExpectedHotkey: miner})
	if err != nil {
		return err
	}
	code := func(err error) string {
		var e *btauth.Error
		var ce *sidecar.ChainError
		switch {
		case err == nil:
			return "ok"
		case errors.As(err, &e):
			return e.Code
		case errors.As(err, &ce):
			return "chain:" + ce.Code
		}
		return err.Error()
	}
	out["start"] = code(c.Start(ctx))
	defer c.Stop()
	h, err := c.Health(ctx)
	out["health"] = map[string]any{"ok": h.OK, "hotkey": h.Hotkey, "stage": h.Stage, "err": code(err)}
	if s := c.Snapshot(); s != nil {
		out["neurons"] = len(s.Neurons)
	}
	out["stage"] = c.Stage()
	checks, callers := map[string]string{}, map[string]string{}
	for _, hk := range probes {
		_, err := c.Check(hk, sidecar.PolicyScope)
		checks[hk] = code(err)
		d, err := c.Caller(ctx, hk)
		switch {
		case err != nil:
			callers[hk] = code(err)
		case d.Allowed:
			callers[hk] = "allowed"
		default:
			callers[hk] = d.Code
		}
	}
	out["check"], out["caller"] = checks, callers
	hash, err := c.ServeAxon(ctx, "127.0.0.2", 8099, "")
	out["serve_axon"] = code(err)
	out["block_hash_ok"] = strings.HasPrefix(hash, "0x") && len(hash) == 66
	wrong, err := sidecar.New(sidecar.Config{NetUID: netuid, URL: base, Token: strings.Repeat("w", 32)})
	if err == nil {
		_, err = wrong.Health(ctx)
	}
	out["wrong_token"] = code(err)
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: btauth-interop serve|sign|stream|sidecar [flags]")
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
	tokenFile := fs.String("token-file", "", "sidecar: token file")
	netuid := fs.Int("netuid", 1, "sidecar: netuid")
	probes := fs.String("probes", "", "sidecar: comma-separated hotkeys to check")
	_ = fs.Parse(os.Args[2:])
	if os.Args[1] == "sidecar" {
		if err := sidecarCheck(*url, *tokenFile, *netuid, *receiver, strings.Split(*probes, ",")); err != nil {
			fmt.Fprintln(os.Stderr, "btauth-interop:", err)
			os.Exit(1)
		}
		return
	}
	k, err := key(*seed, *scheme)
	if err == nil {
		switch os.Args[1] {
		case "serve":
			err = serve(*addr, k)
		case "sign":
			err = sign(*url, *receiver, *body, *count, k)
		case "stream":
			err = stream(*url, *receiver, *body, *count, k)
		default:
			err = fmt.Errorf("unknown mode %q", os.Args[1])
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "btauth-interop:", err)
		os.Exit(1)
	}
}
