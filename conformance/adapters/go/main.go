// Command go-adapter runs one EHBP conformance fixture through the Go library's
// public API and prints one normalized result (see conformance/schema). It reads
// the fixture JSON on stdin and, for e2e fixtures, uses ORACLE_URL as the server.
//
// The adapter performs no validation the library lacks and never special-cases a
// fixture id: it reports exactly what the library does. mapErr is the single,
// reviewable point where a native error becomes a canonical code.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

type fixture struct {
	ID             string         `json:"id"`
	Operation      string         `json:"operation"`
	Inputs         map[string]any `json:"inputs"`
	Chunking       []int          `json:"chunking"`
	ServerScenario string         `json:"server_scenario"`
	Request        struct {
		Method  string            `json:"method"`
		Path    string            `json:"path"`
		BodyHex *string           `json:"body_hex"`
		Headers map[string]string `json:"headers"`
	} `json:"request"`
}

type result struct {
	FixtureID        string            `json:"fixture_id"`
	Outcome          string            `json:"outcome"`
	ErrorCode        *string           `json:"error_code"`
	Status           *int              `json:"status"`
	Headers          map[string]string `json:"response_headers,omitempty"`
	BodyHex          *string           `json:"body_hex"`
	Passthrough      bool              `json:"passthrough"`
	Emitted          bool              `json:"plaintext_emitted_before_error"`
	EmittedN         int               `json:"bytes_emitted_before_error"`
	Native           *string           `json:"native_error"`
	Runner           string            `json:"runner"`
	PeakRSS          *int64            `json:"peak_rss_bytes,omitempty"`
	TokenBeforeClose *bool             `json:"token_before_close,omitempty"`
	TokenAfterClose  *bool             `json:"token_after_close,omitempty"`
	TokenEarly       *bool             `json:"token_before_response,omitempty"`
	TokenAfter       *bool             `json:"token_after_exchange,omitempty"`
}

func main() {
	var fx fixture
	if err := json.NewDecoder(os.Stdin).Decode(&fx); err != nil {
		fatal(err)
	}
	r := result{FixtureID: fx.ID, Outcome: "ok", Runner: "go"}
	if err := run(&fx, &r); err != nil {
		r.Outcome = "error"
		code := mapErr(err)
		r.ErrorCode = &code
		r.BodyHex = nil
		native := err.Error()
		r.Native = &native
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}

// mapErr reads the canonical code the library attached (protocol.CodeOf); it
// never matches message text. Uncoded errors are adapter/transport input errors.
func mapErr(err error) string {
	if c := protocol.CodeOf(err); c != "" {
		return string(c)
	}
	return "INVALID_INPUT"
}

func run(fx *fixture, r *result) error {
	switch fx.Operation {
	case "derive_keys":
		key, nonceBase, err := client.Core().DeriveKeys(hexIn(fx, "exportedSecret"), hexIn(fx, "requestEnc"), hexIn(fx, "responseNonce"))
		if err != nil {
			return err
		}
		setBody(r, append(key, nonceBase...))
		return nil
	case "decrypt_response":
		return decrypt(fx, r, false)
	case "decrypt_response_streaming":
		return decrypt(fx, r, true)
	case "compute_nonce":
		seq, err := strconv.ParseUint(strIn(fx, "seqHex"), 16, 64)
		if err != nil {
			return err
		}
		nonce, err := client.Core().NonceFor(hexIn(fx, "nonceBase"), seq)
		if err != nil {
			return err
		}
		setBody(r, nonce)
		return nil
	case "token_roundtrip":
		var tok client.SessionRecoveryToken
		if err := json.Unmarshal([]byte(strIn(fx, "json")), &tok); err != nil {
			return err
		}
		setBody(r, append(append([]byte{}, tok.ExportedSecret...), tok.RequestEnc...))
		return nil
	case "parse_config":
		pk, err := client.Core().ParseConfig(hexIn(fx, "config"))
		if err != nil {
			return err
		}
		setBody(r, pk)
		return nil
	case "marshal_config":
		cfg, err := client.Core().MarshalConfig(hexIn(fx, "publicKey")) // keyId is opaque: always 0
		if err != nil {
			return err
		}
		setBody(r, cfg)
		return nil
	case "decrypt_request":
		return decryptRequest(fx, r)
	case "middleware_request":
		return middlewareRequest(fx, r)
	case "request":
		return exchange(fx, r, "bytes", false, false, false, false)
	case "discover":
		_, err := client.Discover(context.Background(), discoverTarget(fx))
		return err
	case "reject_reserved_header":
		return hardening(fx, "header")
	case "reject_cross_origin":
		return hardening(fx, "cross")
	case "residue_selfcheck":
		lines := client.SelfCheck() // the core's shared vectors through this language's bindings
		setBody(r, []byte(strings.Join(lines, "\n")))
		if len(lines) > 0 {
			native := strings.Join(lines, "; ")
			r.Native = &native
		}
		return nil
	case "reject_url_credentials":
		return hardening(fx, "credentials")
	case "large_body":
		return exchange(fx, r, "pattern", false, false, false, true)
	case "request_stream":
		return exchange(fx, r, "stream", false, false, false, false)
	case "close_response_early":
		return exchange(fx, r, "bytes", false, true, false, false)
	case "token_before_response":
		return exchange(fx, r, "bytes", true, false, false, false)
	case "token_after_exchange":
		return exchange(fx, r, "bytes", false, false, true, false)
	default:
		return fmt.Errorf("unknown operation %q", fx.Operation)
	}
}

// noFollow is the documented http.Client configuration for an EHBP transport:
// a 3xx is returned to the caller instead of being followed (SPEC 5.1).
func noFollow(tr http.RoundTripper) *http.Client {
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// oracle is a Transport over the oracle, discovering its key through the library.
func oracle() (string, *client.Transport, error) {
	serverURL := os.Getenv("ORACLE_URL")
	tr, err := client.New(serverURL, client.Discovered())
	return serverURL, tr, err
}

// decrypt runs the token-only response path over the framed body, fed whole
// or split at the fixture's byte offsets, and reports the plaintext delivered.
func decrypt(fx *fixture, r *result, streaming bool) error {
	token := &client.SessionRecoveryToken{ExportedSecret: hexIn(fx, "exportedSecret"), RequestEnc: hexIn(fx, "requestEnc")}
	framed := hexIn(fx, "encryptedResponse")
	var body io.Reader = bytes.NewReader(framed)
	if streaming {
		body = &fragmentReader{segments: splitAt(framed, fx.Chunking)}
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(body)}
	resp.Header.Set("Ehbp-Response-Nonce", hex.EncodeToString(hexIn(fx, "responseNonce")))
	if err := client.Core().DecryptResponse(resp, token); err != nil {
		return err
	}
	plain, err := readTracked(resp.Body, r)
	if err != nil {
		return err
	}
	setBody(r, plain)
	return nil
}

// exchange sends the fixture request to the oracle and reads the reply. body
// is how the fixture body is supplied (bytes, stream: unknown length, pattern:
// the lazy large body); hold reads the token while the oracle holds its reply;
// early reads one byte and closes; after reads the token once the exchange
// ended, also on error; rss reports peak RSS.
func exchange(fx *fixture, r *result, body string, hold, early, after, rss bool) error {
	serverURL, tr, err := oracle()
	if err != nil {
		return err
	}
	if after {
		defer func() { has := tr.SessionRecoveryToken() != nil; r.TokenAfter = &has }()
	}
	var reqBody io.Reader
	switch {
	case body == "pattern":
		reqBody = newPatternReader(intIn(fx, "size_bytes"), int(intIn(fx, "block_seed")))
	case fx.Request.BodyHex != nil:
		reqBody = bytes.NewReader(mustHex(*fx.Request.BodyHex, "body_hex"))
		if body == "stream" {
			reqBody = struct{ io.Reader }{reqBody} // hide the length as a streaming caller would
		}
	}
	req, err := http.NewRequest(fx.Request.Method, serverURL+fx.Request.Path, reqBody)
	if err != nil {
		return err
	}
	for k, v := range fx.Request.Headers {
		req.Header.Set(k, v)
	}
	type outcome struct {
		resp *http.Response
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		resp, err := noFollow(tr).Do(req)
		done <- outcome{resp, err}
	}()
	if hold {
		time.Sleep(500 * time.Millisecond) // the oracle holds 5 s
		has := tr.SessionRecoveryToken() != nil
		r.TokenEarly = &has
	}
	out := <-done
	if out.err != nil {
		return out.err
	}
	resp := out.resp
	status := resp.StatusCode
	r.Status = &status
	r.Headers = subsetHeaders(resp.Header)
	if early {
		var prefix [1]byte
		_, readErr := io.ReadFull(resp.Body, prefix[:])
		before := tr.SessionRecoveryToken() != nil
		closeErr := resp.Body.Close()
		afterClose := tr.SessionRecoveryToken() != nil
		r.TokenBeforeClose, r.TokenAfterClose = &before, &afterClose
		setBody(r, prefix[:])
		if readErr != nil {
			return readErr
		}
		return closeErr
	}
	plain, rerr := readTracked(resp.Body, r)
	_ = resp.Body.Close()
	if rss {
		if v, ok := peakRSSBytes(); ok {
			r.PeakRSS = &v
		}
	}
	if rerr != nil {
		return rerr
	}
	// No nonce on a non-2xx is a sanctioned unauthenticated pass-through.
	r.Passthrough = len(resp.Header.Values("Ehbp-Response-Nonce")) == 0 && (status < 200 || status >= 300)
	setBody(r, plain)
	return nil
}

// hardening sends a request the library must refuse before it reaches the
// wire; a reply from the oracle is the divergent result.
func hardening(fx *fixture, target string) error {
	base, tr, err := oracle()
	if err != nil {
		return err
	}
	url := base + "/probe"
	switch target {
	case "cross":
		url = "http://other.invalid/probe"
	case "credentials":
		url = strings.Replace(base, "://", "://user:pass@", 1) + "/probe"
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader("x"))
	if err != nil {
		return err
	}
	if target == "header" {
		name, value := strIn(fx, "header"), "0000000000000000000000000000000000000000000000000000000000000000"
		if strings.EqualFold(name, "Host") {
			value = "attacker.invalid"
		}
		req.Header.Set(name, value)
	}
	resp, err := noFollow(tr).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

// discoverTarget maps a fixture target to the oracle listener the harness
// exposes as ORACLE_<TARGET>_URL (the main oracle for anything else).
func discoverTarget(fx *fixture) string {
	if t := strIn(fx, "target"); t != "ORACLE_URL" {
		if u := os.Getenv("ORACLE_" + strings.ToUpper(t) + "_URL"); u != "" {
			return u
		}
	}
	return os.Getenv("ORACLE_URL")
}

// --- helpers ---

type fragmentReader struct {
	segments [][]byte
	i        int
}

func (f *fragmentReader) Read(p []byte) (int, error) {
	for f.i < len(f.segments) && len(f.segments[f.i]) == 0 {
		f.i++
	}
	if f.i >= len(f.segments) {
		return 0, io.EOF
	}
	n := copy(p, f.segments[f.i])
	f.segments[f.i] = f.segments[f.i][n:]
	return n, nil
}

func splitAt(b []byte, offsets []int) [][]byte {
	var segs [][]byte
	prev := 0
	for _, o := range offsets {
		if o > prev && o < len(b) {
			segs = append(segs, b[prev:o])
			prev = o
		}
	}
	return append(segs, b[prev:])
}

// patternReader yields size bytes of a 1 MiB block with block[i] = (i+seed)&0xff,
// repeated, without ever materialising the body.
type patternReader struct {
	block     []byte
	remaining int64
	pos       int
}

func newPatternReader(size int64, seed int) *patternReader {
	block := make([]byte, 1<<20)
	for i := range block {
		block[i] = byte(i + seed)
	}
	return &patternReader{block: block, remaining: size}
}

func (p *patternReader) Read(buf []byte) (int, error) {
	if p.remaining <= 0 {
		return 0, io.EOF
	}
	n := copy(buf, p.block[p.pos:])
	if int64(n) > p.remaining {
		n = int(p.remaining)
	}
	p.pos = (p.pos + n) % len(p.block)
	p.remaining -= int64(n)
	return n, nil
}

// readTracked reads to EOF; on error it records the bytes delivered before it.
func readTracked(src io.Reader, r *result) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			r.EmittedN, r.Emitted = len(out), len(out) > 0
			return out, err
		}
	}
}

func subsetHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"ehbp-response-nonce", "content-length", "transfer-encoding", "content-type"} {
		if v := h.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}

func setBody(r *result, b []byte) {
	s := hex.EncodeToString(b)
	r.BodyHex = &s
}

// Fixture inputs are repository-controlled; a missing field or bad hex is a
// broken fixture, so fail the adapter loudly (ADAPTER_CRASH in the harness)
// rather than feed an empty value to a crypto API and report its reaction.
func hexIn(fx *fixture, key string) []byte { return mustHex(strIn(fx, key), key) }
func strIn(fx *fixture, key string) string {
	s, ok := fx.Inputs[key].(string)
	if !ok {
		fatal(fmt.Errorf("fixture %s: input %q missing or not a string", fx.ID, key))
	}
	return s
}
func intIn(fx *fixture, key string) int64 {
	v, ok := fx.Inputs[key].(float64)
	if !ok {
		fatal(fmt.Errorf("fixture %s: input %q missing or not a number", fx.ID, key))
	}
	return int64(v)
}
func mustHex(s, field string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fatal(fmt.Errorf("fixture field %q: %w", field, err))
	}
	return b
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(2) }
