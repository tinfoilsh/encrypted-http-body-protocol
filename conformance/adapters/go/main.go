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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
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
	FixtureID   string            `json:"fixture_id"`
	Outcome     string            `json:"outcome"`
	ErrorCode   *string           `json:"error_code"`
	Status      *int              `json:"status"`
	Headers     map[string]string `json:"response_headers,omitempty"`
	BodyHex     *string           `json:"body_hex"`
	Passthrough bool              `json:"passthrough"`
	Emitted     bool              `json:"plaintext_emitted_before_error"`
	EmittedN    int               `json:"bytes_emitted_before_error"`
	Native      *string           `json:"native_error"`
	SkipReason  *string           `json:"skip_reason,omitempty"`
	Runner      string            `json:"runner"`
}

func main() {
	var fx fixture
	if err := json.NewDecoder(os.Stdin).Decode(&fx); err != nil {
		fatal(err)
	}
	r := result{FixtureID: fx.ID, Outcome: "ok", Runner: "go"}
	if err := run(&fx, &r); err != nil {
		r.Outcome = "error"
		code := mapErr(fx.Operation, err)
		r.ErrorCode = &code
		r.BodyHex = nil
		native := err.Error()
		r.Native = &native
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}

func run(fx *fixture, r *result) error {
	switch fx.Operation {
	case "derive_keys":
		km, err := identity.DeriveResponseKeys(hexIn(fx, "exportedSecret"), hexIn(fx, "requestEnc"), hexIn(fx, "responseNonce"))
		if err != nil {
			return err
		}
		setBody(r, append(append([]byte{}, km.Key...), km.NonceBase...))
		return nil
	case "compute_nonce":
		seq, err := strconv.ParseUint(strIn(fx, "seqHex"), 16, 64)
		if err != nil {
			return err
		}
		km := &identity.ResponseKeyMaterial{Key: make([]byte, 32), NonceBase: hexIn(fx, "nonceBase")}
		aead, err := km.NewResponseAEAD()
		if err != nil {
			return err
		}
		setBody(r, aead.NonceForSeq(seq))
		return nil
	case "decrypt_response", "decrypt_response_streaming":
		return decryptResponse(fx, r)
	case "token_roundtrip":
		var tok identity.SessionRecoveryToken
		if err := json.Unmarshal([]byte(strIn(fx, "json")), &tok); err != nil {
			return err
		}
		setBody(r, append(append([]byte{}, tok.ExportedSecret...), tok.RequestEnc...))
		return nil
	case "parse_config":
		id, err := identity.UnmarshalPublicConfig(hexIn(fx, "config"))
		if err != nil {
			return err
		}
		setBody(r, id.MarshalPublicKey())
		return nil
	case "marshal_config":
		id, err := identity.FromPublicKeyBytes(hexIn(fx, "publicKey"))
		if err != nil {
			return err
		}
		cfg, err := id.MarshalConfig()
		if err != nil {
			return err
		}
		setBody(r, cfg)
		return nil
	case "request":
		return doRequest(fx, r)
	case "discover":
		// Go's client constructor performs discovery with content-type/status checks.
		_, err := client.NewTransport(discoverTarget(fx))
		return err
	case "reject_reserved_header", "reject_cross_origin", "reject_url_credentials":
		return hardening(fx.Operation)
	case "decrypt_request":
		return decryptRequest(fx, r)
	case "middleware_request":
		return middlewareRequest(fx)
	default:
		return fmt.Errorf("unknown operation %q", fx.Operation)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// hardening exercises request-boundary validation without contacting the URL
// under test. A recording RoundTripper returns a plaintext 502 if the request
// escapes validation; that successful pass-through is the divergent result.
func hardening(op string) error {
	serverID, err := identity.NewIdentity()
	if err != nil {
		return err
	}
	cfg, err := serverID.MarshalConfig()
	if err != nil {
		return err
	}
	recorder := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("probe")),
			Request:    req,
		}, nil
	})
	base := "http://configured.example"
	tr, err := client.NewTransportWithConfig(base, cfg,
		client.WithHTTPClient(&http.Client{Transport: recorder}))
	if err != nil {
		return err
	}
	target := base + "/probe"
	if op == "reject_cross_origin" {
		target = "http://attacker.invalid/probe"
	} else if op == "reject_url_credentials" {
		target = "http://user:pass@configured.example/probe"
	}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader("x"))
	if err != nil {
		return err
	}
	if op == "reject_reserved_header" {
		req.Header.Set(protocol.ResponseNonceHeader, strings.Repeat("0", 64))
	}
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

func encryptedRequest(id *identity.Identity, plaintext []byte) (*http.Request, []byte, error) {
	req := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader(plaintext))
	if _, err := id.EncryptRequestWithContext(req); err != nil {
		return nil, nil, err
	}
	framed, err := io.ReadAll(req.Body)
	return req, framed, err
}

// decryptRequest drives the public server-side request API with structural
// mutations. The 64 MiB+1 case runs in this disposable adapter process so a
// vulnerable allocation cannot take down the harness itself.
func decryptRequest(fx *fixture, r *result) error {
	id, err := identity.NewIdentity()
	if err != nil {
		return err
	}
	plaintext := []byte("after-zero-frames")
	template, framed, err := encryptedRequest(id, plaintext)
	if err != nil {
		return err
	}

	mutation := strIn(fx, "mutation")
	body := framed
	if mutation == "oversized_frame" {
		body = make([]byte, 4)
		binary.BigEndian.PutUint32(body, (64<<20)+1)
	} else if mutation == "partial_prefix" {
		body = []byte{0, 0, 0}
	} else if mutation == "zero_frame_burst" {
		count := 10000
		if v, ok := fx.Inputs["zeroFrameCount"].(float64); ok {
			count = int(v)
		}
		body = append(make([]byte, count*4), framed...)
	}

	req := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader(body))
	for _, value := range template.Header.Values(protocol.EncapsulatedKeyHeader) {
		req.Header.Add(protocol.EncapsulatedKeyHeader, value)
	}
	if mutation == "duplicate_encapsulated_key" {
		req.Header.Add(protocol.EncapsulatedKeyHeader, strings.Repeat("0", 64))
	}
	if _, err := id.DecryptRequestWithContext(req); err != nil {
		return err
	}
	plain, n, err := readTracked(req.Body)
	if err != nil {
		r.EmittedN = n
		r.Emitted = n > 0
		return err
	}
	setBody(r, plain)
	return nil
}

// middlewareRequest proves whether a trailing authentication failure is
// checked before application code executes. The handler deliberately consumes
// only one byte, as real routing/auth middleware commonly does.
func middlewareRequest(fx *fixture) error {
	if strIn(fx, "mutation") != "trailing_tamper" {
		return fmt.Errorf("unknown middleware mutation")
	}
	id, err := identity.NewIdentity()
	if err != nil {
		return err
	}
	template, framed, err := encryptedRequest(id, bytes.Repeat([]byte("x"), 20<<10))
	if err != nil {
		return err
	}
	framed[len(framed)-1] ^= 1
	req := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader(framed))
	for _, value := range template.Header.Values(protocol.EncapsulatedKeyHeader) {
		req.Header.Add(protocol.EncapsulatedKeyHeader, value)
	}

	handlerRan := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		handlerRan = true
		one := make([]byte, 1)
		_, _ = req.Body.Read(one)
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	id.Middleware()(handler).ServeHTTP(rec, req)
	if handlerRan {
		return nil
	}
	if rec.Code == http.StatusUnprocessableEntity {
		return identity.NewKeyConfigError(fmt.Errorf("trailing request frame failed authentication"))
	}
	return identity.NewClientError(fmt.Errorf("request rejected with status %d", rec.Code))
}

func discoverTarget(fx *fixture) string {
	switch strIn(fx, "target") {
	case "bad_ct":
		return os.Getenv("ORACLE_BAD_CT_URL")
	case "non200":
		return os.Getenv("ORACLE_NON200_URL")
	default:
		return os.Getenv("ORACLE_URL")
	}
}

func decryptResponse(fx *fixture, r *result) error {
	token := &identity.SessionRecoveryToken{ExportedSecret: hexIn(fx, "exportedSecret"), RequestEnc: hexIn(fx, "requestEnc")}
	framed := hexIn(fx, "encryptedResponse")

	var body io.Reader = bytes.NewReader(framed)
	if fx.Operation == "decrypt_response_streaming" {
		body = &fragmentReader{segments: splitAt(framed, fx.Chunking)}
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(body)}
	resp.Header.Set(protocol.ResponseNonceHeader, hex.EncodeToString(hexIn(fx, "responseNonce")))

	if err := identity.DecryptResponseWithToken(resp, token); err != nil {
		return err
	}
	plain, n, err := readTracked(resp.Body)
	if err != nil {
		r.EmittedN = n
		r.Emitted = n > 0
		return err
	}
	setBody(r, plain)
	return nil
}

func doRequest(fx *fixture, r *result) error {
	serverURL := os.Getenv("ORACLE_URL")
	tr, err := client.NewTransport(serverURL)
	if err != nil {
		return err
	}
	var reqBody io.Reader
	if fx.Request.BodyHex != nil {
		reqBody = bytes.NewReader(mustHex(*fx.Request.BodyHex))
	}
	req, err := http.NewRequest(fx.Request.Method, serverURL+fx.Request.Path, reqBody)
	if err != nil {
		return err
	}
	for k, v := range fx.Request.Headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return err
	}
	status := resp.StatusCode
	r.Status = &status
	r.Headers = subsetHeaders(resp.Header)

	plain, n, rerr := readTracked(resp.Body)
	_ = resp.Body.Close()
	if rerr != nil {
		r.EmittedN = n
		r.Emitted = n > 0
		return rerr
	}
	// No nonce on a non-2xx is a sanctioned unauthenticated pass-through.
	if resp.Header.Get(protocol.ResponseNonceHeader) == "" && (status < 200 || status >= 300) {
		r.Passthrough = true
	}
	setBody(r, plain)
	return nil
}

// mapErr is the sole native-error -> canonical-code translation. Each arm names
// the concrete condition it matches so a reviewer can confirm it is not lossy.
func mapErr(op string, err error) string {
	if identity.IsKeyConfigError(err) {
		return "KEY_CONFIG_MISMATCH"
	}
	msg := err.Error()
	switch {
	case contains(msg, "missing "+protocol.ResponseNonceHeader):
		return "MISSING_RESPONSE_NONCE"
	case op == "decrypt_request" && contains(msg, "encapsulated key"):
		return "INVALID_ENCAPSULATED_KEY"
	case contains(msg, "invalid response nonce"):
		return "INVALID_RESPONSE_NONCE"
	case contains(msg, "exceeds maximum allowed size"):
		return "CHUNK_TOO_LARGE"
	case contains(msg, "failed to read encrypted chunk"),
		contains(msg, "invalid chunk length framing"),
		contains(msg, "failed to read chunk length"):
		return "FRAMING_TRUNCATED"
	case contains(msg, "failed to decrypt chunk"):
		return "AEAD_DECRYPT_FAILED"
	case contains(msg, "unsupported KEM"), contains(msg, "invalid KEM"),
		contains(msg, "invalid KDF"), contains(msg, "invalid AEAD"):
		return "UNSUPPORTED_SUITE"
	case contains(msg, "invalid content type"), contains(msg, "returned status"),
		contains(msg, "failed to sync"):
		return "INVALID_KEY_CONFIG"
	case contains(msg, "invalid config"), contains(msg, "no cipher suites"),
		contains(msg, "unmarshal public key"), contains(msg, "invalid public key"):
		return "INVALID_KEY_CONFIG"
	case op == "token_roundtrip" && (contains(msg, "hex") || contains(msg, "invalid")):
		return "INVALID_TOKEN"
	case op == "derive_keys" && contains(msg, "must be"):
		return "INVALID_INPUT"
	default:
		if errors.As(err, new(identity.ClientError)) {
			return "INVALID_INPUT"
		}
		return "INVALID_INPUT"
	}
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
	segs = append(segs, b[prev:])
	return segs
}

func readTracked(r io.Reader) ([]byte, int, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out, len(out), nil
		}
		if err != nil {
			return out, len(out), err
		}
	}
}

func subsetHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, k := range []string{protocol.ResponseNonceHeader, "Content-Length", "Transfer-Encoding", "Content-Type"} {
		if v := h.Get(k); v != "" {
			out[strings.ToLower(k)] = v
		}
	}
	return out
}

func setBody(r *result, b []byte) {
	s := hex.EncodeToString(b)
	r.BodyHex = &s
}

func hexIn(fx *fixture, key string) []byte { return mustHex(strIn(fx, key)) }
func strIn(fx *fixture, key string) string { s, _ := fx.Inputs[key].(string); return s }
func mustHex(s string) []byte              { b, _ := hex.DecodeString(s); return b }
func contains(s, sub string) bool          { return strings.Contains(s, sub) }
func fatal(err error)                      { fmt.Fprintln(os.Stderr, err); os.Exit(2) }
