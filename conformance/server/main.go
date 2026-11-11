// Command oracle is the EHBP conformance oracle server.
//
// It serves the reference HPKE key config and a set of scenario routes under
// /s/{scenario}. Every scenario first derives a CORRECT bound response through
// the reference identity API, then applies one deterministic transform (drop a
// header, flip a tag byte, truncate a frame). No route depends on timing, so a
// client's observed result is fully determined by the scenario. See
// conformance/spec and conformance/README.md.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// observation records what the oracle actually received for a request, so the
// harness can compare client wire shapes side by side. These feed comparison-only
// rows and never gate CI.
type observation struct {
	TransferEncoding string `json:"transfer_encoding"`
	ContentLength    int64  `json:"content_length"`
	BodyBytes        int    `json:"body_bytes"`
	FrameCount       int    `json:"frame_count"`
	TrailingBytes    int    `json:"trailing_bytes"`
	Proto            string `json:"proto"`
	UserAgent        string `json:"user_agent"`
}

var (
	obsMu sync.Mutex
	obs   = map[string]observation{}
)

// countFrames counts length-prefixed frames in a raw encrypted body without
// decrypting, and reports any trailing bytes that do not form a full frame.
func countFrames(b []byte) (frames, trailing int) {
	pos := 0
	for pos+4 <= len(b) {
		l := int(binary.BigEndian.Uint32(b[pos : pos+4]))
		if pos+4+l > len(b) {
			break
		}
		pos += 4 + l
		frames++
	}
	return frames, len(b) - pos
}

func main() {
	addr := flag.String("l", "127.0.0.1:8087", "listen address")
	idFile := flag.String("i", "conformance/server/oracle_identity.json", "identity file (created if absent)")
	flag.Parse()

	id, err := identity.FromFile(*idFile)
	if err != nil {
		log.Fatalf("oracle: identity: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(protocol.KeysPath, cors(id.ConfigHandler))
	mux.HandleFunc("/health", cors(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Oracle-Public-Key", id.MarshalPublicKeyHex())
		io.WriteString(w, "ok")
	}))
	mux.HandleFunc("/s/", cors(scenario(id)))
	mux.HandleFunc("/observations/", cors(func(w http.ResponseWriter, r *http.Request) {
		marker := strings.TrimPrefix(r.URL.Path, "/observations/")
		obsMu.Lock()
		o, ok := obs[marker]
		obsMu.Unlock()
		if !ok {
			http.Error(w, "no observation", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(o)
	}))

	// Two auxiliary key-config endpoints let discovery robustness be tested
	// without disturbing the valid config on the main listener. All three bind
	// synchronously (":0" picks free ports, no reservation race) and are
	// announced on one stdout line before anything is served; the harness
	// reads its URLs from that line.
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("oracle: listen address: %v", err)
	}
	mainLn, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("oracle: main listener %s: %v", *addr, err)
	}
	mainKeys := "http://" + mainLn.Addr().String() + protocol.KeysPath
	aux := []string{"bad_ct", "non200", "ct_params", "status203", "redirect", "trailing"}
	var line strings.Builder
	line.WriteString("listening main=" + mainLn.Addr().String())
	for _, mode := range aux {
		line.WriteString(fmt.Sprintf(" %s=%s", mode, serveBadConfig(net.JoinHostPort(host, "0"), id, mode, mainKeys)))
	}
	fmt.Println(line.String())
	log.Printf("oracle: public key %s", id.MarshalPublicKeyHex())
	log.Fatal(http.Serve(mainLn, mux))
}

// serveBadConfig answers /.well-known/hpke-keys with a discovery variant
// (SPEC 3.1): "bad_ct" serves the valid config under the wrong media type;
// "non200" returns a 500; "ct_params" serves it under a mixed-case media type
// with parameters (valid); "status203" serves it correctly but with status 203
// (invalid: only 200 is accepted); "redirect" answers 302 to the main listener
// (invalid: discovery never follows redirects); "trailing" appends 1 MiB of
// junk after the config (valid: only the first key_config is read).
func serveBadConfig(addr string, id *identity.Identity, mode string, mainKeys string) string {
	mux := http.NewServeMux()
	mux.HandleFunc(protocol.KeysPath, cors(func(w http.ResponseWriter, r *http.Request) {
		cfg, _ := id.MarshalConfig()
		switch mode {
		case "non200":
			http.Error(w, "unavailable", http.StatusInternalServerError)
		case "bad_ct":
			w.Header().Set("Content-Type", "text/plain") // wrong media type
			_, _ = w.Write(cfg)
		case "ct_params":
			w.Header().Set("Content-Type", "Application/OHTTP-Keys; charset=utf-8")
			_, _ = w.Write(cfg)
		case "status203":
			w.Header().Set("Content-Type", protocol.KeysMediaType)
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			_, _ = w.Write(cfg)
		case "redirect":
			w.Header().Set("Location", mainKeys)
			w.WriteHeader(http.StatusFound)
		case "trailing":
			w.Header().Set("Content-Type", protocol.KeysMediaType)
			_, _ = w.Write(append(cfg, make([]byte, 1<<20)...))
		}
	}))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("oracle: auxiliary listener %s: %v", addr, err)
	}
	go func() { _ = http.Serve(ln, mux) }()
	return ln.Addr().String()
}

// cors allows the browser adapter (a cross-origin page) to reach the oracle and
// to read the EHBP response headers.
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		// X-Caller is the caller-supplied header the request_meta scenario echoes
		// (SPEC 5.1: caller headers are preserved); browsers preflight it.
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Ehbp-Encapsulated-Key, X-Caller")
		w.Header().Set("Access-Control-Expose-Headers", "Ehbp-Response-Nonce, Ehbp-Encapsulated-Key, Content-Type, X-Oracle-Public-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func scenario(id *identity.Identity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/s/")

		// Routes that answer without an encrypted request context.
		switch name {
		case "key_config_mismatch_422":
			w.Header().Set("Content-Type", protocol.ProblemJSONMediaType)
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"type":  protocol.KeyConfigProblemType,
				"title": "stale client key configuration",
			})
			return
		case "plaintext_error_502":
			// An intermediary rejects the request before it reaches EHBP: a
			// non-2xx with no nonce. Clients MAY pass this body through.
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, "upstream unavailable")
			return
		case "plaintext_success_200":
			// A 2xx with no nonce. Clients MUST fail closed, never read this.
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "unauthenticated plaintext")
			return
		case "bodyless_plaintext":
			// A bodyless request carries no encapsulated key; the response is
			// plaintext and the client returns it as normal (SPEC 7.4).
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "plaintext for bodyless request")
			return
		case "drop_nonce_204":
			// A 2xx with no nonce and no body: still MISSING_RESPONSE_NONCE (SPEC 5.1).
			w.WriteHeader(http.StatusNoContent)
			return
		case "redirect_302":
			// A redirect of an encrypted request is never followed (SPEC 5.1): it
			// is a non-2xx without a nonce and passes through.
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Location", "/s/bodyless_plaintext")
			w.WriteHeader(http.StatusFound)
			io.WriteString(w, "redirecting")
			return
		case "problem_422_other_type":
			// An application-level problem document: not a key-config problem.
			w.Header().Set("Content-Type", protocol.ProblemJSONMediaType)
			w.WriteHeader(http.StatusUnprocessableEntity)
			io.WriteString(w, `{"type":"urn:example:validation","title":"bad field"}`)
			return
		case "problem_422_text_plain":
			// The right type under the wrong media type is not a problem document.
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusUnprocessableEntity)
			io.WriteString(w, `{"type":"`+protocol.KeyConfigProblemType+`","title":"stale"}`)
			return
		case "problem_422_numeric_title":
			// type decides; a non-string title only loses its text (SPEC 5.4.2).
			w.Header().Set("Content-Type", protocol.ProblemJSONMediaType)
			w.WriteHeader(http.StatusUnprocessableEntity)
			io.WriteString(w, `{"type":"`+protocol.KeyConfigProblemType+`","title":7}`)
			return
		case "problem_422_case_keys":
			// JSON member names are case-sensitive: "Type" is not "type".
			w.Header().Set("Content-Type", protocol.ProblemJSONMediaType)
			w.WriteHeader(http.StatusUnprocessableEntity)
			io.WriteString(w, `{"Type":"`+protocol.KeyConfigProblemType+`","Title":"stale"}`)
			return
		case "problem_422_oversized":
			// A key-config type inside a document above 64 KiB is not parsed.
			w.Header().Set("Content-Type", protocol.ProblemJSONMediaType)
			w.WriteHeader(http.StatusUnprocessableEntity)
			io.WriteString(w, `{"type":"`+protocol.KeyConfigProblemType+`","title":"`+strings.Repeat("x", 70_000)+`"}`)
			return
		case "problem_422_deep_array":
			// 50 000 nested arrays: a recursive JSON parser must not take the
			// client down; this is simply not a problem document.
			w.Header().Set("Content-Type", protocol.ProblemJSONMediaType)
			w.WriteHeader(http.StatusUnprocessableEntity)
			io.WriteString(w, `{"type":`+strings.Repeat("[", 50_000))
			return
		}

		// Observation route for request headers (SPEC 4.1, 5.1, 7.4): reports
		// what arrived, encrypted when the request was, so the harness can
		// assert the key header is present iff a body is, lowercase, and that
		// caller headers survive. The format is fixed: enc=<count>:<len>:<case>.
		if name == "request_meta" {
			raw, _ := io.ReadAll(r.Body)
			keys := r.Header.Values(protocol.EncapsulatedKeyHeader)
			first, kase := "", "none"
			if len(keys) > 0 {
				first = keys[0]
				switch {
				case first == strings.ToLower(first):
					kase = "lower"
				case first == strings.ToUpper(first):
					kase = "upper"
				default:
					kase = "mixed"
				}
			}
			line := fmt.Sprintf("enc=%d:%d:%s x-caller=%s", len(keys), len(first), kase, r.Header.Get("X-Caller"))
			if len(keys) == 0 {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, line)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			respCtx, err := id.DecryptRequestWithContext(r)
			if err != nil || respCtx == nil {
				http.Error(w, "bad encrypted request", http.StatusBadRequest)
				return
			}
			if _, err := io.ReadAll(r.Body); err != nil {
				http.Error(w, "request decryption failed", http.StatusBadRequest)
				return
			}
			sealAndWrite(w, id, respCtx, []byte(line))
			return
		}

		// Observation route: record the received wire shape, then echo normally
		// so the client still sees a valid encrypted response.
		if name == "shape" {
			raw, _ := io.ReadAll(r.Body)
			frames, trailing := countFrames(raw)
			o := observation{
				TransferEncoding: strings.Join(r.TransferEncoding, ","),
				ContentLength:    r.ContentLength,
				BodyBytes:        len(raw),
				FrameCount:       frames,
				TrailingBytes:    trailing,
				Proto:            r.Proto,
				UserAgent:        r.UserAgent(),
			}
			if m := r.Header.Get("X-Conformance-Marker"); m != "" {
				obsMu.Lock()
				obs[m] = o
				obsMu.Unlock()
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			respCtx, err := id.DecryptRequestWithContext(r)
			if err != nil || respCtx == nil {
				http.Error(w, "shape route requires an encrypted request body", http.StatusBadRequest)
				return
			}
			plaintext, _ := io.ReadAll(r.Body)
			sealAndWrite(w, id, respCtx, plaintext)
			return
		}

		// Remaining routes bind a response to the request. Decrypt it first.
		respCtx, err := id.DecryptRequestWithContext(r)
		if err != nil {
			http.Error(w, "bad encrypted request", http.StatusBadRequest)
			return
		}
		if respCtx == nil {
			http.Error(w, "scenario requires an encrypted request body", http.StatusBadRequest)
			return
		}
		if name == "digest" {
			// Stream the decrypted body straight into a hash so a multi-GiB
			// request never lands in memory; reply with the raw 32-byte digest.
			h := sha256.New()
			if _, err := io.Copy(h, r.Body); err != nil {
				http.Error(w, "request decryption failed", http.StatusBadRequest)
				return
			}
			sealAndWrite(w, id, respCtx, h.Sum(nil))
			return
		}
		plaintext, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request decryption failed", http.StatusBadRequest)
			return
		}

		// Produce a correct bound response into a recorder, then transform it.
		nonce, framed, err := sealResponse(id, respCtx, plaintext)
		if err != nil {
			http.Error(w, "response setup failed", http.StatusInternalServerError)
			return
		}

		switch name {
		case "echo":
			writeEncrypted(w, nonce, framed, http.StatusOK)
		case "hold":
			// The whole request has been read; keep the response pending long
			// enough for the client to be observed mid-flight (SPEC 6: the
			// session recovery token must exist before any response). Adapters
			// probe at 500 ms, so this is a 10x timing margin, not a handshake.
			time.Sleep(5 * time.Second)
			writeEncrypted(w, nonce, framed, http.StatusOK)
		case "empty_encrypted":
			// A valid encrypted response with a nonce but zero frames; the client
			// must decrypt it to an empty body.
			emptyNonce, emptyFramed, e := sealResponse(id, respCtx, nil)
			if e != nil {
				http.Error(w, "response setup failed", http.StatusInternalServerError)
				return
			}
			writeEncrypted(w, emptyNonce, emptyFramed, http.StatusOK)
		case "drop_nonce_200":
			writeEncrypted(w, "", framed, http.StatusOK)
		case "empty_nonce_200", "empty_nonce_502":
			// The header is present with an empty value: malformed, not absent
			// (SPEC 4.2), whatever the status.
			w.Header().Set(protocol.ResponseNonceHeader, "")
			w.Header().Set("Content-Type", "application/octet-stream")
			if name == "empty_nonce_200" {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusBadGateway)
			}
			_, _ = w.Write(framed)
		case "invalid_nonce_0x":
			writeEncrypted(w, "0x"+nonce[:62], framed, http.StatusOK)
		case "invalid_nonce_space":
			writeEncrypted(w, nonce[:10]+" "+nonce[11:], framed, http.StatusOK)
		case "encrypted_422_problem":
			// A 422 that carries a nonce is ciphertext like any other response
			// (SPEC 5.1); it is never a key-config problem.
			problem := `{"type":"` + protocol.KeyConfigProblemType + `","title":"encrypted"}`
			pNonce, pFramed, e := sealResponse(id, respCtx, []byte(problem))
			if e != nil {
				http.Error(w, "response setup failed", http.StatusInternalServerError)
				return
			}
			w.Header().Set(protocol.ResponseNonceHeader, pNonce)
			w.Header().Set("Content-Type", protocol.ProblemJSONMediaType)
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write(pFramed)
		case "invalid_nonce_len":
			writeEncrypted(w, hex.EncodeToString(make([]byte, 16)), framed, http.StatusOK)
		case "invalid_nonce_hex":
			writeEncrypted(w, strings.Repeat("z", 64), framed, http.StatusOK)
		case "invalid_nonce_odd_hex":
			writeEncrypted(w, strings.Repeat("0", 63), framed, http.StatusOK)
		case "invalid_nonce_too_long":
			writeEncrypted(w, hex.EncodeToString(make([]byte, 33)), framed, http.StatusOK)
		case "duplicate_nonce":
			w.Header().Add(protocol.ResponseNonceHeader, nonce)
			w.Header().Add(protocol.ResponseNonceHeader, nonce)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(framed)
		case "truncate_final_frame", "tamper_tag":
			if len(framed) == 0 {
				// An empty plaintext seals to zero frames; nothing to mutate.
				http.Error(w, "scenario needs a non-empty request body", http.StatusBadRequest)
				return
			}
			bad := append([]byte(nil), framed...)
			if name == "truncate_final_frame" {
				bad = bad[:len(bad)-1]
			} else {
				bad[len(bad)-1] ^= 0x01
			}
			writeEncrypted(w, nonce, bad, http.StatusOK)
		case "wrong_nonce":
			badNonce, _ := hex.DecodeString(nonce)
			badNonce[0] ^= 1
			writeEncrypted(w, hex.EncodeToString(badNonce), framed, http.StatusOK)
		case "partial_prefix_1":
			writeEncrypted(w, nonce, []byte{0}, http.StatusOK)
		case "partial_prefix_2":
			writeEncrypted(w, nonce, []byte{0, 0}, http.StatusOK)
		case "partial_prefix_3":
			writeEncrypted(w, nonce, []byte{0, 0, 0}, http.StatusOK)
		case "ciphertext_shorter_than_tag":
			short := append([]byte{0, 0, 0, 15}, make([]byte, 15)...)
			writeEncrypted(w, nonce, short, http.StatusOK)
		case "zero_frame_flood":
			flooded := append(bytes.Repeat([]byte{0}, 4*4096), framed...)
			writeEncrypted(w, nonce, flooded, http.StatusOK)
		case "encrypted_error_500":
			writeEncrypted(w, nonce, framed, http.StatusInternalServerError)
		case "oversized_chunk":
			oversized := append([]byte{0xff, 0xff, 0xff, 0xff}, make([]byte, 16)...)
			writeEncrypted(w, nonce, oversized, http.StatusOK)
		default:
			http.Error(w, "unknown scenario", http.StatusNotFound)
		}
	}
}

// sealAndWrite seals body under the request's response context and writes it
// as an encrypted 200. Used by every scenario that answers with an unmodified
// encrypted reply (echo, shape, digest); mutating scenarios call sealResponse
// and writeEncrypted themselves.
func sealAndWrite(w http.ResponseWriter, id *identity.Identity, respCtx *identity.ResponseContext, body []byte) {
	nonce, framed, err := sealResponse(id, respCtx, body)
	if err != nil {
		http.Error(w, "response setup failed", http.StatusInternalServerError)
		return
	}
	writeEncrypted(w, nonce, framed, http.StatusOK)
}

// sealResponse derives a correct EHBP response for the request context and
// returns its nonce header value and framed ciphertext, using only the public
// identity API via an in-memory recorder.
func sealResponse(id *identity.Identity, respCtx *identity.ResponseContext, body []byte) (string, []byte, error) {
	rec := httptest.NewRecorder()
	dw, err := id.SetupDerivedResponseEncryption(rec, respCtx)
	if err != nil {
		return "", nil, err
	}
	if _, err := dw.Write(body); err != nil {
		return "", nil, err
	}
	return rec.Header().Get(protocol.ResponseNonceHeader), rec.Body.Bytes(), nil
}

func writeEncrypted(w http.ResponseWriter, nonce string, body []byte, status int) {
	if nonce != "" {
		w.Header().Set(protocol.ResponseNonceHeader, nonce)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
