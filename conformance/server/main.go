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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"

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

	// Two auxiliary key-config endpoints on port+1 and port+2 let discovery
	// robustness be tested without disturbing the valid config on the main port.
	if host, portStr, err := net.SplitHostPort(*addr); err == nil {
		if port, err := strconv.Atoi(portStr); err == nil {
			go serveBadConfig(net.JoinHostPort(host, strconv.Itoa(port+1)), id, "bad-ct")
			go serveBadConfig(net.JoinHostPort(host, strconv.Itoa(port+2)), id, "non200")
		}
	}

	log.Printf("oracle: listening on %s, public key %s", *addr, id.MarshalPublicKeyHex())
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// serveBadConfig answers /.well-known/hpke-keys with a malformed discovery
// response: "bad-ct" returns the valid config bytes under the wrong content type;
// "non200" returns a 500.
func serveBadConfig(addr string, id *identity.Identity, mode string) {
	mux := http.NewServeMux()
	mux.HandleFunc(protocol.KeysPath, cors(func(w http.ResponseWriter, r *http.Request) {
		if mode == "non200" {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain") // wrong media type
		cfg, _ := id.MarshalConfig()
		_, _ = w.Write(cfg)
	}))
	_ = http.ListenAndServe(addr, mux)
}

// cors allows the browser adapter (a cross-origin page) to reach the oracle and
// to read the EHBP response headers.
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Ehbp-Encapsulated-Key")
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
			nonce, framed, err := sealResponse(id, respCtx, plaintext)
			if err != nil {
				http.Error(w, "response setup failed", http.StatusInternalServerError)
				return
			}
			writeEncrypted(w, nonce, framed, http.StatusOK)
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
		case "invalid_nonce_len":
			writeEncrypted(w, hex.EncodeToString(make([]byte, 16)), framed, http.StatusOK)
		case "duplicate_nonce":
			w.Header().Add(protocol.ResponseNonceHeader, nonce)
			w.Header().Add(protocol.ResponseNonceHeader, nonce)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(framed)
		case "truncate_final_frame":
			writeEncrypted(w, nonce, framed[:len(framed)-1], http.StatusOK)
		case "tamper_tag":
			bad := append([]byte(nil), framed...)
			bad[len(bad)-1] ^= 0x01
			writeEncrypted(w, nonce, bad, http.StatusOK)
		case "oversized_chunk":
			oversized := append([]byte{0xff, 0xff, 0xff, 0xff}, make([]byte, 16)...)
			writeEncrypted(w, nonce, oversized, http.StatusOK)
		default:
			http.Error(w, "unknown scenario", http.StatusNotFound)
		}
	}
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
