package identity_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	core "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/EHBP"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// testClient encrypts requests with the standard library's HPKE, independent
// of the client package, and keeps the sender to decrypt the response.
type testClient struct {
	sender     *hpke.Sender
	requestEnc []byte
}

// encryptRequest seals the body (if any) as one frame to serverPubKey and sets the key header.
func (c *testClient) encryptRequest(t *testing.T, req *http.Request, serverPubKey []byte) {
	t.Helper()
	pk, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(serverPubKey)
	require.NoError(t, err)
	encapKey, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(identity.HPKERequestInfo))
	require.NoError(t, err)
	c.sender, c.requestEnc = sender, encapKey
	req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(encapKey))
	if req.Body != nil && req.ContentLength != 0 {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		framed := c.frame(t, body)
		req.Body, req.ContentLength = io.NopCloser(bytes.NewReader(framed)), int64(len(framed))
	}
}

func (c *testClient) frame(t *testing.T, plaintext []byte) []byte {
	ct, err := c.sender.Seal(nil, plaintext)
	require.NoError(t, err)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(ct))), ct...)
}

// decryptResponse opens the recorded response with the token this client's sender exports.
func (c *testClient) decryptResponse(t *testing.T, w *httptest.ResponseRecorder) []byte {
	t.Helper()
	exported, err := c.sender.Export(identity.ExportLabel, identity.ExportLength)
	require.NoError(t, err)
	resp := w.Result()
	require.NoError(t, client.Core().DecryptResponse(resp, &client.SessionRecoveryToken{ExportedSecret: exported, RequestEnc: c.requestEnc}))
	defer resp.Body.Close()
	plain, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return plain
}

func TestMiddleware(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	require.NoError(t, err)
	middleware := serverIdentity.Middleware()
	wrapped := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Hello, " + string(body)))
	}))

	t.Run("successful encrypted request", func(t *testing.T) {
		c := &testClient{}
		req := httptest.NewRequest("POST", "/test", bytes.NewBufferString("test message"))
		c.encryptRequest(t, req, serverIdentity.MarshalPublicKey())
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get(protocol.ResponseNonceHeader))
		assert.Equal(t, "Hello, test message", string(c.decryptResponse(t, w)))
	})

	t.Run("missing encapsulated key header passes through as plaintext", func(t *testing.T) {
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, httptest.NewRequest("POST", "/test", strings.NewReader("test")))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "Hello, test", w.Body.String())
		assert.Empty(t, w.Header().Get(protocol.ResponseNonceHeader))
	})

	for name, key := range map[string]string{"invalid encapsulated key": "invalid-hex", "wrong length encapsulated key": "deadbeef"} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
			req.Header.Set(protocol.EncapsulatedKeyHeader, key)
			w := httptest.NewRecorder()
			wrapped.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), "failed to decrypt request")
		})
	}

	t.Run("stale key mismatch returns 422 problem details", func(t *testing.T) {
		otherServer, err := identity.NewIdentity()
		require.NoError(t, err)
		req := httptest.NewRequest("POST", "/test", strings.NewReader("test"))
		(&testClient{}).encryptRequest(t, req, otherServer.MarshalPublicKey())
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		assert.Equal(t, protocol.ProblemJSONMediaType, w.Header().Get("Content-Type"))
		var problem map[string]string
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &problem))
		assert.Equal(t, protocol.KeyConfigProblemType, problem["type"])
		assert.Equal(t, "failed to decrypt request", problem["title"])
	})

	t.Run("key requires an authenticated frame before dispatch", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			body   io.ReadCloser
			length int64
		}{
			{"known empty", http.NoBody, 0},
			{"unknown empty", io.NopCloser(strings.NewReader("")), -1},
			{"empty stream with stale length", io.NopCloser(strings.NewReader("")), 24},
			{"padding only", io.NopCloser(bytes.NewReader(make([]byte, 4))), 4},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest("POST", "/test", nil)
				(&testClient{}).encryptRequest(t, req, serverIdentity.MarshalPublicKey())
				req.Body, req.ContentLength = tc.body, tc.length
				w := httptest.NewRecorder()
				middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("handler ran without an authenticated request frame")
				})).ServeHTTP(w, req)
				assert.Equal(t, http.StatusBadRequest, w.Code)
				assert.Empty(t, w.Header().Get(protocol.ResponseNonceHeader))
			})
		}
	})

	for _, payload := range []string{"", "data"} {
		t.Run("sealed empty frame followed by "+payload, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			c := &testClient{}
			c.encryptRequest(t, req, serverIdentity.MarshalPublicKey())
			framed := append(c.frame(t, nil), c.frame(t, []byte(payload))...)
			req.Body, req.ContentLength = io.NopCloser(bytes.NewReader(framed)), int64(len(framed))
			w := httptest.NewRecorder()
			called := false
			middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				assert.Equal(t, payload, string(body))
				w.WriteHeader(http.StatusCreated)
			})).ServeHTTP(w, req)
			assert.Equal(t, payload != "", called)
			if payload == "" {
				assert.Equal(t, http.StatusBadRequest, w.Code)
				assert.Empty(t, w.Header().Get(protocol.ResponseNonceHeader))
			} else {
				assert.Equal(t, http.StatusCreated, w.Code)
				assert.Empty(t, c.decryptResponse(t, w))
			}
		})
	}
}

func TestStreamingResponseWriter(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	require.NoError(t, err)
	wrapped := serverIdentity.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "24")
		for i := 1; i <= 3; i++ {
			fmt.Fprintf(w, "chunk %d\n", i)
			w.(http.Flusher).Flush()
		}
	}))
	c := &testClient{}
	req := httptest.NewRequest("POST", "/stream", strings.NewReader("test body"))
	c.encryptRequest(t, req, serverIdentity.MarshalPublicKey())
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "chunked", w.Header().Get("Transfer-Encoding"))
	assert.Empty(t, w.Header().Get("Content-Length"))
	assert.Equal(t, "chunk 1\nchunk 2\nchunk 3\n", string(c.decryptResponse(t, w)))
}

// GET, HEAD, DELETE and OPTIONS pass through unencrypted (SPEC 6.4).
func TestBodylessHTTPMethods(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	require.NoError(t, err)
	wrapped := serverIdentity.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Method: " + r.Method))
	}))
	for _, method := range []string{"GET", "HEAD", "DELETE", "OPTIONS"} {
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, httptest.NewRequest(method, "/test", nil))
		assert.Equal(t, http.StatusOK, w.Code, method)
		assert.Empty(t, w.Header().Get(protocol.ResponseNonceHeader), method)
		if method != "HEAD" {
			assert.Equal(t, "Method: "+method, w.Body.String())
		}
	}
}

// A success must carry a frame the client can authenticate (SPEC 5.2/5.3):
// a handler that writes nothing still answers with one, and a 204 or 205 is sent as 200.
func TestMiddlewareAlwaysAnswersWithAFrame(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	require.NoError(t, err)
	for name, handler := range map[string]http.HandlerFunc{
		"no write":  func(w http.ResponseWriter, r *http.Request) { _, _ = io.ReadAll(r.Body) },
		"accepted":  func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) },
		"forbidden": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) },
		"204":       func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) },
		"205":       func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusResetContent) },
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(serverIdentity.Middleware()(handler))
			defer srv.Close()
			tr, err := client.New(srv.URL, client.PublicKey(serverIdentity.MarshalPublicKey()))
			require.NoError(t, err)
			resp, err := (&http.Client{Transport: tr}).Post(srv.URL, "text/plain", strings.NewReader("secret"))
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Empty(t, body)
			want := map[string]int{"accepted": http.StatusAccepted, "forbidden": http.StatusForbidden}[name]
			if want == 0 {
				want = http.StatusOK
			}
			assert.Equal(t, want, resp.StatusCode)
		})
	}
}

// tamperedTrailingRequest returns a framed request body of several 8 KiB
// frames whose last frame fails authentication, plus the encapsulated key.
// frameBytes is the plaintext the client seals per frame (EHBP.RequestFrameBytes).
var frameBytes = int(core.Companion_Default___.RequestFrameBytes())

func tamperedTrailingRequest(t *testing.T, serverIdentity *identity.Identity) ([]byte, string) {
	t.Helper()
	// Two full frames that authenticate, then a short one that is tampered.
	template := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader(bytes.Repeat([]byte("x"), 2*frameBytes+4096)))
	_, err := client.Core().EncryptRequest(serverIdentity.MarshalPublicKey(), template)
	require.NoError(t, err)
	var framed []byte
	buf := make([]byte, 8192)
	for {
		n, rerr := template.Body.Read(buf)
		framed = append(framed, buf[:n]...)
		if rerr == io.EOF {
			break
		}
		require.NoError(t, rerr)
	}
	framed[len(framed)-1] ^= 1
	return framed, template.Header.Get(protocol.EncapsulatedKeyHeader)
}

func TestMiddlewareLateDecryptFailureBeforeResponseStartsIs400(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	require.NoError(t, err)
	framed, enc := tamperedTrailingRequest(t, serverIdentity)

	var delivered int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read everything before acting; the read fails on the last frame and
		// the handler returns without writing, so the middleware answers.
		body, rerr := io.ReadAll(r.Body)
		delivered = len(body)
		if rerr != nil {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(serverIdentity.Middleware()(handler))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/probe", bytes.NewReader(framed))
	req.Header.Set(protocol.EncapsulatedKeyHeader, enc)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Earlier frames authenticated, so the key is right: tampering is a 400,
	// not a stale-key 422 (SPEC 5.4.2).
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Header.Get(protocol.ResponseNonceHeader), "plaintext error must not look encrypted")
	assert.Equal(t, 2*frameBytes, delivered, "the two authenticated frames were released, nothing from the bad one")
}

func TestMiddlewareLateDecryptFailureAfterResponseStartedAbortsConnection(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	require.NoError(t, err)
	framed, enc := tamperedTrailingRequest(t, serverIdentity)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Act on the prefix before the body is complete, as a streaming
		// handler would; the exchange must then not complete cleanly.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		_, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("more"))
	})
	srv := httptest.NewServer(serverIdentity.Middleware()(handler))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/probe", bytes.NewReader(framed))
	req.Header.Set(protocol.EncapsulatedKeyHeader, enc)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = io.ReadAll(resp.Body)
	assert.Error(t, err, "the response must not end as a complete message")
}
