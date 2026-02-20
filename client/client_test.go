package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

func TestSecureClient(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	assert.NoError(t, err)

	middleware := serverIdentity.Middleware()

	mux := http.NewServeMux()
	mux.HandleFunc(protocol.KeysPath, serverIdentity.ConfigHandler)

	mux.Handle("/secure", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}

		if _, err := w.Write([]byte("Hello, " + string(body))); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})))

	mux.Handle("/stream", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Transfer-Encoding", "chunked")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}

		for i := 1; i <= 10; i++ {
			_, err := fmt.Fprintf(w, "Number: %d\n", i)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			flusher.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})))

	server := httptest.NewServer(mux)
	defer server.Close()

	secureTransport, err := NewTransport(server.URL)
	assert.NoError(t, err)
	httpClient := &http.Client{
		Transport: secureTransport,
	}

	t.Run("secure endpoint", func(t *testing.T) {
		req, err := http.NewRequest("POST", server.URL+"/secure", bytes.NewBuffer([]byte("test")))
		assert.NoError(t, err)

		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "Hello, test", string(body))
	})

	t.Run("streaming endpoint", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/stream", nil)
		assert.NoError(t, err)

		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		var completeResponse strings.Builder
		buf := make([]byte, 1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				completeResponse.WriteString(string(buf[:n]))
			}

			if err == io.EOF {
				break
			}

			if err != nil {
				assert.NoError(t, err)
				break
			}
		}

		assert.Equal(t, "Number: 1\nNumber: 2\nNumber: 3\nNumber: 4\nNumber: 5\nNumber: 6\nNumber: 7\nNumber: 8\nNumber: 9\nNumber: 10\n", completeResponse.String())
	})
}

func TestTransportReturnsErrorOnKeyConfigMismatch(t *testing.T) {
	identityA, err := identity.NewIdentity()
	assert.NoError(t, err)
	identityB, err := identity.NewIdentity()
	assert.NoError(t, err)

	var (
		mu     sync.RWMutex
		active = identityA
	)

	secureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("Hello, " + string(body)))
	})

	mux := http.NewServeMux()
	mux.HandleFunc(protocol.KeysPath, func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		current := active
		mu.RUnlock()
		current.ConfigHandler(w, r)
	})
	mux.Handle("/secure", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		current := active
		mu.RUnlock()
		current.Middleware()(secureHandler).ServeHTTP(w, r)
	}))

	server := httptest.NewServer(mux)
	defer server.Close()

	transport, err := NewTransport(server.URL)
	assert.NoError(t, err)

	// Rotate key after client initialization to force a stale-key attempt.
	mu.Lock()
	active = identityB
	mu.Unlock()

	httpClient := &http.Client{Transport: transport}
	req, err := http.NewRequest("POST", server.URL+"/secure", bytes.NewBuffer([]byte("test")))
	assert.NoError(t, err)

	_, err = httpClient.Do(req)
	assert.Error(t, err)
	assert.True(t, identity.IsKeyConfigError(err))
}

func TestTransportGetSessionRecoveryToken(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	assert.NoError(t, err)

	middleware := serverIdentity.Middleware()

	mux := http.NewServeMux()
	mux.HandleFunc(protocol.KeysPath, serverIdentity.ConfigHandler)

	mux.Handle("/secure", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Hello, " + string(body)))
	})))

	mux.Handle("/plain", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("plaintext"))
	}))

	server := httptest.NewServer(mux)
	defer server.Close()

	transport, err := NewTransport(server.URL)
	assert.NoError(t, err)
	httpClient := &http.Client{Transport: transport}

	t.Run("nil before any request", func(t *testing.T) {
		token := transport.GetSessionRecoveryToken()
		assert.Nil(t, token)
	})

	t.Run("available after POST with body", func(t *testing.T) {
		req, err := http.NewRequest("POST", server.URL+"/secure", bytes.NewBuffer([]byte("test")))
		assert.NoError(t, err)

		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		io.ReadAll(resp.Body)

		token := transport.GetSessionRecoveryToken()
		assert.NotNil(t, token)
		assert.Len(t, token.ExportedSecret, 32)
		assert.Len(t, token.RequestEnc, 32)
	})

	t.Run("updates on each new request", func(t *testing.T) {
		req1, _ := http.NewRequest("POST", server.URL+"/secure", bytes.NewBuffer([]byte("req1")))
		resp1, err := httpClient.Do(req1)
		assert.NoError(t, err)
		resp1.Body.Close()
		token1 := transport.GetSessionRecoveryToken()

		req2, _ := http.NewRequest("POST", server.URL+"/secure", bytes.NewBuffer([]byte("req2")))
		resp2, err := httpClient.Do(req2)
		assert.NoError(t, err)
		resp2.Body.Close()
		token2 := transport.GetSessionRecoveryToken()

		assert.NotEqual(t, token1.ExportedSecret, token2.ExportedSecret,
			"Tokens from different requests must have different exported secrets")
	})

	t.Run("cleared for bodyless requests", func(t *testing.T) {
		// First make a POST to set a token
		req1, _ := http.NewRequest("POST", server.URL+"/secure", bytes.NewBuffer([]byte("body")))
		resp1, err := httpClient.Do(req1)
		assert.NoError(t, err)
		resp1.Body.Close()
		assert.NotNil(t, transport.GetSessionRecoveryToken())

		// GET without body should clear the token
		req2, _ := http.NewRequest("GET", server.URL+"/plain", nil)
		resp2, err := httpClient.Do(req2)
		assert.NoError(t, err)
		resp2.Body.Close()

		assert.Nil(t, transport.GetSessionRecoveryToken(),
			"Token should be cleared after bodyless request")
	})
}
