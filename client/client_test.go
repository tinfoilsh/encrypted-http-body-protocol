package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

func TestSecureClient(t *testing.T) {
	clientIdentity, err := identity.NewIdentity()
	assert.NoError(t, err)
	serverIdentity, err := identity.NewIdentity()
	assert.NoError(t, err)

	// Use v2 middleware - client now uses v2 protocol
	middleware := serverIdentity.Middleware(false)

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

	secureTransport, err := NewTransport(server.URL, clientIdentity, false)
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

		completeResponse := ""
		buf := make([]byte, 1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				completeResponse += string(buf[:n])
			}

			if err == io.EOF {
				break
			}

			if err != nil {
				assert.NoError(t, err)
				break
			}
		}
		assert.Equal(t, "Number: 1\nNumber: 2\nNumber: 3\nNumber: 4\nNumber: 5\nNumber: 6\nNumber: 7\nNumber: 8\nNumber: 9\nNumber: 10\n", completeResponse)
	})
}
