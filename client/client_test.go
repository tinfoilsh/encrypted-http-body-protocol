package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// echoServer serves the key configuration and an encrypted echo of the body at /secure.
func echoServer(t *testing.T) (*identity.Identity, *httptest.Server) {
	t.Helper()
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc(protocol.KeysPath, id.ConfigHandler)
	mux.Handle("/secure", id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte("Hello, " + string(body)))
	})))
	mux.Handle("/plain", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("plaintext")) }))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return id, srv
}

func post(t *testing.T, c *http.Client, url, body string) string {
	t.Helper()
	resp, err := c.Post(url, "text/plain", strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(got)
}

// Every KeySource drives the same exchange through http.Client.
func TestNewKeySources(t *testing.T) {
	id, srv := echoServer(t)
	cfg, err := id.MarshalConfig()
	require.NoError(t, err)
	discovered, err := Discover(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, id.MarshalPublicKey(), discovered)

	for name, keys := range map[string]KeySource{"discover": Discovered(), "config": Config(cfg), "public key": PublicKey(id.MarshalPublicKey())} {
		t.Run(name, func(t *testing.T) {
			tr, err := New(srv.URL, keys)
			require.NoError(t, err)
			assert.Equal(t, "Hello, test", post(t, &http.Client{Transport: tr}, srv.URL+"/secure", "test"))
		})
	}

	_, err = New(srv.URL, nil)
	assert.Equal(t, protocol.InvalidInput, protocol.CodeOf(err))
	_, err = New(srv.URL, PublicKey([]byte{1, 2, 3}))
	assert.Equal(t, protocol.InvalidKeyConfig, protocol.CodeOf(err))
	_, err = New("http://user:pass@configured.example", Config(cfg))
	assert.Equal(t, protocol.InvalidInput, protocol.CodeOf(err))
}

func TestStreamingResponseThroughHTTPClient(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	srv := httptest.NewServer(id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 1; i <= 3; i++ {
			fmt.Fprintf(w, "Number: %d\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	})))
	defer srv.Close()
	tr, err := New(srv.URL, PublicKey(id.MarshalPublicKey()))
	require.NoError(t, err)
	assert.Equal(t, "Number: 1\nNumber: 2\nNumber: 3\n", post(t, &http.Client{Transport: tr}, srv.URL, "x"))
}

// A 101 hands the connection to another protocol; without a nonce it is not
// an error to pass through, and its bytes must not reach the caller.
func TestTransportRejectsNonceLessProtocolSwitch(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: forged\r\n\r\nforged answer")
		_ = buf.Flush()
	}))
	defer srv.Close()

	tr, err := New(srv.URL, PublicKey(id.MarshalPublicKey()))
	require.NoError(t, err)
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader("secret"))
	resp, err := tr.RoundTrip(req)
	assert.Nil(t, resp)
	assert.Equal(t, protocol.MissingResponseNonce, protocol.CodeOf(err))
}

// httputil.ReverseProxy drives a RoundTripper with an inbound request, whose
// RequestURI http.Client.Do rejects; the transport must clear it before sending.
func TestTransportClearsRequestURI(t *testing.T) {
	id, srv := echoServer(t)
	tr, err := New(srv.URL, PublicKey(id.MarshalPublicKey()))
	require.NoError(t, err)

	req, _ := http.NewRequest("POST", srv.URL+"/secure", strings.NewReader("test"))
	req.RequestURI = "/secure"
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Hello, test", string(body))
}

// A buffering middlebox re-frames the encrypted reply with a Content-Length;
// that header describes the ciphertext and must not survive onto the
// decrypted response, or a reverse proxy announces more bytes than it writes.
func TestTransportBehindReverseProxyNonStreaming(t *testing.T) {
	_, backend := echoServer(t)
	buffering := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(r.Method, backend.URL+r.URL.Path, r.Body)
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		encrypted, _ := io.ReadAll(resp.Body)
		for key, values := range resp.Header {
			w.Header()[key] = values
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(encrypted)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(encrypted)
	}))
	defer buffering.Close()

	tr, err := New(buffering.URL, Discover)
	require.NoError(t, err)

	req, _ := http.NewRequest("POST", buffering.URL+"/secure", strings.NewReader("test"))
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Empty(t, resp.Header.Get("Content-Length"))
	assert.Equal(t, int64(-1), resp.ContentLength)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Hello, test", string(body))

	target, _ := url.Parse(buffering.URL)
	reverseProxy := httputil.NewSingleHostReverseProxy(target)
	reverseProxy.Transport = tr
	proxy := httptest.NewServer(reverseProxy)
	defer proxy.Close()
	assert.Equal(t, "Hello, test", post(t, http.DefaultClient, proxy.URL+"/secure", "test"))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// req.Host is Go's own override of the wire Host; it must follow the validated URL.
func TestTransportHostHeaderFollowsURL(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	var wireHost string
	recorder := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		wireHost = req.Host
		return &http.Response{StatusCode: http.StatusBadGateway, Header: http.Header{}, Body: http.NoBody}, nil
	})
	tr, err := New("http://configured.example", PublicKey(id.MarshalPublicKey()), WithHTTPClient(&http.Client{Transport: recorder}))
	require.NoError(t, err)

	req, _ := http.NewRequest("POST", "http://configured.example/probe", strings.NewReader("x"))
	req.Host = "attacker.invalid"
	_, _ = tr.RoundTrip(req)
	assert.Equal(t, "", wireHost, "an empty Host makes net/http derive it from the URL")
}

func TestWithHTTPClient(t *testing.T) {
	id, srv := echoServer(t)
	var sent int
	rec := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		sent++
		return http.DefaultTransport.RoundTrip(req)
	})
	tr, err := New(srv.URL, PublicKey(id.MarshalPublicKey()), WithHTTPClient(&http.Client{Transport: rec}))
	require.NoError(t, err)
	assert.Equal(t, "Hello, test", post(t, &http.Client{Transport: tr}, srv.URL+"/secure", "test"))
	assert.Equal(t, 1, sent, "injected http client must be used to send encrypted requests")

	// A nil client must not null out the default, which would panic on use.
	tr, err = New("http://example.test", PublicKey(id.MarshalPublicKey()), WithHTTPClient(nil))
	require.NoError(t, err)
	assert.NotNil(t, tr.httpClient)
}

// A stale key is surfaced as identity.KeyConfigError, the Go error type callers rekey on.
func TestTransportReturnsErrorOnKeyConfigMismatch(t *testing.T) {
	stale, err := identity.NewIdentity()
	require.NoError(t, err)
	current, err := identity.NewIdentity()
	require.NoError(t, err)
	srv := httptest.NewServer(current.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	defer srv.Close()

	tr, err := New(srv.URL, PublicKey(stale.MarshalPublicKey()))
	require.NoError(t, err)
	_, err = (&http.Client{Transport: tr}).Post(srv.URL, "text/plain", strings.NewReader("test"))
	assert.True(t, identity.IsKeyConfigError(err), "%v", err)
}

func TestTransportSessionRecoveryToken(t *testing.T) {
	_, srv := echoServer(t)
	tr, err := New(srv.URL, Discover)
	require.NoError(t, err)
	c := &http.Client{Transport: tr}
	assert.Nil(t, tr.SessionRecoveryToken(), "nil before any request")

	resp, err := c.Post(srv.URL+"/secure", "text/plain", strings.NewReader("test"))
	require.NoError(t, err)
	token := tr.SessionRecoveryToken()
	require.NotNil(t, token)
	assert.Len(t, token.ExportedSecret, 32)
	assert.Len(t, token.RequestEnc, 32)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Nil(t, tr.SessionRecoveryToken(), "cleared after full consumption")

	resp, err = c.Post(srv.URL+"/secure", "text/plain", strings.NewReader("test"))
	require.NoError(t, err)
	second := tr.SessionRecoveryToken()
	require.NotNil(t, second)
	assert.NotEqual(t, token.ExportedSecret, second.ExportedSecret, "each request has its own token")
	require.NoError(t, resp.Body.Close())
	assert.Nil(t, tr.SessionRecoveryToken(), "cleared when the body is closed before EOF (SPEC 6.3)")

	resp, err = c.Post(srv.URL+"/secure", "text/plain", strings.NewReader("test"))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.NotNil(t, tr.SessionRecoveryToken())
	plain, err := c.Get(srv.URL + "/plain")
	require.NoError(t, err)
	defer plain.Body.Close()
	assert.Nil(t, tr.SessionRecoveryToken(), "a bodyless request clears the token")
}

// Two exchanges in flight on one Transport: the latest owns the token, and an
// older response completing and closing must not touch it.
func TestConcurrentExchangesLatestOwnsRecoveryToken(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	firstStarted, releaseFirst := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) == "first" {
			close(firstStarted)
			<-releaseFirst
		}
		_, _ = w.Write([]byte("ok"))
	})))
	defer srv.Close()
	tr, err := New(srv.URL, PublicKey(id.MarshalPublicKey()))
	require.NoError(t, err)
	c := &http.Client{Transport: tr}

	initial, err := c.Post(srv.URL, "text/plain", strings.NewReader("initial"))
	require.NoError(t, err)
	initialToken := tr.SessionRecoveryToken()
	require.NotNil(t, initialToken)
	initial.Body.Close()

	firstResult := make(chan error, 1)
	go func() {
		resp, err := c.Post(srv.URL, "text/plain", strings.NewReader("first"))
		if err == nil {
			resp.Body.Close()
		}
		firstResult <- err
	}()
	<-firstStarted
	// SPEC 6: the new exchange's token replaces the old one as soon as the
	// request is sent, so a crash while the response is pending can recover.
	inFlight := tr.SessionRecoveryToken()
	require.NotNil(t, inFlight)
	assert.NotEqual(t, initialToken.RequestEnc, inFlight.RequestEnc)

	second, err := c.Post(srv.URL, "text/plain", strings.NewReader("second"))
	require.NoError(t, err)
	secondToken := append([]byte(nil), tr.SessionRecoveryToken().RequestEnc...)
	assert.NotEqual(t, inFlight.RequestEnc, secondToken)

	close(releaseFirst)
	require.NoError(t, <-firstResult)
	assert.Equal(t, secondToken, tr.SessionRecoveryToken().RequestEnc, "an older response completing and closing must not replace or clear the latest token")
	second.Body.Close()
	assert.Nil(t, tr.SessionRecoveryToken(), "closing the latest body consumes its token")
}

func TestOlderStreamFailurePreservesNewerRecoveryToken(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	srv := httptest.NewServer(id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("encrypted response"))
	})))
	defer srv.Close()

	// Corrupts the first encrypted response only.
	var mu sync.Mutex
	corrupted := false
	corrupting := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		if corrupted {
			return resp, nil
		}
		corrupted = true
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body[len(body)-1] ^= 1
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	})
	tr, err := New(srv.URL, PublicKey(id.MarshalPublicKey()), WithHTTPClient(&http.Client{Transport: corrupting}))
	require.NoError(t, err)

	firstReq, _ := http.NewRequest("POST", srv.URL, strings.NewReader("first"))
	firstResp, err := tr.RoundTrip(firstReq)
	require.NoError(t, err)
	defer firstResp.Body.Close()
	secondReq, _ := http.NewRequest("POST", srv.URL, strings.NewReader("second"))
	secondResp, err := tr.RoundTrip(secondReq)
	require.NoError(t, err)
	defer secondResp.Body.Close()
	newer := append([]byte(nil), tr.SessionRecoveryToken().RequestEnc...)

	_, err = io.ReadAll(firstResp.Body)
	assert.Equal(t, protocol.AEADDecryptFailed, protocol.CodeOf(err))
	assert.Equal(t, newer, tr.SessionRecoveryToken().RequestEnc)
}

// refusingH2CServer speaks just enough prior-knowledge HTTP/2 to refuse the
// first stream it sees, as a TLS-terminating gateway may, and reset every later
// one. It returns the request body received on each stream.
func refusingH2CServer(t *testing.T) (string, func() [][]byte) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var bodies [][]byte
	refused := false

	serve := func(c net.Conn) {
		defer c.Close()
		writeFrame := func(typ, flags byte, stream uint32, payload []byte) {
			hdr := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(hdr[5:], stream)
			_, _ = c.Write(append(hdr, payload...))
		}
		if _, err := io.ReadFull(c, make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))); err != nil {
			return
		}
		writeFrame(0x4, 0, 0, nil) // SETTINGS
		streams := map[uint32][]byte{}
		hdr := make([]byte, 9)
		for {
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			payload := make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2]))
			if _, err := io.ReadFull(c, payload); err != nil {
				return
			}
			typ, flags, stream := hdr[3], hdr[4], binary.BigEndian.Uint32(hdr[5:])&0x7fffffff
			switch {
			case typ == 0x4 && flags&0x1 == 0:
				writeFrame(0x4, 0x1, 0, nil) // SETTINGS ACK
			case typ == 0x0:
				streams[stream] = append(streams[stream], payload...)
				if flags&0x1 == 0 {
					continue
				}
				mu.Lock()
				bodies = append(bodies, streams[stream])
				code := uint32(0x2) // INTERNAL_ERROR, not retryable
				if !refused {
					refused, code = true, 0x7 // REFUSED_STREAM
				}
				mu.Unlock()
				writeFrame(0x3, 0, stream, binary.BigEndian.AppendUint32(nil, code))
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			go serve(c)
		}
	}()

	return "http://" + ln.Addr().String(), func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return bodies
	}
}

func TestTransportDoesNotReplayPlaintextOnRefusedStream(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	serverURL, bodies := refusingH2CServer(t)

	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	h2c := &http.Transport{Protocols: &protocols}
	defer h2c.CloseIdleConnections()
	tr, err := New(serverURL, PublicKey(id.MarshalPublicKey()), WithHTTPClient(&http.Client{Transport: h2c}))
	require.NoError(t, err)

	const secret = "plaintext that only the enclave may read"
	// bytes.Reader makes http.NewRequest set GetBody, as most SDKs do.
	req, _ := http.NewRequest("POST", serverURL+"/secure", bytes.NewReader([]byte(secret)))
	require.NotNil(t, req.GetBody)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err == nil {
		resp.Body.Close()
	}
	assert.Error(t, err)

	got := bodies()
	assert.NotEmpty(t, got, "server must have received the encrypted request")
	for i, body := range got {
		assert.NotContains(t, string(body), secret, "stream %d carried the plaintext body", i)
	}
}

// pausingReader yields its parts one per read, with a read of no bytes and no
// error before each, as io.Reader permits.
type pausingReader struct {
	parts  []string
	paused bool
}

func (r *pausingReader) Read(p []byte) (int, error) {
	if len(r.parts) == 0 {
		return 0, io.EOF
	}
	if !r.paused {
		r.paused = true
		return 0, nil
	}
	r.paused = false
	n := copy(p, r.parts[0])
	r.parts = r.parts[1:]
	return n, nil
}

func TestTransportSendsTheWholeBodyAcrossEmptyReads(t *testing.T) {
	id, srv := echoServer(t)
	tr, err := New(srv.URL, PublicKey(id.MarshalPublicKey()))
	require.NoError(t, err)
	req, _ := http.NewRequest("POST", srv.URL+"/secure", &pausingReader{parts: []string{"first part, ", "second part"}})
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Hello, first part, second part", string(body))
}

func TestInformationalResponseKeepsTheFinalStatus(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	srv := httptest.NewServer(id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	})))
	defer srv.Close()
	tr, err := New(srv.URL, PublicKey(id.MarshalPublicKey()))
	require.NoError(t, err)
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader("secret"))
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "forbidden", string(body))
}

// Cancelling the request context unblocks a RoundTrip waiting on a body that
// never yields.
func TestCancelWhileWaitingForRequestBody(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	tr, err := New("http://example.test", PublicKey(id.MarshalPublicKey()))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	reader, writer := io.Pipe()
	defer writer.Close()
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://example.test/", reader)
	done := make(chan error, 1)
	go func() {
		resp, err := tr.RoundTrip(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		assert.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not unblock the request body")
	}
}
