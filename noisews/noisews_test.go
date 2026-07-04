package noisews

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newTestServer(t *testing.T, handle func(conn *Conn, r *http.Request), opts ...Option) (*httptest.Server, *identity.Identity) {
	t.Helper()
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}
	srv, err := NewServer(id, opts...)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler(handle))
	t.Cleanup(ts.Close)
	return ts, id
}

func publicOnly(t *testing.T, id *identity.Identity) *identity.Identity {
	t.Helper()
	pub, err := identity.FromPublicKeyBytes(id.MarshalPublicKey())
	if err != nil {
		t.Fatalf("failed to build public-only identity: %v", err)
	}
	return pub
}

func echoUntilError(errCh chan<- error) func(conn *Conn, r *http.Request) {
	return func(conn *Conn, r *http.Request) {
		for {
			msg, err := conn.Read(r.Context())
			if err != nil {
				errCh <- err
				return
			}
			if err := conn.Write(r.Context(), msg); err != nil {
				errCh <- err
				return
			}
		}
	}
}

func TestEchoRoundTripAndCleanClose(t *testing.T) {
	ctx := testContext(t)
	errCh := make(chan error, 1)
	ts, id := newTestServer(t, echoUntilError(errCh))

	conn, err := Dial(ctx, ts.URL, publicOnly(t, id))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	for _, msg := range []string{"hello", "", "second message"} {
		if err := conn.Write(ctx, []byte(msg)); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		got, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if string(got) != msg {
			t.Fatalf("echo mismatch: got %q, want %q", got, msg)
		}
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("server should see clean EOF, got: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for server close")
	}

	if err := conn.Write(ctx, []byte("after close")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after close should return ErrClosed, got: %v", err)
	}
}

func TestWrongServerKeyFailsHandshake(t *testing.T) {
	ctx := testContext(t)
	errCh := make(chan error, 1)
	ts, _ := newTestServer(t, echoUntilError(errCh))

	wrongID, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	if _, err := Dial(ctx, ts.URL, publicOnly(t, wrongID)); err == nil {
		t.Fatal("dial with wrong server key should fail")
	}
}

func TestDialHandshakeFailureClosesImmediately(t *testing.T) {
	ctx := testContext(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{protocol.WSSubprotocol},
		})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		_, _, _ = ws.Read(r.Context())
		_ = ws.Write(r.Context(), websocket.MessageBinary, []byte{0})
		<-r.Context().Done()
	}))
	t.Cleanup(ts.Close)

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	start := time.Now()
	if _, err := Dial(ctx, ts.URL, publicOnly(t, id)); err == nil {
		t.Fatal("dial should fail on invalid handshake message")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dial took too long after handshake failure: %v", elapsed)
	}
}

func TestDialHandshakeTimeout(t *testing.T) {
	ctx := testContext(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{protocol.WSSubprotocol},
		})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		// Read the client's handshake message but never reply, simulating
		// a stalled or hostile peer.
		_, _, _ = ws.Read(r.Context())
		<-r.Context().Done()
	}))
	t.Cleanup(ts.Close)

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	start := time.Now()
	if _, err := Dial(ctx, ts.URL, publicOnly(t, id), WithHandshakeTimeout(200*time.Millisecond)); err == nil {
		t.Fatal("dial should time out waiting for the handshake reply")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("dial took too long to time out: %v", elapsed)
	}
}

func TestTamperedRecordFailsClosed(t *testing.T) {
	ctx := testContext(t)
	errCh := make(chan error, 1)
	ts, id := newTestServer(t, echoUntilError(errCh))

	conn, err := Dial(ctx, ts.URL, publicOnly(t, id))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	record := []byte{recordData, 'h', 'i'}
	ciphertext, err := conn.send.Encrypt(nil, nil, record)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	ciphertext[0] ^= 0xFF
	if err := conn.ws.Write(ctx, websocket.MessageBinary, ciphertext); err != nil {
		t.Fatalf("raw write failed: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "decrypt") {
			t.Fatalf("server should fail with decrypt error, got: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for server error")
	}

	_, firstErr := conn.Read(ctx)
	if firstErr == nil {
		t.Fatal("client read should fail after server closed the connection")
	}
	if !errors.Is(firstErr, ErrTruncated) {
		t.Fatalf("client should see truncation, got: %v", firstErr)
	}
	if _, secondErr := conn.Read(ctx); !errors.Is(secondErr, ErrTruncated) {
		t.Fatalf("read errors should be sticky, got: %v", secondErr)
	}
}

func TestLocalCloseUnblocksReader(t *testing.T) {
	ctx := testContext(t)
	errCh := make(chan error, 1)
	ts, id := newTestServer(t, echoUntilError(errCh))

	conn, err := Dial(ctx, ts.URL, publicOnly(t, id))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	readErrCh := make(chan error, 1)
	readStarted := make(chan struct{})
	go func() {
		close(readStarted)
		_, err := conn.Read(ctx)
		readErrCh <- err
	}()

	<-readStarted
	if err := conn.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	select {
	case err := <-readErrCh:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("blocked reader should see ErrClosed after local close, got: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for reader to unblock")
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("server should see clean EOF, got: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for server close")
	}
}

func TestServerHandshakeTimeout(t *testing.T) {
	ctx := testContext(t)
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}
	srv, err := NewServer(id, WithHandshakeTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	upgradeErrCh := make(chan error, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := srv.Upgrade(w, r)
		upgradeErrCh <- err
	}))
	t.Cleanup(ts.Close)

	// Connect with the right subprotocol but never send the handshake message.
	ws, _, err := websocket.Dial(ctx, ts.URL, &websocket.DialOptions{
		Subprotocols:    []string{protocol.WSSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		t.Fatalf("raw dial failed: %v", err)
	}
	defer ws.CloseNow()

	select {
	case err := <-upgradeErrCh:
		if err == nil || !strings.Contains(err.Error(), "read handshake") {
			t.Fatalf("upgrade should time out reading the handshake, got: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for upgrade to fail")
	}
}

func TestTruncationDetected(t *testing.T) {
	ctx := testContext(t)
	errCh := make(chan error, 1)
	ts, id := newTestServer(t, echoUntilError(errCh))

	conn, err := Dial(ctx, ts.URL, publicOnly(t, id))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	if err := conn.Write(ctx, []byte("last message")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	// Close the WebSocket without sending an encrypted close record,
	// simulating truncation by an intermediary.
	if err := conn.ws.Close(websocket.StatusNormalClosure, ""); err != nil {
		t.Fatalf("raw close failed: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("server should detect truncation, got: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for server error")
	}
}

func TestRekeyKeepsDirectionsInSync(t *testing.T) {
	oldRekeyEvery := rekeyEvery.Load()
	rekeyEvery.Store(3)
	t.Cleanup(func() { rekeyEvery.Store(oldRekeyEvery) })

	ctx := testContext(t)
	errCh := make(chan error, 1)
	ts, id := newTestServer(t, echoUntilError(errCh))

	conn, err := Dial(ctx, ts.URL, publicOnly(t, id))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("x"), 100)
	for i := range 10 {
		if err := conn.Write(ctx, payload); err != nil {
			t.Fatalf("write %d failed: %v", i, err)
		}
		got, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read %d failed: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch on message %d", i)
		}
	}
}

func TestOversizedWriteRejected(t *testing.T) {
	ctx := testContext(t)
	errCh := make(chan error, 1)
	ts, id := newTestServer(t, echoUntilError(errCh), WithMaxMessageSize(16))

	conn, err := Dial(ctx, ts.URL, publicOnly(t, id), WithMaxMessageSize(16))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if err := conn.Write(ctx, bytes.Repeat([]byte("x"), 17)); err == nil {
		t.Fatal("oversized write should fail")
	}
	if err := conn.Write(ctx, bytes.Repeat([]byte("x"), 16)); err != nil {
		t.Fatalf("write at limit should succeed: %v", err)
	}
}

func TestOversizedInboundRecordFailsConnection(t *testing.T) {
	ctx := testContext(t)
	writeErrCh := make(chan error, 1)
	// The server's cap is larger than the client's, so it can produce a
	// record that fits the client's WebSocket read limit margin but
	// exceeds the client's payload cap.
	ts, id := newTestServer(t, func(conn *Conn, r *http.Request) {
		writeErrCh <- conn.Write(r.Context(), bytes.Repeat([]byte("x"), 32))
	}, WithMaxMessageSize(64))

	conn, err := Dial(ctx, ts.URL, publicOnly(t, id), WithMaxMessageSize(16))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("server write failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for server write")
	}

	if _, err := conn.Read(ctx); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("oversized inbound record should fail the connection, got: %v", err)
	}
}

func TestMaxMessageSizeOverflowIgnored(t *testing.T) {
	o := applyOptions([]Option{WithMaxMessageSize(math.MaxInt64)})
	if o.maxMessageSize != DefaultMaxMessageSize {
		t.Fatalf("max message size that would overflow the read limit should be ignored, got %d", o.maxMessageSize)
	}
}

func TestWriteAfterLocalTeardownReturnsErrClosed(t *testing.T) {
	ctx := testContext(t)
	errCh := make(chan error, 1)
	ts, id := newTestServer(t, echoUntilError(errCh))

	conn, err := Dial(ctx, ts.URL, publicOnly(t, id))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	readCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := conn.Read(readCtx); err == nil {
		t.Fatal("read with canceled context should fail")
	}

	if err := conn.Write(ctx, []byte("after teardown")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after local teardown should return ErrClosed, got: %v", err)
	}
}

func TestSubprotocolRequired(t *testing.T) {
	ctx := testContext(t)
	errCh := make(chan error, 1)
	ts, _ := newTestServer(t, echoUntilError(errCh))

	ws, _, err := websocket.Dial(ctx, ts.URL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		t.Fatalf("raw dial failed: %v", err)
	}
	defer ws.CloseNow()

	if _, _, err := ws.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("server should close with policy violation, got: %v", err)
	}
}

func TestServerRequiresPrivateKey(t *testing.T) {
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}
	if _, err := NewServer(publicOnly(t, id)); err == nil {
		t.Fatal("NewServer should reject a public-only identity")
	}
	if _, err := NewServer(nil); err == nil {
		t.Fatal("NewServer should reject a nil identity")
	}
}

func TestOriginPatternsCopied(t *testing.T) {
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}
	patterns := []string{"https://allowed.example"}
	srv, err := NewServer(id, WithOriginPatterns(patterns...))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	patterns[0] = "*"
	if got := srv.originPatterns[0]; got != "https://allowed.example" {
		t.Fatalf("origin patterns should be copied, got %q", got)
	}
}

func TestDialRequiresNegotiatedSubprotocol(t *testing.T) {
	ctx := testContext(t)
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	// A plain WebSocket server that never selects the EHBP subprotocol.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		_, _, _ = ws.Read(r.Context())
	}))
	t.Cleanup(ts.Close)

	if _, err := Dial(ctx, ts.URL, publicOnly(t, id)); err == nil ||
		!strings.Contains(err.Error(), "subprotocol") {
		t.Fatalf("dial should fail on missing subprotocol, got: %v", err)
	}
}
