package noisews

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// Server upgrades HTTP requests to Noise-encrypted WebSocket connections,
// acting as the Noise responder authenticated by the identity's static key.
type Server struct {
	static           noise.DHKey
	maxMessageSize   int
	originPatterns   []string
	handshakeTimeout time.Duration
}

// NewServer creates a Server from an identity that holds the private key.
func NewServer(id *identity.Identity, opts ...Option) (*Server, error) {
	static, err := noiseKeypair(id)
	if err != nil {
		return nil, err
	}
	o := applyOptions(opts)
	return &Server{
		static:           static,
		maxMessageSize:   o.maxMessageSize,
		originPatterns:   o.originPatterns,
		handshakeTimeout: o.handshakeTimeout,
	}, nil
}

// Upgrade accepts the WebSocket upgrade and runs the Noise responder
// handshake. On upgrade failure an HTTP error has already been written to w;
// after a failed handshake the WebSocket is closed. The server MUST NOT send
// application data before the handshake completes, which Upgrade enforces by
// only returning a usable Conn afterwards.
func (s *Server) Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{protocol.WSSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
		OriginPatterns:  s.originPatterns,
	})
	if err != nil {
		return nil, fmt.Errorf("noisews: accept: %w", err)
	}
	if ws.Subprotocol() != protocol.WSSubprotocol {
		_ = ws.Close(websocket.StatusPolicyViolation, "ehbp noise subprotocol required")
		return nil, errors.New("noisews: client did not offer required subprotocol")
	}
	ws.SetReadLimit(handshakeReadLimit)

	ctx, cancel := context.WithTimeout(r.Context(), s.handshakeTimeout)
	defer cancel()

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		Prologue:      []byte(Prologue),
		StaticKeypair: s.static,
	})
	if err != nil {
		_ = ws.Close(websocket.StatusInternalError, "")
		return nil, fmt.Errorf("noisews: handshake state: %w", err)
	}

	typ, msg1, err := ws.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("noisews: read handshake message: %w", err)
	}
	if typ != websocket.MessageBinary {
		_ = ws.Close(websocket.StatusPolicyViolation, "binary message required")
		return nil, errors.New("noisews: handshake message must be binary")
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		// A stale client key after server key rotation also fails here;
		// the close reason gives such clients a diagnosable signal.
		_ = ws.Close(websocket.StatusPolicyViolation, "noise handshake failed")
		return nil, fmt.Errorf("noisews: handshake failed: %w", err)
	}

	msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		_ = ws.Close(websocket.StatusInternalError, "")
		return nil, fmt.Errorf("noisews: handshake failed: %w", err)
	}
	if err := ws.Write(ctx, websocket.MessageBinary, msg2); err != nil {
		return nil, fmt.Errorf("noisews: write handshake message: %w", err)
	}

	// Split returns cs1 for initiator-to-responder traffic; the server
	// receives with cs1 and sends with cs2.
	return newConn(ws, cs2, cs1, s.maxMessageSize), nil
}

// Handler wraps handle in an http.Handler that upgrades the request and
// closes the connection when handle returns.
func (s *Server) Handler(handle func(conn *Conn, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := s.Upgrade(w, r)
		if err != nil {
			log.Debugf("noisews upgrade failed: %v", err)
			return
		}
		defer conn.Close()
		handle(conn, r)
	})
}
