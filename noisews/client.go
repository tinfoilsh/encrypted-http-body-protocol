package noisews

import (
	"context"
	"errors"
	"fmt"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// Dial opens a WebSocket connection to urlStr (ws, wss, http, or https
// scheme) and runs the Noise initiator handshake against the server
// identity's public key. The identity may be public-key-only, for example
// one built from an attestation-verified key via identity.FromPublicKeyHex.
// No application data is sent before the handshake completes.
func Dial(ctx context.Context, urlStr string, serverIdentity *identity.Identity, opts ...Option) (*Conn, error) {
	serverPub, err := noisePublicKey(serverIdentity)
	if err != nil {
		return nil, err
	}
	o := applyOptions(opts)

	ctx, cancel := context.WithTimeout(ctx, o.handshakeTimeout)
	defer cancel()

	ws, _, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{
		HTTPClient:      o.httpClient,
		Subprotocols:    []string{protocol.WSSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("noisews: dial: %w", err)
	}
	if ws.Subprotocol() != protocol.WSSubprotocol {
		_ = ws.Close(websocket.StatusPolicyViolation, "ehbp noise subprotocol required")
		return nil, errors.New("noisews: server did not accept required subprotocol")
	}
	ws.SetReadLimit(handshakeReadLimit)

	conn, err := clientHandshake(ctx, ws, serverPub, o.maxMessageSize)
	if err != nil {
		_ = ws.CloseNow()
		return nil, err
	}
	return conn, nil
}

func clientHandshake(ctx context.Context, ws *websocket.Conn, serverPub []byte, maxMessageSize int) (*Conn, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite(),
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		Prologue:    []byte(Prologue),
		PeerStatic:  serverPub,
	})
	if err != nil {
		return nil, fmt.Errorf("noisews: handshake state: %w", err)
	}

	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noisews: handshake failed: %w", err)
	}
	if err := ws.Write(ctx, websocket.MessageBinary, msg1); err != nil {
		return nil, fmt.Errorf("noisews: write handshake message: %w", err)
	}

	typ, msg2, err := ws.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("noisews: read handshake message: %w", err)
	}
	if typ != websocket.MessageBinary {
		return nil, errors.New("noisews: handshake message must be binary")
	}
	_, cs1, cs2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, fmt.Errorf("noisews: handshake failed: %w", err)
	}

	// Split returns cs1 for initiator-to-responder traffic; the client
	// sends with cs1 and receives with cs2.
	return newConn(ws, cs1, cs2, maxMessageSize), nil
}
