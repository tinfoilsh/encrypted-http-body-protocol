// Package noisews provides end-to-end encrypted WebSocket channels for EHBP.
//
// The channel runs the Noise NK handshake (Noise_NK_25519_AESGCM_SHA256)
// inside WebSocket binary messages: the client authenticates the server by
// its X25519 static key (the EHBP HPKE identity key) while remaining
// anonymous itself, mirroring the trust model of the HTTP mode. The
// WebSocket upgrade request and control frames stay in cleartext so
// intermediaries can route the connection; every application message is
// carried as an encrypted record inside a binary frame.
//
// Termination is authenticated: peers exchange an encrypted close record
// before the WebSocket close handshake, so truncation by an intermediary is
// distinguishable from an intentional shutdown (see ErrTruncated).
package noisews

import (
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

const (
	// Prologue domain-separates the Noise handshake from other uses of the
	// server's X25519 key, since the HPKE identity key is reused as the
	// Noise static key. Both peers must use the identical value.
	Prologue = "ehbp noise websocket v1"

	// x25519KEMID is the RFC 9180 identifier for DHKEM(X25519, HKDF-SHA256).
	x25519KEMID = 0x0020

	// handshakeReadLimit bounds WebSocket messages during the handshake.
	// Noise NK handshake messages are 48 bytes each.
	handshakeReadLimit = 4096

	// recordOverhead is the framing added to a payload: 1 record type byte,
	// a 16-byte AEAD tag, and margin for WebSocket read limit accounting.
	recordOverhead = 64

	// DefaultMaxMessageSize is the default cap on a single record payload.
	DefaultMaxMessageSize = 1 << 20

	defaultHandshakeTimeout = 10 * time.Second
	closeTimeout            = 5 * time.Second
)

// defaultRekeyEvery is the number of records after which each direction's
// cipher state is rekeyed. The schedule is deterministic so both peers stay
// in sync.
const defaultRekeyEvery = 1 << 16

// rekeyEvery is a variable only so tests can exercise rekeying cheaply; it
// is atomic because connection goroutines may still read it while a test
// overrides it.
var rekeyEvery atomic.Uint64

func init() { rekeyEvery.Store(defaultRekeyEvery) }

func cipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
}

type options struct {
	maxMessageSize   int
	httpClient       *http.Client
	originPatterns   []string
	handshakeTimeout time.Duration
}

func defaultOptions() options {
	return options{
		maxMessageSize:   DefaultMaxMessageSize,
		handshakeTimeout: defaultHandshakeTimeout,
	}
}

// Option configures Dial or NewServer.
type Option func(*options)

// WithMaxMessageSize caps the payload size of a single record in both
// directions. Both peers should agree on the cap; a received record larger
// than the local cap fails the connection.
func WithMaxMessageSize(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.maxMessageSize = n
		}
	}
}

// WithHTTPClient sets the HTTP client used for the WebSocket upgrade request.
// It applies to Dial only. A nil client is ignored.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		if c != nil {
			o.httpClient = c
		}
	}
}

// WithOriginPatterns authorizes browser origins by host pattern for the
// upgrade's origin check. It applies to NewServer only. Without it, only
// same-origin browser connections are accepted.
func WithOriginPatterns(patterns ...string) Option {
	return func(o *options) {
		o.originPatterns = append([]string(nil), patterns...)
	}
}

// WithHandshakeTimeout bounds the Noise handshake on the server side.
func WithHandshakeTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.handshakeTimeout = d
		}
	}
}

func applyOptions(opts []Option) options {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

func noisePublicKey(id *identity.Identity) ([]byte, error) {
	if id == nil {
		return nil, errors.New("noisews: server identity is required")
	}
	if id.KEM().ID() != x25519KEMID {
		return nil, fmt.Errorf("noisews: unsupported KEM 0x%04x, only X25519 is supported", id.KEM().ID())
	}
	return id.MarshalPublicKey(), nil
}

func noiseKeypair(id *identity.Identity) (noise.DHKey, error) {
	pub, err := noisePublicKey(id)
	if err != nil {
		return noise.DHKey{}, err
	}
	sk := id.PrivateKey()
	if sk == nil {
		return noise.DHKey{}, errors.New("noisews: identity has no private key")
	}
	priv, err := sk.Bytes()
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("noisews: export private key: %w", err)
	}
	return noise.DHKey{Private: priv, Public: pub}, nil
}
