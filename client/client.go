// Package client is the Go API shim over the event-driven EHBP core
// (dafny/ehbp_events.dfy): an http.RoundTripper that encrypts request bodies
// and decrypts responses. Every exchange is driven by internal/eventresidue's
// pump; every protocol decision is made by the core (conformance/spec/handler.md
// section 7).
package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	ev "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen-events/go/EHBPEvents"
	core "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/EHBP"
	_dafny "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/dafny"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/internal/eventresidue"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// constructor: a Transport over one server origin and the key a KeySource yields.

// Transport is an http.RoundTripper bound to one server origin and its HPKE
// public key.
type Transport struct {
	publicKey  []byte
	httpClient *http.Client
	origin     core.Origin
	session    eventresidue.Session
}

// Option configures a Transport.
type Option func(*Transport)

// WithHTTPClient sets the http.Client whose Transport sends encrypted
// requests and which fetches the key configuration. A nil client keeps the default.
func WithHTTPClient(c *http.Client) Option {
	return func(t *Transport) {
		if c != nil {
			t.httpClient = c
		}
	}
}

// KeySource yields the server's HPKE public key for New: Discover, Config or PublicKey.
type KeySource func(ctx context.Context, server string, opts ...Option) ([]byte, error)

// Config is a KeySource for pre-fetched /.well-known/hpke-keys bytes (RFC 9458).
func Config(hpkeConfig []byte) KeySource {
	return func(context.Context, string, ...Option) ([]byte, error) { return Core().ParseConfig(hpkeConfig) }
}

// PublicKey is a KeySource for an already-trusted raw X25519 public key, for
// example one verified through attestation; the core checks its length.
func PublicKey(key []byte) KeySource {
	return func(context.Context, string, ...Option) ([]byte, error) { return Core().CheckPublicKey(key) }
}

// Discovered is the KeySource that fetches /.well-known/hpke-keys from the server (Discover).
func Discovered() KeySource { return Discover }

// New returns a Transport bound to server's origin, with the key keys yields.
func New(server string, keys KeySource, opts ...Option) (*Transport, error) {
	if keys == nil {
		return nil, protocol.Errorf(protocol.InvalidInput, "key source is required")
	}
	t, err := newTransport(server, opts)
	if err != nil {
		return nil, err
	}
	if t.publicKey, err = keys(context.Background(), server, opts...); err != nil {
		return nil, err
	}
	return t, nil
}

func newTransport(server string, opts []Option) (*Transport, error) {
	origin, err := parseOrigin(server)
	if err != nil {
		return nil, err
	}
	t := &Transport{httpClient: &http.Client{}, origin: origin}
	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}
	return t, nil
}

// parts is a parsed URL the way MakeOrigin and Start take it.
func parts(u *url.URL) (scheme, host string, port int, hasPort, hasUserinfo bool) {
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
		hasPort = true
	}
	return u.Scheme, u.Hostname(), port, hasPort, u.User != nil
}

// parseOrigin hands the parsed parts of server to the core, which validates them.
func parseOrigin(server string) (core.Origin, error) {
	u, err := url.Parse(server)
	if err != nil {
		return core.Origin{}, protocol.Errorf(protocol.InvalidInput, "failed to parse server URL: %w", err)
	}
	scheme, host, port, hasPort, hasUserinfo := parts(u)
	optPort := core.Companion_Option_.Create_None_()
	if hasPort {
		optPort = core.Companion_Option_.Create_Some_(_dafny.IntOfInt(port))
	}
	r := core.Companion_Default___.MakeOrigin(eventresidue.Str(scheme), eventresidue.Str(host), optPort, hasUserinfo)
	if r.Is_Err() {
		return core.Origin{}, eventresidue.Error(r.Dtor_code(), eventresidue.String(r.Dtor_message()), nil)
	}
	return r.Dtor_value().(core.Origin), nil
}

// request: the one entry point, RoundTrip; the core validates, seals, classifies and decrypts.

// RoundTrip performs one encrypted exchange. The core validates the request,
// seals the body when present, classifies the response and decrypts it; the
// returned response is the stack's own with its body replaced.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, protocol.Errorf(protocol.InvalidInput, "request has no URL")
	}
	outgoing := req.Clone(req.Context())
	// A request derived from an inbound one (httputil.ReverseProxy) carries
	// RequestURI and Host; the wire target and Host follow the validated URL.
	outgoing.RequestURI = ""
	outgoing.Host = ""

	var body = req.Body
	if body == http.NoBody {
		body = nil
	}
	if body != nil {
		// A cancelled context closes the body so a blocked read in the upload lane returns.
		defer context.AfterFunc(req.Context(), func() { _ = body.Close() })()
	}
	scheme, host, port, hasPort, hasUserinfo := parts(req.URL)
	start := ev.Companion_Event_.Create_Start_(eventresidue.Str(req.Method), eventresidue.Str(req.URL.String()),
		eventresidue.Str(scheme), eventresidue.Str(host), _dafny.IntOfInt(port), hasPort, hasUserinfo,
		eventresidue.HeaderSeq(req.Header), body != nil)
	x := eventresidue.NewExchange(ev.Companion_Default___.Initial(t.origin, eventresidue.Seq(t.publicKey)),
		&t.session, t.roundTripper().RoundTrip, outgoing, body)
	x.Feed(start)
	switch {
	case x.Failure != nil:
		if protocol.CodeOf(x.Failure) == protocol.KeyConfigMismatch {
			return nil, identity.NewKeyConfigError(x.Failure)
		}
		return nil, x.Failure
	case x.Passthrough:
		resp := x.Response
		if len(x.Prefix) > 0 {
			resp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(x.Prefix), resp.Body), resp.Body}
		}
		return resp, nil
	case x.Done:
		resp := x.Response
		resp.Header, resp.ContentLength, resp.Body = x.Headers, -1, &eventresidue.BodyReader{X: x}
		return resp, nil
	}
	return nil, errors.New("exchange ended without an outcome")
}

func (t *Transport) roundTripper() http.RoundTripper {
	if t.httpClient.Transport != nil {
		return t.httpClient.Transport
	}
	return http.DefaultTransport
}

// discover: the same discovery the constructor runs; the 32-byte public key.

// Discover fetches server's key configuration (SPEC 3.1) and returns the
// public key; `Discovered()` is the same discovery as a KeySource for New.
func Discover(ctx context.Context, server string, opts ...Option) ([]byte, error) {
	t, err := newTransport(server, opts)
	if err != nil {
		return nil, err
	}
	keys, err := http.NewRequestWithContext(ctx, http.MethodGet, server, nil)
	if err != nil {
		return nil, protocol.Errorf(protocol.InvalidInput, "failed to parse server URL: %w", err)
	}
	x := eventresidue.NewExchange(ev.Companion_Default___.Initial(t.origin, eventresidue.Seq(nil)), &t.session, noRedirectClient(t.httpClient).Do, keys, nil)
	x.Feed(ev.Companion_Event_.Create_DiscoverStart_())
	if x.Failure != nil {
		return nil, x.Failure
	}
	return x.PublicKey, nil
}

// noRedirectClient copies c with a policy that returns the first response, so
// discovery observes exactly the status the key endpoint sent (SPEC 3.1).
func noRedirectClient(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// token: the exchange in flight.

// SessionRecoveryToken returns the token of the exchange in flight, or nil
// (SPEC 6): nil before any request, after a bodyless one, and once an
// exchange has ended.
func (t *Transport) SessionRecoveryToken() *SessionRecoveryToken {
	tok := t.session.Token()
	if tok == nil {
		return nil
	}
	return &SessionRecoveryToken{
		ExportedSecret: eventresidue.Bytes(tok.Dtor_exportedSecret()),
		RequestEnc:     eventresidue.Bytes(tok.Dtor_requestEnc()),
	}
}

// selfCheck: the core's primitive vectors through this residue.

// SelfCheck runs the core's primitive vectors through this residue.
func SelfCheck() []string { return eventresidue.SelfCheck() }
