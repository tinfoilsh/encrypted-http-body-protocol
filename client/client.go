package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

type Transport struct {
	serverIdentity *identity.Identity
	httpClient     *http.Client
	// origin is the scheme://host[:port] the key configuration was fetched
	// from or declared for; requests must target it. Nil when the Transport
	// was built from a bare identity (NewTransportWithIdentity).
	origin *url.URL

	mu                       sync.Mutex
	lastSessionRecoveryToken *identity.SessionRecoveryToken
	requestGeneration        uint64
}

type problemDetails struct {
	Type  string `json:"type"`
	Title string `json:"title"`
}

const maxProblemDetailsBytes = 64 << 10

type preservingReadCloser struct {
	io.Reader
	io.Closer
}

type tokenOwningReadCloser struct {
	io.ReadCloser
	onComplete func()
	onError    func()
	once       sync.Once
}

func (r *tokenOwningReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if err == io.EOF {
		r.once.Do(r.onComplete)
	} else if err != nil {
		r.once.Do(r.onError)
	}
	return n, err
}

var _ http.RoundTripper = (*Transport)(nil)

// Option configures a Transport.
type Option func(*Transport)

// WithHTTPClient sets the underlying HTTP client used to send encrypted
// requests (and, for NewTransport, to fetch the server key configuration). It
// lets callers compose EHBP with a TLS-pinned or otherwise customized
// http.Client. A nil client is ignored so the default remains in place.
//
// Encrypted requests are sent through the client's Transport only. Redirect
// policy, cookie jar, and timeout are supplied by the outer http.Client that
// drives this RoundTripper, not by the client passed here; the full client is
// used for the key-configuration fetch.
func WithHTTPClient(c *http.Client) Option {
	return func(t *Transport) {
		if c != nil {
			t.httpClient = c
		}
	}
}

func applyOptions(t *Transport, opts []Option) {
	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}
}

func NewTransport(server string, opts ...Option) (*Transport, error) {
	origin, err := parseOrigin(server)
	if err != nil {
		return nil, err
	}
	t := &Transport{
		httpClient: &http.Client{},
		origin:     origin,
	}
	applyOptions(t, opts)

	if err := t.syncServerPublicKey(server); err != nil {
		return nil, fmt.Errorf("failed to sync server public key: %w", err)
	}

	return t, nil
}

// NewTransportWithConfig creates a new Transport with a pre-fetched HPKE key configuration.
// The hpkeConfig should be the raw bytes from /.well-known/hpke-keys (RFC 9458 format).
func NewTransportWithConfig(server string, hpkeConfig []byte, opts ...Option) (*Transport, error) {
	origin, err := parseOrigin(server)
	if err != nil {
		return nil, err
	}
	serverIdentity, err := identity.UnmarshalPublicConfig(hpkeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key config: %w", err)
	}

	t := &Transport{
		serverIdentity: serverIdentity,
		httpClient:     &http.Client{},
		origin:         origin,
	}
	applyOptions(t, opts)
	return t, nil
}

// NewTransportWithIdentity creates a Transport from an already-trusted server
// identity, for example one built from an attestation-verified HPKE public key
// via identity.FromPublicKeyHex. No network request is made to fetch keys.
func NewTransportWithIdentity(serverIdentity *identity.Identity, opts ...Option) (*Transport, error) {
	if serverIdentity == nil {
		return nil, protocol.Errorf(protocol.InvalidInput, "server identity is required")
	}

	t := &Transport{
		serverIdentity: serverIdentity,
		httpClient:     &http.Client{},
	}
	applyOptions(t, opts)
	return t, nil
}

// parseOrigin validates a base URL the way the Python and Rust clients do:
// http(s) scheme, a host, and no credentials.
func parseOrigin(server string) (*url.URL, error) {
	u, err := url.Parse(server)
	if err != nil {
		return nil, protocol.Errorf(protocol.InvalidInput, "failed to parse server URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, protocol.Errorf(protocol.InvalidInput, "base URL must include an HTTP origin")
	}
	if u.User != nil {
		return nil, protocol.Errorf(protocol.InvalidInput, "base URL must not include credentials")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		portOf(a) == portOf(b)
}

// validateRequest rejects requests that would let the caller influence the
// authority or the protocol headers the library owns. Content-Length,
// Transfer-Encoding, and Host entries in req.Header never reach the wire in
// Go's client (the transport derives them from the request itself), so only
// the Ehbp-* headers are reserved here.
func (t *Transport) validateRequest(req *http.Request) error {
	if req.URL == nil {
		return protocol.Errorf(protocol.InvalidInput, "request has no URL")
	}
	if req.URL.User != nil {
		return protocol.Errorf(protocol.InvalidInput, "request URL must not include credentials")
	}
	if t.origin != nil && !sameOrigin(t.origin, req.URL) {
		return protocol.Errorf(protocol.InvalidInput, "request URL must use the configured origin: %s", t.origin)
	}
	for name := range req.Header {
		if strings.EqualFold(name, protocol.EncapsulatedKeyHeader) || strings.EqualFold(name, protocol.ResponseNonceHeader) {
			return protocol.Errorf(protocol.InvalidInput, "reserved request header cannot be set by callers: %s", name)
		}
	}
	return nil
}

func (t *Transport) syncServerPublicKey(server string) error {
	keysURL, err := url.Parse(server)
	if err != nil {
		return protocol.Errorf(protocol.InvalidInput, "failed to parse server URL: %w", err)
	}
	keysURL.Path = protocol.KeysPath

	resp, err := t.httpClient.Get(keysURL.String())
	if err != nil {
		return fmt.Errorf("failed to get server public key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return protocol.Errorf(protocol.InvalidKeyConfig, "server returned status %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != protocol.KeysMediaType {
		return protocol.Errorf(protocol.InvalidKeyConfig, "server returned invalid content type: %s", resp.Header.Get("Content-Type"))
	}

	ohttpKeys, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	serverIdentity, err := identity.UnmarshalPublicConfig(ohttpKeys)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	t.serverIdentity = serverIdentity

	return nil
}

func (t *Transport) ServerIdentity() *identity.Identity {
	return t.serverIdentity
}

// GetSessionRecoveryToken returns the session recovery token from the most
// recent request that had a body. Returns nil if no token is available (e.g.
// no request has been made yet, or the last request was bodyless).
func (t *Transport) GetSessionRecoveryToken() *identity.SessionRecoveryToken {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastSessionRecoveryToken
}

func isProblemJSONContentType(contentType string) bool {
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.HasPrefix(strings.ToLower(contentType), protocol.ProblemJSONMediaType)
	}
	return strings.EqualFold(mediaType, protocol.ProblemJSONMediaType)
}

func isKeyConfigMismatchResponse(resp *http.Response) (bool, string, error) {
	if resp.StatusCode != http.StatusUnprocessableEntity {
		return false, "", nil
	}
	if !isProblemJSONContentType(resp.Header.Get("Content-Type")) {
		return false, "", nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxProblemDetailsBytes+1))
	if err != nil {
		return false, "", fmt.Errorf("failed to read problem response: %w", err)
	}
	if len(bodyBytes) > maxProblemDetailsBytes {
		resp.Body = &preservingReadCloser{
			Reader: io.MultiReader(bytes.NewReader(bodyBytes), resp.Body),
			Closer: resp.Body,
		}
		return false, "", nil
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	var problem problemDetails
	if err := json.Unmarshal(bodyBytes, &problem); err != nil {
		return false, "", nil
	}
	if problem.Type != protocol.KeyConfigProblemType {
		return false, "", nil
	}
	return true, problem.Title, nil
}

// roundTripper returns the RoundTripper used to send encrypted requests,
// honoring a Transport configured via WithHTTPClient.
func (t *Transport) roundTripper() http.RoundTripper {
	if t.httpClient.Transport != nil {
		return t.httpClient.Transport
	}
	return http.DefaultTransport
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.validateRequest(req); err != nil {
		return nil, err
	}

	t.mu.Lock()
	t.requestGeneration++
	generation := t.requestGeneration
	t.lastSessionRecoveryToken = nil
	t.mu.Unlock()

	// Create a copy of the request to avoid modifying the original
	newReq := req.Clone(req.Context())

	// A RoundTripper may be handed a request derived from an inbound server
	// request (for example when used behind httputil.ReverseProxy), which
	// carries RequestURI. http.Client.Do rejects any client request with
	// RequestURI set, and the outbound request-target is taken from URL, so
	// clear it. RequestURI is outside EHBP's protection (bodies only, empty
	// AAD) and is not read during encryption, so clearing it changes no
	// authenticated data.
	newReq.RequestURI = ""

	// req.Host, not req.URL.Host, is what Go sends as the wire Host header,
	// so a caller (or a reverse proxy forwarding its inbound Host) could
	// address another virtual host while the URL passes the origin check.
	// Clear it so the Host header always follows the validated URL, as the
	// Python and Rust clients do.
	newReq.Host = ""

	// Encrypt request to server's public key and get context for response decryption
	// For bodyless requests, reqCtx will be nil - response passes through unencrypted
	reqCtx, err := t.serverIdentity.EncryptRequestWithContext(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %w", err)
	}

	var token *identity.SessionRecoveryToken
	if reqCtx != nil {
		token, err = identity.ExtractSessionRecoveryToken(reqCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to extract session recovery token: %w", err)
		}
	}

	// Send through a RoundTripper rather than a nested http.Client: a
	// RoundTripper performs a single HTTP transaction, so redirects surface
	// to the outer client, whose CheckRedirect and cookie jar then apply
	// (and each redirected attempt is re-encrypted for its target).
	resp, err := t.roundTripper().RoundTrip(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	// Only decrypt if we encrypted the request (had a body)
	if reqCtx != nil {
		rekey, title, checkErr := isKeyConfigMismatchResponse(resp)
		if checkErr != nil {
			resp.Body.Close()
			return nil, checkErr
		}
		if rekey {
			resp.Body.Close()
			if title == "" {
				title = "key configuration mismatch"
			}
			return nil, identity.NewKeyConfigError(protocol.Errorf(protocol.KeyConfigMismatch, "%s", title))
		}

		if resp.Header.Get(protocol.ResponseNonceHeader) == "" &&
			(resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices) {
			return resp, nil
		}

		if err := identity.DecryptResponseWithToken(resp, token); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decrypt response: %w", err)
		}

		t.mu.Lock()
		if t.requestGeneration == generation {
			t.lastSessionRecoveryToken = token
		}
		t.mu.Unlock()

		resp.Body = &tokenOwningReadCloser{
			ReadCloser: resp.Body,
			onComplete: func() {
				t.mu.Lock()
				if t.requestGeneration == generation {
					t.lastSessionRecoveryToken = nil
				}
				t.mu.Unlock()
			},
			onError: func() {
				t.mu.Lock()
				if t.requestGeneration == generation {
					t.lastSessionRecoveryToken = nil
				}
				t.mu.Unlock()
			},
		}
	}

	return resp, nil
}
