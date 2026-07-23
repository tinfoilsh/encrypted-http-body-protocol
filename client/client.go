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
	t := &Transport{
		httpClient: &http.Client{},
	}
	applyOptions(t, opts)

	if err := t.syncServerPublicKey(server); err != nil {
		return nil, fmt.Errorf("failed to sync server public key: %v", err)
	}

	return t, nil
}

// NewTransportWithConfig creates a new Transport with a pre-fetched HPKE key configuration.
// The hpkeConfig should be the raw bytes from /.well-known/hpke-keys (RFC 9458 format).
func NewTransportWithConfig(server string, hpkeConfig []byte, opts ...Option) (*Transport, error) {
	serverIdentity, err := identity.UnmarshalPublicConfig(hpkeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key config: %v", err)
	}

	t := &Transport{
		serverIdentity: serverIdentity,
		httpClient:     &http.Client{},
	}
	applyOptions(t, opts)
	return t, nil
}

// NewTransportWithIdentity creates a Transport from an already-trusted server
// identity, for example one built from an attestation-verified HPKE public key
// via identity.FromPublicKeyHex. No network request is made to fetch keys.
func NewTransportWithIdentity(serverIdentity *identity.Identity, opts ...Option) (*Transport, error) {
	if serverIdentity == nil {
		return nil, fmt.Errorf("server identity is required")
	}

	t := &Transport{
		serverIdentity: serverIdentity,
		httpClient:     &http.Client{},
	}
	applyOptions(t, opts)
	return t, nil
}

func (t *Transport) syncServerPublicKey(server string) error {
	keysURL, err := url.Parse(server)
	if err != nil {
		return fmt.Errorf("failed to parse server URL: %v", err)
	}
	keysURL.Path = protocol.KeysPath

	resp, err := t.httpClient.Get(keysURL.String())
	if err != nil {
		return fmt.Errorf("failed to get server public key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != protocol.KeysMediaType {
		return fmt.Errorf("server returned invalid content type: %s", resp.Header.Get("Content-Type"))
	}

	ohttpKeys, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	serverIdentity, err := identity.UnmarshalPublicConfig(ohttpKeys)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %v", err)
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

	// Encrypt request to server's public key and get context for response decryption
	// For bodyless requests, reqCtx will be nil - response passes through unencrypted
	reqCtx, err := t.serverIdentity.EncryptRequestWithContext(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %v", err)
	}

	var token *identity.SessionRecoveryToken
	if reqCtx != nil {
		token, err = identity.ExtractSessionRecoveryToken(reqCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to extract session recovery token: %v", err)
		}
	}

	// Send through a RoundTripper rather than a nested http.Client: a
	// RoundTripper performs a single HTTP transaction, so redirects surface
	// to the outer client, whose CheckRedirect and cookie jar then apply
	// (and each redirected attempt is re-encrypted for its target).
	resp, err := t.roundTripper().RoundTrip(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
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
			return nil, identity.NewKeyConfigError(fmt.Errorf("%s", title))
		}

		if resp.Header.Get(protocol.ResponseNonceHeader) == "" &&
			(resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices) {
			return resp, nil
		}

		if err := identity.DecryptResponseWithToken(resp, token); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decrypt response: %v", err)
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
