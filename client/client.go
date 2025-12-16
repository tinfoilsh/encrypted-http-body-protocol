package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// Transport implements http.RoundTripper with EHBP v2 encryption.
// It encrypts request bodies and decrypts response bodies using
// HPKE with derived response keys to prevent MitM attacks.
type Transport struct {
	clientIdentity *identity.Identity
	serverIdentity *identity.Identity
	httpClient     *http.Client
}

var _ http.RoundTripper = (*Transport)(nil)

// NewTransport creates a new Transport with EHBP v2 encryption.
// It fetches the server's public key configuration from the well-known endpoint.
func NewTransport(server string, clientIdentity *identity.Identity, insecureSkipVerify bool) (*Transport, error) {
	t := &Transport{
		clientIdentity: clientIdentity,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: insecureSkipVerify,
				},
			},
		},
	}

	if err := t.syncServerPublicKey(server); err != nil {
		return nil, fmt.Errorf("failed to sync server public key: %v", err)
	}

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

// ServerIdentity returns the server's public identity configuration.
func (t *Transport) ServerIdentity() *identity.Identity {
	return t.serverIdentity
}

// RoundTrip implements http.RoundTripper with EHBP v2 encryption.
//
// The v2 protocol:
//  1. Encrypts the request body to the server's public key
//  2. Stores the HPKE sealer context for response decryption
//  3. Derives response decryption keys from the request's HPKE context
//  4. Decrypts the response using the derived keys
//
// This ensures response encryption is bound to the specific request,
// preventing MitM attacks where an attacker could intercept responses.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create a copy of the request to avoid modifying the original
	newReq := req.Clone(req.Context())

	serverPubKeyBytes := t.serverIdentity.MarshalPublicKey()

	// Encrypt request and get context for response decryption (v2)
	reqCtx, err := t.clientIdentity.EncryptRequestWithContext(newReq, serverPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %v", err)
	}

	// Make the HTTP request
	resp, err := t.httpClient.Do(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	// Check for plaintext fallback
	if resp.Header.Get(protocol.FallbackHeader) == "1" {
		return resp, nil
	}

	// Decrypt response using the request context (v2)
	if err := t.clientIdentity.DecryptResponseWithContext(resp, reqCtx); err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to decrypt response: %v", err)
	}

	return resp, nil
}
