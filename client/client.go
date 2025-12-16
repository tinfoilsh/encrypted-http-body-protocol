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

type Transport struct {
	clientIdentity *identity.Identity
	serverIdentity *identity.Identity
	httpClient     *http.Client
}

var _ http.RoundTripper = (*Transport)(nil)

// NewTransport creates a new encrypted transport.
// If clientIdentity is nil, an ephemeral identity is created automatically.
// The client identity is used only for HPKE suite access - its private key is never used
// since response decryption uses keys derived from the request's HPKE context.
func NewTransport(server string, clientIdentity *identity.Identity, insecureSkipVerify bool) (*Transport, error) {
	// Create ephemeral identity if not provided
	if clientIdentity == nil {
		var err error
		clientIdentity, err = identity.NewIdentity()
		if err != nil {
			return nil, fmt.Errorf("failed to create ephemeral identity: %v", err)
		}
	}

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

func (t *Transport) ServerIdentity() *identity.Identity {
	return t.serverIdentity
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create a copy of the request to avoid modifying the original
	newReq := req.Clone(req.Context())

	serverPubKeyBytes := t.serverIdentity.MarshalPublicKey()

	// Encrypt request and get context for response decryption
	reqCtx, err := t.clientIdentity.EncryptRequestWithContext(newReq, serverPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %v", err)
	}

	resp, err := t.httpClient.Do(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	// Check for plaintext fallback
	if resp.Header.Get(protocol.FallbackHeader) == "1" {
		return resp, nil
	}

	if err := t.clientIdentity.DecryptResponseWithContext(resp, reqCtx); err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to decrypt response: %v", err)
	}

	return resp, nil
}
