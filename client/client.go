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

func (t *Transport) ServerIdentity() *identity.Identity {
	return t.serverIdentity
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body == nil || req.ContentLength == 0 {
		return nil, fmt.Errorf("EHBP requires a request body; GET requests are not supported")
	}

	newReq := req.Clone(req.Context())

	serverPubKeyBytes, err := t.serverIdentity.MarshalPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal server public key: %v", err)
	}
	reqCtx, err := t.clientIdentity.EncryptRequest(newReq, serverPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %v", err)
	}

	resp, err := t.httpClient.Do(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	// Derive response decryption key from request context
	opener, err := reqCtx.NewResponseDecrypter()
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to create response decryptor: %v", err)
	}

	resp.Body = identity.NewStreamingDecryptReader(resp.Body, opener)
	resp.ContentLength = -1 // Unknown length for streaming

	return resp, nil
}
