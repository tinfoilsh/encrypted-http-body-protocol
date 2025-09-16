package client

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cloudflare/circl/kem"
	"github.com/tinfoilsh/stransport/identity"
	"github.com/tinfoilsh/stransport/protocol"
)

type Transport struct {
	clientIdentity *identity.Identity
	serverPK       kem.PublicKey
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

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL: %v", err)
	}

	if err := t.syncServerPublicKey(serverURL); err != nil {
		return nil, fmt.Errorf("failed to sync server public key: %v", err)
	}

	return t, nil
}

func (t *Transport) syncServerPublicKey(serverURL *url.URL) error {
	serverURL.Path = protocol.KeysPath

	resp, err := t.httpClient.Get(serverURL.String())
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

	t.serverPK = serverIdentity.PublicKey()
	return nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create a copy of the request to avoid modifying the original
	newReq := req.Clone(req.Context())

	// Encrypt request body using streaming encryption
	if newReq.Body != nil {
		serverPubKeyBytes, err := t.serverPK.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal server public key: %v", err)
		}
		err = t.clientIdentity.EncryptRequest(newReq, serverPubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt request: %v", err)
		}
	} else {
		// EncryptRequest will set the client public key header above if we have something to encrypt
		newReq.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(t.clientIdentity.MarshalPublicKey()))
	}

	resp, err := t.httpClient.Do(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	encapKeyHeader := resp.Header.Get(protocol.EncapsulatedKeyHeader)
	if encapKeyHeader == "" {
		return nil, fmt.Errorf("missing encapsulated key header")
	}

	serverEncapKey, err := hex.DecodeString(encapKeyHeader)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to decode encapsulated key: %v", err)
	}

	// Decrypt
	receiver, err := t.clientIdentity.Suite().NewReceiver(t.clientIdentity.PrivateKey(), nil)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to create receiver: %v", err)
	}
	opener, err := receiver.Setup(serverEncapKey)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to setup decryption: %v", err)
	}

	resp.Body = identity.NewStreamingDecryptReader(resp.Body, opener)
	resp.ContentLength = -1 // Unknown length for streaming

	return resp, nil
}
