package client

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cloudflare/circl/kem"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/stransport/identity"
	"github.com/tinfoilsh/stransport/protocol"
)

type Transport struct {
	clientIdentity *identity.Identity
	serverHost     string
	serverPK       kem.PublicKey
}

var _ http.RoundTripper = (*Transport)(nil)

func NewTransport(serverURL string, clientIdentity *identity.Identity) (*Transport, error) {
	server, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL: %v", err)
	}

	t := &Transport{
		clientIdentity: clientIdentity,
		serverHost:     server.Host,
	}

	t.serverPK, err = getServerPublicKey(server)
	if err != nil {
		return nil, fmt.Errorf("failed to get server public key: %v", err)
	}

	return t, nil
}

func getServerPublicKey(serverURL *url.URL) (kem.PublicKey, error) {
	serverURL.Path = protocol.KeysPath

	resp, err := http.Get(serverURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get server public key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != protocol.KeysMediaType {
		return nil, fmt.Errorf("server returned invalid content type: %s", resp.Header.Get("Content-Type"))
	}

	ohttpKeys, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	serverIdentity, err := identity.UnmarshalPublicConfig(ohttpKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}
	return serverIdentity.PublicKey(), nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create a copy of the request to avoid modifying the original
	newReq := req.Clone(req.Context())
	newReq.Host = t.serverHost

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

	resp, err := http.DefaultClient.Do(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Warnf("Server returned non-OK status: %d", resp.StatusCode)
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
