package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudflare/circl/kem"
	"github.com/tinfoilsh/stransport/identity"
)

type SecureClient struct {
	identity *identity.Identity
	serverPK kem.PublicKey
}

func NewSecureClient(serverURL string, identity *identity.Identity) (*SecureClient, error) {
	serverPK, err := getServerPublicKey(serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get server public key: %v", err)
	}
	return &SecureClient{identity: identity, serverPK: serverPK}, nil
}

func getServerPublicKey(serverURL string) (kem.PublicKey, error) {
	resp, err := http.Get(fmt.Sprintf("%s/.well-known/tinfoil-public-key", serverURL))
	if err != nil {
		return nil, fmt.Errorf("failed to get server public key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	pkBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	pk, err := identity.KEMScheme().UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}
	return pk, nil
}

func (c *SecureClient) Do(req *http.Request) (*http.Response, error) {
	sender, err := identity.Suite().NewSender(c.serverPK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sender context: %v", err)
	}
	clientEncapKey, sealer, err := sender.Setup(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to setup encryption: %v", err)
	}

	// Encrypt request body
	var encrypted []byte
	if req.Body != nil {
		requestBody, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %v", err)
		}
		req.Body.Close()

		encrypted, err = sealer.Seal(requestBody, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt request body: %v", err)
		}
	}

	newReq, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewBuffer(encrypted))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	for k, v := range req.Header {
		newReq.Header[k] = v
	}
	newReq.Header.Set("Tinfoil-Encapsulated-Key", hex.EncodeToString(clientEncapKey))
	newReq.Header.Set("Tinfoil-Client-Public-Key", hex.EncodeToString(c.identity.MarshalPublicKey()))
	newReq.Header.Set("Content-Type", "application/octet-stream")

	// Make request
	resp, err := http.DefaultClient.Do(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	receiver, err := identity.Suite().NewReceiver(c.identity.PrivateKey(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %v", err)
	}

	serverEncapKey, err := hex.DecodeString(resp.Header.Get("Tinfoil-Encapsulated-Key"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode encapsulated key: %v", err)
	}
	opener, err := receiver.Setup(serverEncapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup decryption: %v", err)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	decrypted, err := opener.Open(respBody, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(decrypted))

	return resp, nil
}
