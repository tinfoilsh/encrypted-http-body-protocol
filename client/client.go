package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/stransport/identity"
)

type SecureClient struct {
	clientIdentity *identity.Identity
	serverHost     string
	serverPK       kem.PublicKey
}

var _ http.RoundTripper = (*SecureClient)(nil)

func NewSecureClient(serverURL string, clientIdentity *identity.Identity) (*SecureClient, error) {
	server, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL: %v", err)
	}

	c := &SecureClient{
		clientIdentity: clientIdentity,
		serverHost:     server.Host,
	}

	c.serverPK, err = getServerPublicKey(server)
	if err != nil {
		return nil, fmt.Errorf("failed to get server public key: %v", err)
	}

	return c, nil
}

func getServerPublicKey(serverURL *url.URL) (kem.PublicKey, error) {
	serverURL.Path = "/.well-known/tinfoil-public-key"

	resp, err := http.Get(serverURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get server public key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	pkHexBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	pkBytes, err := hex.DecodeString(string(pkHexBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	pk, err := identity.KEMScheme().UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}
	return pk, nil
}

func (c *SecureClient) RoundTrip(req *http.Request) (*http.Response, error) {
	sender, err := identity.Suite().NewSender(c.serverPK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sender context: %v", err)
	}
	clientEncapKey, sealer, err := sender.Setup(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to setup encryption: %v", err)
	}

	req.Host = c.serverHost

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
	newReq.Header.Set("Tinfoil-Client-Public-Key", hex.EncodeToString(c.clientIdentity.MarshalPublicKey()))
	newReq.Header.Set("Content-Type", "application/octet-stream")

	// Make request
	resp, err := http.DefaultClient.Do(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	receiver, err := identity.Suite().NewReceiver(c.clientIdentity.PrivateKey(), nil)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to create receiver: %v", err)
	}

	serverEncapKey, err := hex.DecodeString(resp.Header.Get("Tinfoil-Encapsulated-Key"))
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to decode encapsulated key: %v", err)
	}
	opener, err := receiver.Setup(serverEncapKey)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to setup decryption: %v", err)
	}

	// Replace the response body with our streaming reader
	resp.Body = &streamingDecryptReader{
		reader: resp.Body,
		opener: opener,
	}

	return resp, nil
}

// streamingDecryptReader implements io.ReadCloser to decrypt data as it's read
type streamingDecryptReader struct {
	reader io.ReadCloser
	opener hpke.Opener
	buffer []byte
}

// Read decrypts data as it's read from the stream
func (r *streamingDecryptReader) Read(p []byte) (int, error) {
	// If we have buffered data, return it
	if len(r.buffer) > 0 {
		n := copy(p, r.buffer)
		r.buffer = r.buffer[n:]
		log.Debugf("Returning %d bytes from buffer", n)
		return n, nil
	}

	// Read encrypted data
	encBuf := make([]byte, 4096) // Fixed buffer size for encrypted data
	n, err := r.reader.Read(encBuf)
	if n == 0 {
		if err == io.EOF {
			log.Debug("Reached end of stream")
			return 0, io.EOF
		}
		if err != nil {
			log.Errorf("Error reading encrypted data: %v", err)
			return 0, fmt.Errorf("error reading encrypted data: %w", err)
		}
		// If we read 0 bytes but no error, try again
		return 0, nil
	}
	log.Debugf("Read %d bytes of encrypted data", n)

	// Decrypt the data
	decrypted, err := r.opener.Open(encBuf[:n], nil)
	if err != nil {
		log.Errorf("Error decrypting data: %v", err)
		return 0, fmt.Errorf("error decrypting data: %w", err)
	}
	log.Debugf("Decrypted %d bytes to %d bytes", n, len(decrypted))

	// Copy decrypted data to output buffer
	copied := copy(p, decrypted)
	if copied < len(decrypted) {
		// Buffer the remaining data
		r.buffer = decrypted[copied:]
		log.Debugf("Buffered %d remaining bytes", len(r.buffer))
	}
	log.Debugf("Returning %d decrypted bytes", copied)

	return copied, nil
}

// Close closes the underlying reader
func (r *streamingDecryptReader) Close() error {
	return r.reader.Close()
}
