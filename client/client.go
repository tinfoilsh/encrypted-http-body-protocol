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

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

type Transport struct {
	serverIdentity *identity.Identity
	httpClient     *http.Client
}

type problemDetails struct {
	Type  string `json:"type"`
	Title string `json:"title"`
}

var _ http.RoundTripper = (*Transport)(nil)

func NewTransport(server string) (*Transport, error) {
	t := &Transport{
		httpClient: &http.Client{},
	}

	if err := t.syncServerPublicKey(server); err != nil {
		return nil, fmt.Errorf("failed to sync server public key: %v", err)
	}

	return t, nil
}

// NewTransportWithConfig creates a new Transport with a pre-fetched HPKE key configuration.
// The hpkeConfig should be the raw bytes from /.well-known/hpke-keys (RFC 9458 format).
func NewTransportWithConfig(hpkeConfig []byte) (*Transport, error) {
	serverIdentity, err := identity.UnmarshalPublicConfig(hpkeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key config: %v", err)
	}

	return &Transport{
		serverIdentity: serverIdentity,
		httpClient:     &http.Client{},
	}, nil
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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("failed to read problem response: %w", err)
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

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create a copy of the request to avoid modifying the original
	newReq := req.Clone(req.Context())

	// Encrypt request to server's public key and get context for response decryption
	// For bodyless requests, reqCtx will be nil - response passes through unencrypted
	reqCtx, err := t.serverIdentity.EncryptRequestWithContext(newReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %v", err)
	}

	resp, err := t.httpClient.Do(newReq)
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

		if err := reqCtx.DecryptResponse(resp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decrypt response: %v", err)
		}
	}

	return resp, nil
}
