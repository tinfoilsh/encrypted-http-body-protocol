package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
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

// NewTransport creates a new Transport with the given server identity.
func NewTransport(serverIdentity *identity.Identity) *Transport {
	return &Transport{
		serverIdentity: serverIdentity,
		httpClient:     &http.Client{},
	}
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
