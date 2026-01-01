package mobile

import (
	"bytes"
	"io"
	"net/http"
	"sync"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
)

// StreamingResponse represents an active streaming HTTP response.
// Call Read() repeatedly to get chunks, and Close() when done.
type StreamingResponse struct {
	Status     string
	StatusCode int
	headers    http.Header
	body       io.ReadCloser
	mu         sync.Mutex
	closed     bool
}

// GetHeader returns the value of a response header
func (r *StreamingResponse) GetHeader(key string) string {
	return r.headers.Get(key)
}

// Read reads the next chunk of data from the response.
// Returns the data read, or nil with an error if the stream is closed or an error occurred.
// When the stream ends normally, returns nil data with nil error.
func (r *StreamingResponse) Read(maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 4096
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, io.EOF
	}

	buf := make([]byte, maxBytes)
	n, err := r.body.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err == io.EOF {
		return nil, nil
	}
	return nil, err
}

// Close closes the streaming response and releases resources
func (r *StreamingResponse) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true
	return r.body.Close()
}

// StreamingClient provides encrypted HTTP streaming using the EHBP protocol.
type StreamingClient struct {
	transport *client.Transport
	serverURL string
}

// NewStreamingClient creates a new EHBP streaming client for the given server URL.
func NewStreamingClient(serverURL string) (*StreamingClient, error) {
	transport, err := client.NewTransport(serverURL, false)
	if err != nil {
		return nil, err
	}
	return &StreamingClient{
		transport: transport,
		serverURL: serverURL,
	}, nil
}

// NewStreamingClientWithHPKEKey creates a new streaming client with a pre-fetched HPKE public key.
func NewStreamingClientWithHPKEKey(serverURL string, hpkeConfig []byte) (*StreamingClient, error) {
	transport, err := client.NewTransportWithConfig(serverURL, hpkeConfig, false)
	if err != nil {
		return nil, err
	}
	return &StreamingClient{
		transport: transport,
		serverURL: serverURL,
	}, nil
}

// ServerPublicKeyHex returns the server's HPKE public key as a hex string
func (c *StreamingClient) ServerPublicKeyHex() string {
	return c.transport.ServerIdentity().MarshalPublicKeyHex()
}

// PostStream makes an encrypted HTTP POST request and returns a streaming response.
// The caller must call Close() on the response when done.
func (c *StreamingClient) PostStream(url string, contentType string, body []byte) (*StreamingResponse, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.doStreamingRequest(req)
}

// StreamingRequest represents a pending streaming HTTP request that can have headers added
type StreamingRequest struct {
	req       *http.Request
	transport *client.Transport
}

// NewStreamingRequest creates a new streaming request with the given method, URL, and optional body
func (c *StreamingClient) NewStreamingRequest(method, url string, body []byte) (*StreamingRequest, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	return &StreamingRequest{req: req, transport: c.transport}, nil
}

// SetHeader sets a header on the streaming request
func (r *StreamingRequest) SetHeader(key, value string) {
	r.req.Header.Set(key, value)
}

// Execute sends the streaming request and returns the streaming response
func (r *StreamingRequest) Execute() (*StreamingResponse, error) {
	return executeStreamingRequest(r.transport, r.req)
}

func (c *StreamingClient) doStreamingRequest(req *http.Request) (*StreamingResponse, error) {
	return executeStreamingRequest(c.transport, req)
}

func executeStreamingRequest(transport *client.Transport, req *http.Request) (*StreamingResponse, error) {
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return &StreamingResponse{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		headers:    resp.Header,
		body:       resp.Body,
	}, nil
}
