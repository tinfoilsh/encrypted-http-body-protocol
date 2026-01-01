// Package mobile provides gomobile-compatible bindings for the EHBP client.
// This package wraps the EHBP client with types that can be exported via gomobile.
package mobile

import (
	"bytes"
	"io"
	"net/http"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
)

// Response wraps an HTTP response with mobile-friendly types
type Response struct {
	Status     string
	StatusCode int
	Body       []byte
	headers    http.Header
}

// GetHeader returns the value of a response header
func (r *Response) GetHeader(key string) string {
	return r.headers.Get(key)
}

// Client provides encrypted HTTP communication using the EHBP protocol.
// It automatically encrypts request bodies and decrypts response bodies.
type Client struct {
	transport *client.Transport
	serverURL string
}

// NewClient creates a new EHBP client for the given server URL.
// It fetches the server's HPKE public key from /.well-known/hpke-keys
func NewClient(serverURL string) (*Client, error) {
	transport, err := client.NewTransport(serverURL, false)
	if err != nil {
		return nil, err
	}
	return &Client{
		transport: transport,
		serverURL: serverURL,
	}, nil
}

// NewClientWithHPKEKey creates a new EHBP client with a pre-fetched HPKE public key.
// The hpkeConfig should be the raw bytes from /.well-known/hpke-keys (RFC 9458 format).
func NewClientWithHPKEKey(serverURL string, hpkeConfig []byte) (*Client, error) {
	transport, err := client.NewTransportWithConfig(serverURL, hpkeConfig, false)
	if err != nil {
		return nil, err
	}
	return &Client{
		transport: transport,
		serverURL: serverURL,
	}, nil
}

// ServerPublicKeyHex returns the server's HPKE public key as a hex string
func (c *Client) ServerPublicKeyHex() string {
	return c.transport.ServerIdentity().MarshalPublicKeyHex()
}

// Post makes an encrypted HTTP POST request
func (c *Client) Post(url string, contentType string, body []byte) (*Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.doRequest(req)
}

// Get makes an HTTP GET request (body passes through unencrypted per EHBP spec)
func (c *Client) Get(url string) (*Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

// Request represents a pending HTTP request that can have headers added
type Request struct {
	req       *http.Request
	transport *client.Transport
}

// NewRequest creates a new request with the given method, URL, and optional body
func (c *Client) NewRequest(method, url string, body []byte) (*Request, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	return &Request{req: req, transport: c.transport}, nil
}

// SetHeader sets a header on the request
func (r *Request) SetHeader(key, value string) {
	r.req.Header.Set(key, value)
}

// Execute sends the request and returns the response
func (r *Request) Execute() (*Response, error) {
	return executeRequest(r.transport, r.req)
}

// Put makes an encrypted HTTP PUT request
func (c *Client) Put(url string, contentType string, body []byte) (*Response, error) {
	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.doRequest(req)
}

// Delete makes an HTTP DELETE request
func (c *Client) Delete(url string) (*Response, error) {
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

func (c *Client) doRequest(req *http.Request) (*Response, error) {
	return executeRequest(c.transport, req)
}

func executeRequest(transport *client.Transport, req *http.Request) (*Response, error) {
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Body:       body,
		headers:    resp.Header,
	}, nil
}
