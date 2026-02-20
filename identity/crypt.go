package identity

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudflare/circl/hpke"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// ClientError represents an error caused by invalid client input
type ClientError struct {
	Err error
}

func (e ClientError) Error() string {
	return e.Err.Error()
}

func (e ClientError) Unwrap() error {
	return e.Err
}

// NewClientError wraps an error as a client-caused error
func NewClientError(err error) error {
	return ClientError{Err: err}
}

// IsClientError determines if an error is caused by invalid client input
func IsClientError(err error) bool {
	var clientErr ClientError
	return errors.As(err, &clientErr)
}

// KeyConfigError represents a client/server key configuration mismatch.
// This is used for stale or incompatible HPKE key material that requires rekey.
type KeyConfigError struct {
	Err error
}

func (e KeyConfigError) Error() string {
	return e.Err.Error()
}

func (e KeyConfigError) Unwrap() error {
	return e.Err
}

// NewKeyConfigError wraps an error as a key configuration mismatch.
func NewKeyConfigError(err error) error {
	return KeyConfigError{Err: err}
}

// IsKeyConfigError determines if an error indicates key configuration mismatch.
func IsKeyConfigError(err error) bool {
	var keyErr KeyConfigError
	return errors.As(err, &keyErr)
}

// StreamingEncryptReader wraps an io.Reader for streaming encryption
type StreamingEncryptReader struct {
	reader io.Reader
	sealer hpke.Sealer
	buffer []byte
	eof    bool
}

// Read implements io.Reader, encrypting data as it's read
func (r *StreamingEncryptReader) Read(p []byte) (n int, err error) {
	if r.eof && len(r.buffer) == 0 {
		return 0, io.EOF
	}

	// If we have buffered encrypted data, return it first
	if len(r.buffer) > 0 {
		n = copy(p, r.buffer)
		r.buffer = r.buffer[n:]
		return n, nil
	}

	if r.eof {
		return 0, io.EOF
	}

	// Read some data from the underlying reader
	chunkSize := min(8192, len(p)) // 8KB chunks

	plaintext := make([]byte, chunkSize)
	bytesRead, err := r.reader.Read(plaintext)
	if err != nil {
		if err == io.EOF {
			r.eof = true
			if bytesRead == 0 {
				return 0, io.EOF
			}
		} else {
			return 0, err
		}
	}

	if bytesRead == 0 {
		return 0, io.EOF
	}

	// Encrypt chunk
	encrypted, err := r.sealer.Seal(plaintext[:bytesRead], nil)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt chunk: %w", err)
	}

	// Chunk with length prefix
	chunkHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkHeader, uint32(len(encrypted)))

	fullChunk := append(chunkHeader, encrypted...)

	// Return as much as fits in p
	n = copy(p, fullChunk)
	if n < len(fullChunk) {
		r.buffer = fullChunk[n:]
	}

	return n, nil
}

// Close implements io.Closer
func (r *StreamingEncryptReader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamingDecryptReader wraps an io.Reader for streaming decryption
type StreamingDecryptReader struct {
	reader io.Reader
	opener hpke.Opener
	buffer []byte
	eof    bool
}

// NewStreamingDecryptReader creates a new streaming decrypt reader
func NewStreamingDecryptReader(reader io.Reader, opener hpke.Opener) *StreamingDecryptReader {
	return &StreamingDecryptReader{
		reader: reader,
		opener: opener,
		buffer: nil,
		eof:    false,
	}
}

// Read implements io.Reader, decrypting data as it's read
func (r *StreamingDecryptReader) Read(p []byte) (n int, err error) {
	if r.eof {
		return 0, io.EOF
	}

	// If we have buffered decrypted data, return it first
	if len(r.buffer) > 0 {
		n = copy(p, r.buffer)
		r.buffer = r.buffer[n:]
		return n, nil
	}

	// Read chunk length (4 bytes), skipping empty chunks
	var chunkLen uint32
	chunkLenBytes := make([]byte, 4)
	for {
		_, err = io.ReadFull(r.reader, chunkLenBytes)
		if err != nil {
			if err == io.EOF {
				r.eof = true
				return 0, io.EOF
			}
			if err == io.ErrUnexpectedEOF {
				return 0, NewClientError(fmt.Errorf("invalid chunk length framing: %w", err))
			}
			return 0, NewClientError(fmt.Errorf("failed to read chunk length: %w", err))
		}

		chunkLen = binary.BigEndian.Uint32(chunkLenBytes)
		if chunkLen != 0 {
			break
		}
	}

	// Read encrypted chunk
	encryptedChunk := make([]byte, chunkLen)
	_, err = io.ReadFull(r.reader, encryptedChunk)
	if err != nil {
		return 0, NewClientError(fmt.Errorf("failed to read encrypted chunk: %w", err))
	}

	// Decrypt chunk
	decryptedChunk, err := r.opener.Open(encryptedChunk, nil)
	if err != nil {
		// Decryption failure at this stage typically indicates request/receiver key mismatch
		// (for example stale client key after server key rotation).
		return 0, NewKeyConfigError(fmt.Errorf("failed to decrypt chunk: %w", err))
	}

	// Return as much as fits in p, buffer the rest
	n = copy(p, decryptedChunk)
	if n < len(decryptedChunk) {
		r.buffer = decryptedChunk[n:]
	}

	return n, nil
}

// Close implements io.Closer
func (r *StreamingDecryptReader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// =============================================================================
// Server-side: Request decryption and response encryption
// =============================================================================

// ResponseContext holds the HPKE context information needed for response encryption.
// This is returned by DecryptRequestWithContext and passed to SetupDerivedResponseEncryption.
type ResponseContext struct {
	opener     hpke.Opener // The opener from request decryption (has Export method)
	RequestEnc []byte      // The encapsulated key from the request
}

// DerivedResponseWriter wraps an http.ResponseWriter for streaming encryption
// using keys derived from the request's HPKE context.
type DerivedResponseWriter struct {
	http.ResponseWriter
	aead        *ResponseAEAD
	wroteHeader bool
	statusCode  int
}

// WriteHeader captures the status code and delegates to the underlying ResponseWriter
func (w *DerivedResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.ResponseWriter.Header().Del("Content-Length")
		w.statusCode = statusCode
		w.ResponseWriter.WriteHeader(statusCode)
		w.wroteHeader = true
	}
}

// Write encrypts data as chunks and writes them to the underlying ResponseWriter.
func (w *DerivedResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	if len(data) == 0 {
		return 0, nil
	}

	// Encrypt the chunk (nonce is computed and sequence incremented automatically)
	encrypted := w.aead.Seal(data, nil)

	// Write chunk header (4 bytes big-endian length)
	chunkHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkHeader, uint32(len(encrypted)))

	if _, err := w.ResponseWriter.Write(chunkHeader); err != nil {
		return 0, err
	}
	if _, err := w.ResponseWriter.Write(encrypted); err != nil {
		return 0, err
	}

	return len(data), nil
}

func (w *DerivedResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// DecryptRequestWithContext decrypts the request body and returns the HPKE context
// needed for response encryption.
//
// The returned ResponseContext contains the HPKE opener which can be used to
// export the shared secret for response key derivation.
func (i *Identity) DecryptRequestWithContext(req *http.Request) (*ResponseContext, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}

	// Get the encapsulated key header
	encapKeyHex := req.Header.Get(protocol.EncapsulatedKeyHeader)
	if encapKeyHex == "" {
		return nil, NewClientError(fmt.Errorf("missing %s header", protocol.EncapsulatedKeyHeader))
	}

	encapKey, err := hex.DecodeString(encapKeyHex)
	if err != nil {
		return nil, NewClientError(fmt.Errorf("invalid encapsulated key: %w", err))
	}

	// Create receiver and setup decryption
	// The info parameter must match the sender's info for domain separation
	receiver, err := i.Suite().NewReceiver(i.sk, []byte(HPKERequestInfo))
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}

	opener, err := receiver.Setup(encapKey)
	if err != nil {
		return nil, NewClientError(fmt.Errorf("failed to setup decryption: %w", err))
	}

	// Wrap the body with streaming decryption
	streamingReader := &StreamingDecryptReader{
		reader: req.Body,
		opener: opener,
		buffer: nil,
		eof:    false,
	}

	req.Body = streamingReader
	req.ContentLength = -1

	// Return the context for response encryption
	return &ResponseContext{
		opener:     opener,
		RequestEnc: encapKey,
	}, nil
}

// SetupDerivedResponseEncryption creates an encrypted response writer using
// keys derived from the request's HPKE context.
func (i *Identity) SetupDerivedResponseEncryption(
	w http.ResponseWriter,
	respCtx *ResponseContext,
) (*DerivedResponseWriter, error) {
	if respCtx == nil {
		return nil, fmt.Errorf("response context is nil")
	}

	// Export secret from the request's HPKE context
	exportedSecret := respCtx.opener.Export([]byte(ExportLabel), uint(ExportLength))

	// Generate random response nonce
	responseNonce := make([]byte, ResponseNonceLength)
	if _, err := rand.Read(responseNonce); err != nil {
		return nil, fmt.Errorf("failed to generate response nonce: %w", err)
	}

	// Derive response keys
	km, err := DeriveResponseKeys(exportedSecret, respCtx.RequestEnc, responseNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to derive response keys: %w", err)
	}

	// Create AEAD
	aead, err := km.NewResponseAEAD()
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	// Set response headers
	w.Header().Set(protocol.ResponseNonceHeader, hex.EncodeToString(responseNonce))
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Del("Content-Length")

	return &DerivedResponseWriter{
		ResponseWriter: w,
		aead:           aead,
		wroteHeader:    false,
	}, nil
}

// =============================================================================
// Client-side: Request encryption and response decryption
// =============================================================================

// RequestContext holds the HPKE context needed for response decryption.
// This is returned by EncryptRequestWithContext and passed to DecryptResponseWithContext.
type RequestContext struct {
	Sealer     hpke.Sealer // The sealer from request encryption (has Export method)
	RequestEnc []byte      // The encapsulated key we sent
}

// EncryptRequestWithContext encrypts the request body TO this identity's public key
// and returns the HPKE context needed for response decryption.
//
// For bodyless requests (no body or empty body), returns nil - the request passes
// through unencrypted and the response will also be unencrypted.
// See SPEC.md Section 6.4 for the security rationale.
func (i *Identity) EncryptRequestWithContext(req *http.Request) (*RequestContext, error) {
	// Bodyless requests pass through unencrypted - no HPKE context needed
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 {
		return nil, nil
	}

	// Set up encryption to this identity's public key
	sender, err := i.Suite().NewSender(i.pk, []byte(HPKERequestInfo))
	if err != nil {
		return nil, fmt.Errorf("failed to create sender: %w", err)
	}

	encapKey, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to setup encryption: %w", err)
	}

	// Set the request enc header
	req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(encapKey))
	req.Header.Set("Transfer-Encoding", "chunked")

	// Wrap body with streaming encryption
	streamingReader := &StreamingEncryptReader{
		reader: req.Body,
		sealer: sealer,
		buffer: nil,
		eof:    false,
	}
	req.Body = streamingReader
	req.ContentLength = -1

	return &RequestContext{
		Sealer:     sealer,
		RequestEnc: encapKey,
	}, nil
}

// DecryptResponse decrypts a response using keys derived from the request's HPKE context.
//
// The response decryption keys are derived using the same process as the server:
//  1. Export a secret from the HPKE context using label "ehbp response"
//  2. Read the response nonce from the Ehbp-Response-Nonce header
//  3. Derive key and IV using HKDF with salt = requestEnc || responseNonce
func (ctx *RequestContext) DecryptResponse(resp *http.Response) error {
	if ctx == nil {
		return fmt.Errorf("request context is nil")
	}

	// Get response nonce from header
	responseNonceHex := resp.Header.Get(protocol.ResponseNonceHeader)
	if responseNonceHex == "" {
		return fmt.Errorf("missing %s header", protocol.ResponseNonceHeader)
	}

	responseNonce, err := hex.DecodeString(responseNonceHex)
	if err != nil {
		return fmt.Errorf("invalid response nonce: %w", err)
	}

	if len(responseNonce) != ResponseNonceLength {
		return fmt.Errorf("invalid response nonce length: expected %d, got %d",
			ResponseNonceLength, len(responseNonce))
	}

	// Export secret from request context
	exportedSecret := ctx.Sealer.Export([]byte(ExportLabel), uint(ExportLength))

	// Derive response keys
	km, err := DeriveResponseKeys(exportedSecret, ctx.RequestEnc, responseNonce)
	if err != nil {
		return fmt.Errorf("failed to derive response keys: %w", err)
	}

	// Create AEAD for decryption
	aead, err := km.NewResponseAEAD()
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	// Wrap response body with streaming decryption
	resp.Body = &DerivedStreamingDecryptReader{
		reader: resp.Body,
		aead:   aead,
		buffer: nil,
		eof:    false,
	}
	resp.ContentLength = -1

	return nil
}

// DerivedStreamingDecryptReader decrypts response chunks using derived keys.
type DerivedStreamingDecryptReader struct {
	reader io.Reader
	aead   *ResponseAEAD
	buffer []byte
	eof    bool
}

// Read implements io.Reader, decrypting chunks as they are read.
func (r *DerivedStreamingDecryptReader) Read(p []byte) (n int, err error) {
	if r.eof {
		return 0, io.EOF
	}

	// Return buffered data first
	if len(r.buffer) > 0 {
		n = copy(p, r.buffer)
		r.buffer = r.buffer[n:]
		return n, nil
	}

	// Read chunk length (4 bytes), skipping empty chunks
	var chunkLen uint32
	chunkLenBytes := make([]byte, 4)
	for {
		_, err = io.ReadFull(r.reader, chunkLenBytes)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				r.eof = true
				return 0, io.EOF
			}
			return 0, fmt.Errorf("failed to read chunk length: %w", err)
		}

		chunkLen = binary.BigEndian.Uint32(chunkLenBytes)
		if chunkLen != 0 {
			break
		}
	}

	// Read encrypted chunk
	encryptedChunk := make([]byte, chunkLen)
	_, err = io.ReadFull(r.reader, encryptedChunk)
	if err != nil {
		return 0, fmt.Errorf("failed to read encrypted chunk: %w", err)
	}

	// Decrypt chunk (nonce is computed and sequence incremented automatically)
	decryptedChunk, err := r.aead.Open(encryptedChunk, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt chunk: %w", err)
	}

	// Return as much as fits, buffer the rest
	n = copy(p, decryptedChunk)
	if n < len(decryptedChunk) {
		r.buffer = decryptedChunk[n:]
	}

	return n, nil
}

func (r *DerivedStreamingDecryptReader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
