package identity

import (
	"bytes"
	"crypto/cipher"
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

// EncryptedResponseWriter wraps an http.ResponseWriter for streaming encryption
type EncryptedResponseWriter struct {
	http.ResponseWriter
	sealer      hpke.Sealer
	wroteHeader bool
	statusCode  int
}

// WriteHeader captures the status code and delegates to the underlying ResponseWriter
func (w *EncryptedResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		// Remove Content-Length as encryption will change the size
		w.ResponseWriter.Header().Del("Content-Length")
		w.statusCode = statusCode
		w.ResponseWriter.WriteHeader(statusCode)
		w.wroteHeader = true
	}
}

// Write encrypts data as chunks and writes them to the underlying ResponseWriter
func (w *EncryptedResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	if len(data) == 0 {
		return 0, nil
	}

	// Encrypt the chunk
	encrypted, err := w.sealer.Seal(data, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Chunk length (4 bytes big-endian) header
	chunkHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkHeader, uint32(len(encrypted)))

	_, err = w.ResponseWriter.Write(chunkHeader)
	if err != nil {
		return 0, err
	}
	_, err = w.ResponseWriter.Write(encrypted)
	if err != nil {
		return 0, err
	}

	// Return the original data length
	return len(data), nil
}

// Flush implements http.Flusher
func (w *EncryptedResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
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

// EncryptRequest creates a streaming encryption reader for the request body
func (i *Identity) EncryptRequest(req *http.Request, recipientPubKey []byte) error {
	if req.Body == nil || req.ContentLength == 0 {
		return nil // Nothing to encrypt
	}

	// Set up encryption
	pk, err := i.KEMScheme().UnmarshalBinaryPublicKey(recipientPubKey)
	if err != nil {
		return fmt.Errorf("invalid recipient public key: %w", err)
	}

	sender, err := i.Suite().NewSender(pk, nil)
	if err != nil {
		return fmt.Errorf("failed to create sender: %w", err)
	}

	encapKey, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to setup encryption: %w", err)
	}

	streamingReader := &StreamingEncryptReader{
		reader: req.Body,
		sealer: sealer,
		buffer: nil,
		eof:    false,
	}

	req.Body = streamingReader
	req.ContentLength = -1 // Unknown length

	req.Header.Set(protocol.ClientPublicKeyHeader, hex.EncodeToString(i.MarshalPublicKey()))
	req.Header.Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(encapKey))
	req.Header.Set("Transfer-Encoding", "chunked")

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

	// Read chunk length (4 bytes)
	chunkLenBytes := make([]byte, 4)
	_, err = io.ReadFull(r.reader, chunkLenBytes)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			r.eof = true
			return 0, io.EOF
		}
		return 0, fmt.Errorf("failed to read chunk length: %w", err)
	}

	chunkLen := binary.BigEndian.Uint32(chunkLenBytes)
	if chunkLen == 0 {
		// Empty chunk, try reading next chunk
		return r.Read(p)
	}

	// Read encrypted chunk
	encryptedChunk := make([]byte, chunkLen)
	_, err = io.ReadFull(r.reader, encryptedChunk)
	if err != nil {
		return 0, fmt.Errorf("failed to read encrypted chunk: %w", err)
	}

	// Decrypt chunk
	decryptedChunk, err := r.opener.Open(encryptedChunk, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt chunk: %w", err)
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

// DecryptRequest creates a streaming decryption reader for the request body
func (i *Identity) DecryptRequest(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil // Nothing to decrypt
	}

	// Get encryption headers
	clientPubKeyHex := req.Header.Get(protocol.ClientPublicKeyHeader)
	encapKeyHex := req.Header.Get(protocol.EncapsulatedKeyHeader)

	if clientPubKeyHex == "" || encapKeyHex == "" {
		return NewClientError(fmt.Errorf("missing encryption headers"))
	}

	// Decrypt
	encapKey, err := hex.DecodeString(encapKeyHex)
	if err != nil {
		return NewClientError(fmt.Errorf("invalid encapsulated key: %w", err))
	}
	receiver, err := i.Suite().NewReceiver(i.sk, nil)
	if err != nil {
		return fmt.Errorf("failed to create receiver: %w", err)
	}
	opener, err := receiver.Setup(encapKey)
	if err != nil {
		return NewClientError(fmt.Errorf("failed to setup decryption: %w", err))
	}

	streamingReader := &StreamingDecryptReader{
		reader: req.Body,
		opener: opener,
		buffer: nil,
		eof:    false,
	}

	req.Body = streamingReader
	req.ContentLength = -1 // Unknown length for streaming

	return nil
}

// SetupResponseEncryption prepares an encrypted response writer for streaming encryption
func (i *Identity) SetupResponseEncryption(w http.ResponseWriter, clientPubKeyHex string) (*EncryptedResponseWriter, error) {
	clientPubKeyBytes, err := hex.DecodeString(clientPubKeyHex)
	if err != nil {
		return nil, NewClientError(fmt.Errorf("invalid client public key: %w", err))
	}

	clientPubKey, err := i.KEMScheme().UnmarshalBinaryPublicKey(clientPubKeyBytes)
	if err != nil {
		return nil, NewClientError(fmt.Errorf("invalid client public key: %w", err))
	}

	sender, err := i.Suite().NewSender(clientPubKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption context: %w", err)
	}
	encapKey, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to setup encryption: %w", err)
	}

	w.Header().Set(protocol.EncapsulatedKeyHeader, hex.EncodeToString(encapKey))
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Del("Content-Length")

	return &EncryptedResponseWriter{
		ResponseWriter: w,
		sealer:         sealer,
		wroteHeader:    false,
	}, nil
}

// DecryptChunkedResponse decrypts a chunked response where each chunk is prefixed with its length
func (i *Identity) DecryptChunkedResponse(data []byte, encapKey []byte) ([]byte, error) {
	receiver, err := i.Suite().NewReceiver(i.sk, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}

	opener, err := receiver.Setup(encapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup decryption: %w", err)
	}

	var result bytes.Buffer
	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		// Read chunk length (4 bytes)
		var chunkLen uint32
		err := binary.Read(reader, binary.BigEndian, &chunkLen)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read chunk length: %w", err)
		}

		if chunkLen == 0 {
			continue
		}

		// Read encrypted chunk data
		encryptedChunk := make([]byte, chunkLen)
		_, err = io.ReadFull(reader, encryptedChunk)
		if err != nil {
			return nil, fmt.Errorf("failed to read encrypted chunk: %w", err)
		}

		// Decrypt chunk
		decryptedChunk, err := opener.Open(encryptedChunk, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt chunk: %w", err)
		}

		result.Write(decryptedChunk)
	}

	return result.Bytes(), nil
}

// =============================================================================
// EHBP v2: Response encryption using derived keys
// =============================================================================

// ResponseContext holds the HPKE context information needed for response encryption.
// This is returned by DecryptRequestWithContext and passed to SetupDerivedResponseEncryption.
type ResponseContext struct {
	opener     hpke.Opener // The opener from request decryption (has Export method)
	RequestEnc []byte      // The encapsulated key from the request
}

// DerivedResponseWriter wraps an http.ResponseWriter for streaming encryption
// using keys derived from the request's HPKE context. This replaces EncryptedResponseWriter
// for the v2 protocol.
type DerivedResponseWriter struct {
	http.ResponseWriter
	aead        cipher.AEAD
	nonceBase   []byte
	seq         uint64
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
// Each chunk is encrypted with AES-256-GCM using a nonce derived from the base nonce
// XORed with the sequence number.
func (w *DerivedResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	if len(data) == 0 {
		return 0, nil
	}

	// Compute nonce for this chunk: nonceBase XOR seq
	nonce := make([]byte, AESGCMNonceLength)
	copy(nonce, w.nonceBase)
	for i := 0; i < 8; i++ {
		nonce[AESGCMNonceLength-1-i] ^= byte(w.seq >> (i * 8))
	}

	// Encrypt the chunk
	encrypted := w.aead.Seal(nil, nonce, data, nil)
	w.seq++

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

// Flush implements http.Flusher
func (w *DerivedResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// DecryptRequestWithContext decrypts the request body and returns the HPKE context
// needed for response encryption. This is the v2 replacement for DecryptRequest.
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
	receiver, err := i.Suite().NewReceiver(i.sk, nil)
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
// keys derived from the request's HPKE context. This is the secure v2 replacement
// for SetupResponseEncryption.
//
// The response encryption keys are derived as follows:
//  1. Export a secret from the HPKE context using label "ehbp response"
//  2. Generate a random response nonce
//  3. Derive key and IV using HKDF with salt = requestEnc || responseNonce
//
// This binds the response encryption to the specific request, preventing MitM attacks.
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
		nonceBase:      km.NonceBase,
		seq:            0,
		wroteHeader:    false,
	}, nil
}

// SetupResponseContextForEmptyBody creates a ResponseContext for requests without a body.
// This is needed when the request has an Ehbp-Encapsulated-Key header but no body,
// and we still need to derive response encryption keys.
func (i *Identity) SetupResponseContextForEmptyBody(encapKeyHex string) (*ResponseContext, error) {
	encapKey, err := hex.DecodeString(encapKeyHex)
	if err != nil {
		return nil, NewClientError(fmt.Errorf("invalid encapsulated key: %w", err))
	}

	receiver, err := i.Suite().NewReceiver(i.sk, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}

	opener, err := receiver.Setup(encapKey)
	if err != nil {
		return nil, NewClientError(fmt.Errorf("failed to setup decryption context: %w", err))
	}

	return &ResponseContext{
		opener:     opener,
		RequestEnc: encapKey,
	}, nil
}
