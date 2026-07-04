package noisews

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
)

const (
	recordData  = 0x01
	recordClose = 0x02
)

// ErrTruncated indicates the connection ended without the peer's encrypted
// close record, so the stream may have been cut short by an intermediary.
var ErrTruncated = errors.New("noisews: connection closed without encrypted close record")

// ErrClosed indicates the connection was closed locally, either by Close or
// by a context expiring during Read or Write (which closes the underlying
// WebSocket).
var ErrClosed = errors.New("noisews: connection closed")

// Conn is a message-oriented connection whose payloads are encrypted
// end-to-end inside WebSocket binary messages. One Read and one Write may
// be in flight concurrently; multiple concurrent Reads or Writes are
// serialized.
type Conn struct {
	ws             *websocket.Conn
	maxMessageSize int

	// localClosed is set before the WebSocket is torn down locally so that
	// a concurrently blocked Read can report ErrClosed instead of
	// misreporting truncation.
	localClosed atomic.Bool

	readMu     sync.Mutex
	recv       *noise.CipherState
	recvCount  uint64
	peerClosed bool
	readErr    error

	writeMu   sync.Mutex
	send      *noise.CipherState
	sendCount uint64
	closeSent bool

	closeOnce sync.Once
	closeErr  error
}

func newConn(ws *websocket.Conn, send, recv *noise.CipherState, maxMessageSize int) *Conn {
	ws.SetReadLimit(int64(maxMessageSize) + recordOverhead)
	return &Conn{
		ws:             ws,
		maxMessageSize: maxMessageSize,
		send:           send,
		recv:           recv,
	}
}

// Write encrypts payload as a single data record and sends it as one
// WebSocket binary message. If ctx expires mid-write the whole connection is
// closed.
func (c *Conn) Write(ctx context.Context, payload []byte) error {
	if len(payload) > c.maxMessageSize {
		return fmt.Errorf("noisews: message of %d bytes exceeds maximum size %d", len(payload), c.maxMessageSize)
	}
	record := make([]byte, 1+len(payload))
	record[0] = recordData
	copy(record[1:], payload)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closeSent || c.localClosed.Load() {
		return ErrClosed
	}
	return c.writeRecordLocked(ctx, record)
}

func (c *Conn) writeRecordLocked(ctx context.Context, record []byte) error {
	ciphertext, err := c.send.Encrypt(nil, nil, record)
	if err != nil {
		return fmt.Errorf("noisews: encrypt: %w", err)
	}
	c.sendCount++
	if c.sendCount%rekeyEvery.Load() == 0 {
		c.send.Rekey()
	}
	if err := c.ws.Write(ctx, websocket.MessageBinary, ciphertext); err != nil {
		if ctx.Err() != nil {
			// The library closes the connection on context expiry; record
			// that the teardown was local so a reader reports ErrClosed
			// rather than truncation.
			c.localClosed.Store(true)
		}
		return err
	}
	return nil
}

// Read receives one record and returns its decrypted payload. It returns
// io.EOF after the peer's encrypted close record, ErrClosed after a local
// Close, and an error wrapping ErrTruncated if the connection ends without
// the peer's close record. If ctx expires mid-read the whole connection is
// closed. Errors other than io.EOF are terminal and sticky.
func (c *Conn) Read(ctx context.Context) ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.peerClosed {
		return nil, io.EOF
	}
	if c.readErr != nil {
		return nil, c.readErr
	}

	typ, ciphertext, err := c.ws.Read(ctx)
	if err != nil {
		if c.localClosed.Load() {
			c.readErr = ErrClosed
			return nil, ErrClosed
		}
		if ctx.Err() != nil {
			// The library closes the connection on context expiry.
			c.localClosed.Store(true)
			c.readErr = ErrClosed
			return nil, err
		}
		c.readErr = fmt.Errorf("%w: %v", ErrTruncated, err)
		return nil, c.readErr
	}
	if typ != websocket.MessageBinary {
		return nil, c.terminate(fmt.Errorf("noisews: unexpected %v message", typ))
	}

	record, err := c.recv.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, c.terminate(fmt.Errorf("noisews: decrypt: %w", err))
	}
	c.recvCount++
	if c.recvCount%rekeyEvery.Load() == 0 {
		c.recv.Rekey()
	}
	if len(record) == 0 {
		return nil, c.terminate(errors.New("noisews: empty record"))
	}

	switch record[0] {
	case recordData:
		// The WebSocket read limit leaves margin above the payload cap, so
		// the decrypted payload size must be checked explicitly.
		if len(record)-1 > c.maxMessageSize {
			return nil, c.terminate(fmt.Errorf("noisews: received message of %d bytes exceeds maximum size %d", len(record)-1, c.maxMessageSize))
		}
		return record[1:], nil
	case recordClose:
		c.peerClosed = true
		_ = c.Close()
		return nil, io.EOF
	default:
		return nil, c.terminate(fmt.Errorf("noisews: unknown record type 0x%02x", record[0]))
	}
}

// Close sends an encrypted close record and performs the WebSocket close
// handshake. The record lets the peer distinguish an intentional shutdown
// from truncation by an intermediary. Close is idempotent and unblocks a
// concurrent Read.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.localClosed.Store(true)

		c.writeMu.Lock()
		c.closeSent = true
		ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
		writeErr := c.writeRecordLocked(ctx, []byte{recordClose})
		cancel()
		c.writeMu.Unlock()

		closeErr := c.ws.Close(websocket.StatusNormalClosure, "")
		if writeErr != nil {
			c.closeErr = writeErr
		} else {
			c.closeErr = closeErr
		}
	})
	return c.closeErr
}

// Ping sends a WebSocket ping and waits for the pong. Ping frames belong to
// the WebSocket layer and are not end-to-end encrypted; they must not carry
// application data. If ctx expires mid-ping the whole connection is closed.
func (c *Conn) Ping(ctx context.Context) error {
	if err := c.ws.Ping(ctx); err != nil {
		if ctx.Err() != nil {
			c.localClosed.Store(true)
		}
		return err
	}
	return nil
}

// terminate records err as the sticky read error and tears the connection
// down immediately after a protocol violation. Waiting for a close handshake
// would let a misbehaving peer pin resources, so no close frame exchange is
// attempted. The caller must hold readMu.
func (c *Conn) terminate(err error) error {
	c.readErr = err
	c.localClosed.Store(true)
	_ = c.ws.CloseNow()
	return err
}
