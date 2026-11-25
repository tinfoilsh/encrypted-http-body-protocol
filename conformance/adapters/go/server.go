// The server-side operations of conformance/spec/operations.md
// (decrypt_request, middleware_request): the one part of an adapter that is
// hand-written, because only Go ships the server. main.go's dispatch calls
// these; they share its helpers.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
	core "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/EHBP"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/internal/eventresidue"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

func encryptedRequest(id *identity.Identity, plaintext []byte) (*http.Request, []byte, error) {
	req := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader(plaintext))
	if _, err := client.Core().EncryptRequest(id.MarshalPublicKey(), req); err != nil {
		return nil, nil, err
	}
	// Read in fixed 8 KiB steps so the encryptor emits deterministic 8 KiB
	// plaintext frames; io.ReadAll's growing buffers would make frame sizes,
	// and therefore the authenticated prefix, depend on allocator behaviour.
	var framed []byte
	buf := make([]byte, 8192)
	for {
		n, err := req.Body.Read(buf)
		framed = append(framed, buf[:n]...)
		if err == io.EOF {
			return req, framed, nil
		}
		if err != nil {
			return nil, nil, err
		}
	}
}

// decryptRequest drives the core's server driver (what Middleware runs) with
// structural mutations. It bypasses Middleware because a refusal reaches the
// wire as a bare 400 and only the driver's failure carries the canonical
// code. The 64 MiB+1 case runs in this disposable adapter process so a
// vulnerable allocation cannot take down the harness itself.
func decryptRequest(fx *fixture, r *result) error {
	id, err := identity.NewIdentity()
	if err != nil {
		return err
	}
	template, framed, err := encryptedRequest(id, []byte("after-zero-frames"))
	if err != nil {
		return err
	}
	mutation := strIn(fx, "mutation")
	body := framed
	switch mutation {
	case "oversized_frame":
		body = make([]byte, 4)
		binary.BigEndian.PutUint32(body, (64<<20)+1)
	case "partial_prefix":
		body = []byte{0, 0, 0}
	case "zero_frame_burst":
		count := 10000
		if v, ok := fx.Inputs["zeroFrameCount"].(float64); ok {
			count = int(v)
		}
		if count < 0 || count > 1_000_000 {
			return fmt.Errorf("zeroFrameCount out of range: %d", count)
		}
		body = append(make([]byte, count*4), framed...)
	}
	req := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader(body))
	copyEncapsulatedKey(req, template)
	if mutation == "duplicate_encapsulated_key" {
		req.Header.Add(protocol.EncapsulatedKeyHeader, strings.Repeat("0", 64))
	}
	var keys identity.IdentityStore
	if exported, err := id.Export(); err != nil {
		return err
	} else if err := json.Unmarshal(exported, &keys); err != nil {
		return err
	}
	x := eventresidue.NewServer(keys.SecretKey, keys.PublicKey, req.Body, httptest.NewRecorder())
	x.Start(req.Header, true)
	if x.Failure != nil {
		return x.Failure
	}
	plain, err := readTracked(&eventresidue.Body{X: x}, r)
	if err != nil {
		return err
	}
	setBody(r, plain)
	return nil
}

// middlewareRequest verifies the server releases request plaintext one
// authenticated frame at a time (SPEC 4.3): the handler reads the body to EOF,
// the tampered trailing frame fails that read, and only the authenticated
// prefix was delivered before the error.
func middlewareRequest(fx *fixture, r *result) error {
	if strIn(fx, "mutation") != "trailing_tamper" {
		return fmt.Errorf("unknown middleware mutation")
	}
	id, err := identity.NewIdentity()
	if err != nil {
		return err
	}
	// Two full frames that authenticate, then a short one that is tampered.
	frame := int(core.Companion_Default___.RequestFrameBytes())
	template, framed, err := encryptedRequest(id, bytes.Repeat([]byte("x"), 2*frame+4096))
	if err != nil {
		return err
	}
	framed[len(framed)-1] ^= 1
	req := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader(framed))
	copyEncapsulatedKey(req, template)

	var readErr error
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, readErr = readTracked(req.Body, r); readErr != nil {
			// Return without writing: the middleware then answers with the
			// protocol status (SPEC 5.2) instead of aborting a started response.
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	id.Middleware()(handler).ServeHTTP(rec, req)
	if readErr != nil {
		return readErr
	}
	if rec.Code != http.StatusOK {
		return identity.NewClientError(fmt.Errorf("request rejected with status %d", rec.Code))
	}
	return nil
}

// copyEncapsulatedKey carries the encrypted template's key header onto the
// probe request, preserving repeats so duplicate-header probes stay exact.
func copyEncapsulatedKey(dst, src *http.Request) {
	for _, value := range src.Header.Values(protocol.EncapsulatedKeyHeader) {
		dst.Header.Add(protocol.EncapsulatedKeyHeader, value)
	}
}
