package noisews

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/flynn/noise"
)

// wsVectorPath is the shared cross-language vector file. Regenerate it with:
//
//	EHBP_WRITE_VECTORS=1 go test -run TestNoiseWSInteropVector ./noisews/
const wsVectorPath = "../test-vectors/noisews.json"

type wsVectorRecord struct {
	Dir        string `json:"dir"`
	Type       string `json:"type"`
	Payload    string `json:"payload"`
	Ciphertext string `json:"ciphertext"`
}

type wsVector struct {
	ProtocolName           string           `json:"protocolName"`
	Prologue               string           `json:"prologue"`
	ServerStaticPrivate    string           `json:"serverStaticPrivate"`
	ServerStaticPublic     string           `json:"serverStaticPublic"`
	ClientEphemeralPrivate string           `json:"clientEphemeralPrivate"`
	ServerEphemeralPrivate string           `json:"serverEphemeralPrivate"`
	Message1               string           `json:"message1"`
	Message2               string           `json:"message2"`
	HandshakeHash          string           `json:"handshakeHash"`
	RekeyInterval          uint64           `json:"rekeyInterval"`
	Records                []wsVectorRecord `json:"records"`
}

func mustHex(t *testing.T, field, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex in %s: %v", field, err)
	}
	return b
}

func fixedKeypair(t *testing.T, priv []byte) noise.DHKey {
	t.Helper()
	key, err := cipherSuite().GenerateKeypair(bytes.NewReader(priv))
	if err != nil {
		t.Fatalf("failed to derive keypair: %v", err)
	}
	return key
}

// runWSVector executes the handshake and record transcript described by the
// vector's inputs and fills in the computed outputs (public key, handshake
// messages, hash, and record ciphertexts).
func runWSVector(t *testing.T, v *wsVector) {
	t.Helper()
	if v.ProtocolName != "Noise_NK_25519_AESGCM_SHA256" {
		t.Fatalf("unexpected protocol name %q", v.ProtocolName)
	}
	serverStatic := fixedKeypair(t, mustHex(t, "serverStaticPrivate", v.ServerStaticPrivate))
	v.ServerStaticPublic = hex.EncodeToString(serverStatic.Public)

	// WriteMessage draws the ephemeral from the configured Random source, so
	// a fixed reader makes the handshake deterministic.
	clientHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite(),
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		Prologue:    []byte(v.Prologue),
		PeerStatic:  serverStatic.Public,
		Random:      bytes.NewReader(mustHex(t, "clientEphemeralPrivate", v.ClientEphemeralPrivate)),
	})
	if err != nil {
		t.Fatalf("client handshake state: %v", err)
	}
	serverHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		Prologue:      []byte(v.Prologue),
		StaticKeypair: serverStatic,
		Random:        bytes.NewReader(mustHex(t, "serverEphemeralPrivate", v.ServerEphemeralPrivate)),
	})
	if err != nil {
		t.Fatalf("server handshake state: %v", err)
	}

	msg1, _, _, err := clientHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("client write message 1: %v", err)
	}
	if _, _, _, err := serverHS.ReadMessage(nil, msg1); err != nil {
		t.Fatalf("server read message 1: %v", err)
	}
	msg2, sCS1, sCS2, err := serverHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("server write message 2: %v", err)
	}
	_, cCS1, cCS2, err := clientHS.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("client read message 2: %v", err)
	}
	if !bytes.Equal(clientHS.ChannelBinding(), serverHS.ChannelBinding()) {
		t.Fatal("handshake hashes diverged")
	}
	v.Message1 = hex.EncodeToString(msg1)
	v.Message2 = hex.EncodeToString(msg2)
	v.HandshakeHash = hex.EncodeToString(clientHS.ChannelBinding())

	if v.RekeyInterval == 0 {
		t.Fatal("rekeyInterval must be positive")
	}
	var c2sCount, s2cCount uint64
	for i := range v.Records {
		rec := &v.Records[i]
		payload := mustHex(t, "payload", rec.Payload)
		var record []byte
		switch rec.Type {
		case "data":
			record = append([]byte{recordData}, payload...)
		case "close":
			record = append([]byte{recordClose}, payload...)
		default:
			t.Fatalf("record %d: unknown type %q", i, rec.Type)
		}
		var send, recv *noise.CipherState
		var count *uint64
		switch rec.Dir {
		case "c2s":
			send, recv, count = cCS1, sCS1, &c2sCount
		case "s2c":
			send, recv, count = sCS2, cCS2, &s2cCount
		default:
			t.Fatalf("record %d: unknown dir %q", i, rec.Dir)
		}
		ciphertext, err := send.Encrypt(nil, nil, record)
		if err != nil {
			t.Fatalf("record %d: encrypt: %v", i, err)
		}
		plaintext, err := recv.Decrypt(nil, nil, ciphertext)
		if err != nil {
			t.Fatalf("record %d: decrypt: %v", i, err)
		}
		if !bytes.Equal(plaintext, record) {
			t.Fatalf("record %d: round trip mismatch", i)
		}
		// Mirror the connection's schedule: every record counts, including
		// close records, and both sides rekey on the interval boundary.
		*count++
		if *count%v.RekeyInterval == 0 {
			send.Rekey()
			recv.Rekey()
		}
		rec.Ciphertext = hex.EncodeToString(ciphertext)
	}
}

// canonicalWSVector defines the vector inputs; outputs are computed by
// runWSVector during generation.
func canonicalWSVector() *wsVector {
	seq := func(start byte, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = start + byte(i)
		}
		return hex.EncodeToString(b)
	}
	text := func(s string) string { return hex.EncodeToString([]byte(s)) }
	return &wsVector{
		ProtocolName:           "Noise_NK_25519_AESGCM_SHA256",
		Prologue:               Prologue,
		ServerStaticPrivate:    seq(0xa0, 32),
		ClientEphemeralPrivate: seq(0x40, 32),
		ServerEphemeralPrivate: seq(0x60, 32),
		RekeyInterval:          4,
		Records: []wsVectorRecord{
			{Dir: "c2s", Type: "data", Payload: text("hello from client")},
			{Dir: "s2c", Type: "data", Payload: text("hello from server")},
			{Dir: "c2s", Type: "data", Payload: ""},
			{Dir: "s2c", Type: "data", Payload: seq(0x00, 64)},
			{Dir: "c2s", Type: "data", Payload: seq(0x80, 64)},
			{Dir: "s2c", Type: "data", Payload: ""},
			{Dir: "c2s", Type: "data", Payload: text("client crosses the rekey boundary")},
			{Dir: "s2c", Type: "data", Payload: text("server crosses the rekey boundary")},
			{Dir: "c2s", Type: "data", Payload: text("client sends under fresh keys")},
			{Dir: "s2c", Type: "data", Payload: text("server sends under fresh keys")},
			{Dir: "c2s", Type: "close", Payload: ""},
			{Dir: "s2c", Type: "close", Payload: ""},
		},
	}
}

func TestNoiseWSInteropVector(t *testing.T) {
	if os.Getenv("EHBP_WRITE_VECTORS") != "" {
		v := canonicalWSVector()
		runWSVector(t, v)
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("marshal vector: %v", err)
		}
		if err := os.WriteFile(wsVectorPath, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write vector: %v", err)
		}
		t.Logf("wrote %s", wsVectorPath)
		return
	}

	raw, err := os.ReadFile(wsVectorPath)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var want wsVector
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse vector: %v", err)
	}

	got := want
	got.Records = make([]wsVectorRecord, len(want.Records))
	copy(got.Records, want.Records)
	runWSVector(t, &got)

	if got.ServerStaticPublic != want.ServerStaticPublic {
		t.Errorf("server static public mismatch:\n got %s\nwant %s", got.ServerStaticPublic, want.ServerStaticPublic)
	}
	if got.Message1 != want.Message1 {
		t.Errorf("message 1 mismatch:\n got %s\nwant %s", got.Message1, want.Message1)
	}
	if got.Message2 != want.Message2 {
		t.Errorf("message 2 mismatch:\n got %s\nwant %s", got.Message2, want.Message2)
	}
	if got.HandshakeHash != want.HandshakeHash {
		t.Errorf("handshake hash mismatch:\n got %s\nwant %s", got.HandshakeHash, want.HandshakeHash)
	}
	for i := range want.Records {
		if got.Records[i].Ciphertext != want.Records[i].Ciphertext {
			t.Errorf("record %d ciphertext mismatch:\n got %s\nwant %s", i, got.Records[i].Ciphertext, want.Records[i].Ciphertext)
		}
	}
}
