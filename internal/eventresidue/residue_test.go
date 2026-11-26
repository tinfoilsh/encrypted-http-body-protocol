package eventresidue_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ev "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen-events/go/EHBPEvents"
	core "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/EHBP"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/internal/eventresidue"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSelfCheckPasses(t *testing.T) {
	if failures := eventresidue.SelfCheck(); len(failures) != 0 {
		t.Fatalf("self-check failures: %v", failures)
	}
}

// The RFC 9180 vector (base mode, X25519 / HKDF-SHA256 / AES-256-GCM) through
// the Dafny HPKE machine and this residue's native primitives, with the
// vector's ephemeral scalar injected in place of RandomBytes.
func TestHpkeVectorWithNativePrimitives(t *testing.T) {
	saved := eventresidue.Rand
	eventresidue.Rand = bytes.NewReader(unhex(t, "179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11"))
	defer func() { eventresidue.Rand = saved }()

	pkR := unhex(t, "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c")
	info := unhex(t, "4f6465206f6e2061204772656369616e2055726e")
	out := ev.Companion_Default___.SenderStart(eventresidue.Seq(pkR), eventresidue.Seq(info))
	x := eventresidue.NewExchange(ev.State{}, nil, nil, nil, nil)
	for i := 0; i < 64 && out.Is_HContinue(); i++ {
		e := ev.Companion_Default___.Perform(x, out.Dtor_action()).Dtor_e()
		out = ev.Companion_Default___.HpkeStep(out.Dtor_h(), e)
	}
	if !out.Is_HReady() {
		t.Fatalf("sender setup did not finish: %v", out)
	}
	ctx := out.Dtor_ctx()
	want := map[string]string{
		"enc":            "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
		"key":            "f50b0609186798729ed0564b36ef2ef8044f1f9d05636874d1f46c819c7a669f",
		"baseNonce":      "151d9929e2449747889bc923",
		"exporterSecret": "86017151bbff6a1940e8abae2ac9e0e7032e33df1eaaecc02ca6259b130d62df",
	}
	got := map[string]string{
		"enc":            hex.EncodeToString(eventresidue.Bytes(out.Dtor_enc())),
		"key":            hex.EncodeToString(eventresidue.Bytes(ctx.Dtor_key())),
		"baseNonce":      hex.EncodeToString(eventresidue.Bytes(ctx.Dtor_baseNonce())),
		"exporterSecret": hex.EncodeToString(eventresidue.Bytes(ctx.Dtor_exporterSecret())),
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %s, want %s", k, got[k], w)
		}
	}
	// The first seal: the vector's nonce, and a ciphertext that opens.
	seal := ev.Companion_Default___.SealAction(ctx, eventresidue.Seq([]byte("Beauty is truth, truth beauty")))
	if hex.EncodeToString(eventresidue.Bytes(seal.Dtor_nonce())) != "151d9929e2449747889bc923" {
		t.Errorf("seal nonce = %x", eventresidue.Bytes(seal.Dtor_nonce()))
	}
	sealed := ev.Companion_Default___.Perform(x, seal).Dtor_e()
	opened := ev.Companion_Default___.Perform(x, ev.Companion_Default___.OpenAction(ctx, sealed.Dtor_ciphertext())).Dtor_e()
	if !opened.Dtor_ok() || string(eventresidue.Bytes(opened.Dtor_plaintext())) != "Beauty is truth, truth beauty" {
		t.Errorf("open failed: %v", opened)
	}
}

// A real exchange against identity.Middleware, including an early close and
// an upload larger than one frame, so the pipe and goroutine paths run under -race.
func TestRoundTripAgainstMiddleware(t *testing.T) {
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/hpke-keys", id.ConfigHandler)
	mux.Handle("/echo", id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	})))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tr, err := client.New(srv.URL, client.Discovered())
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 20_000)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/echo", bytes.NewReader(payload))
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if tr.SessionRecoveryToken() == nil {
		t.Error("token should be readable before the body is drained")
	}
	echoed, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || !bytes.Equal(echoed, payload) {
		t.Fatalf("echo mismatch: %v, %d bytes", err, len(echoed))
	}
	if tr.SessionRecoveryToken() != nil {
		t.Error("token should be cleared after the body ended")
	}

	// Early close clears the token; a plaintext request has none.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/echo", strings.NewReader("hello"))
	resp, err = tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	var first [1]byte
	if _, err := io.ReadFull(resp.Body, first[:]); err != nil || first[0] != 'h' {
		t.Fatalf("first byte: %v %q", err, first)
	}
	_ = resp.Body.Close()
	if tr.SessionRecoveryToken() != nil {
		t.Error("token should be cleared on close")
	}
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/echo", nil)
	resp, err = tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if tr.SessionRecoveryToken() != nil {
		t.Error("a plaintext exchange publishes no token")
	}
}

// The generated printers of the secret-bearing datatypes are redacted by
// dafny/patch-runtime.py (SECRET_TYPES): logging a token or a context, or any
// value holding one, must not expose key material.
func TestGeneratedPrintersRedactSecrets(t *testing.T) {
	secret := eventresidue.Seq(bytes.Repeat([]byte{0xAB}, 32))
	token := core.Companion_Token_.Create_Token_(secret, secret)
	ctx := ev.Companion_Ctx_.Create_Ctx_(secret, eventresidue.Seq(make([]byte, 12)), secret, 0)
	store := ev.Companion_SessionStore_.Create_SessionStore_(1, core.Companion_Option_.Create_Some_(token))
	for _, v := range []any{token, ctx, store, ev.Companion_Action_.Create_PublishToken_(1, secret, secret)} {
		if s := fmt.Sprint(v); !strings.Contains(s, "(<redacted>)") || strings.Contains(s, "171") {
			t.Errorf("printer leaks: %s", s)
		}
	}
}
