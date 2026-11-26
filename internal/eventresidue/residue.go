// Package eventresidue is the Go residue of the event-driven core
// (dafny/ehbp_events.dfy): one binding per action, the loop of
// conformance/spec/handler.md section 5 over the core's Perform, and the
// runtime conversions, laid out as in section 4. Nothing here decides anything.
package eventresidue

import (
	"bufio"
	"cmp"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	neturl "net/url"
	"sync"

	ev "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen-events/go/EHBPEvents"
	core "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/EHBP"
	_dafny "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/dafny"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// crypto: one native call each, bytes in, bytes out. A failure is an empty
// result (or ok false for AeadOpen), which the core rejects by length.
// The stdlib: crypto/ecdh (nil on a low-order point), crypto/hmac, crypto/aes with
// crypto/cipher, crypto/rand.

// gcm is AES-256-GCM under key; the nonce must be the standard 12 bytes.
func gcm(key, nonce []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err == nil && len(nonce) != g.NonceSize() {
		return nil, errors.New("nonce length")
	}
	return g, err
}

// Rand is the source of the ephemeral KEM scalar; tests may replace it.
var Rand io.Reader = rand.Reader

func orNil(v []byte, err error) []byte {
	if err != nil {
		return nil
	}
	return v
}

func X25519(scalar []byte, point []byte) []byte {
	priv, errS := ecdh.X25519().NewPrivateKey(scalar)
	pub, errP := ecdh.X25519().NewPublicKey(point)
	if errS != nil || errP != nil {
		return nil
	}
	return orNil(priv.ECDH(pub))
}

func HmacSha256(key []byte, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func AeadSeal(key []byte, nonce []byte, plaintext []byte) []byte {
	g, err := gcm(key, nonce)
	if err != nil {
		return nil
	}
	return g.Seal(nil, nonce, plaintext, nil)
}

func AeadOpen(key []byte, nonce []byte, ciphertext []byte) (bool, []byte) {
	g, err := gcm(key, nonce)
	if err != nil {
		return false, nil
	}
	v, err := g.Open(nil, nonce, ciphertext, nil)
	return err == nil, v
}

func RandomBytes(length int) []byte {
	return orNil(io.ReadAll(io.LimitReader(Rand, int64(length))))
}

// http: the only block holding native state; one Exchange per request or discovery.

type Exchange struct {
	mu                        sync.Mutex
	state                     ev.State
	session                   *Session
	do                        func(*http.Request) (*http.Response, error)
	tmpl                      *http.Request
	body                      io.ReadCloser  // the caller's request body, nil when absent
	pr                        *io.PipeReader // the encrypted upload, fed by Write
	pw                        *io.PipeWriter
	wbuf                      *bufio.Writer // frames are batched; a pipe write is a goroutine hand-off
	handed                    bool          // the upload lane owns body
	respBody                  io.ReadCloser // the native response body
	sendErr, respErr, bodyErr error         // native causes behind a Transport failure

	// The outcome, written by the terminal actions and read by the shim.
	Response                    *http.Response // the native response, every field the stack set
	Failure                     error
	Passthrough, Done, Finished bool
	Prefix, PublicKey, Plain    []byte // Plain: EmitPlaintext since the last Read
	Headers                     http.Header
}

// NewExchange binds a core state to the native pieces: send performs one HTTP transaction from template; body is the caller's body or nil.
func NewExchange(state ev.State, session *Session, send func(*http.Request) (*http.Response, error), template *http.Request, body io.ReadCloser) *Exchange {
	x := &Exchange{state: state, session: session, do: send, tmpl: template, body: body}
	if body != nil {
		x.pr, x.pw = io.Pipe()
		x.wbuf = bufio.NewWriterSize(x.pw, 256<<10)
	}
	return x
}

// ResponseExchange starts at a response head (DecryptStart, DeriveStart); body may be nil.
func ResponseExchange(body io.ReadCloser) *Exchange { return &Exchange{respBody: body} }

// http: the four performers over net/http (send, write, read, close), written by hand.

// send performs the transaction and reports its head; with a body it blocks
// while the upload lane feeds the pipe. A redirect is seen and never followed.
func (x *Exchange) send(verb, url string, headers http.Header, hasBody bool) (bool, int, http.Header) {
	req := x.tmpl.Clone(x.tmpl.Context())
	target, err := neturl.Parse(url)
	if err != nil {
		x.sendErr = err
		return false, 0, nil
	}
	req.Method, req.URL, req.Host, req.Header = verb, target, "", headers
	req.Body, req.ContentLength, req.GetBody = http.NoBody, 0, nil
	if hasBody {
		req.Body, req.ContentLength = x.pr, -1
	}
	resp, err := x.do(req)
	if err != nil {
		x.sendErr = err
		if hasBody {
			_ = x.pr.Close() // the transport gave up; unblock the upload lane
		}
		return false, 0, nil
	}
	x.Response, x.respBody = resp, resp.Body
	return true, resp.StatusCode, resp.Header
}

// write feeds one encrypted chunk and, by end, ends the upload: Done closes
// the pipe, Aborted fails it with the code; false once the transport is gone.
func (x *Exchange) write(data []byte, end ev.BodyEnd) bool {
	if _, err := x.wbuf.Write(data); err != nil {
		x.close(requestBody)
		return false
	}
	if end.Is_More() {
		return true
	}
	var reason error // CloseWithError(nil) is Close
	if end.Is_Aborted() {
		reason = Error(end.Dtor_code(), "request body failed", x.bodyErr)
	} else if err := x.wbuf.Flush(); err != nil {
		reason = err
	}
	_ = x.pw.CloseWithError(reason)
	x.close(requestBody)
	return true
}

// read reads once from the caller's body or the native response: the chunk, eof, ok; a failure is kept as the cause.
func (x *Exchange) read(stream ev.Stream) ([]byte, bool, bool) {
	if stream.Is_RequestBody() {
		// Nothing sealed is held while the lane waits for the caller.
		if x.wbuf != nil && x.wbuf.Buffered() > 0 {
			if err := x.wbuf.Flush(); err != nil {
				x.bodyErr = err
				return nil, false, false
			}
		}
		return readChunk(x.body, &x.bodyErr)
	}
	return readChunk(x.respBody, &x.respErr)
}

// close releases the native stream, if it exists.
func (x *Exchange) close(stream ev.Stream) {
	r := x.body // set once; respBody is written by Send on the other lane
	if stream.Is_ResponseBody() {
		r = x.respBody
	}
	if r != nil {
		_ = r.Close()
	}
}

func readChunk(r io.Reader, cause *error) ([]byte, bool, bool) {
	buf := make([]byte, 128<<10)
	n, err := r.Read(buf)
	if errors.Is(err, io.EOF) {
		return buf[:n], true, true
	}
	*cause = err
	return buf[:n], false, err == nil
}

var requestBody = ev.Companion_Stream_.Create_RequestBody_()

// session: a mutex around one SessionStore value; every rule is SessionApply.

type Session struct {
	mu    sync.Mutex
	once  sync.Once // NewSession on first use
	store ev.SessionStore
}

func (s *Session) apply(a ev.SessionAction) ev.SessionStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.once.Do(func() { s.store = ev.Companion_Default___.NewSession() })
	s.store = ev.Companion_Default___.SessionApply(s.store, a)
	return s.store
}

func (s *Session) BeginSession() uint64 {
	return s.apply(ev.Companion_SessionAction_.Create_Begin_()).Dtor_generation()
}

func (s *Session) PublishToken(generation uint64, exportedSecret, requestEnc []byte) {
	s.apply(ev.Companion_SessionAction_.Create_Publish_(generation, core.Companion_Token_.Create_Token_(Seq(exportedSecret), Seq(requestEnc))))
}

func (s *Session) ClearToken(generation uint64) {
	s.apply(ev.Companion_SessionAction_.Create_Clear_(generation))
}

// Token returns the stored token, or nil.
func (s *Session) Token() *core.Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.once.Do(func() { s.store = ev.Companion_Default___.NewSession() })
	if !s.store.Dtor_token().Is_Some() {
		return nil
	}
	tok := s.store.Dtor_token().Dtor_value().(core.Token)
	return &tok
}

// pump: handler.md section 5. Perform (ehbp_events.dfy) dispatches one
// action to the Performer below; run is the loop.

// Exchange is the core's Performer: each method converts at the runtime
// boundary and calls one binding.
func (x *Exchange) String() string       { return "Exchange" }
func (x *Exchange) BeginSession() uint64 { return x.session.BeginSession() }
func (x *Exchange) PublishToken(generation uint64, exportedSecret, requestEnc _dafny.Sequence) {
	x.session.PublishToken(generation, Bytes(exportedSecret), Bytes(requestEnc))
}
func (x *Exchange) ClearToken(generation uint64) { x.session.ClearToken(generation) }
func (x *Exchange) RandomBytes(length _dafny.Int) _dafny.Sequence {
	return Seq(RandomBytes(length.Int()))
}
func (x *Exchange) X25519(scalar, point _dafny.Sequence) _dafny.Sequence {
	return Seq(X25519(Bytes(scalar), Bytes(point)))
}
func (x *Exchange) HmacSha256(key, data _dafny.Sequence) _dafny.Sequence {
	return Seq(HmacSha256(Bytes(key), Bytes(data)))
}
func (x *Exchange) AeadSeal(key, nonce, plaintext _dafny.Sequence) _dafny.Sequence {
	return Seq(AeadSeal(Bytes(key), Bytes(nonce), Bytes(plaintext)))
}
func (x *Exchange) AeadOpen(key, nonce, ciphertext _dafny.Sequence) (bool, _dafny.Sequence) {
	ok, plaintext := AeadOpen(Bytes(key), Bytes(nonce), Bytes(ciphertext))
	return ok, Seq(plaintext)
}
func (x *Exchange) Send(verb, url, headers _dafny.Sequence, hasBody bool) (bool, _dafny.Int, _dafny.Sequence, bool) {
	ok, status, head := x.send(String(verb), String(url), HeaderPairs(headers), hasBody)
	return ok, _dafny.IntOfInt(status), HeaderSeq(head), false
}
func (x *Exchange) Write(data _dafny.Sequence, end ev.BodyEnd) bool { return x.write(Bytes(data), end) }
func (x *Exchange) Read(stream ev.Stream) (bool, _dafny.Sequence, bool) {
	data, eof, ok := x.read(stream)
	return ok, Seq(data), eof
}
func (x *Exchange) Close(stream ev.Stream)             { x.close(stream) }
func (x *Exchange) EmitPlaintext(data _dafny.Sequence) { x.Plain = append(x.Plain, Bytes(data)...) }

// run feeds events to Step until a terminal action. A Send with a body hands
// the rest of its action list, the upload, to a second lane (a goroutine) so
// the transaction can block for the response head; this lane stops there.
func (x *Exchange) run(acts []ev.Action) {
	var events []ev.Event
	for {
		for i, a := range acts {
			switch {
			case a.Is_Passthrough():
				x.Passthrough, x.Prefix = true, Bytes(a.Dtor_prefix())
				return
			case a.Is_Done():
				x.Done, x.Headers = true, HeaderPairs(a.Dtor_headers())
				return
			case a.Is_Finished():
				x.Finished = true
				return
			case a.Is_Discovered():
				x.PublicKey = Bytes(a.Dtor_publicKey())
				return
			case a.Is_Fail():
				x.Failure = Error(a.Dtor_code(), String(a.Dtor_message()), cmp.Or(x.sendErr, x.respErr, x.bodyErr))
				return
			case a.Is_Send() && a.Dtor_hasBody():
				x.handed = true
				go x.run(acts[i+1:])
			}
			r := ev.Companion_Default___.Perform(x, a)
			if r.Is_Stop() {
				return
			}
			if r.Is_Got() {
				events = append(events, r.Dtor_e())
			}
			if a.Is_Send() && a.Dtor_hasBody() {
				break
			}
		}
		if len(events) == 0 {
			return
		}
		acts, events = x.step(events[len(events)-1]), events[:len(events)-1]
	}
}

func (x *Exchange) step(e ev.Event) []ev.Action {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.load(ev.Companion_Default___.Step(x.state, e))
}

// load takes a (State, seq<Action>) pair the core returned.
func (x *Exchange) load(t _dafny.Tuple) []ev.Action {
	x.state = (*t.IndexInt(0)).(ev.State)
	acts := (*t.IndexInt(1)).(_dafny.Sequence)
	out := make([]ev.Action, 0, acts.Cardinality())
	for i := uint32(0); i < acts.Cardinality(); i++ {
		out = append(out, acts.Select(i).(ev.Action))
	}
	return out
}

// Feed runs the pump on one caller event: Start, DiscoverStart, CallerRead or CallerClose.
func (x *Exchange) Feed(e ev.Event) {
	x.run(x.step(e))
	if !x.handed {
		x.close(requestBody) // the core never asked for it
	}
}

// Resume runs the pump from a pair the core computed: DeriveStart, DecryptStart.
func (x *Exchange) Resume(t _dafny.Tuple) { x.run(x.load(t)) }

// State is the core's state, for KeysOf once the pump emitted Done.
func (x *Exchange) State() ev.State { return x.state }

// BodyReader is the decrypted body after Done: each Read drives the core with
// CallerRead until it emits plaintext, finishes or fails; Close releases it.
type BodyReader struct {
	X       *Exchange
	pending []byte // Plain not yet handed to Read
}

func (b *BodyReader) Read(p []byte) (int, error) {
	for len(b.pending) == 0 {
		if b.X.Failure != nil || b.X.Finished {
			return 0, cmp.Or(b.X.Failure, io.EOF)
		}
		b.X.Feed(ev.Companion_Event_.Create_CallerRead_())
		b.pending, b.X.Plain = b.X.Plain, nil
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}

func (b *BodyReader) Close() error {
	b.X.Feed(ev.Companion_Event_.Create_CallerClose_())
	return nil
}

// conversions: the runtime boundary only.

func Seq(b []byte) _dafny.Sequence    { return _dafny.SeqOfBytes(b) }
func Bytes(s _dafny.Sequence) []byte  { return appendBytes(make([]byte, 0, s.Cardinality()), s) }
func Str(s string) _dafny.Sequence    { return _dafny.UnicodeSeqOfUtf8Bytes(s) }
func String(s _dafny.Sequence) string { return s.VerbatimString(false) }

// appendBytes copies a sequence leaf by leaf: the runtime's ToByteArray would
// first flatten a lazy concatenation of a boxed leaf (a frame header) and a
// byte-backed one (ciphertext) into a boxed []interface{} Vector, 16 bytes
// per byte. A byte-backed leaf (patch-runtime.py) is one append.
func appendBytes(out []byte, s _dafny.Sequence) []byte {
	switch v := s.(type) {
	case *_dafny.LazySequence:
		return appendBytes(out, v.Box().Get().(_dafny.Sequence))
	case *_dafny.ConcatSequence:
		return appendBytes(appendBytes(out, v.Left()), v.Right())
	}
	arr := s.ToArray()
	if b, ok := arr.(_dafny.GoByteArray); ok {
		return append(out, b.Bytes()...)
	}
	for i, n := uint32(0), arr.Length(); i < n; i++ {
		out = append(out, arr.Select(i).(byte))
	}
	return out
}

// HeaderSeq converts headers to the core's seq<(string, string)>, one entry
// per value.
func HeaderSeq(h http.Header) _dafny.Sequence {
	var pairs []interface{}
	for name, values := range h {
		for _, v := range values {
			pairs = append(pairs, _dafny.TupleOf(Str(name), Str(v)))
		}
	}
	return _dafny.SeqOf(pairs...)
}

// HeaderPairs converts the core's header list to a native Header, one Add per entry.
func HeaderPairs(s _dafny.Sequence) http.Header {
	out := make(http.Header)
	for i := uint32(0); i < s.Cardinality(); i++ {
		t := s.Select(i).(_dafny.Tuple)
		out.Add(String((*t.IndexInt(0)).(_dafny.Sequence)), String((*t.IndexInt(1)).(_dafny.Sequence)))
	}
	return out
}

// mapping: from the core's CodeString; no table of strings.

// Code maps a core code to the canonical protocol code; Transport has none.
func Code(c core.Code) protocol.Code {
	return protocol.Code(String(core.Companion_Default___.CodeString(c)))
}

// Error turns a core failure into a Go error: a coded protocol error, or the
// native cause for a Transport failure.
func Error(c core.Code, message string, native error) error {
	switch code := Code(c); {
	case code != "" && native != nil:
		return protocol.Errorf(code, "%s: %w", message, native)
	case code != "":
		return protocol.Errorf(code, "%s", message)
	case native != nil:
		return native
	}
	return errors.New(message)
}

// Self-check: the core's primitive vectors through this residue.

func SelfCheck() []string {
	x := &Exchange{}
	actions := ev.Companion_Default___.SelfCheckActions()
	var results []interface{}
	for i := uint32(0); i < actions.Cardinality(); i++ {
		results = append(results, ev.Companion_Default___.Perform(x, actions.Select(i).(ev.Action)).Dtor_e())
	}
	failures := ev.Companion_Default___.SelfCheckJudge(_dafny.SeqOf(results...))
	var out []string
	for i := uint32(0); i < failures.Cardinality(); i++ {
		out = append(out, String(failures.Select(i).(_dafny.Sequence)))
	}
	return out
}
