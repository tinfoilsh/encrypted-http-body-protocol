package eventresidue

// The server residue of EHBPServer.ServerStep (dafny/ehbp_server.dfy): one
// SPerformer method per action and the pump; the crypto bindings are the client's.
// Nothing here decides anything.

import (
	"cmp"
	"io"
	"net/http"
	"sync"

	ev "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen-events/go/EHBPEvents"
	sv "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen-events/go/EHBPServer"
	core "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/EHBP"
	_dafny "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/dafny"
)

// Server is the native state of one server-side exchange: the request body
// the core reads, the response writer it fills and the handler it dispatches to.
type Server struct {
	mu      sync.Mutex
	state   sv.SState
	body    io.Reader
	bodyErr error
	W       http.ResponseWriter // the response
	Pass    func()              // PassRequest: the request goes through unchanged (nil: recorded only)
	Handler func()              // Dispatch: runs the handler to completion (nil: recorded only)

	Plain                   []byte // EmitPlaintext not yet read by the handler
	Passed, Dispatched, EOF bool
	Failure                 error // Respond or Fail: what the handler's next read returns
}

func NewServer(privateKey, publicKey []byte, body io.Reader, w http.ResponseWriter) *Server {
	return &Server{state: sv.Companion_Default___.ServerInitial(Seq(privateKey), Seq(publicKey)), body: body, W: w}
}

// Server is the core's SPerformer: each method converts at the runtime
// boundary and performs one native call; SPerform (ehbp_server.dfy) dispatches.
func (x *Server) String() string { return "Server" }
func (x *Server) RandomBytes(length _dafny.Int) _dafny.Sequence {
	return Seq(RandomBytes(length.Int()))
}
func (x *Server) X25519(scalar, point _dafny.Sequence) _dafny.Sequence {
	return Seq(X25519(Bytes(scalar), Bytes(point)))
}
func (x *Server) HmacSha256(key, data _dafny.Sequence) _dafny.Sequence {
	return Seq(HmacSha256(Bytes(key), Bytes(data)))
}
func (x *Server) AeadSeal(key, nonce, plaintext _dafny.Sequence) _dafny.Sequence {
	return Seq(AeadSeal(Bytes(key), Bytes(nonce), Bytes(plaintext)))
}
func (x *Server) AeadOpen(key, nonce, ciphertext _dafny.Sequence) (bool, _dafny.Sequence) {
	ok, plaintext := AeadOpen(Bytes(key), Bytes(nonce), Bytes(ciphertext))
	return ok, Seq(plaintext)
}
func (x *Server) PassRequest() {
	x.Passed = true
	if x.Pass != nil {
		x.Pass()
	}
}
func (x *Server) Respond(status _dafny.Int, code core.Code, message _dafny.Sequence, headers _dafny.Sequence, body _dafny.Sequence) {
	x.Failure = Error(code, String(message), x.bodyErr)
	for name, values := range HeaderPairs(headers) {
		x.W.Header()[name] = values
	}
	x.W.WriteHeader(status.Int())
	_, _ = x.W.Write(Bytes(body))
}
func (x *Server) Read(stream ev.Stream) (bool, _dafny.Sequence, bool) {
	data, eof, ok := readChunk(x.body, &x.bodyErr)
	return ok, Seq(data), eof
}
func (x *Server) EmitPlaintext(data _dafny.Sequence) { x.Plain = append(x.Plain, Bytes(data)...) }
func (x *Server) Close(stream ev.Stream)             { x.EOF = x.EOF || stream.Is_RequestBody() }
func (x *Server) Dispatch() bool {
	x.Dispatched = true
	if x.Handler == nil {
		return false
	}
	x.Handler()
	return true
}
func (x *Server) StartResponse(status _dafny.Int, headers _dafny.Sequence) {
	h := x.W.Header()
	h.Del("Content-Length")
	for name, values := range HeaderPairs(headers) {
		h[name] = values
	}
	x.W.WriteHeader(status.Int())
}
func (x *Server) Write(data _dafny.Sequence, end ev.BodyEnd) {
	if end.Is_Aborted() {
		panic(http.ErrAbortHandler)
	}
	_, _ = x.W.Write(Bytes(data))
	if f, ok := x.W.(http.Flusher); ok {
		f.Flush()
	}
}
func (x *Server) Fail(code core.Code, message _dafny.Sequence) {
	x.Failure = Error(code, String(message), x.bodyErr)
}

// run feeds events to ServerStep until an action list produces none. The
// handler runs inside Dispatch, so its reads and writes are nested pumps.
func (x *Server) run(acts []sv.SAction) {
	var events []sv.SEvent
	for {
		for _, a := range acts {
			if e := sv.Companion_Default___.SPerform(x, a); e.Is_Some() {
				events = append(events, e.Dtor_value().(sv.SEvent))
			}
		}
		if len(events) == 0 {
			return
		}
		acts, events = x.step(events[len(events)-1]), events[:len(events)-1]
	}
}

func (x *Server) step(e sv.SEvent) []sv.SAction {
	x.mu.Lock()
	defer x.mu.Unlock()
	t := sv.Companion_Default___.ServerStep(x.state, e)
	x.state = (*t.IndexInt(0)).(sv.SState)
	acts := (*t.IndexInt(1)).(_dafny.Sequence)
	out := make([]sv.SAction, 0, acts.Cardinality())
	for i := uint32(0); i < acts.Cardinality(); i++ {
		out = append(out, acts.Select(i).(sv.SAction))
	}
	return out
}

// Feed runs the pump on one handler event: HandlerRead, HandlerHead, HandlerChunk or HandlerDone.
func (x *Server) Feed(e sv.SEvent) { x.run(x.step(e)) }

// Start feeds the request head; the pump then runs to PassRequest, Respond or
// Dispatch (and, with a Handler, through the handler to the end of the response).
func (x *Server) Start(headers http.Header, hasBody bool) {
	x.Feed(sv.Companion_SEvent_.Create_RequestStart_(HeaderSeq(headers), hasBody))
}

// Body is the decrypted request body: each Read drives the core with
// HandlerRead until it releases plaintext, ends the body or fails.
type Body struct{ X *Server }

func (b *Body) Read(p []byte) (int, error) {
	for len(b.X.Plain) == 0 {
		if b.X.Failure != nil || b.X.EOF {
			return 0, cmp.Or(b.X.Failure, io.EOF)
		}
		b.X.Feed(sv.Companion_SEvent_.Create_HandlerRead_())
	}
	n := copy(p, b.X.Plain)
	b.X.Plain = b.X.Plain[n:]
	return n, nil
}

func (b *Body) Close() error {
	if c, ok := b.X.body.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
