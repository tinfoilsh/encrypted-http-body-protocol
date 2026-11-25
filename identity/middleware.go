package identity

import (
	"net/http"

	sv "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen-events/go/EHBPServer"
	_dafny "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/dafny"
	"github.com/tinfoilsh/encrypted-http-body-protocol/internal/eventresidue"
)

// Middleware wraps an HTTP handler to decrypt requests and encrypt responses
// on the core's server driver (EHBPServer.ServerStep). Requests with an
// Ehbp-Encapsulated-Key header are decrypted and their responses encrypted;
// requests without one are passed through as plaintext. A request the core
// refuses is answered with its status (400, 422 problem document or 500)
// before the handler runs; a frame that fails after the handler started
// fails its read and, once the handler returns, is answered with a 400 or,
// if the response has started, aborts it (SPEC 5.2).
func (i *Identity) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sk, err := i.sk.Bytes()
			if err != nil {
				http.Error(w, "failed to decrypt request", http.StatusInternalServerError)
				return
			}
			x := eventresidue.NewServer(sk, i.pk.Bytes(), r.Body, w)
			x.Pass = func() { next.ServeHTTP(w, r) }
			x.Handler = func() {
				// The handler reads the core's plaintext stream in place of the wire body.
				r.Body, r.ContentLength = &eventresidue.Body{X: x}, -1
				r.Header.Del("Content-Length")
				next.ServeHTTP(&responseWriter{ResponseWriter: w, x: x}, r)
			}
			x.Start(r.Header, r.Body != nil && r.Body != http.NoBody)
		})
	}
}

// responseWriter hands what the handler writes to the core, which seals it
// under the keys derived from the request's HPKE context, one frame per
// write; 204 and 205 are sent as 200 so the response can carry a frame and
// a response with no body gets one frame of empty plaintext (SPEC 5.2, 5.3).
type responseWriter struct {
	http.ResponseWriter
	x *eventresidue.Server
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.x.Feed(sv.Companion_SEvent_.Create_HandlerHead_(_dafny.IntOfInt(statusCode)))
}

func (w *responseWriter) Write(data []byte) (int, error) {
	w.x.Feed(sv.Companion_SEvent_.Create_HandlerChunk_(eventresidue.Seq(data)))
	return len(data), nil
}

func (w *responseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
