package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	logrus "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/noisews"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

var (
	listenAddr   = flag.String("l", ":8080", "listen address")
	identityFile = flag.String("i", "server_identity.json", "identity file")
	verbose      = flag.Bool("v", false, "verbose logging")
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Ehbp-Encapsulated-Key")
		w.Header().Set("Access-Control-Expose-Headers", "Ehbp-Response-Nonce, Ehbp-Encapsulated-Key, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	flag.Parse()
	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("Verbose logging enabled")
	}

	serverIdentity, err := identity.FromFile(*identityFile)
	if err != nil {
		logrus.Fatalf("Failed to get identity: %v", err)
	}

	middleware := serverIdentity.Middleware()

	logrus.WithFields(logrus.Fields{
		"public_key_hex": hex.EncodeToString(serverIdentity.MarshalPublicKey()),
	}).Info("Server identity")

	mux := http.NewServeMux()

	mux.HandleFunc(protocol.KeysPath, serverIdentity.ConfigHandler)

	mux.Handle("/secure", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			logrus.Errorf("Failed to read request body: %v", err)
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		logrus.Debugf("Received request body: %s", string(body))

		response := []byte("Hello, " + string(body))
		logrus.Debugf("Sending response: %s", string(response))

		if _, err := w.Write(response); err != nil {
			logrus.Errorf("Failed to write response: %v", err)
			return
		}
		logrus.Debug("Response sent successfully")
	})))

	mux.Handle("/stream", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Debug("Received stream request")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Transfer-Encoding", "chunked")

		flusher, ok := w.(http.Flusher)
		if !ok {
			logrus.WithFields(logrus.Fields{
				"type": fmt.Sprintf("%T", w),
			}).Error("Response writer does not implement http.Flusher")
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		logrus.Debug("Stream flusher initialized successfully")

		for i := 1; i <= 20; i++ {
			_, err := fmt.Fprintf(w, "Number: %d\n", i)
			if err != nil {
				logrus.Errorf("Error writing to stream: %v", err)
				return
			}
			flusher.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})))

	wsServer, err := noisews.NewServer(serverIdentity)
	if err != nil {
		logrus.Fatalf("Failed to create WebSocket server: %v", err)
	}
	mux.Handle("/ws", wsServer.Handler(func(conn *noisews.Conn, r *http.Request) {
		logrus.Debug("WebSocket connection established")
		for {
			msg, err := conn.Read(r.Context())
			if err != nil {
				logrus.Debugf("WebSocket connection ended: %v", err)
				return
			}
			logrus.Debugf("Received WebSocket message: %s", string(msg))
			if err := conn.Write(r.Context(), append([]byte("Hello, "), msg...)); err != nil {
				logrus.Errorf("Failed to write WebSocket message: %v", err)
				return
			}
		}
	}))

	proxyUpstream, err := url.Parse("http://localhost:11434")
	if err != nil {
		logrus.Fatalf("Failed to parse proxy backend URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(proxyUpstream)
	proxy.ErrorLog = log.New(os.Stderr, "proxy: ", log.LstdFlags)

	mux.Handle("/", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})))

	logrus.Printf("Listening on %s", *listenAddr)
	logrus.Fatal(http.ListenAndServe(*listenAddr, corsMiddleware(mux)))
}
