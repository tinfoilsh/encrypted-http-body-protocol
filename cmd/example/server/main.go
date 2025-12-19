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
