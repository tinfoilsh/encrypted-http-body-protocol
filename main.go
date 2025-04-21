package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/stransport/identity"
	"github.com/tinfoilsh/stransport/middleware"
)

var (
	listenAddr   = flag.String("l", ":8080", "listen address")
	identityFile = flag.String("i", "identity.json", "identity file")
	verbose      = flag.Bool("v", false, "verbose logging")
)

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	serverIdentity, err := identity.FromFile(*identityFile)
	if err != nil {
		log.Fatalf("Failed to get identity: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/tinfoil-public-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(serverIdentity.MarshalPublicKey())
	})

	mux.Handle("/secure", middleware.EncryptMiddleware(serverIdentity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorf("Failed to read request body: %v", err)
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		log.Debugf("Received request body: %s", string(body))

		response := []byte("Hello, " + string(body))
		log.Debugf("Sending response: %s", string(response))

		if _, err := w.Write(response); err != nil {
			log.Errorf("Failed to write response: %v", err)
			return
		}
		log.Debug("Response sent successfully")
	})))

	mux.Handle("/stream", middleware.EncryptMiddleware(serverIdentity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("Received stream request")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Transfer-Encoding", "chunked")

		flusher, ok := w.(http.Flusher)
		if !ok {
			log.WithFields(log.Fields{
				"type": fmt.Sprintf("%T", w),
			}).Error("Response writer does not implement http.Flusher")
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		log.Debug("Stream flusher initialized successfully")

		for i := 1; i <= 20; i++ {
			_, err := fmt.Fprintf(w, "Number: %d\n", i)
			if err != nil {
				log.Errorf("Error writing to stream: %v", err)
				return
			}
			flusher.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})))

	log.Printf("Listening on %s", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, mux))
}
