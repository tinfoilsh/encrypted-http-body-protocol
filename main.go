package main

import (
	"flag"
	"io"
	"net/http"

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

	http.HandleFunc("/.well-known/tinfoil-public-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(serverIdentity.MarshalPublicKey())
	})

	http.Handle("/secure", middleware.EncryptMiddleware(serverIdentity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Hello, " + string(body)))
	})))

	log.Printf("Listening on %s", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}
