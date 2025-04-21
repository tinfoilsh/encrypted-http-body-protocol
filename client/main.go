package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/stransport/identity"
)

var (
	serverURL    = flag.String("s", "http://localhost:8080", "server URL")
	identityFile = flag.String("i", "identity.json", "client identity file")
	verbose      = flag.Bool("v", false, "verbose logging")
)

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	clientIdentity, err := identity.FromFile(*identityFile)
	if err != nil {
		log.Fatalf("failed to get client identity: %v", err)
	}

	secureClient, err := NewSecureClient(*serverURL, clientIdentity)
	if err != nil {
		log.Fatalf("failed to create secure client: %v", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/secure", *serverURL), bytes.NewBuffer([]byte("nate")))
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}
	resp, err := secureClient.Do(req)
	if err != nil {
		log.Fatalf("failed to make secure request: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %v", err)
	}

	log.Infof("Response body: %s", string(body))
}
