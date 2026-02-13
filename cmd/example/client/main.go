package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
)

var (
	serverURL = flag.String("s", "http://localhost:8080", "server URL")
	verbose   = flag.Bool("v", false, "verbose logging")
)

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
		log.Debug("Verbose logging enabled")
	}

	secureTransport, err := client.NewTransport(*serverURL)
	if err != nil {
		log.Fatalf("failed to create secure client: %v", err)
	}

	httpClient := &http.Client{
		Transport: secureTransport,
	}

	testSecureEndpoint(httpClient)
	testStreamEndpoint(httpClient)
}

func testSecureEndpoint(httpClient *http.Client) {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/secure", *serverURL), bytes.NewBuffer([]byte("nate")))
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("failed to make secure request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %v", err)
	}

	log.Infof("Response body: %s", string(body))
}

func testStreamEndpoint(httpClient *http.Client) {
	log.Info("Testing streaming endpoint...")

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/stream", *serverURL), nil)
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("failed to make stream request: %v", err)
	}
	defer resp.Body.Close()

	log.Info("Streaming response:")

	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			os.Stdout.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Errorf("Error reading stream: %v", err)
			break
		}
	}
}
