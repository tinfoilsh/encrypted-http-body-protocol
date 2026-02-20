package main

import (
	"io"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
)

var (
	requestMethod = pflag.StringP("method", "X", "GET", "request method")
	headers       = pflag.StringSliceP("header", "H", []string{}, "request header (can be used multiple times)")
	data          = pflag.StringP("data", "d", "", "request data")

	verbose = pflag.BoolP("verbose", "v", false, "verbose logging")
)

func main() {
	pflag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
		log.Debug("Verbose logging enabled")
	}

	url := pflag.Arg(0)
	if url == "" {
		log.Fatalf("URL is required")
	}

	secureTransport, err := client.NewTransport(url)
	if err != nil {
		log.Fatalf("failed to create secure client: %v", err)
	}
	httpClient := &http.Client{
		Transport: secureTransport,
	}

	serverID := secureTransport.ServerIdentity()
	log.WithFields(log.Fields{
		"public_key_hex": serverID.MarshalPublicKeyHex(),
		"hpke_kem":       serverID.KEM().ID(),
		"hpke_kdf":       serverID.KDF().ID(),
		"hpke_aead":      serverID.AEAD().ID(),
	}).Debug("Server Identity")

	var body io.Reader
	if *data != "" {
		body = strings.NewReader(*data)
	}

	req, err := http.NewRequest(*requestMethod, url, body)
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}

	// Parse and set headers
	for _, header := range *headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			log.Fatalf("invalid header format: %s (expected 'Name: Value')", header)
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" {
			log.Fatalf("header name cannot be empty: %s", header)
		}
		req.Header.Set(name, value)
		log.Debugf("Set header: %s = %s", name, value)
	}

	log.Debugf("Making request %s %s", req.Method, req.URL)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

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
