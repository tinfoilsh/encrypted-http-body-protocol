package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/cloudflare/circl/kem"
	"github.com/tinfoilsh/stransport/identity"
)

var (
	serverURL    = flag.String("s", "http://localhost:8080", "server URL")
	identityFile = flag.String("i", "identity.json", "client identity file")
	verbose      = flag.Bool("v", false, "verbose logging")
)

func getServerPublicKey(serverURL string) (kem.PublicKey, error) {
	resp, err := http.Get(fmt.Sprintf("%s/.well-known/tinfoil-public-key", serverURL))
	if err != nil {
		return nil, fmt.Errorf("failed to get server public key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	pkBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	pk, err := identity.KEMScheme().UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}
	return pk, nil
}

func makeSecureRequest(clientIdentity *identity.Identity, serverPK kem.PublicKey, endpoint string) error {
	sender, err := identity.Suite().NewSender(serverPK, nil)
	if err != nil {
		return fmt.Errorf("failed to create sender context: %v", err)
	}
	clientEncapKey, sealer, err := sender.Setup(nil)
	if err != nil {
		return fmt.Errorf("failed to setup encryption: %v", err)
	}

	// Encrypt request body with sealer
	requestBody := []byte("nate")
	encrypted, err := sealer.Seal(requestBody, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt request body: %v", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(encrypted))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Tinfoil-Encapsulated-Key", hex.EncodeToString(clientEncapKey))
	req.Header.Set("Tinfoil-Client-Public-Key", hex.EncodeToString(clientIdentity.MarshalPublicKey()))
	req.Header.Set("Content-Type", "application/octet-stream")

	// Make request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	receiver, err := identity.Suite().NewReceiver(clientIdentity.PrivateKey(), nil)
	if err != nil {
		return fmt.Errorf("failed to create receiver: %v", err)
	}

	serverEncapKey, err := hex.DecodeString(resp.Header.Get("Tinfoil-Encapsulated-Key"))
	if err != nil {
		return fmt.Errorf("failed to decode encapsulated key: %v", err)
	}
	opener, err := receiver.Setup(serverEncapKey)
	if err != nil {
		return fmt.Errorf("failed to setup decryption: %v", err)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}
	decrypted, err := opener.Open(respBody, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt response: %v", err)
	}
	fmt.Printf("Decrypted response: %s\n", decrypted)
	return nil
}

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	clientIdentity, err := identity.FromFile(*identityFile)
	if err != nil {
		log.Fatalf("failed to get client identity: %v", err)
	}

	log.Info("Getting server public key")
	serverPK, err := getServerPublicKey(*serverURL)
	if err != nil {
		log.Fatalf("failed to get server public key: %v", err)
	}

	log.Info("Making secure request")
	if err := makeSecureRequest(clientIdentity, serverPK, fmt.Sprintf("%s/secure", *serverURL)); err != nil {
		log.Fatalf("failed to make secure request: %v", err)
	}
}
