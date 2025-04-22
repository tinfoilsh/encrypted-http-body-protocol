package main

import (
	"fmt"
	"net/http"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/stransport/identity"
)

func NewOpenAIClient(serverURL string, identityFile string) *openai.Client {
	clientIdentity, err := identity.FromFile(identityFile)
	if err != nil {
		log.Fatalf("failed to get client identity: %v", err)
	}

	secureClient, err := NewSecureClient(serverURL, clientIdentity)
	if err != nil {
		log.Fatalf("failed to create secure client: %v", err)
	}

	httpClient := &http.Client{
		Transport: secureClient,
	}

	c := openai.NewClient(
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(fmt.Sprintf("%s/v1/", serverURL)),
	)
	return &c
}
