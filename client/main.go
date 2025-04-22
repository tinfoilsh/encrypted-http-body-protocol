package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/openai/openai-go"

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

	httpClient := &http.Client{
		Transport: secureClient,
	}

	testSecureEndpoint(httpClient)
	testStreamEndpoint(httpClient)
	testOpenAI()
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

func testOpenAI() {
	openaiClient := NewOpenAIClient(*serverURL, *identityFile)
	stream := openaiClient.Chat.Completions.NewStreaming(
		context.Background(),
		openai.ChatCompletionNewParams{
			Model: "qwen:0.5b",
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.SystemMessage("You are a helpful assistant."),
				openai.UserMessage("Tell me a short story about aluminum foil."),
			},
		},
	)

	for stream.Next() {
		chunk := stream.Current()
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			fmt.Print(chunk.Choices[0].Delta.Content)
		}
	}
	if err := stream.Err(); err != nil {
		log.Fatalf("Stream error: %v", err)
	}
}
