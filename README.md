# Encrypted HTTP Body Protocol (EHBP)

EHBP (Encrypted HTTP Body Protocol) encrypts the HTTP message body while leaving the rest of the message unmodified.
Proxies can inspect and route upon request metadata without seeing the body.

The protocol uses HPKE, with a Go reference implementation (server middleware and client transport) and a JS client.
For protocol specifications, see [SPEC.md](SPEC.md).

## Motivation
EHBP makes it practical to add body encryption without needing to rethink existing HTTP stacks.
All HTTP metadata (method, URL, headers, query parameters) stays routable, only the message body is sealed.
This ensures that EHBP keeps streaming semantics intact and can be used as a drop-in replacement for HTTP.

## Requirements

- Go 1.24+
- Optional JS client: Node 20+

## Quickstart (Go)

1. Run the example server:

   ```sh
   go run ./cmd/example/server -l :8080 -i server_identity.json -v
   ```

   _The server writes `server_identity.json` on first run if it is absent._

2. Run the example client:

   ```sh
   go run ./cmd/example/client -s http://localhost:8080 -i client_identity.json -v
   ```

   _The client likewise materializes `client_identity.json` the first time it runs._

3. Use the curl-like fetcher (sends encrypted requests and decrypts responses):

   ```sh
   go run ./cmd/fetch -i client_identity.json -X POST -d 'hello' http://localhost:8080/secure
   ```

4. Enable server plaintext fallback (for testing):

   ```sh
   go run ./cmd/example/server -p -v
   ```


## Go Usage

### Server middleware

```go
package main

import (
  "log"
  "net/http"
  "os"

  "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
  "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

func main() {
  id, err := identity.FromFile("server_identity.json")
  if err != nil {
    log.Fatalf("server exited: %v", err)
  }

  mux := http.NewServeMux()
  mux.HandleFunc(protocol.KeysPath, id.ConfigHandler)
  mux.Handle("/secure", id.Middleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("ok"))
  })))

  if err := http.ListenAndServe(":8080", mux); err != nil {
    log.Fatalf("server exited: %v", err)
  }
}
```

### Client transport

```go
package main

import (
  "bytes"
  "log"
  "net/http"
  "os"

  "github.com/tinfoilsh/encrypted-http-body-protocol/client"
  "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

func main() {
  id, err := identity.FromFile("client_identity.json")
  if err != nil {
    log.Fatalf("client exited: %v", err)
  }

  tr, err := client.NewTransport("http://localhost:8080", id, false)
  if err != nil {
    log.Fatalf("client exited: %v", err)
  }

  httpClient := &http.Client{Transport: tr}
  resp, err := httpClient.Post("http://localhost:8080/secure", "text/plain", bytes.NewBufferString("hi"))
  if err != nil {
    log.Fatalf("client exited: %v", err)
  }
  defer resp.Body.Close()
}
```

## License

MIT (see LICENSE)
