# Encrypted HTTP Body Protocol (EHBP)

## 1. Introduction

EHBP (Encrypted HTTP Body Protocol) encrypts HTTP message bodies end‑to‑end between a client and an origin server while leaving HTTP headers in the clear for routing. Payloads can transit proxies unchanged. EHBP uses HPKE (RFC 9180) to derive per‑message encryption contexts and applies length‑prefixed streaming AEAD to bodies without changing HTTP semantics.

This document specifies the application-layer semantics, required headers, and on-the-wire body framing used by the reference implementation in this repository.

## 2. Protocol Overview

EHBP is a layered protocol implemented as:

- Client transport that encrypts request bodies and decrypts response bodies.
- Server middleware that decrypts request bodies and encrypts response bodies.

For each HTTP exchange:

- Request body: If present, the client derives an HPKE context from the server's public key and encrypts the body as a stream.
- Response body: The server derives response encryption keys from the request's HPKE context and encrypts the body as a stream. The client uses the same derivation to decrypt.

Request encryption uses HPKE directly. Response encryption uses keys derived from the request's HPKE shared secret via HKDF, providing cryptographic binding between request and response. Both directions frame the ciphertext as a sequence of length‑prefixed chunks.

## 3. Server Key Distribution

### 3.1 Discovery

Servers MUST expose their HPKE configuration at `/.well-known/hpke-keys` with:

- Content-Type: `application/ohttp-keys`
- Body: a key configuration as defined in RFC 9458 Section 3.

This implementation produces exactly one `key_config` and clients select the first/only config present.

### 3.2 Key Config

The implementation emits a `key_config` with fields:

- `key_id`: 0
- `kem_id`: X25519_HKDF_SHA256
- `cipher_suites`: one suite consisting of KDF=HKDF_SHA256 and AEAD=AES_256_GCM
- `public_key`: server KEM public key bytes for the selected KEM

Clients MUST parse the first `key_config` and use its public key and suite. Additional `key_config` entries, if present, are ignored by this implementation.

## 4. Protocol Messages

### 4.1 Request Headers

Clients MUST set:

- `Ehbp-Encapsulated-Key`: hex (lowercase, no prefix) of the HPKE encapsulated key used to derive the request encryption context. Required if and only if the request body is encrypted (i.e., a non‑empty body is present).
- `Transfer-Encoding: chunked`: used when sending an encrypted body. Content-Length MUST be omitted. Implementations MUST ensure Content-Length is not set (or set to -1/unknown) to trigger automatic chunked transfer encoding. Note: In browser environments, this header cannot be set explicitly due to browser restrictions; browsers handle chunked encoding automatically when Content-Length is omitted.

### 4.2 Response Headers

Servers MUST set for encrypted responses:

- `Ehbp-Response-Nonce`: hex (lowercase, no prefix) of the random nonce used in response key derivation. This MUST be exactly 32 bytes (64 hex characters), matching OHTTP's `max(Nn, Nk)` for AES-256-GCM.
- `Transfer-Encoding: chunked`: used when sending an encrypted body. Content-Length MUST be omitted. Implementations MUST ensure Content-Length is not set (or set to -1/unknown) to trigger automatic chunked transfer encoding.

For plaintext responses corresponding to requests where `Ehbp-Encapsulated-Key` is absent, the server does NOT set any EHBP headers. The absence of `Ehbp-Response-Nonce` indicates the response is plaintext.

### 4.3 Body Framing (Both Directions)

Encrypted bodies are framed as a sequence of chunks:

- Each chunk = `LEN(4 bytes, big-endian uint32)` || `CIPHERTEXT(LEN bytes)`; `LEN` counts ciphertext bytes only.
- `CIPHERTEXT` is produced by AEAD sealing under the single HPKE context for the message direction (AAD is empty). The sealer/opener pair is established once per body and reused for every chunk.
- A chunk length of zero MAY appear when the application performs an empty write; receivers ignore such chunks and continue parsing.
- End of message is indicated by the end of the HTTP entity body; no special sentinel chunk is used.

Receivers MUST read a 4‑byte length, then exactly that many ciphertext bytes, then open with the appropriate opener (HPKE for requests, derived AEAD for responses).

### 4.4 Response Key Derivation

Response encryption uses keys derived from the request's HPKE context, providing cryptographic binding between request and response.

#### 4.4.1 Derivation Procedure

Both client and server derive response keys as follows:

The request HPKE context is established with:

```
enc, context = SetupBaseS(server_public_key, "ehbp request")
```

The derivation then follows OHTTP (RFC 9458) exactly:

1. **Export secret from HPKE context:**
   ```
   secret = context.Export("ehbp response", Nk)
   ```

   Where:
   - `context` is the HPKE context established above (opener on server, sealer on client)
   - `Nk` = 32 (AES-256 key size)

2. **Generate response nonce:**
   ```
   response_nonce = random(max(Nn, Nk))
   ```

   Where `max(Nn, Nk)` = max(12, 32) = 32 bytes for AES-256-GCM.

3. **Construct salt and derive PRK:**
   ```
   salt = concat(enc, response_nonce)
   prk = Extract(salt, secret)
   ```

4. **Derive AEAD key and nonce:**
   ```
   aead_key = Expand(prk, "key", Nk)
   aead_nonce = Expand(prk, "nonce", Nn)
   ```

   Where `Nk` = 32 and `Nn` = 12.

5. **Encrypt/decrypt using AES-256-GCM:**
   - The response body uses the same chunked framing as requests (Section 4.3)
   - Each chunk is encrypted with AES-256-GCM using `aead_key`
   - Nonce for chunk `i` is: `aead_nonce XOR i` (where `i` is zero-indexed)
   - AAD is empty

#### 4.4.2 Security Properties

This derivation ensures:
- Response keys are bound to the specific request (via `request_enc`)
- Only parties who participated in the request HPKE can derive response keys
- Each response has unique keys (via `response_nonce`)
- A MitM cannot derive response keys without the HPKE shared secret

## 5. Message Processing

### 5.1 Client

- Key acquisition: GET `/.well-known/hpke-keys` and parse the first `key_config` with Content-Type `application/ohttp-keys`.
- Outbound request:

  - Encrypt the request body when a non-empty payload body is present. Establish an HPKE sealer to the server public key (Section 4.4.1) and stream‑encrypt using the chunk framing in Section 4.3. Set `Ehbp-Encapsulated-Key` and use chunked transfer encoding without a Content-Length. Retain the HPKE sender context for response decryption.
  - When the request has no payload body, the request MUST be sent without `Ehbp-Encapsulated-Key` and the response will be unencrypted. See Section 7.4 for the security rationale.
- Inbound response:

  - For requests with encrypted bodies: Require `Ehbp-Response-Nonce`; derive response keys using the procedure in Section 4.4 (using the retained HPKE sender context from the request). Stream-decrypt the chunked body using the derived AES-256-GCM key.
  - If `Ehbp-Response-Nonce` is missing or invalid, the client MUST fail the request and MUST NOT treat the response body as authenticated application data. The client MAY parse plaintext error details only for diagnostics and recovery (Section 5.4), but this does not make the response trustworthy.
  - For bodyless requests: The response is unencrypted. Process as a normal HTTP response.

### 5.2 Server

- Request handling:

  - The middleware checks for `Ehbp-Encapsulated-Key`. The server accepts both encrypted and plaintext requests.
  - If `Ehbp-Encapsulated-Key` is present, establish an HPKE opener using the server's private key (Section 4.4.1) and decrypt the body as a chunked stream (Section 4.3). The server retains the HPKE receiver context for response encryption.
  - If the encrypted request is malformed, decapsulation fails, decryption/authentication fails, or framing is invalid, the server MUST fail closed and reject the request before application processing completes.
  - Error status mapping:
    - malformed encapsulated request or cryptographic verification failure: HTTP 400
    - key/configuration mismatch (for example, stale client key after rotation): HTTP 422 (Unprocessable Content) with optional `application/problem+json` details as defined in Section 5.4.2
    - internal failures unrelated to client input: HTTP 500
  - If `Ehbp-Encapsulated-Key` is absent, the request is passed through unchanged to the next handler. The response MUST also be plaintext and MUST not have `Ehbp-Response-Nonce` header.
  - If the request has no payload body, pass through unencrypted without setting any EHBP headers. The client knows it sent a bodyless request and will not attempt to decrypt the response. See Section 7.4 for the security rationale.
- Response handling:

  - If an HPKE receiver context was established from the request, generate a random 32-byte response nonce (matching OHTTP's `max(Nn, Nk)`), derive response keys using the procedure in Section 4.4, and stream-encrypt the response body with AES-256-GCM. Set `Ehbp-Response-Nonce`. Use chunked transfer encoding and omit Content-Length.
  - If no HPKE context was established (plaintext request or bodyless request), the response is sent as plaintext without any EHBP headers.

### 5.3 Mode Detection

The presence or absence of `Ehbp-Response-Nonce` in the response indicates whether EHBP encryption was used:

- `Ehbp-Response-Nonce` present → response body is encrypted
- `Ehbp-Response-Nonce` absent → response body is plaintext

Clients that send encrypted requests MUST verify `Ehbp-Response-Nonce` is present in the response. If the header is missing, the client MUST fail the request rather than falling back to reading plaintext. This prevents body substitution attacks where an attacker strips the nonce header and replaces the encrypted body with attacker-controlled plaintext.

### 5.4 Error Handling and Recovery

This section aligns EHBP error handling with OHTTP guidance and HPKE security considerations.

#### 5.4.1 Failure Classes

EHBP implementations MUST treat these as protocol failures:

- invalid `Ehbp-Encapsulated-Key` (format, length, or unsupported parameters)
- HPKE setup/decapsulation failure
- chunk framing violation
- AEAD authentication/decryption failure
- missing/invalid `Ehbp-Response-Nonce` when an encrypted response is expected

Implementations MUST fail closed: no plaintext fallback for encrypted exchanges and no partial decrypted data exposure after authentication failure.

#### 5.4.2 HTTP Error Signaling

Servers SHOULD return HTTP status codes as follows:

- `400 Bad Request`: malformed encapsulated request or cryptographic/framing failure attributable to request input
- `422 Unprocessable Content`: key configuration mismatch (for example, unknown/replaced key identifier or decryption failure with the selected key, including stale client configuration after key rotation)
- `500 Internal Server Error`: server-side processing failure not attributable to client input

For `422` key configuration mismatch responses, servers SHOULD use:

- `Content-Type: application/problem+json`
- JSON body with:
  - `"type": "urn:ietf:params:ehbp:error:key-config"`
  - `"title": "<human-readable summary>"`

This mirrors OHTTP key-management guidance while keeping EHBP-specific error typing.

#### 5.4.3 Key-Configuration Mismatch Recovery

On receiving a key-configuration mismatch (Section 5.4.2), the client knows the server rejected the request before application processing completed (per Section 5.2). It is safe to:

1. Refresh server key configuration (e.g., by refetching `/.well-known/hpke-keys` or through a trusted out-of-band channel per Section 7.3).
2. Recreate the EHBP transport with the new key.
3. Re-send the original request.


#### 5.4.4 Side-Channel and Oracle Considerations

Error responses MUST NOT disclose fine-grained cryptographic failure causes (for example, whether decapsulation failed versus AEAD authentication failed). Implementations SHOULD use stable external error shapes/status families to reduce oracle risk.

For DHKEM implementations, developers SHOULD follow RFC 9180 guidance on implicit rejection to limit side-channel leakage from malformed public keys.

## 6. Session Recovery Tokens (Optional)

Clients MAY extract a **session recovery token** from the HPKE sender context after encrypting a request. This token contains the minimal cryptographic material needed to derive response decryption keys (Section 4.4) without retaining the live HPKE context, enabling response decryption in a different process or session than the one that sent the request. For example, a client can persist the token before issuing a long-running request so that the response can be decrypted even if the original process is interrupted.

### 6.1 Token Structure

A session recovery token consists of:

- `exported_secret`: `context.Export("ehbp response", Nk)` — the HPKE export secret.
- `request_enc`: the HPKE encapsulated key (`enc`) from the request.

### 6.1.1 JSON Serialization

When serialized to JSON (for storage or cross-language interchange), both fields MUST be encoded as **lowercase hex strings**:

```json
{
  "exportedSecret": "ab01cd...",
  "requestEnc": "ef23ab..."
}
```


### 6.2 Response Decryption with a Token

To decrypt a response using a session recovery token:

1. Read the `Ehbp-Response-Nonce` header from the response (Section 4.2).
2. Derive response keys using the procedure in Section 4.4, substituting the token's `exported_secret` for the HPKE export and the token's `request_enc` for `enc`.
3. Decrypt the response body using the derived AES-256-GCM key and the chunked framing in Section 4.3.

### 6.3 Security Considerations for Tokens

- A session recovery token is equivalent in power to the ability to decrypt a single response. It MUST be treated as sensitive key material.
- Tokens are scoped to a single request-response exchange. Each encrypted request produces a unique token; tokens cannot be reused across requests.
- A token is considered consumed once the corresponding response has been fully decrypted, or once a new request supersedes it. Implementations MUST delete all representations of a consumed token immediately. Tokens that have not yet been consumed SHOULD be stored for the minimum duration necessary for recovery; long-lived storage increases the window of exposure if the storage is compromised.

## 7. Security Considerations

### 7.1 Request-Response Binding

EHBP cryptographically binds responses to their corresponding requests. This prevents:

- **Response interception:** A MitM cannot decrypt responses without the request's HPKE shared secret
- **Response forgery:** A MitM cannot create valid encrypted responses
- **Response swapping:** Responses cannot be replayed or swapped between different requests

### 7.2 Scope of Protection

- EHBP encrypts HTTP bodies only. HTTP headers remain in cleartext.
- Request encryption uses a fresh HPKE setup per HTTP exchange; response encryption uses keys derived from the request context.
- Streaming frame lengths (4‑byte prefixes) reveal ciphertext chunk sizes and boundaries.

### 7.3 Keys and Suites

- Private keys MUST be protected and never transmitted.
- Public keys SHOULD be distributed and verified via a trusted channel.
- Key configurations SHOULD be rotated periodically; clients may cache the advertised `key_config` until rotated.
- The reference implementation uses KEM X25519_HKDF_SHA256, KDF HKDF_SHA256, AEAD AES_256_GCM; AAD is empty for all seals/opens.
- EHBP implementations MUST ensure HPKE keys are not reused in other protocols that use the same HPKE context labels and framing semantics.
- Protocols that reuse EHBP framing MUST use distinct HPKE `info`/export labels to ensure key diversity and avoid cross-protocol key reuse.

### 7.4 Bodyless Requests

EHBP does not support encrypted responses for requests without a payload body (e.g., GET, HEAD, DELETE, OPTIONS without a body). Such requests pass through unencrypted.

**Security rationale:** The encrypted request body provides implicit authentication of the `Ehbp-Encapsulated-Key` header. When the client encrypts a body using the HPKE sealer derived from the encapsulated key, the server's successful decryption proves that:

1. The encapsulated key was generated by an entity that knows the corresponding ephemeral private key
2. The request has not been tampered with

Without an encrypted body, an active man-in-the-middle can substitute the encapsulated key with their own, causing the server to derive response keys that the MitM can compute. While the MitM cannot forward a valid encrypted response to the original client (the client would fail decryption), the MitM can read the server's response content.

This vulnerability does not exist for requests with bodies because substituting the encapsulated key would cause request body decryption to fail, alerting the server to the attack.

Applications requiring confidential responses to bodyless requests should either:
- Include a minimal body (even if semantically empty) to enable EHBP protection
- Use an alternative mechanism such as TLS with mutual authentication

## 8. Encrypted WebSocket Channels (EHBP-WS)

### 8.1 Overview

EHBP-WS extends EHBP's protection model to WebSocket connections: the HTTP upgrade request and WebSocket control frames remain in cleartext so intermediaries can route the connection, while every application message is encrypted end-to-end between the client and the origin server.

Because a WebSocket handshake is a bodyless GET, the header-based mechanism of Section 4 cannot be authenticated (see Section 7.4). EHBP-WS therefore does not use EHBP headers at all. Instead, it runs a Noise NK handshake inside the established WebSocket connection, keyed by the server's X25519 static key, followed by an encrypted record layer.

The Noise protocol name is:

```
Noise_NK_25519_AESGCM_SHA256
```

The client is the Noise initiator and is not authenticated; the server is the responder, authenticated by its static key. This mirrors the HTTP mode's trust model.

### 8.2 Server Key

The Noise responder static key is the server's HPKE identity key (Section 3): the same X25519 key pair serves both DHKEM(X25519, HKDF-SHA256) in the HTTP mode and Noise DH in the WebSocket mode. Clients obtain it via the discovery mechanism of Section 3.1 or a trusted out-of-band channel (Section 7.3).

This cross-protocol reuse is deliberate and is domain-separated by the mandatory Noise prologue:

```
prologue = "ehbp noise websocket v1"
```

Both peers MUST use this exact prologue; a mismatch fails the handshake. In both protocols the key is used only for X25519 Diffie-Hellman; it is never used for signing.

### 8.3 Negotiation

Clients MUST offer and servers MUST select the WebSocket subprotocol:

```
Sec-WebSocket-Protocol: ehbp.noise.v1
```

Either peer MUST fail the connection if the subprotocol is not negotiated. Protocol and cipher agility is expressed only through new subprotocol names; there is no in-band negotiation to downgrade.

WebSocket per-message compression (RFC 7692) MUST NOT be negotiated. Servers MUST decline `permessage-deflate` offers on this subprotocol: compression of attacker-influenced plaintext before encryption enables CRIME-style oracles, and compression of ciphertext is useless.

### 8.4 Handshake

After the upgrade completes, the two Noise NK handshake messages are exchanged, each carried in exactly one WebSocket binary message:

1. Client → Server: `e, es`
2. Server → Client: `e, ee`

Handshake message payloads MUST be empty when sending; receivers MUST ignore any payload present. Neither peer sends application data before the handshake completes: the client MUST NOT send records before processing message 2, and the server MUST NOT send records before successfully processing message 1.

Implementations MUST bound handshake messages (the reference implementation limits them to 4096 bytes; valid NK messages are 48 bytes) and SHOULD apply a handshake timeout (reference default: 10 seconds).

If the handshake fails, the server SHOULD close the WebSocket with status code 1008 (policy violation) and reason `noise handshake failed`. A client holding a stale server key after key rotation fails at this point; on receiving this close code during the handshake, clients SHOULD refresh the server key configuration (Section 5.4.3) before reconnecting.

### 8.5 Record Layer

After the handshake, every WebSocket binary message carries exactly one record. A record plaintext is:

```
record = type (1 byte) || payload
```

encrypted as a Noise transport message under the sending direction's cipher state. Defined types:

- `0x01` data: `payload` is an application message (MAY be empty)
- `0x02` close: authenticated end-of-stream; senders MUST send an empty `payload` and receivers MUST ignore any payload present

Noise transport messages use implicit sequence-number nonces, so records are implicitly ordered per direction; reordering, deletion, or replay causes an authentication failure. AAD is empty.

Text messages MUST NOT be used and receiving one is a protocol violation. WebSocket control frames (ping, pong, close) belong to the transport layer, are not end-to-end protected, and MUST NOT carry application data.

Implementations MUST enforce a maximum record payload size (reference default: 1 MiB) in both directions; an oversized record is a protocol violation. Both peers should agree on the cap out of band. Messages larger than the cap must be split into multiple data records by the application.

### 8.6 Rekeying

After every 65536 (2^16) records sent or received in a direction, that direction's cipher state MUST be advanced with the Noise `Rekey()` function. The schedule is deterministic and counts every record, including close records; peers that disagree on the schedule fail authentication at the next record. Rekeying bounds the amount of traffic protected under a single AEAD key on long-lived connections and provides forward secrecy within the connection for records older than one rekey interval.

### 8.7 Connection Termination

A peer initiating shutdown MUST send a close record (type `0x02`) before starting the WebSocket close handshake. A peer receiving a close record treats the stream as cleanly ended, SHOULD respond with its own close record if it has not already sent one, and completes the WebSocket close handshake.

A connection that ends without a received close record (WebSocket close frame, TCP reset, or any transport error) MUST be surfaced as truncation, not as a clean end of stream. WebSocket close frames are unauthenticated and MUST NOT be trusted to signal a clean shutdown. This gives EHBP-WS authenticated termination, which the HTTP mode's body framing (Section 4.3) does not provide.

### 8.8 Failure Handling

Implementations MUST treat the following as protocol failures and fail closed, terminating the connection immediately without a close handshake:

- non-binary message on the channel
- AEAD authentication or decryption failure
- empty record (missing type byte)
- unknown record type
- record exceeding the size limit

After a failure, no plaintext from the failed record may be exposed, and subsequent reads MUST consistently report the failure rather than a clean end of stream.

### 8.9 Security Considerations

- **Server authentication and key confirmation.** The `es` DH in message 1 means only the holder of the server static key can complete the handshake; the handshake occurring in-band closes the header-substitution attack of Section 7.4 that prevents header-based key exchange on bodyless requests.
- **Forward secrecy.** Transport keys mix `ee`, so recorded EHBP-WS traffic is not decryptable by a later compromise of the server static key. This is stronger than the HTTP mode. An attacker holding the static key at connection time can actively impersonate the server.
- **Client anonymity and replay.** Clients are not authenticated at the channel layer; anyone can open a channel, so a replayed handshake message 1 gains an attacker nothing beyond opening a connection. Applications requiring client identity SHOULD send credentials inside the encrypted channel rather than in upgrade headers, which are visible to intermediaries.
- **Cleartext metadata.** The upgrade request (URL, headers, subprotocol), WebSocket control frames, record sizes, and timing are visible to intermediaries. The upgrade request is not cryptographically bound to the channel; intermediaries can rewrite routing metadata, consistent with Section 7.2.
- **Denial of service.** The handshake is unauthenticated and costs one DH per message; implementations SHOULD apply handshake timeouts and SHOULD bound idle connections at the application layer.

## 9. References

- RFC 9180: Hybrid Public Key Encryption (HPKE)
- RFC 9458: Oblivious HTTP (for `application/ohttp-keys` `key_config` format)
- RFC 6455: The WebSocket Protocol
- The Noise Protocol Framework, revision 34 (https://noiseprotocol.org/noise.html)
