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

The derivation follows OHTTP (RFC 9458) exactly:

1. **Export secret from HPKE context:**
   ```
   secret = context.Export("ehbp response", Nk)
   ```

   Where:
   - `context` is the HPKE context (opener on server, sealer on client)
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

  - Encrypt the request body when a non-empty payload body is present. Establish an HPKE sealer to the server public key and stream‑encrypt using the chunk framing in Section 4.3 of this document. Set `Ehbp-Encapsulated-Key` and use chunked transfer encoding without a Content-Length. Retain the HPKE sender context for response decryption.
  - When the request has no payload body, the request MUST be sent without `Ehbp-Encapsulated-Key` and the response will be unencrypted. See Section 6.4 for the security rationale.
- Inbound response:

  - For requests with encrypted bodies: Require `Ehbp-Response-Nonce`; derive response keys using the procedure in Section 4.4 (using the retained HPKE sender context from the request). Stream-decrypt the chunked body using the derived AES-256-GCM key. If the header is missing or invalid, treat the response as an error and fail the request.
  - For bodyless requests: The response is unencrypted. Process as a normal HTTP response.

### 5.2 Server

- Request handling:

  - The middleware checks for `Ehbp-Encapsulated-Key`. The server accepts both encrypted and plaintext requests.
  - If `Ehbp-Encapsulated-Key` is present, the body is decrypted as a chunked stream (Section 4.3). The server retains the HPKE receiver context for response encryption. If the client request is not well-formed (invalid hex, HPKE setup failure), the server responds with HTTP 400; other failures return 500.
  - If `Ehbp-Encapsulated-Key` is absent, the request is passed through unchanged to the next handler. The response MUST also be plaintext and MUST not have `Ehbp-Response-Nonce` header.
  - If the request has no payload body, pass through unencrypted without setting any EHBP headers. The client knows it sent a bodyless request and will not attempt to decrypt the response. See Section 6.4 for the security rationale.
- Response handling:

  - If an HPKE receiver context was established from the request, generate a random 32-byte response nonce (matching OHTTP's `max(Nn, Nk)`), derive response keys using the procedure in Section 4.4, and stream-encrypt the response body with AES-256-GCM. Set `Ehbp-Response-Nonce`. Use chunked transfer encoding and omit Content-Length.
  - If no HPKE context was established (plaintext request or bodyless request), the response is sent as plaintext without any EHBP headers.

### 5.3 Mode Detection

The presence or absence of `Ehbp-Response-Nonce` in the response indicates whether EHBP encryption was used:

- `Ehbp-Response-Nonce` present → response body is encrypted
- `Ehbp-Response-Nonce` absent → response body is plaintext

Clients that send encrypted requests MUST verify `Ehbp-Response-Nonce` is present in the response. If the header is missing, the client MUST fail the request rather than falling back to reading plaintext. This prevents body substitution attacks where an attacker strips the nonce header and replaces the encrypted body with attacker-controlled plaintext.

## 6. Security Considerations

### 6.1 Request-Response Binding

EHBP cryptographically binds responses to their corresponding requests. This prevents:

- **Response interception:** A MitM cannot decrypt responses without the request's HPKE shared secret
- **Response forgery:** A MitM cannot create valid encrypted responses
- **Response swapping:** Responses cannot be replayed or swapped between different requests

### 6.2 Scope of Protection

- EHBP encrypts HTTP bodies only. HTTP headers remain in cleartext.
- Request encryption uses a fresh HPKE setup per HTTP exchange; response encryption uses keys derived from the request context.
- Streaming frame lengths (4‑byte prefixes) reveal ciphertext chunk sizes and boundaries.

### 6.3 Keys and Suites

- Private keys MUST be protected and never transmitted.
- Public keys SHOULD be distributed and verified via a trusted channel.
- Key configurations SHOULD be rotated periodically; clients may cache the advertised `key_config` until rotated.
- The reference implementation uses KEM X25519_HKDF_SHA256, KDF HKDF_SHA256, AEAD AES_256_GCM; AAD is empty for all seals/opens.

### 6.4 Bodyless Requests

EHBP does not support encrypted responses for requests without a payload body (e.g., GET, HEAD, DELETE, OPTIONS without a body). Such requests pass through unencrypted.

**Security rationale:** The encrypted request body provides implicit authentication of the `Ehbp-Encapsulated-Key` header. When the client encrypts a body using the HPKE sealer derived from the encapsulated key, the server's successful decryption proves that:

1. The encapsulated key was generated by an entity that knows the corresponding ephemeral private key
2. The request has not been tampered with

Without an encrypted body, an active man-in-the-middle can substitute the encapsulated key with their own, causing the server to derive response keys that the MitM can compute. While the MitM cannot forward a valid encrypted response to the original client (the client would fail decryption), the MitM can read the server's response content.

This vulnerability does not exist for requests with bodies because substituting the encapsulated key would cause request body decryption to fail, alerting the server to the attack.

Applications requiring confidential responses to bodyless requests should either:
- Include a minimal body (even if semantically empty) to enable EHBP protection
- Use an alternative mechanism such as TLS with mutual authentication

## 7. References

- RFC 9180: Hybrid Public Key Encryption (HPKE)
- RFC 9458: Oblivious HTTP (for `application/ohttp-keys` `key_config` format)
