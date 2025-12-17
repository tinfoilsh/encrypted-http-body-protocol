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

Servers that accept plaintext fallback (Section 5.3) MUST set:

- `Ehbp-Fallback: 1` on plaintext responses produced due to fallback.

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
  - When the request has no payload body, an encrypted response is not possible (since there is no HPKE context to derive response keys from). Such requests pass through unmodified.
- Inbound response:

  - Require `Ehbp-Response-Nonce`; derive response keys using the procedure in Section 4.4 (using the retained HPKE sender context from the request). Stream-decrypt the chunked body using the derived AES-256-GCM key. If the header is missing or invalid, treat the response as an error and fail the request.

### 5.2 Server

- Request handling:

  - The middleware checks for `Ehbp-Encapsulated-Key`. If it is missing and plaintext fallback is disabled, the request is rejected with 400.
  - With fallback enabled and the header missing, the server sets `Ehbp-Fallback: 1`, leaves the body untouched, and delegates to the next handler.
  - When a non-empty payload body is present, `Ehbp-Encapsulated-Key` MUST be present. The body is decrypted as a chunked stream (Section 4.3). Retain the HPKE receiver context for response encryption. Client-caused errors (missing/invalid headers, invalid hex, HPKE setup failure) produce HTTP 400 responses; other failures return 500.
  - If the request has no payload body, no decryption is attempted and no encrypted response can be sent.
- Response handling:

  - If an HPKE receiver context was established from the request, generate a random 32-byte response nonce (matching OHTTP's `max(Nn, Nk)`), derive response keys using the procedure in Section 4.4, and stream-encrypt the response body with AES-256-GCM. Set `Ehbp-Response-Nonce`. Use chunked transfer encoding and omit Content-Length.

### 5.3 Plaintext Fallback (Server)

Servers MAY support plaintext fallback. If enabled and `Ehbp-Encapsulated-Key` is absent on the request, the server:

- MUST set `Ehbp-Fallback: 1` and pass the request/response through unencrypted.
- MUST NOT send `Ehbp-Response-Nonce` on the response in this case.

Fallback is not used for malformed headers; if `Ehbp-Encapsulated-Key` is present but invalid, the handler returns HTTP 400.

Client implementations MAY support consuming plaintext fallback responses. The reference Go client does not implement fallback consumption and requires encrypted responses. The reference JavaScript client supports plaintext fallback: when `Ehbp-Fallback: 1` is present on the response, it returns the response without attempting decryption.

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

## 7. References

- RFC 9180: Hybrid Public Key Encryption (HPKE)
- RFC 9458: Oblivious HTTP (for `application/ohttp-keys` `key_config` format)
