# Encrypted HTTP Body Protocol (EHBP)

## 1. Introduction

EHBP (Encrypted HTTP Body Protocol) encrypts HTTP message bodies end‑to‑end between a client and an origin server while leaving HTTP headers in the clear for routing. Payloads can transit proxies unchanged. EHBP uses HPKE (RFC 9180) to derive per‑message encryption contexts and applies length‑prefixed streaming AEAD to bodies without changing HTTP semantics.

This document specifies the application-layer semantics, required headers, and on-the-wire body framing used by the reference implementation in this repository.

## 2. Protocol Overview

EHBP is a layered protocol implemented as:

- Client transport that encrypts request bodies and decrypts response bodies.
- Server middleware that decrypts request bodies and encrypts response bodies.

For each HTTP exchange:

- Request body: If present, the client derives an HPKE context from the server’s public key and encrypts the body as a stream.
- Response body: The server derives an HPKE context from the client’s public key and encrypts the body as a stream.

Both directions use a single HPKE setup per body and frame the ciphertext as a sequence of length‑prefixed chunks.

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

- `Ehbp-Client-Public-Key`: hex (lowercase, no prefix) of the client's KEM public key. Required for any request that expects an encrypted response, including requests without a body.
- `Ehbp-Encapsulated-Key`: hex (lowercase, no prefix) of the HPKE encapsulated key used to derive the request sealer. Required if and only if the request body is encrypted (i.e., a non‑empty body is present).
- `Transfer-Encoding: chunked`: used when sending an encrypted body. Content-Length MUST be omitted. Implementations MUST ensure Content-Length is not set (or set to -1/unknown) to trigger automatic chunked transfer encoding. Note: In browser environments, this header cannot be set explicitly due to browser restrictions; browsers handle chunked encoding automatically when Content-Length is omitted.

### 4.2 Response Headers

Servers MUST set for encrypted responses:

- `Ehbp-Encapsulated-Key`: hex (lowercase, no prefix) of the HPKE encapsulated key used to derive the response sealer.
- `Transfer-Encoding: chunked`: used when sending an encrypted body. Content-Length MUST be omitted. Implementations MUST ensure Content-Length is not set (or set to -1/unknown) to trigger automatic chunked transfer encoding.

Servers that accept plaintext fallback (Section 5.3) MUST set:

- `Ehbp-Fallback: 1` on plaintext responses produced due to fallback.

### 4.3 Body Framing (Both Directions)

Encrypted bodies are framed as a sequence of chunks:

- Each chunk = `LEN(4 bytes, big-endian uint32)` || `CIPHERTEXT(LEN bytes)`; `LEN` counts ciphertext bytes only.
- `CIPHERTEXT` is produced by AEAD sealing under the single HPKE context for the message direction (AAD is empty). The sealer/opener pair is established once per body and reused for every chunk.
- A chunk length of zero MAY appear when the application performs an empty write; receivers ignore such chunks and continue parsing.
- End of message is indicated by the end of the HTTP entity body; no special sentinel chunk is used.

Receivers MUST read a 4‑byte length, then exactly that many ciphertext bytes, then open with the HPKE opener.

## 5. Message Processing

### 5.1 Client

- Key acquisition: GET `/.well-known/hpke-keys` and parse the first `key_config` with Content-Type `application/ohttp-keys`.
- Outbound request:

  - Encrypt the request body when a non-empty payload body is present. Establish an HPKE sealer to the server public key and stream‑encrypt using the chunk framing in Section 4.3 of this document. Set `Ehbp-Encapsulated-Key` and `Ehbp-Client-Public-Key`, and use chunked transfer encoding without a Content-Length.
  - When the request has no payload body, attach `Ehbp-Client-Public-Key` so the server can encrypt the response; do not emit a request encapsulated key header.
  - Requests explicitly constructed with a zero-length payload body are forwarded unchanged; clients that require an encrypted response MUST still include `Ehbp-Client-Public-Key`.
- Inbound response:

  - Require `Ehbp-Encapsulated-Key`; derive the opener and stream‑decrypt the chunked body (Section 4.3 of this document). If the header is missing or invalid, treat the response as an error and fail the request.

### 5.2 Server

- Request handling:

  - The middleware first reads `Ehbp-Client-Public-Key`. If it is missing and plaintext fallback is disabled, the request is rejected with 400.
  - With fallback enabled and the header missing, the server sets `Ehbp-Fallback: 1`, leaves the body untouched, and delegates to the next handler.
  - When a non-empty payload body is present, both `Ehbp-Client-Public-Key` and `Ehbp-Encapsulated-Key` MUST be present. The body is decrypted as a chunked stream (Section 4.3). Client-caused errors (missing/invalid headers, invalid hex, HPKE setup failure) produce HTTP 400 responses; other failures return 500.
  - If the request has no payload body, no decryption is attempted.
- Response handling:

  - If `Ehbp-Client-Public-Key` is present, perform HPKE setup to the client public key and stream‑encrypt the response body. Set `Ehbp-Encapsulated-Key`. Use chunked transfer encoding and omit Content-Length.

### 5.3 Plaintext Fallback (Server)

Servers MAY support plaintext fallback. If enabled and `Ehbp-Client-Public-Key` is absent on the request, the server:

- MUST set `Ehbp-Fallback: 1` and pass the request/response through unencrypted.
- MUST NOT send `Ehbp-Encapsulated-Key` on the response in this case.

Fallback is not used for malformed headers; if `Ehbp-Client-Public-Key` is present but invalid, the handler returns HTTP 400.

Client implementations MAY support consuming plaintext fallback responses. The reference Go client does not implement fallback consumption and requires encrypted responses. The reference JavaScript client supports plaintext fallback: when `Ehbp-Fallback: 1` is present on the response, it returns the response without attempting decryption.

## 6. Security Considerations

### 6.1 Scope of Protection

- EHBP encrypts HTTP bodies only. HTTP headers remain in cleartext.
- Each message direction uses a fresh HPKE setup (new encapsulated key) per HTTP exchange.
- Streaming frame lengths (4‑byte prefixes) reveal ciphertext chunk sizes and boundaries.

### 6.2 Keys and Suites

- Private keys MUST be protected and never transmitted.
- Public keys SHOULD be distributed and verified via a trusted channel.
- Key configurations SHOULD be rotated periodically; clients may cache the advertised `key_config` until rotated.
- The reference implementation uses KEM X25519_HKDF_SHA256, KDF HKDF_SHA256, AEAD AES_256_GCM; AAD is empty for all seals/opens.

## 7. References

- RFC 9180: Hybrid Public Key Encryption (HPKE)
- RFC 9458: Oblivious HTTP (for `application/ohttp-keys` `key_config` format)
