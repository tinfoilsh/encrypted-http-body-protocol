# Encrypted HTTP Body Protocol (EHBP)

## 1. Introduction

EHBP (Encrypted HTTP Body Protocol) is designed to provide secure, encrypted communication between HTTP clients and servers. It uses HPKE [RFC9180] to establish secure channels and encrypt message payloads. The protocol is implemented as a middleware layer that can be added to existing HTTP applications.

## 2. Protocol Overview

EHBP operates as a middleware layer that intercepts HTTP requests and responses, encrypting the payloads while preserving the HTTP protocol structure. The protocol consists of two main components:

1. Client-side middleware that encrypts requests and decrypts responses
2. Server-side middleware that decrypts requests and encrypts responses

## 3. Server Key Distribution

### 3.1 Key Format

Servers MUST expose their keys at the well-known URI `/.well-known/hpke-keys`. The response MUST:
- Have Content-Type: application/ohttp-keys  
- Contain one or more key configurations in the format specified in [RFC 9458 Section 3](https://www.ietf.org/rfc/rfc9458.html#section-3)

### 3.2 Media Type

The "application/ohttp-keys" media type identifies a collection of server keys as defined in [RFC 9458 Section 3](https://www.ietf.org/rfc/rfc9458.html#section-3).

## 4. Protocol Messages

### 4.1 Request Headers

Clients MUST include the following headers in encrypted requests:
- `EHBP-Client-Public-Key`: Hex-encoded client public key
- `EHBP-Encapsulated-Key`: Hex-encoded encapsulated key from HPKE setup

### 4.2 Response Headers

Servers MUST include the following headers in encrypted responses:
- `EHBP-Encapsulated-Key`: Hex-encoded encapsulated key from HPKE setup

## 5. Message Processing

### 5.1 Request Processing

1. Client generates an encapsulated key and shared secret using the server's public key
2. Client encrypts the request body using the shared secret
3. Client sends the encrypted request with required headers
4. Server decrypts the request body using the encapsulated key and its private key
5. If decryption fails, server MUST return HTTP 400 with appropriate error message

### 5.2 Response Processing

1. Server generates an encapsulated key and shared secret using the client's public key
2. Server encrypts the response body using streaming encryption as data is written
3. Server sends the encrypted response with required headers and chunked transfer encoding
4. Client decrypts the response body as it reads from the stream
5. If decryption fails, client MUST treat the response as invalid

## 6. Security Considerations

### 6.1 Key Management

- Private keys MUST be stored securely and never transmitted
- Public keys SHOULD be verified through a trusted mechanism
- Key pairs SHOULD be rotated periodically

### 6.2 Protocol Security

- The protocol provides end-to-end encryption for message payloads ONLY
- HTTP headers remain unencrypted for routing purposes
- Each message exchange uses a fresh key encapsulation
- Servers MAY support plaintext fallback mode

## 7. References

- [RFC9180] Hybrid Public Key Encryption
