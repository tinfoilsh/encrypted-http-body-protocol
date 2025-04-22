# Encrypted HTTP Body Protocol (EHBP) v1.0

## 1. Introduction

EHBP (Encrypted HTTP Body Protocol) is designed to provide secure, encrypted communication between HTTP clients and servers. It uses HPKE [RFC9180] to establish secure channels and encrypt message payloads. The protocol is implemented as a middleware layer that can be added to existing HTTP applications.

## 2. Protocol Overview

EHBP operates as a middleware layer that intercepts HTTP requests and responses, encrypting the payloads while preserving the HTTP protocol structure. The protocol consists of two main components:

1. Client-side middleware that encrypts requests and decrypts responses
2. Server-side middleware that decrypts requests and encrypts responses

## 3. Key Exchange

### 3.1 Server Public Key Distribution

Servers MUST expose their public key at the well-known URI `/.well-known/tinfoil-public-key`. The response MUST:
- Have Content-Type: text/plan
- Contain the server's public key, hex encoded

## 4. Protocol Messages

### 4.1 Request Headers

Clients MUST include the following headers in encrypted requests:
- `Tinfoil-Client-Public-Key`: Hex-encoded client public key
- `Tinfoil-Encapsulated-Key`: Hex-encoded encapsulated key from HPKE setup

### 4.2 Response Headers

Servers MUST include the following headers in encrypted responses:
- `Tinfoil-Encapsulated-Key`: Hex-encoded encapsulated key from HPKE setup

## 5. Message Processing

### 5.1 Request Processing

1. Client generates an encapsulated key and shared secret using the server's public key
2. Client encrypts the request body using the shared secret
3. Client sends the encrypted request with required headers
4. Server decrypts the request body using the encapsulated key and its private key
5. If decryption fails, server MUST return HTTP 400 with appropriate error message

### 5.2 Response Processing

1. Server generates an encapsulated key and shared secret using the client's public key
2. Server encrypts the response body using the shared secret
3. Server sends the encrypted response with required headers
4. Client decrypts the response body using the encapsulated key and its private key
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

## 7. References

- [RFC9180] Hybrid Public Key Encryption
