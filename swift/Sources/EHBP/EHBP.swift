// EHBP - Encrypted HTTP Body Protocol
//
// Swift implementation of the EHBP protocol for end-to-end encrypted HTTP communication.
// Uses HPKE (RFC 9180) for request encryption and OHTTP-style (RFC 9458) key derivation
// for response decryption.
//
// Usage:
//
//     let identity = try Identity(publicKeyBytes: serverPublicKey)
//     let client = EHBPClient(identity: identity)
//     let (data, response) = try await client.request(
//         method: "POST",
//         url: "https://api.example.com/v1/chat/completions",
//         headers: ["Authorization": "Bearer \(apiKey)"],
//         body: requestBody
//     )
//

import Foundation

// Re-export all public types
@_exported import struct Foundation.Data
