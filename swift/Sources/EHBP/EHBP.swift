// EHBP - Encrypted HTTP Body Protocol
//
// Swift implementation of the EHBP protocol for end-to-end encrypted HTTP communication.
// Uses HPKE (RFC 9180) for request encryption and OHTTP-style (RFC 9458) key derivation
// for response decryption.
//
// Usage:
//
//     let client = try EHBPClient(baseURL: "https://api.example.com", publicKey: serverPublicKey)
//     let (data, response) = try await client.request(
//         method: "POST",
//         path: "/v1/chat/completions",
//         headers: ["Authorization": "Bearer \(apiKey)"],
//         body: requestBody
//     )
//

import Foundation

// Re-export all public types
@_exported import struct Foundation.Data
