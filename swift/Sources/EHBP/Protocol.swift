import Foundation

/// Protocol constants for EHBP (Encrypted HTTP Body Protocol)
public enum EHBPProtocol {
    /// Header name for the encapsulated HPKE key
    public static let encapsulatedKeyHeader = "Ehbp-Encapsulated-Key"

    /// Header name for the response nonce
    public static let responseNonceHeader = "Ehbp-Response-Nonce"

    /// Media type for HPKE key configuration
    public static let keysMediaType = "application/ohttp-keys"

    /// Well-known path for HPKE keys endpoint
    public static let keysPath = "/.well-known/hpke-keys"
}

/// HPKE suite configuration matching the Go implementation
public enum HPKEConfig {
    /// KEM: X25519 HKDF SHA256 (0x0020)
    public static let kem: UInt16 = 0x0020

    /// KDF: HKDF SHA256 (0x0001)
    public static let kdf: UInt16 = 0x0001

    /// AEAD: AES-256-GCM (0x0002)
    public static let aead: UInt16 = 0x0002
}

/// Cryptographic constants
public enum EHBPConstants {
    /// Info string for HPKE sender/receiver setup
    public static let hpkeRequestInfo = "ehbp request"

    /// Context string for HPKE Export
    public static let exportLabel = "ehbp response"

    /// Length of the exported secret (Nk for AES-256)
    public static let exportLength = 32

    /// Length of the random response nonce: max(Nn, Nk) = max(12, 32) = 32
    public static let responseNonceLength = 32

    /// AES-256 key length
    public static let aes256KeyLength = 32

    /// AES-GCM nonce length
    public static let aesGCMNonceLength = 12

    /// X25519 encapsulated key length
    public static let requestEncLength = 32

    /// Label for deriving response key
    public static let responseKeyLabel = "key"

    /// Label for deriving response nonce
    public static let responseNonceLabel = "nonce"

    /// Maximum allowed encrypted chunk size (1 MB).
    /// The write side uses small chunks; this limit provides headroom while
    /// preventing a malicious peer from triggering a multi-GB allocation.
    public static let maxChunkLength = 1 << 20
}
