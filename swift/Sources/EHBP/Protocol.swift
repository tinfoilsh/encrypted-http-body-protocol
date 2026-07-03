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

    /// Maximum size of a single framed response chunk the client will buffer
    /// (64 MiB). Bounds memory from an attacker-controlled length prefix.
    public static let maxResponseChunkBytes = 64 * 1024 * 1024
}

/// Constants for encrypted WebSocket channels (EHBP-WS, SPEC Section 8)
public enum NoiseWebSocketProtocol {
    /// WebSocket subprotocol identifying EHBP-WS
    public static let subprotocol = "ehbp.noise.v1"

    /// Noise protocol name for the handshake
    public static let protocolName = "Noise_NK_25519_AESGCM_SHA256"

    /// Prologue domain-separates the Noise handshake from other uses of the
    /// server's X25519 key, since the HPKE identity key is reused as the
    /// Noise static key. Both peers must use the identical value.
    public static let prologue = "ehbp noise websocket v1"

    /// Record type byte for application data
    public static let recordData: UInt8 = 0x01

    /// Record type byte for authenticated termination
    public static let recordClose: UInt8 = 0x02

    /// Default cap on a single record payload (1 MiB)
    public static let defaultMaxMessageSize = 1 << 20

    /// Framing added to a record payload: 1 record type byte, a 16-byte
    /// AEAD tag, and margin for WebSocket read limit accounting.
    public static let recordOverhead = 64

    /// Bounds WebSocket messages during the handshake. Noise NK handshake
    /// messages are 48 bytes each.
    public static let handshakeReadLimit = 4096

    /// Number of records after which each direction's cipher state is
    /// rekeyed. The schedule is deterministic so both peers stay in sync.
    public static let rekeyInterval: UInt64 = 1 << 16
}
