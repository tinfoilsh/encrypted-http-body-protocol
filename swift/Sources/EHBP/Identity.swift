import Foundation
import Crypto

/// Context retained after encrypting a request, used to derive response keys (SPEC Section 4.4)
public struct RequestContext: Sendable {
    /// HPKE sender for exporting the shared secret
    public let sender: HPKE.Sender

    /// Encapsulated key sent in Ehbp-Encapsulated-Key header
    public let requestEnc: Data

    public init(sender: HPKE.Sender, requestEnc: Data) {
        self.sender = sender
        self.requestEnc = requestEnc
    }
}

/// Client identity for EHBP encryption/decryption (SPEC Section 5.1)
public final class Identity: Sendable {
    private let publicKey: Curve25519.KeyAgreement.PublicKey
    private let ciphersuite: HPKE.Ciphersuite

    /// Creates an Identity from a server's raw public key bytes
    ///
    /// - Parameter publicKeyBytes: 32-byte X25519 public key
    public init(publicKeyBytes: Data) throws {
        guard publicKeyBytes.count == 32 else {
            throw EHBPError.invalidInput("public key must be 32 bytes, got \(publicKeyBytes.count)")
        }

        self.publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyBytes)
        self.ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )
    }

    /// Creates an Identity from a hex-encoded public key string.
    ///
    /// This is used by clients who already have the server's public key
    /// and don't need to fetch it.
    ///
    /// - Parameter publicKeyHex: 64-character hex string representing a 32-byte X25519 public key
    public convenience init(publicKeyHex: String) throws {
        guard let publicKeyBytes = Data(hexString: publicKeyHex) else {
            throw EHBPError.invalidInput("invalid hex string")
        }
        try self.init(publicKeyBytes: publicKeyBytes)
    }

    /// Creates an Identity from an RFC 9458 key configuration
    ///
    /// Format:
    /// - Key ID (1 byte)
    /// - KEM ID (2 bytes, big-endian)
    /// - Public Key (32 bytes for X25519)
    /// - Cipher Suites Length (2 bytes, big-endian)
    /// - For each cipher suite:
    ///   - KDF ID (2 bytes)
    ///   - AEAD ID (2 bytes)
    ///
    /// - Parameter config: RFC 9458 key configuration data
    public init(config: Data) throws {
        guard config.count >= 7 else {
            throw EHBPError.invalidInput("config too short")
        }

        var offset = 0

        // Key ID (1 byte) - skip
        offset += 1

        // KEM ID (2 bytes, big-endian)
        let kemId = UInt16(config[offset]) << 8 | UInt16(config[offset + 1])
        offset += 2

        guard kemId == HPKEConfig.kem else {
            throw EHBPError.invalidInput("unsupported KEM: 0x\(String(kemId, radix: 16))")
        }

        // Public Key (32 bytes for X25519)
        let publicKeySize = 32
        guard config.count >= offset + publicKeySize else {
            throw EHBPError.invalidInput("config too short for public key")
        }

        let publicKeyBytes = config.subdata(in: offset..<(offset + publicKeySize))
        offset += publicKeySize

        // Cipher Suites Length (2 bytes)
        guard config.count >= offset + 2 else {
            throw EHBPError.invalidInput("config too short for cipher suites length")
        }

        let cipherSuitesLength = Int(config[offset]) << 8 | Int(config[offset + 1])
        offset += 2

        // Parse first cipher suite
        guard cipherSuitesLength >= 4, config.count >= offset + 4 else {
            throw EHBPError.invalidInput("no cipher suites in config")
        }

        let kdfId = UInt16(config[offset]) << 8 | UInt16(config[offset + 1])
        let aeadId = UInt16(config[offset + 2]) << 8 | UInt16(config[offset + 3])

        guard kdfId == HPKEConfig.kdf else {
            throw EHBPError.invalidInput("unsupported KDF: 0x\(String(kdfId, radix: 16))")
        }
        guard aeadId == HPKEConfig.aead else {
            throw EHBPError.invalidInput("unsupported AEAD: 0x\(String(aeadId, radix: 16))")
        }

        self.publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyBytes)
        self.ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )
    }

    /// Encrypts request body and returns context for response decryption (SPEC Section 5.1)
    ///
    /// - Parameter body: Request body to encrypt
    /// - Returns: Encrypted body with chunk framing, and context needed to decrypt the response
    public func encryptRequest(body: Data) throws -> (encryptedBody: Data, context: RequestContext) {
        let info = Data(EHBPConstants.hpkeRequestInfo.utf8)

        var sender = try HPKE.Sender(
            recipientKey: publicKey,
            ciphersuite: ciphersuite,
            info: info
        )

        let encapsulatedKey = sender.encapsulatedKey
        let encrypted = try sender.seal(body)

        // Frame as: LEN (4 bytes big-endian) || ciphertext
        var chunkedData = Data()
        var length = UInt32(encrypted.count).bigEndian
        chunkedData.append(Data(bytes: &length, count: 4))
        chunkedData.append(encrypted)

        let context = RequestContext(
            sender: sender,
            requestEnc: encapsulatedKey
        )

        return (chunkedData, context)
    }

    /// Derives response decryption keys using OHTTP-style derivation (SPEC Section 4.4.1)
    ///
    /// - Parameters:
    ///   - context: Request context from encryptRequest
    ///   - responseNonce: 32 bytes from Ehbp-Response-Nonce header
    /// - Returns: Key material for decrypting response chunks
    public func deriveResponseKeys(
        context: RequestContext,
        responseNonce: Data
    ) throws -> ResponseKeyMaterial {
        let exportLabel = Data(EHBPConstants.exportLabel.utf8)

        let exportedSecret = try context.sender.exportSecret(
            context: exportLabel,
            outputByteCount: EHBPConstants.exportLength
        )

        return try EHBP.deriveResponseKeys(
            exportedSecret: exportedSecret.withUnsafeBytes { Data($0) },
            requestEnc: context.requestEnc,
            responseNonce: responseNonce
        )
    }
}
