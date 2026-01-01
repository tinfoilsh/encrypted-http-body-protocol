import Foundation
import Crypto

/// Request context for response decryption.
/// Holds the HPKE sender context needed to derive response keys.
public struct RequestContext: Sendable {
    /// The HPKE sender for exporting secrets
    public let sender: HPKE.Sender

    /// The encapsulated key from the request
    public let requestEnc: Data

    public init(sender: HPKE.Sender, requestEnc: Data) {
        self.sender = sender
        self.requestEnc = requestEnc
    }
}

/// Identity class for managing HPKE encryption/decryption
public final class Identity: Sendable {
    /// The server's public key for encryption
    private let publicKey: Curve25519.KeyAgreement.PublicKey

    /// The HPKE ciphersuite to use
    private let ciphersuite: HPKE.Ciphersuite

    /// Creates an Identity from a server's public key bytes
    ///
    /// - Parameter publicKeyBytes: 32 bytes X25519 public key
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

    /// Encrypts request body and returns context for response decryption.
    ///
    /// This method:
    /// 1. Creates an HPKE sender context to the server's public key
    /// 2. Encrypts the request body
    /// 3. Returns a RequestContext that must be used to decrypt the response
    ///
    /// - Parameter body: Request body to encrypt
    /// - Returns: Tuple of (encrypted body with chunk framing, request context for response decryption)
    public func encryptRequest(body: Data) throws -> (encryptedBody: Data, context: RequestContext) {
        let info = Data(EHBPConstants.hpkeRequestInfo.utf8)

        var sender = try HPKE.Sender(
            recipientKey: publicKey,
            ciphersuite: ciphersuite,
            info: info
        )

        let encapsulatedKey = sender.encapsulatedKey

        // Encrypt the body
        let encrypted = try sender.seal(body)

        // Create chunked format: 4-byte length header + encrypted data
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

    /// Derives response keys from request context and response nonce
    ///
    /// - Parameters:
    ///   - context: Request context from encryptRequest
    ///   - responseNonce: 32 bytes from Ehbp-Response-Nonce header
    /// - Returns: Key material for decrypting response
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
