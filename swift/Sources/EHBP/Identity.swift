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

/// Serializable token for decrypting a response without a live HPKE context
public struct SessionRecoveryToken: Sendable, Codable {
    public let exportedSecret: Data
    public let requestEnc: Data

    public init(exportedSecret: Data, requestEnc: Data) {
        self.exportedSecret = exportedSecret
        self.requestEnc = requestEnc
    }

    enum CodingKeys: String, CodingKey {
        case exportedSecret
        case requestEnc
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(exportedSecret.hexString, forKey: .exportedSecret)
        try container.encode(requestEnc.hexString, forKey: .requestEnc)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let exportedSecretHex = try container.decode(String.self, forKey: .exportedSecret)
        guard let exportedSecretData = Data(hexString: exportedSecretHex),
              exportedSecretData.count == EHBPConstants.exportLength else {
            throw DecodingError.dataCorruptedError(
                forKey: .exportedSecret,
                in: container,
                debugDescription: "invalid exportedSecret hex"
            )
        }
        self.exportedSecret = exportedSecretData

        let requestEncHex = try container.decode(String.self, forKey: .requestEnc)
        guard let requestEncData = Data(hexString: requestEncHex),
              requestEncData.count == EHBPConstants.requestEncLength else {
            throw DecodingError.dataCorruptedError(
                forKey: .requestEnc,
                in: container,
                debugDescription: "invalid requestEnc hex"
            )
        }
        self.requestEnc = requestEncData
    }

    /// Parses the SPEC 6.1.1 JSON form; any malformation is `EHBPError` with code `.invalidToken`.
    public init(json: Data) throws {
        do {
            self = try JSONDecoder().decode(SessionRecoveryToken.self, from: json)
        } catch let error as DecodingError {
            throw EHBPError(.invalidToken, "invalid session recovery token: \(error.brief)")
        } catch {
            throw EHBPError(.invalidToken, "invalid session recovery token: \(error)")
        }
    }

    /// Creates an incremental authenticated decryptor for this response.
    public func makeResponseDecryptor(
        responseNonce: Data,
        maxChunkLength: Int = EHBPConstants.maxResponseChunkBytes
    ) throws -> ResponseDecryptor {
        guard maxChunkLength > 0 else {
            throw EHBPError(.invalidInput, "maximum chunk length must be positive")
        }
        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )
        return ResponseDecryptor(
            keyMaterial: keyMaterial,
            maxChunkLength: maxChunkLength
        )
    }
}

/// Extracts a session recovery token from an HPKE request context
public func extractSessionRecoveryToken(context: RequestContext) throws -> SessionRecoveryToken {
    let exportLabel = Data(EHBPConstants.exportLabel.utf8)
    let exportedSecret = try context.sender.exportSecret(
        context: exportLabel,
        outputByteCount: EHBPConstants.exportLength
    )

    return SessionRecoveryToken(
        exportedSecret: exportedSecret.withUnsafeBytes { Data($0) },
        requestEnc: context.requestEnc
    )
}

/// Decrypts a response body using a session recovery token
public func decryptResponseBody(
    token: SessionRecoveryToken,
    responseNonce: Data,
    encryptedData: Data
) throws -> Data {
    var decryptor = try token.makeResponseDecryptor(responseNonce: responseNonce)
    var result = Data()
    for plaintext in try decryptor.push(encryptedData) {
        result.append(plaintext)
    }
    try decryptor.finish()
    return result
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
            throw EHBPError(.invalidKeyConfig, "public key must be 32 bytes, got \(publicKeyBytes.count)")
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
            throw EHBPError(.invalidKeyConfig, "invalid public key hex")
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
            throw EHBPError(.invalidKeyConfig, "config too short")
        }

        var offset = 0

        // Key ID (1 byte) - skip
        offset += 1

        // KEM ID (2 bytes, big-endian)
        let kemId = UInt16(config[offset]) << 8 | UInt16(config[offset + 1])
        offset += 2

        guard kemId == HPKEConfig.kem else {
            throw EHBPError(.unsupportedSuite, "unsupported KEM: 0x\(String(kemId, radix: 16))")
        }

        // Public Key (32 bytes for X25519)
        let publicKeySize = 32
        guard config.count >= offset + publicKeySize else {
            throw EHBPError(.invalidKeyConfig, "config too short for public key")
        }

        let publicKeyBytes = config.subdata(in: offset..<(offset + publicKeySize))
        offset += publicKeySize

        // Cipher Suites Length (2 bytes)
        guard config.count >= offset + 2 else {
            throw EHBPError(.invalidKeyConfig, "config too short for cipher suites length")
        }

        let cipherSuitesLength = Int(config[offset]) << 8 | Int(config[offset + 1])
        offset += 2

        // Parse first cipher suite
        guard cipherSuitesLength >= 4, config.count >= offset + 4 else {
            throw EHBPError(.invalidKeyConfig, "no cipher suites in config")
        }

        let kdfId = UInt16(config[offset]) << 8 | UInt16(config[offset + 1])
        let aeadId = UInt16(config[offset + 2]) << 8 | UInt16(config[offset + 3])

        guard kdfId == HPKEConfig.kdf else {
            throw EHBPError(.unsupportedSuite, "unsupported KDF: 0x\(String(kdfId, radix: 16))")
        }
        guard aeadId == HPKEConfig.aead else {
            throw EHBPError(.unsupportedSuite, "unsupported AEAD: 0x\(String(aeadId, radix: 16))")
        }

        self.publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyBytes)
        self.ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )
    }

    /// Encrypts a request body as a sequence of framed chunks (SPEC 4.3).
    /// Large bodies produce several frames; see `makeRequestEncryptor()` for
    /// the incremental form.
    public func encryptRequest(body: Data) throws -> (encryptedBody: Data, context: RequestContext) {
        let encryptor = try makeRequestEncryptor()
        var framed = Data()
        var offset = 0
        while offset < body.count {
            let end = min(offset + RequestEncryptor.frameSize, body.count)
            framed.append(try encryptor.seal(body[offset..<end]))
            offset = end
        }
        return (framed, encryptor.context)
    }

    /// Sets up the HPKE sender once; each `seal` call then yields one framed
    /// chunk, so a body of any size streams with memory bounded by the frame.
    public func makeRequestEncryptor() throws -> RequestEncryptor {
        let sender = try HPKE.Sender(
            recipientKey: publicKey,
            ciphersuite: ciphersuite,
            info: Data(EHBPConstants.hpkeRequestInfo.utf8)
        )
        return RequestEncryptor(sender: sender)
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
        let token = try extractSessionRecoveryToken(context: context)

        return try EHBP.deriveResponseKeys(
            exportedSecret: token.exportedSecret,
            requestEnc: token.requestEnc,
            responseNonce: responseNonce
        )
    }
}

private extension DecodingError {
    /// One-line cause without Foundation's debug dump.
    var brief: String {
        switch self {
        case .keyNotFound(let key, _):
            return "missing \(key.stringValue)"
        case .dataCorrupted(let context):
            return context.debugDescription
        case .typeMismatch(_, let context), .valueNotFound(_, let context):
            let path = context.codingPath.map(\.stringValue).joined(separator: ".")
            return path.isEmpty ? "expected JSON object" : "wrong type for \(path)"
        @unknown default:
            return String(describing: self)
        }
    }
}

/// Incremental request encryptor: one HPKE sender, one framed chunk per `seal`.
public final class RequestEncryptor {
    /// Plaintext bytes per frame; well under the 64 MiB receiver bound.
    public static let frameSize = 64 * 1024

    private var sender: HPKE.Sender
    /// Available before any chunk is sealed, so the session recovery token
    /// can be persisted ahead of the upload.
    public let context: RequestContext

    init(sender: HPKE.Sender) {
        self.sender = sender
        self.context = RequestContext(sender: sender, requestEnc: sender.encapsulatedKey)
    }

    /// Seals one plaintext chunk (split into `frameSize` frames if larger)
    /// and returns the framed ciphertext: LEN(4, big-endian) || CIPHERTEXT per frame.
    public func seal(_ plaintext: Data) throws -> Data {
        var out = Data()
        var offset = plaintext.startIndex
        repeat {
            let end = min(offset + RequestEncryptor.frameSize, plaintext.endIndex)
            let encrypted = try sender.seal(plaintext[offset..<end])
            var length = UInt32(encrypted.count).bigEndian
            out.append(Data(bytes: &length, count: 4))
            out.append(encrypted)
            offset = end
        } while offset < plaintext.endIndex
        return out
    }
}
