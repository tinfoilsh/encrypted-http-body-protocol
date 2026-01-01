import Foundation
import Crypto

/// Response key material for encryption/decryption
public struct ResponseKeyMaterial: Sendable {
    /// 32 bytes for AES-256
    public let key: SymmetricKey

    /// 12 bytes, XORed with sequence number for each chunk
    public let nonceBase: Data

    public init(key: SymmetricKey, nonceBase: Data) {
        self.key = key
        self.nonceBase = nonceBase
    }
}

/// Derives response encryption keys from the HPKE exported secret.
///
/// The derivation follows OHTTP (RFC 9458):
/// ```
/// salt = concat(enc, response_nonce)
/// prk = Extract(salt, secret)
/// aead_key = Expand(prk, "key", Nk)
/// aead_nonce = Expand(prk, "nonce", Nn)
/// ```
///
/// - Parameters:
///   - exportedSecret: 32 bytes exported from HPKE context
///   - requestEnc: 32 bytes encapsulated key from request
///   - responseNonce: 32 bytes random nonce from response
/// - Returns: Key material for response encryption/decryption
public func deriveResponseKeys(
    exportedSecret: Data,
    requestEnc: Data,
    responseNonce: Data
) throws -> ResponseKeyMaterial {
    guard exportedSecret.count == EHBPConstants.exportLength else {
        throw EHBPError.invalidInput("exported secret must be \(EHBPConstants.exportLength) bytes, got \(exportedSecret.count)")
    }
    guard requestEnc.count == EHBPConstants.requestEncLength else {
        throw EHBPError.invalidInput("request enc must be \(EHBPConstants.requestEncLength) bytes, got \(requestEnc.count)")
    }
    guard responseNonce.count == EHBPConstants.responseNonceLength else {
        throw EHBPError.invalidInput("response nonce must be \(EHBPConstants.responseNonceLength) bytes, got \(responseNonce.count)")
    }

    // salt = concat(enc, response_nonce)
    var salt = Data()
    salt.append(requestEnc)
    salt.append(responseNonce)

    // prk = Extract(salt, secret)
    let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: exportedSecret), salt: salt)

    // aead_key = Expand(prk, "key", Nk)
    let keyData = HKDF<SHA256>.expand(
        pseudoRandomKey: prk,
        info: Data(EHBPConstants.responseKeyLabel.utf8),
        outputByteCount: EHBPConstants.aes256KeyLength
    )

    // aead_nonce = Expand(prk, "nonce", Nn)
    let nonceBase = HKDF<SHA256>.expand(
        pseudoRandomKey: prk,
        info: Data(EHBPConstants.responseNonceLabel.utf8),
        outputByteCount: EHBPConstants.aesGCMNonceLength
    )

    return ResponseKeyMaterial(
        key: keyData,
        nonceBase: nonceBase.withUnsafeBytes { Data($0) }
    )
}

/// Computes the nonce for a specific sequence number.
/// nonce = nonceBase XOR sequence_number (big-endian in last 8 bytes)
///
/// - Parameters:
///   - nonceBase: 12 bytes base nonce
///   - seq: Sequence number (0-indexed)
/// - Returns: 12 bytes nonce for this sequence
public func computeNonce(nonceBase: Data, seq: UInt64) -> Data {
    var nonce = Data(nonceBase)

    // XOR with sequence number in the last 8 bytes (big-endian)
    for i in 0..<8 {
        let shift = i * 8
        let byteIndex = EHBPConstants.aesGCMNonceLength - 1 - i
        nonce[byteIndex] ^= UInt8((seq >> shift) & 0xFF)
    }

    return nonce
}

/// Encrypts a chunk using the response key material
///
/// - Parameters:
///   - keyMaterial: Response key material
///   - seq: Sequence number for this chunk
///   - plaintext: Data to encrypt
/// - Returns: Encrypted ciphertext with authentication tag
public func encryptChunk(
    keyMaterial: ResponseKeyMaterial,
    seq: UInt64,
    plaintext: Data
) throws -> Data {
    let nonce = computeNonce(nonceBase: keyMaterial.nonceBase, seq: seq)

    let sealedBox = try AES.GCM.seal(
        plaintext,
        using: keyMaterial.key,
        nonce: try AES.GCM.Nonce(data: nonce)
    )

    return sealedBox.ciphertext + sealedBox.tag
}

/// Decrypts a chunk using the response key material
///
/// - Parameters:
///   - keyMaterial: Response key material
///   - seq: Sequence number for this chunk
///   - ciphertext: Encrypted data with authentication tag
/// - Returns: Decrypted plaintext
public func decryptChunk(
    keyMaterial: ResponseKeyMaterial,
    seq: UInt64,
    ciphertext: Data
) throws -> Data {
    let nonce = computeNonce(nonceBase: keyMaterial.nonceBase, seq: seq)

    guard ciphertext.count >= 16 else {
        throw EHBPError.decryptionFailed("ciphertext too short")
    }

    let tagStart = ciphertext.count - 16
    let encryptedData = ciphertext.prefix(tagStart)
    let tag = ciphertext.suffix(16)

    let sealedBox = try AES.GCM.SealedBox(
        nonce: try AES.GCM.Nonce(data: nonce),
        ciphertext: encryptedData,
        tag: tag
    )

    return try AES.GCM.open(sealedBox, using: keyMaterial.key)
}

/// EHBP errors
public enum EHBPError: Error, LocalizedError {
    case invalidInput(String)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case networkError(String)
    case invalidResponse(String)
    case missingHeader(String)

    public var errorDescription: String? {
        switch self {
        case .invalidInput(let msg): return "Invalid input: \(msg)"
        case .encryptionFailed(let msg): return "Encryption failed: \(msg)"
        case .decryptionFailed(let msg): return "Decryption failed: \(msg)"
        case .networkError(let msg): return "Network error: \(msg)"
        case .invalidResponse(let msg): return "Invalid response: \(msg)"
        case .missingHeader(let msg): return "Missing header: \(msg)"
        }
    }
}
