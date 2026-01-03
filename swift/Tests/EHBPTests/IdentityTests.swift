import XCTest
import Crypto
@testable import EHBP

final class IdentityTests: XCTestCase {

    // MARK: - Identity Creation Tests

    func testIdentityFromPublicKeyCanEncrypt() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKeyBytes = privateKey.publicKey.rawRepresentation

        let identity = try Identity(publicKeyBytes: Data(publicKeyBytes))

        // Verify the identity can actually encrypt data
        let plaintext = Data("test message".utf8)
        let (encrypted, context) = try identity.encryptRequest(body: plaintext)

        // Encrypted output should have length prefix + ciphertext + tag
        XCTAssertGreaterThan(encrypted.count, plaintext.count)
        XCTAssertEqual(context.requestEnc.count, 32)
    }

    func testIdentityFromInvalidPublicKey() {
        // Too short
        XCTAssertThrowsError(try Identity(publicKeyBytes: Data(repeating: 0, count: 16))) { error in
            XCTAssertTrue(error is EHBPError)
        }

        // Too long
        XCTAssertThrowsError(try Identity(publicKeyBytes: Data(repeating: 0, count: 64))) { error in
            XCTAssertTrue(error is EHBPError)
        }

        // Empty
        XCTAssertThrowsError(try Identity(publicKeyBytes: Data())) { error in
            XCTAssertTrue(error is EHBPError)
        }
    }

    // MARK: - RFC 9458 Config Parsing Tests

    func testIdentityFromConfigCanEncrypt() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKeyBytes = privateKey.publicKey.rawRepresentation

        // Build RFC 9458 config
        var config = Data()

        // Key ID (1 byte)
        config.append(0)

        // KEM ID (2 bytes, big-endian) - X25519
        config.append(0x00)
        config.append(0x20)

        // Public Key (32 bytes)
        config.append(contentsOf: publicKeyBytes)

        // Cipher Suites Length (2 bytes) - 4 bytes for one suite
        config.append(0x00)
        config.append(0x04)

        // KDF ID (2 bytes) - HKDF-SHA256
        config.append(0x00)
        config.append(0x01)

        // AEAD ID (2 bytes) - AES-256-GCM
        config.append(0x00)
        config.append(0x02)

        let identity = try Identity(config: config)

        // Verify the parsed identity can encrypt (proves config was parsed correctly)
        let plaintext = Data("test".utf8)
        let (encrypted, context) = try identity.encryptRequest(body: plaintext)
        XCTAssertGreaterThan(encrypted.count, 4)
        XCTAssertEqual(context.requestEnc.count, 32)
    }

    func testIdentityFromConfigWithWrongKEM() {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKeyBytes = privateKey.publicKey.rawRepresentation

        var config = Data()
        config.append(0) // Key ID
        config.append(0x00)
        config.append(0x10) // Wrong KEM ID (P-256 instead of X25519)
        config.append(contentsOf: publicKeyBytes)
        config.append(0x00)
        config.append(0x04)
        config.append(0x00)
        config.append(0x01)
        config.append(0x00)
        config.append(0x02)

        XCTAssertThrowsError(try Identity(config: config)) { error in
            if let ehbpError = error as? EHBPError {
                XCTAssertTrue("\(ehbpError)".contains("KEM"))
            }
        }
    }

    func testIdentityFromConfigWithWrongKDF() {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKeyBytes = privateKey.publicKey.rawRepresentation

        var config = Data()
        config.append(0) // Key ID
        config.append(0x00)
        config.append(0x20) // Correct KEM
        config.append(contentsOf: publicKeyBytes)
        config.append(0x00)
        config.append(0x04)
        config.append(0x00)
        config.append(0x02) // Wrong KDF ID
        config.append(0x00)
        config.append(0x02)

        XCTAssertThrowsError(try Identity(config: config)) { error in
            if let ehbpError = error as? EHBPError {
                XCTAssertTrue("\(ehbpError)".contains("KDF"))
            }
        }
    }

    func testIdentityFromConfigWithWrongAEAD() {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKeyBytes = privateKey.publicKey.rawRepresentation

        var config = Data()
        config.append(0) // Key ID
        config.append(0x00)
        config.append(0x20) // Correct KEM
        config.append(contentsOf: publicKeyBytes)
        config.append(0x00)
        config.append(0x04)
        config.append(0x00)
        config.append(0x01) // Correct KDF
        config.append(0x00)
        config.append(0x01) // Wrong AEAD ID (AES-128-GCM instead of AES-256-GCM)

        XCTAssertThrowsError(try Identity(config: config)) { error in
            if let ehbpError = error as? EHBPError {
                XCTAssertTrue("\(ehbpError)".contains("AEAD"))
            }
        }
    }

    func testIdentityFromTruncatedConfig() {
        // Too short to contain header
        XCTAssertThrowsError(try Identity(config: Data([0, 1, 2])))

        // Too short for public key
        var config = Data()
        config.append(0) // Key ID
        config.append(0x00)
        config.append(0x20) // KEM
        config.append(contentsOf: Data(repeating: 0, count: 16)) // Only 16 bytes, need 32

        XCTAssertThrowsError(try Identity(config: config))
    }

    // MARK: - Request Encryption Tests

    func testEncryptRequestCanBeDecryptedByServer() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKeyBytes = Data(serverPrivateKey.publicKey.rawRepresentation)

        let identity = try Identity(publicKeyBytes: serverPublicKeyBytes)

        let plaintext = Data("Hello, EHBP!".utf8)
        let (encryptedBody, context) = try identity.encryptRequest(body: plaintext)

        // Verify framing structure
        let length = Int(encryptedBody[0]) << 24 |
                     Int(encryptedBody[1]) << 16 |
                     Int(encryptedBody[2]) << 8 |
                     Int(encryptedBody[3])
        XCTAssertEqual(length, encryptedBody.count - 4)
        XCTAssertEqual(context.requestEnc.count, 32)

        // Simulate server decryption using HPKE.Recipient
        let ciphertext = encryptedBody.suffix(from: 4)
        let ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )

        var recipient = try HPKE.Recipient(
            privateKey: serverPrivateKey,
            ciphersuite: ciphersuite,
            info: Data(EHBPConstants.hpkeRequestInfo.utf8),
            encapsulatedKey: context.requestEnc
        )

        let decrypted = try recipient.open(ciphertext)
        XCTAssertEqual(decrypted, plaintext, "Server should be able to decrypt client's request")
    }

    func testEncryptRequestProducesDifferentOutputsEachTime() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKeyBytes = Data(serverPrivateKey.publicKey.rawRepresentation)

        let identity = try Identity(publicKeyBytes: serverPublicKeyBytes)

        let plaintext = Data("Same message".utf8)

        let (encrypted1, context1) = try identity.encryptRequest(body: plaintext)
        let (encrypted2, context2) = try identity.encryptRequest(body: plaintext)

        // Each encryption should use a new ephemeral key
        XCTAssertNotEqual(context1.requestEnc, context2.requestEnc, "Each request should have unique enc")
        XCTAssertNotEqual(encrypted1, encrypted2, "Ciphertexts should be different")
    }

    func testEncryptEmptyRequest() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKeyBytes = Data(serverPrivateKey.publicKey.rawRepresentation)

        let identity = try Identity(publicKeyBytes: serverPublicKeyBytes)

        let (encryptedBody, context) = try identity.encryptRequest(body: Data())

        // Should still produce valid output with just the tag
        XCTAssertGreaterThan(encryptedBody.count, 4)
        XCTAssertEqual(context.requestEnc.count, 32)
    }

    func testEncryptLargeRequest() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKeyBytes = Data(serverPrivateKey.publicKey.rawRepresentation)

        let identity = try Identity(publicKeyBytes: serverPublicKeyBytes)

        // 1MB of data
        let plaintext = Data(repeating: 0xAB, count: 1024 * 1024)
        let (encryptedBody, context) = try identity.encryptRequest(body: plaintext)

        // Verify structure
        let length = Int(encryptedBody[0]) << 24 |
                     Int(encryptedBody[1]) << 16 |
                     Int(encryptedBody[2]) << 8 |
                     Int(encryptedBody[3])
        XCTAssertEqual(length, encryptedBody.count - 4)
        XCTAssertEqual(context.requestEnc.count, 32)
    }

    // MARK: - Response Key Derivation Tests

    func testDeriveResponseKeysFromContext() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKeyBytes = Data(serverPrivateKey.publicKey.rawRepresentation)

        let identity = try Identity(publicKeyBytes: serverPublicKeyBytes)

        let plaintext = Data("Hello, EHBP!".utf8)
        let (_, context) = try identity.encryptRequest(body: plaintext)

        var responseNonce = Data(count: 32)
        _ = responseNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let keyMaterial = try identity.deriveResponseKeys(context: context, responseNonce: responseNonce)

        // Key should be 32 bytes (256 bits)
        XCTAssertEqual(keyMaterial.key.bitCount, 256)

        // Nonce base should be 12 bytes
        XCTAssertEqual(keyMaterial.nonceBase.count, 12)
    }

    func testDeriveResponseKeysWithInvalidNonce() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKeyBytes = Data(serverPrivateKey.publicKey.rawRepresentation)

        let identity = try Identity(publicKeyBytes: serverPublicKeyBytes)

        let (_, context) = try identity.encryptRequest(body: Data("test".utf8))

        // Wrong nonce length
        let shortNonce = Data(repeating: 0, count: 16)
        XCTAssertThrowsError(try identity.deriveResponseKeys(context: context, responseNonce: shortNonce))
    }

    func testDeriveResponseKeysDeterminism() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKeyBytes = Data(serverPrivateKey.publicKey.rawRepresentation)

        let identity = try Identity(publicKeyBytes: serverPublicKeyBytes)

        let (_, context) = try identity.encryptRequest(body: Data("test".utf8))

        var responseNonce = Data(count: 32)
        _ = responseNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let km1 = try identity.deriveResponseKeys(context: context, responseNonce: responseNonce)
        let km2 = try identity.deriveResponseKeys(context: context, responseNonce: responseNonce)

        // Same context + nonce should produce same keys
        XCTAssertEqual(km1.nonceBase, km2.nonceBase)
    }

    func testDifferentNoncesProduceDifferentKeys() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKeyBytes = Data(serverPrivateKey.publicKey.rawRepresentation)

        let identity = try Identity(publicKeyBytes: serverPublicKeyBytes)

        let (_, context) = try identity.encryptRequest(body: Data("test".utf8))

        var nonce1 = Data(count: 32)
        _ = nonce1.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        var nonce2 = Data(count: 32)
        _ = nonce2.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let km1 = try identity.deriveResponseKeys(context: context, responseNonce: nonce1)
        let km2 = try identity.deriveResponseKeys(context: context, responseNonce: nonce2)

        XCTAssertNotEqual(km1.nonceBase, km2.nonceBase)
    }
}
