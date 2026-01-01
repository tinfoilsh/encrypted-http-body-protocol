import XCTest
import Crypto
@testable import EHBP

final class DeriveTests: XCTestCase {

    // MARK: - Nonce Computation Tests

    func testComputeNonce() {
        let nonceBase = Data(repeating: 0, count: 12)

        // seq 0 should return nonceBase unchanged
        let nonce0 = computeNonce(nonceBase: nonceBase, seq: 0)
        XCTAssertEqual(nonce0, nonceBase)

        // seq 1 should XOR 1 into last byte
        let nonce1 = computeNonce(nonceBase: nonceBase, seq: 1)
        var expected1 = Data(repeating: 0, count: 12)
        expected1[11] = 1
        XCTAssertEqual(nonce1, expected1)

        // seq 256 should XOR into second-to-last byte
        let nonce256 = computeNonce(nonceBase: nonceBase, seq: 256)
        var expected256 = Data(repeating: 0, count: 12)
        expected256[10] = 1
        XCTAssertEqual(nonce256, expected256)
    }

    func testComputeNonceWithNonZeroBase() {
        let nonceBase = Data(repeating: 0xFF, count: 12)

        // seq 0 should return nonceBase unchanged
        let nonce0 = computeNonce(nonceBase: nonceBase, seq: 0)
        XCTAssertEqual(nonce0, nonceBase)

        // seq 1 should XOR 1 into last byte (0xFF XOR 0x01 = 0xFE)
        let nonce1 = computeNonce(nonceBase: nonceBase, seq: 1)
        var expected1 = Data(repeating: 0xFF, count: 12)
        expected1[11] = 0xFE
        XCTAssertEqual(nonce1, expected1)

        // Verify first 4 bytes are unchanged for small sequence numbers
        for i in 0..<4 {
            XCTAssertEqual(nonce1[i], 0xFF, "Byte \(i) should be 0xFF for seq=1")
        }
    }

    func testNonceUniquenessFor1000Sequences() {
        let nonceBase = Data(repeating: 0, count: 12)
        var seen = Set<Data>()

        for i in 0..<1000 {
            let nonce = computeNonce(nonceBase: nonceBase, seq: UInt64(i))
            XCTAssertFalse(seen.contains(nonce), "Duplicate nonce at sequence \(i)")
            seen.insert(nonce)
        }
    }

    func testNonceLargeSequence() {
        let nonceBase = Data(repeating: 0, count: 12)

        // Test with a large sequence number that uses multiple bytes
        let seq: UInt64 = 0x0102030405060708
        let nonce = computeNonce(nonceBase: nonceBase, seq: seq)

        // Verify XOR was applied correctly to last 8 bytes
        let expected = Data([0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        XCTAssertEqual(nonce, expected, "Large sequence nonce incorrect")
    }

    // MARK: - Key Derivation Tests

    func testDeriveResponseKeysValidation() {
        // Test with invalid lengths
        XCTAssertThrowsError(try deriveResponseKeys(
            exportedSecret: Data(repeating: 0, count: 16), // wrong size
            requestEnc: Data(repeating: 0, count: 32),
            responseNonce: Data(repeating: 0, count: 32)
        ))

        XCTAssertThrowsError(try deriveResponseKeys(
            exportedSecret: Data(repeating: 0, count: 32),
            requestEnc: Data(repeating: 0, count: 16), // wrong size
            responseNonce: Data(repeating: 0, count: 32)
        ))

        XCTAssertThrowsError(try deriveResponseKeys(
            exportedSecret: Data(repeating: 0, count: 32),
            requestEnc: Data(repeating: 0, count: 32),
            responseNonce: Data(repeating: 0, count: 16) // wrong size
        ))
    }

    func testDeriveResponseKeysSuccess() throws {
        let exportedSecret = Data(repeating: 0xAB, count: 32)
        let requestEnc = Data(repeating: 0xCD, count: 32)
        let responseNonce = Data(repeating: 0xEF, count: 32)

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        // Key should be 32 bytes (256 bits)
        XCTAssertEqual(keyMaterial.key.bitCount, 256)

        // Nonce base should be 12 bytes
        XCTAssertEqual(keyMaterial.nonceBase.count, 12)
    }

    func testDeriveResponseKeysDeterminism() throws {
        // Test vectors with sequential byte values for reproducibility
        var exportedSecret = Data(count: 32)
        for i in 0..<32 { exportedSecret[i] = UInt8(i) }

        var requestEnc = Data(count: 32)
        for i in 0..<32 { requestEnc[i] = UInt8(i + 32) }

        var responseNonce = Data(count: 32)
        for i in 0..<32 { responseNonce[i] = UInt8(i + 64) }

        let km1 = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        let km2 = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        // Same inputs should produce same outputs
        XCTAssertEqual(km1.nonceBase, km2.nonceBase, "Nonce base derivation is not deterministic")
    }

    func testDifferentInputsProduceDifferentKeys() throws {
        let exportedSecret = Data(repeating: 0x01, count: 32)
        let requestEnc = Data(repeating: 0x02, count: 32)
        let responseNonce1 = Data(repeating: 0x03, count: 32)
        var responseNonce2 = Data(repeating: 0x03, count: 32)
        responseNonce2[0] = 0xFF

        let km1 = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce1
        )

        let km2 = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce2
        )

        XCTAssertNotEqual(km1.nonceBase, km2.nonceBase, "Different nonces should produce different nonce bases")
    }

    func testDifferentRequestEncProducesDifferentKeys() throws {
        let exportedSecret = Data(repeating: 0x01, count: 32)
        let requestEnc1 = Data(repeating: 0x02, count: 32)
        var requestEnc2 = Data(repeating: 0x02, count: 32)
        requestEnc2[0] = 0xFF
        let responseNonce = Data(repeating: 0x03, count: 32)

        let km1 = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc1,
            responseNonce: responseNonce
        )

        let km2 = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc2,
            responseNonce: responseNonce
        )

        XCTAssertNotEqual(km1.nonceBase, km2.nonceBase, "Different request enc should produce different keys")
    }

    func testDifferentSecretProducesDifferentKeys() throws {
        let exportedSecret1 = Data(repeating: 0x01, count: 32)
        var exportedSecret2 = Data(repeating: 0x01, count: 32)
        exportedSecret2[0] = 0xFF
        let requestEnc = Data(repeating: 0x02, count: 32)
        let responseNonce = Data(repeating: 0x03, count: 32)

        let km1 = try deriveResponseKeys(
            exportedSecret: exportedSecret1,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        let km2 = try deriveResponseKeys(
            exportedSecret: exportedSecret2,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        XCTAssertNotEqual(km1.nonceBase, km2.nonceBase, "Different exported secret should produce different keys")
    }

    // MARK: - Encrypt/Decrypt Tests

    func testEncryptDecryptChunk() throws {
        let exportedSecret = Data(repeating: 0xAB, count: 32)
        let requestEnc = Data(repeating: 0xCD, count: 32)
        let responseNonce = Data(repeating: 0xEF, count: 32)

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        let plaintext = Data("Hello, EHBP!".utf8)

        // Encrypt
        let ciphertext = try encryptChunk(keyMaterial: keyMaterial, seq: 0, plaintext: plaintext)

        // Ciphertext should be larger (includes auth tag)
        XCTAssertEqual(ciphertext.count, plaintext.count + 16)

        // Decrypt
        let decrypted = try decryptChunk(keyMaterial: keyMaterial, seq: 0, ciphertext: ciphertext)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testDecryptWithWrongSeqFails() throws {
        let exportedSecret = Data(repeating: 0xAB, count: 32)
        let requestEnc = Data(repeating: 0xCD, count: 32)
        let responseNonce = Data(repeating: 0xEF, count: 32)

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        let plaintext = Data("Hello, EHBP!".utf8)
        let ciphertext = try encryptChunk(keyMaterial: keyMaterial, seq: 0, plaintext: plaintext)

        // Decrypt with wrong seq should fail
        XCTAssertThrowsError(try decryptChunk(keyMaterial: keyMaterial, seq: 1, ciphertext: ciphertext))
    }

    func testMultipleChunksRoundTrip() throws {
        let exportedSecret = Data(repeating: 0xAB, count: 32)
        let requestEnc = Data(repeating: 0xCD, count: 32)
        let responseNonce = Data(repeating: 0xEF, count: 32)

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        let chunks = [
            Data("First chunk of data".utf8),
            Data("Second chunk".utf8),
            Data("Third and final chunk with more data".utf8)
        ]

        // Encrypt all chunks with incrementing sequence
        var ciphertexts: [Data] = []
        for (i, chunk) in chunks.enumerated() {
            let ct = try encryptChunk(keyMaterial: keyMaterial, seq: UInt64(i), plaintext: chunk)
            ciphertexts.append(ct)
        }

        // Decrypt all chunks with matching sequence
        for (i, ct) in ciphertexts.enumerated() {
            let decrypted = try decryptChunk(keyMaterial: keyMaterial, seq: UInt64(i), ciphertext: ct)
            XCTAssertEqual(decrypted, chunks[i], "Chunk \(i) mismatch")
        }
    }

    func testDifferentKeysCannotDecrypt() throws {
        // Server's key material
        var serverSecret = Data(count: 32)
        for i in 0..<32 { serverSecret[i] = UInt8(i) }

        let requestEnc = Data(repeating: 0, count: 32)
        let responseNonce = Data(repeating: 0, count: 32)

        let serverKM = try deriveResponseKeys(
            exportedSecret: serverSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        // Attacker's key material (different secret)
        var attackerSecret = Data(count: 32)
        for i in 0..<32 { attackerSecret[i] = UInt8(i + 100) }

        let attackerKM = try deriveResponseKeys(
            exportedSecret: attackerSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        // Server encrypts
        let plaintext = Data("Secret response only for legitimate client".utf8)
        let ciphertext = try encryptChunk(keyMaterial: serverKM, seq: 0, plaintext: plaintext)

        // Attacker tries to decrypt with their keys
        XCTAssertThrowsError(
            try decryptChunk(keyMaterial: attackerKM, seq: 0, ciphertext: ciphertext),
            "Attacker should not be able to decrypt with different keys"
        )
    }

    // MARK: - Go Interoperability Test

    func testGoInteroperability() throws {
        // Test vectors from Go tests: exportedSecret[i] = i, requestEnc[i] = i+32, responseNonce[i] = i+64
        var exportedSecret = Data(count: 32)
        for i in 0..<32 { exportedSecret[i] = UInt8(i) }

        var requestEnc = Data(count: 32)
        for i in 0..<32 { requestEnc[i] = UInt8(i + 32) }

        var responseNonce = Data(count: 32)
        for i in 0..<32 { responseNonce[i] = UInt8(i + 64) }

        let km = try deriveResponseKeys(
            exportedSecret: exportedSecret,
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        // Expected values from Go implementation
        let expectedKeyHex = "40ec528847cd4e928449f2ed1a70a7d1e8ee317d5e900424fc1dd5b0475b97f7"
        let expectedNonceBaseHex = "f8b0ce9466f27aa6243c65f9"

        guard let expectedKey = Data(hexString: expectedKeyHex),
              let expectedNonceBase = Data(hexString: expectedNonceBaseHex) else {
            XCTFail("Failed to parse expected hex values")
            return
        }

        let derivedKeyData = km.key.withUnsafeBytes { Data($0) }
        XCTAssertEqual(
            derivedKeyData,
            expectedKey,
            "Key mismatch with Go implementation.\nExpected: \(expectedKeyHex)\nGot: \(derivedKeyData.hexString)"
        )

        XCTAssertEqual(
            km.nonceBase,
            expectedNonceBase,
            "NonceBase mismatch with Go implementation.\nExpected: \(expectedNonceBaseHex)\nGot: \(km.nonceBase.hexString)"
        )
    }
}
