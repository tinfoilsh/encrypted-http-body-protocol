import XCTest
import Crypto
@testable import EHBP

final class SessionRecoveryTests: XCTestCase {

    // MARK: - Helpers

    private func makeIdentityAndServer() -> (Identity, Curve25519.KeyAgreement.PrivateKey) {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let identity = try! Identity(publicKeyBytes: Data(serverPrivateKey.publicKey.rawRepresentation))
        return (identity, serverPrivateKey)
    }

    private func simulateServerResponse(
        serverPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        requestEnc: Data,
        plaintext: Data,
        chunkSizes: [Int]? = nil
    ) throws -> (responseNonce: Data, encryptedBody: Data) {
        let ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )

        let recipient = try HPKE.Recipient(
            privateKey: serverPrivateKey,
            ciphersuite: ciphersuite,
            info: Data(EHBPConstants.hpkeRequestInfo.utf8),
            encapsulatedKey: requestEnc
        )

        let exportLabel = Data(EHBPConstants.exportLabel.utf8)
        let exportedSecret = try recipient.exportSecret(
            context: exportLabel,
            outputByteCount: EHBPConstants.exportLength
        )

        var responseNonce = Data(count: EHBPConstants.responseNonceLength)
        _ = responseNonce.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, EHBPConstants.responseNonceLength, $0.baseAddress!)
        }

        let keyMaterial = try deriveResponseKeys(
            exportedSecret: exportedSecret.withUnsafeBytes { Data($0) },
            requestEnc: requestEnc,
            responseNonce: responseNonce
        )

        var encryptedBody = Data()
        let chunks: [Data]

        if let sizes = chunkSizes {
            var remaining = plaintext
            var parts = [Data]()
            for size in sizes {
                let chunk = remaining.prefix(size)
                remaining = remaining.suffix(from: remaining.startIndex + size)
                parts.append(Data(chunk))
            }
            chunks = parts
        } else {
            chunks = [plaintext]
        }

        for (i, chunk) in chunks.enumerated() {
            let encrypted = try encryptChunk(
                keyMaterial: keyMaterial,
                seq: UInt64(i),
                plaintext: chunk
            )
            var length = UInt32(encrypted.count).bigEndian
            encryptedBody.append(Data(bytes: &length, count: 4))
            encryptedBody.append(encrypted)
        }

        return (responseNonce, encryptedBody)
    }

    // MARK: - Token Extraction Tests

    func testExtractTokenFieldSizes() throws {
        let (identity, _) = makeIdentityAndServer()
        let (_, context) = try identity.encryptRequest(body: Data("hello".utf8))
        let token = try extractSessionRecoveryToken(context: context)

        XCTAssertEqual(token.exportedSecret.count, EHBPConstants.exportLength)
        XCTAssertEqual(token.requestEnc.count, EHBPConstants.requestEncLength)
    }

    func testExtractTokenMatchesDirectExport() throws {
        let (identity, _) = makeIdentityAndServer()
        let (_, context) = try identity.encryptRequest(body: Data("hello".utf8))
        let token = try extractSessionRecoveryToken(context: context)

        let exportLabel = Data(EHBPConstants.exportLabel.utf8)
        let directExport = try context.sender.exportSecret(
            context: exportLabel,
            outputByteCount: EHBPConstants.exportLength
        )

        XCTAssertEqual(token.exportedSecret, directExport.withUnsafeBytes { Data($0) })
        XCTAssertEqual(token.requestEnc, context.requestEnc)
    }

    func testExtractTokenDiffersPerRequest() throws {
        let (identity, _) = makeIdentityAndServer()

        let (_, ctx1) = try identity.encryptRequest(body: Data("hello".utf8))
        let token1 = try extractSessionRecoveryToken(context: ctx1)

        let (_, ctx2) = try identity.encryptRequest(body: Data("hello".utf8))
        let token2 = try extractSessionRecoveryToken(context: ctx2)

        XCTAssertNotEqual(token1.exportedSecret, token2.exportedSecret)
        XCTAssertNotEqual(token1.requestEnc, token2.requestEnc)
    }

    // MARK: - Decrypt With Token Tests

    func testDecryptWithTokenSingleChunk() throws {
        let (identity, serverPrivateKey) = makeIdentityAndServer()
        let plaintext = Data("hello world".utf8)

        let (encryptedRequest, context) = try identity.encryptRequest(body: plaintext)
        let token = try extractSessionRecoveryToken(context: context)

        // Server decrypts request (to establish shared state), then encrypts response
        let ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )
        let ciphertext = encryptedRequest.suffix(from: 4)
        var recipient = try HPKE.Recipient(
            privateKey: serverPrivateKey,
            ciphersuite: ciphersuite,
            info: Data(EHBPConstants.hpkeRequestInfo.utf8),
            encapsulatedKey: context.requestEnc
        )
        _ = try recipient.open(ciphertext)

        let responseBody = Data("response from server".utf8)
        let (responseNonce, encryptedBody) = try simulateServerResponse(
            serverPrivateKey: serverPrivateKey,
            requestEnc: context.requestEnc,
            plaintext: responseBody
        )

        let decrypted = try decryptResponseBody(
            token: token,
            responseNonce: responseNonce,
            encryptedData: encryptedBody
        )

        XCTAssertEqual(decrypted, responseBody)
    }

    func testDecryptWithTokenMultiChunk() throws {
        let (identity, serverPrivateKey) = makeIdentityAndServer()
        let plaintext = Data("hello world".utf8)

        let (encryptedRequest, context) = try identity.encryptRequest(body: plaintext)
        let token = try extractSessionRecoveryToken(context: context)

        let ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )
        let ciphertext = encryptedRequest.suffix(from: 4)
        var recipient = try HPKE.Recipient(
            privateKey: serverPrivateKey,
            ciphersuite: ciphersuite,
            info: Data(EHBPConstants.hpkeRequestInfo.utf8),
            encapsulatedKey: context.requestEnc
        )
        _ = try recipient.open(ciphertext)

        let responseBody = Data("chunk1chunk2chunk3".utf8)
        let (responseNonce, encryptedBody) = try simulateServerResponse(
            serverPrivateKey: serverPrivateKey,
            requestEnc: context.requestEnc,
            plaintext: responseBody,
            chunkSizes: [6, 6, 6]
        )

        let decrypted = try decryptResponseBody(
            token: token,
            responseNonce: responseNonce,
            encryptedData: encryptedBody
        )

        XCTAssertEqual(decrypted, responseBody)
    }

    func testDecryptWithTokenEquivalentToContextPath() throws {
        let (identity, serverPrivateKey) = makeIdentityAndServer()
        let plaintext = Data("hello".utf8)

        let (encryptedRequest, context) = try identity.encryptRequest(body: plaintext)
        let token = try extractSessionRecoveryToken(context: context)

        let ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )
        let ciphertext = encryptedRequest.suffix(from: 4)
        var recipient = try HPKE.Recipient(
            privateKey: serverPrivateKey,
            ciphersuite: ciphersuite,
            info: Data(EHBPConstants.hpkeRequestInfo.utf8),
            encapsulatedKey: context.requestEnc
        )
        _ = try recipient.open(ciphertext)

        let responseBody = Data("same response".utf8)
        let (responseNonce, encryptedBody) = try simulateServerResponse(
            serverPrivateKey: serverPrivateKey,
            requestEnc: context.requestEnc,
            plaintext: responseBody
        )

        // Token path
        let tokenDecrypted = try decryptResponseBody(
            token: token,
            responseNonce: responseNonce,
            encryptedData: encryptedBody
        )

        // Context path
        let contextKeyMaterial = try identity.deriveResponseKeys(context: context, responseNonce: responseNonce)
        var contextDecrypted = Data()
        var offset = 0
        var seq: UInt64 = 0
        while offset + 4 <= encryptedBody.count {
            let chunkLen = Int(encryptedBody[offset]) << 24 |
                           Int(encryptedBody[offset + 1]) << 16 |
                           Int(encryptedBody[offset + 2]) << 8 |
                           Int(encryptedBody[offset + 3])
            offset += 4
            let ct = encryptedBody.subdata(in: offset..<(offset + chunkLen))
            offset += chunkLen
            let pt = try decryptChunk(keyMaterial: contextKeyMaterial, seq: seq, ciphertext: ct)
            seq += 1
            contextDecrypted.append(pt)
        }

        XCTAssertEqual(tokenDecrypted, contextDecrypted)
    }

    // MARK: - Codable Tests

    func testTokenCodableRoundTrip() throws {
        let (identity, _) = makeIdentityAndServer()
        let (_, context) = try identity.encryptRequest(body: Data("hello".utf8))
        let token = try extractSessionRecoveryToken(context: context)

        let encoded = try JSONEncoder().encode(token)
        let json = String(data: encoded, encoding: .utf8)!

        // Verify hex format in JSON
        XCTAssertTrue(json.contains("\"exportedSecret\""))
        XCTAssertTrue(json.contains("\"requestEnc\""))
        XCTAssertTrue(json.contains(token.exportedSecret.hexString))
        XCTAssertTrue(json.contains(token.requestEnc.hexString))

        let decoded = try JSONDecoder().decode(SessionRecoveryToken.self, from: encoded)
        XCTAssertEqual(decoded.exportedSecret, token.exportedSecret)
        XCTAssertEqual(decoded.requestEnc, token.requestEnc)
    }

    func testTokenInteropVector() throws {
        // Read the shared fixture used by Go and JS interop tests
        let testFile = URL(fileURLWithPath: #filePath)
        let vectorPath = testFile
            .deletingLastPathComponent()  // EHBPTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // swift/
            .deletingLastPathComponent()  // repo root
            .appendingPathComponent("test-vectors")
            .appendingPathComponent("session-recovery-token.json")
        let vectorJSON = try Data(contentsOf: vectorPath)

        let token = try JSONDecoder().decode(SessionRecoveryToken.self, from: vectorJSON)

        XCTAssertEqual(token.exportedSecret.count, EHBPConstants.exportLength)
        XCTAssertEqual(token.requestEnc.count, EHBPConstants.requestEncLength)

        XCTAssertEqual(
            token.exportedSecret.hexString,
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        )
        XCTAssertEqual(
            token.requestEnc.hexString,
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        )

        // Re-serialize and verify identical JSON content
        let reEncoded = try JSONEncoder().encode(token)
        let original = try JSONSerialization.jsonObject(with: vectorJSON) as! [String: Any]
        let reserialized = try JSONSerialization.jsonObject(with: reEncoded) as! [String: Any]
        XCTAssertEqual(original as NSDictionary, reserialized as NSDictionary)
    }

    // MARK: - Error Cases

    func testDecryptWithWrongTokenFails() throws {
        let (identity, serverPrivateKey) = makeIdentityAndServer()
        let plaintext = Data("hello".utf8)

        let (encryptedRequest, context) = try identity.encryptRequest(body: plaintext)

        let ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_256
        )
        let ciphertext = encryptedRequest.suffix(from: 4)
        var recipient = try HPKE.Recipient(
            privateKey: serverPrivateKey,
            ciphersuite: ciphersuite,
            info: Data(EHBPConstants.hpkeRequestInfo.utf8),
            encapsulatedKey: context.requestEnc
        )
        _ = try recipient.open(ciphertext)

        let responseBody = Data("secret response".utf8)
        let (responseNonce, encryptedBody) = try simulateServerResponse(
            serverPrivateKey: serverPrivateKey,
            requestEnc: context.requestEnc,
            plaintext: responseBody
        )

        // Wrong token with random data
        let wrongToken = SessionRecoveryToken(
            exportedSecret: Data(repeating: 0xAA, count: EHBPConstants.exportLength),
            requestEnc: Data(repeating: 0xBB, count: EHBPConstants.requestEncLength)
        )

        XCTAssertThrowsError(try decryptResponseBody(
            token: wrongToken,
            responseNonce: responseNonce,
            encryptedData: encryptedBody
        ))
    }
}
