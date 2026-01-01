import XCTest
import Crypto
@testable import EHBP

/// Security Tests for EHBP
///
/// These tests verify that the following MitM key substitution vulnerability cannot occur:
/// 1. MitM cannot derive the correct response decryption keys
/// 2. MitM cannot forge valid encrypted responses
/// 3. Modified headers cause decryption failures
final class SecurityTests: XCTestCase {

    // MARK: - MitM Cannot Read Responses

    /// Verifies that a man-in-the-middle cannot decrypt responses even if they intercept all headers.
    ///
    /// Attack scenario:
    /// - Eve intercepts the request from Alice to Server
    /// - Eve sees: requestEnc (public header), responseNonce (public header)
    /// - Eve does NOT have: the HPKE shared secret between Alice and Server
    /// - Eve cannot derive the response decryption keys
    func testMitMCannotReadResponse() throws {
        // Server keypair
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKey = serverPrivateKey.publicKey

        // Client (Alice) creates HPKE sender to server
        let aliceIdentity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))
        let (_, aliceContext) = try aliceIdentity.encryptRequest(body: Data("test request".utf8))

        // Response nonce (public, sent in header)
        var responseNonce = Data(count: 32)
        let status = responseNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        XCTAssertEqual(status, errSecSuccess, "Failed to generate random bytes")

        // Alice derives response keys from her HPKE context
        let aliceKM = try aliceIdentity.deriveResponseKeys(context: aliceContext, responseNonce: responseNonce)

        // Eve (attacker) creates her own HPKE context to the server
        // Even though Eve intercepts requestEnc, she cannot derive the shared secret
        let eveIdentity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))
        let (_, eveContext) = try eveIdentity.encryptRequest(body: Data("eve request".utf8))

        // Eve tries to derive keys using intercepted requestEnc but her own context
        // She uses the same responseNonce (public) but her exported secret is different
        let eveKM = try eveIdentity.deriveResponseKeys(context: eveContext, responseNonce: responseNonce)

        // Keys MUST be different - this is the core security property
        XCTAssertNotEqual(
            aliceKM.nonceBase,
            eveKM.nonceBase,
            "SECURITY FAILURE: Alice and Eve derived the same nonce base!"
        )
    }

    /// Verifies that Eve cannot decrypt responses meant for Alice
    func testEveCannotDecryptAlicesResponse() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKey = serverPrivateKey.publicKey

        // Alice creates request
        let aliceIdentity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))
        let (_, aliceContext) = try aliceIdentity.encryptRequest(body: Data("alice request".utf8))

        // Server generates response nonce and encrypts response
        var responseNonce = Data(count: 32)
        XCTAssertEqual(responseNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }, errSecSuccess)

        // Server derives keys (simulated - in reality server uses its HPKE receiver context)
        // For this test, we use Alice's context since server and Alice share the secret
        let serverKM = try aliceIdentity.deriveResponseKeys(context: aliceContext, responseNonce: responseNonce)

        let secretMessage = Data("Secret API key: sk-12345".utf8)
        let encryptedResponse = try encryptChunk(keyMaterial: serverKM, seq: 0, plaintext: secretMessage)

        // Alice can decrypt (she has matching exported secret)
        let aliceKM = try aliceIdentity.deriveResponseKeys(context: aliceContext, responseNonce: responseNonce)
        let aliceDecrypted = try decryptChunk(keyMaterial: aliceKM, seq: 0, ciphertext: encryptedResponse)
        XCTAssertEqual(aliceDecrypted, secretMessage, "Alice should decrypt successfully")

        // Eve creates her own context - she CANNOT decrypt
        let eveIdentity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))
        let (_, eveContext) = try eveIdentity.encryptRequest(body: Data("eve request".utf8))
        let eveKM = try eveIdentity.deriveResponseKeys(context: eveContext, responseNonce: responseNonce)

        // Eve's decryption MUST fail
        XCTAssertThrowsError(
            try decryptChunk(keyMaterial: eveKM, seq: 0, ciphertext: encryptedResponse),
            "SECURITY FAILURE: Eve was able to decrypt the response!"
        )
    }

    // MARK: - MitM Cannot Forge Responses

    /// Verifies that responses encrypted with wrong keys are rejected
    func testMitMCannotForgeResponse() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKey = serverPrivateKey.publicKey

        // Alice creates request
        let aliceIdentity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))
        let (_, aliceContext) = try aliceIdentity.encryptRequest(body: Data("alice request".utf8))

        // Attacker creates forged response with random keys
        var attackerSecret = Data(count: 32)
        XCTAssertEqual(attackerSecret.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }, errSecSuccess)

        var forgedNonce = Data(count: 32)
        XCTAssertEqual(forgedNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }, errSecSuccess)

        let attackerKM = try deriveResponseKeys(
            exportedSecret: attackerSecret,
            requestEnc: aliceContext.requestEnc,
            responseNonce: forgedNonce
        )

        let forgedMessage = Data("Malicious message".utf8)
        let forgedCiphertext = try encryptChunk(keyMaterial: attackerKM, seq: 0, plaintext: forgedMessage)

        // Alice tries to decrypt with her real keys
        let aliceKM = try aliceIdentity.deriveResponseKeys(context: aliceContext, responseNonce: forgedNonce)

        // Decryption MUST fail - attacker used wrong shared secret
        XCTAssertThrowsError(
            try decryptChunk(keyMaterial: aliceKM, seq: 0, ciphertext: forgedCiphertext),
            "SECURITY FAILURE: Forged response was accepted!"
        )
    }

    // MARK: - Modified Headers Cause Failure

    /// Verifies that if request enc is modified, decryption fails
    func testModifiedRequestEncCausesFailure() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKey = serverPrivateKey.publicKey

        let aliceIdentity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))
        let (_, aliceContext) = try aliceIdentity.encryptRequest(body: Data("alice request".utf8))
        let originalEnc = aliceContext.requestEnc

        var responseNonce = Data(count: 32)
        XCTAssertEqual(responseNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }, errSecSuccess)

        // Server encrypts response using original enc
        let serverKM = try aliceIdentity.deriveResponseKeys(context: aliceContext, responseNonce: responseNonce)
        let plaintext = Data("Secret response".utf8)
        let ciphertext = try encryptChunk(keyMaterial: serverKM, seq: 0, plaintext: plaintext)

        // Alice receives with MODIFIED enc (tampered by MitM)
        var modifiedEnc = originalEnc
        modifiedEnc[0] ^= 0xFF

        // Alice derives keys with wrong enc (simulating header tampering)
        // We need to manually derive since context has the original enc
        let exportedSecret = try aliceContext.sender.exportSecret(
            context: Data(EHBPConstants.exportLabel.utf8),
            outputByteCount: EHBPConstants.exportLength
        )

        let aliceKM = try deriveResponseKeys(
            exportedSecret: exportedSecret.withUnsafeBytes { Data($0) },
            requestEnc: modifiedEnc,
            responseNonce: responseNonce
        )

        // Decryption MUST fail because enc was modified
        XCTAssertThrowsError(
            try decryptChunk(keyMaterial: aliceKM, seq: 0, ciphertext: ciphertext),
            "SECURITY FAILURE: Decryption succeeded with modified enc!"
        )
    }

    /// Verifies that if response nonce is modified, decryption fails
    func testModifiedNonceCausesFailure() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKey = serverPrivateKey.publicKey

        let aliceIdentity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))
        let (_, aliceContext) = try aliceIdentity.encryptRequest(body: Data("alice request".utf8))

        var originalNonce = Data(count: 32)
        XCTAssertEqual(originalNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }, errSecSuccess)

        // Server encrypts response
        let serverKM = try aliceIdentity.deriveResponseKeys(context: aliceContext, responseNonce: originalNonce)
        let plaintext = Data("Secret response".utf8)
        let ciphertext = try encryptChunk(keyMaterial: serverKM, seq: 0, plaintext: plaintext)

        // Alice receives with MODIFIED nonce (tampered by MitM)
        var modifiedNonce = originalNonce
        modifiedNonce[0] ^= 0xFF

        // Alice derives keys with wrong nonce
        let aliceKM = try aliceIdentity.deriveResponseKeys(context: aliceContext, responseNonce: modifiedNonce)

        // Decryption MUST fail because nonce was modified
        XCTAssertThrowsError(
            try decryptChunk(keyMaterial: aliceKM, seq: 0, ciphertext: ciphertext),
            "SECURITY FAILURE: Decryption succeeded with modified nonce!"
        )
    }

    // MARK: - End-to-End Security

    /// Verifies complete secure encryption/decryption flow
    func testEndToEndSecureRoundTrip() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKey = serverPrivateKey.publicKey

        // Client creates identity and encrypts request
        let clientIdentity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))
        let requestBody = Data("Hello, secure server!".utf8)
        let (encryptedRequest, clientContext) = try clientIdentity.encryptRequest(body: requestBody)

        // Verify request is encrypted (has length prefix)
        XCTAssertGreaterThan(encryptedRequest.count, 4)

        // Server would decrypt request and prepare response...
        // For this test, we simulate the server using the client's context
        // (In reality, server has its own receiver context with same shared secret)

        var responseNonce = Data(count: 32)
        XCTAssertEqual(responseNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }, errSecSuccess)

        let responseBody = Data("Hello, client! Your secret is safe.".utf8)

        // Server encrypts response
        let serverKM = try clientIdentity.deriveResponseKeys(context: clientContext, responseNonce: responseNonce)
        let encryptedResponse = try encryptChunk(keyMaterial: serverKM, seq: 0, plaintext: responseBody)

        // Client decrypts response
        let clientKM = try clientIdentity.deriveResponseKeys(context: clientContext, responseNonce: responseNonce)
        let decryptedResponse = try decryptChunk(keyMaterial: clientKM, seq: 0, ciphertext: encryptedResponse)

        XCTAssertEqual(decryptedResponse, responseBody, "End-to-end round-trip failed")
    }

    /// Verifies that different clients get different keys even for same server
    func testDifferentClientsGetDifferentKeys() throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPublicKey = serverPrivateKey.publicKey

        // Two different clients
        let client1Identity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))
        let client2Identity = try Identity(publicKeyBytes: Data(serverPublicKey.rawRepresentation))

        let (_, client1Context) = try client1Identity.encryptRequest(body: Data("client1".utf8))
        let (_, client2Context) = try client2Identity.encryptRequest(body: Data("client2".utf8))

        // Same response nonce
        var responseNonce = Data(count: 32)
        XCTAssertEqual(responseNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }, errSecSuccess)

        let km1 = try client1Identity.deriveResponseKeys(context: client1Context, responseNonce: responseNonce)
        let km2 = try client2Identity.deriveResponseKeys(context: client2Context, responseNonce: responseNonce)

        // Keys MUST be different
        XCTAssertNotEqual(km1.nonceBase, km2.nonceBase, "Different clients should derive different keys")
    }
}
