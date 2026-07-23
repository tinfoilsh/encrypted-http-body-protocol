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

    func testResponseDecryptionInteropVector() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let vectorPath = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("test-vectors")
            .appendingPathComponent("response-decryption.json")
        let vectorJSON = try Data(contentsOf: vectorPath)

        struct DecryptionVector: Decodable {
            let exportedSecret: String
            let requestEnc: String
            let responseNonce: String
            let plaintext: String
            let encryptedResponse: String
        }
        let vector = try JSONDecoder().decode(DecryptionVector.self, from: vectorJSON)

        let token = SessionRecoveryToken(
            exportedSecret: Data(hexString: vector.exportedSecret)!,
            requestEnc: Data(hexString: vector.requestEnc)!
        )

        let decrypted = try decryptResponseBody(
            token: token,
            responseNonce: Data(hexString: vector.responseNonce)!,
            encryptedData: Data(hexString: vector.encryptedResponse)!
        )

        XCTAssertEqual(decrypted, Data(hexString: vector.plaintext)!)
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

    // The encrypted reply carries framing headers describing the ciphertext,
    // as buffering middleboxes produce. The decrypted response handed to the
    // caller must not retain them, or consumers forwarding the headers
    // verbatim (proxies) would truncate the reply.
    func testDecryptedResponseDropsEncryptedFramingHeaders() async throws {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()

        StubURLProtocol.handler = { [simulateServerResponse] request in
            guard let encHex = request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader),
                  let requestEnc = Data(hexString: encHex) else {
                throw EHBPError.invalidInput("missing encapsulated key header")
            }
            let (responseNonce, encryptedBody) = try simulateServerResponse(
                serverPrivateKey, requestEnc, Data("full reply".utf8), nil
            )
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    EHBPProtocol.responseNonceHeader: responseNonce.hexString,
                    "Content-Length": String(encryptedBody.count),
                    "Transfer-Encoding": "identity",
                    "Content-Type": "text/plain",
                ]
            )!
            return (response, encryptedBody)
        }
        defer { StubURLProtocol.handler = nil }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)

        let client = try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(serverPrivateKey.publicKey.rawRepresentation),
            session: session
        )

        let (data, response) = try await client.request(
            method: "POST",
            path: "/secure",
            body: Data("hello".utf8)
        )

        XCTAssertEqual(String(data: data, encoding: .utf8), "full reply")
        XCTAssertNil(response.value(forHTTPHeaderField: "Content-Length"),
                     "stale encrypted Content-Length must not survive decryption")
        XCTAssertNil(response.value(forHTTPHeaderField: "Transfer-Encoding"),
                     "stale Transfer-Encoding must not survive decryption")
        XCTAssertEqual(response.value(forHTTPHeaderField: "Content-Type"), "text/plain")
        XCTAssertNotNil(response.value(forHTTPHeaderField: EHBPProtocol.responseNonceHeader))
        XCTAssertThrowsError(try client.getSessionRecoveryToken())
    }

    func testOlderBufferedCompletionPreservesLatestRecoveryToken() async throws {
        let (_, serverPrivateKey) = makeIdentityAndServer()
        let firstStarted = expectation(description: "first request started")

        ControlledURLProtocol.handler = { [simulateServerResponse] request, index in
            guard let encHex = request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader),
                  let requestEnc = Data(hexString: encHex) else {
                throw EHBPError.invalidInput("missing encapsulated key header")
            }
            if index == 1 {
                ControlledURLProtocol.setSecondRequestEnc(requestEnc)
            }
            let (responseNonce, encryptedBody) = try simulateServerResponse(
                serverPrivateKey, requestEnc, Data("ok".utf8), nil
            )
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: [EHBPProtocol.responseNonceHeader: responseNonce.hexString]
            )!
            return (response, encryptedBody)
        }
        ControlledURLProtocol.onFirstStarted = { firstStarted.fulfill() }
        defer { ControlledURLProtocol.reset() }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ControlledURLProtocol.self]
        let client = try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(serverPrivateKey.publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )

        let first = Task {
            try await client.request(method: "POST", path: "/first", body: Data("first".utf8))
        }
        await fulfillment(of: [firstStarted], timeout: 2)

        let (newerStream, _) = try await client.requestStream(
            method: "POST",
            path: "/second",
            body: Data("second".utf8)
        )
        let expectedRequestEnc = ControlledURLProtocol.getSecondRequestEnc()
        XCTAssertEqual(try client.getSessionRecoveryToken().requestEnc, expectedRequestEnc)

        ControlledURLProtocol.releaseFirst()
        _ = try await first.value
        XCTAssertEqual(try client.getSessionRecoveryToken().requestEnc, expectedRequestEnc)
        withExtendedLifetime(newerStream) {}
    }

    func testSuccessfulStreamingCompletionClearsRecoveryToken() async throws {
        let (_, serverPrivateKey) = makeIdentityAndServer()

        StubURLProtocol.handler = { [simulateServerResponse] request in
            guard let encHex = request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader),
                  let requestEnc = Data(hexString: encHex) else {
                throw EHBPError.invalidInput("missing encapsulated key header")
            }
            let (responseNonce, encryptedBody) = try simulateServerResponse(
                serverPrivateKey, requestEnc, Data("ok".utf8), nil
            )
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: [EHBPProtocol.responseNonceHeader: responseNonce.hexString]
            )!
            return (response, encryptedBody)
        }
        defer { StubURLProtocol.handler = nil }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let client = try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(serverPrivateKey.publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )

        let (stream, _) = try await client.requestStream(
            method: "POST",
            path: "/secure",
            body: Data("hello".utf8)
        )
        XCTAssertNoThrow(try client.getSessionRecoveryToken())

        var iterator = stream.makeAsyncIterator()
        let plaintext = try await iterator.next()
        XCTAssertEqual(plaintext, Data("ok".utf8))
        XCTAssertNoThrow(try client.getSessionRecoveryToken())
        let end = try await iterator.next()
        XCTAssertNil(end)
        XCTAssertThrowsError(try client.getSessionRecoveryToken())
        let repeatedEnd = try await iterator.next()
        XCTAssertNil(repeatedEnd)
    }

    func testLatestStreamingFailureClearsRecoveryToken() async throws {
        let (_, serverPrivateKey) = makeIdentityAndServer()

        StubURLProtocol.handler = { [simulateServerResponse] request in
            guard let encHex = request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader),
                  let requestEnc = Data(hexString: encHex) else {
                throw EHBPError.invalidInput("missing encapsulated key header")
            }
            let (responseNonce, encryptedBody) = try simulateServerResponse(
                serverPrivateKey, requestEnc, Data("ok".utf8), nil
            )
            var corrupted = encryptedBody
            corrupted[corrupted.index(before: corrupted.endIndex)] ^= 1
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: [EHBPProtocol.responseNonceHeader: responseNonce.hexString]
            )!
            return (response, corrupted)
        }
        defer { StubURLProtocol.handler = nil }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let client = try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(serverPrivateKey.publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )

        let (stream, _) = try await client.requestStream(
            method: "POST",
            path: "/secure",
            body: Data("hello".utf8)
        )
        XCTAssertNoThrow(try client.getSessionRecoveryToken())

        do {
            for try await _ in stream {}
            XCTFail("expected stream authentication failure")
        } catch {
            XCTAssertThrowsError(try client.getSessionRecoveryToken())
        }
    }

    func testOlderStreamingFailurePreservesNewerRecoveryToken() async throws {
        let (_, serverPrivateKey) = makeIdentityAndServer()

        DelayedFailureURLProtocol.handler = { [simulateServerResponse] request, index in
            guard let encHex = request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader),
                  let requestEnc = Data(hexString: encHex) else {
                throw EHBPError.invalidInput("missing encapsulated key header")
            }
            if index == 1 {
                DelayedFailureURLProtocol.setSecondRequestEnc(requestEnc)
            }
            let plaintext = index == 0
                ? Data(repeating: 0x41, count: 16 * 1024 + 2)
                : Data("ok".utf8)
            let chunkSizes = index == 0 ? [16 * 1024, 2] : nil
            let (responseNonce, encryptedBody) = try simulateServerResponse(
                serverPrivateKey, requestEnc, plaintext, chunkSizes
            )
            var body = encryptedBody
            if index == 0 {
                body[body.index(before: body.endIndex)] ^= 1
            }
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: [EHBPProtocol.responseNonceHeader: responseNonce.hexString]
            )!
            return (response, body)
        }
        defer { DelayedFailureURLProtocol.reset() }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [DelayedFailureURLProtocol.self]
        let client = try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(serverPrivateKey.publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )

        let (olderStream, _) = try await client.requestStream(
            method: "POST",
            path: "/older",
            body: Data("older".utf8)
        )
        let (newerStream, _) = try await client.requestStream(
            method: "POST",
            path: "/newer",
            body: Data("newer".utf8)
        )
        let expectedRequestEnc = DelayedFailureURLProtocol.getSecondRequestEnc()
        XCTAssertEqual(try client.getSessionRecoveryToken().requestEnc, expectedRequestEnc)

        DelayedFailureURLProtocol.releaseFirstBody()
        do {
            for try await _ in olderStream {}
            XCTFail("expected older stream authentication failure")
        } catch {
            XCTAssertEqual(try client.getSessionRecoveryToken().requestEnc, expectedRequestEnc)
        }
        withExtendedLifetime(newerStream) {}
    }
}

final class StubURLProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = StubURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: EHBPError.invalidInput("no stub handler"))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

private final class ControlledURLProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest, Int) throws -> (HTTPURLResponse, Data))?
    nonisolated(unsafe) static var onFirstStarted: (() -> Void)?
    nonisolated(unsafe) static var firstDelivery: (() -> Void)?
    nonisolated(unsafe) static var requestCount = 0
    nonisolated(unsafe) static var secondRequestEnc = Data()
    private static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let index = Self.requestCount
        Self.requestCount += 1
        Self.lock.unlock()

        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: EHBPError.invalidInput("no controlled handler"))
            return
        }
        do {
            let (response, data) = try handler(request, index)
            let deliver = { [weak self] in
                guard let self else { return }
                self.client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                self.client?.urlProtocol(self, didLoad: data)
                self.client?.urlProtocolDidFinishLoading(self)
            }
            if index == 0 {
                Self.lock.lock()
                Self.firstDelivery = deliver
                Self.lock.unlock()
                Self.onFirstStarted?()
            } else {
                deliver()
            }
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    static func releaseFirst() {
        lock.lock()
        let delivery = firstDelivery
        firstDelivery = nil
        lock.unlock()
        delivery?()
    }

    static func setSecondRequestEnc(_ requestEnc: Data) {
        lock.lock()
        secondRequestEnc = requestEnc
        lock.unlock()
    }

    static func getSecondRequestEnc() -> Data {
        lock.lock()
        let requestEnc = secondRequestEnc
        lock.unlock()
        return requestEnc
    }

    static func reset() {
        releaseFirst()
        lock.lock()
        handler = nil
        onFirstStarted = nil
        requestCount = 0
        secondRequestEnc = Data()
        lock.unlock()
    }
}

private final class DelayedFailureURLProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest, Int) throws -> (HTTPURLResponse, Data))?
    nonisolated(unsafe) static var firstBodyDelivery: (() -> Void)?
    nonisolated(unsafe) static var requestCount = 0
    nonisolated(unsafe) static var secondRequestEnc = Data()
    private static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let index = Self.requestCount
        Self.requestCount += 1
        Self.lock.unlock()

        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: EHBPError.invalidInput("no delayed handler"))
            return
        }
        do {
            let (response, data) = try handler(request, index)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if index == 0 {
                let finalByte = data.suffix(1)
                client?.urlProtocol(self, didLoad: data.dropLast())
                Self.lock.lock()
                Self.firstBodyDelivery = { [weak self] in
                    guard let self else { return }
                    self.client?.urlProtocol(self, didLoad: finalByte)
                    self.client?.urlProtocolDidFinishLoading(self)
                }
                Self.lock.unlock()
            } else {
                client?.urlProtocol(self, didLoad: data)
                client?.urlProtocolDidFinishLoading(self)
            }
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    static func setSecondRequestEnc(_ requestEnc: Data) {
        lock.lock()
        secondRequestEnc = requestEnc
        lock.unlock()
    }

    static func getSecondRequestEnc() -> Data {
        lock.lock()
        let requestEnc = secondRequestEnc
        lock.unlock()
        return requestEnc
    }

    static func releaseFirstBody() {
        lock.lock()
        let delivery = firstBodyDelivery
        firstBodyDelivery = nil
        lock.unlock()
        delivery?()
    }

    static func reset() {
        releaseFirstBody()
        lock.lock()
        handler = nil
        requestCount = 0
        secondRequestEnc = Data()
        lock.unlock()
    }
}
