import Crypto
import Foundation
import XCTest
@testable import EHBP

/// Behaviours pinned by the conformance suite after the SDKs disagreed on them.
final class ConformanceDivergenceTests: XCTestCase {
    private let serverKey = Curve25519.KeyAgreement.PrivateKey()

    private func makeClient() throws -> EHBPClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ScriptedURLProtocol.self]
        return try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(serverKey.publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )
    }

    /// Encrypts `frames` as the server would for the request carrying `request`'s key header.
    private func encryptedReply(for request: URLRequest, frames: [String]) throws -> (nonce: String, body: Data) {
        let requestEnc = Data(hexString: request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader)!)!
        let recipient = try HPKE.Recipient(
            privateKey: serverKey,
            ciphersuite: HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256),
            info: Data(EHBPConstants.hpkeRequestInfo.utf8), encapsulatedKey: requestEnc)
        let secret = try recipient.exportSecret(context: Data(EHBPConstants.exportLabel.utf8),
                                                outputByteCount: EHBPConstants.exportLength)
        let nonce = Data((0..<EHBPConstants.responseNonceLength).map { _ in UInt8.random(in: 0...255) })
        let km = try deriveResponseKeys(exportedSecret: secret.withUnsafeBytes { Data($0) },
                                        requestEnc: requestEnc, responseNonce: nonce)
        var body = Data()
        for (seq, frame) in frames.enumerated() {
            let sealed = try encryptChunk(keyMaterial: km, seq: UInt64(seq), plaintext: Data(frame.utf8))
            var length = UInt32(sealed.count).bigEndian
            body.append(Data(bytes: &length, count: 4))
            body.append(sealed)
        }
        return (nonce.hexString, body)
    }

    override func tearDown() {
        ScriptedURLProtocol.script = nil
        super.tearDown()
    }

    // SPEC 4.1: strict hex.
    func testStrictHexDecoding() {
        XCTAssertEqual(Data(hexString: "0aFF"), Data([0x0a, 0xff]))
        XCTAssertEqual(Data(hexString: ""), Data())
        for bad in ["0x0a", "+a", "a b", "abc", "0a\n", "０a", "gg"] {
            XCTAssertNil(Data(hexString: bad), bad)
        }
        let valid = String(repeating: "ab", count: 32)
        XCTAssertNoThrow(try SessionRecoveryToken(json: Data(#"{"exportedSecret":"\#(valid.uppercased())","requestEnc":"\#(valid)"}"#.utf8)))
        for bad in ["0x" + valid.dropFirst(2), " " + valid.dropFirst()] {
            XCTAssertThrowsError(try SessionRecoveryToken(json: Data(#"{"exportedSecret":"\#(bad)","requestEnc":"\#(valid)"}"#.utf8))) {
                XCTAssertEqual(($0 as? EHBPError)?.code, .invalidToken)
            }
        }
    }

    // A default port written out is the same origin.
    func testDefaultPortIsSameOrigin() throws {
        let client = try makeClient()
        XCTAssertEqual(try client.resolveURL("https://server.test:443/x").absoluteString, "https://server.test:443/x")
        let explicit = try EHBPClient(baseURL: "https://server.test:443", publicKey: Data(serverKey.publicKey.rawRepresentation))
        XCTAssertNoThrow(try explicit.resolveURL("https://server.test/x"))
        XCTAssertThrowsError(try client.resolveURL("https://server.test:80/x"))
        XCTAssertThrowsError(try client.resolveURL("http://server.test:443/x"))
    }

    // Key config parsing codes (SPEC 3.2 / 5.5).
    func testKeyConfigParsingCodes() {
        let key = String(repeating: "07", count: 32)
        let cases: [(String, EHBPErrorCode?)] = [
            ("00", .invalidKeyConfig),                       // KEM not readable
            ("000010", .unsupportedSuite),                   // foreign KEM, nothing else
            ("000020" + key + "0005" + "0001000200", .invalidKeyConfig), // length not a multiple of 4
            ("000020" + key + "0003" + "000100", .invalidKeyConfig),
            ("000020" + key + "0008" + "00010002", .invalidKeyConfig),   // declared suites truncated
            ("000020" + key + "0000", .invalidKeyConfig),
            ("000020" + key + "0008" + "0001000200010002", .unsupportedSuite),
            ("070020" + key + "0004" + "00010002", nil),      // key_id is opaque
        ]
        for (hex, code) in cases {
            do {
                _ = try Identity(config: Data(hexString: hex)!)
                XCTAssertNil(code, hex)
            } catch {
                XCTAssertEqual((error as? EHBPError)?.code, code, hex)
            }
        }
    }

    // SPEC 4.2: an empty nonce is malformed, not absent, whatever the status.
    func testEmptyNonceIsInvalidOnAnyStatus() async throws {
        for status in [200, 502] {
            ScriptedURLProtocol.script = { _ in
                (status, [EHBPProtocol.responseNonceHeader: ""], Data("x".utf8))
            }
            let client = try makeClient()
            do {
                _ = try await client.request(method: "POST", path: "/secure", body: Data("hi".utf8))
                XCTFail("expected INVALID_RESPONSE_NONCE for \(status)")
            } catch {
                XCTAssertEqual((error as? EHBPError)?.code, .invalidResponseNonce)
            }
        }
    }

    // SPEC 5.4.2 detection rules.
    func testKeyConfigProblemDetection() {
        func problem(_ body: String, contentType: String = "application/problem+json") -> EHBPError? {
            let response = HTTPURLResponse(url: URL(string: "https://server.test/x")!, statusCode: 422,
                                           httpVersion: nil, headerFields: ["Content-Type": contentType])!
            return EHBPClient.keyConfigMismatch(response, body: Data(body.utf8))
        }
        let urn = EHBPProtocol.keyConfigProblemType
        XCTAssertEqual(problem(#"{"type":"\#(urn)","title":7}"#)?.detail, "stale client key configuration")
        XCTAssertEqual(problem(#"{"type":"\#(urn)","title":"t"}"#)?.detail, "t")
        XCTAssertNil(problem(#"{"Type":"\#(urn)"}"#))
        XCTAssertNil(problem(#"{"type":"\#(urn)"}"#, contentType: "text/plain"))
        XCTAssertNil(problem(String(repeating: "[", count: 50_000)))
        XCTAssertNil(problem(#"{"type":"\#(urn)","pad":"\#(String(repeating: "a", count: 64 * 1024))"}"#))
    }

    // SPEC 5.1: a 3xx is delivered, never followed.
    func testRedirectIsNotFollowed() async throws {
        ScriptedURLProtocol.script = { request in
            request.url!.path == "/elsewhere"
                ? (200, [String: String](), Data("followed".utf8))
                : (302, ["Location": "https://server.test/elsewhere"], Data("redirecting".utf8))
        }
        let client = try makeClient()
        let (data, response) = try await client.request(method: "POST", path: "/secure", body: Data("hi".utf8))
        XCTAssertEqual(response.statusCode, 302)
        XCTAssertEqual(String(data: data, encoding: .utf8), "redirecting")
        XCTAssertThrowsError(try client.getSessionRecoveryToken())
    }

    // SPEC 6.3: abandoning the body before EOF consumes the token.
    func testAbandonedStreamConsumesToken() async throws {
        ScriptedURLProtocol.script = { [self] request in
            let reply = try encryptedReply(for: request, frames: ["one", "two", "three"])
            return (200, [EHBPProtocol.responseNonceHeader: reply.nonce], reply.body)
        }
        let client = try makeClient()
        func readOneChunk() async throws {
            let (stream, _) = try await client.requestStream(method: "POST", path: "/secure", body: Data("hi".utf8))
            var iterator = stream.makeAsyncIterator()
            let first = try await iterator.next()
            XCTAssertEqual(first, Data("one".utf8))
            XCTAssertNoThrow(try client.getSessionRecoveryToken())
        }
        try await readOneChunk()
        XCTAssertThrowsError(try client.getSessionRecoveryToken())
    }

    // SPEC 5.5: a transport failure inside a frame is FRAMING_TRUNCATED.
    func testTransportFailureInsideFrameIsTruncated() async throws {
        // URLSession holds back a short body until it ends; a 20 KiB first
        // frame makes it flush before the failure arrives.
        let complete = String(repeating: "a", count: 20_000)
        ScriptedURLProtocol.script = { [self] request in
            let reply = try encryptedReply(for: request, frames: [complete, "cut"])
            let end = reply.body.count - 2 // fail inside the second frame's tag
            ScriptedURLProtocol.failAfter = (end, URLError(.networkConnectionLost))
            return (200, [EHBPProtocol.responseNonceHeader: reply.nonce], reply.body)
        }
        defer { ScriptedURLProtocol.failAfter = nil }
        let client = try makeClient()
        let (stream, _) = try await client.requestStream(method: "POST", path: "/secure", body: Data("hi".utf8))
        var iterator = stream.makeAsyncIterator()
        let first = try await iterator.next()
        XCTAssertEqual(first, Data(complete.utf8))
        do {
            _ = try await iterator.next()
            XCTFail("expected FRAMING_TRUNCATED")
        } catch {
            XCTAssertEqual((error as? EHBPError)?.code, .framingTruncated)
        }
        XCTAssertThrowsError(try client.getSessionRecoveryToken())
    }
}

/// Serves (status, headers, body) per request; a 3xx with Location goes
/// through URLSession's redirect machinery; `failAfter` delivers a prefix then fails.
final class ScriptedURLProtocol: URLProtocol {
    nonisolated(unsafe) static var script: ((URLRequest) throws -> (Int, [String: String], Data))?
    nonisolated(unsafe) static var failAfter: (Int, Error)?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        do {
            let (status, headers, body) = try Self.script!(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
                                           headerFields: headers)!
            if let location = headers["Location"] {
                client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: URL(string: location)!), redirectResponse: response)
            }
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if let fail = Self.failAfter {
                client?.urlProtocol(self, didLoad: body.prefix(fail.0))
                // Let the prefix reach the reader before the failure does.
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) {
                    self.client?.urlProtocol(self, didFailWithError: fail.1)
                }
                return
            }
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
