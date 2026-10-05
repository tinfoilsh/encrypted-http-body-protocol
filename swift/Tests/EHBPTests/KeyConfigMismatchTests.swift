import Crypto
import Foundation
import XCTest
@testable import EHBP

final class KeyConfigMismatchTests: XCTestCase {
    private func makeClient() throws -> EHBPClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )
    }

    private func stub(contentType: String, body: String) {
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!, statusCode: 422, httpVersion: nil,
                headerFields: ["Content-Type": contentType]
            )!
            return (response, Data(body.utf8))
        }
    }

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    func testKeyConfigMismatchIsTypedOnBothPaths() async throws {
        let problem = #"{"type":"urn:ietf:params:ehbp:error:key-config","title":"stale key"}"#
        stub(contentType: "application/problem+json; charset=utf-8", body: problem)
        let client = try makeClient()

        do {
            _ = try await client.request(method: "POST", path: "/secure", body: Data("hi".utf8))
            XCTFail("expected key config mismatch")
        } catch {
            XCTAssertEqual((error as? EHBPError)?.code, .keyConfigMismatch)
            XCTAssertEqual((error as? EHBPError)?.detail, "stale key")
        }
        do {
            _ = try await client.requestStream(method: "POST", path: "/secure", body: Data("hi".utf8))
            XCTFail("expected key config mismatch on the streaming path")
        } catch {
            XCTAssertEqual((error as? EHBPError)?.code, .keyConfigMismatch)
        }

        // A 422 that is not a key-config problem still passes through untouched.
        stub(contentType: "application/problem+json", body: #"{"type":"about:blank"}"#)
        let (stream, response) = try await client.requestStream(method: "POST", path: "/secure", body: Data("hi".utf8))
        var data = Data()
        for try await chunk in stream { data.append(chunk) }
        XCTAssertEqual(response.statusCode, 422)
        XCTAssertEqual(String(data: data, encoding: .utf8), #"{"type":"about:blank"}"#)
    }

    func testEncrypted422IsNotInspectedAsProblemDocument() {
        // A response nonce means the body is ciphertext; it must reach the
        // decryptor untouched rather than being prefetched as plaintext.
        let response = HTTPURLResponse(
            url: URL(string: "https://server.test/secure")!, statusCode: 422, httpVersion: nil,
            headerFields: [
                "Content-Type": "application/problem+json",
                EHBPProtocol.responseNonceHeader: String(repeating: "0", count: 64),
            ]
        )!
        XCTAssertFalse(EHBPClient.mayBeKeyConfigMismatch(response))
        XCTAssertNil(EHBPClient.keyConfigMismatch(response, body: Data(#"{"type":"\#(EHBPProtocol.keyConfigProblemType)"}"#.utf8)))
    }
}
