import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import EHBP

final class UnencryptedResponseTests: XCTestCase {
    private func makeClient(statusCode: Int) throws -> EHBPClient {
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        UnencryptedResponseURLProtocol.statusCode = statusCode
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [UnencryptedResponseURLProtocol.self]
        return try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(serverPrivateKey.publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )
    }

    override func tearDown() {
        UnencryptedResponseURLProtocol.statusCode = 500
        super.tearDown()
    }

    func testRequestPassesThroughUnencryptedNonSuccessResponses() async throws {
        for statusCode in [300, 400, 503] {
            let client = try makeClient(statusCode: statusCode)
            let (data, response) = try await client.request(
                method: "POST",
                path: "/secure",
                body: Data("hello".utf8)
            )

            XCTAssertEqual(response.statusCode, statusCode)
            XCTAssertEqual(response.value(forHTTPHeaderField: "Content-Type"), "text/plain")
            XCTAssertEqual(data, Data("upstream unavailable".utf8))
            XCTAssertThrowsError(try client.getSessionRecoveryToken())
        }
    }

    func testStreamingRequestPassesThroughUnencryptedNonSuccessResponse() async throws {
        let client = try makeClient(statusCode: 429)
        let (stream, response) = try await client.requestStream(
            method: "POST",
            path: "/secure",
            body: Data("hello".utf8)
        )
        var data = Data()
        for try await chunk in stream {
            data.append(chunk)
        }

        XCTAssertEqual(response.statusCode, 429)
        XCTAssertEqual(response.value(forHTTPHeaderField: "Content-Type"), "text/plain")
        XCTAssertEqual(data, Data("upstream unavailable".utf8))
        XCTAssertThrowsError(try client.getSessionRecoveryToken())
    }

    func testSuccessfulUnencryptedResponseRemainsRejected() async throws {
        let client = try makeClient(statusCode: 200)

        do {
            _ = try await client.request(
                method: "POST",
                path: "/secure",
                body: Data("hello".utf8)
            )
            XCTFail("Expected a missing response nonce error")
        } catch EHBPError.missingHeader(let header) {
            XCTAssertEqual(header, EHBPProtocol.responseNonceHeader)
        }
    }
}

private final class UnencryptedResponseURLProtocol: URLProtocol {
    nonisolated(unsafe) static var statusCode = 500

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: Self.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "text/plain"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data("upstream unavailable".utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
