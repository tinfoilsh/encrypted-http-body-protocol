import XCTest
@testable import EHBP

/// What is URLSession-specific: the streamed upload, pass-through streaming,
/// cancellation and the token lifecycle through the API. Protocol decisions
/// are pinned by the conformance fixtures.
final class ClientTests: XCTestCase {
    private let publicKey = Data(repeating: 7, count: 32)

    private func client() async throws -> EHBPClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ScriptedURLProtocol.self]
        return try await EHBPClient(server: "http://configured.example", keys: .publicKey(publicKey), session: URLSession(configuration: configuration))
    }

    override func tearDown() { ScriptedURLProtocol.script = nil }

    func testUnencryptedErrorPassesThroughAsAStream() async throws {
        ScriptedURLProtocol.script = { _ in (502, ["Content-Type": "text/plain", "X-Upstream": "proxy"], Data("upstream unavailable".utf8)) }
        let client = try await client()
        let (stream, response) = try await client.requestStream(method: "POST", path: "/secure", body: Data("secret".utf8))
        XCTAssertEqual(response.statusCode, 502)
        XCTAssertEqual(response.value(forHTTPHeaderField: "x-upstream"), "proxy")
        XCTAssertNil(client.sessionRecoveryToken())
        var body = Data()
        for try await chunk in stream { body.append(chunk) }
        XCTAssertEqual(body, Data("upstream unavailable".utf8))
    }

    func testBodyIsUploadedChunkedInBoundedFramesAndTokenIsPublishedFirst() async throws {
        let seen = Captured()
        ScriptedURLProtocol.script = { request in
            seen.headers = request.allHTTPHeaderFields ?? [:]
            seen.body = ScriptedURLProtocol.drain(request.httpBodyStream!)
            return (422, [:], Data())
        }
        let client = try await client()
        var chunks: [Data] = [Data("first".utf8), Data(repeating: 0x5A, count: 200 * 1024), Data("last".utf8)]
        _ = try await client.request(method: "POST", path: "/secure", bodySource: { chunks.isEmpty ? nil : chunks.removeFirst() })
        XCTAssertEqual(seen.headers["Ehbp-Encapsulated-Key"]?.count, 64)
        XCTAssertNil(seen.headers["Content-Length"])
        // 5 B, 3 x 64 KiB, 8 KiB, 4 B frames, each a length prefix and a 16-byte tag.
        var frames: [Int] = []
        var at = 0
        while at < seen.body.count {
            let n = Int(seen.body[at..<at + 4].reduce(0) { $0 << 8 | UInt32($1) })
            frames.append(n - 16); at += 4 + n
        }
        XCTAssertEqual(frames, [5, 65536, 65536, 65536, 8192, 4])
        XCTAssertNil(client.sessionRecoveryToken(), "a nonce-less pass-through consumes the token")
    }

    func testEmptyBodySourceIsBodyless() async throws {
        let seen = Captured()
        ScriptedURLProtocol.script = { request in
            seen.headers = request.allHTTPHeaderFields ?? [:]
            seen.hadBody = request.httpBodyStream != nil
            return (502, [:], Data())
        }
        let client = try await client()
        _ = try await client.request(method: "POST", path: "/secure", bodySource: { nil })
        XCTAssertNil(seen.headers["Ehbp-Encapsulated-Key"])
        XCTAssertFalse(seen.hadBody)
    }

    func testTransportFailureClearsTheTokenAndSurfacesTheNativeError() async throws {
        ScriptedURLProtocol.script = { _ in throw URLError(.networkConnectionLost) }
        let client = try await client()
        do {
            _ = try await client.request(method: "POST", path: "/secure", body: Data("secret".utf8))
            XCTFail("expected a failure")
        } catch {
            XCTAssertEqual((error as? URLError)?.code, .networkConnectionLost)
        }
        XCTAssertNil(client.sessionRecoveryToken())
    }

    func testAbandonedDecryptedStreamConsumesTheToken() async throws {
        // A 200 with a nonce and no body: Done is reached, the stream is dropped unread.
        ScriptedURLProtocol.script = { _ in (200, ["Ehbp-Response-Nonce": String(repeating: "0", count: 64)], Data()) }
        let client = try await client()
        func open() async throws {
            let (_, response) = try await client.requestStream(method: "POST", path: "/secure", body: Data("secret".utf8))
            XCTAssertEqual(response.statusCode, 200)
            XCTAssertNotNil(client.sessionRecoveryToken(), "the token lives while the decrypted body is unread")
        }
        try await open()
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertNil(client.sessionRecoveryToken())
    }

    func testCancellingARequestClearsTheToken() async throws {
        let started = expectation(description: "request reached the transport")
        ScriptedURLProtocol.script = { _ in started.fulfill(); Thread.sleep(forTimeInterval: 5); return (502, [:], Data()) }
        let client = try await client()
        let task = Task { try await client.request(method: "POST", path: "/secure", body: Data("secret".utf8)) }
        await fulfillment(of: [started], timeout: 5)
        XCTAssertNotNil(client.sessionRecoveryToken())
        task.cancel()
        _ = await task.result
        XCTAssertNil(client.sessionRecoveryToken())
    }
}

final class Captured: @unchecked Sendable {
    var headers: [String: String] = [:]
    var body = Data()
    var hadBody = false
}

final class ScriptedURLProtocol: URLProtocol {
    nonisolated(unsafe) static var script: ((URLRequest) throws -> (Int, [String: String], Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    static func drain(_ stream: InputStream) -> Data {
        stream.open()
        var out = Data()
        var buf = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = stream.read(&buf, maxLength: buf.count)
            if n <= 0 { return out }
            out.append(buf, count: n)
        }
    }

    override func startLoading() {
        do {
            let (status, headers, body) = try Self.script!(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
