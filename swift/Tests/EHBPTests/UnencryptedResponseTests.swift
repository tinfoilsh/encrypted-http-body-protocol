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
        UnencryptedResponseURLProtocol.finishLoading?()
        UnencryptedResponseURLProtocol.finishLoading = nil
        UnencryptedResponseURLProtocol.streamWithoutFinishing = false
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

    func testStreamingPassThroughYieldsBeforeEndOfResponse() async throws {
        UnencryptedResponseURLProtocol.streamWithoutFinishing = true
        let client = try makeClient(statusCode: 429)
        let (stream, _) = try await client.requestStream(
            method: "POST",
            path: "/secure",
            body: Data("hello".utf8)
        )

        let yielded = expectation(description: "pass-through chunk yielded before EOF")
        let task = Task {
            do {
                var iterator = stream.makeAsyncIterator()
                let chunk = try await iterator.next()
                XCTAssertEqual(chunk?.count, UnencryptedResponseURLProtocol.streamingChunkSize)
                yielded.fulfill()
            } catch {
                XCTFail("unexpected stream error: \(error)")
            }
        }

        await fulfillment(of: [yielded], timeout: 2)
        UnencryptedResponseURLProtocol.finishLoading?()
        UnencryptedResponseURLProtocol.finishLoading = nil
        _ = await task.result
    }

    func testPassThroughChunkerReadsOnlyWhenConsumerRequestsNextChunk() async throws {
        let source = CountingByteSource(bytes: Array(0..<10))
        let chunker = PullDrivenByteChunker(
            iterator: source.makeIterator(),
            chunkSize: CountingByteSource.testChunkSize
        )
        let stream = AsyncThrowingStream<Data, Error>(unfolding: {
            try await chunker.next()
        })

        XCTAssertEqual(source.bytesRead, 0)
        var iterator = stream.makeAsyncIterator()
        let first = try await iterator.next()
        XCTAssertEqual(first, Data([0, 1, 2, 3]))
        XCTAssertEqual(source.bytesRead, CountingByteSource.testChunkSize)

        let second = try await iterator.next()
        XCTAssertEqual(second, Data([4, 5, 6, 7]))
        XCTAssertEqual(source.bytesRead, CountingByteSource.testChunkSize * 2)

        let final = try await iterator.next()
        XCTAssertEqual(final, Data([8, 9]))
        XCTAssertEqual(source.bytesRead, 10)
        let end = try await iterator.next()
        XCTAssertNil(end)
    }
}

private final class UnencryptedResponseURLProtocol: URLProtocol {
    nonisolated(unsafe) static var statusCode = 500
    nonisolated(unsafe) static var streamWithoutFinishing = false
    nonisolated(unsafe) static var finishLoading: (() -> Void)?
    static let streamingChunkSize = 16 * 1024

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
        if Self.streamWithoutFinishing {
            client?.urlProtocol(self, didLoad: Data(repeating: 0x41, count: Self.streamingChunkSize))
            Self.finishLoading = { [weak self] in
                guard let self else { return }
                self.client?.urlProtocolDidFinishLoading(self)
            }
            return
        }
        client?.urlProtocol(self, didLoad: Data("upstream unavailable".utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

final class CountingByteSource: @unchecked Sendable {
    static let testChunkSize = 4

    private let lock = NSLock()
    private let bytes: [UInt8]
    private var index = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    var bytesRead: Int {
        lock.lock()
        defer { lock.unlock() }
        return index
    }

    func makeIterator() -> Iterator {
        Iterator(source: self)
    }

    struct Iterator: AsyncIteratorProtocol, Sendable {
        let source: CountingByteSource

        mutating func next() async -> UInt8? {
            source.next()
        }
    }

    private func next() -> UInt8? {
        lock.lock()
        defer { lock.unlock() }
        guard index < bytes.count else { return nil }
        let byte = bytes[index]
        index += 1
        return byte
    }
}
