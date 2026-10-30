import Crypto
import Foundation
import Network
import XCTest
@testable import EHBP

/// Per-request timeouts against a real local server, since a URLProtocol stub
/// cannot model idle time on the wire. Bodyless requests keep the exchange
/// unencrypted; the timeout applies the same way to an encrypted one.
final class RequestTimeoutTests: XCTestCase {
    private enum Overload: CaseIterable { case body, bodySource }

    private var server: SlowHTTPServer!

    override func tearDown() {
        server?.stop()
        server = nil
        super.tearDown()
    }

    private func makeClient(sessionTimeout: TimeInterval, steps: [SlowHTTPServer.Step]) throws -> EHBPClient {
        server = try SlowHTTPServer(steps: steps)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = sessionTimeout
        return try EHBPClient(
            baseURL: "http://127.0.0.1:\(server.port)",
            publicKey: Data(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )
    }

    private func request(_ client: EHBPClient, _ overload: Overload, timeoutInterval: TimeInterval?) async throws -> Data {
        switch overload {
        case .body:
            return try await client.request(method: "GET", path: "/", timeoutInterval: timeoutInterval, body: nil).data
        case .bodySource:
            return try await client.request(method: "GET", path: "/", timeoutInterval: timeoutInterval, bodySource: { nil }).data
        }
    }

    private func requestStream(_ client: EHBPClient, _ overload: Overload, timeoutInterval: TimeInterval?) async throws -> Data {
        let stream: AsyncThrowingStream<Data, Error>
        switch overload {
        case .body:
            stream = try await client.requestStream(method: "GET", path: "/", timeoutInterval: timeoutInterval, body: nil).stream
        case .bodySource:
            stream = try await client.requestStream(method: "GET", path: "/", timeoutInterval: timeoutInterval, bodySource: { nil }).stream
        }
        var data = Data()
        for try await chunk in stream { data.append(chunk) }
        return data
    }

    private func assertTimedOut(_ run: () async throws -> Data, file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await run()
            XCTFail("expected a timeout", file: file, line: line)
        } catch let error as URLError {
            XCTAssertEqual(error.code, .timedOut, file: file, line: line)
        } catch {
            XCTFail("expected URLError.timedOut, got \(error)", file: file, line: line)
        }
    }

    /// One-second silence before the response headers.
    private let slowHeaders: [SlowHTTPServer.Step] = [.wait(1), .headers, .chunk("hello"), .end]
    /// Headers and a first chunk at once, then one second of silence mid-body.
    private let slowBody: [SlowHTTPServer.Step] = [.headers, .chunk("hello"), .wait(1), .chunk(" world"), .end]

    // MARK: request

    func testShorterRequestTimeoutOverridesSession() async throws {
        for overload in Overload.allCases {
            let client = try makeClient(sessionTimeout: 2, steps: slowHeaders)
            await assertTimedOut { try await self.request(client, overload, timeoutInterval: 0.5) }
        }
    }

    func testLongerRequestTimeoutOverridesSession() async throws {
        for overload in Overload.allCases {
            let client = try makeClient(sessionTimeout: 0.5, steps: slowHeaders)
            let data = try await request(client, overload, timeoutInterval: 2)
            XCTAssertEqual(data, Data("hello".utf8))
        }
    }

    func testNilRequestTimeoutKeepsSessionTimeout() async throws {
        for overload in Overload.allCases {
            let client = try makeClient(sessionTimeout: 0.5, steps: slowHeaders)
            await assertTimedOut { try await self.request(client, overload, timeoutInterval: nil) }
        }
    }

    func testRequestTimeoutAppliesBetweenBodyChunks() async throws {
        var client = try makeClient(sessionTimeout: 0.5, steps: slowBody)
        let data = try await request(client, .body, timeoutInterval: 2)
        XCTAssertEqual(data, Data("hello world".utf8))

        server.stop()
        client = try makeClient(sessionTimeout: 2, steps: slowBody)
        await assertTimedOut { try await self.request(client, .body, timeoutInterval: 0.5) }
    }

    // MARK: requestStream

    func testStreamShorterRequestTimeoutOverridesSession() async throws {
        for overload in Overload.allCases {
            for steps in [slowHeaders, slowBody] {
                let client = try makeClient(sessionTimeout: 2, steps: steps)
                await assertTimedOut { try await self.requestStream(client, overload, timeoutInterval: 0.5) }
                server.stop()
            }
        }
    }

    func testStreamLongerRequestTimeoutOverridesSession() async throws {
        for overload in Overload.allCases {
            for (steps, expected) in [(slowHeaders, "hello"), (slowBody, "hello world")] {
                let client = try makeClient(sessionTimeout: 0.5, steps: steps)
                let data = try await requestStream(client, overload, timeoutInterval: 2)
                XCTAssertEqual(data, Data(expected.utf8))
                server.stop()
            }
        }
    }

    func testStreamNilRequestTimeoutKeepsSessionTimeout() async throws {
        for overload in Overload.allCases {
            for steps in [slowHeaders, slowBody] {
                let client = try makeClient(sessionTimeout: 0.5, steps: steps)
                await assertTimedOut { try await self.requestStream(client, overload, timeoutInterval: nil) }
                server.stop()
            }
        }
    }
}

/// Minimal HTTP/1.1 server on 127.0.0.1 that answers every request with a
/// chunked response paced by `steps`, so tests control when bytes arrive.
final class SlowHTTPServer: @unchecked Sendable {
    enum Step {
        case wait(TimeInterval)
        case headers
        case chunk(String)
        case end
    }

    private let listener: NWListener
    private let queue = DispatchQueue(label: "SlowHTTPServer")
    private let steps: [Step]
    let port: UInt16

    init(steps: [Step]) throws {
        self.steps = steps
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)

        let ready = DispatchSemaphore(value: 0)
        var failure: Error?
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.signal()
            case .failed(let error): failure = error; ready.signal()
            default: break
            }
        }
        listener.newConnectionHandler = { [steps, queue] connection in
            connection.start(queue: queue)
            SlowHTTPServer.readHead(connection, buffered: Data()) {
                SlowHTTPServer.run(steps[...], on: connection, queue: queue)
            }
        }
        listener.start(queue: queue)
        ready.wait()
        if let failure { throw failure }
        guard let port = listener.port?.rawValue else {
            throw EHBPError(.invalidInput, "listener has no port")
        }
        self.port = port
    }

    func stop() {
        listener.cancel()
    }

    private static func readHead(_ connection: NWConnection, buffered: Data, then respond: @escaping () -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
            let buffered = buffered + (data ?? Data())
            if buffered.range(of: Data("\r\n\r\n".utf8)) != nil {
                respond()
            } else if error == nil, !isComplete {
                readHead(connection, buffered: buffered, then: respond)
            } else {
                connection.cancel()
            }
        }
    }

    private static func run(_ steps: ArraySlice<Step>, on connection: NWConnection, queue: DispatchQueue) {
        guard let step = steps.first else {
            connection.send(content: nil, isComplete: true, completion: .contentProcessed { _ in connection.cancel() })
            return
        }
        let rest = steps.dropFirst()
        let bytes: String
        switch step {
        case .wait(let seconds):
            queue.asyncAfter(deadline: .now() + seconds) { run(rest, on: connection, queue: queue) }
            return
        case .headers:
            bytes = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        case .chunk(let text):
            bytes = String(text.utf8.count, radix: 16) + "\r\n" + text + "\r\n"
        case .end:
            bytes = "0\r\n\r\n"
        }
        connection.send(content: Data(bytes.utf8), completion: .contentProcessed { error in
            if error == nil { run(rest, on: connection, queue: queue) } else { connection.cancel() }
        })
    }
}
