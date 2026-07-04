import Crypto
import Darwin
import Foundation
import XCTest

@testable import EHBP

/// FIFO of server-side observations: synchronous producers (server threads)
/// and asynchronous consumers (tests).
final class EventQueue: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [String] = []
    private var waiters: [CheckedContinuation<String, Never>] = []

    func put(_ event: String) {
        lock.lock()
        if waiters.isEmpty {
            events.append(event)
            lock.unlock()
            return
        }
        let waiter = waiters.removeFirst()
        lock.unlock()
        waiter.resume(returning: event)
    }

    func next() async -> String {
        await withCheckedContinuation { continuation in
            lock.lock()
            if let event = events.first {
                events.removeFirst()
                lock.unlock()
                continuation.resume(returning: event)
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }
}

enum WSOpcode: UInt8 {
    case continuation = 0x0
    case text = 0x1
    case binary = 0x2
    case close = 0x8
    case ping = 0x9
    case pong = 0xA
}

enum SocketError: Error {
    case eof
    case posix(Int32)
    case protocolError(String)
}

/// Server side of one WebSocket connection over a raw BSD socket, exposing
/// the encrypted record layer to test behaviors. RFC 6455 framing only, as
/// needed by these tests.
final class RawWSConnection: @unchecked Sendable {
    let fd: Int32
    var sendCipher: NoiseRecordCipher?
    var recvCipher: NoiseRecordCipher?
    private var closeSent = false

    enum ReadResult {
        case data(Data)
        case eof
        case truncated
        case failed(String)
    }

    init(fd: Int32) {
        self.fd = fd
    }

    // MARK: - Raw socket I/O

    private func readExact(_ count: Int) throws -> Data {
        var buffer = Data()
        while buffer.count < count {
            var chunk = [UInt8](repeating: 0, count: count - buffer.count)
            let received = recv(fd, &chunk, chunk.count, 0)
            if received == 0 { throw SocketError.eof }
            if received < 0 { throw SocketError.posix(errno) }
            buffer.append(contentsOf: chunk[0..<received])
        }
        return buffer
    }

    func writeAll(_ data: Data) throws {
        var offset = 0
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            while offset < data.count {
                let sent = send(fd, raw.baseAddress! + offset, data.count - offset, 0)
                if sent <= 0 { throw SocketError.posix(errno) }
                offset += sent
            }
        }
    }

    // MARK: - WebSocket framing

    /// Reads one frame, unmasking client payloads.
    private func readFrame() throws -> (opcode: UInt8, fin: Bool, payload: Data) {
        let header = try readExact(2)
        let fin = header[0] & 0x80 != 0
        let opcode = header[0] & 0x0F
        let masked = header[1] & 0x80 != 0
        var length = Int(header[1] & 0x7F)
        if length == 126 {
            let extended = try readExact(2)
            length = Int(extended[0]) << 8 | Int(extended[1])
        } else if length == 127 {
            let extended = try readExact(8)
            length = extended.reduce(0) { ($0 << 8) | Int($1) }
        }
        var maskKey = Data()
        if masked {
            maskKey = try readExact(4)
        }
        var payload = try readExact(length)
        if masked {
            for index in 0..<payload.count {
                payload[index] ^= maskKey[index % 4]
            }
        }
        return (opcode, fin, payload)
    }

    /// Reads one message, assembling fragments and answering pings.
    func readMessage() throws -> (opcode: WSOpcode, payload: Data) {
        var assembled = Data()
        var messageOpcode: WSOpcode?
        while true {
            let (rawOpcode, fin, payload) = try readFrame()
            switch rawOpcode {
            case WSOpcode.ping.rawValue:
                try writeFrame(opcode: .pong, payload: payload)
            case WSOpcode.pong.rawValue:
                continue
            case WSOpcode.close.rawValue:
                return (.close, payload)
            case WSOpcode.text.rawValue, WSOpcode.binary.rawValue:
                messageOpcode = WSOpcode(rawValue: rawOpcode)
                assembled = payload
                if fin { return (messageOpcode!, assembled) }
            case WSOpcode.continuation.rawValue:
                guard messageOpcode != nil else {
                    throw SocketError.protocolError("continuation without start frame")
                }
                assembled += payload
                if fin { return (messageOpcode!, assembled) }
            default:
                throw SocketError.protocolError("unexpected opcode \(rawOpcode)")
            }
        }
    }

    /// Writes one server frame (servers never mask).
    func writeFrame(opcode: WSOpcode, payload: Data) throws {
        var frame = Data([0x80 | opcode.rawValue])
        if payload.count < 126 {
            frame.append(UInt8(payload.count))
        } else if payload.count <= 0xFFFF {
            frame.append(126)
            frame.append(UInt8(payload.count >> 8))
            frame.append(UInt8(payload.count & 0xFF))
        } else {
            frame.append(127)
            withUnsafeBytes(of: UInt64(payload.count).bigEndian) { frame.append(contentsOf: $0) }
        }
        frame += payload
        try writeAll(frame)
    }

    // MARK: - Encrypted record layer

    func encryptRecord(_ record: Data) throws -> Data {
        guard var cipher = sendCipher else { throw EHBPError.invalidInput("no send cipher") }
        let ciphertext = try cipher.encrypt(record)
        sendCipher = cipher
        return ciphertext
    }

    private func decryptRecord(_ ciphertext: Data) throws -> Data {
        guard var cipher = recvCipher else { throw EHBPError.invalidInput("no recv cipher") }
        let record = try cipher.decrypt(ciphertext)
        recvCipher = cipher
        return record
    }

    func writeRecord(payload: Data) throws {
        let ciphertext = try encryptRecord(Data([NoiseWebSocketProtocol.recordData]) + payload)
        try writeFrame(opcode: .binary, payload: ciphertext)
    }

    func readRecord() -> ReadResult {
        while true {
            let opcode: WSOpcode
            let payload: Data
            do {
                (opcode, payload) = try readMessage()
            } catch {
                return .truncated
            }
            switch opcode {
            case .binary:
                let record: Data
                do {
                    record = try decryptRecord(payload)
                } catch {
                    return .failed("decrypt: \(error)")
                }
                guard let recordType = record.first else { return .failed("empty record") }
                switch recordType {
                case NoiseWebSocketProtocol.recordData:
                    return .data(Data(record.dropFirst()))
                case NoiseWebSocketProtocol.recordClose:
                    return .eof
                default:
                    return .failed("unknown record type")
                }
            case .close:
                // A close frame without a close record is unauthenticated.
                return .truncated
            default:
                return .failed("unexpected opcode \(opcode)")
            }
        }
    }

    /// Responds to the peer's close record and completes the WebSocket
    /// close handshake; the peer may already have torn the connection down.
    func respondCloseAndShutdown() {
        if !closeSent {
            closeSent = true
            if let ciphertext = try? encryptRecord(Data([NoiseWebSocketProtocol.recordClose])) {
                try? writeFrame(opcode: .binary, payload: ciphertext)
            }
        }
        try? writeFrame(opcode: .close, payload: Data([0x03, 0xE8]))
        close(fd)
    }

    /// Closes the WebSocket without sending an encrypted close record,
    /// simulating truncation by an intermediary.
    func shutdownWithoutCloseRecord() {
        try? writeFrame(opcode: .close, payload: Data([0x03, 0xE8]))
        close(fd)
    }

    func abortTCP() {
        close(fd)
    }
}

typealias TestBehavior = @Sendable (RawWSConnection, EventQueue) -> Void

/// In-process WebSocket server over BSD sockets, running the Noise
/// responder handshake and handing the encrypted record layer to a per-test
/// behavior.
final class NoiseWSTestServer: @unchecked Sendable {
    let identity: Identity
    let url: URL
    let events = EventQueue()
    private let listenFD: Int32
    private let staticKey: Curve25519.KeyAgreement.PrivateKey
    private let negotiateSubprotocol: Bool
    private let stallHandshakeReply: Bool
    private let rekeyInterval: UInt64
    private let behavior: TestBehavior

    init(
        negotiateSubprotocol: Bool = true,
        stallHandshakeReply: Bool = false,
        rekeyInterval: UInt64 = NoiseWebSocketProtocol.rekeyInterval,
        behavior: @escaping TestBehavior
    ) throws {
        self.staticKey = Curve25519.KeyAgreement.PrivateKey()
        self.identity = try Identity(publicKeyBytes: staticKey.publicKey.rawRepresentation)
        self.negotiateSubprotocol = negotiateSubprotocol
        self.stallHandshakeReply = stallHandshakeReply
        self.rekeyInterval = rekeyInterval
        self.behavior = behavior

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.posix(errno) }
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr = in_addr(s_addr: in_addr_t(UInt32(0x7F00_0001).bigEndian))
        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else { throw SocketError.posix(errno) }
        guard listen(fd, 8) == 0 else { throw SocketError.posix(errno) }

        var bound = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &bound) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                _ = getsockname(fd, $0, &boundLength)
            }
        }
        let port = UInt16(bigEndian: bound.sin_port)
        self.listenFD = fd
        self.url = URL(string: "ws://127.0.0.1:\(port)")!

        let thread = Thread { [weak self] in
            while true {
                let connFD = accept(fd, nil, nil)
                guard connFD >= 0 else { return }
                guard let self else {
                    close(connFD)
                    return
                }
                var noSigpipe: Int32 = 1
                setsockopt(
                    connFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe,
                    socklen_t(MemoryLayout<Int32>.size))
                let connectionThread = Thread { self.handle(connFD: connFD) }
                connectionThread.start()
            }
        }
        thread.start()
    }

    func stop() {
        close(listenFD)
    }

    private func handle(connFD: Int32) {
        let conn = RawWSConnection(fd: connFD)
        do {
            try upgrade(conn)
        } catch {
            conn.abortTCP()
            events.put("upgrade-error: \(error)")
            return
        }
        if stallHandshakeReply {
            // Read the client's handshake message but never reply,
            // simulating a stalled or hostile peer.
            _ = try? conn.readMessage()
            Thread.sleep(forTimeInterval: 5)
            conn.abortTCP()
            return
        }
        do {
            var handshake = try NoiseHandshakeState(
                role: .responder,
                prologue: Data(NoiseWebSocketProtocol.prologue.utf8),
                localStaticKey: staticKey
            )
            let (opcode, message1) = try conn.readMessage()
            guard opcode == .binary else {
                throw EHBPError.handshakeFailed("handshake message must be binary")
            }
            _ = try handshake.readMessage1(message1)
            try conn.writeFrame(opcode: .binary, payload: handshake.writeMessage2())
            let (clientToServer, serverToClient) = handshake.split()
            conn.sendCipher = NoiseRecordCipher(key: serverToClient, rekeyInterval: rekeyInterval)
            conn.recvCipher = NoiseRecordCipher(key: clientToServer, rekeyInterval: rekeyInterval)
        } catch {
            conn.abortTCP()
            events.put("handshake-error: \(error)")
            return
        }
        behavior(conn, events)
    }

    /// Minimal RFC 6455 server upgrade.
    private func upgrade(_ conn: RawWSConnection) throws {
        var request = Data()
        let terminator = Data("\r\n\r\n".utf8)
        while request.range(of: terminator) == nil {
            guard request.count < 16384 else {
                throw SocketError.protocolError("upgrade request too large")
            }
            var byte = [UInt8](repeating: 0, count: 1)
            let received = recv(conn.fd, &byte, 1, 0)
            if received <= 0 { throw SocketError.eof }
            request.append(byte[0])
        }
        guard let text = String(data: request, encoding: .utf8) else {
            throw SocketError.protocolError("upgrade request is not UTF-8")
        }
        var websocketKey: String?
        var offeredProtocols: [String] = []
        for line in text.components(separatedBy: "\r\n").dropFirst() {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let name = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            if name == "sec-websocket-key" {
                websocketKey = value
            } else if name == "sec-websocket-protocol" {
                offeredProtocols += value.split(separator: ",").map {
                    $0.trimmingCharacters(in: .whitespaces)
                }
            }
        }
        guard let websocketKey else {
            throw SocketError.protocolError("missing Sec-WebSocket-Key")
        }
        let acceptSeed = websocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        let acceptKey = Data(Insecure.SHA1.hash(data: Data(acceptSeed.utf8)))
            .base64EncodedString()
        var response =
            "HTTP/1.1 101 Switching Protocols\r\n"
            + "Upgrade: websocket\r\n"
            + "Connection: Upgrade\r\n"
            + "Sec-WebSocket-Accept: \(acceptKey)\r\n"
        if negotiateSubprotocol, offeredProtocols.contains(NoiseWebSocketProtocol.subprotocol) {
            response += "Sec-WebSocket-Protocol: \(NoiseWebSocketProtocol.subprotocol)\r\n"
        }
        response += "\r\n"
        try conn.writeAll(Data(response.utf8))
    }
}

let echoBehavior: TestBehavior = { conn, events in
    while true {
        switch conn.readRecord() {
        case .data(let payload):
            do {
                try conn.writeRecord(payload: payload)
            } catch {
                events.put("write-error: \(error)")
                return
            }
        case .eof:
            conn.respondCloseAndShutdown()
            events.put("eof")
            return
        case .truncated:
            events.put("truncated")
            return
        case .failed(let detail):
            events.put("failed: \(detail)")
            return
        }
    }
}

final class NoiseWebSocketTests: XCTestCase {

    func testEchoRoundTripAndCleanClose() async throws {
        let server = try NoiseWSTestServer(behavior: echoBehavior)
        defer { server.stop() }
        let channel = try await NoiseWebSocketChannel.connect(
            url: server.url, identity: server.identity)

        for message in [Data("hello".utf8), Data(), Data("second message".utf8)] {
            try await channel.send(message)
            let got = try await channel.receive()
            XCTAssertEqual(got, message)
        }

        try await channel.close()
        let event = await server.events.next()
        XCTAssertEqual(event, "eof")

        do {
            try await channel.send(Data("after close".utf8))
            XCTFail("send after close should fail")
        } catch let error as EHBPError {
            guard case .channelClosed = error else {
                XCTFail("expected channelClosed, got \(error)")
                return
            }
        }
    }

    func testReceiveAfterPeerCloseReturnsNil() async throws {
        let closeImmediately: TestBehavior = { conn, _ in
            if let ciphertext = try? conn.encryptRecord(
                Data([NoiseWebSocketProtocol.recordClose]))
            {
                try? conn.writeFrame(opcode: .binary, payload: ciphertext)
            }
            _ = conn.readRecord()
            conn.respondCloseAndShutdown()
        }
        let server = try NoiseWSTestServer(behavior: closeImmediately)
        defer { server.stop() }
        let channel = try await NoiseWebSocketChannel.connect(
            url: server.url, identity: server.identity)

        let first = try await channel.receive()
        XCTAssertNil(first)
        let second = try await channel.receive()
        XCTAssertNil(second)
    }

    func testReceiveRacingLocalCloseNeverReturnsData() async throws {
        let sendThenAwaitClose: TestBehavior = { conn, events in
            if let ciphertext = try? conn.encryptRecord(
                Data([NoiseWebSocketProtocol.recordData]) + Data("late".utf8))
            {
                try? conn.writeFrame(opcode: .binary, payload: ciphertext)
            }
            _ = conn.readRecord()
            conn.respondCloseAndShutdown()
            events.put("done")
        }
        let server = try NoiseWSTestServer(behavior: sendThenAwaitClose)
        defer { server.stop() }
        let channel = try await NoiseWebSocketChannel.connect(
            url: server.url, identity: server.identity)

        // close() sets its closed flag before it awaits sending its own
        // close record, so a concurrent receive() can observe the flag
        // while the transport is still alive. Racing the two here checks
        // that receive() always honors the flag instead of depending on
        // whether it wins or loses that race against the transport.
        async let receiveResult: Data? = channel.receive()
        try await channel.close()
        do {
            _ = try await receiveResult
            XCTFail("receive racing a local close should never return data")
        } catch let error as EHBPError {
            guard case .channelClosed = error else {
                XCTFail("expected channelClosed, got \(error)")
                return
            }
        }
    }

    func testWrongServerKeyFailsHandshake() async throws {
        let server = try NoiseWSTestServer(behavior: echoBehavior)
        defer { server.stop() }
        let wrongKey = Curve25519.KeyAgreement.PrivateKey()
        let wrongIdentity = try Identity(
            publicKeyBytes: wrongKey.publicKey.rawRepresentation)

        do {
            _ = try await NoiseWebSocketChannel.connect(url: server.url, identity: wrongIdentity)
            XCTFail("dial with wrong server key should fail the handshake")
        } catch let error as EHBPError {
            guard case .handshakeFailed = error else {
                XCTFail("expected handshakeFailed, got \(error)")
                return
            }
        }
    }

    func testTamperedRecordFailsClosed() async throws {
        let tamper: TestBehavior = { conn, _ in
            guard
                var ciphertext = try? conn.encryptRecord(
                    Data([NoiseWebSocketProtocol.recordData]) + Data("hi".utf8))
            else { return }
            ciphertext[0] ^= 0xFF
            try? conn.writeFrame(opcode: .binary, payload: ciphertext)
            // Keep the socket open so the client failure comes from the
            // AEAD, not from the transport ending.
            _ = conn.readRecord()
        }
        let server = try NoiseWSTestServer(behavior: tamper)
        defer { server.stop() }
        let channel = try await NoiseWebSocketChannel.connect(
            url: server.url, identity: server.identity)

        for attempt in 0..<2 {
            do {
                _ = try await channel.receive()
                XCTFail("tampered record should fail decryption (attempt \(attempt))")
            } catch let error as EHBPError {
                guard case .decryptionFailed = error else {
                    XCTFail("expected decryptionFailed, got \(error)")
                    return
                }
            }
        }
    }

    func testTruncationDetected() async throws {
        let truncate: TestBehavior = { conn, _ in
            guard case .data(let payload) = conn.readRecord() else { return }
            try? conn.writeRecord(payload: payload)
            conn.shutdownWithoutCloseRecord()
        }
        let server = try NoiseWSTestServer(behavior: truncate)
        defer { server.stop() }
        let channel = try await NoiseWebSocketChannel.connect(
            url: server.url, identity: server.identity)

        try await channel.send(Data("last message".utf8))
        let echoed = try await channel.receive()
        XCTAssertEqual(echoed, Data("last message".utf8))

        for attempt in 0..<2 {
            do {
                _ = try await channel.receive()
                XCTFail("client should see truncation (attempt \(attempt))")
            } catch let error as EHBPError {
                guard case .channelTruncated = error else {
                    XCTFail("expected channelTruncated, got \(error)")
                    return
                }
            }
        }
    }

    func testRekeyKeepsDirectionsInSync() async throws {
        let server = try NoiseWSTestServer(rekeyInterval: 3, behavior: echoBehavior)
        defer { server.stop() }
        let channel = try await NoiseWebSocketChannel.connect(
            url: server.url,
            identity: server.identity,
            maxMessageSize: NoiseWebSocketProtocol.defaultMaxMessageSize,
            session: .shared,
            rekeyInterval: 3
        )

        let payload = Data(repeating: UInt8(ascii: "x"), count: 100)
        for index in 0..<10 {
            try await channel.send(payload)
            let got = try await channel.receive()
            XCTAssertEqual(got, payload, "echo mismatch on message \(index)")
        }
        try await channel.close()
        let event = await server.events.next()
        XCTAssertEqual(event, "eof")
    }

    func testOversizedWriteRejected() async throws {
        let server = try NoiseWSTestServer(behavior: echoBehavior)
        defer { server.stop() }
        let channel = try await NoiseWebSocketChannel.connect(
            url: server.url, identity: server.identity, maxMessageSize: 16)

        do {
            try await channel.send(Data(repeating: 0, count: 17))
            XCTFail("oversized write should fail")
        } catch let error as EHBPError {
            guard case .invalidInput = error else {
                XCTFail("expected invalidInput, got \(error)")
                return
            }
        }
        try await channel.send(Data(repeating: 0, count: 16))
        let got = try await channel.receive()
        XCTAssertEqual(got, Data(repeating: 0, count: 16))
    }

    func testOversizedInboundRecordFailsConnection() async throws {
        // The server's cap is larger than the client's, so it can produce a
        // record that fits the client's WebSocket read limit margin but
        // exceeds the client's payload cap.
        let oversized: TestBehavior = { conn, _ in
            try? conn.writeRecord(payload: Data(repeating: UInt8(ascii: "x"), count: 32))
            _ = conn.readRecord()
        }
        let server = try NoiseWSTestServer(behavior: oversized)
        defer { server.stop() }
        let channel = try await NoiseWebSocketChannel.connect(
            url: server.url, identity: server.identity, maxMessageSize: 16)

        do {
            _ = try await channel.receive()
            XCTFail("oversized inbound record should fail the connection")
        } catch let error as EHBPError {
            guard case .protocolViolation(let detail) = error else {
                XCTFail("expected protocolViolation, got \(error)")
                return
            }
            XCTAssertTrue(detail.contains("exceeds maximum size"), "unexpected detail: \(detail)")
        }
    }

    func testDialRequiresNegotiatedSubprotocol() async throws {
        let server = try NoiseWSTestServer(negotiateSubprotocol: false, behavior: echoBehavior)
        defer { server.stop() }

        do {
            _ = try await NoiseWebSocketChannel.connect(url: server.url, identity: server.identity)
            XCTFail("dial should fail on missing subprotocol")
        } catch let error as EHBPError {
            guard case .handshakeFailed(let detail) = error else {
                XCTFail("expected handshakeFailed, got \(error)")
                return
            }
            XCTAssertTrue(detail.contains("subprotocol"), "unexpected detail: \(detail)")
        }
    }

    func testConnectHandshakeTimeout() async throws {
        let server = try NoiseWSTestServer(stallHandshakeReply: true, behavior: echoBehavior)
        defer { server.stop() }

        let clock = ContinuousClock()
        let start = clock.now
        do {
            _ = try await NoiseWebSocketChannel.connect(
                url: server.url, identity: server.identity, handshakeTimeout: .milliseconds(200))
            XCTFail("connect should time out waiting for the handshake reply")
        } catch let error as EHBPError {
            guard case .handshakeFailed(let detail) = error else {
                XCTFail("expected handshakeFailed, got \(error)")
                return
            }
            XCTAssertTrue(detail.contains("timed out"), "unexpected detail: \(detail)")
        }
        XCTAssertLessThan(clock.now - start, .seconds(2))
    }

    // MARK: - Cross-Language Interop Tests

    private func vectorsDir() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // EHBPTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // swift/
            .deletingLastPathComponent()  // repo root
            .appendingPathComponent("test-vectors")
    }

    func testNoiseWebSocketInteropVector() throws {
        struct VectorRecord: Decodable {
            let dir: String
            let type: String
            let payload: String
            let ciphertext: String
        }
        struct WSVector: Decodable {
            let protocolName: String
            let prologue: String
            let serverStaticPrivate: String
            let serverStaticPublic: String
            let clientEphemeralPrivate: String
            let serverEphemeralPrivate: String
            let message1: String
            let message2: String
            let handshakeHash: String
            let rekeyInterval: UInt64
            let records: [VectorRecord]
        }

        let vectorPath = vectorsDir().appendingPathComponent("noisews.json")
        let vector = try JSONDecoder().decode(WSVector.self, from: Data(contentsOf: vectorPath))

        XCTAssertEqual(vector.protocolName, NoiseWebSocketProtocol.protocolName)
        XCTAssertEqual(vector.prologue, NoiseWebSocketProtocol.prologue)

        let prologue = Data(vector.prologue.utf8)
        var initiator = try NoiseHandshakeState(
            role: .initiator,
            prologue: prologue,
            remoteStaticKey: Data(hexString: vector.serverStaticPublic)!,
            ephemeral: Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: Data(hexString: vector.clientEphemeralPrivate)!)
        )
        var responder = try NoiseHandshakeState(
            role: .responder,
            prologue: prologue,
            localStaticKey: Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: Data(hexString: vector.serverStaticPrivate)!),
            ephemeral: Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: Data(hexString: vector.serverEphemeralPrivate)!)
        )

        let message1 = try initiator.writeMessage1()
        XCTAssertEqual(message1.hexString, vector.message1)
        _ = try responder.readMessage1(message1)

        let message2 = try responder.writeMessage2()
        XCTAssertEqual(message2.hexString, vector.message2)
        _ = try initiator.readMessage2(message2)

        XCTAssertEqual(initiator.handshakeHash.hexString, vector.handshakeHash)
        XCTAssertEqual(responder.handshakeHash.hexString, vector.handshakeHash)

        let (clientSendKey, clientRecvKey) = initiator.split()
        let (serverRecvKey, serverSendKey) = responder.split()
        XCTAssertEqual(clientSendKey, serverRecvKey)
        XCTAssertEqual(clientRecvKey, serverSendKey)

        var clientSend = NoiseRecordCipher(key: clientSendKey, rekeyInterval: vector.rekeyInterval)
        var clientRecv = NoiseRecordCipher(key: clientRecvKey, rekeyInterval: vector.rekeyInterval)
        var serverSend = NoiseRecordCipher(key: serverSendKey, rekeyInterval: vector.rekeyInterval)
        var serverRecv = NoiseRecordCipher(key: serverRecvKey, rekeyInterval: vector.rekeyInterval)

        for (index, entry) in vector.records.enumerated() {
            let recordType: UInt8
            switch entry.type {
            case "data": recordType = NoiseWebSocketProtocol.recordData
            case "close": recordType = NoiseWebSocketProtocol.recordClose
            default:
                XCTFail("record \(index): unknown type \(entry.type)")
                return
            }
            let record = Data([recordType]) + Data(hexString: entry.payload)!

            let ciphertext: Data
            let roundTrip: Data
            switch entry.dir {
            case "c2s":
                ciphertext = try clientSend.encrypt(record)
                roundTrip = try serverRecv.decrypt(ciphertext)
            case "s2c":
                ciphertext = try serverSend.encrypt(record)
                roundTrip = try clientRecv.decrypt(ciphertext)
            default:
                XCTFail("record \(index): unknown dir \(entry.dir)")
                return
            }
            XCTAssertEqual(
                ciphertext.hexString, entry.ciphertext, "record \(index) ciphertext mismatch")
            XCTAssertEqual(roundTrip, record, "record \(index) round trip mismatch")
        }

        // Not part of the vector, but keep the default schedule aligned
        // with the reference implementation.
        XCTAssertEqual(NoiseWebSocketProtocol.rekeyInterval, 1 << 16)
    }
}
