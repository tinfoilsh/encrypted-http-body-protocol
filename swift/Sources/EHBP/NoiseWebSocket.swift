// End-to-end encrypted WebSocket channels for EHBP (EHBP-WS, SPEC Section 8).
//
// The channel runs the Noise NK handshake (Noise_NK_25519_AESGCM_SHA256)
// inside WebSocket binary messages: the client authenticates the server by
// its X25519 static key (the EHBP HPKE identity key) while remaining
// anonymous itself, mirroring the trust model of the HTTP mode. The
// WebSocket upgrade request and control frames stay in cleartext so
// intermediaries can route the connection; every application message is
// carried as an encrypted record inside a binary frame.
//
// Termination is authenticated: peers exchange an encrypted close record
// before the WebSocket close handshake, so truncation by an intermediary is
// distinguishable from an intentional shutdown (EHBPError.channelTruncated).

import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Resolves once the WebSocket upgrade completes (or fails), reporting the
/// negotiated subprotocol.
private final class WebSocketOpenDelegate: NSObject, URLSessionWebSocketDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<String?, Error>?

    init(_ continuation: CheckedContinuation<String?, Error>) {
        self.continuation = continuation
    }

    private func resume(_ result: Result<String?, Error>) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        switch result {
        case .success(let value): continuation?.resume(returning: value)
        case .failure(let error): continuation?.resume(throwing: error)
        }
    }

    func urlSession(
        _ session: URLSession, webSocketTask: URLSessionWebSocketTask,
        didOpenWithProtocol protocolName: String?
    ) {
        resume(.success(protocolName))
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?
    ) {
        resume(.failure(error ?? EHBPError.webSocketError("connection closed during upgrade")))
    }
}

/// A message-oriented connection whose payloads are encrypted end-to-end
/// inside WebSocket binary messages.
public actor NoiseWebSocketChannel {
    private let task: URLSessionWebSocketTask
    private var sendCipher: NoiseRecordCipher
    private var recvCipher: NoiseRecordCipher
    private let maxMessageSize: Int
    private var peerClosed = false
    private var closeSent = false
    private var localClosed = false
    private var sticky: EHBPError?

    private init(
        task: URLSessionWebSocketTask,
        sendKey: Data,
        recvKey: Data,
        maxMessageSize: Int,
        rekeyInterval: UInt64
    ) {
        self.task = task
        self.sendCipher = NoiseRecordCipher(key: sendKey, rekeyInterval: rekeyInterval)
        self.recvCipher = NoiseRecordCipher(key: recvKey, rekeyInterval: rekeyInterval)
        self.maxMessageSize = maxMessageSize
    }

    /// Opens a WebSocket connection to `url` (ws, wss, http, or https
    /// scheme) and runs the Noise handshake against the server identity's
    /// public key. No application data is sent before the handshake
    /// completes.
    ///
    /// `maxMessageSize` caps the payload size of a single record in both
    /// directions; both peers should agree on the cap.
    public static func connect(
        url: URL,
        identity: Identity,
        maxMessageSize: Int = NoiseWebSocketProtocol.defaultMaxMessageSize,
        session: URLSession = .shared
    ) async throws -> NoiseWebSocketChannel {
        try await connect(
            url: url,
            identity: identity,
            maxMessageSize: maxMessageSize,
            session: session,
            rekeyInterval: NoiseWebSocketProtocol.rekeyInterval
        )
    }

    /// The rekey interval is a parameter only so tests can exercise the
    /// schedule cheaply; peers that disagree on it fail authentication.
    internal static func connect(
        url: URL,
        identity: Identity,
        maxMessageSize: Int,
        session: URLSession,
        rekeyInterval: UInt64
    ) async throws -> NoiseWebSocketChannel {
        let wsURL = try webSocketURL(from: url)
        let task = session.webSocketTask(
            with: wsURL, protocols: [NoiseWebSocketProtocol.subprotocol]
        )
        task.maximumMessageSize = maxMessageSize + NoiseWebSocketProtocol.recordOverhead

        let negotiated: String?
        do {
            negotiated = try await withCheckedThrowingContinuation { continuation in
                task.delegate = WebSocketOpenDelegate(continuation)
                task.resume()
            }
        } catch let error as EHBPError {
            throw error
        } catch {
            throw EHBPError.webSocketError("dial: \(error.localizedDescription)")
        }
        guard negotiated == NoiseWebSocketProtocol.subprotocol else {
            task.cancel(
                with: .policyViolation, reason: Data("ehbp noise subprotocol required".utf8)
            )
            throw EHBPError.handshakeFailed("server did not accept required subprotocol")
        }

        do {
            var handshake = try NoiseHandshakeState(
                role: .initiator,
                prologue: Data(NoiseWebSocketProtocol.prologue.utf8),
                remoteStaticKey: identity.publicKeyBytes
            )
            try await task.send(.data(handshake.writeMessage1()))
            guard case .data(let message2) = try await task.receive() else {
                throw EHBPError.handshakeFailed("handshake message must be binary")
            }
            guard message2.count <= NoiseWebSocketProtocol.handshakeReadLimit else {
                throw EHBPError.handshakeFailed(
                    "handshake message of \(message2.count) bytes exceeds limit "
                        + "\(NoiseWebSocketProtocol.handshakeReadLimit)"
                )
            }
            // Receivers must ignore any handshake payload present.
            _ = try handshake.readMessage2(message2)
            let (sendKey, recvKey) = handshake.split()
            return NoiseWebSocketChannel(
                task: task,
                sendKey: sendKey,
                recvKey: recvKey,
                maxMessageSize: maxMessageSize,
                rekeyInterval: rekeyInterval
            )
        } catch {
            task.cancel(with: .policyViolation, reason: Data("handshake failed".utf8))
            if let error = error as? EHBPError {
                throw error
            }
            throw EHBPError.handshakeFailed("handshake failed: \(error.localizedDescription)")
        }
    }

    private static func webSocketURL(from url: URL) throws -> URL {
        let scheme = url.scheme?.lowercased()
        let mapped: String
        switch scheme {
        case "ws", "wss":
            return url
        case "http":
            mapped = "ws"
        case "https":
            mapped = "wss"
        default:
            throw EHBPError.invalidInput("unsupported URL scheme \(scheme ?? "nil")")
        }
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw EHBPError.invalidInput("invalid URL")
        }
        components.scheme = mapped
        guard let wsURL = components.url else {
            throw EHBPError.invalidInput("invalid URL")
        }
        return wsURL
    }

    /// Encrypts `payload` as a single data record and sends it as one
    /// WebSocket binary message.
    public func send(_ payload: Data) async throws {
        guard payload.count <= maxMessageSize else {
            throw EHBPError.invalidInput(
                "message of \(payload.count) bytes exceeds maximum size \(maxMessageSize)"
            )
        }
        if closeSent || localClosed {
            throw EHBPError.channelClosed
        }
        let record = Data([NoiseWebSocketProtocol.recordData]) + payload
        let ciphertext = try sendCipher.encrypt(record)
        do {
            try await task.send(.data(ciphertext))
        } catch {
            throw EHBPError.webSocketError(error.localizedDescription)
        }
    }

    /// Receives one record and returns its decrypted payload.
    ///
    /// Returns `nil` after the peer's encrypted close record. Throws
    /// `EHBPError.channelClosed` if the transport ends after a local close
    /// and `EHBPError.channelTruncated` if the connection ends without the
    /// peer's close record. Errors are terminal and sticky.
    public func receive() async throws -> Data? {
        if peerClosed {
            return nil
        }
        if let sticky {
            throw sticky
        }
        let message: URLSessionWebSocketTask.Message
        do {
            message = try await task.receive()
        } catch {
            throw transportEnded(error.localizedDescription)
        }
        guard case .data(let ciphertext) = message else {
            throw terminate(.protocolViolation("unexpected text message"))
        }
        let record: Data
        do {
            record = try recvCipher.decrypt(ciphertext)
        } catch let error as EHBPError {
            throw terminate(error)
        }
        guard let recordType = record.first else {
            throw terminate(.protocolViolation("empty record"))
        }
        let payload = Data(record.dropFirst())
        switch recordType {
        case NoiseWebSocketProtocol.recordData:
            // The WebSocket read limit leaves margin above the payload cap,
            // so the decrypted payload size must be checked explicitly.
            guard payload.count <= maxMessageSize else {
                throw terminate(
                    .protocolViolation(
                        "received message of \(payload.count) bytes exceeds maximum size "
                            + "\(maxMessageSize)"
                    ))
            }
            return payload
        case NoiseWebSocketProtocol.recordClose:
            peerClosed = true
            // Respond with our own close record and complete the WebSocket
            // close handshake.
            try? await closeInternal()
            return nil
        default:
            throw terminate(
                .protocolViolation(String(format: "unknown record type 0x%02x", recordType)))
        }
    }

    /// Sends an encrypted close record and performs the WebSocket close
    /// handshake. The record lets the peer distinguish an intentional
    /// shutdown from truncation by an intermediary. Repeated calls are
    /// no-ops.
    public func close() async throws {
        localClosed = true
        try await closeInternal()
    }

    private func closeInternal() async throws {
        if closeSent {
            return
        }
        closeSent = true
        localClosed = true
        var sendError: EHBPError?
        do {
            let ciphertext = try sendCipher.encrypt(Data([NoiseWebSocketProtocol.recordClose]))
            try await task.send(.data(ciphertext))
        } catch let error as EHBPError {
            sendError = error
        } catch {
            sendError = EHBPError.webSocketError("send close record: \(error.localizedDescription)")
        }
        task.cancel(with: .normalClosure, reason: nil)
        if let sendError {
            throw sendError
        }
    }

    private func transportEnded(_ detail: String) -> EHBPError {
        let error: EHBPError
        if localClosed {
            error = .channelClosed
        } else {
            error = .channelTruncated(detail)
        }
        sticky = error
        return error
    }

    /// Records the sticky error and tears the connection down immediately
    /// after a protocol violation. Waiting for a close handshake would let
    /// a misbehaving peer pin resources, so none is attempted.
    private func terminate(_ error: EHBPError) -> EHBPError {
        sticky = error
        localClosed = true
        task.cancel()
        return error
    }
}
