import Foundation

/// Streaming EHBP client for making encrypted HTTP requests
public final class EHBPClient: @unchecked Sendable {
    private let identity: Identity
    private let baseURL: String
    private let session: URLSession
    private let tokenLock = NSLock()
    private var _lastSessionRecoveryToken: SessionRecoveryToken?
    private var requestGeneration: UInt64 = 0

    private static let passThroughChunkSize = 16 * 1024

    /// Creates a new EHBP client
    ///
    /// - Parameters:
    ///   - baseURL: Base URL for the server (e.g., "https://api.example.com")
    ///   - publicKey: Server's X25519 public key (32 bytes)
    ///   - session: URLSession to use (defaults to shared)
    public init(baseURL: String, publicKey: Data, session: URLSession = .shared) throws {
        self.identity = try Identity(publicKeyBytes: publicKey)
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.session = session
    }

    /// Creates a new EHBP client from RFC 9458 key configuration
    ///
    /// - Parameters:
    ///   - baseURL: Base URL for the server
    ///   - config: RFC 9458 key configuration data
    ///   - session: URLSession to use (defaults to shared)
    public init(baseURL: String, config: Data, session: URLSession = .shared) throws {
        self.identity = try Identity(config: config)
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.session = session
    }

    /// Returns the session recovery token from the last request with a body
    ///
    /// - Throws: `EHBPError.invalidInput` if no token is available
    public func getSessionRecoveryToken() throws -> SessionRecoveryToken {
        tokenLock.lock()
        let token = _lastSessionRecoveryToken
        tokenLock.unlock()
        guard let token else {
            throw EHBPError.invalidInput("no session recovery token available")
        }
        return token
    }

    /// Makes an encrypted request and returns the decrypted response
    ///
    /// - Parameters:
    ///   - method: HTTP method
    ///   - path: URL path (will be appended to baseURL)
    ///   - headers: Additional headers to include
    ///   - body: Request body (will be encrypted)
    /// - Returns: Decrypted response data, or an untouched non-success response
    ///   when an intermediary returns an unencrypted error
    public func request(
        method: String,
        path: String,
        headers: [String: String] = [:],
        body: Data?
    ) async throws -> (data: Data, response: HTTPURLResponse) {
        let urlString = baseURL + path
        guard let url = URL(string: urlString) else {
            throw EHBPError.invalidInput("invalid URL: \(urlString)")
        }
        let generation = beginRequest()

        var request = URLRequest(url: url)
        request.httpMethod = method

        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        var requestContext: RequestContext?
        var token: SessionRecoveryToken?

        if let body = body, !body.isEmpty {
            let (encryptedBody, context) = try identity.encryptRequest(body: body)
            requestContext = context
            token = try extractSessionRecoveryToken(context: context)

            request.setValue(
                context.requestEnc.hexString,
                forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader
            )
            request.httpBody = encryptedBody
        }

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw EHBPError.networkError("expected HTTP response")
        }

        guard let responseNonceHex = try EHBPClient.responseNonceHex(
            from: httpResponse,
            requestWasEncrypted: requestContext != nil
        ) else {
            return (data, httpResponse)
        }

        guard let responseNonce = Data(hexString: responseNonceHex) else {
            throw EHBPError.invalidResponse("invalid response nonce hex")
        }

        guard responseNonce.count == EHBPConstants.responseNonceLength else {
            throw EHBPError.invalidResponse("response nonce must be \(EHBPConstants.responseNonceLength) bytes, got \(responseNonce.count)")
        }

        let decryptedData = try EHBP.decryptResponseBody(
            token: token!,
            responseNonce: responseNonce,
            encryptedData: data
        )

        clearToken(for: generation)

        return (decryptedData, EHBPClient.sanitizedResponse(httpResponse))
    }

    /// Makes an encrypted streaming request and returns chunks as an AsyncStream
    ///
    /// - Parameters:
    ///   - method: HTTP method
    ///   - path: URL path
    ///   - headers: Additional headers
    ///   - body: Request body (will be encrypted)
    /// - Returns: AsyncThrowingStream of decrypted response chunks, or untouched
    ///   non-success response chunks when an intermediary returns an unencrypted error
    public func requestStream(
        method: String,
        path: String,
        headers: [String: String] = [:],
        body: Data?
    ) async throws -> (stream: AsyncThrowingStream<Data, Error>, response: HTTPURLResponse) {
        let urlString = baseURL + path
        guard let url = URL(string: urlString) else {
            throw EHBPError.invalidInput("invalid URL: \(urlString)")
        }
        let generation = beginRequest()

        var request = URLRequest(url: url)
        request.httpMethod = method

        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        var requestContext: RequestContext?
        var token: SessionRecoveryToken?

        if let body = body, !body.isEmpty {
            let (encryptedBody, context) = try identity.encryptRequest(body: body)
            requestContext = context
            token = try extractSessionRecoveryToken(context: context)

            request.setValue(
                context.requestEnc.hexString,
                forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader
            )
            request.httpBody = encryptedBody
        }

        let (asyncBytes, response) = try await session.bytes(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw EHBPError.networkError("expected HTTP response")
        }

        guard let responseNonceHex = try EHBPClient.responseNonceHex(
            from: httpResponse,
            requestWasEncrypted: requestContext != nil
        ) else {
            let chunker = PullDrivenByteChunker(
                iterator: asyncBytes.makeAsyncIterator(),
                chunkSize: EHBPClient.passThroughChunkSize,
                onFailure: { self.clearToken(for: generation) },
                onCancel: { asyncBytes.task.cancel() }
            )
            let lifetime = StreamCancellation {
                asyncBytes.task.cancel()
            }
            let stream = AsyncThrowingStream<Data, Error>(unfolding: {
                _ = lifetime
                return try await chunker.next()
            })
            return (stream, httpResponse)
        }

        guard let responseNonce = Data(hexString: responseNonceHex) else {
            throw EHBPError.invalidResponse("invalid response nonce hex")
        }

        let responseDecryptor = try token!.makeResponseDecryptor(
            responseNonce: responseNonce
        )

        publishToken(token!, for: generation)

        let decryptor = PullDrivenResponseDecryptor(
            iterator: asyncBytes.makeAsyncIterator(),
            decryptor: responseDecryptor,
            onComplete: { self.clearToken(for: generation) },
            onFailure: { self.clearToken(for: generation) },
            onCancel: { asyncBytes.task.cancel() }
        )
        let lifetime = StreamCancellation {
            asyncBytes.task.cancel()
        }
        let stream = AsyncThrowingStream<Data, Error>(unfolding: {
            _ = lifetime
            return try await decryptor.next()
        })

        return (stream, EHBPClient.sanitizedResponse(httpResponse))
    }

    private func beginRequest() -> UInt64 {
        tokenLock.lock()
        requestGeneration &+= 1
        let generation = requestGeneration
        _lastSessionRecoveryToken = nil
        tokenLock.unlock()
        return generation
    }

    private func publishToken(_ token: SessionRecoveryToken, for generation: UInt64) {
        tokenLock.lock()
        if requestGeneration == generation {
            _lastSessionRecoveryToken = token
        }
        tokenLock.unlock()
    }

    private func clearToken(for generation: UInt64) {
        tokenLock.lock()
        if requestGeneration == generation {
            _lastSessionRecoveryToken = nil
        }
        tokenLock.unlock()
    }

    private static func responseNonceHex(
        from response: HTTPURLResponse,
        requestWasEncrypted: Bool
    ) throws -> String? {
        guard requestWasEncrypted else { return nil }
        if let nonce = response.value(forHTTPHeaderField: EHBPProtocol.responseNonceHeader) {
            return nonce
        }
        guard !(200..<300).contains(response.statusCode) else {
            throw EHBPError.missingHeader(EHBPProtocol.responseNonceHeader)
        }
        return nil
    }

    /// Removes framing headers that describe the encrypted body. The
    /// decrypted data has a different length, so consumers that forward the
    /// response headers verbatim (for example a proxy) would otherwise
    /// announce a body length that no longer matches what is written,
    /// truncating the reply.
    static func sanitizedResponse(_ response: HTTPURLResponse) -> HTTPURLResponse {
        var headers: [String: String] = [:]
        for (name, value) in response.allHeaderFields {
            guard let name = name as? String, let value = value as? String else { continue }
            let lowered = name.lowercased()
            if lowered == "content-length" || lowered == "transfer-encoding" { continue }
            headers[name] = value
        }
        guard let url = response.url,
              let sanitized = HTTPURLResponse(
                  url: url,
                  statusCode: response.statusCode,
                  httpVersion: nil,
                  headerFields: headers
              ) else {
            return response
        }
        return sanitized
    }

}

actor PullDrivenByteChunker<Iterator: AsyncIteratorProtocol & Sendable>
where Iterator.Element == UInt8 {
    private var iterator: Iterator
    private let chunkSize: Int
    private let onFailure: @Sendable () -> Void
    private let onCancel: @Sendable () -> Void
    private var isReading = false

    init(
        iterator: Iterator,
        chunkSize: Int,
        onFailure: @escaping @Sendable () -> Void = {},
        onCancel: @escaping @Sendable () -> Void = {}
    ) {
        precondition(chunkSize > 0)
        self.iterator = iterator
        self.chunkSize = chunkSize
        self.onFailure = onFailure
        self.onCancel = onCancel
    }

    func next() async throws -> Data? {
        guard !isReading else {
            throw EHBPError.invalidInput("concurrent stream iteration is unsupported")
        }
        isReading = true
        defer { isReading = false }

        do {
            let cancel = onCancel
            return try await withTaskCancellationHandler {
                var iterator = self.iterator
                var chunk = Data(capacity: chunkSize)
                while chunk.count < chunkSize {
                    guard let byte = try await iterator.next() else {
                        self.iterator = iterator
                        return chunk.isEmpty ? nil : chunk
                    }
                    chunk.append(byte)
                }
                self.iterator = iterator
                return chunk
            } onCancel: {
                cancel()
            }
        } catch {
            onFailure()
            throw error
        }
    }
}

actor PullDrivenResponseDecryptor<Iterator: AsyncIteratorProtocol & Sendable>
where Iterator.Element == UInt8 {
    private var iterator: Iterator
    private var decryptor: ResponseDecryptor
    private let onComplete: @Sendable () -> Void
    private let onFailure: @Sendable () -> Void
    private let onCancel: @Sendable () -> Void
    private var isReading = false
    private var isFinished = false

    init(
        iterator: Iterator,
        decryptor: ResponseDecryptor,
        onComplete: @escaping @Sendable () -> Void = {},
        onFailure: @escaping @Sendable () -> Void = {},
        onCancel: @escaping @Sendable () -> Void = {}
    ) {
        self.iterator = iterator
        self.decryptor = decryptor
        self.onComplete = onComplete
        self.onFailure = onFailure
        self.onCancel = onCancel
    }

    func next() async throws -> Data? {
        guard !isFinished else { return nil }
        guard !isReading else {
            throw EHBPError.invalidInput("concurrent stream iteration is unsupported")
        }
        isReading = true
        defer { isReading = false }

        do {
            let cancel = onCancel
            return try await withTaskCancellationHandler {
                var iterator = self.iterator
                var decryptor = self.decryptor
                while let byte = try await iterator.next() {
                    if let plaintext = try decryptor.push(byte) {
                        self.iterator = iterator
                        self.decryptor = decryptor
                        return plaintext
                    }
                }
                try decryptor.finish()
                self.iterator = iterator
                self.decryptor = decryptor
                self.isFinished = true
                self.onComplete()
                return nil
            } onCancel: {
                cancel()
            }
        } catch {
            if !Task.isCancelled {
                onFailure()
            }
            throw error
        }
    }
}

private final class StreamCancellation: @unchecked Sendable {
    private let cancel: @Sendable () -> Void

    init(_ cancel: @escaping @Sendable () -> Void) {
        self.cancel = cancel
    }

    deinit {
        cancel()
    }
}

// MARK: - Data Extensions

public extension Data {
    /// Creates Data from a hex string
    init?(hexString: String) {
        let hex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        guard hex.count % 2 == 0 else { return nil }

        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }

    /// Returns hex string representation
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
