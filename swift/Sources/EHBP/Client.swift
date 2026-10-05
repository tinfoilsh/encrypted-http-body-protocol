import Foundation

/// Pull-based request body: return the next plaintext chunk, or nil at end.
public typealias RequestBodySource = () throws -> Data?

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
    /// - Throws: `EHBPError` with code `.invalidInput` if no token is available
    public func getSessionRecoveryToken() throws -> SessionRecoveryToken {
        tokenLock.lock()
        let token = _lastSessionRecoveryToken
        tokenLock.unlock()
        guard let token else {
            throw EHBPError(.invalidInput, "no session recovery token available")
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
        try await request(method: method, path: path, headers: headers, body: .data(body))
    }

    /// Streaming-body variant: `bodySource` is pulled chunk by chunk (return
    /// nil at end) and encrypted with O(frame) memory, so multi-GiB uploads work.
    public func request(
        method: String,
        path: String,
        headers: [String: String] = [:],
        bodySource: @escaping RequestBodySource
    ) async throws -> (data: Data, response: HTTPURLResponse) {
        try await request(method: method, path: path, headers: headers, body: .source(bodySource))
    }

    private func request(
        method: String,
        path: String,
        headers: [String: String],
        body: RequestBody
    ) async throws -> (data: Data, response: HTTPURLResponse) {
        let prepared = try prepareRequest(method: method, path: path, headers: headers, body: body)
        defer { prepared.cleanup() }
        let (request, generation, requestContext, token) = (prepared.request, prepared.generation, prepared.context, prepared.token)

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw EHBPError.network("expected HTTP response")
        }
        if let mismatch = EHBPClient.keyConfigMismatch(httpResponse, body: data) {
            throw mismatch
        }

        guard let responseNonceHex = try EHBPClient.responseNonceHex(
            from: httpResponse,
            requestWasEncrypted: requestContext != nil
        ) else {
            return (data, httpResponse)
        }

        let responseNonce = try parseResponseNonce(responseNonceHex)

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
        try await requestStream(method: method, path: path, headers: headers, body: .data(body))
    }

    /// Streaming-body variant of `requestStream`; see `request(bodySource:)`.
    public func requestStream(
        method: String,
        path: String,
        headers: [String: String] = [:],
        bodySource: @escaping RequestBodySource
    ) async throws -> (stream: AsyncThrowingStream<Data, Error>, response: HTTPURLResponse) {
        try await requestStream(method: method, path: path, headers: headers, body: .source(bodySource))
    }

    private func requestStream(
        method: String,
        path: String,
        headers: [String: String],
        body: RequestBody
    ) async throws -> (stream: AsyncThrowingStream<Data, Error>, response: HTTPURLResponse) {
        let prepared = try prepareRequest(method: method, path: path, headers: headers, body: body)
        let (request, generation, requestContext, token) = (prepared.request, prepared.generation, prepared.context, prepared.token)

        let (asyncBytes, response): (URLSession.AsyncBytes, URLResponse)
        do {
            (asyncBytes, response) = try await session.bytes(for: request)
        } catch {
            prepared.cleanup()
            throw error
        }
        // Response headers mean the upload finished; the spool is no longer needed.
        prepared.cleanup()

        guard let httpResponse = response as? HTTPURLResponse else {
            throw EHBPError.network("expected HTTP response")
        }
        var iterator = asyncBytes.makeAsyncIterator()
        var prefetched = Data()
        if EHBPClient.mayBeKeyConfigMismatch(httpResponse) {
            // Read the (small) problem body so it can be classified; anything
            // over the limit is not a problem document and passes through.
            while prefetched.count <= EHBPProtocol.maxProblemDetailsBytes,
                  let byte = try await iterator.next() {
                prefetched.append(byte)
            }
            if let mismatch = EHBPClient.keyConfigMismatch(httpResponse, body: prefetched) {
                asyncBytes.task.cancel()
                throw mismatch
            }
        }

        guard let responseNonceHex = try EHBPClient.responseNonceHex(
            from: httpResponse,
            requestWasEncrypted: requestContext != nil
        ) else {
            let chunker = PullDrivenByteChunker(
                iterator: iterator,
                prefix: prefetched,
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

        let responseNonce = try parseResponseNonce(responseNonceHex)

        let responseDecryptor = try token!.makeResponseDecryptor(
            responseNonce: responseNonce
        )

        publishToken(token!, for: generation)

        let decryptor = PullDrivenResponseDecryptor(
            iterator: iterator,
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

    /// Resolves `path` against the configured base URL (RFC 3986) and refuses
    /// anything that would change the authority: a different origin, or
    /// userinfo in either the base or the path. String concatenation let a
    /// path like `@attacker.invalid/x` turn the configured host into userinfo.
    func resolveURL(_ path: String) throws -> URL {
        guard let base = URLComponents(string: baseURL),
              let scheme = base.scheme, let host = base.host,
              base.user == nil, base.password == nil else {
            throw EHBPError(.invalidInput, "base URL must be an origin without credentials: \(baseURL)")
        }
        guard let url = URL(string: path, relativeTo: base.url)?.absoluteURL,
              let resolved = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw EHBPError(.invalidInput, "invalid URL: \(path)")
        }
        guard resolved.user == nil, resolved.password == nil else {
            throw EHBPError(.invalidInput, "request URL must not include credentials")
        }
        guard resolved.scheme?.lowercased() == scheme.lowercased(),
              resolved.host?.lowercased() == host.lowercased(),
              resolved.port == base.port else {
            throw EHBPError(.invalidInput, "request URL must use the configured origin: \(scheme)://\(host)")
        }
        return url
    }

    /// Headers the library or the transport owns; callers may not set them.
    /// Same list as the Python client.
    static let reservedRequestHeaders: Set<String> = [
        "content-length", "transfer-encoding", "host",
        EHBPProtocol.encapsulatedKeyHeader.lowercased(),
        EHBPProtocol.responseNonceHeader.lowercased(),
    ]

    static func callerHeaders(_ headers: [String: String]) throws -> [String: String] {
        for name in headers.keys where reservedRequestHeaders.contains(name.lowercased()) {
            throw EHBPError(.invalidInput, "reserved request header cannot be set by callers: \(name)")
        }
        return headers
    }

    /// Everything that happens before the request leaves the client, shared by
    /// the buffered and streaming paths so the two cannot diverge: URL
    /// resolution against the configured origin, generation tracking,
    /// reserved-header validation, and body encryption.
    private enum RequestBody {
        case data(Data?)
        case source(RequestBodySource)
    }

    private struct PreparedRequest {
        let request: URLRequest
        let generation: UInt64
        let context: RequestContext?
        let token: SessionRecoveryToken?
        /// Encrypted body spooled for a streaming source; removed after upload.
        let spool: URL?

        func cleanup() {
            if let spool { try? FileManager.default.removeItem(at: spool) }
        }
    }

    private func prepareRequest(
        method: String,
        path: String,
        headers: [String: String],
        body: RequestBody
    ) throws -> PreparedRequest {
        let url = try resolveURL(path)
        let generation = beginRequest()

        var request = URLRequest(url: url)
        request.httpMethod = method

        for (key, value) in try EHBPClient.callerHeaders(headers) {
            request.setValue(value, forHTTPHeaderField: key)
        }

        var requestContext: RequestContext?
        var token: SessionRecoveryToken?
        var spool: URL?

        switch body {
        case .data(let data):
            if let data, !data.isEmpty {
                let (encryptedBody, context) = try identity.encryptRequest(body: data)
                requestContext = context
                token = try extractSessionRecoveryToken(context: context)
                request.httpBody = encryptedBody
            }
        case .source(let next):
            // Set up the throwing cryptographic state before touching the
            // caller's (possibly non-rewindable) source, so a setup failure
            // never costs it a chunk. The token therefore exists before any
            // byte is read or sent (SPEC 6).
            let encryptor = try identity.makeRequestEncryptor()
            let candidate = try extractSessionRecoveryToken(context: encryptor.context)
            // A source that yields no bytes is a bodyless request: same path as
            // `.data(nil)`, the unused context is dropped and no header is sent.
            var first = try next()
            while let chunk = first, chunk.isEmpty { first = try next() }
            if let first {
                requestContext = encryptor.context
                token = candidate
                spool = try EHBPClient.spoolEncrypted(first: first, then: next, with: encryptor)
                request.httpBodyStream = InputStream(url: spool!)
            }
        }
        if let context = requestContext {
            request.setValue(
                context.requestEnc.hexString,
                forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader
            )
        }
        return PreparedRequest(request: request, generation: generation,
                               context: requestContext, token: token, spool: spool)
    }

    /// Encrypts a streaming source frame by frame into a temporary file so
    /// memory stays O(frame) while URLSession gets a body it can upload.
    // ponytail: temp-file spool costs O(size) disk; replace with a custom
    // InputStream that seals on demand if disk becomes the constraint.
    private static func spoolEncrypted(first: Data, then next: RequestBodySource, with encryptor: RequestEncryptor) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("ehbp-\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: url.path, contents: nil),
              let handle = FileHandle(forWritingAtPath: url.path) else {
            throw EHBPError.network("cannot create upload spool file")
        }
        defer { try? handle.close() }
        do {
            var chunk: Data? = first
            while let current = chunk {
                // One frame per write so a large pull never materialises all
                // of its ciphertext at once.
                for start in stride(from: current.startIndex, to: current.endIndex, by: RequestEncryptor.frameSize) {
                    try handle.write(contentsOf: try encryptor.seal(current[start..<min(start + RequestEncryptor.frameSize, current.endIndex)]))
                }
                chunk = try next()
            }
        } catch {
            try? FileManager.default.removeItem(at: url)
            throw error
        }
        return url
    }

    static func mayBeKeyConfigMismatch(_ response: HTTPURLResponse) -> Bool {
        // A problem document is plaintext. A 422 carrying a response nonce is
        // an encrypted body and must reach the decryptor untouched.
        guard response.statusCode == 422,
              response.value(forHTTPHeaderField: EHBPProtocol.responseNonceHeader) == nil,
              let contentType = response.value(forHTTPHeaderField: "Content-Type"),
              let mediaType = contentType.split(separator: ";", maxSplits: 1).first else {
            return false
        }
        return mediaType.trimmingCharacters(in: .whitespaces).lowercased() == EHBPProtocol.problemJSONMediaType
    }

    /// A 422 problem-details body whose type is the key-config URN means the
    /// server rejected a stale client key (SPEC 5.4.2); callers re-fetch the
    /// key configuration and retry. Mirrors the Go client.
    static func keyConfigMismatch(_ response: HTTPURLResponse, body: Data) -> EHBPError? {
        guard mayBeKeyConfigMismatch(response),
              body.count <= EHBPProtocol.maxProblemDetailsBytes,
              let problem = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              problem["type"] as? String == EHBPProtocol.keyConfigProblemType else {
            return nil
        }
        let title = problem["title"] as? String ?? ""
        return EHBPError(.keyConfigMismatch, title.isEmpty ? "stale client key configuration" : title)
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
            throw EHBPError(.missingResponseNonce, "missing \(EHBPProtocol.responseNonceHeader) header")
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
    private var prefix: Data
    private let chunkSize: Int
    private let onFailure: @Sendable () -> Void
    private let onCancel: @Sendable () -> Void
    private var isReading = false

    init(
        iterator: Iterator,
        prefix: Data = Data(),
        chunkSize: Int,
        onFailure: @escaping @Sendable () -> Void = {},
        onCancel: @escaping @Sendable () -> Void = {}
    ) {
        precondition(chunkSize > 0)
        self.iterator = iterator
        self.prefix = prefix
        self.chunkSize = chunkSize
        self.onFailure = onFailure
        self.onCancel = onCancel
    }

    func next() async throws -> Data? {
        guard !isReading else {
            throw EHBPError(.invalidInput, "concurrent stream iteration is unsupported")
        }
        isReading = true
        defer { isReading = false }

        if !prefix.isEmpty {
            defer { prefix = Data() }
            return prefix
        }

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
            throw EHBPError(.invalidInput, "concurrent stream iteration is unsupported")
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

/// Decodes the `Ehbp-Response-Nonce` header value; both request paths share it.
func parseResponseNonce(_ hex: String) throws -> Data {
    guard let nonce = Data(hexString: hex) else {
        throw EHBPError(.invalidResponseNonce, "invalid response nonce hex")
    }
    guard nonce.count == EHBPConstants.responseNonceLength else {
        throw EHBPError(.invalidResponseNonce, "response nonce must be \(EHBPConstants.responseNonceLength) bytes, got \(nonce.count)")
    }
    return nonce
}
