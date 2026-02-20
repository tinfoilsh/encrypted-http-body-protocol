import Foundation

/// Streaming EHBP client for making encrypted HTTP requests
public final class EHBPClient: @unchecked Sendable {
    private let identity: Identity
    private let session: URLSession

    /// Creates a new EHBP client
    ///
    /// - Parameters:
    ///   - identity: Server identity (public key) for encryption
    ///   - session: URLSession to use (defaults to shared)
    public init(identity: Identity, session: URLSession = .shared) {
        self.identity = identity
        self.session = session
    }

    /// Makes an encrypted request and returns the decrypted response
    ///
    /// - Parameters:
    ///   - method: HTTP method
    ///   - url: Full URL string (e.g., "https://api.example.com/v1/chat")
    ///   - headers: Additional headers to include
    ///   - body: Request body (will be encrypted)
    /// - Returns: Decrypted response data
    public func request(
        method: String,
        url urlString: String,
        headers: [String: String] = [:],
        body: Data?
    ) async throws -> (data: Data, response: HTTPURLResponse) {
        guard let url = URL(string: urlString) else {
            throw EHBPError.invalidInput("invalid URL: \(urlString)")
        }

        var request = URLRequest(url: url)
        request.httpMethod = method

        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        var requestContext: RequestContext?

        if let body = body, !body.isEmpty {
            let (encryptedBody, context) = try identity.encryptRequest(body: body)
            requestContext = context

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

        guard let context = requestContext else {
            return (data, httpResponse)
        }

        guard let responseNonceHex = httpResponse.value(forHTTPHeaderField: EHBPProtocol.responseNonceHeader) else {
            throw EHBPError.missingHeader(EHBPProtocol.responseNonceHeader)
        }

        guard let responseNonce = Data(hexString: responseNonceHex) else {
            throw EHBPError.invalidResponse("invalid response nonce hex")
        }

        guard responseNonce.count == EHBPConstants.responseNonceLength else {
            throw EHBPError.invalidResponse("response nonce must be \(EHBPConstants.responseNonceLength) bytes, got \(responseNonce.count)")
        }

        let keyMaterial = try identity.deriveResponseKeys(context: context, responseNonce: responseNonce)
        let decryptedData = try decryptResponseBody(data: data, keyMaterial: keyMaterial)

        return (decryptedData, httpResponse)
    }

    /// Makes an encrypted streaming request and returns chunks as an AsyncStream
    ///
    /// - Parameters:
    ///   - method: HTTP method
    ///   - url: Full URL string
    ///   - headers: Additional headers
    ///   - body: Request body (will be encrypted)
    /// - Returns: AsyncThrowingStream of decrypted response chunks
    public func requestStream(
        method: String,
        url urlString: String,
        headers: [String: String] = [:],
        body: Data?
    ) async throws -> (stream: AsyncThrowingStream<Data, Error>, response: HTTPURLResponse) {
        guard let url = URL(string: urlString) else {
            throw EHBPError.invalidInput("invalid URL: \(urlString)")
        }

        var request = URLRequest(url: url)
        request.httpMethod = method

        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        var requestContext: RequestContext?

        if let body = body, !body.isEmpty {
            let (encryptedBody, context) = try identity.encryptRequest(body: body)
            requestContext = context

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

        guard let context = requestContext else {
            let stream = AsyncThrowingStream<Data, Error> { continuation in
                Task {
                    do {
                        var buffer = Data()
                        for try await byte in asyncBytes {
                            buffer.append(byte)
                        }
                        if !buffer.isEmpty {
                            continuation.yield(buffer)
                        }
                        continuation.finish()
                    } catch {
                        continuation.finish(throwing: error)
                    }
                }
            }
            return (stream, httpResponse)
        }

        guard let responseNonceHex = httpResponse.value(forHTTPHeaderField: EHBPProtocol.responseNonceHeader) else {
            throw EHBPError.missingHeader(EHBPProtocol.responseNonceHeader)
        }

        guard let responseNonce = Data(hexString: responseNonceHex) else {
            throw EHBPError.invalidResponse("invalid response nonce hex")
        }

        let keyMaterial = try identity.deriveResponseKeys(context: context, responseNonce: responseNonce)

        let stream = AsyncThrowingStream<Data, Error> { continuation in
            Task {
                do {
                    var buffer = [UInt8]()
                    var seq: UInt64 = 0

                    for try await byte in asyncBytes {
                        buffer.append(byte)

                        while buffer.count >= 4 {
                            let chunkLength = Int(buffer[0]) << 24 |
                                              Int(buffer[1]) << 16 |
                                              Int(buffer[2]) << 8 |
                                              Int(buffer[3])

                            if chunkLength == 0 {
                                buffer.removeFirst(4)
                                continue
                            }

                            guard chunkLength <= EHBPConstants.maxChunkLength else {
                                throw EHBPError.invalidResponse("chunk length \(chunkLength) exceeds maximum \(EHBPConstants.maxChunkLength)")
                            }

                            guard buffer.count >= 4 + chunkLength else {
                                break
                            }

                            let ciphertext = Data(buffer[4..<(4 + chunkLength)])
                            buffer.removeFirst(4 + chunkLength)

                            let plaintext = try decryptChunk(
                                keyMaterial: keyMaterial,
                                seq: seq,
                                ciphertext: ciphertext
                            )
                            seq += 1

                            continuation.yield(plaintext)
                        }
                    }

                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
        }

        return (stream, httpResponse)
    }

    /// Decrypts response body using EHBP chunk framing (SPEC Section 4.3)
    ///
    /// Each chunk: LEN (4 bytes big-endian) || CIPHERTEXT (LEN bytes)
    private func decryptResponseBody(data: Data, keyMaterial: ResponseKeyMaterial) throws -> Data {
        var result = Data()
        var offset = 0
        var seq: UInt64 = 0

        while offset + 4 <= data.count {
            let chunkLength = Int(data[offset]) << 24 |
                              Int(data[offset + 1]) << 16 |
                              Int(data[offset + 2]) << 8 |
                              Int(data[offset + 3])
            offset += 4

            if chunkLength == 0 {
                continue
            }

            guard chunkLength <= EHBPConstants.maxChunkLength else {
                throw EHBPError.invalidResponse("chunk length \(chunkLength) exceeds maximum \(EHBPConstants.maxChunkLength)")
            }

            guard offset + chunkLength <= data.count else {
                throw EHBPError.invalidResponse("incomplete chunk at offset \(offset)")
            }

            let ciphertext = data.subdata(in: offset..<(offset + chunkLength))
            offset += chunkLength

            let plaintext = try decryptChunk(
                keyMaterial: keyMaterial,
                seq: seq,
                ciphertext: ciphertext
            )
            seq += 1

            result.append(plaintext)
        }

        return result
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
