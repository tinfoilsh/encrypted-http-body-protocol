import Crypto
import Foundation
import XCTest
@testable import EHBP

final class StreamingRequestTests: XCTestCase {
    private func openFrames(_ framed: Data, privateKey: Curve25519.KeyAgreement.PrivateKey, enc: Data) throws -> [Data] {
        var recipient = try HPKE.Recipient(
            privateKey: privateKey,
            ciphersuite: HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256),
            info: Data(EHBPConstants.hpkeRequestInfo.utf8),
            encapsulatedKey: enc
        )
        var frames = [Data]()
        var offset = framed.startIndex
        while offset < framed.endIndex {
            let len = framed[offset..<offset + 4].reduce(0) { Int($0) << 8 | Int($1) }
            offset += 4
            frames.append(try recipient.open(framed[offset..<offset + len]))
            offset += len
        }
        return frames
    }

    /// Client whose session is routed through StubURLProtocol.
    private func makeClient(publicKey: Data) throws -> EHBPClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return try EHBPClient(baseURL: "https://server.test", publicKey: publicKey,
                              session: URLSession(configuration: configuration))
    }

    /// Reads the request's httpBodyStream to EOF, as the stub server would.
    private func drainBodyStream(_ request: URLRequest) -> Data {
        var uploaded = Data()
        guard let stream = request.httpBodyStream else { return uploaded }
        stream.open()
        var buf = [UInt8](repeating: 0, count: 1 << 16)
        while stream.hasBytesAvailable {
            let n = stream.read(&buf, maxLength: buf.count)
            if n <= 0 { break }
            uploaded.append(buf, count: n)
        }
        stream.close()
        return uploaded
    }

    /// What the stub server saw: the encapsulated key and the uploaded bytes.
    private final class Capture: @unchecked Sendable {
        var uploaded = Data()
        var enc = Data()
    }

    /// Stub handler that records the upload and answers a nonce-less 502
    /// (passed through, so no response encryption is needed).
    private func captureUpload() -> Capture {
        let capture = Capture()
        StubURLProtocol.handler = { [self] request in
            capture.enc = Data(hexString: request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader) ?? "") ?? Data()
            capture.uploaded = drainBodyStream(request)
            return (HTTPURLResponse(url: request.url!, statusCode: 502, httpVersion: nil, headerFields: [:])!, Data())
        }
        return capture
    }

    func testLargeBodySplitsIntoFramesTheServerCanOpenInOrder() throws {
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        let identity = try Identity(publicKeyBytes: Data(serverKey.publicKey.rawRepresentation))
        let body = Data((0..<(200 * 1024)).map { UInt8($0 & 0xff) })

        let (framed, context) = try identity.encryptRequest(body: body)
        let frames = try openFrames(framed, privateKey: serverKey, enc: context.requestEnc)

        XCTAssertEqual(frames.count, 4) // 64 + 64 + 64 + 8 KiB
        XCTAssertEqual(frames.map(\.count), [65536, 65536, 65536, 8192])
        XCTAssertEqual(frames.reduce(Data(), +), body)
    }

    func testEmptyBodySourceIsBodyless() async throws {
        let client = try makeClient(publicKey: Data(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation))
        defer { StubURLProtocol.handler = nil }

        var sawEncapsulatedKey: String?
        StubURLProtocol.handler = { request in
            sawEncapsulatedKey = request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "text/plain"])!
            return (response, Data("plain".utf8))
        }

        // Only empty pulls, then EOF: no payload body, so no HPKE context.
        var pulls = 0
        let (data, response) = try await client.request(method: "POST", path: "/upload", bodySource: {
            pulls += 1
            return pulls == 1 ? Data() : nil
        })

        XCTAssertNil(sawEncapsulatedKey)
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(String(data: data, encoding: .utf8), "plain")
    }

    func testOversizedPullIsSpooledOneFrameAtATime() async throws {
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        let client = try makeClient(publicKey: Data(serverKey.publicKey.rawRepresentation))
        defer { StubURLProtocol.handler = nil }

        let capture = captureUpload()

        // One 1 MiB pull must still go out as 16 frames of at most 64 KiB.
        var pulled = false
        let body = Data(repeating: 0x5c, count: 1 << 20)
        _ = try await client.request(method: "POST", path: "/upload", bodySource: {
            defer { pulled = true }
            return pulled ? nil : body
        })

        let frames = try openFrames(capture.uploaded, privateKey: serverKey, enc: capture.enc)
        XCTAssertEqual(frames.count, 16)
        XCTAssertTrue(frames.allSatisfy { $0.count <= RequestEncryptor.frameSize })
        XCTAssertEqual(frames.reduce(Data(), +), body)
    }

    func testBodySourceIsEncryptedIncrementallyAndUploaded() async throws {
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        let client = try makeClient(publicKey: Data(serverKey.publicKey.rawRepresentation))
        defer { StubURLProtocol.handler = nil }

        let capture = captureUpload()

        // 3 pulls of 100 KiB, then EOF: the source is consumed chunk by chunk.
        var pulls = 0
        let chunk = Data(repeating: 0xab, count: 100 * 1024)
        let (_, response) = try await client.request(method: "POST", path: "/upload", bodySource: {
            pulls += 1
            return pulls <= 3 ? chunk : nil
        })

        XCTAssertEqual(response.statusCode, 502)
        XCTAssertEqual(pulls, 4)
        let frames = try openFrames(capture.uploaded, privateKey: serverKey, enc: capture.enc)
        XCTAssertEqual(frames.reduce(Data(), +), chunk + chunk + chunk)
        XCTAssertTrue(frames.allSatisfy { $0.count <= RequestEncryptor.frameSize })
        // No token assertion: a nonce-less 502 pass-through consumes the token
        // (SPEC 5.1), and publication timing on this path is tracked by #109.
    }
}

final class TokenBeforeSendTests: XCTestCase {
    /// Stub that reads the client's token while the request is in flight.
    private func inFlightToken(_ run: (EHBPClient) async throws -> Void) async throws -> (seen: SessionRecoveryToken?, sentEnc: Data) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let client = try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )
        defer { StubURLProtocol.handler = nil }
        var seen: SessionRecoveryToken?
        var sentEnc = Data()
        StubURLProtocol.handler = { request in
            sentEnc = Data(hexString: request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader) ?? "") ?? Data()
            seen = try? client.getSessionRecoveryToken()
            // Nonce-less 502: passed through, and consumes the token.
            return (HTTPURLResponse(url: request.url!, statusCode: 502, httpVersion: nil, headerFields: [:])!, Data())
        }
        try await run(client)
        XCTAssertThrowsError(try client.getSessionRecoveryToken(), "pass-through consumes the token")
        return (seen, sentEnc)
    }

    func testBufferedRequestPublishesTokenBeforeSend() async throws {
        let (seen, sentEnc) = try await inFlightToken { client in
            _ = try await client.request(method: "POST", path: "/secure", body: Data("hi".utf8))
        }
        XCTAssertEqual(seen?.requestEnc, sentEnc)
    }

    func testStreamingRequestPublishesTokenBeforeSend() async throws {
        let (seen, sentEnc) = try await inFlightToken { client in
            let (stream, _) = try await client.requestStream(method: "POST", path: "/secure", body: Data("hi".utf8))
            for try await _ in stream {}
        }
        XCTAssertEqual(seen?.requestEnc, sentEnc)
    }

    func testTransportFailureClearsToken() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let client = try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )
        defer { StubURLProtocol.handler = nil }
        StubURLProtocol.handler = { _ in throw URLError(.networkConnectionLost) }
        await XCTAssertThrowsErrorAsync(try await client.request(method: "POST", path: "/secure", body: Data("hi".utf8)))
        XCTAssertThrowsError(try client.getSessionRecoveryToken())
    }
}

private func XCTAssertThrowsErrorAsync<T>(_ expression: @autoclosure () async throws -> T) async {
    do {
        _ = try await expression()
        XCTFail("expected an error")
    } catch {}
}
