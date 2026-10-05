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

    func testBodySourceIsEncryptedIncrementallyAndUploaded() async throws {
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let client = try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(serverKey.publicKey.rawRepresentation),
            session: URLSession(configuration: configuration)
        )
        defer { StubURLProtocol.handler = nil }

        var uploaded = Data()
        var enc = Data()
        StubURLProtocol.handler = { request in
            enc = Data(hexString: request.value(forHTTPHeaderField: EHBPProtocol.encapsulatedKeyHeader) ?? "") ?? Data()
            if let stream = request.httpBodyStream {
                stream.open()
                var buf = [UInt8](repeating: 0, count: 1 << 16)
                while stream.hasBytesAvailable {
                    let n = stream.read(&buf, maxLength: buf.count)
                    if n <= 0 { break }
                    uploaded.append(buf, count: n)
                }
                stream.close()
            }
            // A 502 without a nonce passes through, so no response encryption is needed.
            let response = HTTPURLResponse(url: request.url!, statusCode: 502, httpVersion: nil, headerFields: [:])!
            return (response, Data())
        }

        // 3 pulls of 100 KiB, then EOF: the source is consumed chunk by chunk.
        var pulls = 0
        let chunk = Data(repeating: 0xab, count: 100 * 1024)
        let (_, response) = try await client.request(method: "POST", path: "/upload", bodySource: {
            pulls += 1
            return pulls <= 3 ? chunk : nil
        })

        XCTAssertEqual(response.statusCode, 502)
        XCTAssertEqual(pulls, 4)
        let frames = try openFrames(uploaded, privateKey: serverKey, enc: enc)
        XCTAssertEqual(frames.reduce(Data(), +), chunk + chunk + chunk)
        XCTAssertTrue(frames.allSatisfy { $0.count <= RequestEncryptor.frameSize })
        XCTAssertNotNil(try? client.getSessionRecoveryToken(), "token is published for the exchange")
    }
}
