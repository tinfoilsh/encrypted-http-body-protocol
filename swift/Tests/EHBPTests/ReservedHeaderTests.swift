import Crypto
import Foundation
import XCTest
@testable import EHBP

final class ReservedHeaderTests: XCTestCase {
    func testCallerCannotSetReservedHeaders() async throws {
        let client = try EHBPClient(
            baseURL: "https://server.test",
            publicKey: Data(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation)
        )
        for name in [EHBPProtocol.encapsulatedKeyHeader, "ehbp-response-nonce", "Host"] {
            do {
                _ = try await client.request(method: "POST", path: "/secure", headers: [name: "x"], body: Data("hi".utf8))
                XCTFail("\(name) must be rejected")
            } catch {
                XCTAssertEqual((error as? EHBPError)?.code, .invalidInput, name)
            }
            do {
                _ = try await client.requestStream(method: "POST", path: "/secure", headers: [name: "x"], body: Data("hi".utf8))
                XCTFail("\(name) must be rejected on the streaming path")
            } catch {
                XCTAssertEqual((error as? EHBPError)?.code, .invalidInput, name)
            }
        }
        XCTAssertEqual(try EHBPClient.callerHeaders(["X-Custom": "ok"]), ["X-Custom": "ok"])
        // Body framing belongs to the implementation: caller values are dropped (SPEC 5.1).
        XCTAssertEqual(
            try EHBPClient.callerHeaders(["Content-Length": "1", "transfer-encoding": "chunked", "X-Custom": "ok"]),
            ["X-Custom": "ok"])
    }
}
