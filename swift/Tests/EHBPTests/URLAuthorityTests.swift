import Crypto
import Foundation
import XCTest
@testable import EHBP

final class URLAuthorityTests: XCTestCase {
    private func makeClient(baseURL: String) throws -> EHBPClient {
        try EHBPClient(
            baseURL: baseURL,
            publicKey: Data(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation)
        )
    }

    func testPathCannotChangeAuthority() throws {
        let client = try makeClient(baseURL: "https://server.test")
        XCTAssertEqual(try client.resolveURL("/secure").absoluteString, "https://server.test/secure")
        XCTAssertEqual(try client.resolveURL("@attacker.invalid/x").host, "server.test")
        for bad in ["https://attacker.invalid/x", "http://server.test/x", "https://server.test:8443/x",
                    "https://user:pass@server.test/x"] {
            XCTAssertThrowsError(try client.resolveURL(bad), bad) { error in
                XCTAssertEqual((error as? EHBPError)?.code, .invalidInput)
            }
        }
        XCTAssertThrowsError(try makeClient(baseURL: "https://user:pass@server.test").resolveURL("/x")) { error in
            XCTAssertEqual((error as? EHBPError)?.code, .invalidInput)
        }
    }
}
