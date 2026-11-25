import XCTest
@testable import EHBP

/// The shared interop vectors and the residue self-check. The protocol rules
/// are the core's and are pinned by the conformance fixtures; these tests
/// cover the FFI binding and this residue's crypto.
final class InteropTests: XCTestCase {
    private func vector(_ name: String) throws -> [String: String] {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("test-vectors").appendingPathComponent(name)
        return try JSONDecoder().decode([String: String].self, from: Data(contentsOf: url))
    }

    func testSelfCheckPasses() async {
        let failures = await EHBPClient.selfCheck()
        XCTAssertEqual(failures, [])
    }

    func testDeriveInteropVector() async throws {
        let v = try vector("derive.json")
        let km = try await EHBPClient.core.deriveResponseKeys(
            exportedSecret: Data(hexString: v["exportedSecret"]!)!,
            requestEnc: Data(hexString: v["requestEnc"]!)!,
            responseNonce: Data(hexString: v["responseNonce"]!)!)
        XCTAssertEqual(km.key.hexString, v["derivedKey"])
        XCTAssertEqual(km.nonceBase.hexString, v["derivedNonceBase"])
    }

    func testResponseDecryptionInteropVector() async throws {
        let v = try vector("response-decryption.json")
        let token = SessionRecoveryToken(exportedSecret: Data(hexString: v["exportedSecret"]!)!, requestEnc: Data(hexString: v["requestEnc"]!)!)
        let stream = try await EHBPClient.core.decryptWithToken(
            token, responseNonce: Data(hexString: v["responseNonce"]!)!, chunks: [Data(hexString: v["encryptedResponse"]!)!])
        var plain = Data()
        for try await chunk in stream { plain.append(chunk) }
        XCTAssertEqual(plain.hexString, v["plaintext"])
    }

    func testTokenInteropVector() throws {
        let v = try vector("session-recovery-token.json")
        let token = try SessionRecoveryToken(json: try JSONEncoder().encode(v))
        XCTAssertEqual(token.exportedSecret.hexString, v["exportedSecret"])
        XCTAssertEqual(token.requestEnc.hexString, v["requestEnc"])
        XCTAssertEqual(try SessionRecoveryToken(json: token.json), token)
        XCTAssertThrowsError(try SessionRecoveryToken(json: Data("{\"exportedSecret\":\"00\"}".utf8))) {
            XCTAssertEqual(($0 as? EHBPError)?.code, .invalidToken)
        }
    }

    func testStrictHexDecoding() {
        XCTAssertNil(Data(hexString: "0"))
        XCTAssertNil(Data(hexString: "zz"))
        XCTAssertEqual(Data(hexString: "00ff"), Data([0, 255]))
        XCTAssertEqual(Data([0xAB]).hexString, "ab")
    }
}
