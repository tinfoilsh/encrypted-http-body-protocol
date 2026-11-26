// EHBP conformance adapter (Swift). See conformance/adapters/README.md.
//
// Reads one fixture on stdin, runs it through the public EHBP API (the pure
// helpers through EHBPClient.core), prints one normalized result. All
// native-error translation lives in mapError.

import Foundation
import EHBP

let headerSubset = ["ehbp-response-nonce", "content-length", "transfer-encoding", "content-type"]

let inputData = FileHandle.standardInput.readDataToEndOfFile()
nonisolated(unsafe) let fx = (try? JSONSerialization.jsonObject(with: inputData)) as? [String: Any] ?? [:]
let op = fx["operation"] as? String ?? ""
nonisolated(unsafe) let ins: [String: Any] = fx["inputs"] as? [String: Any] ?? [:]
let env = ProcessInfo.processInfo.environment

nonisolated(unsafe) var res: [String: Any] = [
    "fixture_id": fx["id"] as? String ?? "",
    "outcome": "ok", "error_code": NSNull(), "status": NSNull(), "body_hex": NSNull(),
    "passthrough": false, "plaintext_emitted_before_error": false,
    "bytes_emitted_before_error": 0, "native_error": NSNull(), "runner": "swift",
]

func hexToData(_ s: Any?) -> Data { Data(hexString: (s as? String) ?? "") ?? Data() }
func setBody(_ d: Data) { res["body_hex"] = d.hexString }

func run() async throws {
    switch op {
    case "derive_keys":
        let km = try await EHBPClient.core.deriveResponseKeys(
            exportedSecret: hexToData(ins["exportedSecret"]),
            requestEnc: hexToData(ins["requestEnc"]),
            responseNonce: hexToData(ins["responseNonce"]))
        setBody(km.key + km.nonceBase)
    case "compute_nonce":
        guard let seq = UInt64((ins["seqHex"] as? String) ?? "", radix: 16) else {
            throw EHBPError(.invalidInput, "seqHex is not a hex sequence number")
        }
        setBody(try EHBPClient.core.computeNonce(nonceBase: hexToData(ins["nonceBase"]), seq: seq))
    case "decrypt_response", "decrypt_response_streaming":
        try await decryptOp()
    case "token_roundtrip":
        let token = try SessionRecoveryToken(json: Data(((ins["json"] as? String) ?? "").utf8))
        setBody(token.exportedSecret + token.requestEnc)
    case "parse_config":
        setBody(try EHBPClient.core.parseConfig(hexToData(ins["config"])))
    case "marshal_config":
        setBody(try EHBPClient.core.marshalConfig(publicKey: hexToData(ins["publicKey"])))
    case "discover":
        _ = try await EHBPClient.discover(discoverTarget())
    case "residue_selfcheck":
        // The core's shared vectors through this language's crypto bindings.
        let lines = await EHBPClient.selfCheck()
        setBody(Data(lines.joined(separator: "\n").utf8))
        if !lines.isEmpty { res["native_error"] = lines.joined(separator: "; ") }
    case "reject_reserved_header", "reject_cross_origin", "reject_url_credentials":
        try await hardeningOp()
    case "request", "request_stream", "token_after_exchange", "close_response_early":
        try await exchangeOp()
    case "large_body":
        try await largeBodyOp()
    case "token_before_response":
        try await tokenBeforeResponseOp()
    default:
        throw EHBPError(.invalidInput, "unknown operation \(op)")
    }
}

/// Discovery variants are exposed as ORACLE_<TARGET>_URL (operations.md).
func discoverTarget() -> String {
    let target = ((ins["target"] as? String) ?? "").uppercased()
    if !target.isEmpty, target != "ORACLE_URL", let url = env["ORACLE_\(target)_URL"] { return url }
    return env["ORACLE_URL"] ?? ""
}

/// A client for the oracle, discovering its keys: the one bootstrap shared by
/// every oracle-bound operation.
func oracleClient(_ base: String = env["ORACLE_URL"] ?? "") async throws -> EHBPClient {
    try await EHBPClient(server: base, keys: .discover)
}

func hardeningOp() async throws {
    var base = env["ORACLE_URL"] ?? ""
    var path = "/s/echo"
    var headers = [String: String]()
    switch op {
    case "reject_cross_origin":
        path = "http://other.example/x"
    case "reject_url_credentials":
        base = base.replacingOccurrences(of: "http://", with: "http://user:pass@")
    default:
        let name = ins["header"] as? String ?? EHBPProtocol.responseNonceHeader
        headers[name] = name.lowercased() == "host" ? "attacker.invalid" : String(repeating: "0", count: 64)
    }
    let client = try await oracleClient(base)
    _ = try await client.request(method: "POST", path: path, headers: headers, body: Data([1]))
}

func decryptOp() async throws {
    let token = SessionRecoveryToken(exportedSecret: hexToData(ins["exportedSecret"]), requestEnc: hexToData(ins["requestEnc"]))
    let framed = hexToData(ins["encryptedResponse"])
    let segments = op.hasSuffix("streaming") ? splitAt(framed, (fx["chunking"] as? [NSNumber])?.map { $0.intValue }) : [framed]
    let stream = try await EHBPClient.core.decryptWithToken(token, responseNonce: hexToData(ins["responseNonce"]), chunks: segments)
    var acc = Data()
    do {
        for try await chunk in stream { acc.append(chunk) }
    } catch {
        res["bytes_emitted_before_error"] = acc.count
        res["plaintext_emitted_before_error"] = acc.count > 0
        throw error
    }
    setBody(acc)
}

func fixtureRequest() -> (method: String, path: String, headers: [String: String], body: Data?) {
    let req = fx["request"] as? [String: Any] ?? [:]
    let headers = (req["headers"] as? [String: Any] ?? [:]).compactMapValues { $0 as? String }
    return ((req["method"] as? String) ?? "POST", (req["path"] as? String) ?? "/", headers,
            (req["body_hex"] as? String).flatMap { Data(hexString: $0) })
}

func report(_ response: HTTPURLResponse) {
    res["status"] = response.statusCode
    var hdrs = [String: String]()
    for name in headerSubset {
        if let v = response.value(forHTTPHeaderField: name) { hdrs[name] = v }
    }
    res["response_headers"] = hdrs
    res["passthrough"] = hdrs["ehbp-response-nonce"] == nil && !(200..<300).contains(response.statusCode)
}

/// request, request_stream (the body from an unknown-length producer),
/// close_response_early (one byte, then the stream is dropped) and
/// token_after_exchange (the public accessor read after the exchange ended).
func exchangeOp() async throws {
    let client = try await oracleClient()
    let req = fixtureRequest()
    func exchange() async throws {
        var pending = req.body // one pull, then end: the unknown-length producer of request_stream
        let (stream, response) = try await client.requestStream(
            method: req.method, path: req.path, headers: req.headers,
            bodySource: req.body == nil ? nil : { defer { pending = nil }; return pending })
        report(response)
        var acc = Data()
        if op == "close_response_early" {
            for try await chunk in stream { acc.append(chunk.prefix(1)); break }
            res["token_before_close"] = client.sessionRecoveryToken() != nil
        } else {
            for try await chunk in stream { acc.append(chunk) }
        }
        setBody(acc)
    }
    var failure: Error?
    do { try await exchange() } catch { failure = error }
    // The stream was dropped inside exchange(); the token is cleared on drop.
    try? await Task.sleep(nanoseconds: 100_000_000)
    if op == "close_response_early" { res["token_after_close"] = client.sessionRecoveryToken() != nil }
    if op == "token_after_exchange" { res["token_after_exchange"] = client.sessionRecoveryToken() != nil }
    if let failure { throw failure }
}

// tokenBeforeResponseOp sends the fixture request to the holding oracle route
// and reads the session recovery token while the response is still pending.
func tokenBeforeResponseOp() async throws {
    let client = try await oracleClient()
    let req = fixtureRequest()
    let pending = Task { try await client.request(method: req.method, path: req.path, body: req.body) }
    try await Task.sleep(nanoseconds: 500_000_000) // oracle holds 5 s
    res["token_before_response"] = client.sessionRecoveryToken() != nil
    let (data, response) = try await pending.value
    report(response)
    setBody(data)
}

// largeBodyOp streams a multi-GiB patterned body through the client's
// bodySource path to the oracle's digest route and reports peak RSS so any
// buffering is visible.
func largeBodyOp() async throws {
    let size = Int64((ins["size_bytes"] as? NSNumber)?.int64Value ?? 0)
    let seed = Int((ins["block_seed"] as? NSNumber)?.intValue ?? 0)
    let client = try await oracleClient()
    let req = fixtureRequest()

    // 1 MiB block with block[i] = (i + seed) & 0xff, repeated; never materialised.
    let block = Data((0..<(1 << 20)).map { UInt8(truncatingIfNeeded: $0 + seed) })
    var remaining = size
    let (data, response) = try await client.request(method: req.method, path: req.path, bodySource: {
        if remaining <= 0 { return nil }
        let n = Int(min(remaining, Int64(block.count)))
        remaining -= Int64(n)
        return n == block.count ? block : block.prefix(n)
    })
    res["status"] = response.statusCode
    setBody(data)
    var usage = rusage()
    getrusage(RUSAGE_SELF, &usage)
    res["peak_rss_bytes"] = Int(usage.ru_maxrss) // bytes on macOS
}

// mapError reads the canonical code the library attached; anything uncoded is
// a caller/adapter input error.
func mapError(_ error: Error) -> String {
    (error as? EHBPError)?.code?.rawValue ?? "INVALID_INPUT"
}

func splitAt(_ data: Data, _ offsets: [Int]?) -> [Data] {
    guard let offsets, !offsets.isEmpty else { return [data] }
    var segs = [Data]()
    var prev = 0
    for o in offsets where o > prev && o < data.count {
        segs.append(data.subdata(in: prev..<o))
        prev = o
    }
    segs.append(data.subdata(in: prev..<data.count))
    return segs
}

do {
    try await run()
} catch {
    res["outcome"] = "error"
    res["error_code"] = mapError(error)
    res["body_hex"] = NSNull()
    res["native_error"] = (error as? EHBPError)?.errorDescription ?? String(describing: error)
}

FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: res))
