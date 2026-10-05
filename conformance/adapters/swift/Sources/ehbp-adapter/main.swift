// EHBP conformance adapter (Swift). See conformance/adapters/README.md.
//
// Reads one fixture on stdin, runs it through the public EHBP API, prints one
// normalized result. parse_config/marshal_config are reported skipped: the Swift
// library is client-only and exposes no accessor for the parsed public key.
// All native-error translation lives in mapError.

import Foundation
import EHBP

let headerSubset = ["ehbp-response-nonce", "content-length", "transfer-encoding", "content-type"]

// A local URLProtocol sink makes origin/header probes deterministic and ensures
// an unguarded request never reaches the network.
final class GuardProbeURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!, statusCode: 502, httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "text/plain"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data("probe".utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

let inputData = FileHandle.standardInput.readDataToEndOfFile()
let fx = (try? JSONSerialization.jsonObject(with: inputData)) as? [String: Any] ?? [:]
let op = fx["operation"] as? String ?? ""

var res: [String: Any] = [
    "fixture_id": fx["id"] as? String ?? "",
    "outcome": "ok", "error_code": NSNull(), "status": NSNull(), "body_hex": NSNull(),
    "passthrough": false, "plaintext_emitted_before_error": false,
    "bytes_emitted_before_error": 0, "native_error": NSNull(), "runner": "swift",
]

func hexToData(_ s: Any?) -> Data { Data(hexString: (s as? String) ?? "") ?? Data() }
func setBody(_ d: Data) { res["body_hex"] = d.hexString }

func run() async throws {
    let ins = fx["inputs"] as? [String: Any] ?? [:]
    switch op {
    case "derive_keys":
        let km = try deriveResponseKeys(
            exportedSecret: hexToData(ins["exportedSecret"]),
            requestEnc: hexToData(ins["requestEnc"]),
            responseNonce: hexToData(ins["responseNonce"]))
        let keyData = km.key.withUnsafeBytes { Data($0) }
        setBody(keyData + km.nonceBase)
    case "compute_nonce":
        let seq = UInt64((ins["seqHex"] as? String) ?? "", radix: 16) ?? 0
        setBody(computeNonce(nonceBase: hexToData(ins["nonceBase"]), seq: seq))
    case "decrypt_response", "decrypt_response_streaming":
        try decryptOp(ins)
    case "token_roundtrip":
        let json = Data(((ins["json"] as? String) ?? "").utf8)
        let token = try SessionRecoveryToken(json: json)
        setBody(token.exportedSecret + token.requestEnc)
    case "parse_config", "marshal_config":
        res["outcome"] = "skipped"
        res["skip_reason"] = "swift-client-has-no-public-key-accessor-or-config-marshal"
    case "discover":
        res["outcome"] = "skipped"
        res["skip_reason"] = "swift-client-has-no-discovery-or-request-guards"
    case "reject_reserved_header", "reject_cross_origin", "reject_url_credentials":
        try await hardeningOp(op)
    case "request":
        try await requestOp()
    case "large_body":
        try await largeBodyOp(ins)
    default:
        throw EHBPError(.invalidInput, "unknown operation \(op)")
    }
}

func hardeningOp(_ operation: String) async throws {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [GuardProbeURLProtocol.self]
    let session = URLSession(configuration: configuration)
    let publicKey = Data(repeating: 7, count: 32)

    var base = "http://configured.example"
    var path = "/probe"
    var headers = [String: String]()
    if operation == "reject_cross_origin" {
        // Same absolute cross-origin target the Python and Rust adapters use.
        path = "http://other.example/probe"
    } else if operation == "reject_url_credentials" {
        base = "http://user:pass@configured.example"
    } else {
        headers[EHBPProtocol.responseNonceHeader] = String(repeating: "0", count: 64)
    }

    let client = try EHBPClient(baseURL: base, publicKey: publicKey, session: session)
    _ = try await client.request(
        method: "POST", path: path, headers: headers, body: Data([1]))
}

func decryptOp(_ ins: [String: Any]) throws {
    let token = SessionRecoveryToken(
        exportedSecret: hexToData(ins["exportedSecret"]),
        requestEnc: hexToData(ins["requestEnc"]))
    var decryptor = try token.makeResponseDecryptor(responseNonce: hexToData(ins["responseNonce"]))
    let framed = hexToData(ins["encryptedResponse"])
    let segments = op.hasSuffix("streaming")
        ? splitAt(framed, (fx["chunking"] as? [NSNumber])?.map { $0.intValue })
        : [framed]

    var acc = Data()
    do {
        for seg in segments {
            for chunk in try decryptor.push(seg) { acc.append(chunk) }
        }
        try decryptor.finish()
    } catch {
        res["bytes_emitted_before_error"] = acc.count
        res["plaintext_emitted_before_error"] = acc.count > 0
        throw error
    }
    setBody(acc)
}

func requestOp() async throws {
    let base = ProcessInfo.processInfo.environment["ORACLE_URL"] ?? ""
    let (config, _) = try await URLSession.shared.data(from: URL(string: base + "/.well-known/hpke-keys")!)
    let client = try EHBPClient(baseURL: base, config: config)

    let req = fx["request"] as? [String: Any] ?? [:]
    var headers = [String: String]()
    if let h = req["headers"] as? [String: Any] {
        for (k, v) in h { if let s = v as? String { headers[k] = s } }
    }
    var body: Data?
    if let bh = req["body_hex"] as? String { body = Data(hexString: bh) }

    let (data, response) = try await client.request(
        method: (req["method"] as? String) ?? "POST",
        path: (req["path"] as? String) ?? "/",
        headers: headers, body: body)

    res["status"] = response.statusCode
    var hdrs = [String: String]()
    for name in headerSubset {
        if let v = response.value(forHTTPHeaderField: name) { hdrs[name] = v }
    }
    res["response_headers"] = hdrs
    let noNonce = hdrs["ehbp-response-nonce"] == nil
    setBody(data)
    res["passthrough"] = noNonce && !(200..<300).contains(response.statusCode)
}

// largeBodyOp streams a multi-GiB patterned body through the client's
// bodySource path to the oracle's digest route and reports peak RSS so any
// buffering is visible. Mirrors the Go adapter's op.
func largeBodyOp(_ ins: [String: Any]) async throws {
    let size = Int64((ins["size_bytes"] as? NSNumber)?.int64Value ?? 0)
    let seed = Int((ins["block_seed"] as? NSNumber)?.intValue ?? 0)
    let base = ProcessInfo.processInfo.environment["ORACLE_URL"] ?? ""
    let (config, _) = try await URLSession.shared.data(from: URL(string: base + "/.well-known/hpke-keys")!)
    let client = try EHBPClient(baseURL: base, config: config)
    let req = fx["request"] as? [String: Any] ?? [:]

    // 1 MiB block with block[i] = (i + seed) & 0xff, repeated; never materialised.
    let block = Data((0..<(1 << 20)).map { UInt8(truncatingIfNeeded: $0 + seed) })
    var remaining = size
    let (data, response) = try await client.request(
        method: (req["method"] as? String) ?? "POST",
        path: (req["path"] as? String) ?? "/",
        bodySource: {
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
func mapError(_ op: String, _ error: Error) -> String {
    (error as? EHBPError)?.code?.rawValue ?? "INVALID_INPUT"
}

func splitAt(_ data: Data, _ offsets: [Int]?) -> [Data] {
    guard let offsets = offsets, !offsets.isEmpty else { return [data] }
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
    res["error_code"] = mapError(op, error)
    res["body_hex"] = NSNull()
    res["native_error"] = (error as? EHBPError)?.errorDescription ?? String(describing: error)
}

let outData = try JSONSerialization.data(withJSONObject: res)
FileHandle.standardOutput.write(outData)
