// The API shim over the event-driven EHBP core (dafny/ehbp_events.dfy).
// Every protocol decision is made by the core; this file parses URLs,
// collects headers, wraps bodies, runs the pump in Pump.swift and turns the
// core's terminal actions back into URLSession-shaped responses
// (conformance/spec/handler.md section 7).

import Foundation

/// Where the server's HPKE public key comes from (SPEC 3).
public enum KeySource: Sendable {
    /// Fetch `/.well-known/hpke-keys` from the server.
    case discover
    /// A key configuration (RFC 9458 bytes).
    case config(Data)
    /// The X25519 public key itself (32 bytes).
    case publicKey(Data)
}

/// Streaming EHBP client for making encrypted HTTP requests.
public final class EHBPClient: @unchecked Sendable {
    private let baseURL: URL
    private let origin: Origin
    private let publicKey: Data
    private let urlSession: URLSession
    private let session = Session()

    // constructor: a Client over one server origin and the key a KeySource yields.

    /// `server` is an http(s) origin; `session` carries the native transport
    /// options (timeouts, pinning). Redirects are never followed.
    public init(server: String, keys: KeySource, session: URLSession = .shared) async throws {
        let (baseURL, origin) = try EHBPClient.parse(server)
        self.baseURL = baseURL
        self.origin = origin
        self.urlSession = session
        switch keys {
        case .discover: publicKey = try await EHBPClient.discover(origin, session)
        case .config(let config): publicKey = try Core.parseConfig(config)
        case .publicKey(let key): publicKey = try Core.checkPublicKey(key)
        }
    }

    // discover: the same discovery the constructor runs; the 32-byte public key.

    /// The discovery the constructor runs (SPEC 3.1), for callers that cache
    /// keys: the server's public key, for `KeySource.publicKey`.
    public static func discover(_ server: String, session: URLSession = .shared) async throws -> Data {
        try await discover(parse(server).origin, session)
    }

    private static func discover(_ origin: Origin, _ session: URLSession) async throws -> Data {
        let x = Exchange(state: CoreState(origin: origin, publicKey: Data()), session: Session(), urlSession: session, body: nil)
        await x.feed(.discoverStart)
        if let failure = x.out.failure { throw failure }
        return x.out.publicKey
    }

    // token: the exchange in flight.

    /// The token of the exchange in flight, or nil (SPEC 6): nil before any
    /// request, after a bodyless one, and once an exchange has ended.
    public func sessionRecoveryToken() -> SessionRecoveryToken? {
        session.token().map { SessionRecoveryToken(exportedSecret: $0.0, requestEnc: $0.1) }
    }

    // request: the one entry point; the buffered forms are wrappers.

    /// One exchange: the core validates, seals the body when present,
    /// classifies the response and decrypts its body as the stream is read.
    /// `path` resolves against the server; `bodySource` is pulled chunk by
    /// chunk (nil at end) and encrypted with O(frame) memory, or nil for a
    /// bodyless request. A 4xx or 5xx an intermediary answers in plaintext
    /// passes through untouched; `UNEXPECTED_REDIRECT` when the answer is a
    /// redirect, which is never followed.
    public func requestStream(
        method: String,
        path: String,
        headers: [String: String] = [:],
        bodySource: RequestBodySource?
    ) async throws -> (stream: AsyncThrowingStream<Data, Error>, response: HTTPURLResponse) {
        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
              let u = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw EHBPError(.invalidInput, "invalid URL: \(path)")
        }
        let x = Exchange(state: CoreState(origin: origin, publicKey: publicKey), session: session, urlSession: urlSession, body: bodySource)
        await x.feed(.start(
            verb: method, url: url.absoluteString, scheme: u.scheme ?? "", host: u.host ?? "",
            port: Int64(u.port ?? 0), hasPort: u.port != nil, hasUserinfo: u.user != nil || u.password != nil,
            headers: headers.map { ($0.key, $0.value) }, hasBody: bodySource != nil))
        if let failure = x.out.failure { throw failure }
        guard let response = HTTPURLResponse(url: url, statusCode: Int(x.out.status), httpVersion: "HTTP/1.1", headerFields: headerPairs(x.out.headers)) else {
            throw EHBPError.network("transport reported an impossible status")
        }
        if x.out.passthrough { return (passthrough(x), response) }
        if x.out.done { return (plaintext(x), response) }
        throw EHBPError.network("exchange ended without an outcome")
    }

    /// Reads the whole response of `requestStream`.
    public func request(
        method: String,
        path: String,
        headers: [String: String] = [:],
        bodySource: RequestBodySource?
    ) async throws -> (data: Data, response: HTTPURLResponse) {
        let (stream, response) = try await requestStream(method: method, path: path, headers: headers, bodySource: bodySource)
        var data = Data()
        for try await chunk in stream { data.append(chunk) }
        return (data, response)
    }

    public func request(
        method: String,
        path: String,
        headers: [String: String] = [:],
        body: Data?
    ) async throws -> (data: Data, response: HTTPURLResponse) {
        try await request(method: method, path: path, headers: headers, bodySource: body.map(EHBPClient.once))
    }

    public func requestStream(
        method: String,
        path: String,
        headers: [String: String] = [:],
        body: Data?
    ) async throws -> (stream: AsyncThrowingStream<Data, Error>, response: HTTPURLResponse) {
        try await requestStream(method: method, path: path, headers: headers, bodySource: body.map(EHBPClient.once))
    }

    // selfCheck: the core's known-answer vectors through this residue's bindings.

    /// The failed checks of the core's self-check (dafny/ehbp_events.dfy
    /// `SelfCheckActions`) through this SDK's crypto bindings; empty on pass.
    public static func selfCheck() async -> [String] { await EHBP.selfCheck() }

    /// Helpers over the pure core, for the conformance adapter and tests only.
    public static var core: CoreHelpers.Type { CoreHelpers.self }

    /// Validates the origin (MakeOrigin) and makes relative paths resolve under it.
    private static func parse(_ server: String) throws -> (baseURL: URL, origin: Origin) {
        guard var u = URLComponents(string: server) else { throw EHBPError(.invalidInput, "invalid URL: \(server)") }
        let origin = try Core.makeOrigin(u.scheme ?? "", u.host ?? "", u.port.map(Int64.init), u.user != nil || u.password != nil)
        if !u.path.hasSuffix("/") { u.path += "/" }
        return (u.url!, origin)
    }

    /// A buffered body as a one-shot source.
    private static func once(_ body: Data) -> RequestBodySource {
        var pending: Data? = body
        return { defer { pending = nil }; return pending }
    }
}
