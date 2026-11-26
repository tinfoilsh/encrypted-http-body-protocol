// The Swift residue of the event-driven core (dafny/ehbp_events.dfy): one
// binding per action the core can emit, laid out as conformance/spec/handler.md
// section 4 (crypto, http, session, pump, conversions, mapping). Nothing here
// decides anything about the protocol.

import CryptoKit
import Foundation

// crypto: one native call each, bytes in, bytes out. A failure is an empty
// result (or ok false for aeadOpen), which the core rejects by length.
// CryptoKit: Curve25519.KeyAgreement (an all-zero output is a low-order point), HMAC<SHA256>, AES.GCM, SystemRandomNumberGenerator.

func x25519(_ scalar: Data, _ point: Data) -> Data {
    guard let sk = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar),
          let pk = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: point),
          let shared = try? sk.sharedSecretFromKeyAgreement(with: pk) else { return Data() }
    let out = shared.withUnsafeBytes { Data($0) }
    return out.allSatisfy { $0 == 0 } ? Data() : out
}

func hmacSha256(_ key: Data, _ data: Data) -> Data {
    return Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
}

func aeadSeal(_ key: Data, _ nonce: Data, _ plaintext: Data) -> Data {
    guard key.count == 32, nonce.count == 12, let n = try? AES.GCM.Nonce(data: nonce),
          let box = try? AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: n) else { return Data() }
    return box.ciphertext + box.tag
}

func aeadOpen(_ key: Data, _ nonce: Data, _ ciphertext: Data) -> (Bool, Data) {
    guard key.count == 32, nonce.count == 12, ciphertext.count >= 16, let n = try? AES.GCM.Nonce(data: nonce),
          let box = try? AES.GCM.SealedBox(nonce: n, ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16)),
          let plaintext = try? AES.GCM.open(box, using: SymmetricKey(data: key)) else { return (false, Data()) }
    return (true, plaintext)
}

func randomBytes(_ length: Int) -> Data {
    var rng = SystemRandomNumberGenerator()
    return Data((0..<length).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
}

// http: the only block holding native state. One Exchange per request or
// discovery; the bindings are its methods. The upload is a bound stream pair
// (URLSession reads the InputStream as a chunked body while `write` fills the
// OutputStream); the response arrives through a per-task delegate.

/// Pull-based request body: return the next plaintext chunk, or nil at end.
public typealias RequestBodySource = () throws -> Data?

typealias Chunks = AsyncThrowingStream<Data, Error>

/// The outcome, written by the terminal actions and read by the shim.
struct Outcome {
    var failure: Error?
    var passthrough = false, done = false, finished = false
    var status: Int64 = 0
    var headers: Headers = []
    var prefix = Data(), publicKey = Data()
    var plain = Data()        // EmitPlaintext since the last Read
    var cause: Error?         // the native error behind a Transport failure
    var generation: UInt64?   // what beginSession handed out, for cancellation
    var lane: Task<Void, Never>? // the upload lane
}

final class Exchange: @unchecked Sendable {
    let state: CoreState
    let session: Session
    let urlSession: URLSession
    let lock = NSLock()
    var out = Outcome()
    private var body: RequestBodySource?          // the caller's request body, nil when absent
    private var output: OutputStream?             // the encrypted upload, fed by write
    private let uploadQueue = DispatchQueue(label: "sh.tinfoil.ehbp.upload")
    private var task: URLSessionDataTask?         // the native transaction
    var response: Chunks.AsyncIterator?           // the native response body

    /// Binds a core state to the native pieces: `urlSession` performs one HTTP
    /// transaction; `body` is the caller's body or nil; `response` is a
    /// pre-supplied body for the token-only path.
    init(state: CoreState, session: Session, urlSession: URLSession, body: RequestBodySource?, response: Chunks? = nil) {
        self.state = state; self.session = session; self.urlSession = urlSession; self.body = body
        self.response = response?.makeAsyncIterator()
    }

    // http: the four performers over URLSession (send, write, read, close), written by hand.
    /// Performs the transaction and reports its head; with a body the upload
    /// lane feeds the bound stream meanwhile. The task delegate refuses every
    /// redirect, so `redirected` is never true.
    func send(_ verb: String, _ url: String, _ headers: Headers, _ hasBody: Bool) async -> (Int64, Headers, Bool)? {
        guard let target = URL(string: url) else { return nil }
        var request = URLRequest(url: target)
        request.httpMethod = verb
        for (name, value) in headers { request.addValue(value, forHTTPHeaderField: name) }
        if hasBody {
            var input: InputStream?
            Foundation.Stream.getBoundStreams(withBufferSize: 64 * 1024, inputStream: &input, outputStream: &output)
            request.httpBodyStream = input
            output?.open()
        }
        let delegate = ResponseDelegate()
        let task = urlSession.dataTask(with: request)
        task.delegate = delegate
        lock.withLock { self.task = task; response = delegate.chunks.makeAsyncIterator() }
        let head = await withTaskCancellationHandler {
            await withCheckedContinuation { delegate.head = $0; task.resume() }
        } onCancel: { task.cancel() }
        guard let head else { lock.withLock { out.cause = out.cause ?? delegate.error }; return nil }
        return (Int64(head.statusCode), headerSeq(head), false)
    }

    /// Feeds one encrypted chunk and, by `end`, ends the upload: Done closes
    /// the stream, Aborted cancels the transaction with the code as the cause;
    /// false once the stream is gone. Writes block on the bound buffer, so
    /// they run off the cooperative pool.
    func write(_ data: Data, _ end: BodyEnd) async -> Bool {
        if case .aborted(let code) = end {
            lock.withLock { out.cause = error(code, "request body failed", out.cause); task?.cancel() }
        }
        return await withCheckedContinuation { c in uploadQueue.async {
            guard let output = self.lock.withLock({ self.output }) else { return c.resume(returning: false) }
            var ok = true
            data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
                var at = 0
                while ok, at < buf.count {
                    let n = output.write(buf.baseAddress!.advanced(by: at).assumingMemoryBound(to: UInt8.self), maxLength: buf.count - at)
                    if n <= 0 { ok = false } else { at += n }
                }
            }
            if case .more = end {} else { output.close(); self.lock.withLock { self.output = nil; self.body = nil } }
            c.resume(returning: ok)
        } }
    }

    /// Reads once from the caller's body or the native response: the chunk and eof; nil on a failure, kept as the cause.
    func read(_ stream: Stream) async -> (Data, Bool)? {
        do {
            if stream == .requestBody {
                guard let body else { return nil }
                return try body().map { ($0, false) } ?? (Data(), true)
            }
            let next = try await withTaskCancellationHandler { try await response?.next() } onCancel: { task?.cancel() }
            return next.map { ($0, false) } ?? (Data(), true)
        } catch {
            lock.withLock { out.cause = error }
            return nil
        }
    }

    /// Releases the native stream.
    func close(_ stream: Stream) async {
        lock.withLock {
            if stream == .requestBody { body = nil; output?.close(); output = nil } else { task?.cancel(); response = nil }
        }
    }

    /// Cancellation: the upload lane stops and the token this exchange
    /// published, if still current, is cleared.
    func cancel() {
        let (lane, generation) = lock.withLock { defer { out.lane = nil; out.generation = nil }; return (out.lane, out.generation) }
        lane?.cancel()
        task?.cancel()
        if let generation { session.clearToken(generation) }
    }
}

/// One URLSession transaction: the head, then the body as chunks.
private final class ResponseDelegate: NSObject, URLSessionDataDelegate {
    var head: CheckedContinuation<HTTPURLResponse?, Never>?
    var error: Error?
    private var feed: Chunks.Continuation!
    private(set) lazy var chunks = Chunks { feed = $0 }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        head?.resume(returning: response as? HTTPURLResponse); head = nil
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) { feed.yield(data) }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        self.error = error
        head?.resume(returning: nil); head = nil
        feed.finish(throwing: error)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

/// Keeps `onDrop` alive with the caller's stream; dropping the stream runs it.
private final class Lifetime { let onDrop: () -> Void; init(_ onDrop: @escaping () -> Void) { self.onDrop = onDrop }; deinit { onDrop() } }

/// The pass-through body: the bytes the core read ahead, then the rest of the native response.
func passthrough(_ x: Exchange) -> Chunks {
    let lifetime = Lifetime { x.cancel() }
    var prefix: Data? = x.out.prefix.isEmpty ? nil : x.out.prefix
    return Chunks {
        _ = lifetime
        if let p = prefix { prefix = nil; return p }
        return try await x.response?.next()
    }
}

/// The decrypted body after Done: each pull drives the core with CallerRead until it emits plaintext, finishes or fails.
func plaintext(_ x: Exchange) -> Chunks {
    let lifetime = Lifetime { if !x.out.finished { Task { await x.feed(.callerClose) } } }
    return Chunks {
        _ = lifetime
        while true {
            if x.out.finished || x.out.failure != nil { return nil }
            await x.feed(.callerRead)
            let plain = x.lock.withLock { defer { x.out.plain = Data() }; return x.out.plain }
            if !plain.isEmpty { return plain }
            if let failure = x.out.failure { throw failure }
            if x.out.finished { return nil }
        }
    }
}

// session: a mutex around one SessionStore value; every rule is SessionApply.

final class Session: @unchecked Sendable {
    private let lock = NSLock()
    private var store = Core.newSession()

    private func apply(_ a: SessionAction) -> SessionStore {
        lock.withLock { store = Core.sessionApply(store, a); return store }
    }

    func beginSession() -> UInt64 {
        apply(.begin).generation
    }

    func publishToken(_ generation: UInt64, _ exportedSecret: Data, _ requestEnc: Data) {
        _ = apply(.publish(generation: generation, token: Token(exportedSecret: exportedSecret, requestEnc: requestEnc)))
    }

    func clearToken(_ generation: UInt64) {
        _ = apply(.clear(generation: generation))
    }

    /// The stored token, or none; never computes anything.
    func token() -> (Data, Data)? {
        lock.withLock { store }.token.map { ($0.exportedSecret, $0.requestEnc) }
    }
}

// pump: handler.md section 5, written by hand: perform awaits inside and
// the C ABI carries Step, not Perform.

enum Control {
    case none          // no result event
    case event(Event)  // feed the event back
    case stop          // the upload sink is gone; this lane ends
}

extension Exchange {
    /// Maps one action to one binding call and returns the result event.
    func perform(_ a: Action) async -> Control {
        switch a {
        case .beginSession:
            let generation = session.beginSession()
            lock.withLock { out.generation = generation }
            return .event(.sessionBegun(generation: generation))
        case let .publishToken(generation, exportedSecret, requestEnc): session.publishToken(generation, exportedSecret, requestEnc); return .none
        case let .clearToken(generation): session.clearToken(generation); return .none
        case let .randomBytes(length): return .event(.randomResult(data: randomBytes(Int(length))))
        case let .x25519(scalar, point): return .event(.x25519Result(point: x25519(scalar, point)))
        case let .hmacSha256(key, data): return .event(.hmacResult(mac: hmacSha256(key, data)))
        case let .aeadSeal(key, nonce, plaintext): return .event(.aeadSealResult(ciphertext: aeadSeal(key, nonce, plaintext)))
        case let .aeadOpen(key, nonce, ciphertext):
            let (ok, plaintext) = aeadOpen(key, nonce, ciphertext)
            return .event(.aeadOpenResult(ok: ok, plaintext: plaintext))
        case let .send(verb, url, headers, hasBody):
            guard let (status, headers, redirected) = await send(verb, url, headers, hasBody) else { return .event(.streamFailed(stream: .responseBody)) }
            return .event(.responseHead(status: status, headers: headers, redirected: redirected))
        case let .write(data, end): return await write(data, end) ? .none : .stop
        case let .read(stream):
            guard let (data, eof) = await read(stream) else { return .event(.streamFailed(stream: stream)) }
            return .event(.chunk(stream: stream, data: data, eof: eof))
        case let .close(stream): await close(stream); return .none
        default: return .none
        }
    }

    /// Feeds events to Step until a terminal action. A Send with a body hands
    /// the rest of its action list, the upload, to a second lane (a Task) so
    /// the transaction can await the response head; this lane stops there.
    func run(_ first: [Action]) async {
        var acts = first
        var events: [Event] = []
        while true {
            lane: for (i, a) in acts.enumerated() {
                let settled: Bool = lock.withLock {
                    switch a {
                    case let .emitPlaintext(data): out.plain.append(data); return false
                    case let .passthrough(status, headers, prefix): (out.passthrough, out.status, out.headers, out.prefix) = (true, status, headers, prefix); return true
                    case let .done(status, headers): (out.done, out.status, out.headers) = (true, status, headers); return true
                    case .finished: out.finished = true; return true
                    case let .discovered(publicKey): out.publicKey = publicKey; return true
                    case let .fail(code, message): out.failure = error(code, message, out.cause); out.cause = nil; return true
                    case .send(_, _, _, true):
                        let rest = Array(acts[(i + 1)...])
                        out.lane = Task { await self.run(rest) }
                        return false
                    default: return false
                    }
                }
                if case .emitPlaintext = a { continue }
                if settled { return }
                switch await perform(a) {
                case .stop: return
                case .event(let e): events.append(e)
                case .none: break
                }
                if case .send(_, _, _, true) = a { break lane }
            }
            guard let e = events.popLast() else { return }
            acts = state.step(e)
        }
    }

    /// Runs the pump on one caller event: Start, DiscoverStart, ResponseHead
    /// (the token-only path), CallerRead or CallerClose.
    func feed(_ e: Event) async {
        await run(state.step(e))
    }
}

// conversions: the runtime boundary only. Bytes and strings cross the FFI as
// they are; only headers change shape.

/// The core's header list: URLSession coalesces repeated names into one value.
func headerSeq(_ response: HTTPURLResponse) -> Headers {
    response.allHeaderFields.compactMap { name, value in (name as? String).map { ($0, "\(value)") } }
}

/// The core's header list back as the native dictionary; repeated names join with ", ".
func headerPairs(_ headers: Headers) -> [String: String] {
    var map = [String: String]()
    for (name, value) in headers { map[name] = map[name].map { "\($0), \(value)" } ?? value }
    return map
}

// mapping: from the core's CodeString; no table of strings.

/// The canonical code of a core code; Transport has none.
func code(_ c: Code) -> EHBPErrorCode? {
    EHBPErrorCode(rawValue: Core.codeString(c))
}

/// A core failure as a Swift error: a coded protocol error, or the native
/// cause of a Transport failure.
func error(_ c: Code, _ message: String, _ cause: Error?) -> Error {
    switch (code(c), cause) {
    case (let code?, let cause?): return EHBPError(code, "\(message): \(cause.localizedDescription)")
    case (let code?, nil): return EHBPError(code, message)
    case (nil, let cause?): return cause
    case (nil, nil): return EHBPError.network(message)
    }
}

// Self-check: the core's primitive vectors through this residue.

func selfCheck() async -> [String] {
    let x = Exchange(state: CoreState(origin: Origin(scheme: "https", host: "localhost", port: 443), publicKey: Data()),
                     session: Session(), urlSession: .shared, body: nil)
    var results: [Event] = []
    for a in Core.selfCheckActions() {
        if case .event(let e) = await x.perform(a) { results.append(e) }
    }
    return Core.selfCheckJudge(results)
}
