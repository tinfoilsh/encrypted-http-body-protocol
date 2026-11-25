// Helpers over the pure core: config parse and marshal, token parse and
// format, key derivation, nonce and response decryption. Not part of the
// client API; reached through `EHBPClient.core` for the conformance adapter
// and tests only (conformance/spec/handler.md section 7).

import Foundation

/// Session recovery token (SPEC 6): the HPKE exported secret and the request
/// encapsulated key of one exchange.
public struct SessionRecoveryToken: Sendable, Equatable {
    public let exportedSecret: Data
    public let requestEnc: Data

    public init(exportedSecret: Data, requestEnc: Data) {
        self.exportedSecret = exportedSecret
        self.requestEnc = requestEnc
    }

    /// Parses the SPEC 6.1.1 JSON form; any malformation is `INVALID_TOKEN`.
    public init(json: Data) throws {
        let (secret, enc) = Core.parseToken(String(decoding: json, as: UTF8.self))
        let t = try Core.validateTokenFields(secret, enc)
        (exportedSecret, requestEnc) = (t.exportedSecret, t.requestEnc)
    }

    /// The SPEC 6.1.1 JSON form.
    public var json: Data {
        Data(Core.formatToken(exportedSecret.hexString, requestEnc.hexString).utf8)
    }
}

public enum CoreHelpers {
    /// Parses `/.well-known/hpke-keys` bytes (RFC 9458, SPEC 3.2) to the first config's public key.
    public static func parseConfig(_ config: Data) throws -> Data { try Core.parseConfig(config) }

    public static func marshalConfig(publicKey: Data) throws -> Data { try Core.marshalConfig(publicKey) }

    /// SPEC 4.4 (DeriveResponseKeys): the core's own derivation, run as the
    /// token-only exchange `DeriveStart` up to `Done`, then `KeysOf`.
    public static func deriveResponseKeys(exportedSecret: Data, requestEnc: Data, responseNonce: Data) async throws -> (key: Data, nonceBase: Data) {
        let x = tokenExchange(SessionRecoveryToken(exportedSecret: exportedSecret, requestEnc: requestEnc), responseNonce, response: nil)
        await x.feed(.responseHead(status: 200, headers: [(EHBPProtocol.responseNonceHeader, responseNonce.hexString)], redirected: false))
        if let failure = x.out.failure { throw failure }
        guard let keys = x.state.keysOf() else { throw EHBPError.network("derivation ended without keys") }
        return keys
    }

    public static func computeNonce(nonceBase: Data, seq: UInt64) throws -> Data { try Core.nonceFor(nonceBase, seq) }

    /// SPEC 6.2: decrypts a framed response body from a token alone, as the
    /// token-only exchange `DecryptStart` over `chunks` as the response body;
    /// plaintext is released frame by frame as the stream is read.
    public static func decryptWithToken(_ token: SessionRecoveryToken, responseNonce: Data, chunks: [Data]) async throws -> AsyncThrowingStream<Data, Error> {
        var pending = chunks[...]
        let x = tokenExchange(token, responseNonce, response: Chunks { pending.popFirst() })
        await x.feed(.responseHead(status: 200, headers: [(EHBPProtocol.responseNonceHeader, responseNonce.hexString)], redirected: false))
        if let failure = x.out.failure { throw failure }
        return plaintext(x)
    }

    private static func tokenExchange(_ token: SessionRecoveryToken, _ nonce: Data, response: Chunks?) -> Exchange {
        Exchange(state: CoreState(token: (token.exportedSecret, token.requestEnc)), session: Session(), urlSession: .shared, body: nil, response: response)
    }
}

public extension Data {
    /// Strict lowercase-or-uppercase hex decoding by the core; nil on any malformation.
    init?(hexString: String) {
        guard let d = Core.decodeHex(hexString) else { return nil }
        self = d
    }

    var hexString: String { Core.encodeHex(self) }
}
