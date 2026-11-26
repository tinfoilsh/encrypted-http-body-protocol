import Foundation

/// Canonical, cross-SDK error class (SPEC Section 5.5). Raw values are identical
/// in every SDK, so a caller's handling ports between languages.
public enum EHBPErrorCode: String, Sendable {
    case invalidKeyConfig = "INVALID_KEY_CONFIG"
    case unsupportedSuite = "UNSUPPORTED_SUITE"
    case invalidEncapsulatedKey = "INVALID_ENCAPSULATED_KEY"
    case hpkeSetupFailed = "HPKE_SETUP_FAILED"
    case missingResponseNonce = "MISSING_RESPONSE_NONCE"
    case unexpectedRedirect = "UNEXPECTED_REDIRECT"
    case invalidResponseNonce = "INVALID_RESPONSE_NONCE"
    case duplicateResponseNonce = "DUPLICATE_RESPONSE_NONCE"
    case keyConfigMismatch = "KEY_CONFIG_MISMATCH"
    case framingTruncated = "FRAMING_TRUNCATED"
    case chunkTooLarge = "CHUNK_TOO_LARGE"
    case aeadDecryptFailed = "AEAD_DECRYPT_FAILED"
    case sequenceOverflow = "SEQUENCE_OVERFLOW"
    case invalidToken = "INVALID_TOKEN"
    case invalidInput = "INVALID_INPUT"
}

/// EHBP error: a canonical code (SPEC Section 5.5) plus detail, described as
/// "<CODE>: <detail>". Compare `code`, as with `URLError.code`. Codes are for the
/// in-process caller only and are never sent on the wire (SPEC 5.4.4).
public struct EHBPError: Error, LocalizedError {
    /// `nil` for a transport failure, which carries no canonical code.
    public let code: EHBPErrorCode?
    public let detail: String

    public init(_ code: EHBPErrorCode, _ detail: String) {
        self.code = code
        self.detail = detail
    }

    public static func network(_ detail: String) -> EHBPError {
        EHBPError(code: nil, detail: detail)
    }

    private init(code: EHBPErrorCode?, detail: String) {
        self.code = code
        self.detail = detail
    }

    public var errorDescription: String? {
        guard let code else { return detail }
        return "\(code.rawValue): \(detail)"
    }
}
