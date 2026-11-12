// Mirrors protocol/errors.go.
package sh.tinfoil.ehbp.protocol

import java.io.IOException

/**
 * Code is the canonical, cross-SDK error class (SPEC 5.5). Every SDK exposes
 * the same strings, so a caller's error handling ports between languages.
 */
enum class Code(val value: String) {
    InvalidKeyConfig("INVALID_KEY_CONFIG"),
    UnsupportedSuite("UNSUPPORTED_SUITE"),
    InvalidEncapsulatedKey("INVALID_ENCAPSULATED_KEY"),
    HPKESetupFailed("HPKE_SETUP_FAILED"),
    MissingResponseNonce("MISSING_RESPONSE_NONCE"),
    InvalidResponseNonce("INVALID_RESPONSE_NONCE"),
    DuplicateResponseNonce("DUPLICATE_RESPONSE_NONCE"),
    KeyConfigMismatch("KEY_CONFIG_MISMATCH"),
    FramingTruncated("FRAMING_TRUNCATED"),
    ChunkTooLarge("CHUNK_TOO_LARGE"),
    AEADDecryptFailed("AEAD_DECRYPT_FAILED"),
    SequenceOverflow("SEQUENCE_OVERFLOW"),
    InvalidToken("INVALID_TOKEN"),
    InvalidInput("INVALID_INPUT");

    override fun toString() = value
}

/**
 * ProtocolError pairs a canonical Code with its detail. Its message is
 * "<CODE>: <detail>" so logs are greppable by code across SDKs. Codes are for
 * the in-process caller only; servers MUST NOT echo them to the network
 * (SPEC 5.4.4). It is an IOException so streaming bodies can raise it directly.
 */
class ProtocolError(val code: Code, detail: String, cause: Throwable? = null) :
    IOException("$code: $detail", cause)

/** codeOf returns the canonical code found anywhere in err's cause chain, or null if none. */
fun codeOf(err: Throwable?): Code? =
    generateSequence(err) { it.cause }.filterIsInstance<ProtocolError>().firstOrNull()?.code
