// The types the API shim returns or throws besides OkHttp's own. The helpers
// over the core (config, token, derivation, nonce) are in sh.tinfoil.ehbp.Core.
package sh.tinfoil.ehbp.identity

import java.io.IOException

/** KeyConfigError wraps the KEY_CONFIG_MISMATCH ProtocolError of a 422 key configuration problem that requires a rekey (SPEC 5.4.3). */
class KeyConfigError(cause: Throwable) : IOException(cause.message, cause)

/**
 * SessionRecoveryToken contains the pre-computed bytes needed to decrypt a
 * response without holding a live HPKE context (SPEC 6).
 */
class SessionRecoveryToken(val exportedSecret: ByteArray, val requestEnc: ByteArray)
