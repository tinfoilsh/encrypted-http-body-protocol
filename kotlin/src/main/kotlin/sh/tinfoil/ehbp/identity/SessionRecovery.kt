// Mirrors identity/session_recovery.go.
package sh.tinfoil.ehbp.identity

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.ProtocolError
import okhttp3.Response
import sh.tinfoil.ehbp.protocol.ResponseNonceHeader

/**
 * SessionRecoveryToken contains the pre-computed bytes needed to decrypt a
 * response without holding a live HPKE context. It can be serialized to JSON
 * and used later or in a different process (SPEC 6).
 */
class SessionRecoveryToken(val exportedSecret: ByteArray, val requestEnc: ByteArray) {
    /** MarshalJSON encodes both fields as lowercase hex strings (SPEC 6.1.1). */
    fun toJson(): String = buildJsonObject {
        put("exportedSecret", hexEncode(exportedSecret))
        put("requestEnc", hexEncode(requestEnc))
    }.toString()

    companion object {
        /** UnmarshalJSON decodes both fields from hex strings; every malformation is INVALID_TOKEN. */
        @JvmStatic
        fun fromJson(data: String): SessionRecoveryToken {
            val obj = try {
                Json.parseToJsonElement(data)
            } catch (e: SerializationException) {
                throw ProtocolError(Code.InvalidToken, "invalid token", e)
            } catch (e: StackOverflowError) { // kotlinx recurses on nested arrays
                throw ProtocolError(Code.InvalidToken, "invalid token", e)
            } as? JsonObject ?: throw ProtocolError(Code.InvalidToken, "invalid token: not a JSON object")

            // Missing fields and null decode to empty, as Go's json does; SPEC 6.1.1
            // fixes both fields at 32 bytes, so they are rejected by the length check.
            fun field(name: String): ByteArray {
                val el: JsonElement? = obj[name]
                val hex = when {
                    el == null || el is JsonNull -> ""
                    el is JsonPrimitive && el.isString -> el.content
                    else -> throw ProtocolError(Code.InvalidToken, "invalid token: $name is not a string")
                }
                // Bound the input before decoding so attacker-controlled JSON cannot force a large allocation.
                if (hex.length != 2 * ExportLength) throw ProtocolError(Code.InvalidToken, "$name must be ${2 * ExportLength} hex characters, got ${hex.length}")
                return hexDecodeOrNull(hex) ?: throw ProtocolError(Code.InvalidToken, "invalid $name hex")
            }
            val exportedSecret = field("exportedSecret")
            val requestEnc = field("requestEnc")
            if (exportedSecret.size != ExportLength) {
                throw ProtocolError(Code.InvalidToken, "exportedSecret must be $ExportLength bytes, got ${exportedSecret.size}")
            }
            if (requestEnc.size != RequestEncLength) {
                throw ProtocolError(Code.InvalidToken, "requestEnc must be $RequestEncLength bytes, got ${requestEnc.size}")
            }
            return SessionRecoveryToken(exportedSecret, requestEnc)
        }
    }
}

/**
 * ExtractSessionRecoveryToken exports the HPKE shared secret from a
 * RequestContext and returns a token that can decrypt the corresponding response independently.
 */
fun extractSessionRecoveryToken(ctx: RequestContext): SessionRecoveryToken {
    val exportedSecret = try {
        ctx.sender.export(ExportLabel.toByteArray(), ExportLength)
    } catch (e: Exception) {
        throw ProtocolError(Code.HPKESetupFailed, "failed to export HPKE secret", e)
    }
    return SessionRecoveryToken(exportedSecret, ctx.requestEnc.copyOf())
}

/**
 * DecryptResponseWithToken returns a view of the response whose body is an
 * incremental authenticated plaintext stream derived from the token alone (no
 * live HPKE context). Plaintext frames become readable before the encrypted
 * body reaches EOF. Closing the replacement body closes the original body.
 */
fun decryptResponseWithToken(resp: Response, token: SessionRecoveryToken): Response {
    val nonces = resp.headers(ResponseNonceHeader)
    if (nonces.size > 1) throw ProtocolError(Code.DuplicateResponseNonce, "duplicate $ResponseNonceHeader header")
    val responseNonceHex = nonces.firstOrNull()
        ?: throw ProtocolError(Code.MissingResponseNonce, "missing $ResponseNonceHeader header")
    if (responseNonceHex.isEmpty()) throw ProtocolError(Code.InvalidResponseNonce, "empty $ResponseNonceHeader header")

    val responseNonce = hexDecodeOrNull(responseNonceHex)
        ?: throw ProtocolError(Code.InvalidResponseNonce, "invalid response nonce")
    if (responseNonce.size != ResponseNonceLength) {
        throw ProtocolError(Code.InvalidResponseNonce, "invalid response nonce length: expected $ResponseNonceLength, got ${responseNonce.size}")
    }

    val aead = deriveResponseKeys(token.exportedSecret, token.requestEnc, responseNonce).newResponseAEAD()
    val body = resp.body ?: throw ProtocolError(Code.InvalidInput, "response has no body")
    // Any Content-Length header describes the encrypted body, not the decrypted stream.
    return resp.newBuilder()
        .removeHeader("Content-Length")
        .body(body.withStream(DerivedStreamingDecryptReader(body.byteStream(), aead)))
        .build()
}
