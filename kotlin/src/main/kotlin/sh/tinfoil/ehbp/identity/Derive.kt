// Mirrors identity/derive.go.
package sh.tinfoil.ehbp.identity

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.ProtocolError

/** HPKERequestInfo is the info string for HPKE sender/receiver setup. */
const val HPKERequestInfo = "ehbp request"
/** ResponseKeyLabel is the info string for HKDF-Expand to derive the response key. */
const val ResponseKeyLabel = "key"
/** ResponseNonceLabel is the info string for HKDF-Expand to derive the response nonce. */
const val ResponseNonceLabel = "nonce"
/** ExportLabel is the context string for HPKE Export. */
const val ExportLabel = "ehbp response"
/** ExportLength is the length of the exported secret: Nk = 32 for AES-256-GCM. */
const val ExportLength = 32
/** RequestEncLength is the X25519 encapsulated key size. */
const val RequestEncLength = 32
/** ResponseNonceLength is max(Nn, Nk) = 32 for AES-256-GCM. */
const val ResponseNonceLength = 32
const val AES256KeyLength = 32
const val AESGCMNonceLength = 12

/** ResponseKeyMaterial holds the derived key material for response encryption/decryption. */
class ResponseKeyMaterial(val key: ByteArray, val nonceBase: ByteArray) {
    /** NewResponseAEAD creates an AES-256-GCM AEAD instance with automatic nonce management. */
    fun newResponseAEAD(): ResponseAEAD {
        if (key.size != AES256KeyLength) {
            throw ProtocolError(Code.HPKESetupFailed, "failed to create AES cipher: invalid key size ${key.size}")
        }
        return ResponseAEAD(key.copyOf(), nonceBase.copyOf())
    }
}

/**
 * DeriveResponseKeys derives the response encryption key and nonce base following
 * OHTTP (RFC 9458) exactly:
 *
 *     salt = concat(enc, response_nonce)
 *     prk = Extract(salt, secret)
 *     aead_key = Expand(prk, "key", Nk)
 *     aead_nonce = Expand(prk, "nonce", Nn)
 */
fun deriveResponseKeys(exportedSecret: ByteArray, requestEnc: ByteArray, responseNonce: ByteArray): ResponseKeyMaterial {
    if (exportedSecret.size != ExportLength) {
        throw ProtocolError(Code.InvalidInput, "exported secret must be $ExportLength bytes, got ${exportedSecret.size}")
    }
    if (requestEnc.size != RequestEncLength) {
        throw ProtocolError(Code.InvalidInput, "request enc must be $RequestEncLength bytes, got ${requestEnc.size}")
    }
    if (responseNonce.size != ResponseNonceLength) {
        throw ProtocolError(Code.InvalidInput, "response nonce must be $ResponseNonceLength bytes, got ${responseNonce.size}")
    }
    val salt = requestEnc + responseNonce
    fun expand(label: String, length: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(exportedSecret, salt, label.toByteArray()))
        return ByteArray(length).also { hkdf.generateBytes(it, 0, length) }
    }
    return ResponseKeyMaterial(expand(ResponseKeyLabel, AES256KeyLength), expand(ResponseNonceLabel, AESGCMNonceLength))
}

/**
 * ResponseAEAD provides AES-256-GCM with automatic nonce management:
 * nonce = nonce_base XOR sequence_number (big-endian in the last 8 bytes),
 * and the sequence advances after each Seal and each successful Open.
 */
class ResponseAEAD internal constructor(private val key: ByteArray, private val nonceBase: ByteArray) {
    /** Seq is the current sequence number. */
    var seq: ULong = 0u
        internal set

    /** Seal encrypts plaintext under the current sequence and advances it. Throws if the sequence is exhausted. */
    fun seal(plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        check(seq != ULong.MAX_VALUE) { "response chunk sequence overflow" }
        val nonce = computeNonce()
        seq++
        return gcm(true, nonce, plaintext, aad)
    }

    /** Open decrypts ciphertext under the current sequence and advances it only on success. */
    fun open(ciphertext: ByteArray, aad: ByteArray? = null): ByteArray {
        if (seq == ULong.MAX_VALUE) throw ProtocolError(Code.SequenceOverflow, "response chunk sequence overflow")
        val plaintext = openWithSeq(seq, ciphertext, aad)
        seq++
        return plaintext
    }

    /** OpenWithSeq decrypts under a specific sequence number without touching the counter. */
    fun openWithSeq(seq: ULong, ciphertext: ByteArray, aad: ByteArray? = null): ByteArray =
        try {
            gcm(false, nonceForSeq(seq), ciphertext, aad)
        } catch (e: Exception) { // InvalidCipherTextException in practice; anything else from BC is still a failed open
            throw ProtocolError(Code.AEADDecryptFailed, "failed to decrypt chunk", e)
        }

    /** NonceForSeq returns the nonce for the given sequence number without touching the counter. */
    fun nonceForSeq(seq: ULong): ByteArray {
        val nonce = nonceBase.copyOf(AESGCMNonceLength)
        for (i in 0 until 8) {
            val idx = AESGCMNonceLength - 1 - i
            nonce[idx] = (nonce[idx].toInt() xor (seq shr (i * 8)).toInt()).toByte()
        }
        return nonce
    }

    fun nonceSize() = AESGCMNonceLength
    fun overhead() = 16

    private fun computeNonce() = nonceForSeq(seq)

    private fun gcm(forEncryption: Boolean, nonce: ByteArray, input: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        cipher.init(forEncryption, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val out = ByteArray(cipher.getOutputSize(input.size))
        var n = cipher.processBytes(input, 0, input.size, out, 0)
        n += cipher.doFinal(out, n)
        return if (n == out.size) out else out.copyOf(n)
    }
}
