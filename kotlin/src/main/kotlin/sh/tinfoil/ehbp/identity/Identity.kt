// Mirrors identity/identity.go (client subset: no file persistence, no
// Export/Import of private keys, no HTTP config handler).
package sh.tinfoil.ehbp.identity

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.ProtocolError
import java.io.InputStream
import java.nio.ByteBuffer

// RFC 9180 identifiers of the single suite SPEC 3.2 pins.
const val KemId = 0x0020 // DHKEM(X25519, HKDF-SHA256)
const val KdfId = 0x0001 // HKDF-SHA256
const val AeadId = 0x0002 // AES-256-GCM

// BouncyCastle's HPKE object holds a stateful HMAC, so one instance per operation.
internal fun newHpke() = HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256)

// Hand-rolled hex (java.util.HexFormat needs Android API 34).
internal fun hexEncode(b: ByteArray): String {
    val digits = "0123456789abcdef"
    val sb = StringBuilder(b.size * 2)
    for (x in b) {
        val v = x.toInt() and 0xff
        sb.append(digits[v ushr 4]).append(digits[v and 0xf])
    }
    return sb.toString()
}

/** Decodes hex the way Go's encoding/hex does: ASCII digits of either case, even length, no prefix. Null on any error. */
internal fun hexDecodeOrNull(s: String): ByteArray? {
    if (s.length % 2 != 0) return null
    fun nibble(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }
    val out = ByteArray(s.length / 2)
    for (i in out.indices) {
        val hi = nibble(s[2 * i])
        val lo = nibble(s[2 * i + 1])
        if (hi < 0 || lo < 0) return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}

/** Reads up to n bytes, fewer only at EOF (InputStream.readNBytes needs Android API 33). */
internal fun InputStream.readFully(n: Int): ByteArray {
    val buf = ByteArray(n)
    var off = 0
    while (off < n) {
        val r = read(buf, off, n - off)
        if (r < 0) break
        off += r
    }
    return if (off == n) buf else buf.copyOf(off)
}

class Identity internal constructor(
    private val pk: AsymmetricKeyParameter,
    private val sk: AsymmetricCipherKeyPair?,
) {
    fun kem() = KemId
    fun kdf() = KdfId
    fun aead() = AeadId

    /** PublicKey returns the public key of an identity. */
    fun publicKey(): AsymmetricKeyParameter = pk

    /** PrivateKey returns the key pair of an identity, or null for a public-key-only identity. */
    fun privateKey(): AsymmetricCipherKeyPair? = sk

    /** MarshalPublicKey returns a binary representation of the public key. */
    fun marshalPublicKey(): ByteArray = (pk as X25519PublicKeyParameters).encoded

    /** MarshalPublicKeyHex returns a hex string representation of the public key. */
    fun marshalPublicKeyHex(): String = hexEncode(marshalPublicKey())

    /** MarshalConfig returns a binary representation of the identity compatible with RFC 9458 application/ohttp-keys. */
    fun marshalConfig(): ByteArray =
        ByteBuffer.allocate(1 + 2 + RequestEncLength + 2 + 4)
            .put(0) // Key ID
            .putShort(KemId.toShort())
            .put(marshalPublicKey())
            .putShort(4) // length of the single (kdf, aead) pair
            .putShort(KdfId.toShort())
            .putShort(AeadId.toShort())
            .array()
}

/** NewIdentity generates a new key pair. */
fun newIdentity(): Identity {
    val kp = newHpke().generatePrivateKey()
    return Identity(kp.public, kp)
}

/**
 * FromPublicKeyBytes builds a public-key-only identity from a raw HPKE public
 * key using the pinned suite. The resulting identity can encrypt requests but never decrypt.
 */
fun fromPublicKeyBytes(publicKey: ByteArray): Identity {
    if (publicKey.size != RequestEncLength) {
        throw ProtocolError(Code.InvalidKeyConfig, "invalid public key: expected $RequestEncLength bytes, got ${publicKey.size}")
    }
    return Identity(X25519PublicKeyParameters(publicKey), null)
}

/** FromPublicKeyHex builds a public-key-only identity from a hex-encoded HPKE public key. */
fun fromPublicKeyHex(publicKeyHex: String): Identity =
    fromPublicKeyBytes(hexDecodeOrNull(publicKeyHex) ?: throw ProtocolError(Code.InvalidKeyConfig, "invalid public key hex"))

/**
 * UnmarshalPublicConfig unmarshals a keys config into an identity. Only the first
 * key_config is read; trailing configs are ignored (SPEC 3.2).
 */
fun unmarshalPublicConfig(data: ByteArray): Identity {
    val s = ByteBuffer.wrap(data)
    fun invalid(): Nothing = throw ProtocolError(Code.InvalidKeyConfig, "invalid config")

    if (s.remaining() < 3) invalid()
    s.get() // key id
    val kemID = s.short.toInt() and 0xffff
    // SPEC 3.2 defines a single suite; a config advertising any other KEM,
    // KDF, or AEAD is unsupported, not negotiable.
    if (kemID != KemId) throw ProtocolError(Code.UnsupportedSuite, "unsupported KEM: 0x%04x".format(kemID))

    if (s.remaining() < RequestEncLength) invalid()
    val publicKeyBytes = ByteArray(RequestEncLength).also { s.get(it) }

    if (s.remaining() < 2) invalid()
    val suitesLen = s.short.toInt() and 0xffff
    if (s.remaining() < suitesLen) invalid()
    val end = s.position() + suitesLen
    val suites = ArrayList<Pair<Int, Int>>()
    while (s.position() < end) {
        if (end - s.position() < 4) invalid()
        suites += (s.short.toInt() and 0xffff) to (s.short.toInt() and 0xffff)
    }

    val pk = X25519PublicKeyParameters(publicKeyBytes)

    if (suites.isEmpty()) throw ProtocolError(Code.InvalidKeyConfig, "no cipher suites found in config")
    // SPEC 3.2 defines exactly one suite; a list of several is not a negotiation we support.
    if (suites.size != 1) throw ProtocolError(Code.UnsupportedSuite, "expected exactly one cipher suite, got ${suites.size}")
    if (suites[0] != KdfId to AeadId) {
        throw ProtocolError(Code.UnsupportedSuite, "unsupported cipher suite: KDF=0x%04x, AEAD=0x%04x".format(suites[0].first, suites[0].second))
    }
    return Identity(pk, null)
}
