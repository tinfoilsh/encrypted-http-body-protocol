package sh.tinfoil.ehbp.identity

import sh.tinfoil.ehbp.hex
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.ProtocolError
import sh.tinfoil.ehbp.protocol.codeOf
import sh.tinfoil.ehbp.toHex
import sh.tinfoil.ehbp.vector
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DeriveTest {
    @Test
    fun deriveInteropVector() {
        val v = vector("derive.json")
        val km = deriveResponseKeys(hex(v["exportedSecret"]!!), hex(v["requestEnc"]!!), hex(v["responseNonce"]!!))
        assertEquals(v["derivedKey"], km.key.toHex())
        assertEquals(v["derivedNonceBase"], km.nonceBase.toHex())
    }

    @Test
    fun deriveResponseKeysValidation() {
        val ok = ByteArray(32)
        for (bad in listOf(Triple(ByteArray(31), ok, ok), Triple(ok, ByteArray(33), ok), Triple(ok, ok, ByteArray(12)))) {
            val e = assertFailsWith<ProtocolError> { deriveResponseKeys(bad.first, bad.second, bad.third) }
            assertEquals(Code.InvalidInput, e.code)
        }
    }

    @Test
    fun nonceComputation() {
        val base = hex("f8b0ce9466f27aa6243c65f9")
        val aead = ResponseKeyMaterial(ByteArray(32), base).newResponseAEAD()
        assertContentEquals(base, aead.nonceForSeq(0u))
        assertEquals("f8b0ce9466f27aa6243c65f8", aead.nonceForSeq(1u).toHex())
        assertEquals("f8b0ce9466f27aa6243c64f9", aead.nonceForSeq(256u).toHex())
        // Big-endian u64 in the last 8 bytes: the high byte lands at index 4.
        assertEquals("f8b0ce9467f27aa6243c65f9", aead.nonceForSeq(1uL shl 56).toHex())
        assertEquals("f8b0ce94190d8559dbc39af9", aead.nonceForSeq(0x7fffffffffffff00uL).toHex())
    }

    @Test
    fun openAdvancesOnlyAfterAuthentication() {
        val km = ResponseKeyMaterial(ByteArray(32) { 7 }, ByteArray(12) { 9 })
        val sealer = km.newResponseAEAD()
        val opener = km.newResponseAEAD()
        val ct0 = sealer.seal("first".toByteArray())
        val ct1 = sealer.seal("second".toByteArray())

        val bad = ct0.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(Code.AEADDecryptFailed, codeOf(assertFailsWith<ProtocolError> { opener.open(bad) }))
        assertEquals(0uL, opener.seq)
        assertEquals("first", String(opener.open(ct0)))
        assertEquals("second", String(opener.open(ct1)))
        assertEquals(2uL, opener.seq)
    }

    @Test
    fun wrongSequenceNumberFails() {
        val km = ResponseKeyMaterial(ByteArray(32) { 1 }, ByteArray(12) { 2 })
        val sealer = km.newResponseAEAD()
        sealer.seal("skip".toByteArray())
        val ct1 = sealer.seal("payload".toByteArray())
        val opener = km.newResponseAEAD()
        assertEquals(Code.AEADDecryptFailed, codeOf(assertFailsWith<ProtocolError> { opener.open(ct1) }))
        assertEquals("payload", String(opener.openWithSeq(1u, ct1)))
    }

    @Test
    fun sequenceOverflow() {
        val km = ResponseKeyMaterial(ByteArray(32), ByteArray(12))
        val sealer = km.newResponseAEAD().also { it.seq = ULong.MAX_VALUE }
        assertFailsWith<IllegalStateException> { sealer.seal(ByteArray(1)) }
        val opener = km.newResponseAEAD().also { it.seq = ULong.MAX_VALUE }
        assertEquals(Code.SequenceOverflow, assertFailsWith<ProtocolError> { opener.open(ByteArray(16)) }.code)
    }

    @Test
    fun differentKeysCannotDecrypt() {
        val ct = ResponseKeyMaterial(ByteArray(32) { 1 }, ByteArray(12)).newResponseAEAD().seal("x".toByteArray())
        val other = ResponseKeyMaterial(ByteArray(32) { 2 }, ByteArray(12)).newResponseAEAD()
        assertEquals(Code.AEADDecryptFailed, assertFailsWith<ProtocolError> { other.open(ct) }.code)
        // A frame shorter than the tag is an authentication failure, not truncation.
        assertEquals(Code.AEADDecryptFailed, assertFailsWith<ProtocolError> { other.open(ByteArray(5)) }.code)
    }
}
