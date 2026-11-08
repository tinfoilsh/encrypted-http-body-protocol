package sh.tinfoil.ehbp.identity

import sh.tinfoil.ehbp.hex
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.ProtocolError
import sh.tinfoil.ehbp.toHex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class IdentityTest {
    private val pk07 = "07".repeat(32)
    private val validConfig = "000020${pk07}000400010002"

    @Test
    fun marshalConfigMatchesReferenceLayout() {
        assertEquals(validConfig, fromPublicKeyBytes(hex(pk07)).marshalConfig().toHex())
    }

    @Test
    fun unmarshalPublicConfigTakesFirstConfig() {
        assertEquals(pk07, unmarshalPublicConfig(hex(validConfig)).marshalPublicKeyHex())
        val two = validConfig + "000020${"08".repeat(32)}000400010002"
        assertEquals(pk07, unmarshalPublicConfig(hex(two)).marshalPublicKeyHex())
    }

    @Test
    fun unmarshalPublicConfigErrorCases() {
        val invalid = listOf("", "0000", "000020" + "07".repeat(16), "000020$pk07", "000020${pk07}00", "000020${pk07}0000",
            "000020${pk07}000800010002", "000020${pk07}0003000100")
        for (c in invalid) assertEquals(Code.InvalidKeyConfig, assertFailsWith<ProtocolError> { unmarshalPublicConfig(hex(c)) }.code, c)
    }

    @Test
    fun unmarshalPublicConfigRejectsUnpinnedSuite() {
        val unsupported = listOf(
            "000010" + "04" + "ab".repeat(64) + "000400010002", // P-256 KEM
            "000020${pk07}000400010003", // ChaCha20-Poly1305
            "000020${pk07}000400020002", // HKDF-SHA384
            "000020${pk07}00080001000200010002", // two suites
        )
        for (c in unsupported) assertEquals(Code.UnsupportedSuite, assertFailsWith<ProtocolError> { unmarshalPublicConfig(hex(c)) }.code, c)
    }

    @Test
    fun newIdentityRoundTripsThroughConfig() {
        val id = newIdentity()
        assertNotNull(id.privateKey())
        val parsed = unmarshalPublicConfig(id.marshalConfig())
        assertContentEquals(id.marshalPublicKey(), parsed.marshalPublicKey())
        assertNull(parsed.privateKey())
        assertEquals(KemId, parsed.kem()); assertEquals(KdfId, parsed.kdf()); assertEquals(AeadId, parsed.aead())
    }

    @Test
    fun fromPublicKeyErrorCases() {
        assertEquals(Code.InvalidKeyConfig, assertFailsWith<ProtocolError> { fromPublicKeyHex("zz") }.code)
        assertEquals(Code.InvalidKeyConfig, assertFailsWith<ProtocolError> { fromPublicKeyBytes(ByteArray(31)) }.code)
        assertEquals(pk07, fromPublicKeyHex(pk07.uppercase()).marshalPublicKeyHex())
    }
}
