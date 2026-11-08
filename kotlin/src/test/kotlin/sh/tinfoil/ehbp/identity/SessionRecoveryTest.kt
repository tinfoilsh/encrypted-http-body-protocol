package sh.tinfoil.ehbp.identity

import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okio.BufferedSource
import okio.buffer
import okio.source
import sh.tinfoil.ehbp.frame
import sh.tinfoil.ehbp.hex
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.ProtocolError
import sh.tinfoil.ehbp.protocol.ResponseNonceHeader
import sh.tinfoil.ehbp.protocol.codeOf
import sh.tinfoil.ehbp.sealFrames
import sh.tinfoil.ehbp.toHex
import sh.tinfoil.ehbp.vector
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.SequenceInputStream
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

fun streamBody(stream: InputStream): ResponseBody = object : ResponseBody() {
    private val src = stream.source().buffer()
    override fun contentType() = null
    override fun contentLength() = -1L
    override fun source(): BufferedSource = src
}

fun response(body: InputStream, vararg headers: Pair<String, String>, status: Int = 200): Response =
    Response.Builder()
        .request(Request.Builder().url("http://test.invalid/").build())
        .protocol(Protocol.HTTP_1_1).code(status).message("")
        .apply { headers.forEach { (k, v) -> addHeader(k, v) } }
        .body(streamBody(body))
        .build()

class SessionRecoveryTest {
    private val v = vector("response-decryption.json")
    private val token = SessionRecoveryToken(hex(v["exportedSecret"]!!), hex(v["requestEnc"]!!))
    private val nonceHex = v["responseNonce"]!!

    @Test
    fun tokenJsonRoundTrip() {
        val t = vector("session-recovery-token.json")
        val tok = SessionRecoveryToken(hex(t["exportedSecret"]!!), hex(t["requestEnc"]!!))
        assertEquals("""{"exportedSecret":"${t["exportedSecret"]}","requestEnc":"${t["requestEnc"]}"}""", tok.toJson())
        val back = SessionRecoveryToken.fromJson(tok.toJson())
        assertContentEquals(tok.exportedSecret, back.exportedSecret)
        assertContentEquals(tok.requestEnc, back.requestEnc)
    }

    @Test
    fun tokenUnmarshalRejectsMalformedFields() {
        val good = "ab".repeat(32)
        val bad = listOf("null", "[]", "{}", "7", "not json",
            """{"exportedSecret": "$good"}""",
            """{"exportedSecret": 7, "requestEnc": "$good"}""",
            """{"exportedSecret": "${"zz".repeat(32)}", "requestEnc": "$good"}""",
            """{"exportedSecret": "${good}0", "requestEnc": "$good"}""",
            """{"exportedSecret": "${"ab".repeat(16)}", "requestEnc": "$good"}""",
            """{"exportedSecret": "$good", "requestEnc": "${"ab".repeat(31)}"}""",
            """{"exportedSecret": null, "requestEnc": "$good"}""")
        for (j in bad) assertEquals(Code.InvalidToken, assertFailsWith<ProtocolError> { SessionRecoveryToken.fromJson(j) }.code, j)
    }

    @Test
    fun responseDecryptionInteropVector() {
        val resp = decryptResponseWithToken(response(ByteArrayInputStream(hex(v["encryptedResponse"]!!)), ResponseNonceHeader to nonceHex), token)
        assertEquals(v["plaintext"], resp.body!!.bytes().toHex())
    }

    @Test
    fun decryptResponseWithTokenClearsStaleContentLength() {
        val resp = decryptResponseWithToken(response(ByteArrayInputStream(ByteArray(0)), ResponseNonceHeader to nonceHex, "Content-Length" to "42"), token)
        assertNull(resp.header("Content-Length"))
        assertEquals(-1L, resp.body!!.contentLength())
        assertEquals(-1, resp.body!!.byteStream().read())
    }

    @Test
    fun decryptResponseWithTokenErrors() {
        val body = { ByteArrayInputStream(ByteArray(0)) }
        assertEquals(Code.MissingResponseNonce, assertFailsWith<ProtocolError> { decryptResponseWithToken(response(body()), token) }.code)
        assertEquals(Code.InvalidResponseNonce, assertFailsWith<ProtocolError> { decryptResponseWithToken(response(body(), ResponseNonceHeader to ""), token) }.code)
        assertEquals(Code.InvalidResponseNonce, assertFailsWith<ProtocolError> { decryptResponseWithToken(response(body(), ResponseNonceHeader to "zz"), token) }.code)
        assertEquals(Code.InvalidResponseNonce, assertFailsWith<ProtocolError> { decryptResponseWithToken(response(body(), ResponseNonceHeader to "ab".repeat(16)), token) }.code)
        assertEquals(Code.DuplicateResponseNonce, assertFailsWith<ProtocolError> {
            decryptResponseWithToken(response(body(), ResponseNonceHeader to nonceHex, ResponseNonceHeader to nonceHex), token)
        }.code)
    }

    private fun aead() = deriveResponseKeys(token.exportedSecret, token.requestEnc, hex(nonceHex)).newResponseAEAD()
    private fun decrypt(framed: ByteArray) = decryptResponseWithToken(response(ByteArrayInputStream(framed), ResponseNonceHeader to nonceHex), token).body!!.byteStream()

    @Test
    fun multiChunkWithEmptyFramesAndSmallReads() {
        val framed = ByteArray(4) + sealFrames(aead(), "hello ".toByteArray(), "world".toByteArray()) + ByteArray(8)
        val body = decrypt(framed)
        val out = StringBuilder()
        val one = ByteArray(1)
        while (body.read(one) > 0) out.append(one[0].toInt().toChar())
        assertEquals("hello world", out.toString())
    }

    @Test
    fun rejectsTruncatedFraming() {
        val framed = sealFrames(aead(), "hello".toByteArray())
        for (cut in listOf(1, 2, 3, framed.size - 1)) {
            val body = decrypt(framed.copyOf(cut))
            val e = assertFailsWith<ProtocolError> { body.readBytes() }
            assertEquals(Code.FramingTruncated, e.code, "cut=$cut")
            assertEquals(Code.FramingTruncated, assertFailsWith<ProtocolError> { body.read() }.code, "terminal")
        }
    }

    @Test
    fun rejectsOversizedChunkBeforeReading() {
        val body = decrypt(ByteBuffer.allocate(4).putInt((64 shl 20) + 1).array())
        assertEquals(Code.ChunkTooLarge, assertFailsWith<ProtocolError> { body.read() }.code)
        val max = decrypt(ByteBuffer.allocate(4).putInt(64 shl 20).array() + ByteArray(16))
        assertEquals(Code.FramingTruncated, assertFailsWith<ProtocolError> { max.read() }.code)
    }

    @Test
    fun deliversBeforeSourceEofAndFailsClosedAfter() {
        val a = aead()
        val first = frame(a.seal("prefix".toByteArray()))
        val tampered = frame(a.seal("rest".toByteArray())).also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val blocking = object : InputStream() {
            override fun read(): Int = throw IOException("source reset")
        }
        val body = decryptResponseWithToken(response(SequenceInputStream(ByteArrayInputStream(first), blocking), ResponseNonceHeader to nonceHex), token).body!!.byteStream()
        val buf = ByteArray(64)
        assertEquals("prefix", String(buf, 0, body.read(buf)))
        assertEquals(Code.FramingTruncated, assertFailsWith<ProtocolError> { body.read(buf) }.code)

        val body2 = decrypt(first + tampered)
        assertEquals("prefix", String(buf, 0, body2.read(buf)))
        assertEquals(Code.AEADDecryptFailed, codeOf(assertFailsWith<IOException> { body2.read(buf) }))
        assertEquals(Code.AEADDecryptFailed, codeOf(assertFailsWith<IOException> { body2.read(buf) }))
    }

    @Test
    fun replayAndReorderFail() {
        val a = aead()
        val f0 = frame(a.seal("zero".toByteArray()))
        val f1 = frame(a.seal("one".toByteArray()))
        assertEquals(Code.AEADDecryptFailed, assertFailsWith<ProtocolError> { decrypt(f0 + f0).readBytes() }.code)
        assertEquals(Code.AEADDecryptFailed, assertFailsWith<ProtocolError> { decrypt(f1 + f0).readBytes() }.code)
    }

    @Test
    fun sequenceOverflowSurfaces() {
        val stream = DerivedStreamingDecryptReader(ByteArrayInputStream(frame(ByteArray(16))), aead().also { it.seq = ULong.MAX_VALUE })
        assertEquals(Code.SequenceOverflow, assertFailsWith<ProtocolError> { stream.read() }.code)
    }
}
