package sh.tinfoil.ehbp.identity

import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer
import sh.tinfoil.ehbp.openFrames
import sh.tinfoil.ehbp.protocol.EncapsulatedKeyHeader
import sh.tinfoil.ehbp.toHex
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CryptTest {
    private val server = newIdentity()
    private fun recipient(enc: ByteArray) = newHpke().setupBaseR(enc, server.privateKey(), HPKERequestInfo.toByteArray())
    private fun drain(body: RequestBody): ByteArray = Buffer().also { body.writeTo(it) }.readByteArray()

    @Test
    fun streamingEncryptionFramesAt8KiB() {
        val plaintext = ByteArray(20_000) { (it % 251).toByte() }
        val sender = newHpke().setupBaseS(server.publicKey(), HPKERequestInfo.toByteArray())
        val out = ByteArrayOutputStream()
        StreamingEncryptWriter(out, sender).write(plaintext) // one large write is split into 8 KiB frames
        val framed = out.toByteArray()
        // 8192 + 8192 + 3616 plaintext bytes, 16-byte tag and 4-byte prefix each
        assertEquals(20_000 + 3 * 20, framed.size)
        assertEquals(8192 + 16, ByteBuffer.wrap(framed).int)
        assertContentEquals(plaintext, openFrames(recipient(sender.encapsulation), ByteArrayInputStream(framed)))
    }

    @Test
    fun streamingWriterEdgeCases() {
        val sender = newHpke().setupBaseS(server.publicKey(), HPKERequestInfo.toByteArray())
        val out = ByteArrayOutputStream()
        val w = StreamingEncryptWriter(out, sender)
        // As in Go, the frame follows the producer's write size: one-byte writes
        // yield one-byte frames, each still well formed.
        for (b in "abc".toByteArray()) w.write(b.toInt())
        assertEquals(3 * (4 + 1 + 16), out.size())
        assertContentEquals("abc".toByteArray(), openFrames(recipient(sender.encapsulation), ByteArrayInputStream(out.toByteArray())))

        w.write(ByteArray(0))
        assertEquals(3 * (4 + 1 + 16), out.size(), "an empty write emits nothing")
    }

    @Test
    fun encryptRequestWithContextRoundTrip() {
        val req = Request.Builder().url("http://example.test/x")
            .header("X-Keep", "1")
            .post("hello".toByteArray().toRequestBody())
            .build()
        val (encrypted, ctx) = server.encryptRequestWithContext(req)
        assertNotNull(ctx)
        assertEquals("1", encrypted.header("X-Keep"))
        assertEquals(ctx.requestEnc.toHex(), encrypted.header(EncapsulatedKeyHeader))
        assertEquals(-1L, encrypted.body!!.contentLength())
        assertTrue(encrypted.body!!.isOneShot())
        val framed = drain(encrypted.body!!)
        assertContentEquals("hello".toByteArray(), openFrames(recipient(ctx.requestEnc), ByteArrayInputStream(framed)))
        // The token exports the same secret the server derives.
        val token = extractSessionRecoveryToken(ctx)
        assertContentEquals(recipient(ctx.requestEnc).export(ExportLabel.toByteArray(), ExportLength), token.exportedSecret)
    }

    @Test
    fun largeBufferedBodyFramesLikeGo() {
        val plaintext = ByteArray(20_000) { (it * 3).toByte() }
        val req = Request.Builder().url("http://example.test/x").post(plaintext.toRequestBody()).build()
        val (encrypted, ctx) = server.encryptRequestWithContext(req)
        val framed = drain(encrypted.body!!)
        assertEquals(20_000 + 3 * 20, framed.size, "okio emits 8 KiB segments, so frames match the Go reader")
        assertContentEquals(plaintext, openFrames(recipient(ctx!!.requestEnc), ByteArrayInputStream(framed)))
    }

    @Test
    fun bodylessRequestsPassThrough() {
        val get = Request.Builder().url("http://example.test/x").build()
        assertNull(server.encryptRequestWithContext(get).second)
        val noBody = Request.Builder().url("http://example.test/x").post(ByteArray(0).toRequestBody()).build()
        val (same, ctx) = server.encryptRequestWithContext(noBody)
        assertNull(ctx)
        assertTrue(same === noBody)
    }

    @Test
    fun sessionRecoveryTokenDiffersPerRequest() {
        val req = Request.Builder().url("http://example.test/x").post("a".toByteArray().toRequestBody()).build()
        val t1 = extractSessionRecoveryToken(server.encryptRequestWithContext(req).second!!)
        val t2 = extractSessionRecoveryToken(server.encryptRequestWithContext(req).second!!)
        assertFalse(t1.exportedSecret.contentEquals(t2.exportedSecret))
        assertFalse(t1.requestEnc.contentEquals(t2.requestEnc))
    }
}
