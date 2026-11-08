// Mirrors identity/crypt.go (client side only: request encryption and
// response decryption; the server-side request decryptor and response writer
// are not ported).
package sh.tinfoil.ehbp.identity

import okhttp3.MediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okio.BufferedSink
import okio.BufferedSource
import okio.buffer
import okio.sink
import okio.source
import org.bouncycastle.crypto.hpke.HPKEContext
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.EncapsulatedKeyHeader
import sh.tinfoil.ehbp.protocol.ProtocolError
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer

/**
 * KeyConfigError represents a client/server key configuration mismatch: stale
 * or incompatible HPKE key material that requires a rekey (SPEC 5.4.3).
 */
class KeyConfigError(cause: Throwable) : IOException(cause.message, cause)

/** IsKeyConfigError determines if an error indicates key configuration mismatch. */
fun isKeyConfigError(err: Throwable?): Boolean = generateSequence(err) { it.cause }.any { it is KeyConfigError }

/**
 * maxChunkBytes bounds a single framed chunk in either direction so a malicious
 * or tampered length prefix cannot force an unbounded allocation before the
 * frame is authenticated.
 */
internal const val maxChunkBytes = 64L shl 20

/** Plaintext bytes sealed per frame, as the Go StreamingEncryptReader. */
private const val encryptChunkBytes = 8192

/**
 * StreamingEncryptWriter is the OutputStream counterpart of Go's
 * StreamingEncryptReader: OkHttp pushes request bodies into a sink, so the
 * plaintext is sealed and framed as it is written, in chunks of at most 8 KiB.
 */
class StreamingEncryptWriter(private val out: OutputStream, private val sender: HPKEContext) : OutputStream() {
    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(p: ByteArray, off: Int, len: Int) {
        var pos = off
        val end = off + len
        while (pos < end) {
            val n = minOf(encryptChunkBytes, end - pos)
            val encrypted = try {
                sender.seal(ByteArray(0), p.copyOfRange(pos, pos + n)) // AAD is empty (SPEC 4.3); BC rejects null
            } catch (e: Exception) {
                throw ProtocolError(Code.HPKESetupFailed, "failed to encrypt chunk", e)
            }
            // Chunk with length prefix
            out.write(ByteBuffer.allocate(4 + encrypted.size).putInt(encrypted.size).put(encrypted).array())
            pos += n
        }
    }

    override fun flush() = out.flush()
    override fun close() = out.close()
}

/** RequestContext holds the HPKE context needed for response decryption. */
class RequestContext(val sender: HPKEContextWithEncapsulation, val requestEnc: ByteArray) {
    /** DecryptResponse decrypts a response using keys derived from this request's HPKE context. */
    fun decryptResponse(resp: Response): Response = decryptResponseWithToken(resp, extractSessionRecoveryToken(this))
}

/**
 * EncryptRequestWithContext encrypts the request body TO this identity's public
 * key and returns the new request plus the HPKE context needed for response
 * decryption. Request is immutable, so the encrypted copy is returned rather
 * than mutated in place.
 *
 * For bodyless requests (no body, or a body of known zero length, as Go's
 * http.NoBody) the original request and a null context are returned: the
 * request passes through unencrypted and so does the response (SPEC 7.4).
 */
fun Identity.encryptRequestWithContext(req: Request): Pair<Request, RequestContext?> {
    val body = req.body
    if (body == null || body.contentLength() == 0L) return req to null

    val sender = try {
        newHpke().setupBaseS(publicKey(), HPKERequestInfo.toByteArray())
    } catch (e: Exception) {
        throw ProtocolError(Code.HPKESetupFailed, "failed to setup encryption", e)
    }
    val encapKey = sender.encapsulation

    val encrypted = object : RequestBody() {
        override fun contentType(): MediaType? = body.contentType()
        // Unknown length: OkHttp frames it as chunked on HTTP/1.1 and drops any
        // caller-set Content-Length / Transfer-Encoding (SPEC 4.1).
        override fun contentLength() = -1L
        override fun isOneShot() = true // the HPKE sequence cannot be replayed
        override fun writeTo(sink: BufferedSink) {
            val plain = StreamingEncryptWriter(sink.outputStream(), sender).sink().buffer()
            body.writeTo(plain)
            plain.flush()
        }
    }
    val newReq = req.newBuilder()
        .header(EncapsulatedKeyHeader, hexEncode(encapKey))
        .method(req.method, encrypted)
        .build()
    return newReq to RequestContext(sender, encapKey)
}

/**
 * DerivedStreamingDecryptReader decrypts response chunks using derived keys. It
 * emits each plaintext chunk as soon as the complete encrypted frame has been
 * authenticated and rejects truncated framing at end-of-stream. A protocol
 * failure is terminal: every later read rethrows it.
 */
class DerivedStreamingDecryptReader(private val reader: InputStream, private val aead: ResponseAEAD) : InputStream() {
    private var buffer = ByteArray(0)
    private var bufPos = 0
    private var eof = false
    private var terminalErr: IOException? = null

    override fun read(): Int {
        val b = ByteArray(1)
        return if (read(b, 0, 1) < 0) -1 else b[0].toInt() and 0xff
    }

    override fun read(p: ByteArray, off: Int, len: Int): Int {
        terminalErr?.let { throw it }
        if (len == 0) return 0
        if (eof) return -1
        if (bufPos < buffer.size) return drain(p, off, len)

        while (true) {
            val chunkLenBytes = readFull(4, "failed to read chunk length")
            if (chunkLenBytes.isEmpty()) {
                eof = true
                return -1
            }
            if (chunkLenBytes.size < 4) {
                throw fail(ProtocolError(Code.FramingTruncated, "failed to read chunk length: unexpected EOF"))
            }
            val chunkLen = ByteBuffer.wrap(chunkLenBytes).int.toLong() and 0xffffffffL
            if (chunkLen == 0L) continue // SPEC 4.3: empty frames carry nothing
            if (chunkLen > maxChunkBytes) {
                throw fail(ProtocolError(Code.ChunkTooLarge, "encrypted response chunk exceeds maximum allowed size"))
            }
            val encryptedChunk = readFull(chunkLen.toInt(), "failed to read encrypted chunk")
            if (encryptedChunk.size < chunkLen) {
                throw fail(ProtocolError(Code.FramingTruncated, "failed to read encrypted chunk: unexpected EOF"))
            }
            val decryptedChunk = try {
                aead.open(encryptedChunk, null)
            } catch (e: ProtocolError) {
                throw fail(e)
            }
            if (decryptedChunk.isEmpty()) continue // an InputStream read must not return 0
            buffer = decryptedChunk
            bufPos = 0
            return drain(p, off, len)
        }
    }

    /** Reads up to n bytes, fewer only at EOF; a transport error is FRAMING_TRUNCATED as in the Go reader. */
    private fun readFull(n: Int, what: String): ByteArray =
        try {
            reader.readFully(n)
        } catch (e: IOException) {
            throw fail(ProtocolError(Code.FramingTruncated, "$what: ${e.message}", e))
        }

    private fun drain(p: ByteArray, off: Int, len: Int): Int {
        val n = minOf(len, buffer.size - bufPos)
        System.arraycopy(buffer, bufPos, p, off, n)
        bufPos += n
        return n
    }

    private fun fail(err: IOException): IOException {
        terminalErr = err
        return err
    }

    override fun close() = reader.close()
}

/** Wraps a plain stream as this body's replacement, keeping its media type; length becomes unknown. */
internal fun ResponseBody.withStream(stream: InputStream): ResponseBody {
    val orig = this
    return object : ResponseBody() {
        private val src by lazy { stream.source().buffer() }
        override fun contentType(): MediaType? = orig.contentType()
        override fun contentLength() = -1L
        override fun source(): BufferedSource = src
        override fun close() {
            stream.close()
            orig.close()
        }
    }
}
