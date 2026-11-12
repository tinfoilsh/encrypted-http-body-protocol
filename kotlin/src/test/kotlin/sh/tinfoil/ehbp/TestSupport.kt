package sh.tinfoil.ehbp

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.crypto.hpke.HPKEContext
import sh.tinfoil.ehbp.identity.ExportLabel
import sh.tinfoil.ehbp.identity.ExportLength
import sh.tinfoil.ehbp.identity.HPKERequestInfo
import sh.tinfoil.ehbp.identity.Identity
import sh.tinfoil.ehbp.identity.ResponseAEAD
import sh.tinfoil.ehbp.identity.deriveResponseKeys
import sh.tinfoil.ehbp.identity.newHpke
import sh.tinfoil.ehbp.protocol.EncapsulatedKeyHeader
import sh.tinfoil.ehbp.protocol.ResponseNonceHeader
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.HexFormat

fun hex(s: String): ByteArray = HexFormat.of().parseHex(s)
fun ByteArray.toHex(): String = HexFormat.of().formatHex(this)

/** Shared golden vectors live one directory up, as for the Go tests. */
fun vector(name: String): Map<String, String> =
    Json.parseToJsonElement(File("../test-vectors/$name").readText()).jsonObject
        .mapValues { it.value.jsonPrimitive.content }

fun frame(ct: ByteArray): ByteArray = ByteBuffer.allocate(4 + ct.size).putInt(ct.size).put(ct).array()

/** Encrypts a response body as the Go DerivedResponseWriter would: one frame per write. */
fun sealFrames(aead: ResponseAEAD, vararg chunks: ByteArray): ByteArray =
    chunks.fold(ByteArray(0)) { acc, c -> acc + frame(aead.seal(c)) }

/** Opens an EHBP framed body with an HPKE context, as the Go server reader does. */
fun openFrames(ctx: HPKEContext, framed: InputStream): ByteArray {
    val out = ByteArrayOutputStream()
    while (true) {
        val len = framed.readNBytes(4)
        if (len.isEmpty()) return out.toByteArray()
        check(len.size == 4) { "truncated prefix" }
        val n = ByteBuffer.wrap(len).int
        if (n == 0) continue
        val ct = framed.readNBytes(n)
        check(ct.size == n) { "truncated frame" }
        out.write(ctx.open(ByteArray(0), ct))
    }
}

/**
 * A minimal EHBP server built on the JDK's HttpServer: the test-side twin of the
 * Go middleware. [handler] receives the request plaintext and returns status and
 * body; [tweak] can rewrite the encrypted reply before it is sent.
 */
class EhbpTestServer(
    val identity: Identity,
    private val handler: (HttpExchange, ByteArray) -> Pair<Int, ByteArray>,
) : AutoCloseable {
    private val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    val url get() = "http://127.0.0.1:${server.address.port}"

    /** Replace the encrypted frames and nonce header just before sending. */
    var tweak: (HttpExchange, ByteArray) -> ByteArray = { _, framed -> framed }
    var suppressNonce = false
    /** Send the encrypted body with a Content-Length instead of chunked, as a proxy might. */
    var contentLength = false

    init {
        server.createContext("/.well-known/hpke-keys") { ex ->
            ex.responseHeaders.set("Content-Type", "application/ohttp-keys")
            val cfg = identity.marshalConfig()
            ex.sendResponseHeaders(200, cfg.size.toLong())
            ex.responseBody.use { it.write(cfg) }
        }
        server.createContext("/") { ex -> serve(ex) }
        server.start()
    }

    private fun serve(ex: HttpExchange) {
        val encHex = ex.requestHeaders.getFirst(EncapsulatedKeyHeader)
        if (encHex == null) {
            val (status, body) = handler(ex, ex.requestBody.readAllBytes())
            ex.sendResponseHeaders(status, body.size.toLong().takeIf { it > 0 } ?: -1)
            ex.responseBody.use { it.write(body) }
            return
        }
        val enc = hex(encHex)
        val recipient = newHpke().setupBaseR(enc, identity.privateKey(), HPKERequestInfo.toByteArray())
        val plaintext = openFrames(recipient, ex.requestBody)
        val (status, body) = handler(ex, plaintext)

        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val aead = deriveResponseKeys(recipient.export(ExportLabel.toByteArray(), ExportLength), enc, nonce).newResponseAEAD()
        val framed = tweak(ex, sealFrames(aead, *body.toList().chunked(8192).map { it.toByteArray() }.toTypedArray()))
        if (!suppressNonce && !ex.responseHeaders.containsKey(ResponseNonceHeader)) ex.responseHeaders.set(ResponseNonceHeader, nonce.toHex())
        // HttpServer: 0 = chunked, -1 = no body, otherwise a Content-Length.
        ex.sendResponseHeaders(status, if (!contentLength) 0 else if (framed.isEmpty()) -1 else framed.size.toLong())
        ex.responseBody.use { if (framed.isNotEmpty()) it.write(framed) }
    }

    override fun close() = server.stop(0)
}
