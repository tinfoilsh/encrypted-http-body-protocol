package sh.tinfoil.ehbp.client

import com.sun.net.httpserver.HttpServer
import okhttp3.OkHttpClient
import okhttp3.Headers
import okhttp3.MediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.BufferedSource
import okio.buffer
import okio.source
import sh.tinfoil.ehbp.EhbpTestServer
import sh.tinfoil.ehbp.identity.KeyConfigError
import sh.tinfoil.ehbp.identity.isKeyConfigError
import sh.tinfoil.ehbp.identity.newIdentity
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.EncapsulatedKeyHeader
import sh.tinfoil.ehbp.protocol.ProtocolError
import sh.tinfoil.ehbp.protocol.ResponseNonceHeader
import sh.tinfoil.ehbp.protocol.codeOf
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ClientTest {
    private fun echoServer() = EhbpTestServer(newIdentity()) { _, body -> 200 to body }
    private fun post(url: String, body: String) = Request.Builder().url(url).post(body.toByteArray().toRequestBody()).build()
    private fun port(srv: EhbpTestServer) = srv.url.substringAfterLast(':')

    @Test
    fun secureRoundTripAndTokenLifecycle() = echoServer().use { srv ->
        val tr = newTransport(srv.url)
        assertNull(tr.getSessionRecoveryToken())
        val resp = tr.roundTrip(post("${srv.url}/echo", "hello"))
        assertEquals(200, resp.code)
        assertNotNull(resp.header(ResponseNonceHeader))
        assertNull(resp.header("Content-Length"))
        assertNotNull(tr.getSessionRecoveryToken(), "token available until the body is consumed")
        assertEquals("hello", resp.body!!.string())
        assertNull(tr.getSessionRecoveryToken(), "token consumed at EOF")
    }

    @Test
    fun largeBodyStreamsInBothDirections() = echoServer().use { srv ->
        val body = ByteArray(300_000) { (it * 7).toByte() }
        val resp = newTransport(srv.url).roundTrip(Request.Builder().url("${srv.url}/echo").post(body.toRequestBody()).build())
        assertContentEquals(body, resp.body!!.bytes())
    }

    @Test
    fun bodylessRequestsPassThrough() = EhbpTestServer(newIdentity()) { ex, _ ->
        assertNull(ex.requestHeaders.getFirst(EncapsulatedKeyHeader)); 200 to "plain".toByteArray()
    }.use { srv ->
        val tr = newTransport(srv.url)
        val resp = tr.roundTrip(Request.Builder().url("${srv.url}/x").build())
        assertNull(resp.header(ResponseNonceHeader))
        assertEquals("plain", resp.body!!.string())
        assertNull(tr.getSessionRecoveryToken())
    }

    @Test
    fun rejectsNonceLessSuccessResponse() = echoServer().use { srv ->
        srv.suppressNonce = true
        srv.tweak = { _, _ -> "substituted".toByteArray() }
        val tr = newTransport(srv.url)
        val e = assertFailsWith<ProtocolError> { tr.roundTrip(post("${srv.url}/x", "hi")) }
        assertEquals(Code.MissingResponseNonce, e.code)
        assertNull(tr.getSessionRecoveryToken())
    }

    @Test
    fun passesThroughNonceLessErrorResponse() = EhbpTestServer(newIdentity()) { _, _ -> 503 to "busy".toByteArray() }.use { srv ->
        srv.suppressNonce = true
        srv.tweak = { _, _ -> "busy".toByteArray() }
        val tr = newTransport(srv.url)
        val resp = tr.roundTrip(post("${srv.url}/x", "hi"))
        assertEquals(503, resp.code)
        assertEquals("busy", resp.body!!.string())
        assertNull(tr.getSessionRecoveryToken(), "pass-through consumes the token")
    }

    @Test
    fun redirectsAreReturnedNotFollowed() = EhbpTestServer(newIdentity()) { ex, _ ->
        if (ex.requestURI.path == "/elsewhere") 200 to "followed".toByteArray()
        else { ex.responseHeaders.set("Location", "/elsewhere"); 302 to ByteArray(0) }
    }.use { srv ->
        // A bodyless GET and a 302 is exactly what OkHttp would follow on its own.
        val following = OkHttpClient.Builder().followRedirects(true).build()
        val resp = newTransport(srv.url, following).roundTrip(Request.Builder().url("${srv.url}/x").build())
        assertEquals(302, resp.code, "a single transaction: the 3xx surfaces to the caller")
    }

    @Test
    fun hostHeaderFollowsTheUrlForEveryRequest() {
        val seen = ArrayList<String>()
        EhbpTestServer(newIdentity()) { ex, body -> seen += ex.requestHeaders.getFirst("Host"); 200 to body }.use { srv ->
            val tr = newTransport(srv.url)
            tr.roundTrip(Request.Builder().url("${srv.url}/x").header("Host", "attacker.invalid").build()).body!!.bytes()
            tr.roundTrip(Request.Builder().url("${srv.url}/x").header("Host", "attacker.invalid").post("b".toByteArray().toRequestBody()).build()).body!!.bytes()
            val expected = srv.url.removePrefix("http://")
            assertEquals(listOf(expected, expected), seen)
        }
    }

    @Test
    fun passThroughNeedsEveryNonceHeaderAbsent() = EhbpTestServer(newIdentity()) { _, _ -> 503 to ByteArray(0) }.use { srv ->
        // First value present, second empty: Go reads the first and fails DUPLICATE; so must we.
        srv.tweak = { ex, framed -> ex.responseHeaders.add(ResponseNonceHeader, "00".repeat(32)); ex.responseHeaders.add(ResponseNonceHeader, "11".repeat(32)); framed }
        assertEquals(Code.DuplicateResponseNonce, assertFailsWith<ProtocolError> { newTransport(srv.url).roundTrip(post("${srv.url}/x", "hi")) }.code)
    }

    @Test
    fun rejectsDuplicateResponseNonce() = echoServer().use { srv ->
        srv.tweak = { ex, framed -> ex.responseHeaders.add(ResponseNonceHeader, "00".repeat(32)); ex.responseHeaders.add(ResponseNonceHeader, "11".repeat(32)); framed }
        val e = assertFailsWith<ProtocolError> { newTransport(srv.url).roundTrip(post("${srv.url}/x", "hi")) }
        assertEquals(Code.DuplicateResponseNonce, e.code)
    }

    @Test
    fun emptyFirstNonceCannotTurnAnErrorIntoPassThrough() {
        val identity = newIdentity()
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                .code(503).message("Service Unavailable")
                .headers(Headers.Builder()
                    .add(ResponseNonceHeader, "")
                    .add(ResponseNonceHeader, "00".repeat(32)).build())
                .body("forged plaintext".toResponseBody()).build()
        }.build()
        val tr = newTransportWithConfig("https://example.test", identity.marshalConfig(), http)
        assertEquals(Code.DuplicateResponseNonce, assertFailsWith<ProtocolError> {
            tr.roundTrip(post("https://example.test/x", "request"))
        }.code)
    }

    @Test
    fun encrypted422IsNotTreatedAsAKeyConfigMismatch() {
        val identity = newIdentity()
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                .code(422).message("Unprocessable Content")
                .addHeader(ResponseNonceHeader, "00".repeat(32))
                .addHeader("Content-Type", "application/problem+json")
                .body("""{"type":"urn:ietf:params:ehbp:error:key-config","title":"retry"}""".toResponseBody())
                .build()
        }.build()
        val tr = newTransportWithConfig("https://example.test", identity.marshalConfig(), http)
        tr.roundTrip(post("https://example.test/x", "request")).use { resp ->
            assertEquals(Code.ChunkTooLarge, assertFailsWith<ProtocolError> { resp.body!!.bytes() }.code)
        }
    }

    @Test
    fun rejectsInvalidResponseNonce() = echoServer().use { srv ->
        srv.tweak = { ex, framed -> ex.responseHeaders.set(ResponseNonceHeader, "abc"); framed }
        assertEquals(Code.InvalidResponseNonce, assertFailsWith<ProtocolError> { newTransport(srv.url).roundTrip(post("${srv.url}/x", "hi")) }.code)
    }

    @Test
    fun keyConfigMismatchIsSurfacedAndOtherProblemsPassThrough() {
        val problem = """{"type":"urn:ietf:params:ehbp:error:key-config","title":"stale key"}"""
        var body = problem
        EhbpTestServer(newIdentity()) { _, _ -> 422 to ByteArray(0) }.use { srv ->
            srv.suppressNonce = true
            srv.tweak = { ex, _ ->
                ex.responseHeaders.set("Content-Type", "application/problem+json; charset=utf-8")
                body.toByteArray()
            }
            val tr = newTransport(srv.url)
            val e = assertFailsWith<KeyConfigError> { tr.roundTrip(post("${srv.url}/x", "hi")) }
            assertTrue(isKeyConfigError(e))
            assertEquals(Code.KeyConfigMismatch, codeOf(e))
            assertEquals("KEY_CONFIG_MISMATCH: stale key", e.message)
            assertNull(tr.getSessionRecoveryToken())

            body = """{"type":"urn:example:other","title":"nope"}"""
            val resp = tr.roundTrip(post("${srv.url}/x", "hi"))
            assertEquals(422, resp.code)
            assertEquals(body, resp.body!!.string(), "body intact after inspection")

            // Oversized problem documents are not parsed (bounded peek) and pass through intact.
            body = """{"type":"urn:ietf:params:ehbp:error:key-config","title":"${"x".repeat(70_000)}"}"""
            val big = tr.roundTrip(post("${srv.url}/x", "hi"))
            assertEquals(422, big.code)
            assertEquals(body.length, big.body!!.bytes().size)
        }
    }

    @Test
    fun requestGuardsNeverReachTheWire() {
        val hits = AtomicInteger()
        EhbpTestServer(newIdentity()) { _, body -> hits.incrementAndGet(); 200 to body }.use { srv ->
            val tr = newTransportWithConfig(srv.url, srv.identity.marshalConfig())
            val reserved = Request.Builder().url("${srv.url}/x").header(ResponseNonceHeader, "0".repeat(64)).post("x".toByteArray().toRequestBody()).build()
            assertEquals(Code.InvalidInput, assertFailsWith<ProtocolError> { tr.roundTrip(reserved) }.code)
            assertEquals(Code.InvalidInput, assertFailsWith<ProtocolError> { tr.roundTrip(post("http://attacker.invalid/x", "x")) }.code)
            assertEquals(Code.InvalidInput, assertFailsWith<ProtocolError> { tr.roundTrip(post("http://127.0.0.1:${port(srv).toInt() + 1}/x", "x")) }.code)
            assertEquals(Code.InvalidInput, assertFailsWith<ProtocolError> { tr.roundTrip(post("http://u:p@127.0.0.1:${port(srv)}/x", "x")) }.code)
            assertEquals(Code.InvalidInput, assertFailsWith<ProtocolError> { newTransport("http://u:p@localhost/") }.code)
            assertEquals(Code.InvalidInput, assertFailsWith<ProtocolError> { newTransport("ftp://localhost/") }.code)
            assertEquals(Code.InvalidInput, assertFailsWith<ProtocolError> { newTransport("not a url") }.code)
            assertEquals(0, hits.get())
            // Scheme and host compare case-insensitively; the default port matches an explicit one.
            tr.roundTrip(post("HTTP://127.0.0.1:${port(srv)}/x", "x")).body!!.bytes()
            assertEquals(1, hits.get())
        }
    }

    @Test
    fun transportWithIdentityEnforcesNoOrigin() = echoServer().use { srv ->
        val tr = newTransportWithIdentity(srv.identity)
        assertEquals("ok", tr.roundTrip(post("${srv.url}/x", "ok")).body!!.string())
    }

    @Test
    fun discoveryRejectsBadContentTypeAndStatus() {
        val cfg = newIdentity().marshalConfig()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        var mode = ""
        val seenQuery = AtomicReference<String?>()
        server.createContext("/.well-known/hpke-keys") { ex ->
            seenQuery.set(ex.requestURI.rawQuery)
            ex.responseHeaders.set("Content-Type", if (mode == "ct") "text/plain" else "application/ohttp-keys")
            ex.sendResponseHeaders(if (mode == "status") 404 else 200, cfg.size.toLong())
            ex.responseBody.use { it.write(cfg) }
        }
        server.start()
        try {
            val base = "http://127.0.0.1:${server.address.port}"
            mode = "ct"
            assertEquals(Code.InvalidKeyConfig, assertFailsWith<ProtocolError> { newTransport(base) }.code)
            mode = "status"
            assertEquals(Code.InvalidKeyConfig, assertFailsWith<ProtocolError> { newTransport(base) }.code)
            mode = ""
            assertContentEquals(cfg, newTransport("$base/some/path?q=1").serverIdentity().marshalConfig())
            assertNull(seenQuery.get())
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun discoveryDoesNotFollowRedirects() {
        val targetHits = AtomicInteger()
        val target = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        target.createContext("/") { ex ->
            targetHits.incrementAndGet()
            val cfg = newIdentity().marshalConfig()
            ex.responseHeaders.set("Content-Type", "application/ohttp-keys")
            ex.sendResponseHeaders(200, cfg.size.toLong())
            ex.responseBody.use { it.write(cfg) }
        }
        target.start()
        val source = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        source.createContext("/.well-known/hpke-keys") { ex ->
            ex.responseHeaders.set("Location", "http://127.0.0.1:${target.address.port}/keys")
            ex.sendResponseHeaders(302, -1)
            ex.close()
        }
        source.start()
        try {
            assertEquals(Code.InvalidKeyConfig, assertFailsWith<ProtocolError> {
                newTransport("http://127.0.0.1:${source.address.port}")
            }.code)
            assertEquals(0, targetHits.get())
        } finally {
            source.stop(0)
            target.stop(0)
        }
    }

    @Test
    fun discoveryReadsOnlyTheFirstKeyConfig() {
        val cfg = newIdentity().marshalConfig()
        val stream = object : InputStream() {
            private var pos = 0
            override fun read(): Int {
                if (pos >= cfg.size + 8) throw IOException("unbounded trailing data was read")
                return if (pos < cfg.size) cfg[pos++].toInt() and 0xff else { pos++; 0 }
            }
        }
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                .code(200).message("OK")
                .addHeader("Content-Type", "application/ohttp-keys")
                .body(object : ResponseBody() {
                    private val src = stream.source().buffer()
                    override fun contentType(): MediaType? = null
                    override fun contentLength() = -1L
                    override fun source(): BufferedSource = src
                }).build()
        }.build()
        val tr = newTransport("https://example.test", http)
        assertContentEquals(cfg, tr.serverIdentity().marshalConfig())
    }

    @Test
    fun publishesRecoveryTokenBeforeSendingAndClearsItOnStreamFailure() {
        val release = CountDownLatch(1)
        val started = CountDownLatch(1)
        EhbpTestServer(newIdentity()) { _, body -> started.countDown(); release.await(5, TimeUnit.SECONDS); 200 to body }.use { srv ->
            srv.tweak = { _, framed -> framed.also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() } }
            val tr = newTransport(srv.url)
            var err: Throwable? = null
            val t = thread {
                err = runCatching { tr.roundTrip(post("${srv.url}/x", "payload")).body!!.bytes() }.exceptionOrNull()
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            assertNotNull(tr.getSessionRecoveryToken(), "token readable while the response is pending")
            release.countDown()
            t.join()
            assertEquals(Code.AEADDecryptFailed, codeOf(assertNotNull(err as? IOException)))
            assertNull(tr.getSessionRecoveryToken(), "token cleared after the stream failed")
        }
    }

    @Test
    fun latestRequestOwnsRecoveryToken() = echoServer().use { srv ->
        val tr = newTransport(srv.url)
        val first = tr.roundTrip(post("${srv.url}/x", "one"))
        val firstToken = tr.getSessionRecoveryToken()
        val second = tr.roundTrip(post("${srv.url}/x", "two"))
        val secondToken = tr.getSessionRecoveryToken()
        assertNotNull(secondToken)
        assertTrue(!firstToken!!.requestEnc.contentEquals(secondToken.requestEnc))
        first.body!!.bytes() // completing the older exchange must not clear the newer token
        assertTrue(tr.getSessionRecoveryToken() === secondToken)
        second.body!!.bytes()
        assertNull(tr.getSessionRecoveryToken())
    }
}
