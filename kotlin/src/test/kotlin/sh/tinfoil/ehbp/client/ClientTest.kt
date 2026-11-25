package sh.tinfoil.ehbp.client

import okhttp3.Cache
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.BufferedSink
import okio.ForwardingSink
import okio.blackholeSink
import okio.buffer
import sh.tinfoil.ehbp.EhbpTestServer
import sh.tinfoil.ehbp.config
import sh.tinfoil.ehbp.identity.KeyConfigError
import sh.tinfoil.ehbp.newKeyPair
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.ProtocolError
import sh.tinfoil.ehbp.protocol.ResponseNonceHeader
import sh.tinfoil.ehbp.protocol.codeOf
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The OkHttp-specific surface; protocol decisions are the core's and are pinned by the conformance fixtures. */
class ClientTest {
    private fun echoServer() = EhbpTestServer { _, body -> 200 to body }
    private fun post(url: String, body: String) = Request.Builder().url(url).post(body.toByteArray().toRequestBody()).build()

    /** An OkHttpClient whose only transport is [answer], for tests that need no server. */
    private fun canned(answer: () -> Response.Builder) = OkHttpClient.Builder().addInterceptor { chain -> answer().request(chain.request()).protocol(Protocol.HTTP_1_1).build() }.build()

    @Test
    fun secureRoundTripAndTokenLifecycle() = echoServer().use { srv ->
        val tr = Transport(srv.url, KeySource.Discover)
        assertNull(tr.sessionRecoveryToken())
        srv.contentLength = true
        val resp = tr.roundTrip(post("${srv.url}/echo", "hello"))
        assertEquals(200, resp.code)
        assertNotNull(resp.header(ResponseNonceHeader))
        assertNull(resp.header("Content-Length"), "the encrypted length must not describe the plaintext stream")
        assertNotNull(tr.sessionRecoveryToken(), "token available until the body is consumed")
        assertEquals("hello", resp.body!!.string())
        assertNull(tr.sessionRecoveryToken(), "token consumed at EOF")
    }

    @Test
    fun everyKeySourceBindsTheSameOrigin() = echoServer().use { srv ->
        val pk = discover("${srv.url}/some/path?q=1")
        assertContentEquals(srv.keys.config(), sh.tinfoil.ehbp.Core.marshalConfig(pk))
        for (keys in listOf(KeySource.Config(srv.keys.config()), KeySource.PublicKey(pk))) {
            val tr = Transport(srv.url, keys)
            assertEquals("ok", tr.roundTrip(post("${srv.url}/x", "ok")).body!!.string())
            // A different host string for the same listener is another origin.
            assertEquals(Code.InvalidInput, assertFailsWith<ProtocolError> { tr.roundTrip(post("http://localhost:${srv.url.substringAfterLast(':')}/x", "ok")) }.code)
        }
        for (bad in listOf("http://u:p@localhost/", "ftp://localhost/", "not a url")) {
            assertEquals(Code.InvalidInput, assertFailsWith<ProtocolError> { Transport(bad, KeySource.PublicKey(pk)) }.code, bad)
        }
    }

    @Test
    fun redirectsAreReturnedNotFollowed() = EhbpTestServer { ex, _ ->
        if (ex.requestURI.path == "/elsewhere") 200 to "followed".toByteArray()
        else { ex.responseHeaders.set("Location", "/elsewhere"); 302 to ByteArray(0) }
    }.use { srv ->
        // A bodyless GET and a 302 is exactly what OkHttp would follow on its own.
        val following = OkHttpClient.Builder().followRedirects(true).build()
        val resp = Transport(srv.url, KeySource.Discover, following).roundTrip(Request.Builder().url("${srv.url}/x").build())
        assertEquals(302, resp.code, "a single transaction: the 3xx surfaces to the caller")
    }

    @Test
    fun unknownLengthProducerRunsOnceAndItsFirstFlushReachesTheWire() {
        val flushed = CountDownLatch(1)
        val writes = AtomicInteger()
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            val wire = object : ForwardingSink(blackholeSink()) {
                override fun flush() { flushed.countDown() }
            }
            wire.buffer().use { chain.request().body!!.writeTo(it) }
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                .code(503).message("busy").body("busy".toResponseBody()).build()
        }.build()
        val tr = Transport("https://example.test", KeySource.Config(newKeyPair().config()), http)
        val producer = object : RequestBody() {
            override fun contentType() = null
            override fun writeTo(sink: BufferedSink) {
                writes.incrementAndGet()
                sink.writeByte(1).flush()
                check(flushed.await(5, TimeUnit.SECONDS)) { "first flush was buffered until EOF" }
                sink.writeByte(2)
            }
        }
        val req = Request.Builder().url("https://example.test/").post(producer).build()
        tr.roundTrip(req).use { assertEquals(503, it.code) }
        assertEquals(1, writes.get())
    }

    @Test
    fun failingUnknownLengthProducerNeverCompletesAsAnEmptyOrPartialUpload() {
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            blackholeSink().buffer().use { chain.request().body!!.writeTo(it) }
            error("a failed upload completed")
        }.build()
        val tr = Transport("https://example.test", KeySource.Config(newKeyPair().config()), http)
        for (hasPrefix in listOf(false, true)) {
            val producer = object : RequestBody() {
                override fun contentType() = null
                override fun writeTo(sink: BufferedSink) {
                    if (hasPrefix) sink.writeByte(1).flush()
                    throw IOException("producer failed")
                }
            }
            val req = Request.Builder().url("https://example.test/").post(producer).build()
            assertEquals("producer failed", assertFailsWith<IOException> { tr.roundTrip(req) }.message)
            assertNull(tr.sessionRecoveryToken())
        }
    }

    @Test
    fun tokenClearedWhenTheRequestCannotBeSent() {
        val port = java.net.ServerSocket(0).use { it.localPort } // closed again: nothing listens
        val tr = Transport("http://127.0.0.1:$port", KeySource.Config(newKeyPair().config()))
        assertFailsWith<IOException> { tr.roundTrip(post("http://127.0.0.1:$port/x", "hi")) }
        assertNull(tr.sessionRecoveryToken(), "token consumed by the transport failure")
    }

    @Test
    fun keyConfigMismatchIsThrownAsKeyConfigError() {
        val http = canned {
            Response.Builder().code(422).message("Unprocessable Content").addHeader("Content-Type", "application/problem+json")
                .body("""{"type":"urn:ietf:params:ehbp:error:key-config","title":"stale key"}""".toResponseBody())
        }
        val tr = Transport("https://example.test", KeySource.Config(newKeyPair().config()), http)
        val e = assertFailsWith<KeyConfigError> { tr.roundTrip(post("https://example.test/x", "hi")) }
        assertEquals(Code.KeyConfigMismatch, codeOf(e))
        assertEquals("KEY_CONFIG_MISMATCH: stale key", e.message)
        assertNull(tr.sessionRecoveryToken())
    }

    @Test
    fun neverUsesTheCallersHttpCache() {
        val hits = AtomicInteger()
        EhbpTestServer { ex, _ ->
            hits.incrementAndGet(); ex.responseHeaders.set("Cache-Control", "public, max-age=3600"); 200 to "cacheable".toByteArray()
        }.use { srv ->
            val dir = File.createTempFile("ehbp-cache", "").also { it.delete(); it.mkdirs() }
            val cache = Cache(dir, 10L shl 20)
            val tr = Transport(srv.url, KeySource.Discover, OkHttpClient.Builder().cache(cache).build())
            repeat(2) { tr.roundTrip(Request.Builder().url("${srv.url}/keys-like").build()).body!!.bytes() }
            assertEquals(2, hits.get(), "every request reaches the server")
            assertEquals(0, cache.requestCount(), "the derived client has no cache at all")
            assertEquals(0, cache.writeSuccessCount())
            dir.deleteRecursively()
        }
    }

    @Test
    fun discoveryUsesTheGivenClientAndRequestsExactlyTheKeysPath() {
        val cfg = newKeyPair().config()
        val seen = AtomicReference<String>()
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            seen.set(chain.request().url.toString())
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .addHeader("Content-Type", "application/ohttp-keys").body(cfg.toResponseBody()).build()
        }.build()
        assertContentEquals(cfg, sh.tinfoil.ehbp.Core.marshalConfig(discover("https://example.test/some/path?q=1", http)))
        assertEquals("https://example.test/.well-known/hpke-keys", seen.get())
    }

    @Test
    fun latestRequestOwnsRecoveryToken() = echoServer().use { srv ->
        val tr = Transport(srv.url, KeySource.Discover)
        val first = tr.roundTrip(post("${srv.url}/x", "one"))
        val firstToken = tr.sessionRecoveryToken()
        val second = tr.roundTrip(post("${srv.url}/x", "two"))
        val secondToken = tr.sessionRecoveryToken()
        assertNotNull(secondToken)
        assertTrue(!firstToken!!.requestEnc.contentEquals(secondToken.requestEnc))
        first.body!!.bytes() // completing the older exchange must not clear the newer token
        assertContentEquals(secondToken.requestEnc, tr.sessionRecoveryToken()!!.requestEnc)
        second.body!!.bytes()
        assertNull(tr.sessionRecoveryToken())
    }

    @Test
    fun selfCheckPasses() = assertEquals(emptyList(), selfCheck())
}
