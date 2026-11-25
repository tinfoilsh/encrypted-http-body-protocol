// ehbp-adapter runs one EHBP conformance fixture through the Kotlin library's
// public API and prints one normalized result (see conformance/schema). It reads
// the fixture JSON on stdin and, for e2e fixtures, uses ORACLE_URL as the server.
//
// The adapter performs no validation the library lacks and never special-cases a
// fixture id: it reports exactly what the library does. mapErr is the single,
// reviewable point where a native error becomes a canonical code.

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import okhttp3.Headers
import okhttp3.MediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okio.BufferedSink
import okio.BufferedSource
import okio.buffer
import okio.source
import sh.tinfoil.ehbp.Core
import sh.tinfoil.ehbp.client.KeySource
import sh.tinfoil.ehbp.client.Transport
import sh.tinfoil.ehbp.client.discover
import sh.tinfoil.ehbp.client.selfCheck
import sh.tinfoil.ehbp.identity.SessionRecoveryToken
import sh.tinfoil.ehbp.protocol.codeOf
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import kotlin.concurrent.thread
import kotlin.system.exitProcess

val HEADER_SUBSET = listOf("ehbp-response-nonce", "content-length", "transfer-encoding", "content-type")

class Result(val fixtureId: String) {
    var outcome = "ok"
    var errorCode: String? = null
    var status: Int? = null
    var headers: Map<String, String>? = null
    var bodyHex: String? = null
    var passthrough = false
    var emitted = false
    var emittedN = 0
    var native: String? = null
    var tokenEarly: Boolean? = null
    var tokenBeforeClose: Boolean? = null
    var tokenAfterClose: Boolean? = null
    var tokenAfter: Boolean? = null
    var peakRss: Long? = null

    fun toJson() = buildJsonObject {
        put("fixture_id", fixtureId)
        put("outcome", outcome)
        put("error_code", errorCode)
        put("status", status)
        headers?.let { h -> put("response_headers", buildJsonObject { h.forEach { (k, v) -> put(k, v) } }) }
        put("body_hex", bodyHex)
        put("passthrough", passthrough)
        put("plaintext_emitted_before_error", emitted)
        put("bytes_emitted_before_error", emittedN)
        put("native_error", native)
        put("runner", "kotlin")
        tokenBeforeClose?.let { put("token_before_close", it) }
        tokenAfterClose?.let { put("token_after_close", it) }
        tokenEarly?.let { put("token_before_response", it) }
        tokenAfter?.let { put("token_after_exchange", it) }
        peakRss?.let { put("peak_rss_bytes", it) }
    }.toString()
}

fun main() {
    val fx = Json.parseToJsonElement(System.`in`.readBytes().decodeToString()).jsonObject
    val r = Result(fx.str("id"))
    try {
        run(fx, r)
    } catch (e: Throwable) {
        r.outcome = "error"
        r.errorCode = mapErr(e)
        r.bodyHex = null
        r.native = e.toString()
    }
    println(r.toJson())
    exitProcess(0) // OkHttp's connection pool keeps non-daemon threads alive
}

/** mapErr reads the canonical code the library attached; uncoded errors are adapter/transport input errors. */
fun mapErr(e: Throwable): String = codeOf(e)?.value ?: "INVALID_INPUT"

fun run(fx: JsonObject, r: Result) {
    when (val op = fx.str("operation")) {
        "derive_keys" -> {
            val (key, nonceBase) = Core.deriveKeys(fx.hexIn("exportedSecret"), fx.hexIn("requestEnc"), fx.hexIn("responseNonce"))
            r.setBody(key + nonceBase)
        }
        "decrypt_response" -> {
            decrypt(fx, r, false)
        }
        "decrypt_response_streaming" -> {
            decrypt(fx, r, true)
        }
        "compute_nonce" -> {
            r.setBody(Core.nonceFor(fx.hexIn("nonceBase"), fx.strIn("seqHex").toULong(16)))
        }
        "token_roundtrip" -> {
            val tok = Core.parseToken(fx.strIn("json"))
            r.setBody(tok.exportedSecret + tok.requestEnc)
        }
        "parse_config" -> {
            r.setBody(Core.parseConfig(fx.hexIn("config")))
        }
        "marshal_config" -> {
            r.setBody(Core.marshalConfig(fx.hexIn("publicKey"))) // keyId is opaque: always 0
        }
        "request" -> {
            exchange(fx, r, "bytes", false, false, false, false)
        }
        "discover" -> {
            discover(discoverTarget(fx)) // throws on a bad key configuration
        }
        "reject_reserved_header" -> {
            hardening(fx, "header")
        }
        "reject_cross_origin" -> {
            hardening(fx, "cross")
        }
        "residue_selfcheck" -> {
            val lines = selfCheck() // the core's shared vectors through this language's bindings
            r.setBody(lines.joinToString("\n").toByteArray())
            if (lines.isNotEmpty()) r.native = lines.joinToString("; ")
        }
        "reject_url_credentials" -> {
            hardening(fx, "credentials")
        }
        "large_body" -> {
            exchange(fx, r, "pattern", false, false, false, true)
        }
        "request_stream" -> {
            exchange(fx, r, "stream", false, false, false, false)
        }
        "close_response_early" -> {
            exchange(fx, r, "bytes", false, true, false, false)
        }
        "token_before_response" -> {
            exchange(fx, r, "bytes", true, false, false, false)
        }
        "token_after_exchange" -> {
            exchange(fx, r, "bytes", false, false, true, false)
        }
        else -> throw IllegalArgumentException("unknown operation \"$op\"")
    }
}

/** A Transport over the oracle, discovering its key through the library. */
fun oracle(): Pair<String, Transport> {
    val base = System.getenv("ORACLE_URL")
    return base to Transport(base, KeySource.Discover)
}

/** The token-only response path over the framed body, fed whole or split at the fixture's byte offsets; reports the plaintext delivered. */
fun decrypt(fx: JsonObject, r: Result, streaming: Boolean) {
    val token = SessionRecoveryToken(fx.hexIn("exportedSecret"), fx.hexIn("requestEnc"))
    val framed = fx.hexIn("encryptedResponse")
    var body: InputStream = ByteArrayInputStream(framed)
    if (streaming) {
        val offsets = (fx["chunking"] as? JsonArray)?.map { it.jsonPrimitive.int } ?: emptyList()
        body = FragmentStream(splitAt(framed, offsets))
    }
    val resp = Core.decryptWithToken(fakeResponse(200, Headers.headersOf("Ehbp-Response-Nonce", hexEncode(fx.hexIn("responseNonce"))), body), token)
    r.setBody(readTracked(resp.body!!.byteStream(), r))
}

/**
 * Sends the fixture request to the oracle and reads the reply. body is how the
 * fixture body is supplied (bytes, stream: unknown length, pattern: the lazy
 * large body); hold reads the token while the oracle holds its reply; early
 * reads one byte and closes; after reads the token once the exchange ended,
 * also on error; rss reports peak RSS.
 */
fun exchange(fx: JsonObject, r: Result, body: String, hold: Boolean, early: Boolean, after: Boolean, rss: Boolean) {
    val (serverURL, tr) = oracle()
    try {
        val request = fx.getValue("request").jsonObject
        val method = request.str("method")
        val bodyHex = request["body_hex"]?.takeUnless { it is JsonNull }?.jsonPrimitive?.contentOrNull
        val reqBody = when {
            body == "pattern" -> patternBody(fx.intIn("size_bytes"), fx.intIn("block_seed").toInt())
            // OkHttp insists on a body object for POST/PUT; a zero-length one is the closest to absent.
            bodyHex == null -> if (method in setOf("POST", "PUT", "PATCH", "PROPPATCH", "REPORT")) ByteArray(0).toRequestBody() else null
            body == "stream" -> object : RequestBody() {
                override fun contentType() = null
                override fun writeTo(sink: BufferedSink) { sink.write(hex(bodyHex)) }
            }
            else -> hex(bodyHex).toRequestBody()
        }
        val builder = Request.Builder().url(serverURL + request.str("path")).method(method, reqBody)
        (request["headers"] as? JsonObject)?.forEach { (k, v) -> builder.header(k, v.jsonPrimitive.content) }
        val req = builder.build()
        var outcome: kotlin.Result<Response>? = null
        val t = thread { outcome = runCatching { tr.roundTrip(req) } }
        if (hold) {
            Thread.sleep(500) // the oracle holds 5 s
            r.tokenEarly = tr.sessionRecoveryToken() != null
        }
        t.join()
        val resp = outcome!!.getOrThrow()
        r.status = resp.code
        r.headers = subsetHeaders(resp.headers)
        if (early) {
            resp.use {
                val byte = it.body!!.byteStream().read()
                check(byte >= 0) { "expected a response prefix" }
                r.setBody(byteArrayOf(byte.toByte()))
                r.tokenBeforeClose = tr.sessionRecoveryToken() != null
            }
            r.tokenAfterClose = tr.sessionRecoveryToken() != null
        } else {
            val plain = readTracked(resp.body!!.byteStream(), r)
            resp.close()
            // No nonce on a non-2xx is a sanctioned unauthenticated pass-through.
            r.passthrough = resp.headers("Ehbp-Response-Nonce").isEmpty() && resp.code !in 200..299
            r.setBody(plain)
        }
        if (rss) r.peakRss = peakRssBytes()
    } finally {
        if (after) r.tokenAfter = tr.sessionRecoveryToken() != null
    }
}

/** Sends a request the library must refuse before it reaches the wire; a reply from the oracle is the divergent result. */
fun hardening(fx: JsonObject, target: String) {
    val (base, tr) = oracle()
    val url = when (target) {
        "cross" -> "http://other.invalid/probe"
        "credentials" -> base.replaceFirst("://", "://user:pass@") + "/probe"
        else -> base + "/probe"
    }
    val req = Request.Builder().url(url).post("x".toByteArray().toRequestBody())
    if (target == "header") {
        val name = fx.strIn("header")
        req.header(name, if (name.equals("Host", true)) "attacker.invalid" else "0000000000000000000000000000000000000000000000000000000000000000")
    }
    tr.roundTrip(req.build()).close()
}

/** discoverTarget maps a fixture target to the oracle listener the harness exposes as ORACLE_<TARGET>_URL (the main oracle for anything else). */
fun discoverTarget(fx: JsonObject): String =
    fx.strIn("target").takeIf { it != "ORACLE_URL" }?.let { System.getenv("ORACLE_${it.uppercase()}_URL") } ?: System.getenv("ORACLE_URL")

// --- helpers ---

/** Delivers the framed body split at the fixture's byte offsets, one segment per read. */
class FragmentStream(private val segments: List<ByteArray>) : InputStream() {
    private var i = 0
    private var pos = 0
    override fun read(): Int = ByteArray(1).let { if (read(it, 0, 1) < 0) -1 else it[0].toInt() and 0xff }
    override fun read(p: ByteArray, off: Int, len: Int): Int {
        while (i < segments.size && pos >= segments[i].size) { i++; pos = 0 }
        if (i >= segments.size) return -1
        val n = minOf(len, segments[i].size - pos)
        System.arraycopy(segments[i], pos, p, off, n)
        pos += n
        return n
    }
}

fun splitAt(b: ByteArray, offsets: List<Int>): List<ByteArray> {
    val segs = ArrayList<ByteArray>()
    var prev = 0
    for (o in offsets) if (o > prev && o < b.size) { segs += b.copyOfRange(prev, o); prev = o }
    segs += b.copyOfRange(prev, b.size)
    return segs
}

/** patternBody streams size bytes of a 1 MiB block with block[i] = (i+seed)&0xff, repeated, lazily. */
fun patternBody(size: Long, seed: Int) = object : RequestBody() {
    override fun contentType(): MediaType? = null
    override fun contentLength() = -1L
    override fun writeTo(sink: BufferedSink) {
        val block = ByteArray(1 shl 20) { ((it + seed) and 0xff).toByte() }
        var remaining = size
        while (remaining > 0) {
            val n = minOf(block.size.toLong(), remaining).toInt()
            sink.write(block, 0, n)
            remaining -= n
        }
    }
}

/**
 * Peak resident set size of this process, as the Go adapter reports, or null
 * when not measurable. Linux: VmHWM from /proc/self/status (true high-water
 * mark). macOS: `ps` RSS at completion; the JVM does not uncommit heap without
 * periodic GC, so for this one-shot process it tracks the peak.
 */
fun peakRssBytes(): Long? = runCatching {
    val status = java.io.File("/proc/self/status")
    if (status.exists()) {
        return status.readLines().firstOrNull { it.startsWith("VmHWM:") }
            ?.split(Regex("\\s+"))?.getOrNull(1)?.toLongOrNull()?.times(1024)
    }
    val pid = ProcessHandle.current().pid()
    val out = ProcessBuilder("ps", "-o", "rss=", "-p", pid.toString()).redirectErrorStream(true).start()
        .inputStream.bufferedReader().readText().trim()
    out.toLongOrNull()?.times(1024)
}.getOrNull()

/** Reads to EOF; on error records the authenticated prefix actually delivered and rethrows. */
fun readTracked(s: InputStream, r: Result): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(4096)
    try {
        while (true) {
            val n = s.read(buf)
            if (n < 0) return out.toByteArray()
            out.write(buf, 0, n)
        }
    } catch (e: IOException) {
        r.emittedN = out.size()
        r.emitted = out.size() > 0
        throw e
    }
}

fun subsetHeaders(h: Headers): Map<String, String> = HEADER_SUBSET.mapNotNull { k -> h[k]?.let { k to it } }.toMap()

fun fakeResponse(status: Int, headers: Headers, body: InputStream): Response =
    Response.Builder()
        .request(Request.Builder().url("http://fixture.invalid/").build())
        .protocol(Protocol.HTTP_1_1).code(status).message("")
        .headers(headers)
        .body(object : ResponseBody() {
            private val src = body.source().buffer()
            override fun contentType(): MediaType? = null
            override fun contentLength() = -1L
            override fun source(): BufferedSource = src
        })
        .build()

fun Result.setBody(b: ByteArray) { bodyHex = hexEncode(b) }
fun hexEncode(b: ByteArray): String = buildString(b.size * 2) { for (x in b) append("%02x".format(x.toInt() and 0xff)) }

// Fixture inputs are repository-controlled; a missing field or bad hex is a
// broken fixture, so fail the adapter loudly (ADAPTER_CRASH in the harness).
fun JsonObject.str(key: String): String = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: fatal("fixture: field \"$key\" missing or not a string")
fun JsonObject.strIn(key: String): String = (this["inputs"] as? JsonObject)?.str(key) ?: fatal("fixture: inputs missing")
fun JsonObject.hexIn(key: String): ByteArray = hex(strIn(key))
fun JsonObject.intIn(key: String): Long = (this["inputs"] as? JsonObject)?.get(key)?.jsonPrimitive?.long ?: fatal("fixture: input \"$key\" missing or not a number")
fun hex(s: String): ByteArray {
    if (s.length % 2 != 0) fatal("bad hex: odd length")
    // toInt(16) alone would accept signed pairs like "-1" or "+f".
    if (!s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) fatal("bad hex: non-hex digit in \"$s\"")
    return ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
}
fun fatal(msg: String): Nothing { System.err.println(msg); exitProcess(2) }
