// ehbp-adapter runs one EHBP conformance fixture through the Kotlin library's
// public API and prints one normalized result (see conformance/schema). It reads
// the fixture JSON on stdin and, for e2e fixtures, uses ORACLE_URL as the server.
//
// The adapter performs no validation the library lacks and never special-cases a
// fixture id: it reports exactly what the library does. mapErr is the single,
// reviewable point where a native error becomes a canonical code. It mirrors
// conformance/adapters/go/main.go minus the server-side operations.

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
import sh.tinfoil.ehbp.client.newTransport
import sh.tinfoil.ehbp.client.newTransportWithConfig
import sh.tinfoil.ehbp.identity.ResponseKeyMaterial
import sh.tinfoil.ehbp.identity.SessionRecoveryToken
import sh.tinfoil.ehbp.identity.decryptResponseWithToken
import sh.tinfoil.ehbp.identity.deriveResponseKeys
import sh.tinfoil.ehbp.identity.fromPublicKeyBytes
import sh.tinfoil.ehbp.identity.newIdentity
import sh.tinfoil.ehbp.identity.unmarshalPublicConfig
import sh.tinfoil.ehbp.protocol.ResponseNonceHeader
import sh.tinfoil.ehbp.protocol.codeOf
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import kotlin.concurrent.thread
import kotlin.system.exitProcess

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

fun run(fx: JsonObject, r: Result) {
    when (val op = fx.str("operation")) {
        "derive_keys" -> {
            val km = deriveResponseKeys(fx.hexIn("exportedSecret"), fx.hexIn("requestEnc"), fx.hexIn("responseNonce"))
            r.setBody(km.key + km.nonceBase)
        }
        "compute_nonce" -> {
            val seq = fx.strIn("seqHex").toULong(16)
            val aead = ResponseKeyMaterial(ByteArray(32), fx.hexIn("nonceBase")).newResponseAEAD()
            r.setBody(aead.nonceForSeq(seq))
        }
        "decrypt_response", "decrypt_response_streaming" -> decryptResponse(fx, r)
        "token_roundtrip" -> {
            val tok = SessionRecoveryToken.fromJson(fx.strIn("json"))
            r.setBody(tok.exportedSecret + tok.requestEnc)
        }
        "parse_config" -> r.setBody(unmarshalPublicConfig(fx.hexIn("config")).marshalPublicKey())
        "marshal_config" -> r.setBody(fromPublicKeyBytes(fx.hexIn("publicKey")).marshalConfig())
        "request" -> doRequest(fx, r)
        // The constructor performs discovery with content-type/status checks.
        "discover" -> newTransport(discoverTarget(fx))
        "reject_reserved_header", "reject_cross_origin", "reject_url_credentials" -> hardening(fx)
        "large_body" -> largeBody(fx, r)
        "token_before_response" -> tokenBeforeResponse(fx, r)
        "token_after_exchange" -> tokenAfterExchange(fx, r)
        else -> throw IllegalArgumentException("unknown operation \"$op\"")
    }
}

/**
 * hardening exercises request-boundary validation without contacting the URL
 * under test. A local recorder answers a plaintext 502 if the request escapes
 * validation; that successful pass-through is the divergent result.
 */
fun hardening(fx: JsonObject) {
    val op = fx.str("operation")
    val server = com.sun.net.httpserver.HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    server.createContext("/") { ex ->
        ex.requestBody.readBytes()
        ex.sendResponseHeaders(502, 5)
        ex.responseBody.use { it.write("probe".toByteArray()) }
    }
    server.start()
    try {
        // The configured origin is the recorder itself, so any request that reaches
        // the wire is observable; the cross-origin and credential probes must not.
        val base = "http://127.0.0.1:${server.address.port}"
        val tr = newTransportWithConfig(base, newIdentity().marshalConfig())
        val target = when (op) {
            "reject_cross_origin" -> "http://attacker.invalid/probe"
            "reject_url_credentials" -> "http://user:pass@127.0.0.1:${server.address.port}/probe"
            else -> "$base/probe"
        }
        val req = Request.Builder().url(target).post("x".toByteArray().toRequestBody())
        if (op == "reject_reserved_header") {
            val name = (fx["inputs"] as? JsonObject)?.get("header")?.jsonPrimitive?.contentOrNull ?: ResponseNonceHeader
            req.header(name, if (name.equals("Host", true)) "attacker.invalid" else "0".repeat(64))
        }
        tr.roundTrip(req.build()).close()
    } finally {
        server.stop(0)
    }
}

fun tokenBeforeResponse(fx: JsonObject, r: Result) {
    val serverURL = System.getenv("ORACLE_URL")
    val tr = newTransport(serverURL)
    val request = fx.getValue("request").jsonObject
    val req = Request.Builder().url(serverURL + request.str("path"))
        .method(request.str("method"), hex(request.str("body_hex")).toRequestBody())
        .build()
    var outcome: kotlin.Result<Response>? = null
    val t = thread { outcome = runCatching { tr.roundTrip(req) } }
    Thread.sleep(500) // oracle holds 5 s: 10x margin
    r.tokenEarly = tr.getSessionRecoveryToken() != null
    t.join()
    val resp = outcome!!.getOrThrow()
    r.status = resp.code
    r.setBody(readTracked(resp.body!!.byteStream(), r))
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

fun largeBody(fx: JsonObject, r: Result) {
    val inputs = fx.getValue("inputs").jsonObject
    val serverURL = System.getenv("ORACLE_URL")
    val tr = newTransport(serverURL)
    val request = fx.getValue("request").jsonObject
    val req = Request.Builder().url(serverURL + request.str("path"))
        .method(request.str("method"), patternBody(inputs.getValue("size_bytes").jsonPrimitive.long, inputs.getValue("block_seed").jsonPrimitive.int))
        .build()
    val resp = tr.roundTrip(req)
    r.status = resp.code
    r.setBody(readTracked(resp.body!!.byteStream(), r))
    r.peakRss = peakRssBytes()
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

/** discoverTarget maps a fixture target to the oracle listener the harness exposes as ORACLE_<TARGET>_URL (the main oracle for anything else). */
fun discoverTarget(fx: JsonObject): String =
    fx.strIn("target").takeIf { it != "ORACLE_URL" }?.let { System.getenv("ORACLE_${it.uppercase()}_URL") } ?: System.getenv("ORACLE_URL")

/**
 * tokenAfterExchange runs the fixture request, lets the exchange end (fully read,
 * or closed after at most one frame when close_early is set, or failed), then
 * reports whether the public token accessor still returns one (SPEC 6.3).
 */
fun tokenAfterExchange(fx: JsonObject, r: Result) {
    val serverURL = System.getenv("ORACLE_URL")
    val tr = newTransport(serverURL)
    val request = fx.getValue("request").jsonObject
    val bodyHex = request["body_hex"]?.takeUnless { it is JsonNull }?.jsonPrimitive?.contentOrNull
    val req = Request.Builder().url(serverURL + request.str("path")).method(request.str("method"), bodyHex?.let { hex(it).toRequestBody() }).build()
    try {
        val resp = tr.roundTrip(req)
        r.status = resp.code
        r.headers = subsetHeaders(resp.headers)
        if ((fx["inputs"] as? JsonObject)?.get("close_early")?.jsonPrimitive?.contentOrNull == "true") {
            resp.body!!.byteStream().read(ByteArray(1)) // at most one frame is released by one read
            resp.close()
            return
        }
        val plain = readTracked(resp.body!!.byteStream(), r)
        resp.close()
        if (resp.headers(ResponseNonceHeader).isEmpty() && resp.code !in 200..299) r.passthrough = true
        r.setBody(plain)
    } finally {
        r.tokenAfter = tr.getSessionRecoveryToken() != null
    }
}

fun decryptResponse(fx: JsonObject, r: Result) {
    val token = SessionRecoveryToken(fx.hexIn("exportedSecret"), fx.hexIn("requestEnc"))
    val framed = fx.hexIn("encryptedResponse")
    var body: InputStream = ByteArrayInputStream(framed)
    if (fx.str("operation") == "decrypt_response_streaming") {
        val offsets = (fx["chunking"] as? JsonArray)?.map { it.jsonPrimitive.int } ?: emptyList()
        body = FragmentStream(splitAt(framed, offsets))
    }
    val resp = decryptResponseWithToken(fakeResponse(200, Headers.headersOf(ResponseNonceHeader, hexEncode(fx.hexIn("responseNonce"))), body), token)
    r.setBody(readTracked(resp.body!!.byteStream(), r))
}

fun doRequest(fx: JsonObject, r: Result) {
    val serverURL = System.getenv("ORACLE_URL")
    val tr = newTransport(serverURL)
    val request = fx.getValue("request").jsonObject
    val method = request.str("method")
    val bodyHex = request["body_hex"]?.takeUnless { it is JsonNull }?.jsonPrimitive?.contentOrNull
    // OkHttp insists on a body object for POST/PUT; a zero-length one is bodyless to the library.
    val body = when {
        bodyHex != null -> hex(bodyHex).toRequestBody()
        method in setOf("POST", "PUT", "PATCH", "PROPPATCH", "REPORT") -> ByteArray(0).toRequestBody()
        else -> null
    }
    val builder = Request.Builder().url(serverURL + request.str("path")).method(method, body)
    (request["headers"] as? JsonObject)?.forEach { (k, v) -> builder.header(k, v.jsonPrimitive.content) }
    val resp = tr.roundTrip(builder.build())
    r.status = resp.code
    r.headers = subsetHeaders(resp.headers)
    val plain = readTracked(resp.body!!.byteStream(), r)
    resp.close()
    // No nonce on a non-2xx is a sanctioned unauthenticated pass-through.
    if (resp.headers(ResponseNonceHeader).firstOrNull().isNullOrEmpty() && resp.code !in 200..299) r.passthrough = true
    r.setBody(plain)
}

/** mapErr reads the canonical code the library attached; uncoded errors are adapter/transport input errors. */
fun mapErr(e: Throwable): String = codeOf(e)?.value ?: "INVALID_INPUT"

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

fun subsetHeaders(h: Headers): Map<String, String> =
    listOf(ResponseNonceHeader, "Content-Length", "Transfer-Encoding", "Content-Type")
        .mapNotNull { k -> h[k]?.let { k.lowercase() to it } }.toMap()

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
fun hex(s: String): ByteArray {
    if (s.length % 2 != 0) fatal("bad hex: odd length")
    return ByteArray(s.length / 2) { i ->
        val v = s.substring(2 * i, 2 * i + 2).toIntOrNull(16) ?: fatal("bad hex: ${s.substring(2 * i, 2 * i + 2)}")
        v.toByte()
    }
}
fun fatal(msg: String): Nothing { System.err.println(msg); exitProcess(2) }
