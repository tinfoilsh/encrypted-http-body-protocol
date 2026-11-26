// The Kotlin API shim over the event-driven EHBP core (dafny/ehbp_events.dfy),
// the five entry points of conformance/spec/handler.md section 7: every
// exchange is driven by the pump in sh.tinfoil.ehbp.residue and every protocol
// decision is the core's.
package sh.tinfoil.ehbp.client

import EHBP.Option
import EHBP.Origin
import EHBP.__default.CheckPublicKey
import EHBP.__default.MakeOrigin
import EHBP.__default.ParseConfig
import EHBPEvents.Event
import EHBPEvents.__default.Initial
import dafny.TypeDescriptor
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okio.BufferedSource
import okio.buffer
import okio.source
import sh.tinfoil.ehbp.identity.KeyConfigError
import sh.tinfoil.ehbp.identity.SessionRecoveryToken
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.ProtocolError
import sh.tinfoil.ehbp.protocol.codeOf
import sh.tinfoil.ehbp.residue.BodyReader
import sh.tinfoil.ehbp.residue.Exchange
import sh.tinfoil.ehbp.residue.bytes
import sh.tinfoil.ehbp.residue.headerSeq
import sh.tinfoil.ehbp.residue.seq
import sh.tinfoil.ehbp.residue.str
import sh.tinfoil.ehbp.residue.unwrap
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.SequenceInputStream
import java.math.BigInteger

// constructor: a Transport over one server origin and the key a KeySource yields.

/** KeySource is where a Transport gets the server's HPKE public key (SPEC 3). */
sealed class KeySource {
    /** Fetch /.well-known/hpke-keys from the server. */
    object Discover : KeySource()
    /** A pre-fetched key configuration (RFC 9458 application/ohttp-keys bytes). */
    class Config(val bytes: ByteArray) : KeySource()
    /** A raw 32-byte X25519 public key, for example attestation-verified. */
    class PublicKey(val bytes: ByteArray) : KeySource()
}

/**
 * Transport encrypts request bodies to the server's key and decrypts response
 * bodies, the way Go's client.Transport implements http.RoundTripper. Requests
 * must target [server]'s origin. roundTrip is a single HTTP transaction on a
 * copy of [httpClient] with redirects and the cache disabled; timeouts, TLS
 * pinning, proxies and cookies stay as configured.
 */
class Transport(server: String, keys: KeySource, httpClient: OkHttpClient = OkHttpClient()) {
    private val origin = parseOrigin(server)
    private val httpClient = httpClient.singleTransaction()
    private val publicKey = when (keys) {
        is KeySource.Discover -> discover(origin, this.httpClient)
        is KeySource.Config -> bytes(unwrap(ParseConfig(seq(keys.bytes))))
        is KeySource.PublicKey -> bytes(unwrap(CheckPublicKey(seq(keys.bytes))))
    }
    private val session = Exchange.Session()

    // token: the exchange in flight.

    /** sessionRecoveryToken returns the token of the exchange in flight, or null (SPEC 6). */
    fun sessionRecoveryToken(): SessionRecoveryToken? =
        session.token()?.let { SessionRecoveryToken(bytes(it.dtor_exportedSecret()), bytes(it.dtor_requestEnc())) }

    // request: the one entry point, roundTrip; the core validates, seals, classifies and decrypts.

    /**
     * roundTrip performs one encrypted exchange. Throws ProtocolError (coded),
     * KeyConfigError on a 422 key configuration problem, or OkHttp's
     * IOException for transport failures.
     */
    fun roundTrip(req: Request): Response {
        val body = req.body?.also { if (it.isDuplex()) throw ProtocolError(Code.InvalidInput, "duplex request bodies are unsupported") }
        // OkHttp would add the body's media type itself; the core owns the header list.
        val contentType = body?.contentType()?.takeIf { req.header("Content-Type") == null }?.let { "Content-Type" to it.toString() }
        val u = req.url // HttpUrl already lowercases and resolves the default port
        val start = Event.create_Start(str(req.method), str(u.toString()), str(u.scheme), str(u.host), BigInteger.valueOf(u.port.toLong()), true,
            u.username.isNotEmpty() || u.password.isNotEmpty(), headerSeq(req.headers + listOfNotNull(contentType)), body != null)
        val x = Exchange(Initial(origin, seq(publicKey)), session, httpClient, body)
        x.feed(start)
        x.failure?.let { throw if (codeOf(it) == Code.KeyConfigMismatch) KeyConfigError(it) else it }
        return outcome(x)
    }
}

// discover: the same discovery the constructor runs; the 32-byte public key.

/** discover fetches the server's public key from /.well-known/hpke-keys (SPEC 3.1), as the constructor does, for callers that cache keys. */
fun discover(server: String, httpClient: OkHttpClient = OkHttpClient()): ByteArray = discover(parseOrigin(server), httpClient.singleTransaction())

private fun discover(origin: Origin, httpClient: OkHttpClient): ByteArray {
    val x = Exchange(Initial(origin, seq(ByteArray(0))), Exchange.Session(), httpClient, null)
    x.feed(Event.create_DiscoverStart())
    x.failure?.let { throw it }
    return x.publicKey
}

// selfCheck: the core's primitive vectors through this residue.

/** selfCheck runs the core's primitive vectors through this language's bindings; empty means pass. */
fun selfCheck(): List<String> = sh.tinfoil.ehbp.residue.selfCheck()

// No HTTP cache either: ciphertext and recovery-bound responses are never written to disk or replayed.
private fun OkHttpClient.singleTransaction() = newBuilder().followRedirects(false).followSslRedirects(false).cache(null).build()

/** parseOrigin hands the parsed parts of server to the core, which validates them. */
private fun parseOrigin(server: String): Origin {
    val u = server.toHttpUrlOrNull() ?: throw ProtocolError(Code.InvalidInput, "base URL must include an HTTP origin")
    val port = Option.create_Some(TypeDescriptor.BIG_INTEGER, BigInteger.valueOf(u.port.toLong()))
    return unwrap(MakeOrigin(str(u.scheme), str(u.host), port, u.username.isNotEmpty() || u.password.isNotEmpty()))
}

/**
 * outcome is the response of an exchange the core has run to Passthrough or
 * Done: the native response with its body replaced, as Go's eventclient does.
 */
internal fun outcome(x: Exchange): Response {
    val resp = x.response!!
    val type = resp.body!!.contentType()
    return when {
        x.passthrough -> if (x.prefix.isEmpty()) resp else resp.newBuilder().body(responseBody(type, SequenceInputStream(ByteArrayInputStream(x.prefix), resp.body!!.byteStream()))).build()
        x.done -> resp.newBuilder().headers(x.headers!!).body(responseBody(type, BodyReader(x))).build()
        else -> throw IOException("exchange ended without an outcome")
    }
}

/** responseBody wraps a stream as the replacement OkHttp body; closing it closes the stream. */
private fun responseBody(type: MediaType?, stream: InputStream): ResponseBody = object : ResponseBody() {
    private val src = stream.source().buffer()
    override fun contentType(): MediaType? = type
    override fun contentLength() = -1L
    override fun source(): BufferedSource = src
}
