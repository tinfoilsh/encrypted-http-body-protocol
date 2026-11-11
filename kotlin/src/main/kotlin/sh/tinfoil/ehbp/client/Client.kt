// Mirrors client/client.go.
package sh.tinfoil.ehbp.client

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import sh.tinfoil.ehbp.identity.Identity
import sh.tinfoil.ehbp.identity.KeyConfigError
import sh.tinfoil.ehbp.identity.RequestEncLength
import sh.tinfoil.ehbp.identity.SessionRecoveryToken
import sh.tinfoil.ehbp.identity.decryptResponseWithToken
import sh.tinfoil.ehbp.identity.encryptRequestWithContext
import sh.tinfoil.ehbp.identity.extractSessionRecoveryToken
import sh.tinfoil.ehbp.identity.readFully
import sh.tinfoil.ehbp.identity.unmarshalPublicConfig
import sh.tinfoil.ehbp.identity.withStream
import sh.tinfoil.ehbp.protocol.Code
import sh.tinfoil.ehbp.protocol.EncapsulatedKeyHeader
import sh.tinfoil.ehbp.protocol.KeyConfigProblemType
import sh.tinfoil.ehbp.protocol.KeysMediaType
import sh.tinfoil.ehbp.protocol.KeysPath
import sh.tinfoil.ehbp.protocol.ProblemJSONMediaType
import sh.tinfoil.ehbp.protocol.ProtocolError
import sh.tinfoil.ehbp.protocol.ResponseNonceHeader
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream

private const val maxProblemDetailsBytes = 64 shl 10

/**
 * Transport encrypts request bodies to the server identity and decrypts
 * response bodies, the way Go's client.Transport implements http.RoundTripper.
 *
 * roundTrip performs a single HTTP transaction, as a Go RoundTripper does: the
 * OkHttpClient is derived with redirects disabled, so a 3xx is returned to the
 * caller (an unauthenticated pass-through) instead of being replayed with the
 * same encapsulated key against the new location. Timeouts, TLS pinning,
 * proxies and cookies stay as configured on the supplied client.
 */
class Transport internal constructor(
    private val serverIdentity: Identity,
    httpClient: OkHttpClient,
    // origin is the scheme://host[:port] the key configuration was fetched from
    // or declared for; requests must target it. Null when built from a bare identity.
    private val origin: HttpUrl?,
) {
    // No HTTP cache either: ciphertext and recovery-bound responses are never
    // written to disk or replayed, as with Go's cache-less http.Transport.
    private val httpClient = httpClient.newBuilder().followRedirects(false).followSslRedirects(false).cache(null).build()
    private val mu = Any()
    private var lastSessionRecoveryToken: SessionRecoveryToken? = null
    private var requestGeneration = 0L

    fun serverIdentity(): Identity = serverIdentity

    /**
     * GetSessionRecoveryToken returns the session recovery token from the most
     * recent request that had a body, or null (no request yet, last request
     * bodyless, or its exchange already completed or failed).
     */
    fun getSessionRecoveryToken(): SessionRecoveryToken? = synchronized(mu) { lastSessionRecoveryToken }

    /** setToken publishes (or clears, with null) the token for generation unless a newer request has since started. */
    private fun setToken(generation: Long, token: SessionRecoveryToken?) = synchronized(mu) {
        if (requestGeneration == generation) lastSessionRecoveryToken = token
    }

    /**
     * validateRequest rejects requests that would let the caller influence the
     * authority or the protocol headers the library owns (SPEC 5.1): the Ehbp-*
     * headers and Host. Content-Length and Transfer-Encoding are stripped in
     * roundTrip instead (OkHttp only derives them when a body exists).
     */
    private fun validateRequest(req: Request) {
        val url = req.url
        if (url.username.isNotEmpty() || url.password.isNotEmpty()) {
            throw ProtocolError(Code.InvalidInput, "request URL must not include credentials")
        }
        if (origin != null && !sameOrigin(origin, url)) {
            throw ProtocolError(Code.InvalidInput, "request URL must use the configured origin: $origin")
        }
        for (name in req.headers.names()) {
            if (name.equals(EncapsulatedKeyHeader, true) || name.equals(ResponseNonceHeader, true) || name.equals("Host", true)) {
                throw ProtocolError(Code.InvalidInput, "reserved request header cannot be set by callers: $name")
            }
        }
    }

    /**
     * RoundTrip sends req, encrypting its body when present and decrypting the
     * response. Throws ProtocolError (coded), KeyConfigError on a 422 key
     * configuration problem, or OkHttp's IOException for transport failures.
     */
    fun roundTrip(req: Request): Response {
        validateRequest(req)

        val generation = synchronized(mu) {
            lastSessionRecoveryToken = null
            ++requestGeneration
        }

        // Like Go's transport, which never writes these from req.Header: on a bodyless request
        // OkHttp would send caller-set Content-Length / Transfer-Encoding verbatim.
        val cleaned = req.newBuilder().removeHeader("Content-Length").removeHeader("Transfer-Encoding").build()

        // For bodyless requests reqCtx is null: the response passes through unencrypted.
        val (newReq, reqCtx) = serverIdentity.encryptRequestWithContext(cleaned)

        var token: SessionRecoveryToken? = null
        if (reqCtx != null) {
            token = extractSessionRecoveryToken(reqCtx)
            // Publish before sending (SPEC 6): the token must survive a crash
            // while the response is pending. Every failure path below clears it.
            setToken(generation, token)
        }

        var resp = try {
            httpClient.newCall(newReq).execute()
        } catch (e: Exception) {
            setToken(generation, null)
            throw e
        }

        // Only decrypt if we encrypted the request (had a body)
        if (reqCtx != null) {
            val nonces = resp.headers(ResponseNonceHeader)
            val (rekey, title) = try {
                if (nonces.isEmpty()) isKeyConfigMismatchResponse(resp) else false to ""
            } catch (e: Throwable) { // any failure here ends the exchange: release the connection and the token
                resp.close()
                setToken(generation, null)
                throw e
            }
            if (rekey) {
                resp.close()
                setToken(generation, null)
                throw KeyConfigError(ProtocolError(Code.KeyConfigMismatch, title.ifEmpty { "key configuration mismatch" }))
            }

            if (nonces.isEmpty() && resp.code !in 200..299) {
                // Unauthenticated pass-through: the exchange's token is consumed (SPEC 5.1).
                setToken(generation, null)
                return resp
            }

            resp = try {
                decryptResponseWithToken(resp, token!!)
            } catch (e: Throwable) {
                resp.close()
                setToken(generation, null)
                throw e
            }
            val body = resp.body!!
            resp = resp.newBuilder().body(body.withStream(TokenOwningInputStream(body.byteStream()) { setToken(generation, null) })).build()
        }
        return resp
    }

    /**
     * isKeyConfigMismatchResponse detects the SPEC 5.4.2 problem response. The
     * body is only peeked, so a non-matching 422 can still be passed through
     * or decrypted; bodies above 64 KiB are not parsed.
     */
    private fun isKeyConfigMismatchResponse(resp: Response): Pair<Boolean, String> {
        val none = false to ""
        if (resp.code != 422) return none
        if (!isProblemJSONContentType(resp.header("Content-Type").orEmpty())) return none

        val bodyBytes = resp.peekBody((maxProblemDetailsBytes + 1).toLong()).bytes()
        if (bodyBytes.size > maxProblemDetailsBytes) return none

        val problem = try {
            Json.parseToJsonElement(bodyBytes.decodeToString())
        } catch (_: SerializationException) {
            return none
        } catch (_: StackOverflowError) { // kotlinx recurses on nested arrays: not a problem document
            return none
        } as? JsonObject ?: return none
        // SPEC 5.4.2: the exact, case-sensitive "type" member decides; "title" is used only when it is a string.
        fun str(name: String) = (problem[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
        if (str("type") != KeyConfigProblemType) return none
        return true to str("title").orEmpty()
    }
}

/** Reports the exchange as consumed on EOF or on a read failure so the Transport can drop its token. */
private class TokenOwningInputStream(src: InputStream, private val onDone: () -> Unit) : FilterInputStream(src) {
    private var done = false

    override fun read(): Int = guard { `in`.read() }
    override fun read(b: ByteArray, off: Int, len: Int): Int = guard { `in`.read(b, off, len) }

    private inline fun guard(read: () -> Int): Int {
        val n = try {
            read()
        } catch (e: Throwable) {
            finish()
            throw e
        }
        if (n < 0) finish()
        return n
    }

    /** Close ends the exchange whatever was read (SPEC 6.3): a body abandoned before EOF consumes its token too. */
    override fun close() {
        finish()
        super.close()
    }

    private fun finish() {
        if (!done) {
            done = true
            onDone()
        }
    }
}

/** isMediaType reports whether contentType's media type is want, compared case-insensitively with any parameters ignored. */
private fun isMediaType(contentType: String, want: String): Boolean =
    contentType.substringBefore(';').trim().equals(want, ignoreCase = true)

private fun isProblemJSONContentType(contentType: String): Boolean = isMediaType(contentType, ProblemJSONMediaType)

/** parseOrigin validates a base URL: http(s) scheme, a host, and no credentials. */
private fun parseOrigin(server: String): HttpUrl {
    val u = server.toHttpUrlOrNull() ?: throw ProtocolError(Code.InvalidInput, "base URL must include an HTTP origin")
    if (u.username.isNotEmpty() || u.password.isNotEmpty()) {
        throw ProtocolError(Code.InvalidInput, "base URL must not include credentials")
    }
    return HttpUrl.Builder().scheme(u.scheme).host(u.host).port(u.port).build()
}

// HttpUrl canonicalizes scheme and host to lowercase and resolves the default port.
private fun sameOrigin(a: HttpUrl, b: HttpUrl): Boolean = a.scheme == b.scheme && a.host == b.host && a.port == b.port

private fun syncServerPublicKey(server: HttpUrl, httpClient: OkHttpClient): Identity {
    val keysURL = server.newBuilder().encodedPath(KeysPath).fragment(null).build()
    val discoveryClient = httpClient.newBuilder().followRedirects(false).followSslRedirects(false).cache(null).build()
    discoveryClient.newCall(Request.Builder().url(keysURL).build()).execute().use { resp ->
        if (resp.code != 200) throw ProtocolError(Code.InvalidKeyConfig, "server returned status ${resp.code}")
        val contentType = resp.header("Content-Type").orEmpty()
        if (!isMediaType(contentType, KeysMediaType)) throw ProtocolError(Code.InvalidKeyConfig, "server returned invalid content type: $contentType")
        // Only the first key_config is used. Its suite list has a uint16 length,
        // so reading that config alone bounds discovery memory even when the
        // endpoint sends an unbounded stream of trailing configs or junk.
        val stream = resp.body?.byteStream() ?: throw ProtocolError(Code.InvalidKeyConfig, "server returned no key configuration")
        val prefixLength = 1 + 2 + RequestEncLength + 2
        val prefix = stream.readFully(prefixLength)
        if (prefix.size < prefixLength) return unmarshalPublicConfig(prefix)
        val suitesLength = ((prefix[prefixLength - 2].toInt() and 0xff) shl 8) or
            (prefix[prefixLength - 1].toInt() and 0xff)
        return unmarshalPublicConfig(prefix + stream.readFully(suitesLength))
    }
}

/**
 * NewTransport fetches the server key configuration from /.well-known/hpke-keys
 * on server and returns a Transport bound to that origin. The same httpClient
 * sends the encrypted requests, so callers can supply a TLS-pinned client.
 */
fun newTransport(server: String, httpClient: OkHttpClient = OkHttpClient()): Transport {
    val origin = parseOrigin(server)
    return Transport(syncServerPublicKey(origin, httpClient), httpClient, origin)
}

/** NewTransportWithConfig creates a Transport from pre-fetched /.well-known/hpke-keys bytes (RFC 9458 format). */
fun newTransportWithConfig(server: String, hpkeConfig: ByteArray, httpClient: OkHttpClient = OkHttpClient()): Transport {
    val origin = parseOrigin(server)
    return Transport(unmarshalPublicConfig(hpkeConfig), httpClient, origin)
}

/**
 * NewTransportWithIdentity creates a Transport from an already-trusted server
 * identity, for example one built from an attestation-verified HPKE public key
 * via fromPublicKeyHex. No network request is made and no origin is enforced.
 */
fun newTransportWithIdentity(serverIdentity: Identity, httpClient: OkHttpClient = OkHttpClient()): Transport =
    Transport(serverIdentity, httpClient, null)
