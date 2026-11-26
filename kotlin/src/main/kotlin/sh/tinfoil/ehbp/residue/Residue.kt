// The Kotlin residue of the event-driven core (dafny/ehbp_events.dfy): one
// binding per action the core can emit, the loop of conformance/spec/handler.md
// section 5 over the core's Perform, and the conversions at the runtime boundary. Nothing here decides anything
// about the protocol; the layout follows conformance/spec/handler.md section 4
// and mirrors internal/eventresidue/residue.go.
package sh.tinfoil.ehbp.residue

import EHBP.Code
import EHBP.Result
import EHBP.Token
import EHBPEvents.Action
import EHBPEvents.BodyEnd
import EHBPEvents.Event
import EHBPEvents.Performer
import EHBPEvents.SessionAction
import EHBPEvents.SessionStore
import EHBPEvents.State
import EHBPEvents.Stream
import dafny.CodePoint
import dafny.DafnySequence
import dafny.Tuple2
import dafny.Tuple3
import dafny.Tuple4
import dafny.TypeDescriptor
import okhttp3.Headers
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okio.Buffer
import okio.BufferedSink
import okio.Pipe
import okio.Source
import okio.buffer
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519
import sh.tinfoil.ehbp.protocol.ProtocolError
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread

// crypto: one native call each, bytes in, bytes out. A failure is an empty
// result (or ok false for aeadOpen), which the core rejects by length.
// X25519 (false on a low-order point) and HMAC are BouncyCastle's: the JDK's X25519 needs
// Android 33 and its HMAC rejects the empty key HPKE extracts with; AES-GCM and randomness are the JDK's.

// One Cipher per mode and thread, re-initialised per call: Cipher.getInstance is
// a provider lookup that costs more than sealing a frame until the JIT has warmed up.
private val ciphers = ThreadLocal.withInitial { arrayOfNulls<Cipher>(Cipher.DECRYPT_MODE + 1) }

private fun gcm(mode: Int, key: ByteArray, nonce: ByteArray): Cipher {
    require(nonce.size == 12)
    val slot = ciphers.get()
    val cipher = slot[mode] ?: Cipher.getInstance("AES/GCM/NoPadding").also { slot[mode] = it }
    return cipher.also { it.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)) }
}

private val random = SecureRandom()

internal fun x25519(scalar: ByteArray, point: ByteArray): ByteArray {
    val out = ByteArray(32)
    return try { out.takeIf { scalar.size == 32 && point.size == 32 && X25519.calculateAgreement(scalar, 0, point, 0, out, 0) } } catch (e: Exception) { null } ?: ByteArray(0)
}

internal fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = HMac(SHA256Digest()).also { it.init(KeyParameter(key)); it.update(data, 0, data.size) }
    return try { ByteArray(mac.macSize).also { mac.doFinal(it, 0) } } catch (e: Exception) { null } ?: ByteArray(0)
}

internal fun aeadSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
    return try { gcm(Cipher.ENCRYPT_MODE, key, nonce).doFinal(plaintext) } catch (e: Exception) { null } ?: ByteArray(0)
}

internal fun aeadOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): Pair<Boolean, ByteArray> {
    return try { true to gcm(Cipher.DECRYPT_MODE, key, nonce).doFinal(ciphertext) } catch (e: Exception) { false to ByteArray(0) }
}

internal fun randomBytes(length: Int): ByteArray {
    return try { ByteArray(length).also { random.nextBytes(it) } } catch (e: Exception) { null } ?: ByteArray(0)
}

// http: the only block holding native state. One Exchange per request or
// discovery; the bindings are its methods.

/**
 * Exchange binds a core state to the native pieces: one OkHttp transaction on
 * [client] (built to never follow redirects) and the caller's request body, or
 * null. The outcome fields are written by the terminal actions and read by the shim.
 */
internal class Exchange(
    state: State = State.Default(),
    private val session: Session = Session(),
    private val client: OkHttpClient = OkHttpClient(),
    private val body: RequestBody? = null,
) : Performer {
    var state = state
        private set
    private val upload = Pipe(256L * 1024) // the encrypted upload, fed by write
    private val producer = Pipe(64L * 1024) // the caller's body, pushed by its writeTo on its own thread
    private val worker by lazy {
        if (client.callTimeoutMillis > 0) producer.source.timeout().deadline(client.callTimeoutMillis.toLong(), TimeUnit.MILLISECONDS)
        thread(name = "EHBP request body", isDaemon = true) {
            val sink = producer.sink.buffer()
            try { body!!.writeTo(sink); sink.flush() } catch (e: Throwable) { bodyErr = e } finally { producer.sink.runCatching { close() } }
        }
    }
    private var handed = false // the upload lane owns body
    private var sendErr: Throwable? = null
    private var respErr: Throwable? = null
    @Volatile private var bodyErr: Throwable? = null // native causes behind a Transport failure
    @Volatile private var abortErr: Throwable? = null
    private val bodyRequired = setOf("POST", "PUT", "PATCH", "PROPPATCH", "REPORT") // what OkHttp's HttpMethod.requiresRequestBody says

    // The outcome.
    var response: Response? = null // the native response, every field the stack set
    var failure: Throwable? = null
    var passthrough = false
    var done = false
    var finished = false
    var prefix = ByteArray(0)
    var publicKey = ByteArray(0)
    var plain = ByteArray(0) // EmitPlaintext since the last Read
    var headers: Headers? = null

    // http: the four performers over OkHttp (send, write, read, close), written by hand.
    /** send performs the transaction and reports its head; with a body it blocks while the upload lane feeds the pipe. */
    fun send(verb: String, url: String, headers: List<Pair<String, String>>, hasBody: Boolean): Triple<Boolean, Int, Headers?> {
        // OkHttp insists on a body object for POST and friends; an empty one is bodyless on the wire.
        val native = if (hasBody) streaming() else if (verb in bodyRequired) ByteArray(0).toRequestBody() else null
        val resp = try {
            client.newCall(Request.Builder().url(url).headers(headersOf(headers)).method(verb, native).build()).execute()
        } catch (e: Throwable) {
            sendErr = e
            upload.source.close() // the transport gave up; unblock the upload lane
            return Triple(false, 0, null)
        }
        response = resp
        return Triple(true, resp.code, resp.headers)
    }

    /** streaming is the unknown-length, one-shot upload: every chunk the lane writes is flushed to the wire. */
    private fun streaming() = object : RequestBody() {
        override fun contentType(): MediaType? = null
        override fun contentLength() = -1L
        override fun isOneShot() = true
        override fun writeTo(sink: BufferedSink) {
            val buf = Buffer()
            while (upload.source.read(buf, 64L * 1024) >= 0) {
                sink.write(buf, buf.size)
                sink.flush()
            }
            abortErr?.let { throw it }
        }
    }

    /** write feeds one encrypted chunk; Done ends the upload, Aborted fails it with the code; false once the transport is gone. */
    fun write(data: ByteArray, end: BodyEnd): Boolean {
        try {
            if (data.isNotEmpty()) upload.sink.write(Buffer().write(data), data.size.toLong())
        } catch (e: IOException) {
            close(Stream.create_RequestBody())
            return false
        }
        if (end.is_More) return true
        if (end.is_Aborted) abortErr = error(end.dtor_code(), "request body failed", bodyErr)
        upload.sink.close()
        close(Stream.create_RequestBody())
        return true
    }

    /** read reads once from the caller's body or the native response: chunk, eof, ok. */
    fun read(stream: Stream): Triple<ByteArray, Boolean, Boolean> {
        if (stream.is_RequestBody) worker
        val source = if (stream.is_RequestBody) producer.source else response!!.body!!.source()
        val (chunk, eof) = try { readChunk(source) } catch (e: IOException) {
            if (stream.is_RequestBody) bodyErr = e else respErr = e
            return Triple(ByteArray(0), false, false)
        }
        return Triple(chunk, eof, !(stream.is_RequestBody && eof && bodyErr != null))
    }

    /** close releases the native stream. */
    fun close(stream: Stream) {
        if (stream.is_RequestBody) producer.source.close() else response?.body?.close()
    }

    private fun readChunk(source: Source): Pair<ByteArray, Boolean> {
        val buf = Buffer()
        val n = source.read(buf, 64L * 1024)
        return buf.readByteArray() to (n < 0)
    }

    // session: a mutex around one SessionStore value; every rule is SessionApply (SPEC 6).

    internal class Session {
        private var store: SessionStore = EHBPEvents.__default.NewSession()

        @Synchronized
        private fun apply(a: SessionAction): SessionStore {
            store = EHBPEvents.__default.SessionApply(store, a)
            return store
        }

        fun beginSession(): Long = apply(SessionAction.create_Begin()).dtor_generation()

        fun publishToken(generation: Long, exportedSecret: ByteArray, requestEnc: ByteArray) {
            apply(SessionAction.create_Publish(generation, Token.create(seq(exportedSecret), seq(requestEnc))))
        }

        fun clearToken(generation: Long) {
            apply(SessionAction.create_Clear(generation))
        }

        /** token returns the stored token, or null. */
        @Synchronized
        fun token(): Token? = store.dtor_token().takeIf { it.is_Some }?.dtor_value()
    }

    // pump: handler.md section 5. Perform (ehbp_events.dfy) dispatches one
    // action to this Performer; run is the loop.

    // The core's Performer: each method converts at the runtime boundary and calls one binding.
    override fun BeginSession(): Long = session.beginSession()
    override fun PublishToken(generation: Long, exportedSecret: Bytes, requestEnc: Bytes) = session.publishToken(generation, bytes(exportedSecret), bytes(requestEnc))
    override fun ClearToken(generation: Long) = session.clearToken(generation)
    override fun RandomBytes(length: BigInteger): Bytes = seq(randomBytes(length.toInt()))
    override fun X25519(scalar: Bytes, point: Bytes): Bytes = seq(x25519(bytes(scalar), bytes(point)))
    override fun HmacSha256(key: Bytes, data: Bytes): Bytes = seq(hmacSha256(bytes(key), bytes(data)))
    override fun AeadSeal(key: Bytes, nonce: Bytes, plaintext: Bytes): Bytes = seq(aeadSeal(bytes(key), bytes(nonce), bytes(plaintext)))
    override fun AeadOpen(key: Bytes, nonce: Bytes, ciphertext: Bytes): Tuple2<Boolean, Bytes> = aeadOpen(bytes(key), bytes(nonce), bytes(ciphertext)).let { (ok, plaintext) -> Tuple2.create(ok, seq(plaintext)) }
    override fun Send(verb: Str, url: Str, headers: HeaderSeq, hasBody: Boolean): Tuple4<Boolean, BigInteger, HeaderSeq, Boolean> =
        send(string(verb), string(url), headerPairs(headers), hasBody).let { (ok, status, head) -> Tuple4.create(ok, BigInteger.valueOf(status.toLong()), headerSeq(head ?: emptyList()), false) }
    override fun Write(data: Bytes, end: BodyEnd): Boolean = write(bytes(data), end)
    override fun Read(stream: Stream): Tuple3<Boolean, Bytes, Boolean> = read(stream).let { (data, eof, ok) -> Tuple3.create(ok, seq(data), eof) }
    override fun Close(stream: Stream) = close(stream)
    override fun EmitPlaintext(data: Bytes) { plain += bytes(data) }

    /**
     * run feeds events to Step until a terminal action. A Send with a body hands
     * the rest of its action list, the upload, to a second lane (a thread) so
     * the transaction can block for the response head; this lane stops there.
     */
    fun run(first: List<Action>) {
        var acts = first
        val events = ArrayList<Event>()
        while (true) {
            for ((i, a) in acts.withIndex()) {
                when {
                    a.is_Passthrough -> { passthrough = true; prefix = bytes(a.dtor_prefix()); return }
                    a.is_Done -> { done = true; headers = headersOf(headerPairs(a.dtor_headers())); return }
                    a.is_Finished -> { finished = true; return }
                    a.is_Discovered -> { publicKey = bytes(a.dtor_publicKey()); return }
                    a.is_Fail -> { failure = error(a.dtor_code(), string(a.dtor_message()), cause()); return }
                    a.is_Send && a.dtor_hasBody() -> { handed = true; thread(name = "EHBP upload", isDaemon = true) { run(acts.subList(i + 1, acts.size)) } }
                }
                val r = EHBPEvents.__default.Perform(this, a)
                if (r.is_Stop) return
                if (r.is_Got) events += r.dtor_e()
                if (a.is_Send && a.dtor_hasBody()) break // the upload lane owns the rest of this list
            }
            if (events.isEmpty()) return
            acts = step(events.removeAt(events.size - 1))
        }
    }

    @Synchronized
    private fun step(e: Event): List<Action> {
        val r = EHBPEvents.__default.Step(state, e)
        state = r.dtor__0()
        return r.dtor__1().toList()
    }

    /** cause is the native error behind a Transport failure, if any. */
    private fun cause(): Throwable? = sendErr ?: respErr ?: bodyErr

    /** feed runs the pump on one caller event: Start, DiscoverStart, ResponseHead, CallerRead or CallerClose. */
    fun feed(e: Event) {
        run(step(e))
        if (!handed) close(Stream.create_RequestBody()) // the core never asked for the body
    }
}

/**
 * BodyReader is the decrypted response body after Done: each read drives the
 * core with CallerRead until it emits plaintext, finishes or fails; close releases it.
 */
internal class BodyReader(private val x: Exchange) : InputStream() {
    private var pending = ByteArray(0)
    private var pos = 0
    private var err: Throwable? = null
    private var eof = false

    override fun read(): Int = ByteArray(1).let { if (read(it, 0, 1) < 0) -1 else it[0].toInt() and 0xff }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        while (pos == pending.size) {
            err?.let { throw it }
            if (eof) return -1
            x.feed(Event.create_CallerRead())
            pending = x.plain
            x.plain = ByteArray(0)
            pos = 0
            err = x.failure
            eof = x.finished
        }
        val n = minOf(len, pending.size - pos)
        System.arraycopy(pending, pos, b, off, n)
        pos += n
        return n
    }

    override fun close() = x.feed(Event.create_CallerClose())
}

// conversions: the runtime boundary only.

internal typealias Bytes = DafnySequence<out Byte>
internal typealias Str = DafnySequence<out CodePoint>
internal typealias HeaderSeq = DafnySequence<out Tuple2<Str, Str>>

private val strTd: TypeDescriptor<Str> = DafnySequence._typeDescriptor(TypeDescriptor.UNICODE_CHAR)
private val headerTd: TypeDescriptor<Tuple2<Str, Str>> = Tuple2._typeDescriptor(strTd, strTd)

internal fun seq(b: ByteArray): Bytes = DafnySequence.fromBytes(b)
@Suppress("UNCHECKED_CAST")
internal fun bytes(s: Bytes): ByteArray = DafnySequence.toByteArray(s as DafnySequence<Byte>)
internal fun str(s: String): Str = DafnySequence.asUnicodeString(s)
internal fun string(s: Str): String = s.verbatimString()

/** headerSeq converts headers to the core's seq<(string, string)>, one entry per value. */
internal fun headerSeq(h: Iterable<Pair<String, String>>): HeaderSeq = DafnySequence.fromList(headerTd, h.map { (n, v) -> Tuple2.create<Str, Str>(str(n), str(v)) })

/** headerPairs converts the core's header list back to name/value pairs. */
internal fun headerPairs(s: HeaderSeq): List<Pair<String, String>> = s.map { string(it.dtor__0()) to string(it.dtor__1()) }

internal fun headersOf(pairs: List<Pair<String, String>>): Headers = Headers.Builder().apply { for ((n, v) in pairs) addUnsafeNonAscii(n, v) }.build()

// mapping: from the core's CodeString; no table of strings.

/** code maps a core code to the canonical protocol code; Transport has none. */
internal fun code(c: Code): sh.tinfoil.ehbp.protocol.Code? = string(EHBP.__default.CodeString(c)).let { s -> sh.tinfoil.ehbp.protocol.Code.entries.firstOrNull { it.value == s } }

/** error turns a core failure into a Kotlin exception: a coded ProtocolError, or the native cause of a Transport failure. */
internal fun error(c: Code, message: String, cause: Throwable?): Throwable = code(c)?.let { ProtocolError(it, message, cause) } ?: cause ?: IOException(message)

/** unwrap returns an Ok result's value or throws the Err. */
internal fun <T> unwrap(r: Result<T>): T {
    if (r.is_Err) throw error(r.dtor_code(), string(r.dtor_message()), null)
    return r.dtor_value()
}

/** selfCheck runs the core's primitive vectors through this residue; empty means pass. */
internal fun selfCheck(): List<String> {
    val x = Exchange()
    val results = EHBPEvents.__default.SelfCheckActions().map { EHBPEvents.__default.Perform(x, it).dtor_e() }
    return EHBPEvents.__default.SelfCheckJudge(DafnySequence.fromList(Event._typeDescriptor(), results)).map { string(it) }
}
