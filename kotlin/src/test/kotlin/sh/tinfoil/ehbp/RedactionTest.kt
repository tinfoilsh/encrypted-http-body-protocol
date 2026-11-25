package sh.tinfoil.ehbp

import sh.tinfoil.ehbp.residue.seq
import kotlin.test.Test
import kotlin.test.assertTrue

// The generated printers of the secret-bearing datatypes are redacted by
// dafny/patch-runtime.py (SECRET_TYPES): rendering a token, a context or a
// value holding one must not expose key material.
class RedactionTest {
    @Test
    fun generatedPrintersRedactSecrets() {
        val secret = seq(ByteArray(32) { 0xAB.toByte() })
        val token = EHBP.Token.create(secret, secret)
        val ctx = EHBPEvents.Ctx.create(secret, seq(ByteArray(12)), secret, 0L)
        val store = EHBPEvents.SessionStore.create(1L, EHBP.Option.create_Some(EHBP.Token._typeDescriptor(), token))
        for (value in listOf(token, ctx, store, EHBPEvents.Action.create_PublishToken(1L, secret, secret))) {
            val rendered = value.toString()
            assertTrue(rendered.contains("(<redacted>)") && !rendered.contains("171"), rendered)
        }
    }
}
