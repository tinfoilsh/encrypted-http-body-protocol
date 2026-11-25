// The generated printers of the secret-bearing datatypes are redacted by
// dafny/patch-runtime.py (SECRET_TYPES): rendering a token, a context or a
// value holding one must not expose key material.
import { it } from 'node:test';
import assert from 'node:assert';
// @ts-expect-error the generated CommonJS module has no declarations.
import gen from '../gen/ehbp.cjs';
import { seq } from '../residue.js';

it('generated printers redact secrets', () => {
  const { EHBP, EHBPEvents } = gen;
  const secret = seq(new Uint8Array(32).fill(0xab));
  const token = EHBP.Token.create_Token(secret, secret);
  const ctx = EHBPEvents.Ctx.create_Ctx(secret, seq(new Uint8Array(12)), secret, 0);
  const store = EHBPEvents.SessionStore.create_SessionStore(1, EHBP.Option.create_Some(token));
  for (const value of [token, ctx, store, EHBPEvents.Action.create_PublishToken(1, secret, secret)]) {
    const rendered = String(value);
    assert(rendered.includes('(<redacted>)') && !rendered.includes('171'), rendered);
  }
});
