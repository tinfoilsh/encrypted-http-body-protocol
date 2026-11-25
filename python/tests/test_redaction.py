"""The generated printers of the secret-bearing datatypes are redacted by
dafny/patch-runtime.py (SECRET_TYPES): rendering a token, a context or a
value holding one must not expose key material."""

from ehbp._gen import EHBP, EHBPEvents, _dafny


def test_generated_printers_redact_secrets():
    secret = _dafny.Seq(bytes([0xAB]) * 32)
    token = EHBP.Token_Token(secret, secret)
    ctx = EHBPEvents.Ctx_Ctx(secret, _dafny.Seq(bytes(12)), secret, 0)
    store = EHBPEvents.SessionStore_SessionStore(1, EHBP.Option_Some(token))
    for value in (token, ctx, store, EHBPEvents.Action_PublishToken(1, secret, secret)):
        for rendered in (str(value), repr(value), _dafny.string_of(value)):
            assert "(<redacted>)" in rendered and "171" not in rendered, rendered
