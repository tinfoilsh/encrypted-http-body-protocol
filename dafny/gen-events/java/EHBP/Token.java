// Class Token
// Dafny class Token compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Token {
  public dafny.DafnySequence<? extends java.lang.Byte> _exportedSecret;
  public dafny.DafnySequence<? extends java.lang.Byte> _requestEnc;
  public Token (dafny.DafnySequence<? extends java.lang.Byte> exportedSecret, dafny.DafnySequence<? extends java.lang.Byte> requestEnc) {
    this._exportedSecret = exportedSecret;
    this._requestEnc = requestEnc;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Token o = (Token)other;
    return true && java.util.Objects.equals(this._exportedSecret, o._exportedSecret) && java.util.Objects.equals(this._requestEnc, o._requestEnc);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._exportedSecret);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._requestEnc);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Token.Token(<redacted>)");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Token> _TYPE = dafny.TypeDescriptor.<Token>referenceWithInitializer(Token.class, () -> Token.Default());
  public static dafny.TypeDescriptor<Token> _typeDescriptor() {
    return (dafny.TypeDescriptor<Token>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Token theDefault = Token.create(dafny.DafnySequence.<java.lang.Byte> empty(uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(uint8._typeDescriptor()));
  public static Token Default() {
    return theDefault;
  }
  public static Token create(dafny.DafnySequence<? extends java.lang.Byte> exportedSecret, dafny.DafnySequence<? extends java.lang.Byte> requestEnc) {
    return new Token(exportedSecret, requestEnc);
  }
  public static Token create_Token(dafny.DafnySequence<? extends java.lang.Byte> exportedSecret, dafny.DafnySequence<? extends java.lang.Byte> requestEnc) {
    return create(exportedSecret, requestEnc);
  }
  public boolean is_Token() { return true; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_exportedSecret() {
    return this._exportedSecret;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_requestEnc() {
    return this._requestEnc;
  }
}
