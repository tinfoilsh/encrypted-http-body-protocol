// Class Ctx
// Dafny class Ctx compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Ctx {
  public dafny.DafnySequence<? extends java.lang.Byte> _key;
  public dafny.DafnySequence<? extends java.lang.Byte> _baseNonce;
  public dafny.DafnySequence<? extends java.lang.Byte> _exporterSecret;
  public long _seqNo;
  public Ctx (dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> baseNonce, dafny.DafnySequence<? extends java.lang.Byte> exporterSecret, long seqNo) {
    this._key = key;
    this._baseNonce = baseNonce;
    this._exporterSecret = exporterSecret;
    this._seqNo = seqNo;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Ctx o = (Ctx)other;
    return true && java.util.Objects.equals(this._key, o._key) && java.util.Objects.equals(this._baseNonce, o._baseNonce) && java.util.Objects.equals(this._exporterSecret, o._exporterSecret) && this._seqNo == o._seqNo;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._key);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._baseNonce);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._exporterSecret);
    hash = ((hash << 5) + hash) + java.lang.Long.hashCode(this._seqNo);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Ctx.Ctx(<redacted>)");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Ctx> _TYPE = dafny.TypeDescriptor.<Ctx>referenceWithInitializer(Ctx.class, () -> Ctx.Default());
  public static dafny.TypeDescriptor<Ctx> _typeDescriptor() {
    return (dafny.TypeDescriptor<Ctx>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Ctx theDefault = Ctx.create(Key.defaultValue(), NonceBase.defaultValue(), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), 0L);
  public static Ctx Default() {
    return theDefault;
  }
  public static Ctx create(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> baseNonce, dafny.DafnySequence<? extends java.lang.Byte> exporterSecret, long seqNo) {
    return new Ctx(key, baseNonce, exporterSecret, seqNo);
  }
  public static Ctx create_Ctx(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> baseNonce, dafny.DafnySequence<? extends java.lang.Byte> exporterSecret, long seqNo) {
    return create(key, baseNonce, exporterSecret, seqNo);
  }
  public boolean is_Ctx() { return true; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_key() {
    return this._key;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_baseNonce() {
    return this._baseNonce;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_exporterSecret() {
    return this._exporterSecret;
  }
  public long dtor_seqNo() {
    return this._seqNo;
  }
}
