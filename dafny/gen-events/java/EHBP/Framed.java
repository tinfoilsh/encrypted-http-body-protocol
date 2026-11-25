// Class Framed
// Dafny class Framed compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Framed {
  public long _seqNo;
  public dafny.DafnySequence<? extends java.lang.Byte> _ciphertext;
  public Framed (long seqNo, dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    this._seqNo = seqNo;
    this._ciphertext = ciphertext;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Framed o = (Framed)other;
    return true && this._seqNo == o._seqNo && java.util.Objects.equals(this._ciphertext, o._ciphertext);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.lang.Long.hashCode(this._seqNo);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ciphertext);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Framed.Framed");
    s.append("(");
    s.append(this._seqNo);
    s.append(", ");
    s.append(dafny.Helpers.toString(this._ciphertext));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Framed> _TYPE = dafny.TypeDescriptor.<Framed>referenceWithInitializer(Framed.class, () -> Framed.Default());
  public static dafny.TypeDescriptor<Framed> _typeDescriptor() {
    return (dafny.TypeDescriptor<Framed>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Framed theDefault = Framed.create(0L, dafny.DafnySequence.<java.lang.Byte> empty(uint8._typeDescriptor()));
  public static Framed Default() {
    return theDefault;
  }
  public static Framed create(long seqNo, dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    return new Framed(seqNo, ciphertext);
  }
  public static Framed create_Framed(long seqNo, dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    return create(seqNo, ciphertext);
  }
  public boolean is_Framed() { return true; }
  public long dtor_seqNo() {
    return this._seqNo;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_ciphertext() {
    return this._ciphertext;
  }
}
