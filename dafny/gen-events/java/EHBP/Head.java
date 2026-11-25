// Class Head
// Dafny class Head compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Head {
  public java.math.BigInteger _status;
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _headers;
  public boolean _redirected;
  public Head (java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean redirected) {
    this._status = status;
    this._headers = headers;
    this._redirected = redirected;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Head o = (Head)other;
    return true && java.util.Objects.equals(this._status, o._status) && java.util.Objects.equals(this._headers, o._headers) && this._redirected == o._redirected;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._status);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._headers);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._redirected);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Head.Head");
    s.append("(");
    s.append(dafny.Helpers.toString(this._status));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._headers));
    s.append(", ");
    s.append(this._redirected);
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Head> _TYPE = dafny.TypeDescriptor.<Head>referenceWithInitializer(Head.class, () -> Head.Default());
  public static dafny.TypeDescriptor<Head> _typeDescriptor() {
    return (dafny.TypeDescriptor<Head>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Head theDefault = Head.create(java.math.BigInteger.ZERO, dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> empty(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))), false);
  public static Head Default() {
    return theDefault;
  }
  public static Head create(java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean redirected) {
    return new Head(status, headers, redirected);
  }
  public static Head create_Head(java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean redirected) {
    return create(status, headers, redirected);
  }
  public boolean is_Head() { return true; }
  public java.math.BigInteger dtor_status() {
    return this._status;
  }
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> dtor_headers() {
    return this._headers;
  }
  public boolean dtor_redirected() {
    return this._redirected;
  }
}
