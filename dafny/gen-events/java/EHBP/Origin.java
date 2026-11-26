// Class Origin
// Dafny class Origin compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Origin {
  public dafny.DafnySequence<? extends dafny.CodePoint> _scheme;
  public dafny.DafnySequence<? extends dafny.CodePoint> _host;
  public java.math.BigInteger _port;
  public Origin (dafny.DafnySequence<? extends dafny.CodePoint> scheme, dafny.DafnySequence<? extends dafny.CodePoint> host, java.math.BigInteger port) {
    this._scheme = scheme;
    this._host = host;
    this._port = port;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Origin o = (Origin)other;
    return true && java.util.Objects.equals(this._scheme, o._scheme) && java.util.Objects.equals(this._host, o._host) && java.util.Objects.equals(this._port, o._port);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._scheme);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._host);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._port);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Origin.Origin");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._scheme));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._host));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._port));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Origin> _TYPE = dafny.TypeDescriptor.<Origin>referenceWithInitializer(Origin.class, () -> Origin.Default());
  public static dafny.TypeDescriptor<Origin> _typeDescriptor() {
    return (dafny.TypeDescriptor<Origin>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Origin theDefault = Origin.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), java.math.BigInteger.ZERO);
  public static Origin Default() {
    return theDefault;
  }
  public static Origin create(dafny.DafnySequence<? extends dafny.CodePoint> scheme, dafny.DafnySequence<? extends dafny.CodePoint> host, java.math.BigInteger port) {
    return new Origin(scheme, host, port);
  }
  public static Origin create_Origin(dafny.DafnySequence<? extends dafny.CodePoint> scheme, dafny.DafnySequence<? extends dafny.CodePoint> host, java.math.BigInteger port) {
    return create(scheme, host, port);
  }
  public boolean is_Origin() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_scheme() {
    return this._scheme;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_host() {
    return this._host;
  }
  public java.math.BigInteger dtor_port() {
    return this._port;
  }
}
