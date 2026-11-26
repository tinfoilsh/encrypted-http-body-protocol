// Class Dec
// Dafny class Dec compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Dec {
  public dafny.DafnySequence<? extends java.lang.Byte> _pending;
  public long _next;
  public boolean _authenticated;
  public boolean _requireFrame;
  public Dec (dafny.DafnySequence<? extends java.lang.Byte> pending, long next, boolean authenticated, boolean requireFrame) {
    this._pending = pending;
    this._next = next;
    this._authenticated = authenticated;
    this._requireFrame = requireFrame;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Dec o = (Dec)other;
    return true && java.util.Objects.equals(this._pending, o._pending) && this._next == o._next && this._authenticated == o._authenticated && this._requireFrame == o._requireFrame;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._pending);
    hash = ((hash << 5) + hash) + java.lang.Long.hashCode(this._next);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._authenticated);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._requireFrame);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Dec.Dec");
    s.append("(");
    s.append(dafny.Helpers.toString(this._pending));
    s.append(", ");
    s.append(this._next);
    s.append(", ");
    s.append(this._authenticated);
    s.append(", ");
    s.append(this._requireFrame);
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Dec> _TYPE = dafny.TypeDescriptor.<Dec>referenceWithInitializer(Dec.class, () -> Dec.Default());
  public static dafny.TypeDescriptor<Dec> _typeDescriptor() {
    return (dafny.TypeDescriptor<Dec>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Dec theDefault = Dec.create(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), 0L, false, false);
  public static Dec Default() {
    return theDefault;
  }
  public static Dec create(dafny.DafnySequence<? extends java.lang.Byte> pending, long next, boolean authenticated, boolean requireFrame) {
    return new Dec(pending, next, authenticated, requireFrame);
  }
  public static Dec create_Dec(dafny.DafnySequence<? extends java.lang.Byte> pending, long next, boolean authenticated, boolean requireFrame) {
    return create(pending, next, authenticated, requireFrame);
  }
  public boolean is_Dec() { return true; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_pending() {
    return this._pending;
  }
  public long dtor_next() {
    return this._next;
  }
  public boolean dtor_authenticated() {
    return this._authenticated;
  }
  public boolean dtor_requireFrame() {
    return this._requireFrame;
  }
}
