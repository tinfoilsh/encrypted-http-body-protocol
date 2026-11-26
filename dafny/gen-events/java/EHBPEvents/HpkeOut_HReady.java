// Class HpkeOut_HReady
// Dafny class HpkeOut_HReady compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class HpkeOut_HReady extends HpkeOut {
  public Ctx _ctx;
  public dafny.DafnySequence<? extends java.lang.Byte> _enc;
  public HpkeOut_HReady (Ctx ctx, dafny.DafnySequence<? extends java.lang.Byte> enc) {
    super();
    this._ctx = ctx;
    this._enc = enc;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    HpkeOut_HReady o = (HpkeOut_HReady)other;
    return true && java.util.Objects.equals(this._ctx, o._ctx) && java.util.Objects.equals(this._enc, o._enc);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ctx);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._enc);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.HpkeOut.HReady");
    s.append("(");
    s.append(dafny.Helpers.toString(this._ctx));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._enc));
    s.append(")");
    return s.toString();
  }
}
