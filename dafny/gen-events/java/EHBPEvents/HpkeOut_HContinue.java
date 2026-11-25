// Class HpkeOut_HContinue
// Dafny class HpkeOut_HContinue compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class HpkeOut_HContinue extends HpkeOut {
  public Hpke _h;
  public Action _action;
  public HpkeOut_HContinue (Hpke h, Action action) {
    super();
    this._h = h;
    this._action = action;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    HpkeOut_HContinue o = (HpkeOut_HContinue)other;
    return true && java.util.Objects.equals(this._h, o._h) && java.util.Objects.equals(this._action, o._action);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._h);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._action);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.HpkeOut.HContinue");
    s.append("(");
    s.append(dafny.Helpers.toString(this._h));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._action));
    s.append(")");
    return s.toString();
  }
}
