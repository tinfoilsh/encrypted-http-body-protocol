// Class Action_X25519
// Dafny class Action_X25519 compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_X25519 extends Action {
  public dafny.DafnySequence<? extends java.lang.Byte> _scalar;
  public dafny.DafnySequence<? extends java.lang.Byte> _point;
  public Action_X25519 (dafny.DafnySequence<? extends java.lang.Byte> scalar, dafny.DafnySequence<? extends java.lang.Byte> point) {
    super();
    this._scalar = scalar;
    this._point = point;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_X25519 o = (Action_X25519)other;
    return true && java.util.Objects.equals(this._scalar, o._scalar) && java.util.Objects.equals(this._point, o._point);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 4;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._scalar);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._point);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.X25519(<redacted>)");
    return s.toString();
  }
}
