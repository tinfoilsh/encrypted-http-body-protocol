// Class Action_RandomBytes
// Dafny class Action_RandomBytes compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_RandomBytes extends Action {
  public java.math.BigInteger _length;
  public Action_RandomBytes (java.math.BigInteger length) {
    super();
    this._length = length;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_RandomBytes o = (Action_RandomBytes)other;
    return true && java.util.Objects.equals(this._length, o._length);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._length);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.RandomBytes");
    s.append("(");
    s.append(dafny.Helpers.toString(this._length));
    s.append(")");
    return s.toString();
  }
}
