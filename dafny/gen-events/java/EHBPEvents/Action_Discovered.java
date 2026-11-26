// Class Action_Discovered
// Dafny class Action_Discovered compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_Discovered extends Action {
  public dafny.DafnySequence<? extends java.lang.Byte> _publicKey;
  public Action_Discovered (dafny.DafnySequence<? extends java.lang.Byte> publicKey) {
    super();
    this._publicKey = publicKey;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_Discovered o = (Action_Discovered)other;
    return true && java.util.Objects.equals(this._publicKey, o._publicKey);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 16;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._publicKey);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.Discovered");
    s.append("(");
    s.append(dafny.Helpers.toString(this._publicKey));
    s.append(")");
    return s.toString();
  }
}
