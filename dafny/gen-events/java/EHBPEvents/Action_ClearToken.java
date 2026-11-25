// Class Action_ClearToken
// Dafny class Action_ClearToken compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_ClearToken extends Action {
  public long _generation;
  public Action_ClearToken (long generation) {
    super();
    this._generation = generation;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_ClearToken o = (Action_ClearToken)other;
    return true && this._generation == o._generation;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.lang.Long.hashCode(this._generation);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.ClearToken");
    s.append("(");
    s.append(this._generation);
    s.append(")");
    return s.toString();
  }
}
