// Class SessionAction_Clear
// Dafny class SessionAction_Clear compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class SessionAction_Clear extends SessionAction {
  public long _generation;
  public SessionAction_Clear (long generation) {
    super();
    this._generation = generation;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    SessionAction_Clear o = (SessionAction_Clear)other;
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
    s.append("EHBPEvents.SessionAction.Clear");
    s.append("(");
    s.append(this._generation);
    s.append(")");
    return s.toString();
  }
}
