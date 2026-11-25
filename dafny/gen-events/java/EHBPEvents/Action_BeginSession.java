// Class Action_BeginSession
// Dafny class Action_BeginSession compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_BeginSession extends Action {
  public Action_BeginSession () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_BeginSession o = (Action_BeginSession)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.BeginSession");
    return s.toString();
  }
}
