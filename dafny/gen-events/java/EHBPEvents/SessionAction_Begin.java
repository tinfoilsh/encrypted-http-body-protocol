// Class SessionAction_Begin
// Dafny class SessionAction_Begin compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class SessionAction_Begin extends SessionAction {
  public SessionAction_Begin () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    SessionAction_Begin o = (SessionAction_Begin)other;
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
    s.append("EHBPEvents.SessionAction.Begin");
    return s.toString();
  }
}
