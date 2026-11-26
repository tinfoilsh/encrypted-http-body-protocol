// Class SessionAction_Publish
// Dafny class SessionAction_Publish compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class SessionAction_Publish extends SessionAction {
  public long _generation;
  public EHBP.Token _token;
  public SessionAction_Publish (long generation, EHBP.Token token) {
    super();
    this._generation = generation;
    this._token = token;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    SessionAction_Publish o = (SessionAction_Publish)other;
    return true && this._generation == o._generation && java.util.Objects.equals(this._token, o._token);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.lang.Long.hashCode(this._generation);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._token);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.SessionAction.Publish");
    s.append("(");
    s.append(this._generation);
    s.append(", ");
    s.append(dafny.Helpers.toString(this._token));
    s.append(")");
    return s.toString();
  }
}
