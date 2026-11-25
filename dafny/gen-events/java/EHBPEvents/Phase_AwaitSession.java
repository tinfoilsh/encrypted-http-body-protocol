// Class Phase_AwaitSession
// Dafny class Phase_AwaitSession compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Phase_AwaitSession extends Phase {
  public boolean _hasBody;
  public Phase_AwaitSession (boolean hasBody) {
    super();
    this._hasBody = hasBody;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Phase_AwaitSession o = (Phase_AwaitSession)other;
    return true && this._hasBody == o._hasBody;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._hasBody);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Phase.AwaitSession");
    s.append("(");
    s.append(this._hasBody);
    s.append(")");
    return s.toString();
  }
}
