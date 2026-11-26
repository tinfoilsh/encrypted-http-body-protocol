// Class Action_Read
// Dafny class Action_Read compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_Read extends Action {
  public Stream _stream;
  public Action_Read (Stream stream) {
    super();
    this._stream = stream;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_Read o = (Action_Read)other;
    return true && java.util.Objects.equals(this._stream, o._stream);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 10;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._stream);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.Read");
    s.append("(");
    s.append(dafny.Helpers.toString(this._stream));
    s.append(")");
    return s.toString();
  }
}
