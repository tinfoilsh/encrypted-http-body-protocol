// Class Action_Close
// Dafny class Action_Close compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_Close extends Action {
  public Stream _stream;
  public Action_Close (Stream stream) {
    super();
    this._stream = stream;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_Close o = (Action_Close)other;
    return true && java.util.Objects.equals(this._stream, o._stream);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 11;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._stream);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.Close");
    s.append("(");
    s.append(dafny.Helpers.toString(this._stream));
    s.append(")");
    return s.toString();
  }
}
