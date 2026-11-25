// Class Action_EmitPlaintext
// Dafny class Action_EmitPlaintext compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_EmitPlaintext extends Action {
  public dafny.DafnySequence<? extends java.lang.Byte> _data;
  public Action_EmitPlaintext (dafny.DafnySequence<? extends java.lang.Byte> data) {
    super();
    this._data = data;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_EmitPlaintext o = (Action_EmitPlaintext)other;
    return true && java.util.Objects.equals(this._data, o._data);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 12;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._data);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.EmitPlaintext");
    s.append("(");
    s.append(dafny.Helpers.toString(this._data));
    s.append(")");
    return s.toString();
  }
}
