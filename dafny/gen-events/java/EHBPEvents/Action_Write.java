// Class Action_Write
// Dafny class Action_Write compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_Write extends Action {
  public dafny.DafnySequence<? extends java.lang.Byte> _data;
  public BodyEnd _end;
  public Action_Write (dafny.DafnySequence<? extends java.lang.Byte> data, BodyEnd end) {
    super();
    this._data = data;
    this._end = end;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_Write o = (Action_Write)other;
    return true && java.util.Objects.equals(this._data, o._data) && java.util.Objects.equals(this._end, o._end);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 9;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._data);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._end);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.Write");
    s.append("(");
    s.append(dafny.Helpers.toString(this._data));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._end));
    s.append(")");
    return s.toString();
  }
}
