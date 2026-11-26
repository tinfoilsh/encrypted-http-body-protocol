// Class Action_Done
// Dafny class Action_Done compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_Done extends Action {
  public java.math.BigInteger _status;
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _headers;
  public Action_Done (java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers) {
    super();
    this._status = status;
    this._headers = headers;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_Done o = (Action_Done)other;
    return true && java.util.Objects.equals(this._status, o._status) && java.util.Objects.equals(this._headers, o._headers);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 14;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._status);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._headers);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.Done");
    s.append("(");
    s.append(dafny.Helpers.toString(this._status));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._headers));
    s.append(")");
    return s.toString();
  }
}
