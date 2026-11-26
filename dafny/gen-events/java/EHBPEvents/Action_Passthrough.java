// Class Action_Passthrough
// Dafny class Action_Passthrough compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_Passthrough extends Action {
  public java.math.BigInteger _status;
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _headers;
  public dafny.DafnySequence<? extends java.lang.Byte> _prefix;
  public Action_Passthrough (java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, dafny.DafnySequence<? extends java.lang.Byte> prefix) {
    super();
    this._status = status;
    this._headers = headers;
    this._prefix = prefix;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_Passthrough o = (Action_Passthrough)other;
    return true && java.util.Objects.equals(this._status, o._status) && java.util.Objects.equals(this._headers, o._headers) && java.util.Objects.equals(this._prefix, o._prefix);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 13;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._status);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._headers);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._prefix);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.Passthrough");
    s.append("(");
    s.append(dafny.Helpers.toString(this._status));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._headers));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._prefix));
    s.append(")");
    return s.toString();
  }
}
