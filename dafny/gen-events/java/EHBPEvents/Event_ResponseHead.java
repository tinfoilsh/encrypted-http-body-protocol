// Class Event_ResponseHead
// Dafny class Event_ResponseHead compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_ResponseHead extends Event {
  public java.math.BigInteger _status;
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _headers;
  public boolean _redirected;
  public Event_ResponseHead (java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean redirected) {
    super();
    this._status = status;
    this._headers = headers;
    this._redirected = redirected;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_ResponseHead o = (Event_ResponseHead)other;
    return true && java.util.Objects.equals(this._status, o._status) && java.util.Objects.equals(this._headers, o._headers) && this._redirected == o._redirected;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 8;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._status);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._headers);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._redirected);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.ResponseHead");
    s.append("(");
    s.append(dafny.Helpers.toString(this._status));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._headers));
    s.append(", ");
    s.append(this._redirected);
    s.append(")");
    return s.toString();
  }
}
