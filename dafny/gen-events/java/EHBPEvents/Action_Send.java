// Class Action_Send
// Dafny class Action_Send compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_Send extends Action {
  public dafny.DafnySequence<? extends dafny.CodePoint> _verb;
  public dafny.DafnySequence<? extends dafny.CodePoint> _url;
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _headers;
  public boolean _hasBody;
  public Action_Send (dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> url, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean hasBody) {
    super();
    this._verb = verb;
    this._url = url;
    this._headers = headers;
    this._hasBody = hasBody;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_Send o = (Action_Send)other;
    return true && java.util.Objects.equals(this._verb, o._verb) && java.util.Objects.equals(this._url, o._url) && java.util.Objects.equals(this._headers, o._headers) && this._hasBody == o._hasBody;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 8;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verb);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._url);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._headers);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._hasBody);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.Send");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._verb));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._url));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._headers));
    s.append(", ");
    s.append(this._hasBody);
    s.append(")");
    return s.toString();
  }
}
