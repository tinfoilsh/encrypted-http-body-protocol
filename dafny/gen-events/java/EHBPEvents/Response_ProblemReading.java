// Class Response_ProblemReading
// Dafny class Response_ProblemReading compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Response_ProblemReading extends Response {
  public java.math.BigInteger _status;
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _headers;
  public dafny.DafnySequence<? extends java.lang.Byte> _data;
  public Response_ProblemReading (java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, dafny.DafnySequence<? extends java.lang.Byte> data) {
    super();
    this._status = status;
    this._headers = headers;
    this._data = data;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Response_ProblemReading o = (Response_ProblemReading)other;
    return true && java.util.Objects.equals(this._status, o._status) && java.util.Objects.equals(this._headers, o._headers) && java.util.Objects.equals(this._data, o._data);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._status);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._headers);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._data);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Response.ProblemReading");
    s.append("(");
    s.append(dafny.Helpers.toString(this._status));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._headers));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._data));
    s.append(")");
    return s.toString();
  }
}
