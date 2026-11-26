// Class Response_AwaitKeys
// Dafny class Response_AwaitKeys compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Response_AwaitKeys extends Response {
  public java.math.BigInteger _status;
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _headers;
  public boolean _requireFrame;
  public java.math.BigInteger _stage;
  public Job _job;
  public dafny.DafnySequence<? extends java.lang.Byte> _prk;
  public dafny.DafnySequence<? extends java.lang.Byte> _key;
  public Response_AwaitKeys (java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean requireFrame, java.math.BigInteger stage, Job job, dafny.DafnySequence<? extends java.lang.Byte> prk, dafny.DafnySequence<? extends java.lang.Byte> key) {
    super();
    this._status = status;
    this._headers = headers;
    this._requireFrame = requireFrame;
    this._stage = stage;
    this._job = job;
    this._prk = prk;
    this._key = key;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Response_AwaitKeys o = (Response_AwaitKeys)other;
    return true && java.util.Objects.equals(this._status, o._status) && java.util.Objects.equals(this._headers, o._headers) && this._requireFrame == o._requireFrame && java.util.Objects.equals(this._stage, o._stage) && java.util.Objects.equals(this._job, o._job) && java.util.Objects.equals(this._prk, o._prk) && java.util.Objects.equals(this._key, o._key);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._status);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._headers);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._requireFrame);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._stage);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._job);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._prk);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._key);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Response.AwaitKeys(<redacted>)");
    return s.toString();
  }
}
