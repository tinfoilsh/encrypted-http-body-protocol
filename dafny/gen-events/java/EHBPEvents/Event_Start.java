// Class Event_Start
// Dafny class Event_Start compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_Start extends Event {
  public dafny.DafnySequence<? extends dafny.CodePoint> _verb;
  public dafny.DafnySequence<? extends dafny.CodePoint> _url;
  public dafny.DafnySequence<? extends dafny.CodePoint> _scheme;
  public dafny.DafnySequence<? extends dafny.CodePoint> _host;
  public java.math.BigInteger _port;
  public boolean _hasPort;
  public boolean _hasUserinfo;
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _headers;
  public boolean _hasBody;
  public Event_Start (dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> url, dafny.DafnySequence<? extends dafny.CodePoint> scheme, dafny.DafnySequence<? extends dafny.CodePoint> host, java.math.BigInteger port, boolean hasPort, boolean hasUserinfo, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean hasBody) {
    super();
    this._verb = verb;
    this._url = url;
    this._scheme = scheme;
    this._host = host;
    this._port = port;
    this._hasPort = hasPort;
    this._hasUserinfo = hasUserinfo;
    this._headers = headers;
    this._hasBody = hasBody;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_Start o = (Event_Start)other;
    return true && java.util.Objects.equals(this._verb, o._verb) && java.util.Objects.equals(this._url, o._url) && java.util.Objects.equals(this._scheme, o._scheme) && java.util.Objects.equals(this._host, o._host) && java.util.Objects.equals(this._port, o._port) && this._hasPort == o._hasPort && this._hasUserinfo == o._hasUserinfo && java.util.Objects.equals(this._headers, o._headers) && this._hasBody == o._hasBody;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verb);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._url);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._scheme);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._host);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._port);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._hasPort);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._hasUserinfo);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._headers);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._hasBody);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.Start");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._verb));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._url));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._scheme));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._host));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._port));
    s.append(", ");
    s.append(this._hasPort);
    s.append(", ");
    s.append(this._hasUserinfo);
    s.append(", ");
    s.append(dafny.Helpers.toString(this._headers));
    s.append(", ");
    s.append(this._hasBody);
    s.append(")");
    return s.toString();
  }
}
