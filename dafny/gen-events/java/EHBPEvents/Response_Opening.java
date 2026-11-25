// Class Response_Opening
// Dafny class Response_Opening compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Response_Opening extends Response {
  public Ctx _keys;
  public Dec _dec;
  public dafny.DafnySequence<? extends EHBP.Framed> _frames;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.lang.Byte>> _chunks;
  public boolean _eof;
  public Response_Opening (Ctx keys, Dec dec, dafny.DafnySequence<? extends EHBP.Framed> frames, dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.lang.Byte>> chunks, boolean eof) {
    super();
    this._keys = keys;
    this._dec = dec;
    this._frames = frames;
    this._chunks = chunks;
    this._eof = eof;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Response_Opening o = (Response_Opening)other;
    return true && java.util.Objects.equals(this._keys, o._keys) && java.util.Objects.equals(this._dec, o._dec) && java.util.Objects.equals(this._frames, o._frames) && java.util.Objects.equals(this._chunks, o._chunks) && this._eof == o._eof;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 5;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._keys);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._dec);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._frames);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._chunks);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._eof);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Response.Opening");
    s.append("(");
    s.append(dafny.Helpers.toString(this._keys));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._dec));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._frames));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._chunks));
    s.append(", ");
    s.append(this._eof);
    s.append(")");
    return s.toString();
  }
}
