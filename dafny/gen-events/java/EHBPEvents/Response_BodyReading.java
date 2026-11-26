// Class Response_BodyReading
// Dafny class Response_BodyReading compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Response_BodyReading extends Response {
  public Ctx _keys;
  public Dec _dec;
  public Response_BodyReading (Ctx keys, Dec dec) {
    super();
    this._keys = keys;
    this._dec = dec;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Response_BodyReading o = (Response_BodyReading)other;
    return true && java.util.Objects.equals(this._keys, o._keys) && java.util.Objects.equals(this._dec, o._dec);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 4;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._keys);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._dec);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Response.BodyReading");
    s.append("(");
    s.append(dafny.Helpers.toString(this._keys));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._dec));
    s.append(")");
    return s.toString();
  }
}
