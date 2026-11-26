// Class Response_Body
// Dafny class Response_Body compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Response_Body extends Response {
  public Ctx _keys;
  public Dec _dec;
  public boolean _done;
  public Response_Body (Ctx keys, Dec dec, boolean done) {
    super();
    this._keys = keys;
    this._dec = dec;
    this._done = done;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Response_Body o = (Response_Body)other;
    return true && java.util.Objects.equals(this._keys, o._keys) && java.util.Objects.equals(this._dec, o._dec) && this._done == o._done;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._keys);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._dec);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._done);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Response.Body");
    s.append("(");
    s.append(dafny.Helpers.toString(this._keys));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._dec));
    s.append(", ");
    s.append(this._done);
    s.append(")");
    return s.toString();
  }
}
