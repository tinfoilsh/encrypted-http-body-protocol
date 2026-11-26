// Class Response_AwaitHead
// Dafny class Response_AwaitHead compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Response_AwaitHead extends Response {
  public boolean _encrypted;
  public Response_AwaitHead (boolean encrypted) {
    super();
    this._encrypted = encrypted;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Response_AwaitHead o = (Response_AwaitHead)other;
    return true && this._encrypted == o._encrypted;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._encrypted);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Response.AwaitHead");
    s.append("(");
    s.append(this._encrypted);
    s.append(")");
    return s.toString();
  }
}
