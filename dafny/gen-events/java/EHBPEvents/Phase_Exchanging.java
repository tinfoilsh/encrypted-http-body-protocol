// Class Phase_Exchanging
// Dafny class Phase_Exchanging compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Phase_Exchanging extends Phase {
  public Upload _upload;
  public Response _response;
  public Phase_Exchanging (Upload upload, Response response) {
    super();
    this._upload = upload;
    this._response = response;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Phase_Exchanging o = (Phase_Exchanging)other;
    return true && java.util.Objects.equals(this._upload, o._upload) && java.util.Objects.equals(this._response, o._response);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 5;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._upload);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._response);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Phase.Exchanging");
    s.append("(");
    s.append(dafny.Helpers.toString(this._upload));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._response));
    s.append(")");
    return s.toString();
  }
}
