// Class Response_RespEnded
// Dafny class Response_RespEnded compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Response_RespEnded extends Response {
  public Response_RespEnded () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Response_RespEnded o = (Response_RespEnded)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 6;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Response.RespEnded");
    return s.toString();
  }
}
