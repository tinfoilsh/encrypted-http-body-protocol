// Class BodyEnd_Aborted
// Dafny class BodyEnd_Aborted compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class BodyEnd_Aborted extends BodyEnd {
  public EHBP.Code _code;
  public BodyEnd_Aborted (EHBP.Code code) {
    super();
    this._code = code;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    BodyEnd_Aborted o = (BodyEnd_Aborted)other;
    return true && java.util.Objects.equals(this._code, o._code);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._code);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.BodyEnd.Aborted");
    s.append("(");
    s.append(dafny.Helpers.toString(this._code));
    s.append(")");
    return s.toString();
  }
}
