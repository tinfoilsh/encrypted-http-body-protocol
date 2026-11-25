// Class Code_Transport
// Dafny class Code_Transport compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_Transport extends Code {
  public Code_Transport () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_Transport o = (Code_Transport)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 15;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.Transport");
    return s.toString();
  }
}
