// Class Code_UnsupportedSuite
// Dafny class Code_UnsupportedSuite compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_UnsupportedSuite extends Code {
  public Code_UnsupportedSuite () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_UnsupportedSuite o = (Code_UnsupportedSuite)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.UnsupportedSuite");
    return s.toString();
  }
}
