// Class Code_MissingResponseNonce
// Dafny class Code_MissingResponseNonce compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_MissingResponseNonce extends Code {
  public Code_MissingResponseNonce () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_MissingResponseNonce o = (Code_MissingResponseNonce)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 4;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.MissingResponseNonce");
    return s.toString();
  }
}
