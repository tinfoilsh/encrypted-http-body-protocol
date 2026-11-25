// Class Code_DuplicateResponseNonce
// Dafny class Code_DuplicateResponseNonce compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_DuplicateResponseNonce extends Code {
  public Code_DuplicateResponseNonce () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_DuplicateResponseNonce o = (Code_DuplicateResponseNonce)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 7;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.DuplicateResponseNonce");
    return s.toString();
  }
}
