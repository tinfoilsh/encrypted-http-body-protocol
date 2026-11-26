// Class Code_InvalidToken
// Dafny class Code_InvalidToken compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_InvalidToken extends Code {
  public Code_InvalidToken () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_InvalidToken o = (Code_InvalidToken)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 13;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.InvalidToken");
    return s.toString();
  }
}
