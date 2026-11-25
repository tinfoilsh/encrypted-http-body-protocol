// Class Code_InvalidInput
// Dafny class Code_InvalidInput compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_InvalidInput extends Code {
  public Code_InvalidInput () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_InvalidInput o = (Code_InvalidInput)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 14;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.InvalidInput");
    return s.toString();
  }
}
