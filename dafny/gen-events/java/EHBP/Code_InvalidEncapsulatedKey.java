// Class Code_InvalidEncapsulatedKey
// Dafny class Code_InvalidEncapsulatedKey compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_InvalidEncapsulatedKey extends Code {
  public Code_InvalidEncapsulatedKey () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_InvalidEncapsulatedKey o = (Code_InvalidEncapsulatedKey)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.InvalidEncapsulatedKey");
    return s.toString();
  }
}
