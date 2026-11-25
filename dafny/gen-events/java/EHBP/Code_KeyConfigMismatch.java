// Class Code_KeyConfigMismatch
// Dafny class Code_KeyConfigMismatch compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_KeyConfigMismatch extends Code {
  public Code_KeyConfigMismatch () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_KeyConfigMismatch o = (Code_KeyConfigMismatch)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 8;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.KeyConfigMismatch");
    return s.toString();
  }
}
