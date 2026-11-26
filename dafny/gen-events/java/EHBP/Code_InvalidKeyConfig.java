// Class Code_InvalidKeyConfig
// Dafny class Code_InvalidKeyConfig compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_InvalidKeyConfig extends Code {
  public Code_InvalidKeyConfig () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_InvalidKeyConfig o = (Code_InvalidKeyConfig)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.InvalidKeyConfig");
    return s.toString();
  }
}
