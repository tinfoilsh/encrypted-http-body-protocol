// Class Code_HpkeSetupFailed
// Dafny class Code_HpkeSetupFailed compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_HpkeSetupFailed extends Code {
  public Code_HpkeSetupFailed () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_HpkeSetupFailed o = (Code_HpkeSetupFailed)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.HpkeSetupFailed");
    return s.toString();
  }
}
