// Class Code_AeadDecryptFailed
// Dafny class Code_AeadDecryptFailed compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_AeadDecryptFailed extends Code {
  public Code_AeadDecryptFailed () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_AeadDecryptFailed o = (Code_AeadDecryptFailed)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 11;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.AeadDecryptFailed");
    return s.toString();
  }
}
