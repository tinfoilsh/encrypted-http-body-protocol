// Class Code_FramingTruncated
// Dafny class Code_FramingTruncated compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_FramingTruncated extends Code {
  public Code_FramingTruncated () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_FramingTruncated o = (Code_FramingTruncated)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 9;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.FramingTruncated");
    return s.toString();
  }
}
