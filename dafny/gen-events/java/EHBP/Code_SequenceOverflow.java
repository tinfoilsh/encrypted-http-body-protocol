// Class Code_SequenceOverflow
// Dafny class Code_SequenceOverflow compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_SequenceOverflow extends Code {
  public Code_SequenceOverflow () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_SequenceOverflow o = (Code_SequenceOverflow)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 12;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.SequenceOverflow");
    return s.toString();
  }
}
