// Class Code_ChunkTooLarge
// Dafny class Code_ChunkTooLarge compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Code_ChunkTooLarge extends Code {
  public Code_ChunkTooLarge () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Code_ChunkTooLarge o = (Code_ChunkTooLarge)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 10;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Code.ChunkTooLarge");
    return s.toString();
  }
}
