// Class Disposition_NeedProblemBody
// Dafny class Disposition_NeedProblemBody compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Disposition_NeedProblemBody extends Disposition {
  public Disposition_NeedProblemBody () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Disposition_NeedProblemBody o = (Disposition_NeedProblemBody)other;
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
    s.append("EHBP.Disposition.NeedProblemBody");
    return s.toString();
  }
}
