// Class Disposition_PassThrough
// Dafny class Disposition_PassThrough compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Disposition_PassThrough extends Disposition {
  public Disposition_PassThrough () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Disposition_PassThrough o = (Disposition_PassThrough)other;
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
    s.append("EHBP.Disposition.PassThrough");
    return s.toString();
  }
}
