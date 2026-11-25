// Class Performed_Quiet
// Dafny class Performed_Quiet compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Performed_Quiet extends Performed {
  public Performed_Quiet () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Performed_Quiet o = (Performed_Quiet)other;
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
    s.append("EHBPEvents.Performed.Quiet");
    return s.toString();
  }
}
