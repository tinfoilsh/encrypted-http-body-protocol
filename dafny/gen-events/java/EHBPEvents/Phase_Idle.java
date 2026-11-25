// Class Phase_Idle
// Dafny class Phase_Idle compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Phase_Idle extends Phase {
  public Phase_Idle () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Phase_Idle o = (Phase_Idle)other;
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
    s.append("EHBPEvents.Phase.Idle");
    return s.toString();
  }
}
