// Class Phase_Ended
// Dafny class Phase_Ended compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Phase_Ended extends Phase {
  public Phase_Ended () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Phase_Ended o = (Phase_Ended)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 8;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Phase.Ended");
    return s.toString();
  }
}
