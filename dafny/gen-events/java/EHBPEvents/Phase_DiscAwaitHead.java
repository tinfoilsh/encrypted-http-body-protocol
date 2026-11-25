// Class Phase_DiscAwaitHead
// Dafny class Phase_DiscAwaitHead compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Phase_DiscAwaitHead extends Phase {
  public Phase_DiscAwaitHead () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Phase_DiscAwaitHead o = (Phase_DiscAwaitHead)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 6;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Phase.DiscAwaitHead");
    return s.toString();
  }
}
