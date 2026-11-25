// Class Performed_Stop
// Dafny class Performed_Stop compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Performed_Stop extends Performed {
  public Performed_Stop () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Performed_Stop o = (Performed_Stop)other;
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
    s.append("EHBPEvents.Performed.Stop");
    return s.toString();
  }
}
