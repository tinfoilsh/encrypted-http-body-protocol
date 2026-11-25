// Class BodyEnd_Done
// Dafny class BodyEnd_Done compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class BodyEnd_Done extends BodyEnd {
  public BodyEnd_Done () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    BodyEnd_Done o = (BodyEnd_Done)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.BodyEnd.Done");
    return s.toString();
  }
}
