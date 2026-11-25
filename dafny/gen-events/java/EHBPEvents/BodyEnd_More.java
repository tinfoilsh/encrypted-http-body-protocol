// Class BodyEnd_More
// Dafny class BodyEnd_More compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class BodyEnd_More extends BodyEnd {
  public BodyEnd_More () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    BodyEnd_More o = (BodyEnd_More)other;
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
    s.append("EHBPEvents.BodyEnd.More");
    return s.toString();
  }
}
