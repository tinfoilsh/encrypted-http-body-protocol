// Class Event_DiscoverStart
// Dafny class Event_DiscoverStart compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_DiscoverStart extends Event {
  public Event_DiscoverStart () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_DiscoverStart o = (Event_DiscoverStart)other;
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
    s.append("EHBPEvents.Event.DiscoverStart");
    return s.toString();
  }
}
