// Class Event_CallerRead
// Dafny class Event_CallerRead compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_CallerRead extends Event {
  public Event_CallerRead () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_CallerRead o = (Event_CallerRead)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 11;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.CallerRead");
    return s.toString();
  }
}
