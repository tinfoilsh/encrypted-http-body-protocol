// Class Event_SessionBegun
// Dafny class Event_SessionBegun compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_SessionBegun extends Event {
  public long _generation;
  public Event_SessionBegun (long generation) {
    super();
    this._generation = generation;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_SessionBegun o = (Event_SessionBegun)other;
    return true && this._generation == o._generation;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.lang.Long.hashCode(this._generation);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.SessionBegun");
    s.append("(");
    s.append(this._generation);
    s.append(")");
    return s.toString();
  }
}
