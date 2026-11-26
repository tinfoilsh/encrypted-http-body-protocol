// Class Event_X25519Result
// Dafny class Event_X25519Result compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_X25519Result extends Event {
  public dafny.DafnySequence<? extends java.lang.Byte> _point;
  public Event_X25519Result (dafny.DafnySequence<? extends java.lang.Byte> point) {
    super();
    this._point = point;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_X25519Result o = (Event_X25519Result)other;
    return true && java.util.Objects.equals(this._point, o._point);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 4;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._point);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.X25519Result(<redacted>)");
    return s.toString();
  }
}
