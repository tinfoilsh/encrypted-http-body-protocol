// Class Event_HmacResult
// Dafny class Event_HmacResult compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_HmacResult extends Event {
  public dafny.DafnySequence<? extends java.lang.Byte> _mac;
  public Event_HmacResult (dafny.DafnySequence<? extends java.lang.Byte> mac) {
    super();
    this._mac = mac;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_HmacResult o = (Event_HmacResult)other;
    return true && java.util.Objects.equals(this._mac, o._mac);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 5;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._mac);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.HmacResult(<redacted>)");
    return s.toString();
  }
}
