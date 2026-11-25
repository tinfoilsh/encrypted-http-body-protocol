// Class Event_RandomResult
// Dafny class Event_RandomResult compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_RandomResult extends Event {
  public dafny.DafnySequence<? extends java.lang.Byte> _data;
  public Event_RandomResult (dafny.DafnySequence<? extends java.lang.Byte> data) {
    super();
    this._data = data;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_RandomResult o = (Event_RandomResult)other;
    return true && java.util.Objects.equals(this._data, o._data);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._data);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.RandomResult(<redacted>)");
    return s.toString();
  }
}
