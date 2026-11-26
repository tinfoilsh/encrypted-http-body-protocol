// Class Event_StreamFailed
// Dafny class Event_StreamFailed compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_StreamFailed extends Event {
  public Stream _stream;
  public Event_StreamFailed (Stream stream) {
    super();
    this._stream = stream;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_StreamFailed o = (Event_StreamFailed)other;
    return true && java.util.Objects.equals(this._stream, o._stream);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 10;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._stream);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.StreamFailed");
    s.append("(");
    s.append(dafny.Helpers.toString(this._stream));
    s.append(")");
    return s.toString();
  }
}
