// Class Event_AeadOpenResult
// Dafny class Event_AeadOpenResult compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_AeadOpenResult extends Event {
  public boolean _ok;
  public dafny.DafnySequence<? extends java.lang.Byte> _plaintext;
  public Event_AeadOpenResult (boolean ok, dafny.DafnySequence<? extends java.lang.Byte> plaintext) {
    super();
    this._ok = ok;
    this._plaintext = plaintext;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_AeadOpenResult o = (Event_AeadOpenResult)other;
    return true && this._ok == o._ok && java.util.Objects.equals(this._plaintext, o._plaintext);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 7;
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._ok);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._plaintext);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.AeadOpenResult");
    s.append("(");
    s.append(this._ok);
    s.append(", ");
    s.append(dafny.Helpers.toString(this._plaintext));
    s.append(")");
    return s.toString();
  }
}
