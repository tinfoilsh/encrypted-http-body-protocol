// Class Event_AeadSealResult
// Dafny class Event_AeadSealResult compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_AeadSealResult extends Event {
  public dafny.DafnySequence<? extends java.lang.Byte> _ciphertext;
  public Event_AeadSealResult (dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    super();
    this._ciphertext = ciphertext;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_AeadSealResult o = (Event_AeadSealResult)other;
    return true && java.util.Objects.equals(this._ciphertext, o._ciphertext);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 6;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ciphertext);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.AeadSealResult");
    s.append("(");
    s.append(dafny.Helpers.toString(this._ciphertext));
    s.append(")");
    return s.toString();
  }
}
