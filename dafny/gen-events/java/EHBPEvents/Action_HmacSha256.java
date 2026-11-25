// Class Action_HmacSha256
// Dafny class Action_HmacSha256 compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_HmacSha256 extends Action {
  public dafny.DafnySequence<? extends java.lang.Byte> _key;
  public dafny.DafnySequence<? extends java.lang.Byte> _data;
  public Action_HmacSha256 (dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> data) {
    super();
    this._key = key;
    this._data = data;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_HmacSha256 o = (Action_HmacSha256)other;
    return true && java.util.Objects.equals(this._key, o._key) && java.util.Objects.equals(this._data, o._data);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 5;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._key);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._data);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.HmacSha256(<redacted>)");
    return s.toString();
  }
}
