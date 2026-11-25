// Class Action_AeadSeal
// Dafny class Action_AeadSeal compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_AeadSeal extends Action {
  public dafny.DafnySequence<? extends java.lang.Byte> _key;
  public dafny.DafnySequence<? extends java.lang.Byte> _nonce;
  public dafny.DafnySequence<? extends java.lang.Byte> _plaintext;
  public Action_AeadSeal (dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> nonce, dafny.DafnySequence<? extends java.lang.Byte> plaintext) {
    super();
    this._key = key;
    this._nonce = nonce;
    this._plaintext = plaintext;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_AeadSeal o = (Action_AeadSeal)other;
    return true && java.util.Objects.equals(this._key, o._key) && java.util.Objects.equals(this._nonce, o._nonce) && java.util.Objects.equals(this._plaintext, o._plaintext);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 6;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._key);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._nonce);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._plaintext);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.AeadSeal(<redacted>)");
    return s.toString();
  }
}
