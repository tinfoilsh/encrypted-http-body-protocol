// Class Action_AeadOpen
// Dafny class Action_AeadOpen compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_AeadOpen extends Action {
  public dafny.DafnySequence<? extends java.lang.Byte> _key;
  public dafny.DafnySequence<? extends java.lang.Byte> _nonce;
  public dafny.DafnySequence<? extends java.lang.Byte> _ciphertext;
  public Action_AeadOpen (dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> nonce, dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    super();
    this._key = key;
    this._nonce = nonce;
    this._ciphertext = ciphertext;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_AeadOpen o = (Action_AeadOpen)other;
    return true && java.util.Objects.equals(this._key, o._key) && java.util.Objects.equals(this._nonce, o._nonce) && java.util.Objects.equals(this._ciphertext, o._ciphertext);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 7;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._key);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._nonce);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ciphertext);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.AeadOpen(<redacted>)");
    return s.toString();
  }
}
