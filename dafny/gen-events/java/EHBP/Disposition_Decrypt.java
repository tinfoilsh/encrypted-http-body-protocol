// Class Disposition_Decrypt
// Dafny class Disposition_Decrypt compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Disposition_Decrypt extends Disposition {
  public dafny.DafnySequence<? extends java.lang.Byte> _nonce;
  public boolean _requireFrame;
  public Disposition_Decrypt (dafny.DafnySequence<? extends java.lang.Byte> nonce, boolean requireFrame) {
    super();
    this._nonce = nonce;
    this._requireFrame = requireFrame;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Disposition_Decrypt o = (Disposition_Decrypt)other;
    return true && java.util.Objects.equals(this._nonce, o._nonce) && this._requireFrame == o._requireFrame;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._nonce);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._requireFrame);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Disposition.Decrypt");
    s.append("(");
    s.append(dafny.Helpers.toString(this._nonce));
    s.append(", ");
    s.append(this._requireFrame);
    s.append(")");
    return s.toString();
  }
}
