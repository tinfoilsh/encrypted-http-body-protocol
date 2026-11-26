// Class Hpke_HDh
// Dafny class Hpke_HDh compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Hpke_HDh extends Hpke {
  public dafny.DafnySequence<? extends java.lang.Byte> _enc;
  public dafny.DafnySequence<? extends java.lang.Byte> _pkR;
  public dafny.DafnySequence<? extends java.lang.Byte> _info;
  public Hpke_HDh (dafny.DafnySequence<? extends java.lang.Byte> enc, dafny.DafnySequence<? extends java.lang.Byte> pkR, dafny.DafnySequence<? extends java.lang.Byte> info) {
    super();
    this._enc = enc;
    this._pkR = pkR;
    this._info = info;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Hpke_HDh o = (Hpke_HDh)other;
    return true && java.util.Objects.equals(this._enc, o._enc) && java.util.Objects.equals(this._pkR, o._pkR) && java.util.Objects.equals(this._info, o._info);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._enc);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._pkR);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._info);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Hpke.HDh");
    s.append("(");
    s.append(dafny.Helpers.toString(this._enc));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._pkR));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._info));
    s.append(")");
    return s.toString();
  }
}
