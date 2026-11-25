// Class Hpke_HEnc
// Dafny class Hpke_HEnc compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Hpke_HEnc extends Hpke {
  public dafny.DafnySequence<? extends java.lang.Byte> _skE;
  public dafny.DafnySequence<? extends java.lang.Byte> _pkR;
  public dafny.DafnySequence<? extends java.lang.Byte> _info;
  public Hpke_HEnc (dafny.DafnySequence<? extends java.lang.Byte> skE, dafny.DafnySequence<? extends java.lang.Byte> pkR, dafny.DafnySequence<? extends java.lang.Byte> info) {
    super();
    this._skE = skE;
    this._pkR = pkR;
    this._info = info;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Hpke_HEnc o = (Hpke_HEnc)other;
    return true && java.util.Objects.equals(this._skE, o._skE) && java.util.Objects.equals(this._pkR, o._pkR) && java.util.Objects.equals(this._info, o._info);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._skE);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._pkR);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._info);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Hpke.HEnc(<redacted>)");
    return s.toString();
  }
}
