// Class Phase_AwaitSetup
// Dafny class Phase_AwaitSetup compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Phase_AwaitSetup extends Phase {
  public dafny.DafnySequence<? extends java.lang.Byte> _first;
  public boolean _firstEof;
  public Hpke _hpke;
  public Phase_AwaitSetup (dafny.DafnySequence<? extends java.lang.Byte> first, boolean firstEof, Hpke hpke) {
    super();
    this._first = first;
    this._firstEof = firstEof;
    this._hpke = hpke;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Phase_AwaitSetup o = (Phase_AwaitSetup)other;
    return true && java.util.Objects.equals(this._first, o._first) && this._firstEof == o._firstEof && java.util.Objects.equals(this._hpke, o._hpke);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._first);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._firstEof);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._hpke);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Phase.AwaitSetup");
    s.append("(");
    s.append(dafny.Helpers.toString(this._first));
    s.append(", ");
    s.append(this._firstEof);
    s.append(", ");
    s.append(dafny.Helpers.toString(this._hpke));
    s.append(")");
    return s.toString();
  }
}
