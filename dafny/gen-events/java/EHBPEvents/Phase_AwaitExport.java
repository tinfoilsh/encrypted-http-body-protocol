// Class Phase_AwaitExport
// Dafny class Phase_AwaitExport compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Phase_AwaitExport extends Phase {
  public dafny.DafnySequence<? extends java.lang.Byte> _first;
  public boolean _firstEof;
  public dafny.DafnySequence<? extends java.lang.Byte> _enc;
  public Job _job;
  public Phase_AwaitExport (dafny.DafnySequence<? extends java.lang.Byte> first, boolean firstEof, dafny.DafnySequence<? extends java.lang.Byte> enc, Job job) {
    super();
    this._first = first;
    this._firstEof = firstEof;
    this._enc = enc;
    this._job = job;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Phase_AwaitExport o = (Phase_AwaitExport)other;
    return true && java.util.Objects.equals(this._first, o._first) && this._firstEof == o._firstEof && java.util.Objects.equals(this._enc, o._enc) && java.util.Objects.equals(this._job, o._job);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 4;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._first);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._firstEof);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._enc);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._job);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Phase.AwaitExport");
    s.append("(");
    s.append(dafny.Helpers.toString(this._first));
    s.append(", ");
    s.append(this._firstEof);
    s.append(", ");
    s.append(dafny.Helpers.toString(this._enc));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._job));
    s.append(")");
    return s.toString();
  }
}
