// Class Job_JExpand
// Dafny class Job_JExpand compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Job_JExpand extends Job {
  public dafny.DafnySequence<? extends java.lang.Byte> _prk;
  public dafny.DafnySequence<? extends java.lang.Byte> _info;
  public java.math.BigInteger _length;
  public dafny.DafnySequence<? extends java.lang.Byte> _acc;
  public dafny.DafnySequence<? extends java.lang.Byte> _prev;
  public byte _i;
  public Job_JExpand (dafny.DafnySequence<? extends java.lang.Byte> prk, dafny.DafnySequence<? extends java.lang.Byte> info, java.math.BigInteger length, dafny.DafnySequence<? extends java.lang.Byte> acc, dafny.DafnySequence<? extends java.lang.Byte> prev, byte i) {
    super();
    this._prk = prk;
    this._info = info;
    this._length = length;
    this._acc = acc;
    this._prev = prev;
    this._i = i;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Job_JExpand o = (Job_JExpand)other;
    return true && java.util.Objects.equals(this._prk, o._prk) && java.util.Objects.equals(this._info, o._info) && java.util.Objects.equals(this._length, o._length) && java.util.Objects.equals(this._acc, o._acc) && java.util.Objects.equals(this._prev, o._prev) && this._i == o._i;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._prk);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._info);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._length);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._acc);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._prev);
    hash = ((hash << 5) + hash) + java.lang.Byte.hashCode(this._i);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Job.JExpand(<redacted>)");
    return s.toString();
  }
}
