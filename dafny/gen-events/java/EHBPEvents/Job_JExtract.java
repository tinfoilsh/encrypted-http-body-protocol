// Class Job_JExtract
// Dafny class Job_JExtract compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Job_JExtract extends Job {
  public dafny.DafnySequence<? extends java.lang.Byte> _salt;
  public dafny.DafnySequence<? extends java.lang.Byte> _ikm;
  public Job_JExtract (dafny.DafnySequence<? extends java.lang.Byte> salt, dafny.DafnySequence<? extends java.lang.Byte> ikm) {
    super();
    this._salt = salt;
    this._ikm = ikm;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Job_JExtract o = (Job_JExtract)other;
    return true && java.util.Objects.equals(this._salt, o._salt) && java.util.Objects.equals(this._ikm, o._ikm);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._salt);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ikm);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Job.JExtract(<redacted>)");
    return s.toString();
  }
}
