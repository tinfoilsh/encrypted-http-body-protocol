// Class JobOut_Output
// Dafny class JobOut_Output compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class JobOut_Output extends JobOut {
  public dafny.DafnySequence<? extends java.lang.Byte> _data;
  public JobOut_Output (dafny.DafnySequence<? extends java.lang.Byte> data) {
    super();
    this._data = data;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    JobOut_Output o = (JobOut_Output)other;
    return true && java.util.Objects.equals(this._data, o._data);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._data);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.JobOut.Output(<redacted>)");
    return s.toString();
  }
}
