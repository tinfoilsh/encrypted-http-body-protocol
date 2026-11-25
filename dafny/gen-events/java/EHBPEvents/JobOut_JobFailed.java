// Class JobOut_JobFailed
// Dafny class JobOut_JobFailed compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class JobOut_JobFailed extends JobOut {
  public EHBP.Code _code;
  public dafny.DafnySequence<? extends dafny.CodePoint> _message;
  public JobOut_JobFailed (EHBP.Code code, dafny.DafnySequence<? extends dafny.CodePoint> message) {
    super();
    this._code = code;
    this._message = message;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    JobOut_JobFailed o = (JobOut_JobFailed)other;
    return true && java.util.Objects.equals(this._code, o._code) && java.util.Objects.equals(this._message, o._message);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._code);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._message);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.JobOut.JobFailed");
    s.append("(");
    s.append(dafny.Helpers.toString(this._code));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._message));
    s.append(")");
    return s.toString();
  }
}
