// Class JobOut_Pending
// Dafny class JobOut_Pending compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class JobOut_Pending extends JobOut {
  public Job _job;
  public Action _action;
  public JobOut_Pending (Job job, Action action) {
    super();
    this._job = job;
    this._action = action;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    JobOut_Pending o = (JobOut_Pending)other;
    return true && java.util.Objects.equals(this._job, o._job) && java.util.Objects.equals(this._action, o._action);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._job);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._action);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.JobOut.Pending");
    s.append("(");
    s.append(dafny.Helpers.toString(this._job));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._action));
    s.append(")");
    return s.toString();
  }
}
