// Class JobOut
// Dafny class JobOut compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class JobOut {
  public JobOut() {
  }
  private static final dafny.TypeDescriptor<JobOut> _TYPE = dafny.TypeDescriptor.<JobOut>referenceWithInitializer(JobOut.class, () -> JobOut.Default());
  public static dafny.TypeDescriptor<JobOut> _typeDescriptor() {
    return (dafny.TypeDescriptor<JobOut>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final JobOut theDefault = JobOut.create_Pending(Job.Default(), Action.Default());
  public static JobOut Default() {
    return theDefault;
  }
  public static JobOut create_Pending(Job job, Action action) {
    return new JobOut_Pending(job, action);
  }
  public static JobOut create_Output(dafny.DafnySequence<? extends java.lang.Byte> data) {
    return new JobOut_Output(data);
  }
  public static JobOut create_JobFailed(EHBP.Code code, dafny.DafnySequence<? extends dafny.CodePoint> message) {
    return new JobOut_JobFailed(code, message);
  }
  public boolean is_Pending() { return this instanceof JobOut_Pending; }
  public boolean is_Output() { return this instanceof JobOut_Output; }
  public boolean is_JobFailed() { return this instanceof JobOut_JobFailed; }
  public Job dtor_job() {
    JobOut d = this;
    return ((JobOut_Pending)d)._job;
  }
  public Action dtor_action() {
    JobOut d = this;
    return ((JobOut_Pending)d)._action;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_data() {
    JobOut d = this;
    return ((JobOut_Output)d)._data;
  }
  public EHBP.Code dtor_code() {
    JobOut d = this;
    return ((JobOut_JobFailed)d)._code;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_message() {
    JobOut d = this;
    return ((JobOut_JobFailed)d)._message;
  }
}
