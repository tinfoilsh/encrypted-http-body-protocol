// Class Job
// Dafny class Job compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Job {
  public Job() {
  }
  private static final dafny.TypeDescriptor<Job> _TYPE = dafny.TypeDescriptor.<Job>referenceWithInitializer(Job.class, () -> Job.Default());
  public static dafny.TypeDescriptor<Job> _typeDescriptor() {
    return (dafny.TypeDescriptor<Job>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Job theDefault = Job.create_JExtract(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()));
  public static Job Default() {
    return theDefault;
  }
  public static Job create_JExtract(dafny.DafnySequence<? extends java.lang.Byte> salt, dafny.DafnySequence<? extends java.lang.Byte> ikm) {
    return new Job_JExtract(salt, ikm);
  }
  public static Job create_JExpand(dafny.DafnySequence<? extends java.lang.Byte> prk, dafny.DafnySequence<? extends java.lang.Byte> info, java.math.BigInteger length, dafny.DafnySequence<? extends java.lang.Byte> acc, dafny.DafnySequence<? extends java.lang.Byte> prev, byte i) {
    return new Job_JExpand(prk, info, length, acc, prev, i);
  }
  public boolean is_JExtract() { return this instanceof Job_JExtract; }
  public boolean is_JExpand() { return this instanceof Job_JExpand; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_salt() {
    Job d = this;
    return ((Job_JExtract)d)._salt;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_ikm() {
    Job d = this;
    return ((Job_JExtract)d)._ikm;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_prk() {
    Job d = this;
    return ((Job_JExpand)d)._prk;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_info() {
    Job d = this;
    return ((Job_JExpand)d)._info;
  }
  public java.math.BigInteger dtor_length() {
    Job d = this;
    return ((Job_JExpand)d)._length;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_acc() {
    Job d = this;
    return ((Job_JExpand)d)._acc;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_prev() {
    Job d = this;
    return ((Job_JExpand)d)._prev;
  }
  public byte dtor_i() {
    Job d = this;
    return ((Job_JExpand)d)._i;
  }
}
