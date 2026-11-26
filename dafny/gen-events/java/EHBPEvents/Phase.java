// Class Phase
// Dafny class Phase compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Phase {
  public Phase() {
  }
  private static final dafny.TypeDescriptor<Phase> _TYPE = dafny.TypeDescriptor.<Phase>referenceWithInitializer(Phase.class, () -> Phase.Default());
  public static dafny.TypeDescriptor<Phase> _typeDescriptor() {
    return (dafny.TypeDescriptor<Phase>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Phase theDefault = Phase.create_Idle();
  public static Phase Default() {
    return theDefault;
  }
  public static Phase create_Idle() {
    return new Phase_Idle();
  }
  public static Phase create_AwaitSession(boolean hasBody) {
    return new Phase_AwaitSession(hasBody);
  }
  public static Phase create_Peeking(java.math.BigInteger empty) {
    return new Phase_Peeking(empty);
  }
  public static Phase create_AwaitSetup(dafny.DafnySequence<? extends java.lang.Byte> first, boolean firstEof, Hpke hpke) {
    return new Phase_AwaitSetup(first, firstEof, hpke);
  }
  public static Phase create_AwaitExport(dafny.DafnySequence<? extends java.lang.Byte> first, boolean firstEof, dafny.DafnySequence<? extends java.lang.Byte> enc, Job job) {
    return new Phase_AwaitExport(first, firstEof, enc, job);
  }
  public static Phase create_Exchanging(Upload upload, Response response) {
    return new Phase_Exchanging(upload, response);
  }
  public static Phase create_DiscAwaitHead() {
    return new Phase_DiscAwaitHead();
  }
  public static Phase create_DiscReading(dafny.DafnySequence<? extends java.lang.Byte> data) {
    return new Phase_DiscReading(data);
  }
  public static Phase create_Ended() {
    return new Phase_Ended();
  }
  public boolean is_Idle() { return this instanceof Phase_Idle; }
  public boolean is_AwaitSession() { return this instanceof Phase_AwaitSession; }
  public boolean is_Peeking() { return this instanceof Phase_Peeking; }
  public boolean is_AwaitSetup() { return this instanceof Phase_AwaitSetup; }
  public boolean is_AwaitExport() { return this instanceof Phase_AwaitExport; }
  public boolean is_Exchanging() { return this instanceof Phase_Exchanging; }
  public boolean is_DiscAwaitHead() { return this instanceof Phase_DiscAwaitHead; }
  public boolean is_DiscReading() { return this instanceof Phase_DiscReading; }
  public boolean is_Ended() { return this instanceof Phase_Ended; }
  public boolean dtor_hasBody() {
    Phase d = this;
    return ((Phase_AwaitSession)d)._hasBody;
  }
  public java.math.BigInteger dtor_empty() {
    Phase d = this;
    return ((Phase_Peeking)d)._empty;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_first() {
    Phase d = this;
    if (d instanceof Phase_AwaitSetup) { return ((Phase_AwaitSetup)d)._first; }
    return ((Phase_AwaitExport)d)._first;
  }
  public boolean dtor_firstEof() {
    Phase d = this;
    if (d instanceof Phase_AwaitSetup) { return ((Phase_AwaitSetup)d)._firstEof; }
    return ((Phase_AwaitExport)d)._firstEof;
  }
  public Hpke dtor_hpke() {
    Phase d = this;
    return ((Phase_AwaitSetup)d)._hpke;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_enc() {
    Phase d = this;
    return ((Phase_AwaitExport)d)._enc;
  }
  public Job dtor_job() {
    Phase d = this;
    return ((Phase_AwaitExport)d)._job;
  }
  public Upload dtor_upload() {
    Phase d = this;
    return ((Phase_Exchanging)d)._upload;
  }
  public Response dtor_response() {
    Phase d = this;
    return ((Phase_Exchanging)d)._response;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_data() {
    Phase d = this;
    return ((Phase_DiscReading)d)._data;
  }
}
