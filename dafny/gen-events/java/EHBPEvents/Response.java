// Class Response
// Dafny class Response compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Response {
  public Response() {
  }
  private static final dafny.TypeDescriptor<Response> _TYPE = dafny.TypeDescriptor.<Response>referenceWithInitializer(Response.class, () -> Response.Default());
  public static dafny.TypeDescriptor<Response> _typeDescriptor() {
    return (dafny.TypeDescriptor<Response>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Response theDefault = Response.create_AwaitHead(false);
  public static Response Default() {
    return theDefault;
  }
  public static Response create_AwaitHead(boolean encrypted) {
    return new Response_AwaitHead(encrypted);
  }
  public static Response create_ProblemReading(java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, dafny.DafnySequence<? extends java.lang.Byte> data) {
    return new Response_ProblemReading(status, headers, data);
  }
  public static Response create_AwaitKeys(java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean requireFrame, java.math.BigInteger stage, Job job, dafny.DafnySequence<? extends java.lang.Byte> prk, dafny.DafnySequence<? extends java.lang.Byte> key) {
    return new Response_AwaitKeys(status, headers, requireFrame, stage, job, prk, key);
  }
  public static Response create_Body(Ctx keys, Dec dec, boolean done) {
    return new Response_Body(keys, dec, done);
  }
  public static Response create_BodyReading(Ctx keys, Dec dec) {
    return new Response_BodyReading(keys, dec);
  }
  public static Response create_Opening(Ctx keys, Dec dec, dafny.DafnySequence<? extends EHBP.Framed> frames, dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.lang.Byte>> chunks, boolean eof) {
    return new Response_Opening(keys, dec, frames, chunks, eof);
  }
  public static Response create_RespEnded() {
    return new Response_RespEnded();
  }
  public boolean is_AwaitHead() { return this instanceof Response_AwaitHead; }
  public boolean is_ProblemReading() { return this instanceof Response_ProblemReading; }
  public boolean is_AwaitKeys() { return this instanceof Response_AwaitKeys; }
  public boolean is_Body() { return this instanceof Response_Body; }
  public boolean is_BodyReading() { return this instanceof Response_BodyReading; }
  public boolean is_Opening() { return this instanceof Response_Opening; }
  public boolean is_RespEnded() { return this instanceof Response_RespEnded; }
  public boolean dtor_encrypted() {
    Response d = this;
    return ((Response_AwaitHead)d)._encrypted;
  }
  public java.math.BigInteger dtor_status() {
    Response d = this;
    if (d instanceof Response_ProblemReading) { return ((Response_ProblemReading)d)._status; }
    return ((Response_AwaitKeys)d)._status;
  }
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> dtor_headers() {
    Response d = this;
    if (d instanceof Response_ProblemReading) { return ((Response_ProblemReading)d)._headers; }
    return ((Response_AwaitKeys)d)._headers;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_data() {
    Response d = this;
    return ((Response_ProblemReading)d)._data;
  }
  public boolean dtor_requireFrame() {
    Response d = this;
    return ((Response_AwaitKeys)d)._requireFrame;
  }
  public java.math.BigInteger dtor_stage() {
    Response d = this;
    return ((Response_AwaitKeys)d)._stage;
  }
  public Job dtor_job() {
    Response d = this;
    return ((Response_AwaitKeys)d)._job;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_prk() {
    Response d = this;
    return ((Response_AwaitKeys)d)._prk;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_key() {
    Response d = this;
    return ((Response_AwaitKeys)d)._key;
  }
  public Ctx dtor_keys() {
    Response d = this;
    if (d instanceof Response_Body) { return ((Response_Body)d)._keys; }
    if (d instanceof Response_BodyReading) { return ((Response_BodyReading)d)._keys; }
    return ((Response_Opening)d)._keys;
  }
  public Dec dtor_dec() {
    Response d = this;
    if (d instanceof Response_Body) { return ((Response_Body)d)._dec; }
    if (d instanceof Response_BodyReading) { return ((Response_BodyReading)d)._dec; }
    return ((Response_Opening)d)._dec;
  }
  public boolean dtor_done() {
    Response d = this;
    return ((Response_Body)d)._done;
  }
  public dafny.DafnySequence<? extends EHBP.Framed> dtor_frames() {
    Response d = this;
    return ((Response_Opening)d)._frames;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.lang.Byte>> dtor_chunks() {
    Response d = this;
    return ((Response_Opening)d)._chunks;
  }
  public boolean dtor_eof() {
    Response d = this;
    return ((Response_Opening)d)._eof;
  }
}
