// Class Event
// Dafny class Event compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Event {
  public Event() {
  }
  private static final dafny.TypeDescriptor<Event> _TYPE = dafny.TypeDescriptor.<Event>referenceWithInitializer(Event.class, () -> Event.Default());
  public static dafny.TypeDescriptor<Event> _typeDescriptor() {
    return (dafny.TypeDescriptor<Event>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Event theDefault = Event.create_Start(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), java.math.BigInteger.ZERO, false, false, dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> empty(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))), false);
  public static Event Default() {
    return theDefault;
  }
  public static Event create_Start(dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> url, dafny.DafnySequence<? extends dafny.CodePoint> scheme, dafny.DafnySequence<? extends dafny.CodePoint> host, java.math.BigInteger port, boolean hasPort, boolean hasUserinfo, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean hasBody) {
    return new Event_Start(verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody);
  }
  public static Event create_DiscoverStart() {
    return new Event_DiscoverStart();
  }
  public static Event create_SessionBegun(long generation) {
    return new Event_SessionBegun(generation);
  }
  public static Event create_RandomResult(dafny.DafnySequence<? extends java.lang.Byte> data) {
    return new Event_RandomResult(data);
  }
  public static Event create_X25519Result(dafny.DafnySequence<? extends java.lang.Byte> point) {
    return new Event_X25519Result(point);
  }
  public static Event create_HmacResult(dafny.DafnySequence<? extends java.lang.Byte> mac) {
    return new Event_HmacResult(mac);
  }
  public static Event create_AeadSealResult(dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    return new Event_AeadSealResult(ciphertext);
  }
  public static Event create_AeadOpenResult(boolean ok, dafny.DafnySequence<? extends java.lang.Byte> plaintext) {
    return new Event_AeadOpenResult(ok, plaintext);
  }
  public static Event create_ResponseHead(java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean redirected) {
    return new Event_ResponseHead(status, headers, redirected);
  }
  public static Event create_Chunk(Stream stream, dafny.DafnySequence<? extends java.lang.Byte> data, boolean eof) {
    return new Event_Chunk(stream, data, eof);
  }
  public static Event create_StreamFailed(Stream stream) {
    return new Event_StreamFailed(stream);
  }
  public static Event create_CallerRead() {
    return new Event_CallerRead();
  }
  public static Event create_CallerClose() {
    return new Event_CallerClose();
  }
  public boolean is_Start() { return this instanceof Event_Start; }
  public boolean is_DiscoverStart() { return this instanceof Event_DiscoverStart; }
  public boolean is_SessionBegun() { return this instanceof Event_SessionBegun; }
  public boolean is_RandomResult() { return this instanceof Event_RandomResult; }
  public boolean is_X25519Result() { return this instanceof Event_X25519Result; }
  public boolean is_HmacResult() { return this instanceof Event_HmacResult; }
  public boolean is_AeadSealResult() { return this instanceof Event_AeadSealResult; }
  public boolean is_AeadOpenResult() { return this instanceof Event_AeadOpenResult; }
  public boolean is_ResponseHead() { return this instanceof Event_ResponseHead; }
  public boolean is_Chunk() { return this instanceof Event_Chunk; }
  public boolean is_StreamFailed() { return this instanceof Event_StreamFailed; }
  public boolean is_CallerRead() { return this instanceof Event_CallerRead; }
  public boolean is_CallerClose() { return this instanceof Event_CallerClose; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_verb() {
    Event d = this;
    return ((Event_Start)d)._verb;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_url() {
    Event d = this;
    return ((Event_Start)d)._url;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_scheme() {
    Event d = this;
    return ((Event_Start)d)._scheme;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_host() {
    Event d = this;
    return ((Event_Start)d)._host;
  }
  public java.math.BigInteger dtor_port() {
    Event d = this;
    return ((Event_Start)d)._port;
  }
  public boolean dtor_hasPort() {
    Event d = this;
    return ((Event_Start)d)._hasPort;
  }
  public boolean dtor_hasUserinfo() {
    Event d = this;
    return ((Event_Start)d)._hasUserinfo;
  }
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> dtor_headers() {
    Event d = this;
    if (d instanceof Event_Start) { return ((Event_Start)d)._headers; }
    return ((Event_ResponseHead)d)._headers;
  }
  public boolean dtor_hasBody() {
    Event d = this;
    return ((Event_Start)d)._hasBody;
  }
  public long dtor_generation() {
    Event d = this;
    return ((Event_SessionBegun)d)._generation;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_data() {
    Event d = this;
    if (d instanceof Event_RandomResult) { return ((Event_RandomResult)d)._data; }
    return ((Event_Chunk)d)._data;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_point() {
    Event d = this;
    return ((Event_X25519Result)d)._point;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_mac() {
    Event d = this;
    return ((Event_HmacResult)d)._mac;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_ciphertext() {
    Event d = this;
    return ((Event_AeadSealResult)d)._ciphertext;
  }
  public boolean dtor_ok() {
    Event d = this;
    return ((Event_AeadOpenResult)d)._ok;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_plaintext() {
    Event d = this;
    return ((Event_AeadOpenResult)d)._plaintext;
  }
  public java.math.BigInteger dtor_status() {
    Event d = this;
    return ((Event_ResponseHead)d)._status;
  }
  public boolean dtor_redirected() {
    Event d = this;
    return ((Event_ResponseHead)d)._redirected;
  }
  public Stream dtor_stream() {
    Event d = this;
    if (d instanceof Event_Chunk) { return ((Event_Chunk)d)._stream; }
    return ((Event_StreamFailed)d)._stream;
  }
  public boolean dtor_eof() {
    Event d = this;
    return ((Event_Chunk)d)._eof;
  }
}
