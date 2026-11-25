// Class Action
// Dafny class Action compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Action {
  public Action() {
  }
  private static final dafny.TypeDescriptor<Action> _TYPE = dafny.TypeDescriptor.<Action>referenceWithInitializer(Action.class, () -> Action.Default());
  public static dafny.TypeDescriptor<Action> _typeDescriptor() {
    return (dafny.TypeDescriptor<Action>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Action theDefault = Action.create_BeginSession();
  public static Action Default() {
    return theDefault;
  }
  public static Action create_BeginSession() {
    return new Action_BeginSession();
  }
  public static Action create_PublishToken(long generation, dafny.DafnySequence<? extends java.lang.Byte> exportedSecret, dafny.DafnySequence<? extends java.lang.Byte> requestEnc) {
    return new Action_PublishToken(generation, exportedSecret, requestEnc);
  }
  public static Action create_ClearToken(long generation) {
    return new Action_ClearToken(generation);
  }
  public static Action create_RandomBytes(java.math.BigInteger length) {
    return new Action_RandomBytes(length);
  }
  public static Action create_X25519(dafny.DafnySequence<? extends java.lang.Byte> scalar, dafny.DafnySequence<? extends java.lang.Byte> point) {
    return new Action_X25519(scalar, point);
  }
  public static Action create_HmacSha256(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> data) {
    return new Action_HmacSha256(key, data);
  }
  public static Action create_AeadSeal(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> nonce, dafny.DafnySequence<? extends java.lang.Byte> plaintext) {
    return new Action_AeadSeal(key, nonce, plaintext);
  }
  public static Action create_AeadOpen(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> nonce, dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    return new Action_AeadOpen(key, nonce, ciphertext);
  }
  public static Action create_Send(dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> url, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean hasBody) {
    return new Action_Send(verb, url, headers, hasBody);
  }
  public static Action create_Write(dafny.DafnySequence<? extends java.lang.Byte> data, BodyEnd end) {
    return new Action_Write(data, end);
  }
  public static Action create_Read(Stream stream) {
    return new Action_Read(stream);
  }
  public static Action create_Close(Stream stream) {
    return new Action_Close(stream);
  }
  public static Action create_EmitPlaintext(dafny.DafnySequence<? extends java.lang.Byte> data) {
    return new Action_EmitPlaintext(data);
  }
  public static Action create_Passthrough(java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, dafny.DafnySequence<? extends java.lang.Byte> prefix) {
    return new Action_Passthrough(status, headers, prefix);
  }
  public static Action create_Done(java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers) {
    return new Action_Done(status, headers);
  }
  public static Action create_Finished() {
    return new Action_Finished();
  }
  public static Action create_Discovered(dafny.DafnySequence<? extends java.lang.Byte> publicKey) {
    return new Action_Discovered(publicKey);
  }
  public static Action create_Fail(EHBP.Code code, dafny.DafnySequence<? extends dafny.CodePoint> message) {
    return new Action_Fail(code, message);
  }
  public boolean is_BeginSession() { return this instanceof Action_BeginSession; }
  public boolean is_PublishToken() { return this instanceof Action_PublishToken; }
  public boolean is_ClearToken() { return this instanceof Action_ClearToken; }
  public boolean is_RandomBytes() { return this instanceof Action_RandomBytes; }
  public boolean is_X25519() { return this instanceof Action_X25519; }
  public boolean is_HmacSha256() { return this instanceof Action_HmacSha256; }
  public boolean is_AeadSeal() { return this instanceof Action_AeadSeal; }
  public boolean is_AeadOpen() { return this instanceof Action_AeadOpen; }
  public boolean is_Send() { return this instanceof Action_Send; }
  public boolean is_Write() { return this instanceof Action_Write; }
  public boolean is_Read() { return this instanceof Action_Read; }
  public boolean is_Close() { return this instanceof Action_Close; }
  public boolean is_EmitPlaintext() { return this instanceof Action_EmitPlaintext; }
  public boolean is_Passthrough() { return this instanceof Action_Passthrough; }
  public boolean is_Done() { return this instanceof Action_Done; }
  public boolean is_Finished() { return this instanceof Action_Finished; }
  public boolean is_Discovered() { return this instanceof Action_Discovered; }
  public boolean is_Fail() { return this instanceof Action_Fail; }
  public long dtor_generation() {
    Action d = this;
    if (d instanceof Action_PublishToken) { return ((Action_PublishToken)d)._generation; }
    return ((Action_ClearToken)d)._generation;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_exportedSecret() {
    Action d = this;
    return ((Action_PublishToken)d)._exportedSecret;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_requestEnc() {
    Action d = this;
    return ((Action_PublishToken)d)._requestEnc;
  }
  public java.math.BigInteger dtor_length() {
    Action d = this;
    return ((Action_RandomBytes)d)._length;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_scalar() {
    Action d = this;
    return ((Action_X25519)d)._scalar;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_point() {
    Action d = this;
    return ((Action_X25519)d)._point;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_key() {
    Action d = this;
    if (d instanceof Action_HmacSha256) { return ((Action_HmacSha256)d)._key; }
    if (d instanceof Action_AeadSeal) { return ((Action_AeadSeal)d)._key; }
    return ((Action_AeadOpen)d)._key;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_data() {
    Action d = this;
    if (d instanceof Action_HmacSha256) { return ((Action_HmacSha256)d)._data; }
    if (d instanceof Action_Write) { return ((Action_Write)d)._data; }
    return ((Action_EmitPlaintext)d)._data;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_nonce() {
    Action d = this;
    if (d instanceof Action_AeadSeal) { return ((Action_AeadSeal)d)._nonce; }
    return ((Action_AeadOpen)d)._nonce;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_plaintext() {
    Action d = this;
    return ((Action_AeadSeal)d)._plaintext;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_ciphertext() {
    Action d = this;
    return ((Action_AeadOpen)d)._ciphertext;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_verb() {
    Action d = this;
    return ((Action_Send)d)._verb;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_url() {
    Action d = this;
    return ((Action_Send)d)._url;
  }
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> dtor_headers() {
    Action d = this;
    if (d instanceof Action_Send) { return ((Action_Send)d)._headers; }
    if (d instanceof Action_Passthrough) { return ((Action_Passthrough)d)._headers; }
    return ((Action_Done)d)._headers;
  }
  public boolean dtor_hasBody() {
    Action d = this;
    return ((Action_Send)d)._hasBody;
  }
  public BodyEnd dtor_end() {
    Action d = this;
    return ((Action_Write)d)._end;
  }
  public Stream dtor_stream() {
    Action d = this;
    if (d instanceof Action_Read) { return ((Action_Read)d)._stream; }
    return ((Action_Close)d)._stream;
  }
  public java.math.BigInteger dtor_status() {
    Action d = this;
    if (d instanceof Action_Passthrough) { return ((Action_Passthrough)d)._status; }
    return ((Action_Done)d)._status;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_prefix() {
    Action d = this;
    return ((Action_Passthrough)d)._prefix;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_publicKey() {
    Action d = this;
    return ((Action_Discovered)d)._publicKey;
  }
  public EHBP.Code dtor_code() {
    Action d = this;
    return ((Action_Fail)d)._code;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_message() {
    Action d = this;
    return ((Action_Fail)d)._message;
  }
}
