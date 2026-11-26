// Interface Performer
// Dafny trait Performer compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public interface Performer {
  public long BeginSession();
  public void PublishToken(long generation, dafny.DafnySequence<? extends java.lang.Byte> exportedSecret, dafny.DafnySequence<? extends java.lang.Byte> requestEnc);
  public void ClearToken(long generation);
  public dafny.DafnySequence<? extends java.lang.Byte> RandomBytes(java.math.BigInteger length);
  public dafny.DafnySequence<? extends java.lang.Byte> X25519(dafny.DafnySequence<? extends java.lang.Byte> scalar, dafny.DafnySequence<? extends java.lang.Byte> point);
  public dafny.DafnySequence<? extends java.lang.Byte> HmacSha256(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> data);
  public dafny.DafnySequence<? extends java.lang.Byte> AeadSeal(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> nonce, dafny.DafnySequence<? extends java.lang.Byte> plaintext);
  public dafny.Tuple2 AeadOpen(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> nonce, dafny.DafnySequence<? extends java.lang.Byte> ciphertext);
  public dafny.Tuple4 Send(dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> url, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, boolean hasBody);
  public boolean Write(dafny.DafnySequence<? extends java.lang.Byte> data, BodyEnd end);
  public dafny.Tuple3 Read(Stream stream);
  public void Close(Stream stream);
  public void EmitPlaintext(dafny.DafnySequence<? extends java.lang.Byte> data);
}
