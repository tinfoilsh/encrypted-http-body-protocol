// Class Upload
// Dafny class Upload compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Upload {
  public Upload() {
  }
  private static final dafny.TypeDescriptor<Upload> _TYPE = dafny.TypeDescriptor.<Upload>referenceWithInitializer(Upload.class, () -> Upload.Default());
  public static dafny.TypeDescriptor<Upload> _typeDescriptor() {
    return (dafny.TypeDescriptor<Upload>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Upload theDefault = Upload.create_NoUpload();
  public static Upload Default() {
    return theDefault;
  }
  public static Upload create_NoUpload() {
    return new Upload_NoUpload();
  }
  public static Upload create_Sealing(dafny.DafnySequence<? extends java.lang.Byte> plaintext, int offset, boolean eof) {
    return new Upload_Sealing(plaintext, offset, eof);
  }
  public static Upload create_UpReading(java.math.BigInteger empty) {
    return new Upload_UpReading(empty);
  }
  public static Upload create_UpDone() {
    return new Upload_UpDone();
  }
  public boolean is_NoUpload() { return this instanceof Upload_NoUpload; }
  public boolean is_Sealing() { return this instanceof Upload_Sealing; }
  public boolean is_UpReading() { return this instanceof Upload_UpReading; }
  public boolean is_UpDone() { return this instanceof Upload_UpDone; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_plaintext() {
    Upload d = this;
    return ((Upload_Sealing)d)._plaintext;
  }
  public int dtor_offset() {
    Upload d = this;
    return ((Upload_Sealing)d)._offset;
  }
  public boolean dtor_eof() {
    Upload d = this;
    return ((Upload_Sealing)d)._eof;
  }
  public java.math.BigInteger dtor_empty() {
    Upload d = this;
    return ((Upload_UpReading)d)._empty;
  }
}
