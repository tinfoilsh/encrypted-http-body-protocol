// Class Disposition
// Dafny class Disposition compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Disposition {
  public Disposition() {
  }
  private static final dafny.TypeDescriptor<Disposition> _TYPE = dafny.TypeDescriptor.<Disposition>referenceWithInitializer(Disposition.class, () -> Disposition.Default());
  public static dafny.TypeDescriptor<Disposition> _typeDescriptor() {
    return (dafny.TypeDescriptor<Disposition>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Disposition theDefault = Disposition.create_PassThrough();
  public static Disposition Default() {
    return theDefault;
  }
  public static Disposition create_PassThrough() {
    return new Disposition_PassThrough();
  }
  public static Disposition create_Decrypt(dafny.DafnySequence<? extends java.lang.Byte> nonce, boolean requireFrame) {
    return new Disposition_Decrypt(nonce, requireFrame);
  }
  public static Disposition create_NeedProblemBody() {
    return new Disposition_NeedProblemBody();
  }
  public static Disposition create_Refuse(Code code, dafny.DafnySequence<? extends dafny.CodePoint> message) {
    return new Disposition_Refuse(code, message);
  }
  public boolean is_PassThrough() { return this instanceof Disposition_PassThrough; }
  public boolean is_Decrypt() { return this instanceof Disposition_Decrypt; }
  public boolean is_NeedProblemBody() { return this instanceof Disposition_NeedProblemBody; }
  public boolean is_Refuse() { return this instanceof Disposition_Refuse; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_nonce() {
    Disposition d = this;
    return ((Disposition_Decrypt)d)._nonce;
  }
  public boolean dtor_requireFrame() {
    Disposition d = this;
    return ((Disposition_Decrypt)d)._requireFrame;
  }
  public Code dtor_code() {
    Disposition d = this;
    return ((Disposition_Refuse)d)._code;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_message() {
    Disposition d = this;
    return ((Disposition_Refuse)d)._message;
  }
}
