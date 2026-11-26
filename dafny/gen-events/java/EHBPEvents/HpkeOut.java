// Class HpkeOut
// Dafny class HpkeOut compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class HpkeOut {
  public HpkeOut() {
  }
  private static final dafny.TypeDescriptor<HpkeOut> _TYPE = dafny.TypeDescriptor.<HpkeOut>referenceWithInitializer(HpkeOut.class, () -> HpkeOut.Default());
  public static dafny.TypeDescriptor<HpkeOut> _typeDescriptor() {
    return (dafny.TypeDescriptor<HpkeOut>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final HpkeOut theDefault = HpkeOut.create_HContinue(Hpke.Default(), Action.Default());
  public static HpkeOut Default() {
    return theDefault;
  }
  public static HpkeOut create_HContinue(Hpke h, Action action) {
    return new HpkeOut_HContinue(h, action);
  }
  public static HpkeOut create_HReady(Ctx ctx, dafny.DafnySequence<? extends java.lang.Byte> enc) {
    return new HpkeOut_HReady(ctx, enc);
  }
  public static HpkeOut create_HFailed(EHBP.Code code, dafny.DafnySequence<? extends dafny.CodePoint> message) {
    return new HpkeOut_HFailed(code, message);
  }
  public boolean is_HContinue() { return this instanceof HpkeOut_HContinue; }
  public boolean is_HReady() { return this instanceof HpkeOut_HReady; }
  public boolean is_HFailed() { return this instanceof HpkeOut_HFailed; }
  public Hpke dtor_h() {
    HpkeOut d = this;
    return ((HpkeOut_HContinue)d)._h;
  }
  public Action dtor_action() {
    HpkeOut d = this;
    return ((HpkeOut_HContinue)d)._action;
  }
  public Ctx dtor_ctx() {
    HpkeOut d = this;
    return ((HpkeOut_HReady)d)._ctx;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_enc() {
    HpkeOut d = this;
    return ((HpkeOut_HReady)d)._enc;
  }
  public EHBP.Code dtor_code() {
    HpkeOut d = this;
    return ((HpkeOut_HFailed)d)._code;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_message() {
    HpkeOut d = this;
    return ((HpkeOut_HFailed)d)._message;
  }
}
