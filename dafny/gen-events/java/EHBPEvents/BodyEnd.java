// Class BodyEnd
// Dafny class BodyEnd compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class BodyEnd {
  public BodyEnd() {
  }
  private static final dafny.TypeDescriptor<BodyEnd> _TYPE = dafny.TypeDescriptor.<BodyEnd>referenceWithInitializer(BodyEnd.class, () -> BodyEnd.Default());
  public static dafny.TypeDescriptor<BodyEnd> _typeDescriptor() {
    return (dafny.TypeDescriptor<BodyEnd>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final BodyEnd theDefault = BodyEnd.create_More();
  public static BodyEnd Default() {
    return theDefault;
  }
  public static BodyEnd create_More() {
    return new BodyEnd_More();
  }
  public static BodyEnd create_Done() {
    return new BodyEnd_Done();
  }
  public static BodyEnd create_Aborted(EHBP.Code code) {
    return new BodyEnd_Aborted(code);
  }
  public boolean is_More() { return this instanceof BodyEnd_More; }
  public boolean is_Done() { return this instanceof BodyEnd_Done; }
  public boolean is_Aborted() { return this instanceof BodyEnd_Aborted; }
  public EHBP.Code dtor_code() {
    BodyEnd d = this;
    return ((BodyEnd_Aborted)d)._code;
  }
}
