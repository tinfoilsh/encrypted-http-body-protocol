// Class Performed
// Dafny class Performed compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Performed {
  public Performed() {
  }
  private static final dafny.TypeDescriptor<Performed> _TYPE = dafny.TypeDescriptor.<Performed>referenceWithInitializer(Performed.class, () -> Performed.Default());
  public static dafny.TypeDescriptor<Performed> _typeDescriptor() {
    return (dafny.TypeDescriptor<Performed>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Performed theDefault = Performed.create_Quiet();
  public static Performed Default() {
    return theDefault;
  }
  public static Performed create_Quiet() {
    return new Performed_Quiet();
  }
  public static Performed create_Got(Event e) {
    return new Performed_Got(e);
  }
  public static Performed create_Stop() {
    return new Performed_Stop();
  }
  public boolean is_Quiet() { return this instanceof Performed_Quiet; }
  public boolean is_Got() { return this instanceof Performed_Got; }
  public boolean is_Stop() { return this instanceof Performed_Stop; }
  public Event dtor_e() {
    Performed d = this;
    return ((Performed_Got)d)._e;
  }
}
