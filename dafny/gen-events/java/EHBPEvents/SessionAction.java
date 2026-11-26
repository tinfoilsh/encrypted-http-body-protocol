// Class SessionAction
// Dafny class SessionAction compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class SessionAction {
  public SessionAction() {
  }
  private static final dafny.TypeDescriptor<SessionAction> _TYPE = dafny.TypeDescriptor.<SessionAction>referenceWithInitializer(SessionAction.class, () -> SessionAction.Default());
  public static dafny.TypeDescriptor<SessionAction> _typeDescriptor() {
    return (dafny.TypeDescriptor<SessionAction>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final SessionAction theDefault = SessionAction.create_Begin();
  public static SessionAction Default() {
    return theDefault;
  }
  public static SessionAction create_Begin() {
    return new SessionAction_Begin();
  }
  public static SessionAction create_Publish(long generation, EHBP.Token token) {
    return new SessionAction_Publish(generation, token);
  }
  public static SessionAction create_Clear(long generation) {
    return new SessionAction_Clear(generation);
  }
  public boolean is_Begin() { return this instanceof SessionAction_Begin; }
  public boolean is_Publish() { return this instanceof SessionAction_Publish; }
  public boolean is_Clear() { return this instanceof SessionAction_Clear; }
  public long dtor_generation() {
    SessionAction d = this;
    if (d instanceof SessionAction_Publish) { return ((SessionAction_Publish)d)._generation; }
    return ((SessionAction_Clear)d)._generation;
  }
  public EHBP.Token dtor_token() {
    SessionAction d = this;
    return ((SessionAction_Publish)d)._token;
  }
}
