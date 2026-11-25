// Class SessionStore
// Dafny class SessionStore compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class SessionStore {
  public long _generation;
  public EHBP.Option<EHBP.Token> _token;
  public SessionStore (long generation, EHBP.Option<EHBP.Token> token) {
    this._generation = generation;
    this._token = token;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    SessionStore o = (SessionStore)other;
    return true && this._generation == o._generation && java.util.Objects.equals(this._token, o._token);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.lang.Long.hashCode(this._generation);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._token);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.SessionStore.SessionStore");
    s.append("(");
    s.append(this._generation);
    s.append(", ");
    s.append(dafny.Helpers.toString(this._token));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<SessionStore> _TYPE = dafny.TypeDescriptor.<SessionStore>referenceWithInitializer(SessionStore.class, () -> SessionStore.Default());
  public static dafny.TypeDescriptor<SessionStore> _typeDescriptor() {
    return (dafny.TypeDescriptor<SessionStore>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final SessionStore theDefault = SessionStore.create(0L, EHBP.Option.<EHBP.Token>Default(EHBP.Token._typeDescriptor()));
  public static SessionStore Default() {
    return theDefault;
  }
  public static SessionStore create(long generation, EHBP.Option<EHBP.Token> token) {
    return new SessionStore(generation, token);
  }
  public static SessionStore create_SessionStore(long generation, EHBP.Option<EHBP.Token> token) {
    return create(generation, token);
  }
  public boolean is_SessionStore() { return true; }
  public long dtor_generation() {
    return this._generation;
  }
  public EHBP.Option<EHBP.Token> dtor_token() {
    return this._token;
  }
}
