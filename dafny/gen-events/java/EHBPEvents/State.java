// Class State
// Dafny class State compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class State {
  public Phase _phase;
  public EHBP.Origin _origin;
  public dafny.DafnySequence<? extends java.lang.Byte> _publicKey;
  public dafny.DafnySequence<? extends dafny.CodePoint> _verb;
  public dafny.DafnySequence<? extends dafny.CodePoint> _url;
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _headers;
  public long _generation;
  public boolean _published;
  public EHBP.Token _token;
  public Ctx _ctx;
  public State (Phase phase, EHBP.Origin origin, dafny.DafnySequence<? extends java.lang.Byte> publicKey, dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> url, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, long generation, boolean published, EHBP.Token token, Ctx ctx) {
    this._phase = phase;
    this._origin = origin;
    this._publicKey = publicKey;
    this._verb = verb;
    this._url = url;
    this._headers = headers;
    this._generation = generation;
    this._published = published;
    this._token = token;
    this._ctx = ctx;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    State o = (State)other;
    return true && java.util.Objects.equals(this._phase, o._phase) && java.util.Objects.equals(this._origin, o._origin) && java.util.Objects.equals(this._publicKey, o._publicKey) && java.util.Objects.equals(this._verb, o._verb) && java.util.Objects.equals(this._url, o._url) && java.util.Objects.equals(this._headers, o._headers) && this._generation == o._generation && this._published == o._published && java.util.Objects.equals(this._token, o._token) && java.util.Objects.equals(this._ctx, o._ctx);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._phase);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._origin);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._publicKey);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verb);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._url);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._headers);
    hash = ((hash << 5) + hash) + java.lang.Long.hashCode(this._generation);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._published);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._token);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ctx);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.State.State");
    s.append("(");
    s.append(dafny.Helpers.toString(this._phase));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._origin));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._publicKey));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._verb));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._url));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._headers));
    s.append(", ");
    s.append(this._generation);
    s.append(", ");
    s.append(this._published);
    s.append(", ");
    s.append(dafny.Helpers.toString(this._token));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._ctx));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<State> _TYPE = dafny.TypeDescriptor.<State>referenceWithInitializer(State.class, () -> State.Default());
  public static dafny.TypeDescriptor<State> _typeDescriptor() {
    return (dafny.TypeDescriptor<State>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final State theDefault = State.create(Phase.Default(), EHBP.Origin.Default(), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> empty(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))), 0L, false, EHBP.Token.Default(), Ctx.Default());
  public static State Default() {
    return theDefault;
  }
  public static State create(Phase phase, EHBP.Origin origin, dafny.DafnySequence<? extends java.lang.Byte> publicKey, dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> url, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, long generation, boolean published, EHBP.Token token, Ctx ctx) {
    return new State(phase, origin, publicKey, verb, url, headers, generation, published, token, ctx);
  }
  public static State create_State(Phase phase, EHBP.Origin origin, dafny.DafnySequence<? extends java.lang.Byte> publicKey, dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> url, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, long generation, boolean published, EHBP.Token token, Ctx ctx) {
    return create(phase, origin, publicKey, verb, url, headers, generation, published, token, ctx);
  }
  public boolean is_State() { return true; }
  public Phase dtor_phase() {
    return this._phase;
  }
  public EHBP.Origin dtor_origin() {
    return this._origin;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_publicKey() {
    return this._publicKey;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_verb() {
    return this._verb;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_url() {
    return this._url;
  }
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> dtor_headers() {
    return this._headers;
  }
  public long dtor_generation() {
    return this._generation;
  }
  public boolean dtor_published() {
    return this._published;
  }
  public EHBP.Token dtor_token() {
    return this._token;
  }
  public Ctx dtor_ctx() {
    return this._ctx;
  }
}
