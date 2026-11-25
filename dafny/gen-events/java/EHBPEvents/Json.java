// Class Json
// Dafny class Json compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Json {
  public Json() {
  }
  private static final dafny.TypeDescriptor<Json> _TYPE = dafny.TypeDescriptor.<Json>referenceWithInitializer(Json.class, () -> Json.Default());
  public static dafny.TypeDescriptor<Json> _typeDescriptor() {
    return (dafny.TypeDescriptor<Json>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Json theDefault = Json.create_JNull();
  public static Json Default() {
    return theDefault;
  }
  public static Json create_JNull() {
    return new Json_JNull();
  }
  public static Json create_JBool(boolean b) {
    return new Json_JBool(b);
  }
  public static Json create_JNumber(dafny.DafnySequence<? extends dafny.CodePoint> raw) {
    return new Json_JNumber(raw);
  }
  public static Json create_JString(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return new Json_JString(s);
  }
  public static Json create_JArray(dafny.DafnySequence<? extends Json> items) {
    return new Json_JArray(items);
  }
  public static Json create_JObject(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> members) {
    return new Json_JObject(members);
  }
  public boolean is_JNull() { return this instanceof Json_JNull; }
  public boolean is_JBool() { return this instanceof Json_JBool; }
  public boolean is_JNumber() { return this instanceof Json_JNumber; }
  public boolean is_JString() { return this instanceof Json_JString; }
  public boolean is_JArray() { return this instanceof Json_JArray; }
  public boolean is_JObject() { return this instanceof Json_JObject; }
  public boolean dtor_b() {
    Json d = this;
    return ((Json_JBool)d)._b;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_raw() {
    Json d = this;
    return ((Json_JNumber)d)._raw;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_s() {
    Json d = this;
    return ((Json_JString)d)._s;
  }
  public dafny.DafnySequence<? extends Json> dtor_items() {
    Json d = this;
    return ((Json_JArray)d)._items;
  }
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> dtor_members() {
    Json d = this;
    return ((Json_JObject)d)._members;
  }
}
