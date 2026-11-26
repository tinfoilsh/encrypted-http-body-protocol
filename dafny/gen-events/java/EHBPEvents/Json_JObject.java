// Class Json_JObject
// Dafny class Json_JObject compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Json_JObject extends Json {
  public dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> _members;
  public Json_JObject (dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> members) {
    super();
    this._members = members;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Json_JObject o = (Json_JObject)other;
    return true && java.util.Objects.equals(this._members, o._members);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 5;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._members);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Json.JObject");
    s.append("(");
    s.append(dafny.Helpers.toString(this._members));
    s.append(")");
    return s.toString();
  }
}
