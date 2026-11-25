// Class Json_JString
// Dafny class Json_JString compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Json_JString extends Json {
  public dafny.DafnySequence<? extends dafny.CodePoint> _s;
  public Json_JString (dafny.DafnySequence<? extends dafny.CodePoint> s) {
    super();
    this._s = s;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Json_JString o = (Json_JString)other;
    return true && java.util.Objects.equals(this._s, o._s);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._s);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder ss = new StringBuilder();
    ss.append("EHBPEvents.Json.JString");
    ss.append("(");
    ss.append(dafny.Helpers.ToStringLiteral(this._s));
    ss.append(")");
    return ss.toString();
  }
}
