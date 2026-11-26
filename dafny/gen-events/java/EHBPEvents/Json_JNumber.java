// Class Json_JNumber
// Dafny class Json_JNumber compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Json_JNumber extends Json {
  public dafny.DafnySequence<? extends dafny.CodePoint> _raw;
  public Json_JNumber (dafny.DafnySequence<? extends dafny.CodePoint> raw) {
    super();
    this._raw = raw;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Json_JNumber o = (Json_JNumber)other;
    return true && java.util.Objects.equals(this._raw, o._raw);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._raw);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Json.JNumber");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._raw));
    s.append(")");
    return s.toString();
  }
}
