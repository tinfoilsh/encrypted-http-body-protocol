// Class Json_JBool
// Dafny class Json_JBool compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Json_JBool extends Json {
  public boolean _b;
  public Json_JBool (boolean b) {
    super();
    this._b = b;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Json_JBool o = (Json_JBool)other;
    return true && this._b == o._b;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._b);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Json.JBool");
    s.append("(");
    s.append(this._b);
    s.append(")");
    return s.toString();
  }
}
