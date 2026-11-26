// Class Json_JArray
// Dafny class Json_JArray compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Json_JArray extends Json {
  public dafny.DafnySequence<? extends Json> _items;
  public Json_JArray (dafny.DafnySequence<? extends Json> items) {
    super();
    this._items = items;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Json_JArray o = (Json_JArray)other;
    return true && java.util.Objects.equals(this._items, o._items);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 4;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._items);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Json.JArray");
    s.append("(");
    s.append(dafny.Helpers.toString(this._items));
    s.append(")");
    return s.toString();
  }
}
