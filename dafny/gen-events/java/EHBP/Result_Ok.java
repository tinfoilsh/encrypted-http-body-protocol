// Class Result_Ok<T>
// Dafny class Result_Ok<T> compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Result_Ok<T> extends Result<T> {
  public T _value;
  public Result_Ok (dafny.TypeDescriptor<T> _td_T, T value) {
    super(_td_T);
    this._value = value;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Result_Ok<T> o = (Result_Ok<T>)other;
    return true && java.util.Objects.equals(this._value, o._value);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._value);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Result.Ok");
    s.append("(");
    s.append(dafny.Helpers.toString(this._value));
    s.append(")");
    return s.toString();
  }
}
