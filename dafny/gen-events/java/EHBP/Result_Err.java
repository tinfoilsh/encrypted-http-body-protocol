// Class Result_Err<T>
// Dafny class Result_Err<T> compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Result_Err<T> extends Result<T> {
  public Code _code;
  public dafny.DafnySequence<? extends dafny.CodePoint> _message;
  public Result_Err (dafny.TypeDescriptor<T> _td_T, Code code, dafny.DafnySequence<? extends dafny.CodePoint> message) {
    super(_td_T);
    this._code = code;
    this._message = message;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Result_Err<T> o = (Result_Err<T>)other;
    return true && java.util.Objects.equals(this._code, o._code) && java.util.Objects.equals(this._message, o._message);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._code);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._message);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Result.Err");
    s.append("(");
    s.append(dafny.Helpers.toString(this._code));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._message));
    s.append(")");
    return s.toString();
  }
}
