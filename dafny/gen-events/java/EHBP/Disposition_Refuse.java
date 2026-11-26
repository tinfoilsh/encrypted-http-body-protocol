// Class Disposition_Refuse
// Dafny class Disposition_Refuse compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class Disposition_Refuse extends Disposition {
  public Code _code;
  public dafny.DafnySequence<? extends dafny.CodePoint> _message;
  public Disposition_Refuse (Code code, dafny.DafnySequence<? extends dafny.CodePoint> message) {
    super();
    this._code = code;
    this._message = message;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Disposition_Refuse o = (Disposition_Refuse)other;
    return true && java.util.Objects.equals(this._code, o._code) && java.util.Objects.equals(this._message, o._message);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._code);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._message);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBP.Disposition.Refuse");
    s.append("(");
    s.append(dafny.Helpers.toString(this._code));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._message));
    s.append(")");
    return s.toString();
  }
}
