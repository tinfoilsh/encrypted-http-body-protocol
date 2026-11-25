// Class Performed_Got
// Dafny class Performed_Got compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Performed_Got extends Performed {
  public Event _e;
  public Performed_Got (Event e) {
    super();
    this._e = e;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Performed_Got o = (Performed_Got)other;
    return true && java.util.Objects.equals(this._e, o._e);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._e);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Performed.Got");
    s.append("(");
    s.append(dafny.Helpers.toString(this._e));
    s.append(")");
    return s.toString();
  }
}
