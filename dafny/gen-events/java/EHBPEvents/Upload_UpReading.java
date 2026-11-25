// Class Upload_UpReading
// Dafny class Upload_UpReading compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Upload_UpReading extends Upload {
  public java.math.BigInteger _empty;
  public Upload_UpReading (java.math.BigInteger empty) {
    super();
    this._empty = empty;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Upload_UpReading o = (Upload_UpReading)other;
    return true && java.util.Objects.equals(this._empty, o._empty);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._empty);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Upload.UpReading");
    s.append("(");
    s.append(dafny.Helpers.toString(this._empty));
    s.append(")");
    return s.toString();
  }
}
