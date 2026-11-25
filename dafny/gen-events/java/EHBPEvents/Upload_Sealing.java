// Class Upload_Sealing
// Dafny class Upload_Sealing compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Upload_Sealing extends Upload {
  public dafny.DafnySequence<? extends java.lang.Byte> _plaintext;
  public int _offset;
  public boolean _eof;
  public Upload_Sealing (dafny.DafnySequence<? extends java.lang.Byte> plaintext, int offset, boolean eof) {
    super();
    this._plaintext = plaintext;
    this._offset = offset;
    this._eof = eof;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Upload_Sealing o = (Upload_Sealing)other;
    return true && java.util.Objects.equals(this._plaintext, o._plaintext) && this._offset == o._offset && this._eof == o._eof;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._plaintext);
    hash = ((hash << 5) + hash) + java.lang.Integer.hashCode(this._offset);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._eof);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Upload.Sealing");
    s.append("(");
    s.append(dafny.Helpers.toString(this._plaintext));
    s.append(", ");
    s.append(this._offset);
    s.append(", ");
    s.append(this._eof);
    s.append(")");
    return s.toString();
  }
}
