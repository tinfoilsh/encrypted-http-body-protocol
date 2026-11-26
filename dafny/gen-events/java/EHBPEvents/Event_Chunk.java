// Class Event_Chunk
// Dafny class Event_Chunk compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Event_Chunk extends Event {
  public Stream _stream;
  public dafny.DafnySequence<? extends java.lang.Byte> _data;
  public boolean _eof;
  public Event_Chunk (Stream stream, dafny.DafnySequence<? extends java.lang.Byte> data, boolean eof) {
    super();
    this._stream = stream;
    this._data = data;
    this._eof = eof;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Event_Chunk o = (Event_Chunk)other;
    return true && java.util.Objects.equals(this._stream, o._stream) && java.util.Objects.equals(this._data, o._data) && this._eof == o._eof;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 9;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._stream);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._data);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._eof);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Event.Chunk");
    s.append("(");
    s.append(dafny.Helpers.toString(this._stream));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._data));
    s.append(", ");
    s.append(this._eof);
    s.append(")");
    return s.toString();
  }
}
