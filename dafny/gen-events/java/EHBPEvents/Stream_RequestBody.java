// Class Stream_RequestBody
// Dafny class Stream_RequestBody compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Stream_RequestBody extends Stream {
  public Stream_RequestBody () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Stream_RequestBody o = (Stream_RequestBody)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Stream.RequestBody");
    return s.toString();
  }
}
