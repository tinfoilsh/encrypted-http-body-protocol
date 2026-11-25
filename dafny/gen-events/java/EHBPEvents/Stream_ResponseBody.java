// Class Stream_ResponseBody
// Dafny class Stream_ResponseBody compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Stream_ResponseBody extends Stream {
  public Stream_ResponseBody () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Stream_ResponseBody o = (Stream_ResponseBody)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Stream.ResponseBody");
    return s.toString();
  }
}
