// Class Upload_NoUpload
// Dafny class Upload_NoUpload compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Upload_NoUpload extends Upload {
  public Upload_NoUpload () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Upload_NoUpload o = (Upload_NoUpload)other;
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
    s.append("EHBPEvents.Upload.NoUpload");
    return s.toString();
  }
}
