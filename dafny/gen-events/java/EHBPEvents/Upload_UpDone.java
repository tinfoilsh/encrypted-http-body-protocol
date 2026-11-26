// Class Upload_UpDone
// Dafny class Upload_UpDone compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Upload_UpDone extends Upload {
  public Upload_UpDone () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Upload_UpDone o = (Upload_UpDone)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Upload.UpDone");
    return s.toString();
  }
}
