// Class Stream
// Dafny class Stream compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Stream {
  public Stream() {
  }
  private static final dafny.TypeDescriptor<Stream> _TYPE = dafny.TypeDescriptor.<Stream>referenceWithInitializer(Stream.class, () -> Stream.Default());
  public static dafny.TypeDescriptor<Stream> _typeDescriptor() {
    return (dafny.TypeDescriptor<Stream>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Stream theDefault = Stream.create_RequestBody();
  public static Stream Default() {
    return theDefault;
  }
  public static Stream create_RequestBody() {
    return new Stream_RequestBody();
  }
  public static Stream create_ResponseBody() {
    return new Stream_ResponseBody();
  }
  public boolean is_RequestBody() { return this instanceof Stream_RequestBody; }
  public boolean is_ResponseBody() { return this instanceof Stream_ResponseBody; }
  public static java.util.ArrayList<Stream> AllSingletonConstructors() {
    java.util.ArrayList<Stream> singleton_iterator = new java.util.ArrayList<>();
    singleton_iterator.add(new Stream_RequestBody());
    singleton_iterator.add(new Stream_ResponseBody());
    return singleton_iterator;
  }
}
