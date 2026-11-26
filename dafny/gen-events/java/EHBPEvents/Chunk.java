// Class Chunk
// Dafny class Chunk compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Chunk {
  public Chunk() {
  }
  public static dafny.DafnySequence Witness = dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor());
  public static dafny.DafnySequence<? extends java.lang.Byte> defaultValue() {
    return Witness;
  }
  public static boolean _Is(dafny.DafnySequence<? extends java.lang.Byte> __source) {
    dafny.DafnySequence<? extends java.lang.Byte> _4_b = __source;
    return (java.math.BigInteger.valueOf((_4_b).length())).compareTo(java.math.BigInteger.valueOf(4294967296L)) < 0;
  }
  private static final dafny.TypeDescriptor<dafny.DafnySequence<? extends java.lang.Byte>> _TYPE = dafny.TypeDescriptor.<dafny.DafnySequence<? extends java.lang.Byte>>referenceWithInitializer(dafny.DafnySequence.class, () -> Chunk.defaultValue());
  public static dafny.TypeDescriptor<dafny.DafnySequence<? extends java.lang.Byte>> _typeDescriptor() {
    return (dafny.TypeDescriptor<dafny.DafnySequence<? extends java.lang.Byte>>) (dafny.TypeDescriptor<?>) _TYPE;
  }
}
