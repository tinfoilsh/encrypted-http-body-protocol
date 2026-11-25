// Class NonceBase
// Dafny class NonceBase compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class NonceBase {
  public NonceBase() {
  }
  public static dafny.DafnySequence Witness = dafny.DafnySequence.Create(EHBP.uint8._typeDescriptor(), java.math.BigInteger.valueOf(12L), ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_2_i_boxed0) -> {
  java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
  return (byte) 0;
}));
  public static dafny.DafnySequence<? extends java.lang.Byte> defaultValue() {
    return Witness;
  }
  public static boolean _Is(dafny.DafnySequence<? extends java.lang.Byte> __source) {
    dafny.DafnySequence<? extends java.lang.Byte> _3_b = __source;
    return java.util.Objects.equals(java.math.BigInteger.valueOf((_3_b).length()), EHBP.__default.NonceLength());
  }
  private static final dafny.TypeDescriptor<dafny.DafnySequence<? extends java.lang.Byte>> _TYPE = dafny.TypeDescriptor.<dafny.DafnySequence<? extends java.lang.Byte>>referenceWithInitializer(dafny.DafnySequence.class, () -> NonceBase.defaultValue());
  public static dafny.TypeDescriptor<dafny.DafnySequence<? extends java.lang.Byte>> _typeDescriptor() {
    return (dafny.TypeDescriptor<dafny.DafnySequence<? extends java.lang.Byte>>) (dafny.TypeDescriptor<?>) _TYPE;
  }
}
