// Class Key
// Dafny class Key compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Key {
  public Key() {
  }
  public static dafny.DafnySequence Witness = dafny.DafnySequence.Create(EHBP.uint8._typeDescriptor(), java.math.BigInteger.valueOf(32L), ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_0_i_boxed0) -> {
  java.math.BigInteger _0_i = ((java.math.BigInteger)(java.lang.Object)(_0_i_boxed0));
  return (byte) 0;
}));
  public static dafny.DafnySequence<? extends java.lang.Byte> defaultValue() {
    return Witness;
  }
  public static boolean _Is(dafny.DafnySequence<? extends java.lang.Byte> __source) {
    dafny.DafnySequence<? extends java.lang.Byte> _1_b = __source;
    return java.util.Objects.equals(java.math.BigInteger.valueOf((_1_b).length()), EHBP.__default.KeyLength());
  }
  private static final dafny.TypeDescriptor<dafny.DafnySequence<? extends java.lang.Byte>> _TYPE = dafny.TypeDescriptor.<dafny.DafnySequence<? extends java.lang.Byte>>referenceWithInitializer(dafny.DafnySequence.class, () -> Key.defaultValue());
  public static dafny.TypeDescriptor<dafny.DafnySequence<? extends java.lang.Byte>> _typeDescriptor() {
    return (dafny.TypeDescriptor<dafny.DafnySequence<? extends java.lang.Byte>>) (dafny.TypeDescriptor<?>) _TYPE;
  }
}
