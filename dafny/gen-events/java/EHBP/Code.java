// Class Code
// Dafny class Code compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Code {
  public Code() {
  }
  private static final dafny.TypeDescriptor<Code> _TYPE = dafny.TypeDescriptor.<Code>referenceWithInitializer(Code.class, () -> Code.Default());
  public static dafny.TypeDescriptor<Code> _typeDescriptor() {
    return (dafny.TypeDescriptor<Code>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Code theDefault = Code.create_InvalidKeyConfig();
  public static Code Default() {
    return theDefault;
  }
  public static Code create_InvalidKeyConfig() {
    return new Code_InvalidKeyConfig();
  }
  public static Code create_UnsupportedSuite() {
    return new Code_UnsupportedSuite();
  }
  public static Code create_InvalidEncapsulatedKey() {
    return new Code_InvalidEncapsulatedKey();
  }
  public static Code create_HpkeSetupFailed() {
    return new Code_HpkeSetupFailed();
  }
  public static Code create_MissingResponseNonce() {
    return new Code_MissingResponseNonce();
  }
  public static Code create_UnexpectedRedirect() {
    return new Code_UnexpectedRedirect();
  }
  public static Code create_InvalidResponseNonce() {
    return new Code_InvalidResponseNonce();
  }
  public static Code create_DuplicateResponseNonce() {
    return new Code_DuplicateResponseNonce();
  }
  public static Code create_KeyConfigMismatch() {
    return new Code_KeyConfigMismatch();
  }
  public static Code create_FramingTruncated() {
    return new Code_FramingTruncated();
  }
  public static Code create_ChunkTooLarge() {
    return new Code_ChunkTooLarge();
  }
  public static Code create_AeadDecryptFailed() {
    return new Code_AeadDecryptFailed();
  }
  public static Code create_SequenceOverflow() {
    return new Code_SequenceOverflow();
  }
  public static Code create_InvalidToken() {
    return new Code_InvalidToken();
  }
  public static Code create_InvalidInput() {
    return new Code_InvalidInput();
  }
  public static Code create_Transport() {
    return new Code_Transport();
  }
  public boolean is_InvalidKeyConfig() { return this instanceof Code_InvalidKeyConfig; }
  public boolean is_UnsupportedSuite() { return this instanceof Code_UnsupportedSuite; }
  public boolean is_InvalidEncapsulatedKey() { return this instanceof Code_InvalidEncapsulatedKey; }
  public boolean is_HpkeSetupFailed() { return this instanceof Code_HpkeSetupFailed; }
  public boolean is_MissingResponseNonce() { return this instanceof Code_MissingResponseNonce; }
  public boolean is_UnexpectedRedirect() { return this instanceof Code_UnexpectedRedirect; }
  public boolean is_InvalidResponseNonce() { return this instanceof Code_InvalidResponseNonce; }
  public boolean is_DuplicateResponseNonce() { return this instanceof Code_DuplicateResponseNonce; }
  public boolean is_KeyConfigMismatch() { return this instanceof Code_KeyConfigMismatch; }
  public boolean is_FramingTruncated() { return this instanceof Code_FramingTruncated; }
  public boolean is_ChunkTooLarge() { return this instanceof Code_ChunkTooLarge; }
  public boolean is_AeadDecryptFailed() { return this instanceof Code_AeadDecryptFailed; }
  public boolean is_SequenceOverflow() { return this instanceof Code_SequenceOverflow; }
  public boolean is_InvalidToken() { return this instanceof Code_InvalidToken; }
  public boolean is_InvalidInput() { return this instanceof Code_InvalidInput; }
  public boolean is_Transport() { return this instanceof Code_Transport; }
  public static java.util.ArrayList<Code> AllSingletonConstructors() {
    java.util.ArrayList<Code> singleton_iterator = new java.util.ArrayList<>();
    singleton_iterator.add(new Code_InvalidKeyConfig());
    singleton_iterator.add(new Code_UnsupportedSuite());
    singleton_iterator.add(new Code_InvalidEncapsulatedKey());
    singleton_iterator.add(new Code_HpkeSetupFailed());
    singleton_iterator.add(new Code_MissingResponseNonce());
    singleton_iterator.add(new Code_UnexpectedRedirect());
    singleton_iterator.add(new Code_InvalidResponseNonce());
    singleton_iterator.add(new Code_DuplicateResponseNonce());
    singleton_iterator.add(new Code_KeyConfigMismatch());
    singleton_iterator.add(new Code_FramingTruncated());
    singleton_iterator.add(new Code_ChunkTooLarge());
    singleton_iterator.add(new Code_AeadDecryptFailed());
    singleton_iterator.add(new Code_SequenceOverflow());
    singleton_iterator.add(new Code_InvalidToken());
    singleton_iterator.add(new Code_InvalidInput());
    singleton_iterator.add(new Code_Transport());
    return singleton_iterator;
  }
}
