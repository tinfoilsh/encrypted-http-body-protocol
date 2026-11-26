// Class Option<T>
// Dafny class Option<T> compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Option<T> {
  protected dafny.TypeDescriptor<T> _td_T;
  public Option(dafny.TypeDescriptor<T> _td_T) {
    this._td_T = _td_T;
  }
  public static <T> dafny.TypeDescriptor<Option<T>> _typeDescriptor(dafny.TypeDescriptor<T> _td_T) {
    return (dafny.TypeDescriptor<Option<T>>) (dafny.TypeDescriptor<?>) dafny.TypeDescriptor.<Option<T>>referenceWithInitializer(Option.class, () -> Option.<T>Default(_td_T));
  }

  public static <T> Option<T> Default(dafny.TypeDescriptor<T> _td_T) {
    return Option.<T>create_None(_td_T);
  }
  public static <T> Option<T> create_None(dafny.TypeDescriptor<T> _td_T) {
    return new Option_None<T>(_td_T);
  }
  public static <T> Option<T> create_Some(dafny.TypeDescriptor<T> _td_T, T value) {
    return new Option_Some<T>(_td_T, value);
  }
  public boolean is_None() { return this instanceof Option_None; }
  public boolean is_Some() { return this instanceof Option_Some; }
  public T dtor_value() {
    Option<T> d = this;
    return ((Option_Some<T>)d)._value;
  }
}
