// Class Result<T>
// Dafny class Result<T> compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Result<T> {
  protected dafny.TypeDescriptor<T> _td_T;
  public Result(dafny.TypeDescriptor<T> _td_T) {
    this._td_T = _td_T;
  }
  public static <T> dafny.TypeDescriptor<Result<T>> _typeDescriptor(dafny.TypeDescriptor<T> _td_T) {
    return (dafny.TypeDescriptor<Result<T>>) (dafny.TypeDescriptor<?>) dafny.TypeDescriptor.<Result<T>>referenceWithInitializer(Result.class, () -> Result.<T>Default(_td_T));
  }

  public static <T> Result<T> Default(dafny.TypeDescriptor<T> _td_T) {
    return Result.<T>create_Err(_td_T, Code.Default(), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
  }
  public static <T> Result<T> create_Ok(dafny.TypeDescriptor<T> _td_T, T value) {
    return new Result_Ok<T>(_td_T, value);
  }
  public static <T> Result<T> create_Err(dafny.TypeDescriptor<T> _td_T, Code code, dafny.DafnySequence<? extends dafny.CodePoint> message) {
    return new Result_Err<T>(_td_T, code, message);
  }
  public boolean is_Ok() { return this instanceof Result_Ok; }
  public boolean is_Err() { return this instanceof Result_Err; }
  public T dtor_value() {
    Result<T> d = this;
    return ((Result_Ok<T>)d)._value;
  }
  public Code dtor_code() {
    Result<T> d = this;
    return ((Result_Err<T>)d)._code;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_message() {
    Result<T> d = this;
    return ((Result_Err<T>)d)._message;
  }
}
