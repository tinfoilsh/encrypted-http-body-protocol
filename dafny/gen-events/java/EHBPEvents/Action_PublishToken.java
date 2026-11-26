// Class Action_PublishToken
// Dafny class Action_PublishToken compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Action_PublishToken extends Action {
  public long _generation;
  public dafny.DafnySequence<? extends java.lang.Byte> _exportedSecret;
  public dafny.DafnySequence<? extends java.lang.Byte> _requestEnc;
  public Action_PublishToken (long generation, dafny.DafnySequence<? extends java.lang.Byte> exportedSecret, dafny.DafnySequence<? extends java.lang.Byte> requestEnc) {
    super();
    this._generation = generation;
    this._exportedSecret = exportedSecret;
    this._requestEnc = requestEnc;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Action_PublishToken o = (Action_PublishToken)other;
    return true && this._generation == o._generation && java.util.Objects.equals(this._exportedSecret, o._exportedSecret) && java.util.Objects.equals(this._requestEnc, o._requestEnc);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.lang.Long.hashCode(this._generation);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._exportedSecret);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._requestEnc);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Action.PublishToken(<redacted>)");
    return s.toString();
  }
}
