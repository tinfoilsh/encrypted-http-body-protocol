// Class Hpke_HSchedule
// Dafny class Hpke_HSchedule compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class Hpke_HSchedule extends Hpke {
  public java.math.BigInteger _stage;
  public Job _job;
  public dafny.DafnySequence<? extends java.lang.Byte> _enc;
  public dafny.DafnySequence<? extends java.lang.Byte> _pkR;
  public dafny.DafnySequence<? extends java.lang.Byte> _info;
  public dafny.DafnySequence<? extends java.lang.Byte> _shared;
  public dafny.DafnySequence<? extends java.lang.Byte> _pskIdHash;
  public dafny.DafnySequence<? extends java.lang.Byte> _infoHash;
  public dafny.DafnySequence<? extends java.lang.Byte> _secret;
  public dafny.DafnySequence<? extends java.lang.Byte> _key;
  public dafny.DafnySequence<? extends java.lang.Byte> _baseNonce;
  public Hpke_HSchedule (java.math.BigInteger stage, Job job, dafny.DafnySequence<? extends java.lang.Byte> enc, dafny.DafnySequence<? extends java.lang.Byte> pkR, dafny.DafnySequence<? extends java.lang.Byte> info, dafny.DafnySequence<? extends java.lang.Byte> shared, dafny.DafnySequence<? extends java.lang.Byte> pskIdHash, dafny.DafnySequence<? extends java.lang.Byte> infoHash, dafny.DafnySequence<? extends java.lang.Byte> secret, dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> baseNonce) {
    super();
    this._stage = stage;
    this._job = job;
    this._enc = enc;
    this._pkR = pkR;
    this._info = info;
    this._shared = shared;
    this._pskIdHash = pskIdHash;
    this._infoHash = infoHash;
    this._secret = secret;
    this._key = key;
    this._baseNonce = baseNonce;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Hpke_HSchedule o = (Hpke_HSchedule)other;
    return true && java.util.Objects.equals(this._stage, o._stage) && java.util.Objects.equals(this._job, o._job) && java.util.Objects.equals(this._enc, o._enc) && java.util.Objects.equals(this._pkR, o._pkR) && java.util.Objects.equals(this._info, o._info) && java.util.Objects.equals(this._shared, o._shared) && java.util.Objects.equals(this._pskIdHash, o._pskIdHash) && java.util.Objects.equals(this._infoHash, o._infoHash) && java.util.Objects.equals(this._secret, o._secret) && java.util.Objects.equals(this._key, o._key) && java.util.Objects.equals(this._baseNonce, o._baseNonce);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._stage);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._job);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._enc);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._pkR);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._info);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._shared);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._pskIdHash);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._infoHash);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._secret);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._key);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._baseNonce);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("EHBPEvents.Hpke.HSchedule(<redacted>)");
    return s.toString();
  }
}
