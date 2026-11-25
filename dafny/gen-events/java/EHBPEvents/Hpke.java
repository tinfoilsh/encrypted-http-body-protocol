// Class Hpke
// Dafny class Hpke compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Hpke {
  public Hpke() {
  }
  private static final dafny.TypeDescriptor<Hpke> _TYPE = dafny.TypeDescriptor.<Hpke>referenceWithInitializer(Hpke.class, () -> Hpke.Default());
  public static dafny.TypeDescriptor<Hpke> _typeDescriptor() {
    return (dafny.TypeDescriptor<Hpke>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Hpke theDefault = Hpke.create_HRandom(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()));
  public static Hpke Default() {
    return theDefault;
  }
  public static Hpke create_HRandom(dafny.DafnySequence<? extends java.lang.Byte> pkR, dafny.DafnySequence<? extends java.lang.Byte> info) {
    return new Hpke_HRandom(pkR, info);
  }
  public static Hpke create_HEnc(dafny.DafnySequence<? extends java.lang.Byte> skE, dafny.DafnySequence<? extends java.lang.Byte> pkR, dafny.DafnySequence<? extends java.lang.Byte> info) {
    return new Hpke_HEnc(skE, pkR, info);
  }
  public static Hpke create_HDh(dafny.DafnySequence<? extends java.lang.Byte> enc, dafny.DafnySequence<? extends java.lang.Byte> pkR, dafny.DafnySequence<? extends java.lang.Byte> info) {
    return new Hpke_HDh(enc, pkR, info);
  }
  public static Hpke create_HSchedule(java.math.BigInteger stage, Job job, dafny.DafnySequence<? extends java.lang.Byte> enc, dafny.DafnySequence<? extends java.lang.Byte> pkR, dafny.DafnySequence<? extends java.lang.Byte> info, dafny.DafnySequence<? extends java.lang.Byte> shared, dafny.DafnySequence<? extends java.lang.Byte> pskIdHash, dafny.DafnySequence<? extends java.lang.Byte> infoHash, dafny.DafnySequence<? extends java.lang.Byte> secret, dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> baseNonce) {
    return new Hpke_HSchedule(stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce);
  }
  public boolean is_HRandom() { return this instanceof Hpke_HRandom; }
  public boolean is_HEnc() { return this instanceof Hpke_HEnc; }
  public boolean is_HDh() { return this instanceof Hpke_HDh; }
  public boolean is_HSchedule() { return this instanceof Hpke_HSchedule; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_pkR() {
    Hpke d = this;
    if (d instanceof Hpke_HRandom) { return ((Hpke_HRandom)d)._pkR; }
    if (d instanceof Hpke_HEnc) { return ((Hpke_HEnc)d)._pkR; }
    if (d instanceof Hpke_HDh) { return ((Hpke_HDh)d)._pkR; }
    return ((Hpke_HSchedule)d)._pkR;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_info() {
    Hpke d = this;
    if (d instanceof Hpke_HRandom) { return ((Hpke_HRandom)d)._info; }
    if (d instanceof Hpke_HEnc) { return ((Hpke_HEnc)d)._info; }
    if (d instanceof Hpke_HDh) { return ((Hpke_HDh)d)._info; }
    return ((Hpke_HSchedule)d)._info;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_skE() {
    Hpke d = this;
    return ((Hpke_HEnc)d)._skE;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_enc() {
    Hpke d = this;
    if (d instanceof Hpke_HDh) { return ((Hpke_HDh)d)._enc; }
    return ((Hpke_HSchedule)d)._enc;
  }
  public java.math.BigInteger dtor_stage() {
    Hpke d = this;
    return ((Hpke_HSchedule)d)._stage;
  }
  public Job dtor_job() {
    Hpke d = this;
    return ((Hpke_HSchedule)d)._job;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_shared() {
    Hpke d = this;
    return ((Hpke_HSchedule)d)._shared;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_pskIdHash() {
    Hpke d = this;
    return ((Hpke_HSchedule)d)._pskIdHash;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_infoHash() {
    Hpke d = this;
    return ((Hpke_HSchedule)d)._infoHash;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_secret() {
    Hpke d = this;
    return ((Hpke_HSchedule)d)._secret;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_key() {
    Hpke d = this;
    return ((Hpke_HSchedule)d)._key;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_baseNonce() {
    Hpke d = this;
    return ((Hpke_HSchedule)d)._baseNonce;
  }
}
