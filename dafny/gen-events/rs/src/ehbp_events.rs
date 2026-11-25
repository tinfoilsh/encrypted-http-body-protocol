#![allow(warnings, unconditional_panic)]
#![allow(nonstandard_style)]
#![cfg_attr(any(), rustfmt::skip)]

pub mod _module {
    
}
/// ehbp.dfy(8,1)
pub mod EHBP {
    pub use ::dafny_runtime::Sequence;
    pub use ::std::sync::Arc;
    pub use ::dafny_runtime::int;
    pub use ::dafny_runtime::string_of;
    pub use ::dafny_runtime::DafnyChar;
    pub use crate::EHBP::Code::InvalidKeyConfig;
    pub use crate::EHBP::Code::UnsupportedSuite;
    pub use crate::EHBP::Code::InvalidEncapsulatedKey;
    pub use crate::EHBP::Code::HpkeSetupFailed;
    pub use crate::EHBP::Code::MissingResponseNonce;
    pub use crate::EHBP::Code::UnexpectedRedirect;
    pub use crate::EHBP::Code::InvalidResponseNonce;
    pub use crate::EHBP::Code::DuplicateResponseNonce;
    pub use crate::EHBP::Code::KeyConfigMismatch;
    pub use crate::EHBP::Code::FramingTruncated;
    pub use crate::EHBP::Code::ChunkTooLarge;
    pub use crate::EHBP::Code::AeadDecryptFailed;
    pub use crate::EHBP::Code::SequenceOverflow;
    pub use crate::EHBP::Code::InvalidToken;
    pub use crate::EHBP::Code::InvalidInput;
    pub use ::dafny_runtime::_System::nat;
    pub use ::dafny_runtime::seq;
    pub use ::dafny_runtime::integer_range;
    pub use ::dafny_runtime::DafnyInt;
    pub use ::std::marker::Sync;
    pub use ::std::marker::Send;
    pub use ::dafny_runtime::truncate;
    pub use ::dafny_runtime::Zero;
    pub use ::std::primitive::char;
    pub use ::dafny_runtime::NumCast;
    pub use crate::EHBP::Option::Some;
    pub use ::dafny_runtime::euclidian_modulo;
    pub use ::dafny_runtime::euclidian_division;
    pub use crate::EHBP::Result::Ok;
    pub use crate::EHBP::Option::None;
    pub use crate::EHBP::Result::Err;
    pub use ::std::cmp::PartialEq;
    pub use ::std::cmp::Eq;
    pub use ::std::hash::Hash;
    pub use ::std::hash::Hasher;
    pub use ::std::default::Default;
    pub use ::dafny_runtime::DafnyPrint;
    pub use ::std::fmt::Formatter;
    pub use ::std::ops::Deref;
    pub use ::std::mem::transmute;
    pub use ::std::ops::Add;
    pub use ::std::ops::Sub;
    pub use ::std::ops::Mul;
    pub use ::std::ops::Div;
    pub use ::std::cmp::PartialOrd;
    pub use ::std::cmp::Ordering;
    pub use ::std::fmt::Debug;
    pub use ::dafny_runtime::SequenceIter;
    pub use ::std::convert::AsRef;
    pub use ::dafny_runtime::DafnyType;

    pub struct _default {}

    impl _default {
        /// ehbp.dfy(18,3)
        pub fn CheckPublicKey(b: &Sequence<u8>) -> Arc<Result<PublicKey>> {
            if b.cardinality() == int!(32) {
                let mut key: PublicKey = b.clone();
                Arc::new(Result::Ok::<PublicKey> {
                        value: key.clone()
                    })
            } else {
                Arc::new(Result::Err::<PublicKey> {
                        code: Arc::new(Code::InvalidKeyConfig {}),
                        message: string_of("public key must be 32 bytes")
                    })
            }
        }
        /// ehbp.dfy(44,3)
        pub fn CodeString(c: &Arc<Code>) -> Sequence<DafnyChar> {
            let mut _source0: Arc<Code> = c.clone();
            if matches!((&_source0).as_ref(), InvalidKeyConfig{ .. }) {
                string_of("INVALID_KEY_CONFIG")
            } else {
                if matches!((&_source0).as_ref(), UnsupportedSuite{ .. }) {
                    string_of("UNSUPPORTED_SUITE")
                } else {
                    if matches!((&_source0).as_ref(), InvalidEncapsulatedKey{ .. }) {
                        string_of("INVALID_ENCAPSULATED_KEY")
                    } else {
                        if matches!((&_source0).as_ref(), HpkeSetupFailed{ .. }) {
                            string_of("HPKE_SETUP_FAILED")
                        } else {
                            if matches!((&_source0).as_ref(), MissingResponseNonce{ .. }) {
                                string_of("MISSING_RESPONSE_NONCE")
                            } else {
                                if matches!((&_source0).as_ref(), UnexpectedRedirect{ .. }) {
                                    string_of("UNEXPECTED_REDIRECT")
                                } else {
                                    if matches!((&_source0).as_ref(), InvalidResponseNonce{ .. }) {
                                        string_of("INVALID_RESPONSE_NONCE")
                                    } else {
                                        if matches!((&_source0).as_ref(), DuplicateResponseNonce{ .. }) {
                                            string_of("DUPLICATE_RESPONSE_NONCE")
                                        } else {
                                            if matches!((&_source0).as_ref(), KeyConfigMismatch{ .. }) {
                                                string_of("KEY_CONFIG_MISMATCH")
                                            } else {
                                                if matches!((&_source0).as_ref(), FramingTruncated{ .. }) {
                                                    string_of("FRAMING_TRUNCATED")
                                                } else {
                                                    if matches!((&_source0).as_ref(), ChunkTooLarge{ .. }) {
                                                        string_of("CHUNK_TOO_LARGE")
                                                    } else {
                                                        if matches!((&_source0).as_ref(), AeadDecryptFailed{ .. }) {
                                                            string_of("AEAD_DECRYPT_FAILED")
                                                        } else {
                                                            if matches!((&_source0).as_ref(), SequenceOverflow{ .. }) {
                                                                string_of("SEQUENCE_OVERFLOW")
                                                            } else {
                                                                if matches!((&_source0).as_ref(), InvalidToken{ .. }) {
                                                                    string_of("INVALID_TOKEN")
                                                                } else {
                                                                    if matches!((&_source0).as_ref(), InvalidInput{ .. }) {
                                                                        string_of("INVALID_INPUT")
                                                                    } else {
                                                                        string_of("")
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp.dfy(115,3)
        pub fn U16(b: &Sequence<u8>, i: &nat) -> u16 {
            b.get(i) as u16 * 256 + b.get(&(i.clone() + int!(1))) as u16
        }
        /// ehbp.dfy(121,3)
        pub fn U32(b: &Sequence<u8>, i: &nat) -> u32 {
            _default::U16(b, i) as u32 * 65536 + _default::U16(b, &(i.clone() + int!(2))) as u32
        }
        /// ehbp.dfy(127,3)
        pub fn BE16(v: u16) -> Sequence<u8> {
            seq![(v / 256) as u8, (v % 256) as u8]
        }
        /// ehbp.dfy(133,3)
        pub fn BE32(v: u32) -> Sequence<u8> {
            _default::BE16((v / 65536) as u16).concat(&_default::BE16((v % 65536) as u16))
        }
        /// ehbp.dfy(139,3)
        pub fn IsAscii(s: &Sequence<DafnyChar>) -> bool {
            integer_range(int!(0), s.cardinality()).all(({
                    let mut s = s.clone();
                    Arc::new(move |__forall_var_0: DafnyInt| -> bool{
            let mut i: DafnyInt = __forall_var_0.clone();
            !(int!(0) <= i.clone() && i.clone() < s.cardinality()) || int!(s.get(&i).0) < int!(128)
        }) as Arc<dyn ::std::ops::Fn(_) -> _ + Sync + Send>
                }).as_ref())
        }
        /// ehbp.dfy(141,3)
        pub fn Ascii(s: &Sequence<DafnyChar>) -> Sequence<u8> {
            {
                let _initializer = {
                        let s: Sequence<DafnyChar> = s.clone();
                        {
                            let mut s = s.clone();
                            Arc::new(move |i: &DafnyInt| -> u8{
            truncate!(int!(s.get(i).0), u8)
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + Send>
                        }
                    };
                integer_range(Zero::zero(), s.cardinality()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
            }
        }
        /// ehbp.dfy(148,3)
        pub fn LowerChar(c: &DafnyChar) -> DafnyChar {
            if DafnyChar(char::from_u32(65).unwrap()) <= c.clone() && c.clone() <= DafnyChar(char::from_u32(90).unwrap()) {
                DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(c.clone().0) + int!(32)).unwrap()).unwrap())
            } else {
                c.clone()
            }
        }
        /// ehbp.dfy(153,3)
        pub fn Lower(s: &Sequence<DafnyChar>) -> Sequence<DafnyChar> {
            {
                let _initializer = {
                        let s: Sequence<DafnyChar> = s.clone();
                        {
                            let mut s = s.clone();
                            Arc::new(move |i: &DafnyInt| -> DafnyChar{
            _default::LowerChar(&s.get(i))
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + Send>
                        }
                    };
                integer_range(Zero::zero(), s.cardinality()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
            }
        }
        /// ehbp.dfy(159,3)
        pub fn EqualFold(a: &Sequence<DafnyChar>, b: &Sequence<DafnyChar>) -> bool {
            _default::Lower(a) == _default::Lower(b)
        }
        /// ehbp.dfy(161,3)
        pub fn IsSpace(c: &DafnyChar) -> bool {
            c.clone() == DafnyChar(char::from_u32(32).unwrap()) || c.clone() == DafnyChar(char::from_u32(9).unwrap())
        }
        /// ehbp.dfy(163,3)
        pub fn TrimLeft(s: &Sequence<DafnyChar>) -> Sequence<DafnyChar> {
            let mut _r0 = s.clone();
            'TAIL_CALL_START: loop {
                let s = _r0;
                if int!(0) < s.cardinality() && _default::IsSpace(&s.get(&int!(0))) {
                    let mut _in0: Sequence<DafnyChar> = s.drop(&int!(1));
                    _r0 = _in0.clone();
                    continue 'TAIL_CALL_START;
                } else {
                    return s.clone();
                }
            }
        }
        /// ehbp.dfy(169,3)
        pub fn TrimRight(s: &Sequence<DafnyChar>) -> Sequence<DafnyChar> {
            let mut _r0 = s.clone();
            'TAIL_CALL_START: loop {
                let s = _r0;
                if int!(0) < s.cardinality() && _default::IsSpace(&s.get(&(s.cardinality() - int!(1)))) {
                    let mut _in0: Sequence<DafnyChar> = s.take(&(s.cardinality() - int!(1)));
                    _r0 = _in0.clone();
                    continue 'TAIL_CALL_START;
                } else {
                    return s.clone();
                }
            }
        }
        /// ehbp.dfy(175,3)
        pub fn Trim(s: &Sequence<DafnyChar>) -> Sequence<DafnyChar> {
            _default::TrimRight(&_default::TrimLeft(s))
        }
        /// ehbp.dfy(177,3)
        pub fn Before(s: &Sequence<DafnyChar>, sep: &DafnyChar) -> Sequence<DafnyChar> {
            _default::BeforeFrom(s, sep, &int!(0))
        }
        /// ehbp.dfy(182,3)
        pub fn BeforeFrom(s: &Sequence<DafnyChar>, sep: &DafnyChar, i: &nat) -> Sequence<DafnyChar> {
            let mut _r0 = s.clone();
            let mut _r1 = sep.clone();
            let mut _r2 = i.clone();
            'TAIL_CALL_START: loop {
                let s = _r0;
                let sep = _r1;
                let i = _r2;
                if i.clone() == s.cardinality() || s.get(&i) == sep.clone() {
                    return s.take(&i);
                } else {
                    let mut _in0: Sequence<DafnyChar> = s.clone();
                    let mut _in1: DafnyChar = sep.clone();
                    let mut _in2: DafnyInt = i.clone() + int!(1);
                    _r0 = _in0.clone();
                    _r1 = _in1.clone();
                    _r2 = _in2.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp.dfy(190,3)
        pub fn MediaType(contentType: &Sequence<DafnyChar>) -> Sequence<DafnyChar> {
            _default::Lower(&_default::Trim(&_default::Before(contentType, &DafnyChar(char::from_u32(59).unwrap()))))
        }
        /// ehbp.dfy(192,3)
        pub fn HasMediaType(contentType: &Arc<Option<Sequence<DafnyChar>>>, want: &Sequence<DafnyChar>) -> bool {
            matches!(contentType.as_ref(), Some{ .. }) && _default::MediaType(contentType.value()) == _default::Lower(want)
        }
        /// ehbp.dfy(197,3)
        pub fn HexDigitValue(c: &DafnyChar) -> Arc<Option<u8>> {
            if DafnyChar(char::from_u32(48).unwrap()) <= c.clone() && c.clone() <= DafnyChar(char::from_u32(57).unwrap()) {
                Arc::new(Option::Some::<u8> {
                        value: truncate!(int!(c.clone().0) - int!(DafnyChar(char::from_u32(48).unwrap()).0), u8)
                    })
            } else {
                if DafnyChar(char::from_u32(97).unwrap()) <= c.clone() && c.clone() <= DafnyChar(char::from_u32(102).unwrap()) {
                    Arc::new(Option::Some::<u8> {
                            value: truncate!(int!(c.clone().0) - int!(DafnyChar(char::from_u32(97).unwrap()).0) + int!(10), u8)
                        })
                } else {
                    if DafnyChar(char::from_u32(65).unwrap()) <= c.clone() && c.clone() <= DafnyChar(char::from_u32(70).unwrap()) {
                        Arc::new(Option::Some::<u8> {
                                value: truncate!(int!(c.clone().0) - int!(DafnyChar(char::from_u32(65).unwrap()).0) + int!(10), u8)
                            })
                    } else {
                        Arc::new(Option::None::<u8> {})
                    }
                }
            }
        }
        /// ehbp.dfy(207,3)
        pub fn IsHex(s: &Sequence<DafnyChar>) -> bool {
            euclidian_modulo(s.cardinality(), int!(2)) == int!(0) && integer_range(int!(0), s.cardinality()).all(({
                    let mut s = s.clone();
                    Arc::new(move |__forall_var_0: DafnyInt| -> bool{
            let mut i: DafnyInt = __forall_var_0.clone();
            !(int!(0) <= i.clone() && i.clone() < s.cardinality()) || matches!((&_default::HexDigitValue(&s.get(&i))).as_ref(), Some{ .. })
        }) as Arc<dyn ::std::ops::Fn(_) -> _ + Sync + Send>
                }).as_ref())
        }
        /// ehbp.dfy(209,3)
        pub fn DecodeHex(s: &Sequence<DafnyChar>) -> Arc<Option<Sequence<u8>>> {
            if !_default::IsHex(s) {
                Arc::new(Option::None::<Sequence<u8>> {})
            } else {
                Arc::new(Option::Some::<Sequence<u8>> {
                        value: {
                                let _initializer = {
                                        let s: Sequence<DafnyChar> = s.clone();
                                        {
                                            let mut s = s.clone();
                                            Arc::new(move |i: &DafnyInt| -> u8{
            _default::HexDigitValue(&s.get(&(int!(2) * i.clone()))).value().clone() * 16 + _default::HexDigitValue(&s.get(&(int!(2) * i.clone() + int!(1)))).value().clone()
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + Send>
                                        }
                                    };
                                integer_range(Zero::zero(), euclidian_division(s.cardinality(), int!(2))).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
                            }
                    })
            }
        }
        /// ehbp.dfy(219,3)
        pub fn EncodeHex(b: &Sequence<u8>) -> Sequence<DafnyChar> {
            {
                let _initializer = {
                        let b: Sequence<u8> = b.clone();
                        {
                            let mut b = b.clone();
                            Arc::new(move |i: &DafnyInt| -> DafnyChar{
            if euclidian_modulo(i.clone(), int!(2)) == int!(0) {
                _default::HexDigits().get(&euclidian_division(int!(b.get(&euclidian_division(i.clone(), int!(2)))), int!(16)))
            } else {
                _default::HexDigits().get(&euclidian_modulo(int!(b.get(&euclidian_division(i.clone(), int!(2)))), int!(16)))
            }
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + Send>
                        }
                    };
                integer_range(Zero::zero(), int!(2) * b.cardinality()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
            }
        }
        /// ehbp.dfy(231,3)
        pub fn ComputeNonce(nonceBase: &Sequence<u8>, seqNo: u64) -> Sequence<u8> {
            {
                let _initializer = {
                        let nonceBase: Sequence<u8> = nonceBase.clone();
                        let seqNo: u64 = seqNo;
                        {
                            let mut seqNo = seqNo.clone();
                            let mut nonceBase = nonceBase.clone();
                            Arc::new(move |i: &DafnyInt| -> u8{
            {
                let __pat_let0_0: u32 = truncate!(i.clone(), u32);
                {
                    let j: u32 = __pat_let0_0;
                    if j < 4 {
                        nonceBase.get(&int!((&j).clone()))
                    } else {
                        (nonceBase.get(&int!((&j).clone())) as u8 ^ _default::ByteAt(seqNo, 11 - j) as u8) as u8
                    }
                }
            }
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + Send>
                        }
                    };
                integer_range(Zero::zero(), _default::NonceLength()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
            }
        }
        /// ehbp.dfy(241,3)
        pub fn NonceFor(nonceBase: &Sequence<u8>, seqNo: u64) -> Arc<Result<Sequence<u8>>> {
            if nonceBase.cardinality() != _default::NonceLength() {
                Arc::new(Result::Err::<Sequence<u8>> {
                        code: Arc::new(Code::InvalidInput {}),
                        message: string_of("nonce base must be 12 bytes")
                    })
            } else {
                Arc::new(Result::Ok::<Sequence<u8>> {
                        value: _default::ComputeNonce(nonceBase, seqNo)
                    })
            }
        }
        /// ehbp.dfy(248,3)
        pub fn ByteAt(x: u64, k: u32) -> u8 {
            let mut _r0 = x;
            let mut _r1 = k;
            'TAIL_CALL_START: loop {
                let x = _r0;
                let k = _r1;
                if k == 0 {
                    return (x % 256) as u8;
                } else {
                    let mut _in0: u64 = x / 256;
                    let mut _in1: u32 = k - 1;
                    _r0 = _in0;
                    _r1 = _in1;
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp.dfy(264,3)
        pub fn KnownKdf(id: u16) -> bool {
            id == 1 || id == 2 || id == 3
        }
        /// ehbp.dfy(265,3)
        pub fn KnownAead(id: u16) -> bool {
            id == 1 || id == 2 || id == 3
        }
        /// ehbp.dfy(267,3)
        pub fn ParseConfig(data: &Sequence<u8>) -> Arc<Result<Sequence<u8>>> {
            if data.cardinality() < int!(3) {
                Arc::new(Result::Err::<Sequence<u8>> {
                        code: Arc::new(Code::InvalidKeyConfig {}),
                        message: string_of("invalid config")
                    })
            } else {
                if _default::U16(data, &int!(1)) != _default::KemX25519() {
                    Arc::new(Result::Err::<Sequence<u8>> {
                            code: Arc::new(Code::UnsupportedSuite {}),
                            message: string_of("unsupported KEM")
                        })
                } else {
                    if data.cardinality() < int!(3) + _default::PublicKeyLength() + int!(2) {
                        Arc::new(Result::Err::<Sequence<u8>> {
                                code: Arc::new(Code::InvalidKeyConfig {}),
                                message: string_of("invalid config")
                            })
                    } else {
                        let mut pk: Sequence<u8> = data.slice(&int!(3), &(int!(3) + _default::PublicKeyLength()));
                        let mut suitesLen: nat = int!(_default::U16(data, &(int!(3) + _default::PublicKeyLength())));
                        let mut start: DafnyInt = int!(3) + _default::PublicKeyLength() + int!(2);
                        if data.cardinality() < start.clone() + suitesLen.clone() {
                            Arc::new(Result::Err::<Sequence<u8>> {
                                    code: Arc::new(Code::InvalidKeyConfig {}),
                                    message: string_of("invalid config")
                                })
                        } else {
                            let mut _source0: Arc<Result<Sequence<(u16, u16)>>> = _default::ParseSuites(&data.slice(&start, &(start.clone() + suitesLen.clone())));
                            if matches!((&_source0).as_ref(), Ok{ .. }) {
                                let mut ___mcc_h0: Sequence<(u16, u16)> = _source0.value().clone();
                                let mut suites: Sequence<(u16, u16)> = ___mcc_h0.clone();
                                if suites.cardinality() == int!(0) {
                                    Arc::new(Result::Err::<Sequence<u8>> {
                                            code: Arc::new(Code::InvalidKeyConfig {}),
                                            message: string_of("no cipher suites found in config")
                                        })
                                } else {
                                    if suites.cardinality() != int!(1) {
                                        Arc::new(Result::Err::<Sequence<u8>> {
                                                code: Arc::new(Code::UnsupportedSuite {}),
                                                message: string_of("expected exactly one cipher suite")
                                            })
                                    } else {
                                        if suites.get(&int!(0)) != ((
                                                    _default::KdfHkdfSha256(),
                                                    _default::AeadAes256Gcm()
                                                )) {
                                            Arc::new(Result::Err::<Sequence<u8>> {
                                                    code: Arc::new(Code::UnsupportedSuite {}),
                                                    message: string_of("unsupported cipher suite")
                                                })
                                        } else {
                                            Arc::new(Result::Ok::<Sequence<u8>> {
                                                    value: pk.clone()
                                                })
                                        }
                                    }
                                }
                            } else {
                                let mut ___mcc_h1: Arc<Code> = _source0.code().clone();
                                let mut ___mcc_h2: Sequence<DafnyChar> = _source0.message().clone();
                                let mut message: Sequence<DafnyChar> = ___mcc_h2.clone();
                                let mut code: Arc<Code> = ___mcc_h1.clone();
                                Arc::new(Result::Err::<Sequence<u8>> {
                                        code: code.clone(),
                                        message: message.clone()
                                    })
                            }
                        }
                    }
                }
            }
        }
        /// ehbp.dfy(288,3)
        pub fn ParseSuites(s: &Sequence<u8>) -> Arc<Result<Sequence<(u16, u16)>>> {
            _default::ParseSuitesFrom(s, &int!(0), &(seq![] as Sequence<(u16, u16)>))
        }
        /// ehbp.dfy(293,3)
        pub fn ParseSuitesFrom(s: &Sequence<u8>, i: &nat, acc: &Sequence<(u16, u16)>) -> Arc<Result<Sequence<(u16, u16)>>> {
            let mut _r0 = s.clone();
            let mut _r1 = i.clone();
            let mut _r2 = acc.clone();
            'TAIL_CALL_START: loop {
                let s = _r0;
                let i = _r1;
                let acc = _r2;
                if i.clone() == s.cardinality() {
                    return Arc::new(Result::Ok::<Sequence<(u16, u16)>> {
                                value: acc.clone()
                            });
                } else {
                    if s.cardinality() - i.clone() < int!(4) {
                        return Arc::new(Result::Err::<Sequence<(u16, u16)>> {
                                    code: Arc::new(Code::InvalidKeyConfig {}),
                                    message: string_of("invalid config")
                                });
                    } else {
                        let mut kdf: u16 = _default::U16(&s, &i);
                        let mut aead: u16 = _default::U16(&s, &(i.clone() + int!(2)));
                        if !_default::KnownKdf(kdf) {
                            return Arc::new(Result::Err::<Sequence<(u16, u16)>> {
                                        code: Arc::new(Code::UnsupportedSuite {}),
                                        message: string_of("invalid KDF")
                                    });
                        } else {
                            if !_default::KnownAead(aead) {
                                return Arc::new(Result::Err::<Sequence<(u16, u16)>> {
                                            code: Arc::new(Code::UnsupportedSuite {}),
                                            message: string_of("invalid AEAD")
                                        });
                            } else {
                                let mut _in0: Sequence<u8> = s.clone();
                                let mut _in1: DafnyInt = i.clone() + int!(4);
                                let mut _in2: Sequence<(u16, u16)> = acc.concat(&seq![(
                                                kdf,
                                                aead
                                            )]);
                                _r0 = _in0.clone();
                                _r1 = _in1.clone();
                                _r2 = _in2.clone();
                                continue 'TAIL_CALL_START;
                            }
                        }
                    }
                }
            }
        }
        /// ehbp.dfy(307,3)
        pub fn MarshalConfig(publicKey: &Sequence<u8>) -> Arc<Result<Sequence<u8>>> {
            if publicKey.cardinality() != _default::PublicKeyLength() {
                Arc::new(Result::Err::<Sequence<u8>> {
                        code: Arc::new(Code::InvalidKeyConfig {}),
                        message: string_of("invalid public key")
                    })
            } else {
                Arc::new(Result::Ok::<Sequence<u8>> {
                        value: seq![0].concat(&_default::BE16(_default::KemX25519())).concat(publicKey).concat(&_default::BE16(4)).concat(&_default::BE16(_default::KdfHkdfSha256())).concat(&_default::BE16(_default::AeadAes256Gcm()))
                    })
            }
        }
        /// ehbp.dfy(334,3)
        pub fn ValidToken(t: &Arc<Token>) -> bool {
            t.exportedSecret().cardinality() == _default::ExportLength() && t.requestEnc().cardinality() == _default::RequestEncLength()
        }
        /// ehbp.dfy(336,3)
        pub fn ValidateTokenFields(exportedSecretHex: &Arc<Option<Sequence<DafnyChar>>>, requestEncHex: &Arc<Option<Sequence<DafnyChar>>>) -> Arc<Result<Arc<Token>>> {
            if matches!(exportedSecretHex.as_ref(), None{ .. }) || matches!(requestEncHex.as_ref(), None{ .. }) {
                Arc::new(Result::Err::<Arc<Token>> {
                        code: Arc::new(Code::InvalidToken {}),
                        message: string_of("token field missing")
                    })
            } else {
                let mut _source0: (Arc<Option<Sequence<u8>>>, Arc<Option<Sequence<u8>>>) = (
                        _default::DecodeHex(exportedSecretHex.value()),
                        _default::DecodeHex(requestEncHex.value())
                    );
                let mut ___mcc_h0: Arc<Option<Sequence<u8>>> = _source0.0.clone();
                let mut ___mcc_h1: Arc<Option<Sequence<u8>>> = _source0.1.clone();
                let mut _source1: Arc<Option<Sequence<u8>>> = ___mcc_h0.clone();
                if matches!((&_source1).as_ref(), None{ .. }) {
                    Arc::new(Result::Err::<Arc<Token>> {
                            code: Arc::new(Code::InvalidToken {}),
                            message: string_of("token field is not hex")
                        })
                } else {
                    let mut ___mcc_h4: Sequence<u8> = _source1.value().clone();
                    let mut _source2: Arc<Option<Sequence<u8>>> = ___mcc_h1.clone();
                    if matches!((&_source2).as_ref(), None{ .. }) {
                        Arc::new(Result::Err::<Arc<Token>> {
                                code: Arc::new(Code::InvalidToken {}),
                                message: string_of("token field is not hex")
                            })
                    } else {
                        let mut ___mcc_h6: Sequence<u8> = _source2.value().clone();
                        let mut enc: Sequence<u8> = ___mcc_h6.clone();
                        let mut secret: Sequence<u8> = ___mcc_h4.clone();
                        if secret.cardinality() != _default::ExportLength() || enc.cardinality() != _default::RequestEncLength() {
                            Arc::new(Result::Err::<Arc<Token>> {
                                    code: Arc::new(Code::InvalidToken {}),
                                    message: string_of("token field has wrong length")
                                })
                        } else {
                            Arc::new(Result::Ok::<Arc<Token>> {
                                    value: Arc::new(Token::Token {
                                                exportedSecret: secret.clone(),
                                                requestEnc: enc.clone()
                                            })
                                })
                        }
                    }
                }
            }
        }
        /// ehbp.dfy(351,3)
        pub fn Frame(ciphertext: &Sequence<u8>) -> Sequence<u8> {
            _default::BE32(truncate!(ciphertext.cardinality(), u32)).concat(ciphertext)
        }
        /// ehbp.dfy(367,3)
        pub fn HeaderValues(headers: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>, name: &Sequence<DafnyChar>) -> Sequence<Sequence<DafnyChar>> {
            _default::HeaderValuesFrom(headers, name, &int!(0), &(seq![] as Sequence<Sequence<DafnyChar>>))
        }
        /// ehbp.dfy(372,3)
        pub fn HeaderValuesFrom(headers: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>, name: &Sequence<DafnyChar>, i: &nat, acc: &Sequence<Sequence<DafnyChar>>) -> Sequence<Sequence<DafnyChar>> {
            let mut _r0 = headers.clone();
            let mut _r1 = name.clone();
            let mut _r2 = i.clone();
            let mut _r3 = acc.clone();
            'TAIL_CALL_START: loop {
                let headers = _r0;
                let name = _r1;
                let i = _r2;
                let acc = _r3;
                if i.clone() == headers.cardinality() {
                    return acc.clone();
                } else {
                    let mut _in0: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = headers.clone();
                    let mut _in1: Sequence<DafnyChar> = name.clone();
                    let mut _in2: DafnyInt = i.clone() + int!(1);
                    let mut _in3: Sequence<Sequence<DafnyChar>> = if _default::EqualFold(&headers.get(&i).0.clone(), &name) {
                            acc.concat(&seq![headers.get(&i).1.clone()])
                        } else {
                            acc.clone()
                        };
                    _r0 = _in0.clone();
                    _r1 = _in1.clone();
                    _r2 = _in2.clone();
                    _r3 = _in3.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp.dfy(380,3)
        pub fn FirstHeader(headers: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>, name: &Sequence<DafnyChar>) -> Arc<Option<Sequence<DafnyChar>>> {
            let mut values: Sequence<Sequence<DafnyChar>> = _default::HeaderValues(headers, name);
            if values.cardinality() == int!(0) {
                Arc::new(Option::None::<Sequence<DafnyChar>> {})
            } else {
                Arc::new(Option::Some::<Sequence<DafnyChar>> {
                        value: values.get(&int!(0))
                    })
            }
        }
        /// ehbp.dfy(397,3)
        pub fn BodylessSuccess(status: &DafnyInt) -> bool {
            status.clone() == int!(204) || status.clone() == int!(205)
        }
        /// ehbp.dfy(399,3)
        pub fn Classify(encrypted: bool, head: &Arc<Head>) -> Arc<Disposition> {
            let mut nonces: Sequence<Sequence<DafnyChar>> = _default::HeaderValues(head.headers(), &_default::ResponseNonceHeader());
            if !encrypted {
                Arc::new(Disposition::PassThrough {})
            } else {
                if head.redirected().clone() || int!(300) <= head.status().clone() && head.status().clone() < int!(400) {
                    Arc::new(Disposition::Refuse {
                            code: Arc::new(Code::UnexpectedRedirect {}),
                            message: string_of("redirect in response to an encrypted request")
                        })
                } else {
                    if nonces.cardinality() == int!(0) {
                        if head.status().clone() < int!(400) {
                            Arc::new(Disposition::Refuse {
                                    code: Arc::new(Code::MissingResponseNonce {}),
                                    message: string_of("missing ").concat(&_default::ResponseNonceHeader()).concat(&string_of(" header"))
                                })
                        } else {
                            if head.status().clone() == int!(422) && _default::HasMediaType(&_default::FirstHeader(head.headers(), &string_of("Content-Type")), &_default::ProblemJsonMediaType()) {
                                Arc::new(Disposition::NeedProblemBody {})
                            } else {
                                Arc::new(Disposition::PassThrough {})
                            }
                        }
                    } else {
                        if int!(1) < nonces.cardinality() {
                            Arc::new(Disposition::Refuse {
                                    code: Arc::new(Code::DuplicateResponseNonce {}),
                                    message: string_of("duplicate response nonce")
                                })
                        } else {
                            if nonces.get(&int!(0)) == string_of("") {
                                Arc::new(Disposition::Refuse {
                                        code: Arc::new(Code::InvalidResponseNonce {}),
                                        message: string_of("empty response nonce")
                                    })
                            } else {
                                let mut _source0: Arc<Option<Sequence<u8>>> = _default::DecodeHex(&nonces.get(&int!(0)));
                                if matches!((&_source0).as_ref(), None{ .. }) {
                                    Arc::new(Disposition::Refuse {
                                            code: Arc::new(Code::InvalidResponseNonce {}),
                                            message: string_of("response nonce is not hex")
                                        })
                                } else {
                                    let mut ___mcc_h0: Sequence<u8> = _source0.value().clone();
                                    let mut nonce: Sequence<u8> = ___mcc_h0.clone();
                                    if nonce.cardinality() != _default::ResponseNonceLength() {
                                        Arc::new(Disposition::Refuse {
                                                code: Arc::new(Code::InvalidResponseNonce {}),
                                                message: string_of("response nonce has wrong length")
                                            })
                                    } else {
                                        if _default::BodylessSuccess(head.status()) {
                                            Arc::new(Disposition::Refuse {
                                                    code: Arc::new(Code::FramingTruncated {}),
                                                    message: string_of("status cannot carry an authenticated frame")
                                                })
                                        } else {
                                            Arc::new(Disposition::Decrypt {
                                                    nonce: nonce.clone(),
                                                    requireFrame: head.status().clone() < int!(400)
                                                })
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp.dfy(428,3)
        pub fn ClassifyProblem(oversized: bool, isObject: bool, typeValue: &Arc<Option<Sequence<DafnyChar>>>, title: &Arc<Option<Sequence<DafnyChar>>>) -> Arc<Disposition> {
            if oversized || !isObject || typeValue.clone() != Arc::new(Option::Some::<Sequence<DafnyChar>> {
                        value: _default::KeyConfigProblemType()
                    }) {
                Arc::new(Disposition::PassThrough {})
            } else {
                Arc::new(Disposition::Refuse {
                        code: Arc::new(Code::KeyConfigMismatch {}),
                        message: if matches!(title.as_ref(), Some{ .. }) && title.value().clone() != string_of("") {
                                title.value().clone()
                            } else {
                                _default::DefaultKeyConfigTitle()
                            }
                    })
            }
        }
        /// ehbp.dfy(435,3)
        pub fn ClassifyDiscovery(head: &Arc<Head>) -> Arc<Result<()>> {
            if head.redirected().clone() || head.status().clone() != int!(200) {
                Arc::new(Result::Err::<()> {
                        code: Arc::new(Code::InvalidKeyConfig {}),
                        message: string_of("discovery returned a non-200 status")
                    })
            } else {
                if !_default::HasMediaType(&_default::FirstHeader(head.headers(), &string_of("Content-Type")), &_default::KeysMediaType()) {
                    Arc::new(Result::Err::<()> {
                            code: Arc::new(Code::InvalidKeyConfig {}),
                            message: string_of("discovery returned the wrong media type")
                        })
                } else {
                    Arc::new(Result::Ok::<()> {
                            value: ()
                        })
                }
            }
        }
        /// ehbp.dfy(446,3)
        pub fn DefaultPort(scheme: &Sequence<DafnyChar>) -> DafnyInt {
            if _default::Lower(scheme) == string_of("https") {
                int!(443)
            } else {
                int!(80)
            }
        }
        /// ehbp.dfy(448,3)
        pub fn MakeOrigin(scheme: &Sequence<DafnyChar>, host: &Sequence<DafnyChar>, port: &Arc<Option<DafnyInt>>, hasUserinfo: bool) -> Arc<Result<Arc<Origin>>> {
            let mut s: Sequence<DafnyChar> = _default::Lower(scheme);
            if s.clone() != string_of("http") && s.clone() != string_of("https") {
                Arc::new(Result::Err::<Arc<Origin>> {
                        code: Arc::new(Code::InvalidInput {}),
                        message: string_of("base URL must include an HTTP origin")
                    })
            } else {
                if host.clone() == string_of("") {
                    Arc::new(Result::Err::<Arc<Origin>> {
                            code: Arc::new(Code::InvalidInput {}),
                            message: string_of("base URL must include an HTTP origin")
                        })
                } else {
                    if hasUserinfo {
                        Arc::new(Result::Err::<Arc<Origin>> {
                                code: Arc::new(Code::InvalidInput {}),
                                message: string_of("base URL must not include credentials")
                            })
                    } else {
                        Arc::new(Result::Ok::<Arc<Origin>> {
                                value: Arc::new(Origin::Origin {
                                            scheme: s.clone(),
                                            host: _default::Lower(host),
                                            port: if matches!(port.as_ref(), Some{ .. }) {
                                                    port.value().clone()
                                                } else {
                                                    _default::DefaultPort(&s)
                                                }
                                        })
                            })
                    }
                }
            }
        }
        /// ehbp.dfy(457,3)
        pub fn SameOrigin(a: &Arc<Origin>, b: &Arc<Origin>) -> bool {
            a.scheme().clone() == b.scheme().clone() && a.host().clone() == b.host().clone() && a.port().clone() == b.port().clone()
        }
        /// ehbp.dfy(459,3)
        pub fn ReservedHeader(name: &Sequence<DafnyChar>) -> bool {
            _default::EqualFold(name, &_default::EncapsulatedKeyHeader()) || _default::EqualFold(name, &_default::ResponseNonceHeader()) || _default::EqualFold(name, &string_of("Host"))
        }
        /// ehbp.dfy(464,3)
        pub fn FramingHeader(name: &Sequence<DafnyChar>) -> bool {
            _default::EqualFold(name, &string_of("Content-Length")) || _default::EqualFold(name, &string_of("Transfer-Encoding"))
        }
        /// ehbp.dfy(467,3)
        pub fn ValidateRequest(origin: &Arc<Origin>, target: &Arc<Result<Arc<Origin>>>, headers: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>) -> Arc<Result<()>> {
            if matches!(target.as_ref(), Err{ .. }) {
                Arc::new(Result::Err::<()> {
                        code: Arc::new(Code::InvalidInput {}),
                        message: target.message().clone()
                    })
            } else {
                if !_default::SameOrigin(origin, target.value()) {
                    Arc::new(Result::Err::<()> {
                            code: Arc::new(Code::InvalidInput {}),
                            message: string_of("request URL must use the configured origin")
                        })
                } else {
                    _default::ValidateHeadersFrom(headers, &int!(0))
                }
            }
        }
        /// ehbp.dfy(474,3)
        pub fn ValidateHeadersFrom(headers: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>, i: &nat) -> Arc<Result<()>> {
            let mut _r0 = headers.clone();
            let mut _r1 = i.clone();
            'TAIL_CALL_START: loop {
                let headers = _r0;
                let i = _r1;
                if i.clone() == headers.cardinality() {
                    return Arc::new(Result::Ok::<()> {
                                value: ()
                            });
                } else {
                    if _default::ReservedHeader(&headers.get(&i).0.clone()) {
                        return Arc::new(Result::Err::<()> {
                                    code: Arc::new(Code::InvalidInput {}),
                                    message: string_of("reserved request header cannot be set by callers: ").concat(&headers.get(&i).0.clone())
                                });
                    } else {
                        let mut _in0: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = headers.clone();
                        let mut _in1: DafnyInt = i.clone() + int!(1);
                        _r0 = _in0.clone();
                        _r1 = _in1.clone();
                        continue 'TAIL_CALL_START;
                    }
                }
            }
        }
        /// ehbp.dfy(484,3)
        pub fn DropFraming(headers: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>) -> Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> {
            _default::DropFramingFrom(headers, &int!(0), &(seq![] as Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>))
        }
        /// ehbp.dfy(489,3)
        pub fn DropFramingFrom(headers: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>, i: &nat, acc: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>) -> Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> {
            let mut _r0 = headers.clone();
            let mut _r1 = i.clone();
            let mut _r2 = acc.clone();
            'TAIL_CALL_START: loop {
                let headers = _r0;
                let i = _r1;
                let acc = _r2;
                if i.clone() == headers.cardinality() {
                    return acc.clone();
                } else {
                    let mut _in0: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = headers.clone();
                    let mut _in1: DafnyInt = i.clone() + int!(1);
                    let mut _in2: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = if _default::FramingHeader(&headers.get(&i).0.clone()) {
                            acc.clone()
                        } else {
                            acc.concat(&seq![headers.get(&i)])
                        };
                    _r0 = _in0.clone();
                    _r1 = _in1.clone();
                    _r2 = _in2.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp.dfy(497,3)
        pub fn OriginUrl(origin: &Arc<Origin>) -> Sequence<DafnyChar> {
            let mut portPart: Sequence<DafnyChar> = if origin.port().clone() == _default::DefaultPort(origin.scheme()) {
                    string_of("")
                } else {
                    string_of(":").concat(&_default::IntToString(origin.port()))
                };
            origin.scheme().concat(&string_of("://")).concat(origin.host()).concat(&portPart)
        }
        /// ehbp.dfy(503,3)
        pub fn IntToString(n: &DafnyInt) -> Sequence<DafnyChar> {
            if n.clone() < int!(0) {
                string_of("-").concat(&_default::IntToString(&(int!(0) - n.clone())))
            } else {
                if n.clone() < int!(10) {
                    seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(DafnyChar(char::from_u32(48).unwrap()).0) + n.clone()).unwrap()).unwrap())]
                } else {
                    _default::IntToString(&euclidian_division(n.clone(), int!(10))).concat(&seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(DafnyChar(char::from_u32(48).unwrap()).0) + euclidian_modulo(n.clone(), int!(10))).unwrap()).unwrap())])
                }
            }
        }
        /// ehbp.dfy(66,3)
        pub fn Codes() -> Sequence<Arc<Code>> {
            seq![Arc::new(Code::InvalidKeyConfig {}), Arc::new(Code::UnsupportedSuite {}), Arc::new(Code::InvalidEncapsulatedKey {}), Arc::new(Code::HpkeSetupFailed {}), Arc::new(Code::MissingResponseNonce {}), Arc::new(Code::UnexpectedRedirect {}), Arc::new(Code::InvalidResponseNonce {}), Arc::new(Code::DuplicateResponseNonce {}), Arc::new(Code::KeyConfigMismatch {}), Arc::new(Code::FramingTruncated {}), Arc::new(Code::ChunkTooLarge {}), Arc::new(Code::AeadDecryptFailed {}), Arc::new(Code::SequenceOverflow {}), Arc::new(Code::InvalidToken {}), Arc::new(Code::InvalidInput {})]
        }
        /// ehbp.dfy(81,3)
        pub fn KemX25519() -> u16 {
            32
        }
        /// ehbp.dfy(82,3)
        pub fn KdfHkdfSha256() -> u16 {
            1
        }
        /// ehbp.dfy(83,3)
        pub fn AeadAes256Gcm() -> u16 {
            2
        }
        /// ehbp.dfy(102,3)
        pub fn MaxChunkBytes() -> u32 {
            64 * 1024 * 1024
        }
        /// ehbp.dfy(104,3)
        pub fn RequestFrameBytes() -> u32 {
            65536
        }
        /// ehbp.dfy(217,3)
        pub fn HexDigits() -> Sequence<DafnyChar> {
            string_of("0123456789abcdef")
        }
        /// ehbp.dfy(89,3)
        pub fn NonceLength() -> nat {
            int!(12)
        }
        /// ehbp.dfy(84,3)
        pub fn PublicKeyLength() -> nat {
            int!(32)
        }
        /// ehbp.dfy(86,3)
        pub fn ExportLength() -> nat {
            int!(32)
        }
        /// ehbp.dfy(85,3)
        pub fn RequestEncLength() -> nat {
            int!(32)
        }
        /// ehbp.dfy(95,3)
        pub fn ResponseNonceHeader() -> Sequence<DafnyChar> {
            string_of("Ehbp-Response-Nonce")
        }
        /// ehbp.dfy(98,3)
        pub fn ProblemJsonMediaType() -> Sequence<DafnyChar> {
            string_of("application/problem+json")
        }
        /// ehbp.dfy(87,3)
        pub fn ResponseNonceLength() -> nat {
            int!(32)
        }
        /// ehbp.dfy(99,3)
        pub fn KeyConfigProblemType() -> Sequence<DafnyChar> {
            string_of("urn:ietf:params:ehbp:error:key-config")
        }
        /// ehbp.dfy(100,3)
        pub fn DefaultKeyConfigTitle() -> Sequence<DafnyChar> {
            string_of("key configuration mismatch")
        }
        /// ehbp.dfy(97,3)
        pub fn KeysMediaType() -> Sequence<DafnyChar> {
            string_of("application/ohttp-keys")
        }
        /// ehbp.dfy(94,3)
        pub fn EncapsulatedKeyHeader() -> Sequence<DafnyChar> {
            string_of("Ehbp-Encapsulated-Key")
        }
        /// ehbp.dfy(88,3)
        pub fn KeyLength() -> nat {
            int!(32)
        }
        /// ehbp.dfy(90,3)
        pub fn HpkeRequestInfo() -> Sequence<DafnyChar> {
            string_of("ehbp request")
        }
        /// ehbp.dfy(91,3)
        pub fn ExportLabel() -> Sequence<DafnyChar> {
            string_of("ehbp response")
        }
        /// ehbp.dfy(92,3)
        pub fn ResponseKeyLabel() -> Sequence<DafnyChar> {
            string_of("key")
        }
        /// ehbp.dfy(93,3)
        pub fn ResponseNonceLabel() -> Sequence<DafnyChar> {
            string_of("nonce")
        }
        /// ehbp.dfy(96,3)
        pub fn KeysPath() -> Sequence<DafnyChar> {
            string_of("/.well-known/hpke-keys")
        }
        /// ehbp.dfy(106,3)
        pub fn MaxProblemBytes() -> nat {
            int!(64) * int!(1024)
        }
        /// ehbp.dfy(108,3)
        pub fn MaxKeyConfigBytes() -> nat {
            int!(37) + int!(b"65535")
        }
        /// ehbp.dfy(110,3)
        pub fn MaxEmptyReads() -> nat {
            int!(100)
        }
        /// ehbp.dfy(513,3)
        pub fn AeadTagLength() -> nat {
            int!(16)
        }
        /// ehbp.dfy(514,3)
        pub fn HashLength() -> nat {
            int!(32)
        }
    }

    /// ehbp.dfy(9,3)
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct uint8(pub u8);

    impl PartialEq
        for uint8 {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl Eq
        for uint8 {}

    impl Hash
        for uint8 {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            Hash::hash(&self.0, _state)
        }
    }

    impl uint8 {
        /// Constraint check
        pub fn is(_source: u8) -> bool {
            return true;
        }
    }

    impl Default
        for uint8 {
        /// An element of uint8
        fn default() -> Self {
            uint8(Default::default())
        }
    }

    impl DafnyPrint
        for uint8 {
        /// For Dafny print statements
        fn fmt_print(&self, _formatter: &mut Formatter, in_seq: bool) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(&self.0, _formatter, in_seq)
        }
    }

    impl Deref
        for uint8 {
        type Target = u8;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl uint8 {
        /// SAFETY: The newtype is marked as transparent
        pub fn _from_ref(o: &u8) -> &Self {
            unsafe {
                transmute(o)
            }
        }
    }

    impl Add
        for uint8 {
        type Output = uint8;
        fn add(self, other: Self) -> Self {
            uint8(self.0 + other.0)
        }
    }

    impl Sub
        for uint8 {
        type Output = uint8;
        fn sub(self, other: Self) -> Self {
            uint8(self.0 - other.0)
        }
    }

    impl Mul
        for uint8 {
        type Output = uint8;
        fn mul(self, other: Self) -> Self {
            uint8(self.0 * other.0)
        }
    }

    impl Div
        for uint8 {
        type Output = uint8;
        fn div(self, other: Self) -> Self {
            uint8(self.0 / other.0)
        }
    }

    impl PartialOrd
        for uint8 {
        fn partial_cmp(&self, other: &Self) -> ::std::option::Option<Ordering> {
            PartialOrd::partial_cmp(&self.0, &other.0)
        }
    }

    /// ehbp.dfy(10,3)
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct uint16(pub u16);

    impl PartialEq
        for uint16 {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl Eq
        for uint16 {}

    impl Hash
        for uint16 {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            Hash::hash(&self.0, _state)
        }
    }

    impl uint16 {
        /// Constraint check
        pub fn is(_source: u16) -> bool {
            return true;
        }
    }

    impl Default
        for uint16 {
        /// An element of uint16
        fn default() -> Self {
            uint16(Default::default())
        }
    }

    impl DafnyPrint
        for uint16 {
        /// For Dafny print statements
        fn fmt_print(&self, _formatter: &mut Formatter, in_seq: bool) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(&self.0, _formatter, in_seq)
        }
    }

    impl Deref
        for uint16 {
        type Target = u16;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl uint16 {
        /// SAFETY: The newtype is marked as transparent
        pub fn _from_ref(o: &u16) -> &Self {
            unsafe {
                transmute(o)
            }
        }
    }

    impl Add
        for uint16 {
        type Output = uint16;
        fn add(self, other: Self) -> Self {
            uint16(self.0 + other.0)
        }
    }

    impl Sub
        for uint16 {
        type Output = uint16;
        fn sub(self, other: Self) -> Self {
            uint16(self.0 - other.0)
        }
    }

    impl Mul
        for uint16 {
        type Output = uint16;
        fn mul(self, other: Self) -> Self {
            uint16(self.0 * other.0)
        }
    }

    impl Div
        for uint16 {
        type Output = uint16;
        fn div(self, other: Self) -> Self {
            uint16(self.0 / other.0)
        }
    }

    impl PartialOrd
        for uint16 {
        fn partial_cmp(&self, other: &Self) -> ::std::option::Option<Ordering> {
            PartialOrd::partial_cmp(&self.0, &other.0)
        }
    }

    /// ehbp.dfy(11,3)
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct uint32(pub u32);

    impl PartialEq
        for uint32 {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl Eq
        for uint32 {}

    impl Hash
        for uint32 {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            Hash::hash(&self.0, _state)
        }
    }

    impl uint32 {
        /// Constraint check
        pub fn is(_source: u32) -> bool {
            return true;
        }
    }

    impl Default
        for uint32 {
        /// An element of uint32
        fn default() -> Self {
            uint32(Default::default())
        }
    }

    impl DafnyPrint
        for uint32 {
        /// For Dafny print statements
        fn fmt_print(&self, _formatter: &mut Formatter, in_seq: bool) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(&self.0, _formatter, in_seq)
        }
    }

    impl Deref
        for uint32 {
        type Target = u32;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl uint32 {
        /// SAFETY: The newtype is marked as transparent
        pub fn _from_ref(o: &u32) -> &Self {
            unsafe {
                transmute(o)
            }
        }
    }

    impl Add
        for uint32 {
        type Output = uint32;
        fn add(self, other: Self) -> Self {
            uint32(self.0 + other.0)
        }
    }

    impl Sub
        for uint32 {
        type Output = uint32;
        fn sub(self, other: Self) -> Self {
            uint32(self.0 - other.0)
        }
    }

    impl Mul
        for uint32 {
        type Output = uint32;
        fn mul(self, other: Self) -> Self {
            uint32(self.0 * other.0)
        }
    }

    impl Div
        for uint32 {
        type Output = uint32;
        fn div(self, other: Self) -> Self {
            uint32(self.0 / other.0)
        }
    }

    impl PartialOrd
        for uint32 {
        fn partial_cmp(&self, other: &Self) -> ::std::option::Option<Ordering> {
            PartialOrd::partial_cmp(&self.0, &other.0)
        }
    }

    /// ehbp.dfy(12,3)
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct uint64(pub u64);

    impl PartialEq
        for uint64 {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl Eq
        for uint64 {}

    impl Hash
        for uint64 {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            Hash::hash(&self.0, _state)
        }
    }

    impl uint64 {
        /// Constraint check
        pub fn is(_source: u64) -> bool {
            return true;
        }
    }

    impl Default
        for uint64 {
        /// An element of uint64
        fn default() -> Self {
            uint64(Default::default())
        }
    }

    impl DafnyPrint
        for uint64 {
        /// For Dafny print statements
        fn fmt_print(&self, _formatter: &mut Formatter, in_seq: bool) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(&self.0, _formatter, in_seq)
        }
    }

    impl Deref
        for uint64 {
        type Target = u64;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl uint64 {
        /// SAFETY: The newtype is marked as transparent
        pub fn _from_ref(o: &u64) -> &Self {
            unsafe {
                transmute(o)
            }
        }
    }

    impl Add
        for uint64 {
        type Output = uint64;
        fn add(self, other: Self) -> Self {
            uint64(self.0 + other.0)
        }
    }

    impl Sub
        for uint64 {
        type Output = uint64;
        fn sub(self, other: Self) -> Self {
            uint64(self.0 - other.0)
        }
    }

    impl Mul
        for uint64 {
        type Output = uint64;
        fn mul(self, other: Self) -> Self {
            uint64(self.0 * other.0)
        }
    }

    impl Div
        for uint64 {
        type Output = uint64;
        fn div(self, other: Self) -> Self {
            uint64(self.0 / other.0)
        }
    }

    impl PartialOrd
        for uint64 {
        fn partial_cmp(&self, other: &Self) -> ::std::option::Option<Ordering> {
            PartialOrd::partial_cmp(&self.0, &other.0)
        }
    }

    /// ehbp.dfy(15,3)
    pub type PublicKey = Sequence<u8>;

    /// An element of PublicKey
    pub fn __init_PublicKey() -> Sequence<u8> {
        {
            let _initializer = {
                    Arc::new(move |i: &DafnyInt| -> u8{
            0
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + Send>
                };
            integer_range(Zero::zero(), int!(32)).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
        }
    }

    /// ehbp.dfy(23,3)
    #[derive(Clone)]
    pub enum Code {
        InvalidKeyConfig {},
        UnsupportedSuite {},
        InvalidEncapsulatedKey {},
        HpkeSetupFailed {},
        MissingResponseNonce {},
        UnexpectedRedirect {},
        InvalidResponseNonce {},
        DuplicateResponseNonce {},
        KeyConfigMismatch {},
        FramingTruncated {},
        ChunkTooLarge {},
        AeadDecryptFailed {},
        SequenceOverflow {},
        InvalidToken {},
        InvalidInput {},
        Transport {}
    }

    impl Code {}

    impl Debug
        for Code {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Code {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Code::InvalidKeyConfig{} => {
                    write!(_formatter, "EHBP.Code.InvalidKeyConfig")?;
                    Ok(())
                },
                Code::UnsupportedSuite{} => {
                    write!(_formatter, "EHBP.Code.UnsupportedSuite")?;
                    Ok(())
                },
                Code::InvalidEncapsulatedKey{} => {
                    write!(_formatter, "EHBP.Code.InvalidEncapsulatedKey")?;
                    Ok(())
                },
                Code::HpkeSetupFailed{} => {
                    write!(_formatter, "EHBP.Code.HpkeSetupFailed")?;
                    Ok(())
                },
                Code::MissingResponseNonce{} => {
                    write!(_formatter, "EHBP.Code.MissingResponseNonce")?;
                    Ok(())
                },
                Code::UnexpectedRedirect{} => {
                    write!(_formatter, "EHBP.Code.UnexpectedRedirect")?;
                    Ok(())
                },
                Code::InvalidResponseNonce{} => {
                    write!(_formatter, "EHBP.Code.InvalidResponseNonce")?;
                    Ok(())
                },
                Code::DuplicateResponseNonce{} => {
                    write!(_formatter, "EHBP.Code.DuplicateResponseNonce")?;
                    Ok(())
                },
                Code::KeyConfigMismatch{} => {
                    write!(_formatter, "EHBP.Code.KeyConfigMismatch")?;
                    Ok(())
                },
                Code::FramingTruncated{} => {
                    write!(_formatter, "EHBP.Code.FramingTruncated")?;
                    Ok(())
                },
                Code::ChunkTooLarge{} => {
                    write!(_formatter, "EHBP.Code.ChunkTooLarge")?;
                    Ok(())
                },
                Code::AeadDecryptFailed{} => {
                    write!(_formatter, "EHBP.Code.AeadDecryptFailed")?;
                    Ok(())
                },
                Code::SequenceOverflow{} => {
                    write!(_formatter, "EHBP.Code.SequenceOverflow")?;
                    Ok(())
                },
                Code::InvalidToken{} => {
                    write!(_formatter, "EHBP.Code.InvalidToken")?;
                    Ok(())
                },
                Code::InvalidInput{} => {
                    write!(_formatter, "EHBP.Code.InvalidInput")?;
                    Ok(())
                },
                Code::Transport{} => {
                    write!(_formatter, "EHBP.Code.Transport")?;
                    Ok(())
                },
            }
        }
    }

    impl Code {
        /// Enumerates all possible values of Code
        pub fn _AllSingletonConstructors() -> SequenceIter<Arc<Code>> {
            seq![Arc::new(Code::InvalidKeyConfig {}), Arc::new(Code::UnsupportedSuite {}), Arc::new(Code::InvalidEncapsulatedKey {}), Arc::new(Code::HpkeSetupFailed {}), Arc::new(Code::MissingResponseNonce {}), Arc::new(Code::UnexpectedRedirect {}), Arc::new(Code::InvalidResponseNonce {}), Arc::new(Code::DuplicateResponseNonce {}), Arc::new(Code::KeyConfigMismatch {}), Arc::new(Code::FramingTruncated {}), Arc::new(Code::ChunkTooLarge {}), Arc::new(Code::AeadDecryptFailed {}), Arc::new(Code::SequenceOverflow {}), Arc::new(Code::InvalidToken {}), Arc::new(Code::InvalidInput {}), Arc::new(Code::Transport {})].iter()
        }
    }

    impl PartialEq
        for Code {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Code::InvalidKeyConfig{}, Code::InvalidKeyConfig{}) => {
                    true
                },
                (Code::UnsupportedSuite{}, Code::UnsupportedSuite{}) => {
                    true
                },
                (Code::InvalidEncapsulatedKey{}, Code::InvalidEncapsulatedKey{}) => {
                    true
                },
                (Code::HpkeSetupFailed{}, Code::HpkeSetupFailed{}) => {
                    true
                },
                (Code::MissingResponseNonce{}, Code::MissingResponseNonce{}) => {
                    true
                },
                (Code::UnexpectedRedirect{}, Code::UnexpectedRedirect{}) => {
                    true
                },
                (Code::InvalidResponseNonce{}, Code::InvalidResponseNonce{}) => {
                    true
                },
                (Code::DuplicateResponseNonce{}, Code::DuplicateResponseNonce{}) => {
                    true
                },
                (Code::KeyConfigMismatch{}, Code::KeyConfigMismatch{}) => {
                    true
                },
                (Code::FramingTruncated{}, Code::FramingTruncated{}) => {
                    true
                },
                (Code::ChunkTooLarge{}, Code::ChunkTooLarge{}) => {
                    true
                },
                (Code::AeadDecryptFailed{}, Code::AeadDecryptFailed{}) => {
                    true
                },
                (Code::SequenceOverflow{}, Code::SequenceOverflow{}) => {
                    true
                },
                (Code::InvalidToken{}, Code::InvalidToken{}) => {
                    true
                },
                (Code::InvalidInput{}, Code::InvalidInput{}) => {
                    true
                },
                (Code::Transport{}, Code::Transport{}) => {
                    true
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Code {}

    impl Hash
        for Code {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Code::InvalidKeyConfig{} => {
                    
                },
                Code::UnsupportedSuite{} => {
                    
                },
                Code::InvalidEncapsulatedKey{} => {
                    
                },
                Code::HpkeSetupFailed{} => {
                    
                },
                Code::MissingResponseNonce{} => {
                    
                },
                Code::UnexpectedRedirect{} => {
                    
                },
                Code::InvalidResponseNonce{} => {
                    
                },
                Code::DuplicateResponseNonce{} => {
                    
                },
                Code::KeyConfigMismatch{} => {
                    
                },
                Code::FramingTruncated{} => {
                    
                },
                Code::ChunkTooLarge{} => {
                    
                },
                Code::AeadDecryptFailed{} => {
                    
                },
                Code::SequenceOverflow{} => {
                    
                },
                Code::InvalidToken{} => {
                    
                },
                Code::InvalidInput{} => {
                    
                },
                Code::Transport{} => {
                    
                },
            }
        }
    }

    impl AsRef<Code>
        for Code {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp.dfy(74,3)
    #[derive(Clone)]
    pub enum Result<T: DafnyType> {
        Ok {
            value: T
        },
        Err {
            code: Arc<Code>,
            message: Sequence<DafnyChar>
        }
    }

    impl<T: DafnyType> Result<T> {
        /// Gets the field value for all enum members which have it
        pub fn value(&self) -> &T {
            match self {
                Result::Ok{value, } => value,
                Result::Err{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field code for all enum members which have it
        pub fn code(&self) -> &Arc<Code> {
            match self {
                Result::Ok{value, } => panic!("field does not exist on this variant"),
                Result::Err{code, message, } => code,
            }
        }
        /// Gets the field message for all enum members which have it
        pub fn message(&self) -> &Sequence<DafnyChar> {
            match self {
                Result::Ok{value, } => panic!("field does not exist on this variant"),
                Result::Err{code, message, } => message,
            }
        }
    }

    impl<T: DafnyType> Debug
        for Result<T> {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl<T: DafnyType> DafnyPrint
        for Result<T> {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Result::Ok{value, } => {
                    write!(_formatter, "EHBP.Result.Ok(")?;
                    DafnyPrint::fmt_print(value, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Result::Err{code, message, } => {
                    write!(_formatter, "EHBP.Result.Err(")?;
                    DafnyPrint::fmt_print(code, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(message, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl<T: DafnyType + Eq + Hash> PartialEq
        for Result<T> {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Result::Ok{value, }, Result::Ok{value: _2_value, }) => {
                    value == _2_value
                },
                (Result::Err{code, message, }, Result::Err{code: _2_code, message: _2_message, }) => {
                    code == _2_code && message == _2_message
                },
                _ => {
                    false
                },
            }
        }
    }

    impl<T: DafnyType + Eq + Hash> Eq
        for Result<T> {}

    impl<T: DafnyType + Hash> Hash
        for Result<T> {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Result::Ok{value, } => {
                    Hash::hash(value, _state)
                },
                Result::Err{code, message, } => {
                    Hash::hash(code, _state);
                    Hash::hash(message, _state)
                },
            }
        }
    }

    impl<T: DafnyType> AsRef<Result<T>>
        for Result<T> {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp.dfy(76,3)
    #[derive(Clone)]
    pub enum Option<T: DafnyType> {
        None {},
        Some {
            value: T
        }
    }

    impl<T: DafnyType> Option<T> {
        /// Gets the field value for all enum members which have it
        pub fn value(&self) -> &T {
            match self {
                Option::None{} => panic!("field does not exist on this variant"),
                Option::Some{value, } => value,
            }
        }
    }

    impl<T: DafnyType> Debug
        for Option<T> {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl<T: DafnyType> DafnyPrint
        for Option<T> {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Option::None{} => {
                    write!(_formatter, "EHBP.Option.None")?;
                    Ok(())
                },
                Option::Some{value, } => {
                    write!(_formatter, "EHBP.Option.Some(")?;
                    DafnyPrint::fmt_print(value, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl<T: DafnyType + Eq + Hash> PartialEq
        for Option<T> {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Option::None{}, Option::None{}) => {
                    true
                },
                (Option::Some{value, }, Option::Some{value: _2_value, }) => {
                    value == _2_value
                },
                _ => {
                    false
                },
            }
        }
    }

    impl<T: DafnyType + Eq + Hash> Eq
        for Option<T> {}

    impl<T: DafnyType + Hash> Hash
        for Option<T> {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Option::None{} => {
                    
                },
                Option::Some{value, } => {
                    Hash::hash(value, _state)
                },
            }
        }
    }

    impl<T: DafnyType> AsRef<Option<T>>
        for Option<T> {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp.dfy(332,3)
    #[derive(Clone)]
    pub enum Token {
        Token {
            exportedSecret: Sequence<u8>,
            requestEnc: Sequence<u8>
        }
    }

    impl Token {
        /// Returns a borrow of the field exportedSecret
        pub fn exportedSecret(&self) -> &Sequence<u8> {
            match self {
                Token::Token{exportedSecret, requestEnc, } => exportedSecret,
            }
        }
        /// Returns a borrow of the field requestEnc
        pub fn requestEnc(&self) -> &Sequence<u8> {
            match self {
                Token::Token{exportedSecret, requestEnc, } => requestEnc,
            }
        }
    }

    impl Debug
        for Token {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Token {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Token::Token{exportedSecret, requestEnc, } => {
                    write!(_formatter, "EHBP.Token.Token(<redacted>)")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Token {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Token::Token{exportedSecret, requestEnc, }, Token::Token{exportedSecret: _2_exportedSecret, requestEnc: _2_requestEnc, }) => {
                    exportedSecret == _2_exportedSecret && requestEnc == _2_requestEnc
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Token {}

    impl Hash
        for Token {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Token::Token{exportedSecret, requestEnc, } => {
                    Hash::hash(exportedSecret, _state);
                    Hash::hash(requestEnc, _state)
                },
            }
        }
    }

    impl AsRef<Token>
        for Token {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp.dfy(357,3)
    #[derive(Clone)]
    pub enum Framed {
        Framed {
            seqNo: u64,
            ciphertext: Sequence<u8>
        }
    }

    impl Framed {
        /// Returns a borrow of the field seqNo
        pub fn seqNo(&self) -> &u64 {
            match self {
                Framed::Framed{seqNo, ciphertext, } => seqNo,
            }
        }
        /// Returns a borrow of the field ciphertext
        pub fn ciphertext(&self) -> &Sequence<u8> {
            match self {
                Framed::Framed{seqNo, ciphertext, } => ciphertext,
            }
        }
    }

    impl Debug
        for Framed {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Framed {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Framed::Framed{seqNo, ciphertext, } => {
                    write!(_formatter, "EHBP.Framed.Framed(")?;
                    DafnyPrint::fmt_print(seqNo, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(ciphertext, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Framed {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Framed::Framed{seqNo, ciphertext, }, Framed::Framed{seqNo: _2_seqNo, ciphertext: _2_ciphertext, }) => {
                    seqNo == _2_seqNo && ciphertext == _2_ciphertext
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Framed {}

    impl Hash
        for Framed {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Framed::Framed{seqNo, ciphertext, } => {
                    Hash::hash(seqNo, _state);
                    Hash::hash(ciphertext, _state)
                },
            }
        }
    }

    impl AsRef<Framed>
        for Framed {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp.dfy(388,3)
    #[derive(Clone)]
    pub enum Head {
        Head {
            status: DafnyInt,
            headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
            redirected: bool
        }
    }

    impl Head {
        /// Returns a borrow of the field status
        pub fn status(&self) -> &DafnyInt {
            match self {
                Head::Head{status, headers, redirected, } => status,
            }
        }
        /// Returns a borrow of the field headers
        pub fn headers(&self) -> &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> {
            match self {
                Head::Head{status, headers, redirected, } => headers,
            }
        }
        /// Returns a borrow of the field redirected
        pub fn redirected(&self) -> &bool {
            match self {
                Head::Head{status, headers, redirected, } => redirected,
            }
        }
    }

    impl Debug
        for Head {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Head {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Head::Head{status, headers, redirected, } => {
                    write!(_formatter, "EHBP.Head.Head(")?;
                    DafnyPrint::fmt_print(status, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(headers, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(redirected, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Head {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Head::Head{status, headers, redirected, }, Head::Head{status: _2_status, headers: _2_headers, redirected: _2_redirected, }) => {
                    status == _2_status && headers == _2_headers && redirected == _2_redirected
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Head {}

    impl Hash
        for Head {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Head::Head{status, headers, redirected, } => {
                    Hash::hash(status, _state);
                    Hash::hash(headers, _state);
                    Hash::hash(redirected, _state)
                },
            }
        }
    }

    impl AsRef<Head>
        for Head {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp.dfy(390,3)
    #[derive(Clone)]
    pub enum Disposition {
        PassThrough {},
        Decrypt {
            nonce: Sequence<u8>,
            requireFrame: bool
        },
        NeedProblemBody {},
        Refuse {
            code: Arc<Code>,
            message: Sequence<DafnyChar>
        }
    }

    impl Disposition {
        /// Gets the field nonce for all enum members which have it
        pub fn nonce(&self) -> &Sequence<u8> {
            match self {
                Disposition::PassThrough{} => panic!("field does not exist on this variant"),
                Disposition::Decrypt{nonce, requireFrame, } => nonce,
                Disposition::NeedProblemBody{} => panic!("field does not exist on this variant"),
                Disposition::Refuse{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field requireFrame for all enum members which have it
        pub fn requireFrame(&self) -> &bool {
            match self {
                Disposition::PassThrough{} => panic!("field does not exist on this variant"),
                Disposition::Decrypt{nonce, requireFrame, } => requireFrame,
                Disposition::NeedProblemBody{} => panic!("field does not exist on this variant"),
                Disposition::Refuse{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field code for all enum members which have it
        pub fn code(&self) -> &Arc<Code> {
            match self {
                Disposition::PassThrough{} => panic!("field does not exist on this variant"),
                Disposition::Decrypt{nonce, requireFrame, } => panic!("field does not exist on this variant"),
                Disposition::NeedProblemBody{} => panic!("field does not exist on this variant"),
                Disposition::Refuse{code, message, } => code,
            }
        }
        /// Gets the field message for all enum members which have it
        pub fn message(&self) -> &Sequence<DafnyChar> {
            match self {
                Disposition::PassThrough{} => panic!("field does not exist on this variant"),
                Disposition::Decrypt{nonce, requireFrame, } => panic!("field does not exist on this variant"),
                Disposition::NeedProblemBody{} => panic!("field does not exist on this variant"),
                Disposition::Refuse{code, message, } => message,
            }
        }
    }

    impl Debug
        for Disposition {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Disposition {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Disposition::PassThrough{} => {
                    write!(_formatter, "EHBP.Disposition.PassThrough")?;
                    Ok(())
                },
                Disposition::Decrypt{nonce, requireFrame, } => {
                    write!(_formatter, "EHBP.Disposition.Decrypt(")?;
                    DafnyPrint::fmt_print(nonce, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(requireFrame, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Disposition::NeedProblemBody{} => {
                    write!(_formatter, "EHBP.Disposition.NeedProblemBody")?;
                    Ok(())
                },
                Disposition::Refuse{code, message, } => {
                    write!(_formatter, "EHBP.Disposition.Refuse(")?;
                    DafnyPrint::fmt_print(code, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(message, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Disposition {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Disposition::PassThrough{}, Disposition::PassThrough{}) => {
                    true
                },
                (Disposition::Decrypt{nonce, requireFrame, }, Disposition::Decrypt{nonce: _2_nonce, requireFrame: _2_requireFrame, }) => {
                    nonce == _2_nonce && requireFrame == _2_requireFrame
                },
                (Disposition::NeedProblemBody{}, Disposition::NeedProblemBody{}) => {
                    true
                },
                (Disposition::Refuse{code, message, }, Disposition::Refuse{code: _2_code, message: _2_message, }) => {
                    code == _2_code && message == _2_message
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Disposition {}

    impl Hash
        for Disposition {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Disposition::PassThrough{} => {
                    
                },
                Disposition::Decrypt{nonce, requireFrame, } => {
                    Hash::hash(nonce, _state);
                    Hash::hash(requireFrame, _state)
                },
                Disposition::NeedProblemBody{} => {
                    
                },
                Disposition::Refuse{code, message, } => {
                    Hash::hash(code, _state);
                    Hash::hash(message, _state)
                },
            }
        }
    }

    impl AsRef<Disposition>
        for Disposition {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp.dfy(444,3)
    #[derive(Clone)]
    pub enum Origin {
        Origin {
            scheme: Sequence<DafnyChar>,
            host: Sequence<DafnyChar>,
            port: DafnyInt
        }
    }

    impl Origin {
        /// Returns a borrow of the field scheme
        pub fn scheme(&self) -> &Sequence<DafnyChar> {
            match self {
                Origin::Origin{scheme, host, port, } => scheme,
            }
        }
        /// Returns a borrow of the field host
        pub fn host(&self) -> &Sequence<DafnyChar> {
            match self {
                Origin::Origin{scheme, host, port, } => host,
            }
        }
        /// Returns a borrow of the field port
        pub fn port(&self) -> &DafnyInt {
            match self {
                Origin::Origin{scheme, host, port, } => port,
            }
        }
    }

    impl Debug
        for Origin {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Origin {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Origin::Origin{scheme, host, port, } => {
                    write!(_formatter, "EHBP.Origin.Origin(")?;
                    DafnyPrint::fmt_print(scheme, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(host, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(port, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Origin {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Origin::Origin{scheme, host, port, }, Origin::Origin{scheme: _2_scheme, host: _2_host, port: _2_port, }) => {
                    scheme == _2_scheme && host == _2_host && port == _2_port
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Origin {}

    impl Hash
        for Origin {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Origin::Origin{scheme, host, port, } => {
                    Hash::hash(scheme, _state);
                    Hash::hash(host, _state);
                    Hash::hash(port, _state)
                },
            }
        }
    }

    impl AsRef<Origin>
        for Origin {
        fn as_ref(&self) -> &Self {
            self
        }
    }
}
/// ehbp_events.dfy(16,1)
pub mod EHBPEvents {
    pub use ::std::sync::Arc;
    pub use crate::EHBPEvents::Action::Fail;
    pub use crate::EHBPEvents::Action::Finished;
    pub use crate::EHBPEvents::Action::Passthrough;
    pub use crate::EHBPEvents::Action::Discovered;
    pub use crate::EHBPEvents::Action::Close;
    pub use ::dafny_runtime::Sequence;
    pub use ::dafny_runtime::integer_range;
    pub use ::dafny_runtime::int;
    pub use ::dafny_runtime::DafnyInt;
    pub use ::std::marker::Sync;
    pub use crate::EHBPEvents::Action::ClearToken;
    pub use crate::EHBPEvents::Action::EmitPlaintext;
    pub use ::dafny_runtime::Object;
    pub use crate::EHBPEvents::Action::BeginSession;
    pub use ::dafny_runtime::rd;
    pub use crate::EHBPEvents::Action::PublishToken;
    pub use crate::EHBPEvents::Action::RandomBytes;
    pub use ::dafny_runtime::_System::nat;
    pub use crate::EHBPEvents::Action::X25519;
    pub use crate::EHBPEvents::Action::HmacSha256;
    pub use crate::EHBPEvents::Action::AeadSeal;
    pub use crate::EHBPEvents::Action::AeadOpen;
    pub use ::dafny_runtime::DafnyChar;
    pub use crate::EHBPEvents::Action::Write;
    pub use crate::EHBPEvents::Action::Read;
    pub use crate::EHBPEvents::Action::Done;
    pub use crate::EHBP::Code;
    pub use ::dafny_runtime::seq;
    pub use crate::EHBPEvents::Job::JExtract;
    pub use crate::EHBPEvents::Event::HmacResult;
    pub use ::dafny_runtime::string_of;
    pub use ::dafny_runtime::Zero;
    pub use ::dafny_runtime::truncate;
    pub use crate::EHBPEvents::Hpke::HRandom;
    pub use crate::EHBPEvents::Event::RandomResult;
    pub use crate::EHBPEvents::Hpke::HEnc;
    pub use crate::EHBPEvents::Event::X25519Result;
    pub use crate::EHBPEvents::Hpke::HDh;
    pub use crate::EHBPEvents::JobOut::Pending;
    pub use crate::EHBPEvents::JobOut::Output;
    pub use ::std::primitive::char;
    pub use crate::EHBP::Option;
    pub use crate::EHBP::Option::None;
    pub use ::dafny_runtime::NumCast;
    pub use crate::EHBP::Option::Some;
    pub use ::dafny_runtime::MaybePlacebo;
    pub use ::std::mem::MaybeUninit;
    pub use ::dafny_runtime::array;
    pub use ::dafny_runtime::DafnyUsize;
    pub use ::dafny_runtime::DafnyType;
    pub use crate::EHBPEvents::Json::JNull;
    pub use crate::EHBPEvents::Json::JBool;
    pub use crate::EHBPEvents::Json::JNumber;
    pub use crate::EHBPEvents::Json::JString;
    pub use crate::EHBPEvents::Json::JArray;
    pub use ::dafny_runtime::euclidian_division;
    pub use ::dafny_runtime::euclidian_modulo;
    pub use crate::EHBPEvents::SessionAction::Begin;
    pub use crate::EHBP::Token;
    pub use crate::EHBPEvents::SessionAction::Publish;
    pub use crate::EHBP::Framed;
    pub use crate::EHBP::Origin;
    pub use crate::EHBPEvents::Phase::Exchanging;
    pub use crate::EHBPEvents::Response::Body;
    pub use crate::EHBPEvents::Event::AeadOpenResult;
    pub use crate::EHBPEvents::Response::Opening;
    pub use crate::EHBPEvents::Phase::Idle;
    pub use crate::EHBPEvents::Phase::AwaitSession;
    pub use crate::EHBPEvents::Phase::Peeking;
    pub use crate::EHBPEvents::Phase::AwaitSetup;
    pub use crate::EHBPEvents::Phase::AwaitExport;
    pub use crate::EHBPEvents::Phase::DiscAwaitHead;
    pub use crate::EHBPEvents::Phase::DiscReading;
    pub use crate::EHBPEvents::Event::StreamFailed;
    pub use crate::EHBPEvents::Stream::RequestBody;
    pub use crate::EHBPEvents::Event::AeadSealResult;
    pub use crate::EHBPEvents::Event::CallerClose;
    pub use crate::EHBPEvents::Event::Start;
    pub use crate::EHBPEvents::Event::DiscoverStart;
    pub use crate::EHBPEvents::Event::SessionBegun;
    pub use crate::EHBPEvents::Event::ResponseHead;
    pub use crate::EHBPEvents::HpkeOut::HContinue;
    pub use crate::EHBPEvents::HpkeOut::HReady;
    pub use crate::EHBPEvents::Event::CallerRead;
    pub use crate::EHBP::Head;
    pub use crate::EHBP::Result::Ok;
    pub use crate::EHBPEvents::Upload::NoUpload;
    pub use crate::EHBPEvents::Upload::Sealing;
    pub use crate::EHBPEvents::Upload::UpReading;
    pub use crate::EHBPEvents::Response::AwaitHead;
    pub use crate::EHBP::Disposition;
    pub use crate::EHBP::Disposition::PassThrough;
    pub use crate::EHBP::Disposition::Decrypt;
    pub use crate::EHBP::Disposition::NeedProblemBody;
    pub use crate::EHBPEvents::Response::ProblemReading;
    pub use crate::EHBPEvents::Response::AwaitKeys;
    pub use crate::EHBPEvents::Response::BodyReading;
    pub use ::std::fmt::Debug;
    pub use ::std::fmt::Formatter;
    pub use ::dafny_runtime::DafnyPrint;
    pub use ::dafny_runtime::SequenceIter;
    pub use ::std::cmp::PartialEq;
    pub use ::std::cmp::Eq;
    pub use ::std::hash::Hash;
    pub use ::std::hash::Hasher;
    pub use ::std::convert::AsRef;
    pub use ::dafny_runtime::Any;
    pub use ::dafny_runtime::UpcastObject;

    pub struct _default {}

    impl _default {
        /// ehbp_events.dfy(75,3)
        pub fn Terminal(a: &Arc<Action>) -> bool {
            matches!(a.as_ref(), Fail{ .. }) || matches!(a.as_ref(), Finished{ .. }) || matches!(a.as_ref(), Passthrough{ .. }) || matches!(a.as_ref(), Discovered{ .. }) || matches!(a.as_ref(), Close{ .. })
        }
        /// ehbp_events.dfy(76,3)
        pub fn Ends(acts: &Sequence<Arc<Action>>) -> bool {
            integer_range(int!(0), acts.cardinality()).any(({
                    let mut acts = acts.clone();
                    Arc::new(move |__exists_var_0: DafnyInt| -> bool{
            let mut i: DafnyInt = __exists_var_0.clone();
            int!(0) <= i.clone() && i.clone() < acts.cardinality() && _default::Terminal(&acts.get(&i))
        }) as Arc<dyn ::std::ops::Fn(_) -> _ + Sync + ::std::marker::Send>
                }).as_ref())
        }
        /// ehbp_events.dfy(77,3)
        pub fn NoClear(acts: &Sequence<Arc<Action>>) -> bool {
            integer_range(int!(0), acts.cardinality()).all(({
                    let mut acts = acts.clone();
                    Arc::new(move |__forall_var_0: DafnyInt| -> bool{
            let mut i: DafnyInt = __forall_var_0.clone();
            !(int!(0) <= i.clone() && i.clone() < acts.cardinality()) || !matches!((&acts.get(&i)).as_ref(), ClearToken{ .. })
        }) as Arc<dyn ::std::ops::Fn(_) -> _ + Sync + ::std::marker::Send>
                }).as_ref())
        }
        /// ehbp_events.dfy(78,3)
        pub fn ClearsOnce(acts: &Sequence<Arc<Action>>, g: u64) -> bool {
            integer_range(int!(0), acts.cardinality()).any(({
                    let mut g = g.clone();
                    let mut acts = acts.clone();
                    Arc::new(move |__exists_var_0: DafnyInt| -> bool{
            let mut i: DafnyInt = __exists_var_0.clone();
            int!(0) <= i.clone() && i.clone() < acts.cardinality() && acts.get(&i) == Arc::new(Action::ClearToken {
                    generation: g
                }) && integer_range(int!(0), acts.cardinality()).all(({
                    let mut i = i.clone();
                    let mut acts = acts.clone();
                    Arc::new(move |__forall_var_0: DafnyInt| -> bool{
            let mut j: DafnyInt = __forall_var_0.clone();
            !(int!(0) <= j.clone() && j.clone() < acts.cardinality() && j.clone() != i.clone()) || !matches!((&acts.get(&j)).as_ref(), ClearToken{ .. })
        }) as Arc<dyn ::std::ops::Fn(_) -> _ + Sync + ::std::marker::Send>
                }).as_ref())
        }) as Arc<dyn ::std::ops::Fn(_) -> _ + Sync + ::std::marker::Send>
                }).as_ref())
        }
        /// ehbp_events.dfy(82,3)
        pub fn NoEmit(acts: &Sequence<Arc<Action>>) -> bool {
            integer_range(int!(0), acts.cardinality()).all(({
                    let mut acts = acts.clone();
                    Arc::new(move |__forall_var_0: DafnyInt| -> bool{
            let mut i: DafnyInt = __forall_var_0.clone();
            !(int!(0) <= i.clone() && i.clone() < acts.cardinality()) || !matches!((&acts.get(&i)).as_ref(), EmitPlaintext{ .. })
        }) as Arc<dyn ::std::ops::Fn(_) -> _ + Sync + ::std::marker::Send>
                }).as_ref())
        }
        /// ehbp_events.dfy(113,3)
        pub fn Perform(p: &Object<dyn Performer>, a: &Arc<Action>) -> Arc<Performed> {
            let mut r: Arc<Performed>;
            let mut _source0: Arc<Action> = a.clone();
            if matches!((&_source0).as_ref(), BeginSession{ .. }) {
                let mut generation: u64;
                let mut _out0: u64 = Performer::BeginSession(rd!(p.clone()));
                generation = _out0;
                r = Arc::new(Performed::Got {
                            e: Arc::new(Event::SessionBegun {
                                        generation: generation
                                    })
                        });
                return r.clone();
            } else {
                if matches!((&_source0).as_ref(), PublishToken{ .. }) {
                    let mut ___mcc_h0: u64 = _source0.generation().clone();
                    let mut ___mcc_h1: Sequence<u8> = _source0.exportedSecret().clone();
                    let mut ___mcc_h2: Sequence<u8> = _source0.requestEnc().clone();
                    let mut requestEnc: Sequence<u8> = ___mcc_h2.clone();
                    let mut exportedSecret: Sequence<u8> = ___mcc_h1.clone();
                    let mut generation: u64 = ___mcc_h0;
                    Performer::PublishToken(rd!(p.clone()), generation, &exportedSecret, &requestEnc);
                    r = Arc::new(Performed::Quiet {});
                    return r.clone();
                } else {
                    if matches!((&_source0).as_ref(), ClearToken{ .. }) {
                        let mut ___mcc_h3: u64 = _source0.generation().clone();
                        let mut generation: u64 = ___mcc_h3;
                        Performer::ClearToken(rd!(p.clone()), generation);
                        r = Arc::new(Performed::Quiet {});
                        return r.clone();
                    } else {
                        if matches!((&_source0).as_ref(), RandomBytes{ .. }) {
                            let mut ___mcc_h4: nat = _source0.length().clone();
                            let mut length: nat = ___mcc_h4.clone();
                            let mut data: Sequence<u8>;
                            let mut _out1: Sequence<u8> = Performer::RandomBytes(rd!(p.clone()), &length);
                            data = _out1.clone();
                            r = Arc::new(Performed::Got {
                                        e: Arc::new(Event::RandomResult {
                                                    data: data.clone()
                                                })
                                    });
                            return r.clone();
                        } else {
                            if matches!((&_source0).as_ref(), X25519{ .. }) {
                                let mut ___mcc_h5: Sequence<u8> = _source0.scalar().clone();
                                let mut ___mcc_h6: Sequence<u8> = _source0.point().clone();
                                let mut point: Sequence<u8> = ___mcc_h6.clone();
                                let mut scalar: Sequence<u8> = ___mcc_h5.clone();
                                let mut shared: Sequence<u8>;
                                let mut _out2: Sequence<u8> = Performer::X25519(rd!(p.clone()), &scalar, &point);
                                shared = _out2.clone();
                                r = Arc::new(Performed::Got {
                                            e: Arc::new(Event::X25519Result {
                                                        point: shared.clone()
                                                    })
                                        });
                                return r.clone();
                            } else {
                                if matches!((&_source0).as_ref(), HmacSha256{ .. }) {
                                    let mut ___mcc_h7: Sequence<u8> = _source0.key().clone();
                                    let mut ___mcc_h8: Sequence<u8> = _source0.data().clone();
                                    let mut data: Sequence<u8> = ___mcc_h8.clone();
                                    let mut key: Sequence<u8> = ___mcc_h7.clone();
                                    let mut mac: Sequence<u8>;
                                    let mut _out3: Sequence<u8> = Performer::HmacSha256(rd!(p.clone()), &key, &data);
                                    mac = _out3.clone();
                                    r = Arc::new(Performed::Got {
                                                e: Arc::new(Event::HmacResult {
                                                            mac: mac.clone()
                                                        })
                                            });
                                    return r.clone();
                                } else {
                                    if matches!((&_source0).as_ref(), AeadSeal{ .. }) {
                                        let mut ___mcc_h9: Sequence<u8> = _source0.key().clone();
                                        let mut ___mcc_h10: Sequence<u8> = _source0.nonce().clone();
                                        let mut ___mcc_h11: Sequence<u8> = _source0.plaintext().clone();
                                        let mut plaintext: Sequence<u8> = ___mcc_h11.clone();
                                        let mut nonce: Sequence<u8> = ___mcc_h10.clone();
                                        let mut key: Sequence<u8> = ___mcc_h9.clone();
                                        let mut ciphertext: Sequence<u8>;
                                        let mut _out4: Sequence<u8> = Performer::AeadSeal(rd!(p.clone()), &key, &nonce, &plaintext);
                                        ciphertext = _out4.clone();
                                        r = Arc::new(Performed::Got {
                                                    e: Arc::new(Event::AeadSealResult {
                                                                ciphertext: ciphertext.clone()
                                                            })
                                                });
                                        return r.clone();
                                    } else {
                                        if matches!((&_source0).as_ref(), AeadOpen{ .. }) {
                                            let mut ___mcc_h12: Sequence<u8> = _source0.key().clone();
                                            let mut ___mcc_h13: Sequence<u8> = _source0.nonce().clone();
                                            let mut ___mcc_h14: Sequence<u8> = _source0.ciphertext().clone();
                                            let mut ciphertext: Sequence<u8> = ___mcc_h14.clone();
                                            let mut nonce: Sequence<u8> = ___mcc_h13.clone();
                                            let mut key: Sequence<u8> = ___mcc_h12.clone();
                                            let mut ok: bool;
                                            let mut plaintext: Sequence<u8>;
                                            let mut _out5: bool;
                                            let mut _out6: Sequence<u8>;
                                            let _x = Performer::AeadOpen(rd!(p.clone()), &key, &nonce, &ciphertext);
                                            _out5 = _x.0;
                                            _out6 = _x.1;
                                            ok = _out5;
                                            plaintext = _out6.clone();
                                            r = Arc::new(Performed::Got {
                                                        e: Arc::new(Event::AeadOpenResult {
                                                                    ok: ok,
                                                                    plaintext: plaintext.clone()
                                                                })
                                                    });
                                            return r.clone();
                                        } else {
                                            if matches!((&_source0).as_ref(), crate::EHBPEvents::Action::Send{ .. }) {
                                                let mut ___mcc_h15: Sequence<DafnyChar> = _source0.verb().clone();
                                                let mut ___mcc_h16: Sequence<DafnyChar> = _source0.url().clone();
                                                let mut ___mcc_h17: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source0.headers().clone();
                                                let mut ___mcc_h18: bool = _source0.hasBody().clone();
                                                let mut hasBody: bool = ___mcc_h18;
                                                let mut headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = ___mcc_h17.clone();
                                                let mut url: Sequence<DafnyChar> = ___mcc_h16.clone();
                                                let mut verb: Sequence<DafnyChar> = ___mcc_h15.clone();
                                                let mut ok: bool;
                                                let mut status: DafnyInt;
                                                let mut head: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>;
                                                let mut redirected: bool;
                                                let mut _out7: bool;
                                                let mut _out8: DafnyInt;
                                                let mut _out9: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>;
                                                let mut _out10: bool;
                                                let _x = Performer::Send(rd!(p.clone()), &verb, &url, &headers, hasBody);
                                                _out7 = _x.0;
                                                _out8 = _x.1;
                                                _out9 = _x.2;
                                                _out10 = _x.3;
                                                ok = _out7;
                                                status = _out8.clone();
                                                head = _out9.clone();
                                                redirected = _out10;
                                                r = Arc::new(Performed::Got {
                                                            e: if ok {
                                                                    Arc::new(Event::ResponseHead {
                                                                            status: status.clone(),
                                                                            headers: head.clone(),
                                                                            redirected: redirected
                                                                        })
                                                                } else {
                                                                    Arc::new(Event::StreamFailed {
                                                                            stream: Arc::new(Stream::ResponseBody {})
                                                                        })
                                                                }
                                                        });
                                                return r.clone();
                                            } else {
                                                if matches!((&_source0).as_ref(), Write{ .. }) {
                                                    let mut ___mcc_h19: Sequence<u8> = _source0.data().clone();
                                                    let mut ___mcc_h20: Arc<BodyEnd> = _source0.end().clone();
                                                    let mut end: Arc<BodyEnd> = ___mcc_h20.clone();
                                                    let mut data: Sequence<u8> = ___mcc_h19.clone();
                                                    let mut ok: bool;
                                                    let mut _out11: bool = Performer::Write(rd!(p.clone()), &data, &end);
                                                    ok = _out11;
                                                    if ok {
                                                        r = Arc::new(Performed::Quiet {});
                                                    } else {
                                                        r = Arc::new(Performed::Stop {});
                                                    };
                                                    return r.clone();
                                                } else {
                                                    if matches!((&_source0).as_ref(), Read{ .. }) {
                                                        let mut ___mcc_h21: Arc<Stream> = _source0.stream().clone();
                                                        let mut stream: Arc<Stream> = ___mcc_h21.clone();
                                                        let mut ok: bool;
                                                        let mut data: Sequence<u8>;
                                                        let mut eof: bool;
                                                        let mut _out12: bool;
                                                        let mut _out13: Sequence<u8>;
                                                        let mut _out14: bool;
                                                        let _x = Performer::Read(rd!(p.clone()), &stream);
                                                        _out12 = _x.0;
                                                        _out13 = _x.1;
                                                        _out14 = _x.2;
                                                        ok = _out12;
                                                        data = _out13.clone();
                                                        eof = _out14;
                                                        r = Arc::new(Performed::Got {
                                                                    e: if ok {
                                                                            Arc::new(Event::Chunk {
                                                                                    stream: stream.clone(),
                                                                                    data: data.clone(),
                                                                                    eof: eof
                                                                                })
                                                                        } else {
                                                                            Arc::new(Event::StreamFailed {
                                                                                    stream: stream.clone()
                                                                                })
                                                                        }
                                                                });
                                                        return r.clone();
                                                    } else {
                                                        if matches!((&_source0).as_ref(), Close{ .. }) {
                                                            let mut ___mcc_h22: Arc<Stream> = _source0.stream().clone();
                                                            let mut stream: Arc<Stream> = ___mcc_h22.clone();
                                                            Performer::Close(rd!(p.clone()), &stream);
                                                            r = Arc::new(Performed::Quiet {});
                                                            return r.clone();
                                                        } else {
                                                            if matches!((&_source0).as_ref(), EmitPlaintext{ .. }) {
                                                                let mut ___mcc_h23: Sequence<u8> = _source0.data().clone();
                                                                let mut data: Sequence<u8> = ___mcc_h23.clone();
                                                                Performer::EmitPlaintext(rd!(p.clone()), &data);
                                                                r = Arc::new(Performed::Quiet {});
                                                                return r.clone();
                                                            } else {
                                                                if matches!((&_source0).as_ref(), Passthrough{ .. }) {
                                                                    let mut ___mcc_h24: DafnyInt = _source0.status().clone();
                                                                    let mut ___mcc_h25: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source0.headers().clone();
                                                                    let mut ___mcc_h26: Sequence<u8> = _source0.prefix().clone();
                                                                    r = Arc::new(Performed::Quiet {});
                                                                    return r.clone();
                                                                } else {
                                                                    if matches!((&_source0).as_ref(), Done{ .. }) {
                                                                        let mut ___mcc_h27: DafnyInt = _source0.status().clone();
                                                                        let mut ___mcc_h28: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source0.headers().clone();
                                                                        r = Arc::new(Performed::Quiet {});
                                                                        return r.clone();
                                                                    } else {
                                                                        if matches!((&_source0).as_ref(), Finished{ .. }) {
                                                                            r = Arc::new(Performed::Quiet {});
                                                                            return r.clone();
                                                                        } else {
                                                                            if matches!((&_source0).as_ref(), Discovered{ .. }) {
                                                                                let mut ___mcc_h29: Sequence<u8> = _source0.publicKey().clone();
                                                                                r = Arc::new(Performed::Quiet {});
                                                                                return r.clone();
                                                                            } else {
                                                                                let mut ___mcc_h30: Arc<Code> = _source0.code().clone();
                                                                                let mut ___mcc_h31: Sequence<DafnyChar> = _source0.message().clone();
                                                                                r = Arc::new(Performed::Quiet {});
                                                                                return r.clone();
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };
            return r.clone();
        }
        /// ehbp_events.dfy(170,3)
        pub fn Extract(salt: &Sequence<u8>, ikm: &Sequence<u8>) -> Arc<Job> {
            Arc::new(Job::JExtract {
                    salt: salt.clone(),
                    ikm: ikm.clone()
                })
        }
        /// ehbp_events.dfy(171,3)
        pub fn Expand(prk: &Sequence<u8>, info: &Sequence<u8>, length: &nat) -> Arc<Job> {
            Arc::new(Job::JExpand {
                    prk: prk.clone(),
                    info: info.clone(),
                    length: length.clone(),
                    acc: seq![] as Sequence<u8>,
                    prev: seq![] as Sequence<u8>,
                    i: 1
                })
        }
        /// ehbp_events.dfy(173,3)
        pub fn JobAction(j: &Arc<Job>) -> Arc<Action> {
            let mut _source0: Arc<Job> = j.clone();
            if matches!((&_source0).as_ref(), JExtract{ .. }) {
                let mut ___mcc_h0: Sequence<u8> = _source0.salt().clone();
                let mut ___mcc_h1: Sequence<u8> = _source0.ikm().clone();
                let mut ikm: Sequence<u8> = ___mcc_h1.clone();
                let mut salt: Sequence<u8> = ___mcc_h0.clone();
                Arc::new(Action::HmacSha256 {
                        key: salt.clone(),
                        data: ikm.clone()
                    })
            } else {
                let mut ___mcc_h2: Sequence<u8> = _source0.prk().clone();
                let mut ___mcc_h3: Sequence<u8> = _source0.info().clone();
                let mut ___mcc_h4: nat = _source0.length().clone();
                let mut ___mcc_h5: Sequence<u8> = _source0.acc().clone();
                let mut ___mcc_h6: Sequence<u8> = _source0.prev().clone();
                let mut ___mcc_h7: u8 = _source0.i().clone();
                let mut i: u8 = ___mcc_h7;
                let mut prev: Sequence<u8> = ___mcc_h6.clone();
                let mut info: Sequence<u8> = ___mcc_h3.clone();
                let mut prk: Sequence<u8> = ___mcc_h2.clone();
                Arc::new(Action::HmacSha256 {
                        key: prk.clone(),
                        data: prev.concat(&info).concat(&seq![i])
                    })
            }
        }
        /// ehbp_events.dfy(182,3)
        pub fn JobStep(j: &Arc<Job>, e: &Arc<Event>) -> Arc<JobOut> {
            if !matches!(e.as_ref(), HmacResult{ .. }) {
                Arc::new(JobOut::JobFailed {
                        code: Arc::new(Code::Transport {}),
                        message: string_of("unexpected event")
                    })
            } else {
                if e.mac().cardinality() != crate::EHBP::_default::HashLength() {
                    Arc::new(JobOut::JobFailed {
                            code: Arc::new(Code::HpkeSetupFailed {}),
                            message: string_of("HMAC returned the wrong length")
                        })
                } else {
                    let mut _source0: Arc<Job> = j.clone();
                    if matches!((&_source0).as_ref(), JExtract{ .. }) {
                        let mut ___mcc_h0: Sequence<u8> = _source0.salt().clone();
                        let mut ___mcc_h1: Sequence<u8> = _source0.ikm().clone();
                        Arc::new(JobOut::Output {
                                data: e.mac().clone()
                            })
                    } else {
                        let mut ___mcc_h2: Sequence<u8> = _source0.prk().clone();
                        let mut ___mcc_h3: Sequence<u8> = _source0.info().clone();
                        let mut ___mcc_h4: nat = _source0.length().clone();
                        let mut ___mcc_h5: Sequence<u8> = _source0.acc().clone();
                        let mut ___mcc_h6: Sequence<u8> = _source0.prev().clone();
                        let mut ___mcc_h7: u8 = _source0.i().clone();
                        let mut i: u8 = ___mcc_h7;
                        let mut acc: Sequence<u8> = ___mcc_h5.clone();
                        let mut length: nat = ___mcc_h4.clone();
                        let mut info: Sequence<u8> = ___mcc_h3.clone();
                        let mut prk: Sequence<u8> = ___mcc_h2.clone();
                        let mut grown: Sequence<u8> = acc.concat(e.mac());
                        if grown.cardinality() >= length.clone() {
                            Arc::new(JobOut::Output {
                                    data: grown.take(&length)
                                })
                        } else {
                            if i == 255 {
                                Arc::new(JobOut::JobFailed {
                                        code: Arc::new(Code::HpkeSetupFailed {}),
                                        message: string_of("HKDF expand length too large")
                                    })
                            } else {
                                let mut next: Arc<Job> = Arc::new(Job::JExpand {
                                            prk: prk.clone(),
                                            info: info.clone(),
                                            length: length.clone(),
                                            acc: grown.clone(),
                                            prev: e.mac().clone(),
                                            i: i + 1
                                        });
                                Arc::new(JobOut::Pending {
                                        job: next.clone(),
                                        action: _default::JobAction(&next)
                                    })
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(206,3)
        pub fn Repeat(n: &nat, v: u8) -> Sequence<u8> {
            {
                let _initializer = {
                        let v: u8 = v;
                        {
                            let mut v = v.clone();
                            Arc::new(move |i: &DafnyInt| -> u8{
            v
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                        }
                    };
                integer_range(Zero::zero(), n.clone()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
            }
        }
        /// ehbp_events.dfy(207,3)
        pub fn Iota(n: &nat) -> Sequence<u8> {
            {
                let _initializer = {
                        let n: nat = n.clone();
                        {
                            Arc::new(move |i: &DafnyInt| -> u8{
            truncate!(i.clone(), u8)
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                        }
                    };
                integer_range(Zero::zero(), n.clone()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
            }
        }
        /// ehbp_events.dfy(211,3)
        pub fn LabeledExtract(suite: &Sequence<u8>, salt: &Sequence<u8>, tag: &Sequence<DafnyChar>, ikm: &Sequence<u8>) -> Arc<Job> {
            _default::Extract(salt, &_default::HpkeVersion().concat(suite).concat(&crate::EHBP::_default::Ascii(tag)).concat(ikm))
        }
        /// ehbp_events.dfy(217,3)
        pub fn LabeledExpand(suite: &Sequence<u8>, prk: &Sequence<u8>, tag: &Sequence<DafnyChar>, info: &Sequence<u8>, length: &nat) -> Arc<Job> {
            _default::Expand(prk, &crate::EHBP::_default::BE16(truncate!(length.clone(), u16)).concat(&_default::HpkeVersion()).concat(suite).concat(&crate::EHBP::_default::Ascii(tag)).concat(info), length)
        }
        /// ehbp_events.dfy(237,3)
        pub fn SenderStart(pkR: &Sequence<u8>, info: &Sequence<u8>) -> Arc<HpkeOut> {
            Arc::new(HpkeOut::HContinue {
                    h: Arc::new(Hpke::HRandom {
                                pkR: pkR.clone(),
                                info: info.clone()
                            }),
                    action: Arc::new(Action::RandomBytes {
                                length: int!(32)
                            })
                })
        }
        /// ehbp_events.dfy(239,3)
        pub fn RecipientStart(skR: &Sequence<u8>, pkR: &Sequence<u8>, enc: &Sequence<u8>, info: &Sequence<u8>) -> Arc<HpkeOut> {
            Arc::new(HpkeOut::HContinue {
                    h: Arc::new(Hpke::HDh {
                                enc: enc.clone(),
                                pkR: pkR.clone(),
                                info: info.clone()
                            }),
                    action: Arc::new(Action::X25519 {
                                scalar: skR.clone(),
                                point: enc.clone()
                            })
                })
        }
        /// ehbp_events.dfy(241,3)
        pub fn Schedule(h: &Arc<Hpke>, job: &Arc<Job>) -> Arc<HpkeOut> {
            Arc::new(HpkeOut::HContinue {
                    h: {
                            let __pat_let1_0: Arc<Hpke> = h.clone();
                            {
                                let _dt__update__tmp_h0: Arc<Hpke> = __pat_let1_0.clone();
                                {
                                    let __pat_let2_0: Arc<Job> = job.clone();
                                    {
                                        let _dt__update_hjob_h0: Arc<Job> = __pat_let2_0.clone();
                                        Arc::new(Hpke::HSchedule {
                                                stage: _dt__update__tmp_h0.stage().clone(),
                                                job: _dt__update_hjob_h0.clone(),
                                                enc: _dt__update__tmp_h0.enc().clone(),
                                                pkR: _dt__update__tmp_h0.pkR().clone(),
                                                info: _dt__update__tmp_h0.info().clone(),
                                                shared: _dt__update__tmp_h0.shared().clone(),
                                                pskIdHash: _dt__update__tmp_h0.pskIdHash().clone(),
                                                infoHash: _dt__update__tmp_h0.infoHash().clone(),
                                                secret: _dt__update__tmp_h0.secret().clone(),
                                                key: _dt__update__tmp_h0.key().clone(),
                                                baseNonce: _dt__update__tmp_h0.baseNonce().clone()
                                            })
                                    }
                                }
                            }
                        },
                    action: _default::JobAction(job)
                })
        }
        /// ehbp_events.dfy(247,3)
        pub fn HpkeStep(h: &Arc<Hpke>, e: &Arc<Event>) -> Arc<HpkeOut> {
            let mut _source0: Arc<Hpke> = h.clone();
            if matches!((&_source0).as_ref(), HRandom{ .. }) {
                let mut ___mcc_h0: Sequence<u8> = _source0.pkR().clone();
                let mut ___mcc_h1: Sequence<u8> = _source0.info().clone();
                let mut info: Sequence<u8> = ___mcc_h1.clone();
                let mut pkR: Sequence<u8> = ___mcc_h0.clone();
                if !matches!(e.as_ref(), RandomResult{ .. }) {
                    Arc::new(HpkeOut::HFailed {
                            code: Arc::new(Code::Transport {}),
                            message: string_of("unexpected event")
                        })
                } else {
                    if e.data().cardinality() != int!(32) {
                        Arc::new(HpkeOut::HFailed {
                                code: Arc::new(Code::HpkeSetupFailed {}),
                                message: string_of("random bytes have the wrong length")
                            })
                    } else {
                        Arc::new(HpkeOut::HContinue {
                                h: Arc::new(Hpke::HEnc {
                                            skE: e.data().clone(),
                                            pkR: pkR.clone(),
                                            info: info.clone()
                                        }),
                                action: Arc::new(Action::X25519 {
                                            scalar: e.data().clone(),
                                            point: _default::BasePoint()
                                        })
                            })
                    }
                }
            } else {
                if matches!((&_source0).as_ref(), HEnc{ .. }) {
                    let mut ___mcc_h2: Sequence<u8> = _source0.skE().clone();
                    let mut ___mcc_h3: Sequence<u8> = _source0.pkR().clone();
                    let mut ___mcc_h4: Sequence<u8> = _source0.info().clone();
                    let mut info: Sequence<u8> = ___mcc_h4.clone();
                    let mut pkR: Sequence<u8> = ___mcc_h3.clone();
                    let mut skE: Sequence<u8> = ___mcc_h2.clone();
                    if !matches!(e.as_ref(), X25519Result{ .. }) {
                        Arc::new(HpkeOut::HFailed {
                                code: Arc::new(Code::Transport {}),
                                message: string_of("unexpected event")
                            })
                    } else {
                        if e.point().cardinality() != int!(32) {
                            Arc::new(HpkeOut::HFailed {
                                    code: Arc::new(Code::HpkeSetupFailed {}),
                                    message: string_of("X25519 failed")
                                })
                        } else {
                            Arc::new(HpkeOut::HContinue {
                                    h: Arc::new(Hpke::HDh {
                                                enc: e.point().clone(),
                                                pkR: pkR.clone(),
                                                info: info.clone()
                                            }),
                                    action: Arc::new(Action::X25519 {
                                                scalar: skE.clone(),
                                                point: pkR.clone()
                                            })
                                })
                        }
                    }
                } else {
                    if matches!((&_source0).as_ref(), HDh{ .. }) {
                        let mut ___mcc_h5: Sequence<u8> = _source0.enc().clone();
                        let mut ___mcc_h6: Sequence<u8> = _source0.pkR().clone();
                        let mut ___mcc_h7: Sequence<u8> = _source0.info().clone();
                        let mut info: Sequence<u8> = ___mcc_h7.clone();
                        let mut pkR: Sequence<u8> = ___mcc_h6.clone();
                        let mut enc: Sequence<u8> = ___mcc_h5.clone();
                        if !matches!(e.as_ref(), X25519Result{ .. }) {
                            Arc::new(HpkeOut::HFailed {
                                    code: Arc::new(Code::Transport {}),
                                    message: string_of("unexpected event")
                                })
                        } else {
                            if e.point().cardinality() != int!(32) {
                                Arc::new(HpkeOut::HFailed {
                                        code: Arc::new(Code::HpkeSetupFailed {}),
                                        message: string_of("X25519 failed")
                                    })
                            } else {
                                _default::Schedule(&Arc::new(Hpke::HSchedule {
                                            stage: int!(0),
                                            job: _default::Extract(&(seq![] as Sequence<u8>), &(seq![] as Sequence<u8>)),
                                            enc: enc.clone(),
                                            pkR: pkR.clone(),
                                            info: info.clone(),
                                            shared: seq![] as Sequence<u8>,
                                            pskIdHash: seq![] as Sequence<u8>,
                                            infoHash: seq![] as Sequence<u8>,
                                            secret: seq![] as Sequence<u8>,
                                            key: seq![] as Sequence<u8>,
                                            baseNonce: seq![] as Sequence<u8>
                                        }), &_default::LabeledExtract(&_default::KemSuiteId(), &(seq![] as Sequence<u8>), &string_of("eae_prk"), e.point()))
                            }
                        }
                    } else {
                        let mut ___mcc_h8: nat = _source0.stage().clone();
                        let mut ___mcc_h9: Arc<Job> = _source0.job().clone();
                        let mut ___mcc_h10: Sequence<u8> = _source0.enc().clone();
                        let mut ___mcc_h11: Sequence<u8> = _source0.pkR().clone();
                        let mut ___mcc_h12: Sequence<u8> = _source0.info().clone();
                        let mut ___mcc_h13: Sequence<u8> = _source0.shared().clone();
                        let mut ___mcc_h14: Sequence<u8> = _source0.pskIdHash().clone();
                        let mut ___mcc_h15: Sequence<u8> = _source0.infoHash().clone();
                        let mut ___mcc_h16: Sequence<u8> = _source0.secret().clone();
                        let mut ___mcc_h17: Sequence<u8> = _source0.key().clone();
                        let mut ___mcc_h18: Sequence<u8> = _source0.baseNonce().clone();
                        let mut baseNonce: Sequence<u8> = ___mcc_h18.clone();
                        let mut key: Sequence<u8> = ___mcc_h17.clone();
                        let mut secret: Sequence<u8> = ___mcc_h16.clone();
                        let mut infoHash: Sequence<u8> = ___mcc_h15.clone();
                        let mut pskIdHash: Sequence<u8> = ___mcc_h14.clone();
                        let mut shared: Sequence<u8> = ___mcc_h13.clone();
                        let mut info: Sequence<u8> = ___mcc_h12.clone();
                        let mut pkR: Sequence<u8> = ___mcc_h11.clone();
                        let mut enc: Sequence<u8> = ___mcc_h10.clone();
                        let mut job: Arc<Job> = ___mcc_h9.clone();
                        let mut stage: nat = ___mcc_h8.clone();
                        let mut _source1: Arc<JobOut> = _default::JobStep(&job, e);
                        if matches!((&_source1).as_ref(), Pending{ .. }) {
                            let mut ___mcc_h19: Arc<Job> = _source1.job().clone();
                            let mut ___mcc_h20: Arc<Action> = _source1.action().clone();
                            let mut action: Arc<Action> = ___mcc_h20.clone();
                            let mut next: Arc<Job> = ___mcc_h19.clone();
                            Arc::new(HpkeOut::HContinue {
                                    h: {
                                            let __pat_let3_0: Arc<Hpke> = h.clone();
                                            {
                                                let _dt__update__tmp_h0: Arc<Hpke> = __pat_let3_0.clone();
                                                {
                                                    let __pat_let4_0: Arc<Job> = next.clone();
                                                    {
                                                        let _dt__update_hjob_h0: Arc<Job> = __pat_let4_0.clone();
                                                        Arc::new(Hpke::HSchedule {
                                                                stage: _dt__update__tmp_h0.stage().clone(),
                                                                job: _dt__update_hjob_h0.clone(),
                                                                enc: _dt__update__tmp_h0.enc().clone(),
                                                                pkR: _dt__update__tmp_h0.pkR().clone(),
                                                                info: _dt__update__tmp_h0.info().clone(),
                                                                shared: _dt__update__tmp_h0.shared().clone(),
                                                                pskIdHash: _dt__update__tmp_h0.pskIdHash().clone(),
                                                                infoHash: _dt__update__tmp_h0.infoHash().clone(),
                                                                secret: _dt__update__tmp_h0.secret().clone(),
                                                                key: _dt__update__tmp_h0.key().clone(),
                                                                baseNonce: _dt__update__tmp_h0.baseNonce().clone()
                                                            })
                                                    }
                                                }
                                            }
                                        },
                                    action: action.clone()
                                })
                        } else {
                            if matches!((&_source1).as_ref(), Output{ .. }) {
                                let mut ___mcc_h21: Sequence<u8> = _source1.data().clone();
                                let mut out: Sequence<u8> = ___mcc_h21.clone();
                                let mut ksc: Sequence<u8> = seq![0].concat(&pskIdHash).concat(&infoHash);
                                if stage.clone() == int!(0) {
                                    _default::Schedule(&({
                                            let __pat_let5_0: Arc<Hpke> = h.clone();
                                            {
                                                let _dt__update__tmp_h1: Arc<Hpke> = __pat_let5_0.clone();
                                                {
                                                    let __pat_let6_0: DafnyInt = int!(1);
                                                    {
                                                        let _dt__update_hstage_h0: nat = __pat_let6_0.clone();
                                                        Arc::new(Hpke::HSchedule {
                                                                stage: _dt__update_hstage_h0.clone(),
                                                                job: _dt__update__tmp_h1.job().clone(),
                                                                enc: _dt__update__tmp_h1.enc().clone(),
                                                                pkR: _dt__update__tmp_h1.pkR().clone(),
                                                                info: _dt__update__tmp_h1.info().clone(),
                                                                shared: _dt__update__tmp_h1.shared().clone(),
                                                                pskIdHash: _dt__update__tmp_h1.pskIdHash().clone(),
                                                                infoHash: _dt__update__tmp_h1.infoHash().clone(),
                                                                secret: _dt__update__tmp_h1.secret().clone(),
                                                                key: _dt__update__tmp_h1.key().clone(),
                                                                baseNonce: _dt__update__tmp_h1.baseNonce().clone()
                                                            })
                                                    }
                                                }
                                            }
                                        }), &_default::LabeledExpand(&_default::KemSuiteId(), &out, &string_of("shared_secret"), &enc.concat(&pkR), &crate::EHBP::_default::HashLength()))
                                } else {
                                    if stage.clone() == int!(1) {
                                        _default::Schedule(&({
                                                let __pat_let7_0: Arc<Hpke> = h.clone();
                                                {
                                                    let _dt__update__tmp_h2: Arc<Hpke> = __pat_let7_0.clone();
                                                    {
                                                        let __pat_let8_0: Sequence<u8> = out.clone();
                                                        {
                                                            let _dt__update_hshared_h0: Sequence<u8> = __pat_let8_0.clone();
                                                            {
                                                                let __pat_let9_0: DafnyInt = int!(2);
                                                                {
                                                                    let _dt__update_hstage_h1: nat = __pat_let9_0.clone();
                                                                    Arc::new(Hpke::HSchedule {
                                                                            stage: _dt__update_hstage_h1.clone(),
                                                                            job: _dt__update__tmp_h2.job().clone(),
                                                                            enc: _dt__update__tmp_h2.enc().clone(),
                                                                            pkR: _dt__update__tmp_h2.pkR().clone(),
                                                                            info: _dt__update__tmp_h2.info().clone(),
                                                                            shared: _dt__update_hshared_h0.clone(),
                                                                            pskIdHash: _dt__update__tmp_h2.pskIdHash().clone(),
                                                                            infoHash: _dt__update__tmp_h2.infoHash().clone(),
                                                                            secret: _dt__update__tmp_h2.secret().clone(),
                                                                            key: _dt__update__tmp_h2.key().clone(),
                                                                            baseNonce: _dt__update__tmp_h2.baseNonce().clone()
                                                                        })
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }), &_default::LabeledExtract(&_default::HpkeSuiteId(), &(seq![] as Sequence<u8>), &string_of("psk_id_hash"), &(seq![] as Sequence<u8>)))
                                    } else {
                                        if stage.clone() == int!(2) {
                                            _default::Schedule(&({
                                                    let __pat_let10_0: Arc<Hpke> = h.clone();
                                                    {
                                                        let _dt__update__tmp_h3: Arc<Hpke> = __pat_let10_0.clone();
                                                        {
                                                            let __pat_let11_0: Sequence<u8> = out.clone();
                                                            {
                                                                let _dt__update_hpskIdHash_h0: Sequence<u8> = __pat_let11_0.clone();
                                                                {
                                                                    let __pat_let12_0: DafnyInt = int!(3);
                                                                    {
                                                                        let _dt__update_hstage_h2: nat = __pat_let12_0.clone();
                                                                        Arc::new(Hpke::HSchedule {
                                                                                stage: _dt__update_hstage_h2.clone(),
                                                                                job: _dt__update__tmp_h3.job().clone(),
                                                                                enc: _dt__update__tmp_h3.enc().clone(),
                                                                                pkR: _dt__update__tmp_h3.pkR().clone(),
                                                                                info: _dt__update__tmp_h3.info().clone(),
                                                                                shared: _dt__update__tmp_h3.shared().clone(),
                                                                                pskIdHash: _dt__update_hpskIdHash_h0.clone(),
                                                                                infoHash: _dt__update__tmp_h3.infoHash().clone(),
                                                                                secret: _dt__update__tmp_h3.secret().clone(),
                                                                                key: _dt__update__tmp_h3.key().clone(),
                                                                                baseNonce: _dt__update__tmp_h3.baseNonce().clone()
                                                                            })
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }), &_default::LabeledExtract(&_default::HpkeSuiteId(), &(seq![] as Sequence<u8>), &string_of("info_hash"), &info))
                                        } else {
                                            if stage.clone() == int!(3) {
                                                _default::Schedule(&({
                                                        let __pat_let13_0: Arc<Hpke> = h.clone();
                                                        {
                                                            let _dt__update__tmp_h4: Arc<Hpke> = __pat_let13_0.clone();
                                                            {
                                                                let __pat_let14_0: Sequence<u8> = out.clone();
                                                                {
                                                                    let _dt__update_hinfoHash_h0: Sequence<u8> = __pat_let14_0.clone();
                                                                    {
                                                                        let __pat_let15_0: DafnyInt = int!(4);
                                                                        {
                                                                            let _dt__update_hstage_h3: nat = __pat_let15_0.clone();
                                                                            Arc::new(Hpke::HSchedule {
                                                                                    stage: _dt__update_hstage_h3.clone(),
                                                                                    job: _dt__update__tmp_h4.job().clone(),
                                                                                    enc: _dt__update__tmp_h4.enc().clone(),
                                                                                    pkR: _dt__update__tmp_h4.pkR().clone(),
                                                                                    info: _dt__update__tmp_h4.info().clone(),
                                                                                    shared: _dt__update__tmp_h4.shared().clone(),
                                                                                    pskIdHash: _dt__update__tmp_h4.pskIdHash().clone(),
                                                                                    infoHash: _dt__update_hinfoHash_h0.clone(),
                                                                                    secret: _dt__update__tmp_h4.secret().clone(),
                                                                                    key: _dt__update__tmp_h4.key().clone(),
                                                                                    baseNonce: _dt__update__tmp_h4.baseNonce().clone()
                                                                                })
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }), &_default::LabeledExtract(&_default::HpkeSuiteId(), &shared, &string_of("secret"), &(seq![] as Sequence<u8>)))
                                            } else {
                                                if stage.clone() == int!(4) {
                                                    _default::Schedule(&({
                                                            let __pat_let16_0: Arc<Hpke> = h.clone();
                                                            {
                                                                let _dt__update__tmp_h5: Arc<Hpke> = __pat_let16_0.clone();
                                                                {
                                                                    let __pat_let17_0: Sequence<u8> = out.clone();
                                                                    {
                                                                        let _dt__update_hsecret_h0: Sequence<u8> = __pat_let17_0.clone();
                                                                        {
                                                                            let __pat_let18_0: DafnyInt = int!(5);
                                                                            {
                                                                                let _dt__update_hstage_h4: nat = __pat_let18_0.clone();
                                                                                Arc::new(Hpke::HSchedule {
                                                                                        stage: _dt__update_hstage_h4.clone(),
                                                                                        job: _dt__update__tmp_h5.job().clone(),
                                                                                        enc: _dt__update__tmp_h5.enc().clone(),
                                                                                        pkR: _dt__update__tmp_h5.pkR().clone(),
                                                                                        info: _dt__update__tmp_h5.info().clone(),
                                                                                        shared: _dt__update__tmp_h5.shared().clone(),
                                                                                        pskIdHash: _dt__update__tmp_h5.pskIdHash().clone(),
                                                                                        infoHash: _dt__update__tmp_h5.infoHash().clone(),
                                                                                        secret: _dt__update_hsecret_h0.clone(),
                                                                                        key: _dt__update__tmp_h5.key().clone(),
                                                                                        baseNonce: _dt__update__tmp_h5.baseNonce().clone()
                                                                                    })
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }), &_default::LabeledExpand(&_default::HpkeSuiteId(), &out, &string_of("key"), &ksc, &crate::EHBP::_default::KeyLength()))
                                                } else {
                                                    if stage.clone() == int!(5) {
                                                        _default::Schedule(&({
                                                                let __pat_let19_0: Arc<Hpke> = h.clone();
                                                                {
                                                                    let _dt__update__tmp_h6: Arc<Hpke> = __pat_let19_0.clone();
                                                                    {
                                                                        let __pat_let20_0: Sequence<u8> = out.clone();
                                                                        {
                                                                            let _dt__update_hkey_h0: Sequence<u8> = __pat_let20_0.clone();
                                                                            {
                                                                                let __pat_let21_0: DafnyInt = int!(6);
                                                                                {
                                                                                    let _dt__update_hstage_h5: nat = __pat_let21_0.clone();
                                                                                    Arc::new(Hpke::HSchedule {
                                                                                            stage: _dt__update_hstage_h5.clone(),
                                                                                            job: _dt__update__tmp_h6.job().clone(),
                                                                                            enc: _dt__update__tmp_h6.enc().clone(),
                                                                                            pkR: _dt__update__tmp_h6.pkR().clone(),
                                                                                            info: _dt__update__tmp_h6.info().clone(),
                                                                                            shared: _dt__update__tmp_h6.shared().clone(),
                                                                                            pskIdHash: _dt__update__tmp_h6.pskIdHash().clone(),
                                                                                            infoHash: _dt__update__tmp_h6.infoHash().clone(),
                                                                                            secret: _dt__update__tmp_h6.secret().clone(),
                                                                                            key: _dt__update_hkey_h0.clone(),
                                                                                            baseNonce: _dt__update__tmp_h6.baseNonce().clone()
                                                                                        })
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }), &_default::LabeledExpand(&_default::HpkeSuiteId(), &secret, &string_of("base_nonce"), &ksc, &crate::EHBP::_default::NonceLength()))
                                                    } else {
                                                        if stage.clone() == int!(6) {
                                                            _default::Schedule(&({
                                                                    let __pat_let22_0: Arc<Hpke> = h.clone();
                                                                    {
                                                                        let _dt__update__tmp_h7: Arc<Hpke> = __pat_let22_0.clone();
                                                                        {
                                                                            let __pat_let23_0: Sequence<u8> = out.clone();
                                                                            {
                                                                                let _dt__update_hbaseNonce_h0: Sequence<u8> = __pat_let23_0.clone();
                                                                                {
                                                                                    let __pat_let24_0: DafnyInt = int!(7);
                                                                                    {
                                                                                        let _dt__update_hstage_h6: nat = __pat_let24_0.clone();
                                                                                        Arc::new(Hpke::HSchedule {
                                                                                                stage: _dt__update_hstage_h6.clone(),
                                                                                                job: _dt__update__tmp_h7.job().clone(),
                                                                                                enc: _dt__update__tmp_h7.enc().clone(),
                                                                                                pkR: _dt__update__tmp_h7.pkR().clone(),
                                                                                                info: _dt__update__tmp_h7.info().clone(),
                                                                                                shared: _dt__update__tmp_h7.shared().clone(),
                                                                                                pskIdHash: _dt__update__tmp_h7.pskIdHash().clone(),
                                                                                                infoHash: _dt__update__tmp_h7.infoHash().clone(),
                                                                                                secret: _dt__update__tmp_h7.secret().clone(),
                                                                                                key: _dt__update__tmp_h7.key().clone(),
                                                                                                baseNonce: _dt__update_hbaseNonce_h0.clone()
                                                                                            })
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }), &_default::LabeledExpand(&_default::HpkeSuiteId(), &secret, &string_of("exp"), &ksc, &crate::EHBP::_default::HashLength()))
                                                        } else {
                                                            if stage.clone() == int!(7) && key.cardinality() == crate::EHBP::_default::KeyLength() && baseNonce.cardinality() == crate::EHBP::_default::NonceLength() {
                                                                let mut k: Key = key.clone();
                                                                let mut n: NonceBase = baseNonce.clone();
                                                                Arc::new(HpkeOut::HReady {
                                                                        ctx: Arc::new(Ctx::Ctx {
                                                                                    key: k.clone(),
                                                                                    baseNonce: n.clone(),
                                                                                    exporterSecret: out.clone(),
                                                                                    seqNo: 0
                                                                                }),
                                                                        enc: enc.clone()
                                                                    })
                                                            } else {
                                                                Arc::new(HpkeOut::HFailed {
                                                                        code: Arc::new(Code::HpkeSetupFailed {}),
                                                                        message: string_of("key schedule produced the wrong lengths")
                                                                    })
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                let mut ___mcc_h22: Arc<Code> = _source1.code().clone();
                                let mut ___mcc_h23: Sequence<DafnyChar> = _source1.message().clone();
                                let mut message: Sequence<DafnyChar> = ___mcc_h23.clone();
                                let mut code: Arc<Code> = ___mcc_h22.clone();
                                Arc::new(HpkeOut::HFailed {
                                        code: code.clone(),
                                        message: message.clone()
                                    })
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(284,3)
        pub fn SealAction(ctx: &Arc<Ctx>, plaintext: &Sequence<u8>) -> Arc<Action> {
            Arc::new(Action::AeadSeal {
                    key: ctx.key().clone(),
                    nonce: crate::EHBP::_default::ComputeNonce(ctx.baseNonce(), ctx.seqNo().clone()),
                    plaintext: plaintext.clone()
                })
        }
        /// ehbp_events.dfy(285,3)
        pub fn OpenAction(ctx: &Arc<Ctx>, ciphertext: &Sequence<u8>) -> Arc<Action> {
            Arc::new(Action::AeadOpen {
                    key: ctx.key().clone(),
                    nonce: crate::EHBP::_default::ComputeNonce(ctx.baseNonce(), ctx.seqNo().clone()),
                    ciphertext: ciphertext.clone()
                })
        }
        /// ehbp_events.dfy(286,3)
        pub fn Bump(ctx: &Arc<Ctx>) -> Arc<Ctx> {
            let mut _dt__update__tmp_h0: Arc<Ctx> = ctx.clone();
            let mut _dt__update_hseqNo_h0: u64 = ctx.seqNo().clone() + 1;
            Arc::new(Ctx::Ctx {
                    key: _dt__update__tmp_h0.key().clone(),
                    baseNonce: _dt__update__tmp_h0.baseNonce().clone(),
                    exporterSecret: _dt__update__tmp_h0.exporterSecret().clone(),
                    seqNo: _dt__update_hseqNo_h0
                })
        }
        /// ehbp_events.dfy(288,3)
        pub fn ExportJob(ctx: &Arc<Ctx>, context: &Sequence<u8>, length: &nat) -> Arc<Job> {
            _default::LabeledExpand(&_default::HpkeSuiteId(), ctx.exporterSecret(), &string_of("sec"), context, length)
        }
        /// ehbp_events.dfy(304,3)
        pub fn JsonWs(c: &DafnyChar) -> bool {
            c.clone() == DafnyChar(char::from_u32(32).unwrap()) || c.clone() == DafnyChar(char::from_u32(9).unwrap()) || c.clone() == DafnyChar(char::from_u32(10).unwrap()) || c.clone() == DafnyChar(char::from_u32(13).unwrap())
        }
        /// ehbp_events.dfy(305,3)
        pub fn IsDigit(c: &DafnyChar) -> bool {
            DafnyChar(char::from_u32(48).unwrap()) <= c.clone() && c.clone() <= DafnyChar(char::from_u32(57).unwrap())
        }
        /// ehbp_events.dfy(307,3)
        pub fn SkipWs(s: &Sequence<DafnyChar>, i: &nat) -> nat {
            let mut _r0 = s.clone();
            let mut _r1 = i.clone();
            'TAIL_CALL_START: loop {
                let s = _r0;
                let i = _r1;
                if i.clone() < s.cardinality() && _default::JsonWs(&s.get(&i)) {
                    let mut _in0: Sequence<DafnyChar> = s.clone();
                    let mut _in1: DafnyInt = i.clone() + int!(1);
                    _r0 = _in0.clone();
                    _r1 = _in1.clone();
                    continue 'TAIL_CALL_START;
                } else {
                    return i.clone();
                }
            }
        }
        /// ehbp_events.dfy(315,3)
        pub fn Digits(s: &Sequence<DafnyChar>, i: &nat) -> nat {
            let mut _r0 = s.clone();
            let mut _r1 = i.clone();
            'TAIL_CALL_START: loop {
                let s = _r0;
                let i = _r1;
                if i.clone() < s.cardinality() && _default::IsDigit(&s.get(&i)) {
                    let mut _in0: Sequence<DafnyChar> = s.clone();
                    let mut _in1: DafnyInt = i.clone() + int!(1);
                    _r0 = _in0.clone();
                    _r1 = _in1.clone();
                    continue 'TAIL_CALL_START;
                } else {
                    return i.clone();
                }
            }
        }
        /// ehbp_events.dfy(323,3)
        pub fn Hex4(s: &Sequence<DafnyChar>, i: &nat) -> Arc<Option<DafnyInt>> {
            if s.cardinality() < i.clone() + int!(4) {
                Arc::new(Option::None::<DafnyInt> {})
            } else {
                let mut _source0: (Arc<Option<u8>>, Arc<Option<u8>>, Arc<Option<u8>>, Arc<Option<u8>>) = (
                        crate::EHBP::_default::HexDigitValue(&s.get(i)),
                        crate::EHBP::_default::HexDigitValue(&s.get(&(i.clone() + int!(1)))),
                        crate::EHBP::_default::HexDigitValue(&s.get(&(i.clone() + int!(2)))),
                        crate::EHBP::_default::HexDigitValue(&s.get(&(i.clone() + int!(3))))
                    );
                let mut ___mcc_h0: Arc<Option<u8>> = _source0.0.clone();
                let mut ___mcc_h1: Arc<Option<u8>> = _source0.1.clone();
                let mut ___mcc_h2: Arc<Option<u8>> = _source0.2.clone();
                let mut ___mcc_h3: Arc<Option<u8>> = _source0.3.clone();
                let mut _source1: Arc<Option<u8>> = ___mcc_h0.clone();
                if matches!((&_source1).as_ref(), None{ .. }) {
                    Arc::new(Option::None::<DafnyInt> {})
                } else {
                    let mut ___mcc_h8: u8 = _source1.value().clone();
                    let mut _source2: Arc<Option<u8>> = ___mcc_h1.clone();
                    if matches!((&_source2).as_ref(), None{ .. }) {
                        Arc::new(Option::None::<DafnyInt> {})
                    } else {
                        let mut ___mcc_h10: u8 = _source2.value().clone();
                        let mut _source3: Arc<Option<u8>> = ___mcc_h2.clone();
                        if matches!((&_source3).as_ref(), None{ .. }) {
                            Arc::new(Option::None::<DafnyInt> {})
                        } else {
                            let mut ___mcc_h12: u8 = _source3.value().clone();
                            let mut _source4: Arc<Option<u8>> = ___mcc_h3.clone();
                            if matches!((&_source4).as_ref(), None{ .. }) {
                                Arc::new(Option::None::<DafnyInt> {})
                            } else {
                                let mut ___mcc_h14: u8 = _source4.value().clone();
                                let mut d: u8 = ___mcc_h14;
                                let mut c: u8 = ___mcc_h12;
                                let mut b: u8 = ___mcc_h10;
                                let mut a: u8 = ___mcc_h8;
                                Arc::new(Option::Some::<DafnyInt> {
                                        value: int!(a) * int!(4096) + int!(b) * int!(256) + int!(c) * int!(16) + int!(d)
                                    })
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(340,3)
        pub fn Keep(acc: &Sequence<DafnyChar>, add: &Sequence<DafnyChar>) -> Sequence<DafnyChar> {
            if acc.cardinality() >= _default::MaxJsonStringChars() {
                acc.clone()
            } else {
                if acc.cardinality() + add.cardinality() <= _default::MaxJsonStringChars() {
                    acc.concat(add)
                } else {
                    acc.concat(&add.take(&(_default::MaxJsonStringChars() - acc.cardinality())))
                }
            }
        }
        /// ehbp_events.dfy(348,3)
        pub fn Max(a: &nat, b: &nat) -> nat {
            if a.clone() >= b.clone() {
                a.clone()
            } else {
                b.clone()
            }
        }
        /// ehbp_events.dfy(352,3)
        pub fn LiteralEnd(s: &Sequence<DafnyChar>, i: &nat) -> nat {
            let mut _r0 = s.clone();
            let mut _r1 = i.clone();
            'TAIL_CALL_START: loop {
                let s = _r0;
                let i = _r1;
                if i.clone() == s.cardinality() || s.get(&i) == DafnyChar(char::from_u32(34).unwrap()) || s.get(&i) == DafnyChar(char::from_u32(92).unwrap()) || int!(s.get(&i).0) < int!(32) {
                    return i.clone();
                } else {
                    let mut _in0: Sequence<DafnyChar> = s.clone();
                    let mut _in1: DafnyInt = i.clone() + int!(1);
                    _r0 = _in0.clone();
                    _r1 = _in1.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp_events.dfy(360,3)
        pub fn ParseString(s: &Sequence<DafnyChar>, i: &nat, acc: &Sequence<DafnyChar>) -> Arc<Option<(Sequence<DafnyChar>, nat)>> {
            let mut _r0 = s.clone();
            let mut _r1 = i.clone();
            let mut _r2 = acc.clone();
            'TAIL_CALL_START: loop {
                let s = _r0;
                let i = _r1;
                let acc = _r2;
                let mut j: nat = _default::LiteralEnd(&s, &i);
                let mut run: Sequence<DafnyChar> = _default::Keep(&acc, &s.slice(&i, &j));
                if j.clone() == s.cardinality() {
                    return Arc::new(Option::None::<(Sequence<DafnyChar>, DafnyInt)> {});
                } else {
                    if s.get(&j) == DafnyChar(char::from_u32(34).unwrap()) {
                        return Arc::new(Option::Some::<(Sequence<DafnyChar>, DafnyInt)> {
                                    value: (
                                            run.clone(),
                                            j.clone() + int!(1)
                                        )
                                });
                    } else {
                        if int!(s.get(&j).0) < int!(32) {
                            return Arc::new(Option::None::<(Sequence<DafnyChar>, DafnyInt)> {});
                        } else {
                            if j.clone() + int!(1) == s.cardinality() {
                                return Arc::new(Option::None::<(Sequence<DafnyChar>, DafnyInt)> {});
                            } else {
                                let mut c: DafnyChar = s.get(&(j.clone() + int!(1)));
                                if c.clone() == DafnyChar(char::from_u32(34).unwrap()) || c.clone() == DafnyChar(char::from_u32(92).unwrap()) || c.clone() == DafnyChar(char::from_u32(47).unwrap()) {
                                    let mut _in0: Sequence<DafnyChar> = s.clone();
                                    let mut _in1: DafnyInt = j.clone() + int!(2);
                                    let mut _in2: Sequence<DafnyChar> = _default::Keep(&run, &seq![c.clone()]);
                                    _r0 = _in0.clone();
                                    _r1 = _in1.clone();
                                    _r2 = _in2.clone();
                                    continue 'TAIL_CALL_START;
                                } else {
                                    if c.clone() == DafnyChar(char::from_u32(98).unwrap()) {
                                        let mut _in3: Sequence<DafnyChar> = s.clone();
                                        let mut _in4: DafnyInt = j.clone() + int!(2);
                                        let mut _in5: Sequence<DafnyChar> = _default::Keep(&run, &seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(8)).unwrap()).unwrap())]);
                                        _r0 = _in3.clone();
                                        _r1 = _in4.clone();
                                        _r2 = _in5.clone();
                                        continue 'TAIL_CALL_START;
                                    } else {
                                        if c.clone() == DafnyChar(char::from_u32(102).unwrap()) {
                                            let mut _in6: Sequence<DafnyChar> = s.clone();
                                            let mut _in7: DafnyInt = j.clone() + int!(2);
                                            let mut _in8: Sequence<DafnyChar> = _default::Keep(&run, &seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(12)).unwrap()).unwrap())]);
                                            _r0 = _in6.clone();
                                            _r1 = _in7.clone();
                                            _r2 = _in8.clone();
                                            continue 'TAIL_CALL_START;
                                        } else {
                                            if c.clone() == DafnyChar(char::from_u32(110).unwrap()) {
                                                let mut _in9: Sequence<DafnyChar> = s.clone();
                                                let mut _in10: DafnyInt = j.clone() + int!(2);
                                                let mut _in11: Sequence<DafnyChar> = _default::Keep(&run, &seq![DafnyChar(char::from_u32(10).unwrap())]);
                                                _r0 = _in9.clone();
                                                _r1 = _in10.clone();
                                                _r2 = _in11.clone();
                                                continue 'TAIL_CALL_START;
                                            } else {
                                                if c.clone() == DafnyChar(char::from_u32(114).unwrap()) {
                                                    let mut _in12: Sequence<DafnyChar> = s.clone();
                                                    let mut _in13: DafnyInt = j.clone() + int!(2);
                                                    let mut _in14: Sequence<DafnyChar> = _default::Keep(&run, &seq![DafnyChar(char::from_u32(13).unwrap())]);
                                                    _r0 = _in12.clone();
                                                    _r1 = _in13.clone();
                                                    _r2 = _in14.clone();
                                                    continue 'TAIL_CALL_START;
                                                } else {
                                                    if c.clone() == DafnyChar(char::from_u32(116).unwrap()) {
                                                        let mut _in15: Sequence<DafnyChar> = s.clone();
                                                        let mut _in16: DafnyInt = j.clone() + int!(2);
                                                        let mut _in17: Sequence<DafnyChar> = _default::Keep(&run, &seq![DafnyChar(char::from_u32(9).unwrap())]);
                                                        _r0 = _in15.clone();
                                                        _r1 = _in16.clone();
                                                        _r2 = _in17.clone();
                                                        continue 'TAIL_CALL_START;
                                                    } else {
                                                        if c.clone() != DafnyChar(char::from_u32(117).unwrap()) {
                                                            return Arc::new(Option::None::<(Sequence<DafnyChar>, nat)> {});
                                                        } else {
                                                            let mut _source0: Arc<Option<DafnyInt>> = _default::Hex4(&s, &(j.clone() + int!(2)));
                                                            if matches!((&_source0).as_ref(), None{ .. }) {
                                                                return Arc::new(Option::None::<(Sequence<DafnyChar>, nat)> {});
                                                            } else {
                                                                let mut ___mcc_h0: DafnyInt = _source0.value().clone();
                                                                let mut cp: DafnyInt = ___mcc_h0.clone();
                                                                if int!(b"55296") <= cp.clone() && cp.clone() <= int!(b"56319") {
                                                                    let mut lo: Arc<Option<DafnyInt>> = if j.clone() + int!(8) <= s.cardinality() && s.get(&(j.clone() + int!(6))) == DafnyChar(char::from_u32(92).unwrap()) && s.get(&(j.clone() + int!(7))) == DafnyChar(char::from_u32(117).unwrap()) {
                                                                            _default::Hex4(&s, &(j.clone() + int!(8)))
                                                                        } else {
                                                                            Arc::new(Option::None::<DafnyInt> {})
                                                                        };
                                                                    if matches!((&lo).as_ref(), Some{ .. }) && (int!(b"56320") <= lo.value().clone() && lo.value().clone() <= int!(b"57343")) {
                                                                        let mut _in18: Sequence<DafnyChar> = s.clone();
                                                                        let mut _in19: DafnyInt = j.clone() + int!(12);
                                                                        let mut _in20: Sequence<DafnyChar> = _default::Keep(&run, &seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(b"65536") + (cp.clone() - int!(b"55296")) * int!(1024) + (lo.value().clone() - int!(b"56320"))).unwrap()).unwrap())]);
                                                                        _r0 = _in18.clone();
                                                                        _r1 = _in19.clone();
                                                                        _r2 = _in20.clone();
                                                                        continue 'TAIL_CALL_START;
                                                                    } else {
                                                                        let mut _in21: Sequence<DafnyChar> = s.clone();
                                                                        let mut _in22: DafnyInt = j.clone() + int!(6);
                                                                        let mut _in23: Sequence<DafnyChar> = _default::Keep(&run, &seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(b"65533")).unwrap()).unwrap())]);
                                                                        _r0 = _in21.clone();
                                                                        _r1 = _in22.clone();
                                                                        _r2 = _in23.clone();
                                                                        continue 'TAIL_CALL_START;
                                                                    }
                                                                } else {
                                                                    if int!(b"56320") <= cp.clone() && cp.clone() <= int!(b"57343") {
                                                                        let mut _in24: Sequence<DafnyChar> = s.clone();
                                                                        let mut _in25: DafnyInt = j.clone() + int!(6);
                                                                        let mut _in26: Sequence<DafnyChar> = _default::Keep(&run, &seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(b"65533")).unwrap()).unwrap())]);
                                                                        _r0 = _in24.clone();
                                                                        _r1 = _in25.clone();
                                                                        _r2 = _in26.clone();
                                                                        continue 'TAIL_CALL_START;
                                                                    } else {
                                                                        let mut _in27: Sequence<DafnyChar> = s.clone();
                                                                        let mut _in28: DafnyInt = j.clone() + int!(6);
                                                                        let mut _in29: Sequence<DafnyChar> = _default::Keep(&run, &seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(cp.clone()).unwrap()).unwrap())]);
                                                                        _r0 = _in27.clone();
                                                                        _r1 = _in28.clone();
                                                                        _r2 = _in29.clone();
                                                                        continue 'TAIL_CALL_START;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(393,3)
        pub fn Frac(s: &Sequence<DafnyChar>, i: &nat) -> Arc<Option<nat>> {
            if i.clone() < s.cardinality() && s.get(i) == DafnyChar(char::from_u32(46).unwrap()) {
                if i.clone() + int!(1) < s.cardinality() && _default::IsDigit(&s.get(&(i.clone() + int!(1)))) {
                    Arc::new(Option::Some::<nat> {
                            value: _default::Digits(s, &(i.clone() + int!(1)))
                        })
                } else {
                    Arc::new(Option::None::<nat> {})
                }
            } else {
                Arc::new(Option::Some::<nat> {
                        value: i.clone()
                    })
            }
        }
        /// ehbp_events.dfy(401,3)
        pub fn Exponent(s: &Sequence<DafnyChar>, i: &nat) -> Arc<Option<nat>> {
            if i.clone() < s.cardinality() && (s.get(i) == DafnyChar(char::from_u32(101).unwrap()) || s.get(i) == DafnyChar(char::from_u32(69).unwrap())) {
                let mut j: DafnyInt = if i.clone() + int!(1) < s.cardinality() && (s.get(&(i.clone() + int!(1))) == DafnyChar(char::from_u32(43).unwrap()) || s.get(&(i.clone() + int!(1))) == DafnyChar(char::from_u32(45).unwrap())) {
                        i.clone() + int!(2)
                    } else {
                        i.clone() + int!(1)
                    };
                if j.clone() < s.cardinality() && _default::IsDigit(&s.get(&j)) {
                    Arc::new(Option::Some::<nat> {
                            value: _default::Digits(s, &j)
                        })
                } else {
                    Arc::new(Option::None::<nat> {})
                }
            } else {
                Arc::new(Option::Some::<nat> {
                        value: i.clone()
                    })
            }
        }
        /// ehbp_events.dfy(411,3)
        pub fn ParseNumber(s: &Sequence<DafnyChar>, i: &nat) -> Arc<Option<(Arc<Json>, nat)>> {
            let mut j: DafnyInt = if i.clone() < s.cardinality() && s.get(i) == DafnyChar(char::from_u32(45).unwrap()) {
                    i.clone() + int!(1)
                } else {
                    i.clone()
                };
            if j.clone() == s.cardinality() {
                Arc::new(Option::None::<(Arc<Json>, nat)> {})
            } else {
                let mut k: Arc<Option<DafnyInt>> = if s.get(&j) == DafnyChar(char::from_u32(48).unwrap()) {
                        Arc::new(Option::Some::<DafnyInt> {
                                value: j.clone() + int!(1)
                            })
                    } else {
                        if _default::IsDigit(&s.get(&j)) {
                            Arc::new(Option::Some::<DafnyInt> {
                                    value: _default::Digits(s, &(j.clone() + int!(1)))
                                })
                        } else {
                            Arc::new(Option::None::<DafnyInt> {})
                        }
                    };
                if matches!((&k).as_ref(), None{ .. }) {
                    Arc::new(Option::None::<(Arc<Json>, nat)> {})
                } else {
                    let mut _source0: Arc<Option<nat>> = _default::Frac(s, k.value());
                    if matches!((&_source0).as_ref(), None{ .. }) {
                        Arc::new(Option::None::<(Arc<Json>, nat)> {})
                    } else {
                        let mut ___mcc_h0: nat = _source0.value().clone();
                        let mut f: nat = ___mcc_h0.clone();
                        let mut _source1: Arc<Option<nat>> = _default::Exponent(s, &f);
                        if matches!((&_source1).as_ref(), None{ .. }) {
                            Arc::new(Option::None::<(Arc<Json>, nat)> {})
                        } else {
                            let mut ___mcc_h1: nat = _source1.value().clone();
                            let mut end: nat = ___mcc_h1.clone();
                            Arc::new(Option::Some::<(Arc<Json>, nat)> {
                                    value: (
                                            Arc::new(Json::JNumber {
                                                    raw: s.slice(i, &end)
                                                }),
                                            end.clone()
                                        )
                                })
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(430,3)
        pub fn Literal(s: &Sequence<DafnyChar>, i: &nat, word: &Sequence<DafnyChar>, value: &Arc<Json>) -> Arc<Option<(Arc<Json>, nat)>> {
            if i.clone() + word.cardinality() <= s.cardinality() && s.slice(i, &(i.clone() + word.cardinality())) == word.clone() {
                Arc::new(Option::Some::<(Arc<Json>, DafnyInt)> {
                        value: (
                                value.clone(),
                                i.clone() + word.cardinality()
                            )
                    })
            } else {
                Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
            }
        }
        /// ehbp_events.dfy(438,3)
        pub fn ParseValue(s: &Sequence<DafnyChar>, i: &nat, depth: &nat) -> Arc<Option<(Arc<Json>, nat)>> {
            if i.clone() == s.cardinality() {
                Arc::new(Option::None::<(Arc<Json>, nat)> {})
            } else {
                if (s.get(i) == DafnyChar(char::from_u32(123).unwrap()) || s.get(i) == DafnyChar(char::from_u32(91).unwrap())) && depth.clone() >= _default::MaxJsonDepth() {
                    Arc::new(Option::None::<(Arc<Json>, nat)> {})
                } else {
                    if s.get(i) == DafnyChar(char::from_u32(123).unwrap()) {
                        _default::ParseMembers(s, &_default::SkipWs(s, &(i.clone() + int!(1))), &(depth.clone() + int!(1)), &(seq![] as Sequence<(Sequence<DafnyChar>, Arc<Json>)>), true)
                    } else {
                        if s.get(i) == DafnyChar(char::from_u32(91).unwrap()) {
                            _default::ParseItems(s, &_default::SkipWs(s, &(i.clone() + int!(1))), &(depth.clone() + int!(1)), &(seq![] as Sequence<Arc<Json>>), true)
                        } else {
                            if s.get(i) == DafnyChar(char::from_u32(34).unwrap()) {
                                let mut _source0: Arc<Option<(Sequence<DafnyChar>, nat)>> = _default::ParseString(s, &(i.clone() + int!(1)), &(seq![] as Sequence<DafnyChar>));
                                if matches!((&_source0).as_ref(), None{ .. }) {
                                    Arc::new(Option::None::<(Arc<Json>, nat)> {})
                                } else {
                                    let mut ___mcc_h0: (Sequence<DafnyChar>, nat) = _source0.value().clone();
                                    let mut _source1: (Sequence<DafnyChar>, nat) = ___mcc_h0.clone();
                                    let mut ___mcc_h1: Sequence<DafnyChar> = _source1.0.clone();
                                    let mut ___mcc_h2: nat = _source1.1.clone();
                                    let mut j: nat = ___mcc_h2.clone();
                                    let mut str: Sequence<DafnyChar> = ___mcc_h1.clone();
                                    Arc::new(Option::Some::<(Arc<Json>, nat)> {
                                            value: (
                                                    Arc::new(Json::JString {
                                                            s: str.clone()
                                                        }),
                                                    j.clone()
                                                )
                                        })
                                }
                            } else {
                                if s.get(i) == DafnyChar(char::from_u32(116).unwrap()) {
                                    _default::Literal(s, i, &string_of("true"), &Arc::new(Json::JBool {
                                                b: true
                                            }))
                                } else {
                                    if s.get(i) == DafnyChar(char::from_u32(102).unwrap()) {
                                        _default::Literal(s, i, &string_of("false"), &Arc::new(Json::JBool {
                                                    b: false
                                                }))
                                    } else {
                                        if s.get(i) == DafnyChar(char::from_u32(110).unwrap()) {
                                            _default::Literal(s, i, &string_of("null"), &Arc::new(Json::JNull {}))
                                        } else {
                                            _default::ParseNumber(s, i)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(455,3)
        pub fn ItemsFrom(s: &Sequence<DafnyChar>, i: &nat, depth: &nat, acc: &Sequence<Arc<Json>>, first: bool) -> Arc<Option<(Arc<Json>, nat)>> {
            if i.clone() == s.cardinality() {
                Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
            } else {
                if first && s.get(i) == DafnyChar(char::from_u32(93).unwrap()) {
                    Arc::new(Option::Some::<(Arc<Json>, DafnyInt)> {
                            value: (
                                    Arc::new(Json::JArray {
                                            items: acc.clone()
                                        }),
                                    i.clone() + int!(1)
                                )
                        })
                } else {
                    let mut _source0: Arc<Option<(Arc<Json>, nat)>> = _default::ParseValue(s, i, depth);
                    if matches!((&_source0).as_ref(), None{ .. }) {
                        Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
                    } else {
                        let mut ___mcc_h0: (Arc<Json>, nat) = _source0.value().clone();
                        let mut _source1: (Arc<Json>, nat) = ___mcc_h0.clone();
                        let mut ___mcc_h1: Arc<Json> = _source1.0.clone();
                        let mut ___mcc_h2: nat = _source1.1.clone();
                        let mut k: nat = ___mcc_h2.clone();
                        let mut v: Arc<Json> = ___mcc_h1.clone();
                        let mut m: nat = _default::SkipWs(s, &k);
                        if m.clone() == s.cardinality() {
                            Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
                        } else {
                            if s.get(&m) == DafnyChar(char::from_u32(44).unwrap()) {
                                _default::ItemsFrom(s, &_default::SkipWs(s, &(m.clone() + int!(1))), depth, &acc.concat(&seq![v.clone()]), false)
                            } else {
                                if s.get(&m) == DafnyChar(char::from_u32(93).unwrap()) {
                                    Arc::new(Option::Some::<(Arc<Json>, DafnyInt)> {
                                            value: (
                                                    Arc::new(Json::JArray {
                                                            items: acc.concat(&seq![v.clone()])
                                                        }),
                                                    m.clone() + int!(1)
                                                )
                                        })
                                } else {
                                    Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(475,3)
        pub fn ParseItems(s: &Sequence<DafnyChar>, i: &nat, depth: &nat, acc: &Sequence<Arc<Json>>, first: bool) -> Arc<Option<(Arc<Json>, nat)>> {
            let mut r = MaybePlacebo::<Arc<Option<(Arc<Json>, nat)>>>::new();
            let mut a = MaybePlacebo::<Object<[Arc<Json>]>>::new();
            let mut _init0: Arc<dyn ::std::ops::Fn(&nat) -> Arc<Json> + Sync + ::std::marker::Send> = {
                    Arc::new(move |_v14: &nat| -> Arc<Json>{
            Arc::new(Json::JNull {})
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                };
            let mut _nw0: Object<[MaybeUninit<Arc<Json>>]> = array::placebos_usize_object::<Arc<Json>>(DafnyUsize::into_usize(int!(0)));
            for __i0_0 in integer_range(0, rd!(_nw0.clone()).len()) {
                {
                    let __idx0 = DafnyUsize::into_usize(__i0_0.clone());
                    ::dafny_runtime::md!(_nw0)[__idx0] = MaybeUninit::new((&_init0)(&int!(__i0_0.clone())));
                }
            }
            a = MaybePlacebo::from(array::construct_object(_nw0.clone()));
            let mut n: DafnyInt;
            let mut j: DafnyInt;
            let mut f: bool;
            let mut _rhs0: DafnyInt = int!(0);
            let mut _rhs1: nat = i.clone();
            let mut _rhs2: bool = first;
            n = _rhs0.clone();
            j = _rhs1.clone();
            f = _rhs2;
            while true {
                if j.clone() == s.cardinality() {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                if f && s.get(&j) == DafnyChar(char::from_u32(93).unwrap()) {
                    r = MaybePlacebo::from(Arc::new(Option::Some::<(Arc<Json>, DafnyInt)> {
                                    value: (
                                            Arc::new(Json::JArray {
                                                    items: acc.concat(&Sequence::from_array_take_object(&a.read(), &n))
                                                }),
                                            j.clone() + int!(1)
                                        )
                                }));
                    return r.read();
                };
                let mut __0_r: Arc<Option<(Arc<Json>, nat)>> = _default::ParseValue(s, &j, depth);
                if matches!((&__0_r).as_ref(), None{ .. }) {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                let mut __let_tmp_rhs0: (Arc<Json>, nat) = __0_r.value().clone();
                let mut v: Arc<Json> = __let_tmp_rhs0.0.clone();
                let mut k: nat = __let_tmp_rhs0.1.clone();
                let mut m: nat = _default::SkipWs(s, &k);
                if m.clone() == s.cardinality() {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                if s.get(&m) == DafnyChar(char::from_u32(93).unwrap()) {
                    r = MaybePlacebo::from(Arc::new(Option::Some::<(Arc<Json>, nat)> {
                                    value: (
                                            Arc::new(Json::JArray {
                                                    items: acc.concat(&Sequence::from_array_take_object(&a.read(), &n)).concat(&seq![v.clone()])
                                                }),
                                            m.clone() + int!(1)
                                        )
                                }));
                    return r.read();
                };
                if s.get(&m) != DafnyChar(char::from_u32(44).unwrap()) {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                let mut _out0: Object<[Arc<Json>]> = _default::Append::<Arc<Json>>(&a.read(), &n, &v);
                a = MaybePlacebo::from(_out0.clone());
                let mut _rhs3: DafnyInt = n.clone() + int!(1);
                let mut _rhs4: nat = _default::SkipWs(s, &(m.clone() + int!(1)));
                let mut _rhs5: bool = false;
                n = _rhs3.clone();
                j = _rhs4.clone();
                f = _rhs5;
            };
            return r.read();
        }
        /// ehbp_events.dfy(507,3)
        pub fn MembersFrom(s: &Sequence<DafnyChar>, i: &nat, depth: &nat, acc: &Sequence<(Sequence<DafnyChar>, Arc<Json>)>, first: bool) -> Arc<Option<(Arc<Json>, nat)>> {
            if i.clone() == s.cardinality() {
                Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
            } else {
                if first && s.get(i) == DafnyChar(char::from_u32(125).unwrap()) {
                    Arc::new(Option::Some::<(Arc<Json>, DafnyInt)> {
                            value: (
                                    Arc::new(Json::JObject {
                                            members: acc.clone()
                                        }),
                                    i.clone() + int!(1)
                                )
                        })
                } else {
                    if s.get(i) != DafnyChar(char::from_u32(34).unwrap()) {
                        Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
                    } else {
                        let mut _source0: Arc<Option<(Sequence<DafnyChar>, nat)>> = _default::ParseString(s, &(i.clone() + int!(1)), &(seq![] as Sequence<DafnyChar>));
                        if matches!((&_source0).as_ref(), None{ .. }) {
                            Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
                        } else {
                            let mut ___mcc_h0: (Sequence<DafnyChar>, nat) = _source0.value().clone();
                            let mut _source1: (Sequence<DafnyChar>, nat) = ___mcc_h0.clone();
                            let mut ___mcc_h1: Sequence<DafnyChar> = _source1.0.clone();
                            let mut ___mcc_h2: nat = _source1.1.clone();
                            let mut k: nat = ___mcc_h2.clone();
                            let mut name: Sequence<DafnyChar> = ___mcc_h1.clone();
                            let mut c: nat = _default::SkipWs(s, &k);
                            if c.clone() == s.cardinality() || s.get(&c) != DafnyChar(char::from_u32(58).unwrap()) {
                                Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
                            } else {
                                let mut _source2: Arc<Option<(Arc<Json>, nat)>> = _default::ParseValue(s, &_default::SkipWs(s, &(c.clone() + int!(1))), depth);
                                if matches!((&_source2).as_ref(), None{ .. }) {
                                    Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
                                } else {
                                    let mut ___mcc_h3: (Arc<Json>, nat) = _source2.value().clone();
                                    let mut _source3: (Arc<Json>, nat) = ___mcc_h3.clone();
                                    let mut ___mcc_h4: Arc<Json> = _source3.0.clone();
                                    let mut ___mcc_h5: nat = _source3.1.clone();
                                    let mut k2: nat = ___mcc_h5.clone();
                                    let mut v: Arc<Json> = ___mcc_h4.clone();
                                    let mut m: nat = _default::SkipWs(s, &k2);
                                    if m.clone() == s.cardinality() {
                                        Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
                                    } else {
                                        if s.get(&m) == DafnyChar(char::from_u32(44).unwrap()) {
                                            _default::MembersFrom(s, &_default::SkipWs(s, &(m.clone() + int!(1))), depth, &acc.concat(&seq![(
                                                            name.clone(),
                                                            v.clone()
                                                        )]), false)
                                        } else {
                                            if s.get(&m) == DafnyChar(char::from_u32(125).unwrap()) {
                                                Arc::new(Option::Some::<(Arc<Json>, DafnyInt)> {
                                                        value: (
                                                                Arc::new(Json::JObject {
                                                                        members: acc.concat(&seq![(
                                                                                        name.clone(),
                                                                                        v.clone()
                                                                                    )])
                                                                    }),
                                                                m.clone() + int!(1)
                                                            )
                                                    })
                                            } else {
                                                Arc::new(Option::None::<(Arc<Json>, DafnyInt)> {})
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(532,3)
        pub fn ParseMembers(s: &Sequence<DafnyChar>, i: &nat, depth: &nat, acc: &Sequence<(Sequence<DafnyChar>, Arc<Json>)>, first: bool) -> Arc<Option<(Arc<Json>, nat)>> {
            let mut r = MaybePlacebo::<Arc<Option<(Arc<Json>, nat)>>>::new();
            let mut a = MaybePlacebo::<Object<[(Sequence<DafnyChar>, Arc<Json>)]>>::new();
            let mut _init0: Arc<dyn ::std::ops::Fn(&nat) -> (Sequence<DafnyChar>, Arc<Json>) + Sync + ::std::marker::Send> = {
                    Arc::new(move |_v15: &nat| -> (Sequence<DafnyChar>, Arc<Json>){
            (
                string_of(""),
                Arc::new(Json::JNull {})
            )
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                };
            let mut _nw0: Object<[MaybeUninit<(Sequence<DafnyChar>, Arc<Json>)>]> = array::placebos_usize_object::<(Sequence<DafnyChar>, Arc<Json>)>(DafnyUsize::into_usize(int!(0)));
            for __i0_0 in integer_range(0, rd!(_nw0.clone()).len()) {
                {
                    let __idx0 = DafnyUsize::into_usize(__i0_0.clone());
                    ::dafny_runtime::md!(_nw0)[__idx0] = MaybeUninit::new((&_init0)(&int!(__i0_0.clone())));
                }
            }
            a = MaybePlacebo::from(array::construct_object(_nw0.clone()));
            let mut n: DafnyInt;
            let mut j: DafnyInt;
            let mut f: bool;
            let mut _rhs0: DafnyInt = int!(0);
            let mut _rhs1: nat = i.clone();
            let mut _rhs2: bool = first;
            n = _rhs0.clone();
            j = _rhs1.clone();
            f = _rhs2;
            while true {
                if j.clone() == s.cardinality() {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                if f && s.get(&j) == DafnyChar(char::from_u32(125).unwrap()) {
                    r = MaybePlacebo::from(Arc::new(Option::Some::<(Arc<Json>, DafnyInt)> {
                                    value: (
                                            Arc::new(Json::JObject {
                                                    members: acc.concat(&Sequence::from_array_take_object(&a.read(), &n))
                                                }),
                                            j.clone() + int!(1)
                                        )
                                }));
                    return r.read();
                };
                if s.get(&j) != DafnyChar(char::from_u32(34).unwrap()) {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                let mut rn: Arc<Option<(Sequence<DafnyChar>, nat)>> = _default::ParseString(s, &(j.clone() + int!(1)), &(seq![] as Sequence<DafnyChar>));
                if matches!((&rn).as_ref(), None{ .. }) {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                let mut __let_tmp_rhs0: (Sequence<DafnyChar>, nat) = rn.value().clone();
                let mut name: Sequence<DafnyChar> = __let_tmp_rhs0.0.clone();
                let mut k: nat = __let_tmp_rhs0.1.clone();
                let mut c: nat = _default::SkipWs(s, &k);
                if c.clone() == s.cardinality() || s.get(&c) != DafnyChar(char::from_u32(58).unwrap()) {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                let mut __0_r: Arc<Option<(Arc<Json>, nat)>> = _default::ParseValue(s, &_default::SkipWs(s, &(c.clone() + int!(1))), depth);
                if matches!((&__0_r).as_ref(), None{ .. }) {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                let mut __let_tmp_rhs1: (Arc<Json>, nat) = __0_r.value().clone();
                let mut v: Arc<Json> = __let_tmp_rhs1.0.clone();
                let mut k2: nat = __let_tmp_rhs1.1.clone();
                let mut m: nat = _default::SkipWs(s, &k2);
                if m.clone() == s.cardinality() {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                if s.get(&m) == DafnyChar(char::from_u32(125).unwrap()) {
                    r = MaybePlacebo::from(Arc::new(Option::Some::<(Arc<Json>, nat)> {
                                    value: (
                                            Arc::new(Json::JObject {
                                                    members: acc.concat(&Sequence::from_array_take_object(&a.read(), &n)).concat(&seq![(
                                                                    name.clone(),
                                                                    v.clone()
                                                                )])
                                                }),
                                            m.clone() + int!(1)
                                        )
                                }));
                    return r.read();
                };
                if s.get(&m) != DafnyChar(char::from_u32(44).unwrap()) {
                    r = MaybePlacebo::from(Arc::new(Option::None::<(Arc<Json>, nat)> {}));
                    return r.read();
                };
                let mut _out0: Object<[(Sequence<DafnyChar>, Arc<Json>)]> = _default::Append::<(Sequence<DafnyChar>, Arc<Json>)>(&a.read(), &n, &((
                            name.clone(),
                            v.clone()
                        )));
                a = MaybePlacebo::from(_out0.clone());
                let mut _rhs3: DafnyInt = n.clone() + int!(1);
                let mut _rhs4: nat = _default::SkipWs(s, &(m.clone() + int!(1)));
                let mut _rhs5: bool = false;
                n = _rhs3.clone();
                j = _rhs4.clone();
                f = _rhs5;
            };
            return r.read();
        }
        /// ehbp_events.dfy(574,3)
        pub fn Append<_T: DafnyType>(a: &Object<[_T]>, n: &nat, v: &_T) -> Object<[_T]> {
            let mut b = MaybePlacebo::<Object<[_T]>>::new();
            if n.clone() < int!(rd!(a.clone()).len()) {
                {
                    let __idx0 = DafnyUsize::into_usize(n.clone());
                    ::dafny_runtime::md!(a)[__idx0] = v.clone();
                };
                b = MaybePlacebo::from(a.clone());
                return b.read();
            };
            let mut _init0: Arc<dyn ::std::ops::Fn(&DafnyInt) -> _T + Sync + ::std::marker::Send> = {
                    let n: nat = n.clone();
                    let a: Object<[_T]> = a.clone();
                    let v: _T = v.clone();
                    {
                        let mut a = a.clone();
                        let mut n = n.clone();
                        let mut v = v.clone();
                        Arc::new(move |k: &DafnyInt| -> _T{
            if int!(0) <= k.clone() && k.clone() < n.clone() {
                rd!(a)[DafnyUsize::into_usize(k.clone())].clone()
            } else {
                v.clone()
            }
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                    }
                };
            let mut _nw0: Object<[MaybeUninit<_T>]> = array::placebos_usize_object::<_T>(DafnyUsize::into_usize(int!(2) * n.clone() + int!(1)));
            for __i0_0 in integer_range(0, rd!(_nw0.clone()).len()) {
                {
                    let __idx0 = DafnyUsize::into_usize(__i0_0.clone());
                    ::dafny_runtime::md!(_nw0)[__idx0] = MaybeUninit::new((&_init0)(&int!(__i0_0.clone())));
                }
            }
            b = MaybePlacebo::from(array::construct_object(_nw0.clone()));
            return b.read();
        }
        /// ehbp_events.dfy(588,3)
        pub fn ParseJson(s: &Sequence<DafnyChar>) -> Arc<Option<Arc<Json>>> {
            let mut _source0: Arc<Option<(Arc<Json>, nat)>> = _default::ParseValue(s, &_default::SkipWs(s, &int!(0)), &int!(0));
            if matches!((&_source0).as_ref(), None{ .. }) {
                Arc::new(Option::None::<Arc<Json>> {})
            } else {
                let mut ___mcc_h0: (Arc<Json>, nat) = _source0.value().clone();
                let mut _source1: (Arc<Json>, nat) = ___mcc_h0.clone();
                let mut ___mcc_h1: Arc<Json> = _source1.0.clone();
                let mut ___mcc_h2: nat = _source1.1.clone();
                let mut j: nat = ___mcc_h2.clone();
                let mut v: Arc<Json> = ___mcc_h1.clone();
                if _default::SkipWs(s, &j) == s.cardinality() {
                    Arc::new(Option::Some::<Arc<Json>> {
                            value: v.clone()
                        })
                } else {
                    Arc::new(Option::None::<Arc<Json>> {})
                }
            }
        }
        /// ehbp_events.dfy(597,3)
        pub fn Member(members: &Sequence<(Sequence<DafnyChar>, Arc<Json>)>, name: &Sequence<DafnyChar>) -> Arc<Option<Arc<Json>>> {
            _default::MemberFrom(members, &members.cardinality(), name)
        }
        /// ehbp_events.dfy(599,3)
        pub fn MemberFrom(members: &Sequence<(Sequence<DafnyChar>, Arc<Json>)>, n: &nat, name: &Sequence<DafnyChar>) -> Arc<Option<Arc<Json>>> {
            let mut _r0 = members.clone();
            let mut _r1 = n.clone();
            let mut _r2 = name.clone();
            'TAIL_CALL_START: loop {
                let members = _r0;
                let n = _r1;
                let name = _r2;
                if n.clone() == int!(0) {
                    return Arc::new(Option::None::<Arc<Json>> {});
                } else {
                    if members.get(&(n.clone() - int!(1))).0.clone() == name.clone() {
                        return Arc::new(Option::Some::<Arc<Json>> {
                                    value: members.get(&(n.clone() - int!(1))).1.clone()
                                });
                    } else {
                        let mut _in0: Sequence<(Sequence<DafnyChar>, Arc<Json>)> = members.clone();
                        let mut _in1: DafnyInt = n.clone() - int!(1);
                        let mut _in2: Sequence<DafnyChar> = name.clone();
                        _r0 = _in0.clone();
                        _r1 = _in1.clone();
                        _r2 = _in2.clone();
                        continue 'TAIL_CALL_START;
                    }
                }
            }
        }
        /// ehbp_events.dfy(607,3)
        pub fn StringMember(members: &Sequence<(Sequence<DafnyChar>, Arc<Json>)>, name: &Sequence<DafnyChar>) -> Arc<Option<Sequence<DafnyChar>>> {
            let mut _source0: Arc<Option<Arc<Json>>> = _default::Member(members, name);
            if matches!((&_source0).as_ref(), None{ .. }) {
                Arc::new(Option::None::<Sequence<DafnyChar>> {})
            } else {
                let mut ___mcc_h0: Arc<Json> = _source0.value().clone();
                let mut _source1: Arc<Json> = ___mcc_h0.clone();
                if matches!((&_source1).as_ref(), JNull{ .. }) {
                    Arc::new(Option::None::<Sequence<DafnyChar>> {})
                } else {
                    if matches!((&_source1).as_ref(), JBool{ .. }) {
                        let mut ___mcc_h2: bool = _source1.b().clone();
                        Arc::new(Option::None::<Sequence<DafnyChar>> {})
                    } else {
                        if matches!((&_source1).as_ref(), JNumber{ .. }) {
                            let mut ___mcc_h4: Sequence<DafnyChar> = _source1.raw().clone();
                            Arc::new(Option::None::<Sequence<DafnyChar>> {})
                        } else {
                            if matches!((&_source1).as_ref(), JString{ .. }) {
                                let mut ___mcc_h6: Sequence<DafnyChar> = _source1.s().clone();
                                let mut v: Sequence<DafnyChar> = ___mcc_h6.clone();
                                Arc::new(Option::Some::<Sequence<DafnyChar>> {
                                        value: v.clone()
                                    })
                            } else {
                                if matches!((&_source1).as_ref(), JArray{ .. }) {
                                    let mut ___mcc_h8: Sequence<Arc<Json>> = _source1.items().clone();
                                    Arc::new(Option::None::<Sequence<DafnyChar>> {})
                                } else {
                                    let mut ___mcc_h10: Sequence<(Sequence<DafnyChar>, Arc<Json>)> = _source1.members().clone();
                                    Arc::new(Option::None::<Sequence<DafnyChar>> {})
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(613,3)
        pub fn Cont(b: u8) -> bool {
            128 <= b && b <= 191
        }
        /// ehbp_events.dfy(615,3)
        pub fn Utf8From(b: &Sequence<u8>, i: &nat, acc: &Sequence<DafnyChar>) -> Sequence<DafnyChar> {
            let mut _r0 = b.clone();
            let mut _r1 = i.clone();
            let mut _r2 = acc.clone();
            'TAIL_CALL_START: loop {
                let b = _r0;
                let i = _r1;
                let acc = _r2;
                if i.clone() == b.cardinality() {
                    return acc.clone();
                } else {
                    let mut c: u8 = b.get(&i);
                    if c < 128 {
                        let mut _in0: Sequence<u8> = b.clone();
                        let mut _in1: DafnyInt = i.clone() + int!(1);
                        let mut _in2: Sequence<DafnyChar> = acc.concat(&seq![DafnyChar(c as char)]);
                        _r0 = _in0.clone();
                        _r1 = _in1.clone();
                        _r2 = _in2.clone();
                        continue 'TAIL_CALL_START;
                    } else {
                        if 194 <= c && c <= 223 && i.clone() + int!(2) <= b.cardinality() && _default::Cont(b.get(&(i.clone() + int!(1)))) {
                            let mut _in3: Sequence<u8> = b.clone();
                            let mut _in4: DafnyInt = i.clone() + int!(2);
                            let mut _in5: Sequence<DafnyChar> = acc.concat(&seq![DafnyChar(char::from_u32(<u32 as NumCast>::from((int!(c) - int!(192)) * int!(64) + (int!(b.get(&(i.clone() + int!(1)))) - int!(128))).unwrap()).unwrap())]);
                            _r0 = _in3.clone();
                            _r1 = _in4.clone();
                            _r2 = _in5.clone();
                            continue 'TAIL_CALL_START;
                        } else {
                            if 224 <= c && c <= 239 && i.clone() + int!(3) <= b.cardinality() && _default::Cont(b.get(&(i.clone() + int!(1)))) && _default::Cont(b.get(&(i.clone() + int!(2)))) {
                                let mut cp: DafnyInt = (int!(c) - int!(224)) * int!(4096) + (int!(b.get(&(i.clone() + int!(1)))) - int!(128)) * int!(64) + (int!(b.get(&(i.clone() + int!(2)))) - int!(128));
                                if cp.clone() < int!(2048) || int!(b"55296") <= cp.clone() && cp.clone() <= int!(b"57343") {
                                    let mut _in6: Sequence<u8> = b.clone();
                                    let mut _in7: DafnyInt = i.clone() + int!(1);
                                    let mut _in8: Sequence<DafnyChar> = acc.concat(&seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(b"65533")).unwrap()).unwrap())]);
                                    _r0 = _in6.clone();
                                    _r1 = _in7.clone();
                                    _r2 = _in8.clone();
                                    continue 'TAIL_CALL_START;
                                } else {
                                    let mut _in9: Sequence<u8> = b.clone();
                                    let mut _in10: DafnyInt = i.clone() + int!(3);
                                    let mut _in11: Sequence<DafnyChar> = acc.concat(&seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(cp.clone()).unwrap()).unwrap())]);
                                    _r0 = _in9.clone();
                                    _r1 = _in10.clone();
                                    _r2 = _in11.clone();
                                    continue 'TAIL_CALL_START;
                                }
                            } else {
                                if 240 <= c && c <= 244 && i.clone() + int!(4) <= b.cardinality() && _default::Cont(b.get(&(i.clone() + int!(1)))) && _default::Cont(b.get(&(i.clone() + int!(2)))) && _default::Cont(b.get(&(i.clone() + int!(3)))) {
                                    let mut cp: DafnyInt = (int!(c) - int!(240)) * int!(b"262144") + (int!(b.get(&(i.clone() + int!(1)))) - int!(128)) * int!(4096) + (int!(b.get(&(i.clone() + int!(2)))) - int!(128)) * int!(64) + (int!(b.get(&(i.clone() + int!(3)))) - int!(128));
                                    if cp.clone() < int!(b"65536") || int!(b"1114111") < cp.clone() {
                                        let mut _in12: Sequence<u8> = b.clone();
                                        let mut _in13: DafnyInt = i.clone() + int!(1);
                                        let mut _in14: Sequence<DafnyChar> = acc.concat(&seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(b"65533")).unwrap()).unwrap())]);
                                        _r0 = _in12.clone();
                                        _r1 = _in13.clone();
                                        _r2 = _in14.clone();
                                        continue 'TAIL_CALL_START;
                                    } else {
                                        let mut _in15: Sequence<u8> = b.clone();
                                        let mut _in16: DafnyInt = i.clone() + int!(4);
                                        let mut _in17: Sequence<DafnyChar> = acc.concat(&seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(cp.clone()).unwrap()).unwrap())]);
                                        _r0 = _in15.clone();
                                        _r1 = _in16.clone();
                                        _r2 = _in17.clone();
                                        continue 'TAIL_CALL_START;
                                    }
                                } else {
                                    let mut _in18: Sequence<u8> = b.clone();
                                    let mut _in19: DafnyInt = i.clone() + int!(1);
                                    let mut _in20: Sequence<DafnyChar> = acc.concat(&seq![DafnyChar(char::from_u32(<u32 as NumCast>::from(int!(b"65533")).unwrap()).unwrap())]);
                                    _r0 = _in18.clone();
                                    _r1 = _in19.clone();
                                    _r2 = _in20.clone();
                                    continue 'TAIL_CALL_START;
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(636,3)
        pub fn Utf8(b: &Sequence<u8>) -> Sequence<DafnyChar> {
            let mut _hresult = MaybePlacebo::<Sequence<DafnyChar>>::new();
            let mut a = MaybePlacebo::<Object<[DafnyChar]>>::new();
            let mut _init0: Arc<dyn ::std::ops::Fn(&nat) -> DafnyChar + Sync + ::std::marker::Send> = {
                    Arc::new(move |_v17: &nat| -> DafnyChar{
            DafnyChar(char::from_u32(32).unwrap())
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                };
            let mut _nw0: Object<[MaybeUninit<DafnyChar>]> = array::placebos_usize_object::<DafnyChar>(DafnyUsize::into_usize(b.cardinality()));
            for __i0_0 in integer_range(0, rd!(_nw0.clone()).len()) {
                {
                    let __idx0 = DafnyUsize::into_usize(__i0_0.clone());
                    ::dafny_runtime::md!(_nw0)[__idx0] = MaybeUninit::new((&_init0)(&int!(__i0_0.clone())));
                }
            }
            a = MaybePlacebo::from(array::construct_object(_nw0.clone()));
            let mut i: DafnyInt;
            let mut n: DafnyInt;
            let mut _rhs0: DafnyInt = int!(0);
            let mut _rhs1: DafnyInt = int!(0);
            i = _rhs0.clone();
            n = _rhs1.clone();
            while i.clone() < b.cardinality() {
                let mut c: u8 = b.get(&i);
                let mut cp: DafnyInt;
                let mut w: DafnyInt;
                let mut _rhs2: DafnyInt = int!(b"65533");
                let mut _rhs3: DafnyInt = int!(1);
                cp = _rhs2.clone();
                w = _rhs3.clone();
                if c < 128 {
                    cp = int!(c);
                } else {
                    if 194 <= c && c <= 223 && i.clone() + int!(2) <= b.cardinality() && _default::Cont(b.get(&(i.clone() + int!(1)))) {
                        let mut _rhs4: DafnyInt = (int!(c) - int!(192)) * int!(64) + (int!(b.get(&(i.clone() + int!(1)))) - int!(128));
                        let mut _rhs5: DafnyInt = int!(2);
                        cp = _rhs4.clone();
                        w = _rhs5.clone();
                    } else {
                        if 224 <= c && c <= 239 && i.clone() + int!(3) <= b.cardinality() && _default::Cont(b.get(&(i.clone() + int!(1)))) && _default::Cont(b.get(&(i.clone() + int!(2)))) {
                            let mut v: DafnyInt = (int!(c) - int!(224)) * int!(4096) + (int!(b.get(&(i.clone() + int!(1)))) - int!(128)) * int!(64) + (int!(b.get(&(i.clone() + int!(2)))) - int!(128));
                            if !(v.clone() < int!(2048) || int!(b"55296") <= v.clone() && v.clone() <= int!(b"57343")) {
                                let mut _rhs6: DafnyInt = v.clone();
                                let mut _rhs7: DafnyInt = int!(3);
                                cp = _rhs6.clone();
                                w = _rhs7.clone();
                            }
                        } else {
                            if 240 <= c && c <= 244 && i.clone() + int!(4) <= b.cardinality() && _default::Cont(b.get(&(i.clone() + int!(1)))) && _default::Cont(b.get(&(i.clone() + int!(2)))) && _default::Cont(b.get(&(i.clone() + int!(3)))) {
                                let mut v: DafnyInt = (int!(c) - int!(240)) * int!(b"262144") + (int!(b.get(&(i.clone() + int!(1)))) - int!(128)) * int!(4096) + (int!(b.get(&(i.clone() + int!(2)))) - int!(128)) * int!(64) + (int!(b.get(&(i.clone() + int!(3)))) - int!(128));
                                if !(v.clone() < int!(b"65536") || int!(b"1114111") < v.clone()) {
                                    let mut _rhs8: DafnyInt = v.clone();
                                    let mut _rhs9: DafnyInt = int!(4);
                                    cp = _rhs8.clone();
                                    w = _rhs9.clone();
                                }
                            }
                        }
                    }
                };
                {
                    let __idx0 = DafnyUsize::into_usize(n.clone());
                    ::dafny_runtime::md!(a.read())[__idx0] = DafnyChar(char::from_u32(<u32 as NumCast>::from(cp.clone()).unwrap()).unwrap());
                };
                let mut _rhs10: DafnyInt = i.clone() + w.clone();
                let mut _rhs11: DafnyInt = n.clone() + int!(1);
                i = _rhs10.clone();
                n = _rhs11.clone();
            };
            _hresult = MaybePlacebo::from(Sequence::from_array_take_object(&a.read(), &n));
            return _hresult.read();
        }
        /// ehbp_events.dfy(667,3)
        pub fn ParseProblem(body: &Sequence<u8>) -> (bool, Arc<Option<Sequence<DafnyChar>>>, Arc<Option<Sequence<DafnyChar>>>) {
            let mut _source0: Arc<Option<Arc<Json>>> = _default::ParseJson(&_default::Utf8(body));
            if matches!((&_source0).as_ref(), None{ .. }) {
                (
                    false,
                    Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                    Arc::new(Option::None::<Sequence<DafnyChar>> {})
                )
            } else {
                let mut ___mcc_h0: Arc<Json> = _source0.value().clone();
                let mut _source1: Arc<Json> = ___mcc_h0.clone();
                if matches!((&_source1).as_ref(), JNull{ .. }) {
                    (
                        false,
                        Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                        Arc::new(Option::None::<Sequence<DafnyChar>> {})
                    )
                } else {
                    if matches!((&_source1).as_ref(), JBool{ .. }) {
                        let mut ___mcc_h2: bool = _source1.b().clone();
                        (
                            false,
                            Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                            Arc::new(Option::None::<Sequence<DafnyChar>> {})
                        )
                    } else {
                        if matches!((&_source1).as_ref(), JNumber{ .. }) {
                            let mut ___mcc_h4: Sequence<DafnyChar> = _source1.raw().clone();
                            (
                                false,
                                Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                                Arc::new(Option::None::<Sequence<DafnyChar>> {})
                            )
                        } else {
                            if matches!((&_source1).as_ref(), JString{ .. }) {
                                let mut ___mcc_h6: Sequence<DafnyChar> = _source1.s().clone();
                                (
                                    false,
                                    Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                                    Arc::new(Option::None::<Sequence<DafnyChar>> {})
                                )
                            } else {
                                if matches!((&_source1).as_ref(), JArray{ .. }) {
                                    let mut ___mcc_h8: Sequence<Arc<Json>> = _source1.items().clone();
                                    (
                                        false,
                                        Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                                        Arc::new(Option::None::<Sequence<DafnyChar>> {})
                                    )
                                } else {
                                    let mut ___mcc_h10: Sequence<(Sequence<DafnyChar>, Arc<Json>)> = _source1.members().clone();
                                    let mut members: Sequence<(Sequence<DafnyChar>, Arc<Json>)> = ___mcc_h10.clone();
                                    (
                                        true,
                                        _default::StringMember(&members, &string_of("type")),
                                        _default::StringMember(&members, &string_of("title"))
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(676,3)
        pub fn ParseToken(json: &Sequence<DafnyChar>) -> (Arc<Option<Sequence<DafnyChar>>>, Arc<Option<Sequence<DafnyChar>>>) {
            let mut _source0: Arc<Option<Arc<Json>>> = _default::ParseJson(json);
            if matches!((&_source0).as_ref(), None{ .. }) {
                (
                    Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                    Arc::new(Option::None::<Sequence<DafnyChar>> {})
                )
            } else {
                let mut ___mcc_h0: Arc<Json> = _source0.value().clone();
                let mut _source1: Arc<Json> = ___mcc_h0.clone();
                if matches!((&_source1).as_ref(), JNull{ .. }) {
                    (
                        Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                        Arc::new(Option::None::<Sequence<DafnyChar>> {})
                    )
                } else {
                    if matches!((&_source1).as_ref(), JBool{ .. }) {
                        let mut ___mcc_h2: bool = _source1.b().clone();
                        (
                            Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                            Arc::new(Option::None::<Sequence<DafnyChar>> {})
                        )
                    } else {
                        if matches!((&_source1).as_ref(), JNumber{ .. }) {
                            let mut ___mcc_h4: Sequence<DafnyChar> = _source1.raw().clone();
                            (
                                Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                                Arc::new(Option::None::<Sequence<DafnyChar>> {})
                            )
                        } else {
                            if matches!((&_source1).as_ref(), JString{ .. }) {
                                let mut ___mcc_h6: Sequence<DafnyChar> = _source1.s().clone();
                                (
                                    Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                                    Arc::new(Option::None::<Sequence<DafnyChar>> {})
                                )
                            } else {
                                if matches!((&_source1).as_ref(), JArray{ .. }) {
                                    let mut ___mcc_h8: Sequence<Arc<Json>> = _source1.items().clone();
                                    (
                                        Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                                        Arc::new(Option::None::<Sequence<DafnyChar>> {})
                                    )
                                } else {
                                    let mut ___mcc_h10: Sequence<(Sequence<DafnyChar>, Arc<Json>)> = _source1.members().clone();
                                    let mut members: Sequence<(Sequence<DafnyChar>, Arc<Json>)> = ___mcc_h10.clone();
                                    (
                                        _default::StringMember(&members, &string_of("exportedSecret")),
                                        _default::StringMember(&members, &string_of("requestEnc"))
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(684,3)
        pub fn Escape(s: &Sequence<DafnyChar>) -> Sequence<DafnyChar> {
            let mut _accumulator: Sequence<DafnyChar> = seq![] as Sequence<DafnyChar>;
            let mut _r0 = s.clone();
            'TAIL_CALL_START: loop {
                let s = _r0;
                if s.cardinality() == int!(0) {
                    return _accumulator.concat(&(seq![] as Sequence<DafnyChar>));
                } else {
                    let mut c: DafnyChar = s.get(&int!(0));
                    _accumulator = _accumulator.concat(&(if c.clone() == DafnyChar(char::from_u32(34).unwrap()) {
                                string_of("\\\"")
                            } else {
                                if c.clone() == DafnyChar(char::from_u32(92).unwrap()) {
                                    string_of("\\\\")
                                } else {
                                    if int!(c.clone().0) < int!(32) {
                                        string_of("\\u00").concat(&seq![crate::EHBP::_default::HexDigits().get(&euclidian_division(int!(c.clone().0), int!(16))), crate::EHBP::_default::HexDigits().get(&euclidian_modulo(int!(c.clone().0), int!(16)))])
                                    } else {
                                        seq![c.clone()]
                                    }
                                }
                            }));
                    let mut _in0: Sequence<DafnyChar> = s.drop(&int!(1));
                    _r0 = _in0.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp_events.dfy(694,3)
        pub fn FormatToken(exportedSecretHex: &Sequence<DafnyChar>, requestEncHex: &Sequence<DafnyChar>) -> Sequence<DafnyChar> {
            string_of("{\"exportedSecret\":\"").concat(&_default::Escape(exportedSecretHex)).concat(&string_of("\",\"requestEnc\":\"")).concat(&_default::Escape(requestEncHex)).concat(&string_of("\"}"))
        }
        /// ehbp_events.dfy(709,3)
        pub fn SessionApply(store: &Arc<SessionStore>, action: &Arc<SessionAction>) -> Arc<SessionStore> {
            let mut _source0: Arc<SessionAction> = action.clone();
            if matches!((&_source0).as_ref(), Begin{ .. }) {
                Arc::new(SessionStore::SessionStore {
                        generation: if store.generation().clone() == _default::MaxSeq() {
                                0
                            } else {
                                store.generation().clone() + 1
                            },
                        token: Arc::new(Option::None::<Arc<Token>> {})
                    })
            } else {
                if matches!((&_source0).as_ref(), Publish{ .. }) {
                    let mut ___mcc_h0: u64 = _source0.generation().clone();
                    let mut ___mcc_h1: Arc<Token> = _source0.token().clone();
                    let mut token: Arc<Token> = ___mcc_h1.clone();
                    let mut generation: u64 = ___mcc_h0;
                    if generation == store.generation().clone() {
                        let mut _dt__update__tmp_h0: Arc<SessionStore> = store.clone();
                        let mut _dt__update_htoken_h0: Arc<Option<Arc<Token>>> = Arc::new(Option::Some::<Arc<Token>> {
                                    value: token.clone()
                                });
                        Arc::new(SessionStore::SessionStore {
                                generation: _dt__update__tmp_h0.generation().clone(),
                                token: _dt__update_htoken_h0.clone()
                            })
                    } else {
                        store.clone()
                    }
                } else {
                    let mut ___mcc_h2: u64 = _source0.generation().clone();
                    let mut generation: u64 = ___mcc_h2;
                    if generation == store.generation().clone() {
                        let mut _dt__update__tmp_h1: Arc<SessionStore> = store.clone();
                        let mut _dt__update_htoken_h1: Arc<Option<Arc<Token>>> = Arc::new(Option::None::<Arc<Token>> {});
                        Arc::new(SessionStore::SessionStore {
                                generation: _dt__update__tmp_h1.generation().clone(),
                                token: _dt__update_htoken_h1.clone()
                            })
                    } else {
                        store.clone()
                    }
                }
            }
        }
        /// ehbp_events.dfy(726,3)
        pub fn Frames(d: &Arc<Dec>, buf: &Sequence<u8>, i: &nat, acc: &Sequence<Arc<Framed>>) -> (Sequence<Arc<Framed>>, Arc<Dec>, Arc<Option<Arc<Code>>>) {
            let mut _r0 = d.clone();
            let mut _r1 = buf.clone();
            let mut _r2 = i.clone();
            let mut _r3 = acc.clone();
            'TAIL_CALL_START: loop {
                let d = _r0;
                let buf = _r1;
                let i = _r2;
                let acc = _r3;
                if buf.cardinality() - i.clone() < int!(4) {
                    return (
                            acc.clone(),
                            {
                                let __pat_let25_0: Arc<Dec> = d.clone();
                                {
                                    let _dt__update__tmp_h0: Arc<Dec> = __pat_let25_0.clone();
                                    {
                                        let __pat_let26_0: Sequence<u8> = buf.drop(&i);
                                        {
                                            let _dt__update_hpending_h0: Sequence<u8> = __pat_let26_0.clone();
                                            Arc::new(Dec::Dec {
                                                    pending: _dt__update_hpending_h0.clone(),
                                                    next: _dt__update__tmp_h0.next().clone(),
                                                    authenticated: _dt__update__tmp_h0.authenticated().clone(),
                                                    requireFrame: _dt__update__tmp_h0.requireFrame().clone()
                                                })
                                        }
                                    }
                                }
                            },
                            Arc::new(Option::None::<Arc<Code>> {})
                        );
                } else {
                    let mut length: u32 = crate::EHBP::_default::U32(&buf, &i);
                    if length == 0 {
                        let mut _in0: Arc<Dec> = d.clone();
                        let mut _in1: Sequence<u8> = buf.clone();
                        let mut _in2: DafnyInt = i.clone() + int!(4);
                        let mut _in3: Sequence<Arc<Framed>> = acc.clone();
                        _r0 = _in0.clone();
                        _r1 = _in1.clone();
                        _r2 = _in2.clone();
                        _r3 = _in3.clone();
                        continue 'TAIL_CALL_START;
                    } else {
                        if crate::EHBP::_default::MaxChunkBytes() < length {
                            return (
                                    acc.clone(),
                                    d.clone(),
                                    Arc::new(Option::Some::<Arc<Code>> {
                                            value: Arc::new(Code::ChunkTooLarge {})
                                        })
                                );
                        } else {
                            if buf.cardinality() - i.clone() < int!(4) + int!(length) {
                                return (
                                        acc.clone(),
                                        {
                                            let __pat_let27_0: Arc<Dec> = d.clone();
                                            {
                                                let _dt__update__tmp_h1: Arc<Dec> = __pat_let27_0.clone();
                                                {
                                                    let __pat_let28_0: Sequence<u8> = buf.drop(&i);
                                                    {
                                                        let _dt__update_hpending_h1: Sequence<u8> = __pat_let28_0.clone();
                                                        Arc::new(Dec::Dec {
                                                                pending: _dt__update_hpending_h1.clone(),
                                                                next: _dt__update__tmp_h1.next().clone(),
                                                                authenticated: _dt__update__tmp_h1.authenticated().clone(),
                                                                requireFrame: _dt__update__tmp_h1.requireFrame().clone()
                                                            })
                                                    }
                                                }
                                            }
                                        },
                                        Arc::new(Option::None::<Arc<Code>> {})
                                    );
                            } else {
                                if d.next().clone() == _default::MaxSeq() {
                                    return (
                                            acc.clone(),
                                            d.clone(),
                                            Arc::new(Option::Some::<Arc<Code>> {
                                                    value: Arc::new(Code::SequenceOverflow {})
                                                })
                                        );
                                } else {
                                    let mut _in4: Arc<Dec> = Arc::new(Dec::Dec {
                                                pending: seq![] as Sequence<u8>,
                                                next: d.next().clone() + 1,
                                                authenticated: true,
                                                requireFrame: d.requireFrame().clone()
                                            });
                                    let mut _in5: Sequence<u8> = buf.clone();
                                    let mut _in6: DafnyInt = i.clone() + int!(4) + int!(length);
                                    let mut _in7: Sequence<Arc<Framed>> = acc.concat(&seq![Arc::new(Framed::Framed {
                                                        seqNo: d.next().clone(),
                                                        ciphertext: buf.slice(&(i.clone() + int!(4)), &(i.clone() + int!(4) + int!(length)))
                                                    })]);
                                    _r0 = _in4.clone();
                                    _r1 = _in5.clone();
                                    _r2 = _in6.clone();
                                    _r3 = _in7.clone();
                                    continue 'TAIL_CALL_START;
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(742,3)
        pub fn FrameNeed(pending: &Sequence<u8>) -> nat {
            if pending.cardinality() < int!(4) {
                int!(4) - pending.cardinality()
            } else {
                let mut whole: DafnyInt = int!(4) + int!(crate::EHBP::_default::U32(pending, &int!(0)));
                if pending.cardinality() < whole.clone() {
                    whole.clone() - pending.cardinality()
                } else {
                    int!(1)
                }
            }
        }
        /// ehbp_events.dfy(749,3)
        pub fn Push(d: &Arc<Dec>, data: &Sequence<u8>) -> (Sequence<Arc<Framed>>, Arc<Dec>, Arc<Option<Arc<Code>>>) {
            _default::PushFrom(d, data, &int!(0), &(seq![] as Sequence<Arc<Framed>>))
        }
        /// ehbp_events.dfy(751,3)
        pub fn PushFrom(d: &Arc<Dec>, data: &Sequence<u8>, i: &nat, acc: &Sequence<Arc<Framed>>) -> (Sequence<Arc<Framed>>, Arc<Dec>, Arc<Option<Arc<Code>>>) {
            let mut _r0 = d.clone();
            let mut _r1 = data.clone();
            let mut _r2 = i.clone();
            let mut _r3 = acc.clone();
            'TAIL_CALL_START: loop {
                let d = _r0;
                let data = _r1;
                let i = _r2;
                let acc = _r3;
                if d.pending().cardinality() == int!(0) {
                    return _default::Frames(&d, &data, &i, &acc);
                } else {
                    if i.clone() == data.cardinality() {
                        return (
                                acc.clone(),
                                d.clone(),
                                Arc::new(Option::None::<Arc<Code>> {})
                            );
                    } else {
                        let mut take: nat = _default::Min(&(data.cardinality() - i.clone()), &_default::FrameNeed(d.pending()));
                        let mut __let_tmp_rhs0: (Sequence<Arc<Framed>>, Arc<Dec>, Arc<Option<Arc<Code>>>) = _default::Frames(&d, &d.pending().concat(&data.slice(&i, &(i.clone() + take.clone()))), &int!(0), &acc);
                        let mut frames: Sequence<Arc<Framed>> = __let_tmp_rhs0.0.clone();
                        let mut next: Arc<Dec> = __let_tmp_rhs0.1.clone();
                        let mut err: Arc<Option<Arc<Code>>> = __let_tmp_rhs0.2.clone();
                        if matches!((&err).as_ref(), Some{ .. }) {
                            return (
                                    frames.clone(),
                                    next.clone(),
                                    err.clone()
                                );
                        } else {
                            let mut _in0: Arc<Dec> = next.clone();
                            let mut _in1: Sequence<u8> = data.clone();
                            let mut _in2: DafnyInt = i.clone() + take.clone();
                            let mut _in3: Sequence<Arc<Framed>> = frames.clone();
                            _r0 = _in0.clone();
                            _r1 = _in1.clone();
                            _r2 = _in2.clone();
                            _r3 = _in3.clone();
                            continue 'TAIL_CALL_START;
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(763,3)
        pub fn Finish(d: &Arc<Dec>) -> Arc<Option<Arc<Code>>> {
            if d.pending().cardinality() != int!(0) || d.requireFrame().clone() && !d.authenticated().clone() {
                Arc::new(Option::Some::<Arc<Code>> {
                        value: Arc::new(Code::FramingTruncated {})
                    })
            } else {
                Arc::new(Option::None::<Arc<Code>> {})
            }
        }
        /// ehbp_events.dfy(813,3)
        pub fn Initial(origin: &Arc<Origin>, publicKey: &Sequence<u8>) -> Arc<State> {
            Arc::new(State::State {
                    phase: Arc::new(Phase::Idle {}),
                    origin: origin.clone(),
                    publicKey: publicKey.clone(),
                    verb: string_of(""),
                    url: string_of(""),
                    headers: seq![] as Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
                    generation: 0,
                    published: false,
                    token: Arc::new(Token::Token {
                                exportedSecret: seq![] as Sequence<u8>,
                                requestEnc: seq![] as Sequence<u8>
                            }),
                    ctx: _default::NoCtx()
                })
        }
        /// ehbp_events.dfy(821,3)
        pub fn ResponseOnly(origin: &Arc<Origin>, token: &Arc<Token>) -> Arc<State> {
            Arc::new(State::State {
                    phase: Arc::new(Phase::Exchanging {
                                upload: Arc::new(Upload::UpDone {}),
                                response: Arc::new(Response::AwaitHead {
                                            encrypted: true
                                        })
                            }),
                    origin: origin.clone(),
                    publicKey: seq![] as Sequence<u8>,
                    verb: string_of(""),
                    url: string_of(""),
                    headers: seq![] as Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
                    generation: 0,
                    published: false,
                    token: token.clone(),
                    ctx: _default::NoCtx()
                })
        }
        /// ehbp_events.dfy(832,3)
        pub fn DecryptStart(token: &Arc<Token>, status: &DafnyInt, headers: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>) -> (Arc<State>, Sequence<Arc<Action>>) {
            _default::Step(&_default::ResponseOnly(&_default::NoOrigin(), token), &Arc::new(Event::ResponseHead {
                        status: status.clone(),
                        headers: headers.clone(),
                        redirected: false
                    }))
        }
        /// ehbp_events.dfy(837,3)
        pub fn DeriveStart(token: &Arc<Token>, responseNonce: &Sequence<u8>) -> (Arc<State>, Sequence<Arc<Action>>) {
            _default::Step(&_default::ResponseOnly(&_default::NoOrigin(), token), &Arc::new(Event::ResponseHead {
                        status: int!(200),
                        headers: seq![(
                                    crate::EHBP::_default::ResponseNonceHeader(),
                                    crate::EHBP::_default::EncodeHex(responseNonce)
                                )],
                        redirected: false
                    }))
        }
        /// ehbp_events.dfy(843,3)
        pub fn KeysOf(s: &Arc<State>) -> Arc<Option<(Sequence<u8>, Sequence<u8>)>> {
            if matches!(s.phase().as_ref(), Exchanging{ .. }) && matches!(s.phase().response().as_ref(), Body{ .. }) {
                Arc::new(Option::Some::<(Sequence<u8>, Sequence<u8>)> {
                        value: (
                                s.phase().response().keys().key().clone(),
                                s.phase().response().keys().baseNonce().clone()
                            )
                    })
            } else {
                Arc::new(Option::None::<(Sequence<u8>, Sequence<u8>)> {})
            }
        }
        /// ehbp_events.dfy(851,3)
        pub fn Contract(s: &Arc<State>, e: &Arc<Event>, r: &(Arc<State>, Sequence<Arc<Action>>)) -> bool {
            (!_default::Ends(&r.1.clone()) || !r.0.clone().published().clone() && (if s.published().clone() {
                        _default::ClearsOnce(&r.1.clone(), s.generation().clone())
                    } else {
                        _default::NoClear(&r.1.clone())
                    })) && (!(!_default::Ends(&r.1.clone())) || _default::NoClear(&r.1.clone())) && (!(!_default::NoEmit(&r.1.clone())) || matches!(e.as_ref(), AeadOpenResult{ .. }) && e.ok().clone() && matches!(s.phase().as_ref(), Exchanging{ .. }) && matches!(s.phase().response().as_ref(), Opening{ .. }))
        }
        /// ehbp_events.dfy(858,3)
        pub fn Ending(s: &Arc<State>, r: &(Arc<State>, Sequence<Arc<Action>>)) -> bool {
            _default::Ends(&r.1.clone()) && !r.0.clone().published().clone() && (if s.published().clone() {
                    _default::ClearsOnce(&r.1.clone(), s.generation().clone())
                } else {
                    _default::NoClear(&r.1.clone())
                }) && _default::NoEmit(&r.1.clone())
        }
        /// ehbp_events.dfy(865,3)
        pub fn End(s: &Arc<State>, close: bool, last: &Arc<Action>) -> (Arc<State>, Sequence<Arc<Action>>) {
            let mut phase: Arc<Phase> = (&({
                    Arc::new(move |_source0: &Arc<Phase>| -> Arc<Phase>{
            if matches!(_source0.as_ref(), Idle{ .. }) {
                Arc::new(Phase::Ended {})
            } else {
                if matches!(_source0.as_ref(), AwaitSession{ .. }) {
                    let mut ___mcc_h0: bool = _source0.hasBody().clone();
                    Arc::new(Phase::Ended {})
                } else {
                    if matches!(_source0.as_ref(), Peeking{ .. }) {
                        let mut ___mcc_h2: nat = _source0.empty().clone();
                        Arc::new(Phase::Ended {})
                    } else {
                        if matches!(_source0.as_ref(), AwaitSetup{ .. }) {
                            let mut ___mcc_h4: Chunk = _source0.first().clone();
                            let mut ___mcc_h5: bool = _source0.firstEof().clone();
                            let mut ___mcc_h6: Arc<Hpke> = _source0.hpke().clone();
                            Arc::new(Phase::Ended {})
                        } else {
                            if matches!(_source0.as_ref(), AwaitExport{ .. }) {
                                let mut ___mcc_h10: Chunk = _source0.first().clone();
                                let mut ___mcc_h11: bool = _source0.firstEof().clone();
                                let mut ___mcc_h12: Sequence<u8> = _source0.enc().clone();
                                let mut ___mcc_h13: Arc<Job> = _source0.job().clone();
                                Arc::new(Phase::Ended {})
                            } else {
                                if matches!(_source0.as_ref(), Exchanging{ .. }) {
                                    let mut ___mcc_h18: Arc<Upload> = _source0.upload().clone();
                                    let mut ___mcc_h19: Arc<Response> = _source0.response().clone();
                                    let mut up: Arc<Upload> = ___mcc_h18.clone();
                                    Arc::new(Phase::Exchanging {
                                            upload: up.clone(),
                                            response: Arc::new(Response::RespEnded {})
                                        })
                                } else {
                                    if matches!(_source0.as_ref(), DiscAwaitHead{ .. }) {
                                        Arc::new(Phase::Ended {})
                                    } else {
                                        if matches!(_source0.as_ref(), DiscReading{ .. }) {
                                            let mut ___mcc_h22: Sequence<u8> = _source0.data().clone();
                                            Arc::new(Phase::Ended {})
                                        } else {
                                            Arc::new(Phase::Ended {})
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                }))(s.phase());
            let mut g: u64 = s.generation().clone();
            let mut acts: Sequence<Arc<Action>> = if close && s.published().clone() {
                    seq![Arc::new(Action::Close {
                                stream: Arc::new(Stream::ResponseBody {})
                            }), Arc::new(Action::ClearToken {
                                generation: g
                            }), last.clone()]
                } else {
                    if close {
                        seq![Arc::new(Action::Close {
                                    stream: Arc::new(Stream::ResponseBody {})
                                }), last.clone()]
                    } else {
                        if s.published().clone() {
                            seq![Arc::new(Action::ClearToken {
                                        generation: g
                                    }), last.clone()]
                        } else {
                            seq![last.clone()]
                        }
                    }
                };
            (
                {
                    let __pat_let29_0: Arc<State> = s.clone();
                    {
                        let _dt__update__tmp_h0: Arc<State> = __pat_let29_0.clone();
                        {
                            let __pat_let30_0: bool = false;
                            {
                                let _dt__update_hpublished_h0: bool = __pat_let30_0;
                                {
                                    let __pat_let31_0: Arc<Phase> = phase.clone();
                                    {
                                        let _dt__update_hphase_h0: Arc<Phase> = __pat_let31_0.clone();
                                        Arc::new(State::State {
                                                phase: _dt__update_hphase_h0.clone(),
                                                origin: _dt__update__tmp_h0.origin().clone(),
                                                publicKey: _dt__update__tmp_h0.publicKey().clone(),
                                                verb: _dt__update__tmp_h0.verb().clone(),
                                                url: _dt__update__tmp_h0.url().clone(),
                                                headers: _dt__update__tmp_h0.headers().clone(),
                                                generation: _dt__update__tmp_h0.generation().clone(),
                                                published: _dt__update_hpublished_h0,
                                                token: _dt__update__tmp_h0.token().clone(),
                                                ctx: _dt__update__tmp_h0.ctx().clone()
                                            })
                                    }
                                }
                            }
                        }
                    }
                },
                acts.clone()
            )
        }
        /// ehbp_events.dfy(881,3)
        pub fn Abort(s: &Arc<State>, close: bool, code: &Arc<Code>, message: &Sequence<DafnyChar>) -> (Arc<State>, Sequence<Arc<Action>>) {
            _default::End(s, close, &Arc::new(Action::Fail {
                        code: code.clone(),
                        message: message.clone()
                    }))
        }
        /// ehbp_events.dfy(887,3)
        pub fn Unexpected(s: &Arc<State>) -> (Arc<State>, Sequence<Arc<Action>>) {
            _default::Abort(s, false, &Arc::new(Code::Transport {}), &string_of("unexpected event"))
        }
        /// ehbp_events.dfy(893,3)
        pub fn Min(a: &nat, b: &nat) -> nat {
            if a.clone() < b.clone() {
                a.clone()
            } else {
                b.clone()
            }
        }
        /// ehbp_events.dfy(894,3)
        pub fn Min32(a: u32, b: u32) -> u32 {
            if a < b {
                a
            } else {
                b
            }
        }
        /// ehbp_events.dfy(899,3)
        pub fn Piece(chunk: &Chunk, at: u32, n: u32) -> Sequence<u8> {
            if at == 0 && int!(n) == chunk.cardinality() {
                chunk.clone()
            } else {
                chunk.slice(&int!((&at).clone()), &int!((&(at + n)).clone()))
            }
        }
        /// ehbp_events.dfy(908,3)
        pub fn FrameWrites(ciphertext: &Sequence<u8>, end: &Arc<BodyEnd>) -> Sequence<Arc<Action>> {
            seq![Arc::new(Action::Write {
                        data: crate::EHBP::_default::BE32(truncate!(ciphertext.cardinality(), u32)),
                        end: Arc::new(BodyEnd::More {})
                    }), Arc::new(Action::Write {
                        data: ciphertext.clone(),
                        end: end.clone()
                    })]
        }
        /// ehbp_events.dfy(914,3)
        pub fn WithUpload(s: &Arc<State>, up: &Arc<Upload>) -> Arc<State> {
            let mut _dt__update__tmp_h0: Arc<State> = s.clone();
            let mut _dt__update_hphase_h0: Arc<Phase> = Arc::new(Phase::Exchanging {
                        upload: up.clone(),
                        response: s.phase().response().clone()
                    });
            Arc::new(State::State {
                    phase: _dt__update_hphase_h0.clone(),
                    origin: _dt__update__tmp_h0.origin().clone(),
                    publicKey: _dt__update__tmp_h0.publicKey().clone(),
                    verb: _dt__update__tmp_h0.verb().clone(),
                    url: _dt__update__tmp_h0.url().clone(),
                    headers: _dt__update__tmp_h0.headers().clone(),
                    generation: _dt__update__tmp_h0.generation().clone(),
                    published: _dt__update__tmp_h0.published().clone(),
                    token: _dt__update__tmp_h0.token().clone(),
                    ctx: _dt__update__tmp_h0.ctx().clone()
                })
        }
        /// ehbp_events.dfy(920,3)
        pub fn WithResponse(s: &Arc<State>, rs: &Arc<Response>) -> Arc<State> {
            let mut _dt__update__tmp_h0: Arc<State> = s.clone();
            let mut _dt__update_hphase_h0: Arc<Phase> = Arc::new(Phase::Exchanging {
                        upload: s.phase().upload().clone(),
                        response: rs.clone()
                    });
            Arc::new(State::State {
                    phase: _dt__update_hphase_h0.clone(),
                    origin: _dt__update__tmp_h0.origin().clone(),
                    publicKey: _dt__update__tmp_h0.publicKey().clone(),
                    verb: _dt__update__tmp_h0.verb().clone(),
                    url: _dt__update__tmp_h0.url().clone(),
                    headers: _dt__update__tmp_h0.headers().clone(),
                    generation: _dt__update__tmp_h0.generation().clone(),
                    published: _dt__update__tmp_h0.published().clone(),
                    token: _dt__update__tmp_h0.token().clone(),
                    ctx: _dt__update__tmp_h0.ctx().clone()
                })
        }
        /// ehbp_events.dfy(926,3)
        pub fn SendPlain(s: &Arc<State>) -> (Arc<State>, Sequence<Arc<Action>>) {
            (
                {
                    let __pat_let32_0: Arc<State> = s.clone();
                    {
                        let _dt__update__tmp_h0: Arc<State> = __pat_let32_0.clone();
                        {
                            let __pat_let33_0: Arc<Phase> = Arc::new(Phase::Exchanging {
                                        upload: Arc::new(Upload::NoUpload {}),
                                        response: Arc::new(Response::AwaitHead {
                                                    encrypted: false
                                                })
                                    });
                            {
                                let _dt__update_hphase_h0: Arc<Phase> = __pat_let33_0.clone();
                                Arc::new(State::State {
                                        phase: _dt__update_hphase_h0.clone(),
                                        origin: _dt__update__tmp_h0.origin().clone(),
                                        publicKey: _dt__update__tmp_h0.publicKey().clone(),
                                        verb: _dt__update__tmp_h0.verb().clone(),
                                        url: _dt__update__tmp_h0.url().clone(),
                                        headers: _dt__update__tmp_h0.headers().clone(),
                                        generation: _dt__update__tmp_h0.generation().clone(),
                                        published: _dt__update__tmp_h0.published().clone(),
                                        token: _dt__update__tmp_h0.token().clone(),
                                        ctx: _dt__update__tmp_h0.ctx().clone()
                                    })
                            }
                        }
                    }
                },
                seq![Arc::new(Action::Send {
                            verb: s.verb().clone(),
                            url: s.url().clone(),
                            headers: s.headers().clone(),
                            hasBody: false
                        })]
            )
        }
        /// ehbp_events.dfy(932,3)
        pub fn ForUpload(e: &Arc<Event>) -> bool {
            (matches!(e.as_ref(), crate::EHBPEvents::Event::Chunk{ .. }) || matches!(e.as_ref(), StreamFailed{ .. })) && matches!(e.stream().as_ref(), RequestBody{ .. }) || matches!(e.as_ref(), AeadSealResult{ .. })
        }
        /// ehbp_events.dfy(935,3)
        pub fn AbortUpload(s: &Arc<State>, code: &Arc<Code>) -> (Arc<State>, Sequence<Arc<Action>>) {
            (
                _default::WithUpload(s, &Arc::new(Upload::UpDone {})),
                seq![Arc::new(Action::Write {
                            data: seq![] as Sequence<u8>,
                            end: Arc::new(BodyEnd::Aborted {
                                        code: code.clone()
                                    })
                        })]
            )
        }
        /// ehbp_events.dfy(944,3)
        pub fn Step(s: &Arc<State>, e: &Arc<Event>) -> (Arc<State>, Sequence<Arc<Action>>) {
            if matches!(e.as_ref(), CallerClose{ .. }) {
                _default::End(s, false, &Arc::new(Action::Close {
                            stream: Arc::new(Stream::ResponseBody {})
                        }))
            } else {
                let mut _source0: Arc<Phase> = s.phase().clone();
                if matches!((&_source0).as_ref(), Idle{ .. }) {
                    if matches!(e.as_ref(), Start{ .. }) {
                        _default::StepStart(s, e)
                    } else {
                        if matches!(e.as_ref(), DiscoverStart{ .. }) {
                            (
                                {
                                    let __pat_let34_0: Arc<State> = s.clone();
                                    {
                                        let _dt__update__tmp_h0: Arc<State> = __pat_let34_0.clone();
                                        {
                                            let __pat_let35_0: Arc<Phase> = Arc::new(Phase::DiscAwaitHead {});
                                            {
                                                let _dt__update_hphase_h0: Arc<Phase> = __pat_let35_0.clone();
                                                Arc::new(State::State {
                                                        phase: _dt__update_hphase_h0.clone(),
                                                        origin: _dt__update__tmp_h0.origin().clone(),
                                                        publicKey: _dt__update__tmp_h0.publicKey().clone(),
                                                        verb: _dt__update__tmp_h0.verb().clone(),
                                                        url: _dt__update__tmp_h0.url().clone(),
                                                        headers: _dt__update__tmp_h0.headers().clone(),
                                                        generation: _dt__update__tmp_h0.generation().clone(),
                                                        published: _dt__update__tmp_h0.published().clone(),
                                                        token: _dt__update__tmp_h0.token().clone(),
                                                        ctx: _dt__update__tmp_h0.ctx().clone()
                                                    })
                                            }
                                        }
                                    }
                                },
                                seq![Arc::new(Action::Send {
                                            verb: string_of("GET"),
                                            url: crate::EHBP::_default::OriginUrl(s.origin()).concat(&crate::EHBP::_default::KeysPath()),
                                            headers: seq![] as Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
                                            hasBody: false
                                        })]
                            )
                        } else {
                            _default::Unexpected(s)
                        }
                    }
                } else {
                    if matches!((&_source0).as_ref(), AwaitSession{ .. }) {
                        let mut ___mcc_h0: bool = _source0.hasBody().clone();
                        let mut hasBody: bool = ___mcc_h0;
                        if !matches!(e.as_ref(), SessionBegun{ .. }) {
                            _default::Unexpected(s)
                        } else {
                            let mut begun: Arc<State> = {
                                    let __pat_let36_0: Arc<State> = s.clone();
                                    {
                                        let _dt__update__tmp_h1: Arc<State> = __pat_let36_0.clone();
                                        {
                                            let __pat_let37_0: u64 = e.generation().clone();
                                            {
                                                let _dt__update_hgeneration_h0: u64 = __pat_let37_0;
                                                Arc::new(State::State {
                                                        phase: _dt__update__tmp_h1.phase().clone(),
                                                        origin: _dt__update__tmp_h1.origin().clone(),
                                                        publicKey: _dt__update__tmp_h1.publicKey().clone(),
                                                        verb: _dt__update__tmp_h1.verb().clone(),
                                                        url: _dt__update__tmp_h1.url().clone(),
                                                        headers: _dt__update__tmp_h1.headers().clone(),
                                                        generation: _dt__update_hgeneration_h0,
                                                        published: _dt__update__tmp_h1.published().clone(),
                                                        token: _dt__update__tmp_h1.token().clone(),
                                                        ctx: _dt__update__tmp_h1.ctx().clone()
                                                    })
                                            }
                                        }
                                    }
                                };
                            if hasBody {
                                (
                                    {
                                        let __pat_let38_0: Arc<State> = begun.clone();
                                        {
                                            let _dt__update__tmp_h2: Arc<State> = __pat_let38_0.clone();
                                            {
                                                let __pat_let39_0: Arc<Phase> = Arc::new(Phase::Peeking {
                                                            empty: int!(0)
                                                        });
                                                {
                                                    let _dt__update_hphase_h1: Arc<Phase> = __pat_let39_0.clone();
                                                    Arc::new(State::State {
                                                            phase: _dt__update_hphase_h1.clone(),
                                                            origin: _dt__update__tmp_h2.origin().clone(),
                                                            publicKey: _dt__update__tmp_h2.publicKey().clone(),
                                                            verb: _dt__update__tmp_h2.verb().clone(),
                                                            url: _dt__update__tmp_h2.url().clone(),
                                                            headers: _dt__update__tmp_h2.headers().clone(),
                                                            generation: _dt__update__tmp_h2.generation().clone(),
                                                            published: _dt__update__tmp_h2.published().clone(),
                                                            token: _dt__update__tmp_h2.token().clone(),
                                                            ctx: _dt__update__tmp_h2.ctx().clone()
                                                        })
                                                }
                                            }
                                        }
                                    },
                                    seq![Arc::new(Action::Read {
                                                stream: Arc::new(Stream::RequestBody {})
                                            })]
                                )
                            } else {
                                _default::SendPlain(&begun)
                            }
                        }
                    } else {
                        if matches!((&_source0).as_ref(), Peeking{ .. }) {
                            let mut ___mcc_h1: nat = _source0.empty().clone();
                            let mut empty: nat = ___mcc_h1.clone();
                            let mut _source1: Arc<Event> = e.clone();
                            if matches!((&_source1).as_ref(), Start{ .. }) {
                                let mut ___mcc_h12: Sequence<DafnyChar> = _source1.verb().clone();
                                let mut ___mcc_h13: Sequence<DafnyChar> = _source1.url().clone();
                                let mut ___mcc_h14: Sequence<DafnyChar> = _source1.scheme().clone();
                                let mut ___mcc_h15: Sequence<DafnyChar> = _source1.host().clone();
                                let mut ___mcc_h16: DafnyInt = _source1.port().clone();
                                let mut ___mcc_h17: bool = _source1.hasPort().clone();
                                let mut ___mcc_h18: bool = _source1.hasUserinfo().clone();
                                let mut ___mcc_h19: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source1.headers().clone();
                                let mut ___mcc_h20: bool = _source1.hasBody().clone();
                                _default::Unexpected(s)
                            } else {
                                if matches!((&_source1).as_ref(), DiscoverStart{ .. }) {
                                    _default::Unexpected(s)
                                } else {
                                    if matches!((&_source1).as_ref(), SessionBegun{ .. }) {
                                        let mut ___mcc_h30: u64 = _source1.generation().clone();
                                        _default::Unexpected(s)
                                    } else {
                                        if matches!((&_source1).as_ref(), RandomResult{ .. }) {
                                            let mut ___mcc_h32: Sequence<u8> = _source1.data().clone();
                                            _default::Unexpected(s)
                                        } else {
                                            if matches!((&_source1).as_ref(), X25519Result{ .. }) {
                                                let mut ___mcc_h34: Sequence<u8> = _source1.point().clone();
                                                _default::Unexpected(s)
                                            } else {
                                                if matches!((&_source1).as_ref(), HmacResult{ .. }) {
                                                    let mut ___mcc_h36: Sequence<u8> = _source1.mac().clone();
                                                    _default::Unexpected(s)
                                                } else {
                                                    if matches!((&_source1).as_ref(), AeadSealResult{ .. }) {
                                                        let mut ___mcc_h38: Sequence<u8> = _source1.ciphertext().clone();
                                                        _default::Unexpected(s)
                                                    } else {
                                                        if matches!((&_source1).as_ref(), AeadOpenResult{ .. }) {
                                                            let mut ___mcc_h40: bool = _source1.ok().clone();
                                                            let mut ___mcc_h41: Sequence<u8> = _source1.plaintext().clone();
                                                            _default::Unexpected(s)
                                                        } else {
                                                            if matches!((&_source1).as_ref(), ResponseHead{ .. }) {
                                                                let mut ___mcc_h44: DafnyInt = _source1.status().clone();
                                                                let mut ___mcc_h45: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source1.headers().clone();
                                                                let mut ___mcc_h46: bool = _source1.redirected().clone();
                                                                _default::Unexpected(s)
                                                            } else {
                                                                if matches!((&_source1).as_ref(), crate::EHBPEvents::Event::Chunk{ .. }) {
                                                                    let mut ___mcc_h50: Arc<Stream> = _source1.stream().clone();
                                                                    let mut ___mcc_h51: Sequence<u8> = _source1.data().clone();
                                                                    let mut ___mcc_h52: bool = _source1.eof().clone();
                                                                    let mut _source2: Arc<Stream> = ___mcc_h50.clone();
                                                                    if matches!((&_source2).as_ref(), RequestBody{ .. }) {
                                                                        let mut eof: bool = ___mcc_h52;
                                                                        let mut data: Sequence<u8> = ___mcc_h51.clone();
                                                                        if _default::MaxReadBytes() < data.cardinality() {
                                                                            _default::Abort(s, false, &Arc::new(Code::Transport {}), &string_of("request body chunk too large"))
                                                                        } else {
                                                                            if int!(0) < data.cardinality() {
                                                                                let mut _source3: Arc<HpkeOut> = _default::SenderStart(s.publicKey(), &crate::EHBP::_default::Ascii(&crate::EHBP::_default::HpkeRequestInfo()));
                                                                                if matches!((&_source3).as_ref(), HContinue{ .. }) {
                                                                                    let mut ___mcc_h58: Arc<Hpke> = _source3.h().clone();
                                                                                    let mut ___mcc_h59: Arc<Action> = _source3.action().clone();
                                                                                    let mut a: Arc<Action> = ___mcc_h59.clone();
                                                                                    let mut h: Arc<Hpke> = ___mcc_h58.clone();
                                                                                    (
                                                                                        {
                                                                                            let __pat_let40_0: Arc<State> = s.clone();
                                                                                            {
                                                                                                let _dt__update__tmp_h3: Arc<State> = __pat_let40_0.clone();
                                                                                                {
                                                                                                    let __pat_let41_0: Arc<Phase> = Arc::new(Phase::AwaitSetup {
                                                                                                                first: data.clone(),
                                                                                                                firstEof: eof,
                                                                                                                hpke: h.clone()
                                                                                                            });
                                                                                                    {
                                                                                                        let _dt__update_hphase_h2: Arc<Phase> = __pat_let41_0.clone();
                                                                                                        Arc::new(State::State {
                                                                                                                phase: _dt__update_hphase_h2.clone(),
                                                                                                                origin: _dt__update__tmp_h3.origin().clone(),
                                                                                                                publicKey: _dt__update__tmp_h3.publicKey().clone(),
                                                                                                                verb: _dt__update__tmp_h3.verb().clone(),
                                                                                                                url: _dt__update__tmp_h3.url().clone(),
                                                                                                                headers: _dt__update__tmp_h3.headers().clone(),
                                                                                                                generation: _dt__update__tmp_h3.generation().clone(),
                                                                                                                published: _dt__update__tmp_h3.published().clone(),
                                                                                                                token: _dt__update__tmp_h3.token().clone(),
                                                                                                                ctx: _dt__update__tmp_h3.ctx().clone()
                                                                                                            })
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        seq![a.clone()]
                                                                                    )
                                                                                } else {
                                                                                    if matches!((&_source3).as_ref(), HReady{ .. }) {
                                                                                        let mut ___mcc_h62: Arc<Ctx> = _source3.ctx().clone();
                                                                                        let mut ___mcc_h63: Sequence<u8> = _source3.enc().clone();
                                                                                        _default::Unexpected(s)
                                                                                    } else {
                                                                                        let mut ___mcc_h66: Arc<Code> = _source3.code().clone();
                                                                                        let mut ___mcc_h67: Sequence<DafnyChar> = _source3.message().clone();
                                                                                        _default::Unexpected(s)
                                                                                    }
                                                                                }
                                                                            } else {
                                                                                if eof {
                                                                                    _default::SendPlain(s)
                                                                                } else {
                                                                                    if empty.clone() + int!(1) == crate::EHBP::_default::MaxEmptyReads() {
                                                                                        _default::Abort(s, false, &Arc::new(Code::Transport {}), &string_of("request body made no progress"))
                                                                                    } else {
                                                                                        (
                                                                                            {
                                                                                                let __pat_let42_0: Arc<State> = s.clone();
                                                                                                {
                                                                                                    let _dt__update__tmp_h4: Arc<State> = __pat_let42_0.clone();
                                                                                                    {
                                                                                                        let __pat_let43_0: Arc<Phase> = Arc::new(Phase::Peeking {
                                                                                                                    empty: empty.clone() + int!(1)
                                                                                                                });
                                                                                                        {
                                                                                                            let _dt__update_hphase_h3: Arc<Phase> = __pat_let43_0.clone();
                                                                                                            Arc::new(State::State {
                                                                                                                    phase: _dt__update_hphase_h3.clone(),
                                                                                                                    origin: _dt__update__tmp_h4.origin().clone(),
                                                                                                                    publicKey: _dt__update__tmp_h4.publicKey().clone(),
                                                                                                                    verb: _dt__update__tmp_h4.verb().clone(),
                                                                                                                    url: _dt__update__tmp_h4.url().clone(),
                                                                                                                    headers: _dt__update__tmp_h4.headers().clone(),
                                                                                                                    generation: _dt__update__tmp_h4.generation().clone(),
                                                                                                                    published: _dt__update__tmp_h4.published().clone(),
                                                                                                                    token: _dt__update__tmp_h4.token().clone(),
                                                                                                                    ctx: _dt__update__tmp_h4.ctx().clone()
                                                                                                                })
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            },
                                                                                            seq![Arc::new(Action::Read {
                                                                                                        stream: Arc::new(Stream::RequestBody {})
                                                                                                    })]
                                                                                        )
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    } else {
                                                                        _default::Unexpected(s)
                                                                    }
                                                                } else {
                                                                    if matches!((&_source1).as_ref(), StreamFailed{ .. }) {
                                                                        let mut ___mcc_h56: Arc<Stream> = _source1.stream().clone();
                                                                        let mut _source4: Arc<Stream> = ___mcc_h56.clone();
                                                                        if matches!((&_source4).as_ref(), RequestBody{ .. }) {
                                                                            _default::Abort(s, false, &Arc::new(Code::Transport {}), &string_of("failed to read request body"))
                                                                        } else {
                                                                            _default::Unexpected(s)
                                                                        }
                                                                    } else {
                                                                        if matches!((&_source1).as_ref(), CallerRead{ .. }) {
                                                                            _default::Unexpected(s)
                                                                        } else {
                                                                            _default::Unexpected(s)
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            if matches!((&_source0).as_ref(), AwaitSetup{ .. }) {
                                let mut ___mcc_h2: Chunk = _source0.first().clone();
                                let mut ___mcc_h3: bool = _source0.firstEof().clone();
                                let mut ___mcc_h4: Arc<Hpke> = _source0.hpke().clone();
                                let mut h: Arc<Hpke> = ___mcc_h4.clone();
                                let mut firstEof: bool = ___mcc_h3;
                                let mut first: Chunk = ___mcc_h2.clone();
                                let mut _source5: Arc<HpkeOut> = _default::HpkeStep(&h, e);
                                if matches!((&_source5).as_ref(), HContinue{ .. }) {
                                    let mut ___mcc_h70: Arc<Hpke> = _source5.h().clone();
                                    let mut ___mcc_h71: Arc<Action> = _source5.action().clone();
                                    let mut a: Arc<Action> = ___mcc_h71.clone();
                                    let mut next: Arc<Hpke> = ___mcc_h70.clone();
                                    (
                                        {
                                            let __pat_let44_0: Arc<State> = s.clone();
                                            {
                                                let _dt__update__tmp_h5: Arc<State> = __pat_let44_0.clone();
                                                {
                                                    let __pat_let45_0: Arc<Phase> = Arc::new(Phase::AwaitSetup {
                                                                first: first.clone(),
                                                                firstEof: firstEof,
                                                                hpke: next.clone()
                                                            });
                                                    {
                                                        let _dt__update_hphase_h4: Arc<Phase> = __pat_let45_0.clone();
                                                        Arc::new(State::State {
                                                                phase: _dt__update_hphase_h4.clone(),
                                                                origin: _dt__update__tmp_h5.origin().clone(),
                                                                publicKey: _dt__update__tmp_h5.publicKey().clone(),
                                                                verb: _dt__update__tmp_h5.verb().clone(),
                                                                url: _dt__update__tmp_h5.url().clone(),
                                                                headers: _dt__update__tmp_h5.headers().clone(),
                                                                generation: _dt__update__tmp_h5.generation().clone(),
                                                                published: _dt__update__tmp_h5.published().clone(),
                                                                token: _dt__update__tmp_h5.token().clone(),
                                                                ctx: _dt__update__tmp_h5.ctx().clone()
                                                            })
                                                    }
                                                }
                                            }
                                        },
                                        seq![a.clone()]
                                    )
                                } else {
                                    if matches!((&_source5).as_ref(), HReady{ .. }) {
                                        let mut ___mcc_h72: Arc<Ctx> = _source5.ctx().clone();
                                        let mut ___mcc_h73: Sequence<u8> = _source5.enc().clone();
                                        let mut enc: Sequence<u8> = ___mcc_h73.clone();
                                        let mut ctx: Arc<Ctx> = ___mcc_h72.clone();
                                        let mut job: Arc<Job> = _default::ExportJob(&ctx, &crate::EHBP::_default::Ascii(&crate::EHBP::_default::ExportLabel()), &crate::EHBP::_default::ExportLength());
                                        (
                                            {
                                                let __pat_let46_0: Arc<State> = s.clone();
                                                {
                                                    let _dt__update__tmp_h6: Arc<State> = __pat_let46_0.clone();
                                                    {
                                                        let __pat_let47_0: Arc<Ctx> = ctx.clone();
                                                        {
                                                            let _dt__update_hctx_h0: Arc<Ctx> = __pat_let47_0.clone();
                                                            {
                                                                let __pat_let48_0: Arc<Phase> = Arc::new(Phase::AwaitExport {
                                                                            first: first.clone(),
                                                                            firstEof: firstEof,
                                                                            enc: enc.clone(),
                                                                            job: job.clone()
                                                                        });
                                                                {
                                                                    let _dt__update_hphase_h5: Arc<Phase> = __pat_let48_0.clone();
                                                                    Arc::new(State::State {
                                                                            phase: _dt__update_hphase_h5.clone(),
                                                                            origin: _dt__update__tmp_h6.origin().clone(),
                                                                            publicKey: _dt__update__tmp_h6.publicKey().clone(),
                                                                            verb: _dt__update__tmp_h6.verb().clone(),
                                                                            url: _dt__update__tmp_h6.url().clone(),
                                                                            headers: _dt__update__tmp_h6.headers().clone(),
                                                                            generation: _dt__update__tmp_h6.generation().clone(),
                                                                            published: _dt__update__tmp_h6.published().clone(),
                                                                            token: _dt__update__tmp_h6.token().clone(),
                                                                            ctx: _dt__update_hctx_h0.clone()
                                                                        })
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            seq![_default::JobAction(&job)]
                                        )
                                    } else {
                                        let mut ___mcc_h74: Arc<Code> = _source5.code().clone();
                                        let mut ___mcc_h75: Sequence<DafnyChar> = _source5.message().clone();
                                        let mut message: Sequence<DafnyChar> = ___mcc_h75.clone();
                                        let mut code: Arc<Code> = ___mcc_h74.clone();
                                        _default::Abort(s, false, &code, &message)
                                    }
                                }
                            } else {
                                if matches!((&_source0).as_ref(), AwaitExport{ .. }) {
                                    let mut ___mcc_h5: Chunk = _source0.first().clone();
                                    let mut ___mcc_h6: bool = _source0.firstEof().clone();
                                    let mut ___mcc_h7: Sequence<u8> = _source0.enc().clone();
                                    let mut ___mcc_h8: Arc<Job> = _source0.job().clone();
                                    let mut job: Arc<Job> = ___mcc_h8.clone();
                                    let mut enc: Sequence<u8> = ___mcc_h7.clone();
                                    let mut firstEof: bool = ___mcc_h6;
                                    let mut first: Chunk = ___mcc_h5.clone();
                                    let mut _source6: Arc<JobOut> = _default::JobStep(&job, e);
                                    if matches!((&_source6).as_ref(), Pending{ .. }) {
                                        let mut ___mcc_h76: Arc<Job> = _source6.job().clone();
                                        let mut ___mcc_h77: Arc<Action> = _source6.action().clone();
                                        let mut a: Arc<Action> = ___mcc_h77.clone();
                                        let mut next: Arc<Job> = ___mcc_h76.clone();
                                        (
                                            {
                                                let __pat_let49_0: Arc<State> = s.clone();
                                                {
                                                    let _dt__update__tmp_h7: Arc<State> = __pat_let49_0.clone();
                                                    {
                                                        let __pat_let50_0: Arc<Phase> = Arc::new(Phase::AwaitExport {
                                                                    first: first.clone(),
                                                                    firstEof: firstEof,
                                                                    enc: enc.clone(),
                                                                    job: next.clone()
                                                                });
                                                        {
                                                            let _dt__update_hphase_h6: Arc<Phase> = __pat_let50_0.clone();
                                                            Arc::new(State::State {
                                                                    phase: _dt__update_hphase_h6.clone(),
                                                                    origin: _dt__update__tmp_h7.origin().clone(),
                                                                    publicKey: _dt__update__tmp_h7.publicKey().clone(),
                                                                    verb: _dt__update__tmp_h7.verb().clone(),
                                                                    url: _dt__update__tmp_h7.url().clone(),
                                                                    headers: _dt__update__tmp_h7.headers().clone(),
                                                                    generation: _dt__update__tmp_h7.generation().clone(),
                                                                    published: _dt__update__tmp_h7.published().clone(),
                                                                    token: _dt__update__tmp_h7.token().clone(),
                                                                    ctx: _dt__update__tmp_h7.ctx().clone()
                                                                })
                                                        }
                                                    }
                                                }
                                            },
                                            seq![a.clone()]
                                        )
                                    } else {
                                        if matches!((&_source6).as_ref(), Output{ .. }) {
                                            let mut ___mcc_h78: Sequence<u8> = _source6.data().clone();
                                            let mut secret: Sequence<u8> = ___mcc_h78.clone();
                                            if enc.cardinality() != crate::EHBP::_default::RequestEncLength() {
                                                _default::Abort(s, false, &Arc::new(Code::HpkeSetupFailed {}), &string_of("HPKE sender setup failed"))
                                            } else {
                                                if secret.cardinality() != crate::EHBP::_default::ExportLength() {
                                                    _default::Abort(s, false, &Arc::new(Code::HpkeSetupFailed {}), &string_of("HPKE export failed"))
                                                } else {
                                                    let mut token: Arc<Token> = Arc::new(Token::Token {
                                                                exportedSecret: secret.clone(),
                                                                requestEnc: enc.clone()
                                                            });
                                                    let mut headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = s.headers().concat(&seq![(
                                                                    crate::EHBP::_default::EncapsulatedKeyHeader(),
                                                                    crate::EHBP::_default::EncodeHex(&enc)
                                                                )]);
                                                    (
                                                        {
                                                            let __pat_let51_0: Arc<State> = s.clone();
                                                            {
                                                                let _dt__update__tmp_h8: Arc<State> = __pat_let51_0.clone();
                                                                {
                                                                    let __pat_let52_0: Arc<Token> = token.clone();
                                                                    {
                                                                        let _dt__update_htoken_h0: Arc<Token> = __pat_let52_0.clone();
                                                                        {
                                                                            let __pat_let53_0: bool = true;
                                                                            {
                                                                                let _dt__update_hpublished_h0: bool = __pat_let53_0;
                                                                                {
                                                                                    let __pat_let54_0: Arc<Phase> = Arc::new(Phase::Exchanging {
                                                                                                upload: Arc::new(Upload::Sealing {
                                                                                                            plaintext: first.clone(),
                                                                                                            offset: 0,
                                                                                                            eof: firstEof
                                                                                                        }),
                                                                                                response: Arc::new(Response::AwaitHead {
                                                                                                            encrypted: true
                                                                                                        })
                                                                                            });
                                                                                    {
                                                                                        let _dt__update_hphase_h7: Arc<Phase> = __pat_let54_0.clone();
                                                                                        Arc::new(State::State {
                                                                                                phase: _dt__update_hphase_h7.clone(),
                                                                                                origin: _dt__update__tmp_h8.origin().clone(),
                                                                                                publicKey: _dt__update__tmp_h8.publicKey().clone(),
                                                                                                verb: _dt__update__tmp_h8.verb().clone(),
                                                                                                url: _dt__update__tmp_h8.url().clone(),
                                                                                                headers: _dt__update__tmp_h8.headers().clone(),
                                                                                                generation: _dt__update__tmp_h8.generation().clone(),
                                                                                                published: _dt__update_hpublished_h0,
                                                                                                token: _dt__update_htoken_h0.clone(),
                                                                                                ctx: _dt__update__tmp_h8.ctx().clone()
                                                                                            })
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        seq![Arc::new(Action::PublishToken {
                                                                    generation: s.generation().clone(),
                                                                    exportedSecret: secret.clone(),
                                                                    requestEnc: enc.clone()
                                                                }), Arc::new(Action::Send {
                                                                    verb: s.verb().clone(),
                                                                    url: s.url().clone(),
                                                                    headers: headers.clone(),
                                                                    hasBody: true
                                                                }), _default::SealAction(s.ctx(), &_default::Piece(&first, 0, _default::Min32(truncate!(first.cardinality(), u32), crate::EHBP::_default::RequestFrameBytes())))]
                                                    )
                                                }
                                            }
                                        } else {
                                            let mut ___mcc_h79: Arc<Code> = _source6.code().clone();
                                            let mut ___mcc_h80: Sequence<DafnyChar> = _source6.message().clone();
                                            let mut message: Sequence<DafnyChar> = ___mcc_h80.clone();
                                            let mut code: Arc<Code> = ___mcc_h79.clone();
                                            _default::Abort(s, false, &code, &message)
                                        }
                                    }
                                } else {
                                    if matches!((&_source0).as_ref(), Exchanging{ .. }) {
                                        let mut ___mcc_h9: Arc<Upload> = _source0.upload().clone();
                                        let mut ___mcc_h10: Arc<Response> = _source0.response().clone();
                                        let mut rs: Arc<Response> = ___mcc_h10.clone();
                                        let mut up: Arc<Upload> = ___mcc_h9.clone();
                                        if _default::ForUpload(e) {
                                            _default::StepUpload(s, &up, e)
                                        } else {
                                            _default::StepResponse(s, &rs, e)
                                        }
                                    } else {
                                        if matches!((&_source0).as_ref(), DiscAwaitHead{ .. }) {
                                            let mut _source7: Arc<Event> = e.clone();
                                            if matches!((&_source7).as_ref(), Start{ .. }) {
                                                let mut ___mcc_h81: Sequence<DafnyChar> = _source7.verb().clone();
                                                let mut ___mcc_h82: Sequence<DafnyChar> = _source7.url().clone();
                                                let mut ___mcc_h83: Sequence<DafnyChar> = _source7.scheme().clone();
                                                let mut ___mcc_h84: Sequence<DafnyChar> = _source7.host().clone();
                                                let mut ___mcc_h85: DafnyInt = _source7.port().clone();
                                                let mut ___mcc_h86: bool = _source7.hasPort().clone();
                                                let mut ___mcc_h87: bool = _source7.hasUserinfo().clone();
                                                let mut ___mcc_h88: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source7.headers().clone();
                                                let mut ___mcc_h89: bool = _source7.hasBody().clone();
                                                _default::Unexpected(s)
                                            } else {
                                                if matches!((&_source7).as_ref(), DiscoverStart{ .. }) {
                                                    _default::Unexpected(s)
                                                } else {
                                                    if matches!((&_source7).as_ref(), SessionBegun{ .. }) {
                                                        let mut ___mcc_h99: u64 = _source7.generation().clone();
                                                        _default::Unexpected(s)
                                                    } else {
                                                        if matches!((&_source7).as_ref(), RandomResult{ .. }) {
                                                            let mut ___mcc_h101: Sequence<u8> = _source7.data().clone();
                                                            _default::Unexpected(s)
                                                        } else {
                                                            if matches!((&_source7).as_ref(), X25519Result{ .. }) {
                                                                let mut ___mcc_h103: Sequence<u8> = _source7.point().clone();
                                                                _default::Unexpected(s)
                                                            } else {
                                                                if matches!((&_source7).as_ref(), HmacResult{ .. }) {
                                                                    let mut ___mcc_h105: Sequence<u8> = _source7.mac().clone();
                                                                    _default::Unexpected(s)
                                                                } else {
                                                                    if matches!((&_source7).as_ref(), AeadSealResult{ .. }) {
                                                                        let mut ___mcc_h107: Sequence<u8> = _source7.ciphertext().clone();
                                                                        _default::Unexpected(s)
                                                                    } else {
                                                                        if matches!((&_source7).as_ref(), AeadOpenResult{ .. }) {
                                                                            let mut ___mcc_h109: bool = _source7.ok().clone();
                                                                            let mut ___mcc_h110: Sequence<u8> = _source7.plaintext().clone();
                                                                            _default::Unexpected(s)
                                                                        } else {
                                                                            if matches!((&_source7).as_ref(), ResponseHead{ .. }) {
                                                                                let mut ___mcc_h113: DafnyInt = _source7.status().clone();
                                                                                let mut ___mcc_h114: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source7.headers().clone();
                                                                                let mut ___mcc_h115: bool = _source7.redirected().clone();
                                                                                let mut redirected: bool = ___mcc_h115;
                                                                                let mut headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = ___mcc_h114.clone();
                                                                                let mut status: DafnyInt = ___mcc_h113.clone();
                                                                                if status.clone() < int!(100) || int!(599) < status.clone() {
                                                                                    _default::Abort(s, true, &Arc::new(Code::Transport {}), &string_of("failed to get server public key"))
                                                                                } else {
                                                                                    let mut _source8: Arc<crate::EHBP::Result<()>> = crate::EHBP::_default::ClassifyDiscovery(&Arc::new(Head::Head {
                                                                                                    status: status.clone(),
                                                                                                    headers: headers.clone(),
                                                                                                    redirected: redirected
                                                                                                }));
                                                                                    if matches!((&_source8).as_ref(), Ok{ .. }) {
                                                                                        let mut ___mcc_h127: () = _source8.value().clone();
                                                                                        (
                                                                                            {
                                                                                                let __pat_let55_0: Arc<State> = s.clone();
                                                                                                {
                                                                                                    let _dt__update__tmp_h9: Arc<State> = __pat_let55_0.clone();
                                                                                                    {
                                                                                                        let __pat_let56_0: Arc<Phase> = Arc::new(Phase::DiscReading {
                                                                                                                    data: seq![] as Sequence<u8>
                                                                                                                });
                                                                                                        {
                                                                                                            let _dt__update_hphase_h8: Arc<Phase> = __pat_let56_0.clone();
                                                                                                            Arc::new(State::State {
                                                                                                                    phase: _dt__update_hphase_h8.clone(),
                                                                                                                    origin: _dt__update__tmp_h9.origin().clone(),
                                                                                                                    publicKey: _dt__update__tmp_h9.publicKey().clone(),
                                                                                                                    verb: _dt__update__tmp_h9.verb().clone(),
                                                                                                                    url: _dt__update__tmp_h9.url().clone(),
                                                                                                                    headers: _dt__update__tmp_h9.headers().clone(),
                                                                                                                    generation: _dt__update__tmp_h9.generation().clone(),
                                                                                                                    published: _dt__update__tmp_h9.published().clone(),
                                                                                                                    token: _dt__update__tmp_h9.token().clone(),
                                                                                                                    ctx: _dt__update__tmp_h9.ctx().clone()
                                                                                                                })
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            },
                                                                                            seq![Arc::new(Action::Read {
                                                                                                        stream: Arc::new(Stream::ResponseBody {})
                                                                                                    })]
                                                                                        )
                                                                                    } else {
                                                                                        let mut ___mcc_h128: Arc<Code> = _source8.code().clone();
                                                                                        let mut ___mcc_h129: Sequence<DafnyChar> = _source8.message().clone();
                                                                                        let mut message: Sequence<DafnyChar> = ___mcc_h129.clone();
                                                                                        let mut code: Arc<Code> = ___mcc_h128.clone();
                                                                                        _default::Abort(s, true, &code, &message)
                                                                                    }
                                                                                }
                                                                            } else {
                                                                                if matches!((&_source7).as_ref(), crate::EHBPEvents::Event::Chunk{ .. }) {
                                                                                    let mut ___mcc_h119: Arc<Stream> = _source7.stream().clone();
                                                                                    let mut ___mcc_h120: Sequence<u8> = _source7.data().clone();
                                                                                    let mut ___mcc_h121: bool = _source7.eof().clone();
                                                                                    _default::Unexpected(s)
                                                                                } else {
                                                                                    if matches!((&_source7).as_ref(), StreamFailed{ .. }) {
                                                                                        let mut ___mcc_h125: Arc<Stream> = _source7.stream().clone();
                                                                                        let mut _source9: Arc<Stream> = ___mcc_h125.clone();
                                                                                        if matches!((&_source9).as_ref(), RequestBody{ .. }) {
                                                                                            _default::Unexpected(s)
                                                                                        } else {
                                                                                            _default::Abort(s, false, &Arc::new(Code::Transport {}), &string_of("failed to get server public key"))
                                                                                        }
                                                                                    } else {
                                                                                        if matches!((&_source7).as_ref(), CallerRead{ .. }) {
                                                                                            _default::Unexpected(s)
                                                                                        } else {
                                                                                            _default::Unexpected(s)
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            if matches!((&_source0).as_ref(), DiscReading{ .. }) {
                                                let mut ___mcc_h11: Sequence<u8> = _source0.data().clone();
                                                let mut data: Sequence<u8> = ___mcc_h11.clone();
                                                let mut _source10: Arc<Event> = e.clone();
                                                if matches!((&_source10).as_ref(), Start{ .. }) {
                                                    let mut ___mcc_h130: Sequence<DafnyChar> = _source10.verb().clone();
                                                    let mut ___mcc_h131: Sequence<DafnyChar> = _source10.url().clone();
                                                    let mut ___mcc_h132: Sequence<DafnyChar> = _source10.scheme().clone();
                                                    let mut ___mcc_h133: Sequence<DafnyChar> = _source10.host().clone();
                                                    let mut ___mcc_h134: DafnyInt = _source10.port().clone();
                                                    let mut ___mcc_h135: bool = _source10.hasPort().clone();
                                                    let mut ___mcc_h136: bool = _source10.hasUserinfo().clone();
                                                    let mut ___mcc_h137: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source10.headers().clone();
                                                    let mut ___mcc_h138: bool = _source10.hasBody().clone();
                                                    _default::Unexpected(s)
                                                } else {
                                                    if matches!((&_source10).as_ref(), DiscoverStart{ .. }) {
                                                        _default::Unexpected(s)
                                                    } else {
                                                        if matches!((&_source10).as_ref(), SessionBegun{ .. }) {
                                                            let mut ___mcc_h148: u64 = _source10.generation().clone();
                                                            _default::Unexpected(s)
                                                        } else {
                                                            if matches!((&_source10).as_ref(), RandomResult{ .. }) {
                                                                let mut ___mcc_h150: Sequence<u8> = _source10.data().clone();
                                                                _default::Unexpected(s)
                                                            } else {
                                                                if matches!((&_source10).as_ref(), X25519Result{ .. }) {
                                                                    let mut ___mcc_h152: Sequence<u8> = _source10.point().clone();
                                                                    _default::Unexpected(s)
                                                                } else {
                                                                    if matches!((&_source10).as_ref(), HmacResult{ .. }) {
                                                                        let mut ___mcc_h154: Sequence<u8> = _source10.mac().clone();
                                                                        _default::Unexpected(s)
                                                                    } else {
                                                                        if matches!((&_source10).as_ref(), AeadSealResult{ .. }) {
                                                                            let mut ___mcc_h156: Sequence<u8> = _source10.ciphertext().clone();
                                                                            _default::Unexpected(s)
                                                                        } else {
                                                                            if matches!((&_source10).as_ref(), AeadOpenResult{ .. }) {
                                                                                let mut ___mcc_h158: bool = _source10.ok().clone();
                                                                                let mut ___mcc_h159: Sequence<u8> = _source10.plaintext().clone();
                                                                                _default::Unexpected(s)
                                                                            } else {
                                                                                if matches!((&_source10).as_ref(), ResponseHead{ .. }) {
                                                                                    let mut ___mcc_h162: DafnyInt = _source10.status().clone();
                                                                                    let mut ___mcc_h163: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source10.headers().clone();
                                                                                    let mut ___mcc_h164: bool = _source10.redirected().clone();
                                                                                    _default::Unexpected(s)
                                                                                } else {
                                                                                    if matches!((&_source10).as_ref(), crate::EHBPEvents::Event::Chunk{ .. }) {
                                                                                        let mut ___mcc_h168: Arc<Stream> = _source10.stream().clone();
                                                                                        let mut ___mcc_h169: Sequence<u8> = _source10.data().clone();
                                                                                        let mut ___mcc_h170: bool = _source10.eof().clone();
                                                                                        let mut _source11: Arc<Stream> = ___mcc_h168.clone();
                                                                                        if matches!((&_source11).as_ref(), RequestBody{ .. }) {
                                                                                            _default::Unexpected(s)
                                                                                        } else {
                                                                                            let mut eof: bool = ___mcc_h170;
                                                                                            let mut chunk: Sequence<u8> = ___mcc_h169.clone();
                                                                                            let mut grown: Sequence<u8> = data.concat(&chunk);
                                                                                            if grown.cardinality() <= crate::EHBP::_default::MaxKeyConfigBytes() && !eof {
                                                                                                (
                                                                                                    {
                                                                                                        let __pat_let57_0: Arc<State> = s.clone();
                                                                                                        {
                                                                                                            let _dt__update__tmp_h10: Arc<State> = __pat_let57_0.clone();
                                                                                                            {
                                                                                                                let __pat_let58_0: Arc<Phase> = Arc::new(Phase::DiscReading {
                                                                                                                            data: grown.clone()
                                                                                                                        });
                                                                                                                {
                                                                                                                    let _dt__update_hphase_h9: Arc<Phase> = __pat_let58_0.clone();
                                                                                                                    Arc::new(State::State {
                                                                                                                            phase: _dt__update_hphase_h9.clone(),
                                                                                                                            origin: _dt__update__tmp_h10.origin().clone(),
                                                                                                                            publicKey: _dt__update__tmp_h10.publicKey().clone(),
                                                                                                                            verb: _dt__update__tmp_h10.verb().clone(),
                                                                                                                            url: _dt__update__tmp_h10.url().clone(),
                                                                                                                            headers: _dt__update__tmp_h10.headers().clone(),
                                                                                                                            generation: _dt__update__tmp_h10.generation().clone(),
                                                                                                                            published: _dt__update__tmp_h10.published().clone(),
                                                                                                                            token: _dt__update__tmp_h10.token().clone(),
                                                                                                                            ctx: _dt__update__tmp_h10.ctx().clone()
                                                                                                                        })
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    },
                                                                                                    seq![Arc::new(Action::Read {
                                                                                                                stream: Arc::new(Stream::ResponseBody {})
                                                                                                            })]
                                                                                                )
                                                                                            } else {
                                                                                                let mut _source12: Arc<crate::EHBP::Result<Sequence<u8>>> = crate::EHBP::_default::ParseConfig(&grown);
                                                                                                if matches!((&_source12).as_ref(), Ok{ .. }) {
                                                                                                    let mut ___mcc_h176: Sequence<u8> = _source12.value().clone();
                                                                                                    let mut pk: Sequence<u8> = ___mcc_h176.clone();
                                                                                                    _default::End(s, true, &Arc::new(Action::Discovered {
                                                                                                                publicKey: pk.clone()
                                                                                                            }))
                                                                                                } else {
                                                                                                    let mut ___mcc_h177: Arc<Code> = _source12.code().clone();
                                                                                                    let mut ___mcc_h178: Sequence<DafnyChar> = _source12.message().clone();
                                                                                                    let mut message: Sequence<DafnyChar> = ___mcc_h178.clone();
                                                                                                    let mut code: Arc<Code> = ___mcc_h177.clone();
                                                                                                    _default::Abort(s, true, &code, &message)
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    } else {
                                                                                        if matches!((&_source10).as_ref(), StreamFailed{ .. }) {
                                                                                            let mut ___mcc_h174: Arc<Stream> = _source10.stream().clone();
                                                                                            let mut _source13: Arc<Stream> = ___mcc_h174.clone();
                                                                                            if matches!((&_source13).as_ref(), RequestBody{ .. }) {
                                                                                                _default::Unexpected(s)
                                                                                            } else {
                                                                                                _default::Abort(s, true, &Arc::new(Code::Transport {}), &string_of("failed to read key configuration"))
                                                                                            }
                                                                                        } else {
                                                                                            if matches!((&_source10).as_ref(), CallerRead{ .. }) {
                                                                                                _default::Unexpected(s)
                                                                                            } else {
                                                                                                _default::Unexpected(s)
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                _default::Unexpected(s)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(1024,3)
        pub fn StepStart(s: &Arc<State>, e: &Arc<Event>) -> (Arc<State>, Sequence<Arc<Action>>) {
            let mut target: Arc<crate::EHBP::Result<Arc<Origin>>> = crate::EHBP::_default::MakeOrigin(e.scheme(), e.host(), &(if e.hasPort().clone() {
                        Arc::new(Option::Some::<DafnyInt> {
                                value: e.port().clone()
                            })
                    } else {
                        Arc::new(Option::None::<DafnyInt> {})
                    }), e.hasUserinfo().clone());
            let mut _source0: Arc<crate::EHBP::Result<()>> = crate::EHBP::_default::ValidateRequest(s.origin(), &target, e.headers());
            if matches!((&_source0).as_ref(), Ok{ .. }) {
                let mut ___mcc_h0: () = _source0.value().clone();
                (
                    {
                        let __pat_let59_0: Arc<State> = s.clone();
                        {
                            let _dt__update__tmp_h0: Arc<State> = __pat_let59_0.clone();
                            {
                                let __pat_let60_0: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = crate::EHBP::_default::DropFraming(e.headers());
                                {
                                    let _dt__update_hheaders_h0: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = __pat_let60_0.clone();
                                    {
                                        let __pat_let61_0: Sequence<DafnyChar> = e.url().clone();
                                        {
                                            let _dt__update_hurl_h0: Sequence<DafnyChar> = __pat_let61_0.clone();
                                            {
                                                let __pat_let62_0: Sequence<DafnyChar> = e.verb().clone();
                                                {
                                                    let _dt__update_hverb_h0: Sequence<DafnyChar> = __pat_let62_0.clone();
                                                    {
                                                        let __pat_let63_0: Arc<Phase> = Arc::new(Phase::AwaitSession {
                                                                    hasBody: e.hasBody().clone()
                                                                });
                                                        {
                                                            let _dt__update_hphase_h0: Arc<Phase> = __pat_let63_0.clone();
                                                            Arc::new(State::State {
                                                                    phase: _dt__update_hphase_h0.clone(),
                                                                    origin: _dt__update__tmp_h0.origin().clone(),
                                                                    publicKey: _dt__update__tmp_h0.publicKey().clone(),
                                                                    verb: _dt__update_hverb_h0.clone(),
                                                                    url: _dt__update_hurl_h0.clone(),
                                                                    headers: _dt__update_hheaders_h0.clone(),
                                                                    generation: _dt__update__tmp_h0.generation().clone(),
                                                                    published: _dt__update__tmp_h0.published().clone(),
                                                                    token: _dt__update__tmp_h0.token().clone(),
                                                                    ctx: _dt__update__tmp_h0.ctx().clone()
                                                                })
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    seq![Arc::new(Action::BeginSession {})]
                )
            } else {
                let mut ___mcc_h1: Arc<Code> = _source0.code().clone();
                let mut ___mcc_h2: Sequence<DafnyChar> = _source0.message().clone();
                let mut message: Sequence<DafnyChar> = ___mcc_h2.clone();
                let mut code: Arc<Code> = ___mcc_h1.clone();
                _default::Abort(s, false, &code, &message)
            }
        }
        /// ehbp_events.dfy(1038,3)
        pub fn StepUpload(s: &Arc<State>, up: &Arc<Upload>, e: &Arc<Event>) -> (Arc<State>, Sequence<Arc<Action>>) {
            let mut _source0: Arc<Upload> = up.clone();
            if matches!((&_source0).as_ref(), NoUpload{ .. }) {
                _default::AbortUpload(s, &Arc::new(Code::Transport {}))
            } else {
                if matches!((&_source0).as_ref(), Sealing{ .. }) {
                    let mut ___mcc_h0: Chunk = _source0.plaintext().clone();
                    let mut ___mcc_h1: u32 = _source0.offset().clone();
                    let mut ___mcc_h2: bool = _source0.eof().clone();
                    let mut eof: bool = ___mcc_h2;
                    let mut offset: u32 = ___mcc_h1;
                    let mut plaintext: Chunk = ___mcc_h0.clone();
                    let mut size: u32 = truncate!(plaintext.cardinality(), u32);
                    let mut at: u32 = _default::Min32(offset, size);
                    let mut n: u32 = _default::Min32(size - at, crate::EHBP::_default::RequestFrameBytes());
                    if !matches!(e.as_ref(), AeadSealResult{ .. }) {
                        _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                    } else {
                        if e.ciphertext().cardinality() != int!(n) + crate::EHBP::_default::AeadTagLength() {
                            _default::AbortUpload(s, &Arc::new(Code::HpkeSetupFailed {}))
                        } else {
                            if s.ctx().seqNo().clone() == _default::MaxSeq() {
                                _default::AbortUpload(s, &Arc::new(Code::SequenceOverflow {}))
                            } else {
                                let mut bumped: Arc<State> = {
                                        let __pat_let64_0: Arc<State> = s.clone();
                                        {
                                            let _dt__update__tmp_h0: Arc<State> = __pat_let64_0.clone();
                                            {
                                                let __pat_let65_0: Arc<Ctx> = _default::Bump(s.ctx());
                                                {
                                                    let _dt__update_hctx_h0: Arc<Ctx> = __pat_let65_0.clone();
                                                    Arc::new(State::State {
                                                            phase: _dt__update__tmp_h0.phase().clone(),
                                                            origin: _dt__update__tmp_h0.origin().clone(),
                                                            publicKey: _dt__update__tmp_h0.publicKey().clone(),
                                                            verb: _dt__update__tmp_h0.verb().clone(),
                                                            url: _dt__update__tmp_h0.url().clone(),
                                                            headers: _dt__update__tmp_h0.headers().clone(),
                                                            generation: _dt__update__tmp_h0.generation().clone(),
                                                            published: _dt__update__tmp_h0.published().clone(),
                                                            token: _dt__update__tmp_h0.token().clone(),
                                                            ctx: _dt__update_hctx_h0.clone()
                                                        })
                                                }
                                            }
                                        }
                                    };
                                let mut next: u32 = at + n;
                                if next < size {
                                    (
                                        _default::WithUpload(&bumped, &Arc::new(Upload::Sealing {
                                                    plaintext: plaintext.clone(),
                                                    offset: next,
                                                    eof: eof
                                                })),
                                        _default::FrameWrites(e.ciphertext(), &Arc::new(BodyEnd::More {})).concat(&seq![_default::SealAction(bumped.ctx(), &_default::Piece(&plaintext, next, _default::Min32(size - next, crate::EHBP::_default::RequestFrameBytes())))])
                                    )
                                } else {
                                    if eof {
                                        (
                                            _default::WithUpload(&bumped, &Arc::new(Upload::UpDone {})),
                                            _default::FrameWrites(e.ciphertext(), &Arc::new(BodyEnd::Done {}))
                                        )
                                    } else {
                                        (
                                            _default::WithUpload(&bumped, &Arc::new(Upload::UpReading {
                                                        empty: int!(0)
                                                    })),
                                            _default::FrameWrites(e.ciphertext(), &Arc::new(BodyEnd::More {})).concat(&seq![Arc::new(Action::Read {
                                                            stream: Arc::new(Stream::RequestBody {})
                                                        })])
                                        )
                                    }
                                }
                            }
                        }
                    }
                } else {
                    if matches!((&_source0).as_ref(), UpReading{ .. }) {
                        let mut ___mcc_h6: nat = _source0.empty().clone();
                        let mut empty: nat = ___mcc_h6.clone();
                        let mut _source1: Arc<Event> = e.clone();
                        if matches!((&_source1).as_ref(), Start{ .. }) {
                            let mut ___mcc_h8: Sequence<DafnyChar> = _source1.verb().clone();
                            let mut ___mcc_h9: Sequence<DafnyChar> = _source1.url().clone();
                            let mut ___mcc_h10: Sequence<DafnyChar> = _source1.scheme().clone();
                            let mut ___mcc_h11: Sequence<DafnyChar> = _source1.host().clone();
                            let mut ___mcc_h12: DafnyInt = _source1.port().clone();
                            let mut ___mcc_h13: bool = _source1.hasPort().clone();
                            let mut ___mcc_h14: bool = _source1.hasUserinfo().clone();
                            let mut ___mcc_h15: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source1.headers().clone();
                            let mut ___mcc_h16: bool = _source1.hasBody().clone();
                            _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                        } else {
                            if matches!((&_source1).as_ref(), DiscoverStart{ .. }) {
                                _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                            } else {
                                if matches!((&_source1).as_ref(), SessionBegun{ .. }) {
                                    let mut ___mcc_h26: u64 = _source1.generation().clone();
                                    _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                } else {
                                    if matches!((&_source1).as_ref(), RandomResult{ .. }) {
                                        let mut ___mcc_h28: Sequence<u8> = _source1.data().clone();
                                        _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                    } else {
                                        if matches!((&_source1).as_ref(), X25519Result{ .. }) {
                                            let mut ___mcc_h30: Sequence<u8> = _source1.point().clone();
                                            _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                        } else {
                                            if matches!((&_source1).as_ref(), HmacResult{ .. }) {
                                                let mut ___mcc_h32: Sequence<u8> = _source1.mac().clone();
                                                _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                            } else {
                                                if matches!((&_source1).as_ref(), AeadSealResult{ .. }) {
                                                    let mut ___mcc_h34: Sequence<u8> = _source1.ciphertext().clone();
                                                    _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                } else {
                                                    if matches!((&_source1).as_ref(), AeadOpenResult{ .. }) {
                                                        let mut ___mcc_h36: bool = _source1.ok().clone();
                                                        let mut ___mcc_h37: Sequence<u8> = _source1.plaintext().clone();
                                                        _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                    } else {
                                                        if matches!((&_source1).as_ref(), ResponseHead{ .. }) {
                                                            let mut ___mcc_h40: DafnyInt = _source1.status().clone();
                                                            let mut ___mcc_h41: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source1.headers().clone();
                                                            let mut ___mcc_h42: bool = _source1.redirected().clone();
                                                            _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                        } else {
                                                            if matches!((&_source1).as_ref(), crate::EHBPEvents::Event::Chunk{ .. }) {
                                                                let mut ___mcc_h46: Arc<Stream> = _source1.stream().clone();
                                                                let mut ___mcc_h47: Sequence<u8> = _source1.data().clone();
                                                                let mut ___mcc_h48: bool = _source1.eof().clone();
                                                                let mut _source2: Arc<Stream> = ___mcc_h46.clone();
                                                                if matches!((&_source2).as_ref(), RequestBody{ .. }) {
                                                                    let mut eof: bool = ___mcc_h48;
                                                                    let mut data: Sequence<u8> = ___mcc_h47.clone();
                                                                    if _default::MaxReadBytes() < data.cardinality() {
                                                                        _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                                    } else {
                                                                        if int!(0) < data.cardinality() {
                                                                            (
                                                                                _default::WithUpload(s, &Arc::new(Upload::Sealing {
                                                                                            plaintext: data.clone(),
                                                                                            offset: 0,
                                                                                            eof: eof
                                                                                        })),
                                                                                seq![_default::SealAction(s.ctx(), &_default::Piece(&data, 0, _default::Min32(truncate!(data.cardinality(), u32), crate::EHBP::_default::RequestFrameBytes())))]
                                                                            )
                                                                        } else {
                                                                            if eof {
                                                                                (
                                                                                    _default::WithUpload(s, &Arc::new(Upload::UpDone {})),
                                                                                    seq![Arc::new(Action::Write {
                                                                                                data: seq![] as Sequence<u8>,
                                                                                                end: Arc::new(BodyEnd::Done {})
                                                                                            })]
                                                                                )
                                                                            } else {
                                                                                if empty.clone() + int!(1) == crate::EHBP::_default::MaxEmptyReads() {
                                                                                    _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                                                } else {
                                                                                    (
                                                                                        _default::WithUpload(s, &Arc::new(Upload::UpReading {
                                                                                                    empty: empty.clone() + int!(1)
                                                                                                })),
                                                                                        seq![Arc::new(Action::Read {
                                                                                                    stream: Arc::new(Stream::RequestBody {})
                                                                                                })]
                                                                                    )
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                } else {
                                                                    _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                                }
                                                            } else {
                                                                if matches!((&_source1).as_ref(), StreamFailed{ .. }) {
                                                                    let mut ___mcc_h52: Arc<Stream> = _source1.stream().clone();
                                                                    let mut _source3: Arc<Stream> = ___mcc_h52.clone();
                                                                    if matches!((&_source3).as_ref(), RequestBody{ .. }) {
                                                                        _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                                    } else {
                                                                        _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                                    }
                                                                } else {
                                                                    if matches!((&_source1).as_ref(), CallerRead{ .. }) {
                                                                        _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                                    } else {
                                                                        _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        _default::AbortUpload(s, &Arc::new(Code::Transport {}))
                    }
                }
            }
        }
        /// ehbp_events.dfy(1074,3)
        pub fn StepResponse(s: &Arc<State>, rs: &Arc<Response>, e: &Arc<Event>) -> (Arc<State>, Sequence<Arc<Action>>) {
            let mut _source0: Arc<Response> = rs.clone();
            if matches!((&_source0).as_ref(), AwaitHead{ .. }) {
                let mut ___mcc_h0: bool = _source0.encrypted().clone();
                let mut encrypted: bool = ___mcc_h0;
                let mut _source1: Arc<Event> = e.clone();
                if matches!((&_source1).as_ref(), Start{ .. }) {
                    let mut ___mcc_h21: Sequence<DafnyChar> = _source1.verb().clone();
                    let mut ___mcc_h22: Sequence<DafnyChar> = _source1.url().clone();
                    let mut ___mcc_h23: Sequence<DafnyChar> = _source1.scheme().clone();
                    let mut ___mcc_h24: Sequence<DafnyChar> = _source1.host().clone();
                    let mut ___mcc_h25: DafnyInt = _source1.port().clone();
                    let mut ___mcc_h26: bool = _source1.hasPort().clone();
                    let mut ___mcc_h27: bool = _source1.hasUserinfo().clone();
                    let mut ___mcc_h28: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source1.headers().clone();
                    let mut ___mcc_h29: bool = _source1.hasBody().clone();
                    _default::Unexpected(s)
                } else {
                    if matches!((&_source1).as_ref(), DiscoverStart{ .. }) {
                        _default::Unexpected(s)
                    } else {
                        if matches!((&_source1).as_ref(), SessionBegun{ .. }) {
                            let mut ___mcc_h39: u64 = _source1.generation().clone();
                            _default::Unexpected(s)
                        } else {
                            if matches!((&_source1).as_ref(), RandomResult{ .. }) {
                                let mut ___mcc_h41: Sequence<u8> = _source1.data().clone();
                                _default::Unexpected(s)
                            } else {
                                if matches!((&_source1).as_ref(), X25519Result{ .. }) {
                                    let mut ___mcc_h43: Sequence<u8> = _source1.point().clone();
                                    _default::Unexpected(s)
                                } else {
                                    if matches!((&_source1).as_ref(), HmacResult{ .. }) {
                                        let mut ___mcc_h45: Sequence<u8> = _source1.mac().clone();
                                        _default::Unexpected(s)
                                    } else {
                                        if matches!((&_source1).as_ref(), AeadSealResult{ .. }) {
                                            let mut ___mcc_h47: Sequence<u8> = _source1.ciphertext().clone();
                                            _default::Unexpected(s)
                                        } else {
                                            if matches!((&_source1).as_ref(), AeadOpenResult{ .. }) {
                                                let mut ___mcc_h49: bool = _source1.ok().clone();
                                                let mut ___mcc_h50: Sequence<u8> = _source1.plaintext().clone();
                                                _default::Unexpected(s)
                                            } else {
                                                if matches!((&_source1).as_ref(), ResponseHead{ .. }) {
                                                    let mut ___mcc_h53: DafnyInt = _source1.status().clone();
                                                    let mut ___mcc_h54: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source1.headers().clone();
                                                    let mut ___mcc_h55: bool = _source1.redirected().clone();
                                                    let mut redirected: bool = ___mcc_h55;
                                                    let mut headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = ___mcc_h54.clone();
                                                    let mut status: DafnyInt = ___mcc_h53.clone();
                                                    if !redirected && (status.clone() < int!(100) || int!(599) < status.clone()) {
                                                        _default::Abort(s, true, &Arc::new(Code::Transport {}), &string_of("transport reported an impossible status"))
                                                    } else {
                                                        let mut _source2: Arc<Disposition> = crate::EHBP::_default::Classify(encrypted, &Arc::new(Head::Head {
                                                                        status: status.clone(),
                                                                        headers: headers.clone(),
                                                                        redirected: redirected
                                                                    }));
                                                        if matches!((&_source2).as_ref(), PassThrough{ .. }) {
                                                            _default::End(s, false, &Arc::new(Action::Passthrough {
                                                                        status: status.clone(),
                                                                        headers: headers.clone(),
                                                                        prefix: seq![] as Sequence<u8>
                                                                    }))
                                                        } else {
                                                            if matches!((&_source2).as_ref(), Decrypt{ .. }) {
                                                                let mut ___mcc_h67: Sequence<u8> = _source2.nonce().clone();
                                                                let mut ___mcc_h68: bool = _source2.requireFrame().clone();
                                                                let mut requireFrame: bool = ___mcc_h68;
                                                                let mut nonce: Sequence<u8> = ___mcc_h67.clone();
                                                                if !crate::EHBP::_default::ValidToken(s.token()) {
                                                                    _default::Abort(s, true, &Arc::new(Code::InvalidInput {}), &string_of("token fields must be 32 bytes"))
                                                                } else {
                                                                    if nonce.cardinality() != crate::EHBP::_default::ResponseNonceLength() {
                                                                        _default::Abort(s, true, &Arc::new(Code::InvalidInput {}), &string_of("response nonce must be 32 bytes"))
                                                                    } else {
                                                                        let mut job: Arc<Job> = _default::Extract(&s.token().requestEnc().concat(&nonce), s.token().exportedSecret());
                                                                        (
                                                                            _default::WithResponse(s, &Arc::new(Response::AwaitKeys {
                                                                                        status: status.clone(),
                                                                                        headers: headers.clone(),
                                                                                        requireFrame: requireFrame,
                                                                                        stage: int!(0),
                                                                                        job: job.clone(),
                                                                                        prk: seq![] as Sequence<u8>,
                                                                                        key: seq![] as Sequence<u8>
                                                                                    })),
                                                                            seq![_default::JobAction(&job)]
                                                                        )
                                                                    }
                                                                }
                                                            } else {
                                                                if matches!((&_source2).as_ref(), NeedProblemBody{ .. }) {
                                                                    (
                                                                        _default::WithResponse(s, &Arc::new(Response::ProblemReading {
                                                                                    status: status.clone(),
                                                                                    headers: headers.clone(),
                                                                                    data: seq![] as Sequence<u8>
                                                                                })),
                                                                        seq![Arc::new(Action::Read {
                                                                                    stream: Arc::new(Stream::ResponseBody {})
                                                                                })]
                                                                    )
                                                                } else {
                                                                    let mut ___mcc_h69: Arc<Code> = _source2.code().clone();
                                                                    let mut ___mcc_h70: Sequence<DafnyChar> = _source2.message().clone();
                                                                    let mut message: Sequence<DafnyChar> = ___mcc_h70.clone();
                                                                    let mut code: Arc<Code> = ___mcc_h69.clone();
                                                                    _default::Abort(s, true, &code, &message)
                                                                }
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    if matches!((&_source1).as_ref(), crate::EHBPEvents::Event::Chunk{ .. }) {
                                                        let mut ___mcc_h59: Arc<Stream> = _source1.stream().clone();
                                                        let mut ___mcc_h60: Sequence<u8> = _source1.data().clone();
                                                        let mut ___mcc_h61: bool = _source1.eof().clone();
                                                        _default::Unexpected(s)
                                                    } else {
                                                        if matches!((&_source1).as_ref(), StreamFailed{ .. }) {
                                                            let mut ___mcc_h65: Arc<Stream> = _source1.stream().clone();
                                                            let mut _source3: Arc<Stream> = ___mcc_h65.clone();
                                                            if matches!((&_source3).as_ref(), RequestBody{ .. }) {
                                                                _default::Unexpected(s)
                                                            } else {
                                                                _default::Abort(s, false, &Arc::new(Code::Transport {}), &string_of("failed to make request"))
                                                            }
                                                        } else {
                                                            if matches!((&_source1).as_ref(), CallerRead{ .. }) {
                                                                _default::Unexpected(s)
                                                            } else {
                                                                _default::Unexpected(s)
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                if matches!((&_source0).as_ref(), ProblemReading{ .. }) {
                    let mut ___mcc_h1: DafnyInt = _source0.status().clone();
                    let mut ___mcc_h2: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source0.headers().clone();
                    let mut ___mcc_h3: Sequence<u8> = _source0.data().clone();
                    let mut data: Sequence<u8> = ___mcc_h3.clone();
                    let mut headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = ___mcc_h2.clone();
                    let mut status: DafnyInt = ___mcc_h1.clone();
                    let mut _source4: Arc<Event> = e.clone();
                    if matches!((&_source4).as_ref(), Start{ .. }) {
                        let mut ___mcc_h71: Sequence<DafnyChar> = _source4.verb().clone();
                        let mut ___mcc_h72: Sequence<DafnyChar> = _source4.url().clone();
                        let mut ___mcc_h73: Sequence<DafnyChar> = _source4.scheme().clone();
                        let mut ___mcc_h74: Sequence<DafnyChar> = _source4.host().clone();
                        let mut ___mcc_h75: DafnyInt = _source4.port().clone();
                        let mut ___mcc_h76: bool = _source4.hasPort().clone();
                        let mut ___mcc_h77: bool = _source4.hasUserinfo().clone();
                        let mut ___mcc_h78: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source4.headers().clone();
                        let mut ___mcc_h79: bool = _source4.hasBody().clone();
                        _default::Unexpected(s)
                    } else {
                        if matches!((&_source4).as_ref(), DiscoverStart{ .. }) {
                            _default::Unexpected(s)
                        } else {
                            if matches!((&_source4).as_ref(), SessionBegun{ .. }) {
                                let mut ___mcc_h89: u64 = _source4.generation().clone();
                                _default::Unexpected(s)
                            } else {
                                if matches!((&_source4).as_ref(), RandomResult{ .. }) {
                                    let mut ___mcc_h91: Sequence<u8> = _source4.data().clone();
                                    _default::Unexpected(s)
                                } else {
                                    if matches!((&_source4).as_ref(), X25519Result{ .. }) {
                                        let mut ___mcc_h93: Sequence<u8> = _source4.point().clone();
                                        _default::Unexpected(s)
                                    } else {
                                        if matches!((&_source4).as_ref(), HmacResult{ .. }) {
                                            let mut ___mcc_h95: Sequence<u8> = _source4.mac().clone();
                                            _default::Unexpected(s)
                                        } else {
                                            if matches!((&_source4).as_ref(), AeadSealResult{ .. }) {
                                                let mut ___mcc_h97: Sequence<u8> = _source4.ciphertext().clone();
                                                _default::Unexpected(s)
                                            } else {
                                                if matches!((&_source4).as_ref(), AeadOpenResult{ .. }) {
                                                    let mut ___mcc_h99: bool = _source4.ok().clone();
                                                    let mut ___mcc_h100: Sequence<u8> = _source4.plaintext().clone();
                                                    _default::Unexpected(s)
                                                } else {
                                                    if matches!((&_source4).as_ref(), ResponseHead{ .. }) {
                                                        let mut ___mcc_h103: DafnyInt = _source4.status().clone();
                                                        let mut ___mcc_h104: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source4.headers().clone();
                                                        let mut ___mcc_h105: bool = _source4.redirected().clone();
                                                        _default::Unexpected(s)
                                                    } else {
                                                        if matches!((&_source4).as_ref(), crate::EHBPEvents::Event::Chunk{ .. }) {
                                                            let mut ___mcc_h109: Arc<Stream> = _source4.stream().clone();
                                                            let mut ___mcc_h110: Sequence<u8> = _source4.data().clone();
                                                            let mut ___mcc_h111: bool = _source4.eof().clone();
                                                            let mut _source5: Arc<Stream> = ___mcc_h109.clone();
                                                            if matches!((&_source5).as_ref(), RequestBody{ .. }) {
                                                                _default::Unexpected(s)
                                                            } else {
                                                                let mut eof: bool = ___mcc_h111;
                                                                let mut chunk: Sequence<u8> = ___mcc_h110.clone();
                                                                let mut grown: Sequence<u8> = data.concat(&chunk);
                                                                if grown.cardinality() <= crate::EHBP::_default::MaxProblemBytes() + int!(1) && !eof {
                                                                    (
                                                                        _default::WithResponse(s, &Arc::new(Response::ProblemReading {
                                                                                    status: status.clone(),
                                                                                    headers: headers.clone(),
                                                                                    data: grown.clone()
                                                                                })),
                                                                        seq![Arc::new(Action::Read {
                                                                                    stream: Arc::new(Stream::ResponseBody {})
                                                                                })]
                                                                    )
                                                                } else {
                                                                    let mut oversized: bool = crate::EHBP::_default::MaxProblemBytes() < grown.cardinality();
                                                                    let mut __let_tmp_rhs0: (bool, Arc<Option<Sequence<DafnyChar>>>, Arc<Option<Sequence<DafnyChar>>>) = if oversized {
                                                                            (
                                                                                false,
                                                                                Arc::new(Option::None::<Sequence<DafnyChar>> {}),
                                                                                Arc::new(Option::None::<Sequence<DafnyChar>> {})
                                                                            )
                                                                        } else {
                                                                            _default::ParseProblem(&grown)
                                                                        };
                                                                    let mut isObject: bool = __let_tmp_rhs0.0.clone();
                                                                    let mut typeValue: Arc<Option<Sequence<DafnyChar>>> = __let_tmp_rhs0.1.clone();
                                                                    let mut title: Arc<Option<Sequence<DafnyChar>>> = __let_tmp_rhs0.2.clone();
                                                                    let mut _source6: Arc<Disposition> = crate::EHBP::_default::ClassifyProblem(oversized, isObject, &typeValue, &title);
                                                                    if matches!((&_source6).as_ref(), PassThrough{ .. }) {
                                                                        _default::End(s, false, &Arc::new(Action::Passthrough {
                                                                                    status: status.clone(),
                                                                                    headers: headers.clone(),
                                                                                    prefix: grown.clone()
                                                                                }))
                                                                    } else {
                                                                        if matches!((&_source6).as_ref(), Decrypt{ .. }) {
                                                                            let mut ___mcc_h117: Sequence<u8> = _source6.nonce().clone();
                                                                            let mut ___mcc_h118: bool = _source6.requireFrame().clone();
                                                                            _default::Abort(s, true, &Arc::new(Code::Transport {}), &string_of("unreachable"))
                                                                        } else {
                                                                            if matches!((&_source6).as_ref(), NeedProblemBody{ .. }) {
                                                                                _default::Abort(s, true, &Arc::new(Code::Transport {}), &string_of("unreachable"))
                                                                            } else {
                                                                                let mut ___mcc_h121: Arc<Code> = _source6.code().clone();
                                                                                let mut ___mcc_h122: Sequence<DafnyChar> = _source6.message().clone();
                                                                                let mut message: Sequence<DafnyChar> = ___mcc_h122.clone();
                                                                                let mut code: Arc<Code> = ___mcc_h121.clone();
                                                                                _default::Abort(s, true, &code, &message)
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            if matches!((&_source4).as_ref(), StreamFailed{ .. }) {
                                                                let mut ___mcc_h115: Arc<Stream> = _source4.stream().clone();
                                                                let mut _source7: Arc<Stream> = ___mcc_h115.clone();
                                                                if matches!((&_source7).as_ref(), RequestBody{ .. }) {
                                                                    _default::Unexpected(s)
                                                                } else {
                                                                    _default::Abort(s, true, &Arc::new(Code::Transport {}), &string_of("failed to read problem response"))
                                                                }
                                                            } else {
                                                                if matches!((&_source4).as_ref(), CallerRead{ .. }) {
                                                                    _default::Unexpected(s)
                                                                } else {
                                                                    _default::Unexpected(s)
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    if matches!((&_source0).as_ref(), AwaitKeys{ .. }) {
                        let mut ___mcc_h4: DafnyInt = _source0.status().clone();
                        let mut ___mcc_h5: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source0.headers().clone();
                        let mut ___mcc_h6: bool = _source0.requireFrame().clone();
                        let mut ___mcc_h7: nat = _source0.stage().clone();
                        let mut ___mcc_h8: Arc<Job> = _source0.job().clone();
                        let mut ___mcc_h9: Sequence<u8> = _source0.prk().clone();
                        let mut ___mcc_h10: Sequence<u8> = _source0.key().clone();
                        let mut key: Sequence<u8> = ___mcc_h10.clone();
                        let mut prk: Sequence<u8> = ___mcc_h9.clone();
                        let mut job: Arc<Job> = ___mcc_h8.clone();
                        let mut stage: nat = ___mcc_h7.clone();
                        let mut requireFrame: bool = ___mcc_h6;
                        let mut headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = ___mcc_h5.clone();
                        let mut status: DafnyInt = ___mcc_h4.clone();
                        let mut _source8: Arc<JobOut> = _default::JobStep(&job, e);
                        if matches!((&_source8).as_ref(), Pending{ .. }) {
                            let mut ___mcc_h125: Arc<Job> = _source8.job().clone();
                            let mut ___mcc_h126: Arc<Action> = _source8.action().clone();
                            let mut a: Arc<Action> = ___mcc_h126.clone();
                            let mut next: Arc<Job> = ___mcc_h125.clone();
                            (
                                _default::WithResponse(s, &Arc::new(Response::AwaitKeys {
                                            status: status.clone(),
                                            headers: headers.clone(),
                                            requireFrame: requireFrame,
                                            stage: stage.clone(),
                                            job: next.clone(),
                                            prk: prk.clone(),
                                            key: key.clone()
                                        })),
                                seq![a.clone()]
                            )
                        } else {
                            if matches!((&_source8).as_ref(), Output{ .. }) {
                                let mut ___mcc_h127: Sequence<u8> = _source8.data().clone();
                                let mut out: Sequence<u8> = ___mcc_h127.clone();
                                if stage.clone() == int!(0) {
                                    let mut next: Arc<Job> = _default::Expand(&out, &crate::EHBP::_default::Ascii(&crate::EHBP::_default::ResponseKeyLabel()), &crate::EHBP::_default::KeyLength());
                                    (
                                        _default::WithResponse(s, &Arc::new(Response::AwaitKeys {
                                                    status: status.clone(),
                                                    headers: headers.clone(),
                                                    requireFrame: requireFrame,
                                                    stage: int!(1),
                                                    job: next.clone(),
                                                    prk: out.clone(),
                                                    key: seq![] as Sequence<u8>
                                                })),
                                        seq![_default::JobAction(&next)]
                                    )
                                } else {
                                    if stage.clone() == int!(1) {
                                        let mut next: Arc<Job> = _default::Expand(&prk, &crate::EHBP::_default::Ascii(&crate::EHBP::_default::ResponseNonceLabel()), &crate::EHBP::_default::NonceLength());
                                        (
                                            _default::WithResponse(s, &Arc::new(Response::AwaitKeys {
                                                        status: status.clone(),
                                                        headers: headers.clone(),
                                                        requireFrame: requireFrame,
                                                        stage: int!(2),
                                                        job: next.clone(),
                                                        prk: prk.clone(),
                                                        key: out.clone()
                                                    })),
                                            seq![_default::JobAction(&next)]
                                        )
                                    } else {
                                        if key.cardinality() == crate::EHBP::_default::KeyLength() && out.cardinality() == crate::EHBP::_default::NonceLength() {
                                            let mut k: Key = key.clone();
                                            let mut n: NonceBase = out.clone();
                                            (
                                                _default::WithResponse(s, &Arc::new(Response::Body {
                                                            keys: Arc::new(Ctx::Ctx {
                                                                        key: k.clone(),
                                                                        baseNonce: n.clone(),
                                                                        exporterSecret: seq![] as Sequence<u8>,
                                                                        seqNo: 0
                                                                    }),
                                                            dec: Arc::new(Dec::Dec {
                                                                        pending: seq![] as Sequence<u8>,
                                                                        next: 0,
                                                                        authenticated: false,
                                                                        requireFrame: requireFrame
                                                                    }),
                                                            done: false
                                                        })),
                                                seq![Arc::new(Action::Done {
                                                            status: status.clone(),
                                                            headers: crate::EHBP::_default::DropFraming(&headers)
                                                        })]
                                            )
                                        } else {
                                            _default::Abort(s, true, &Arc::new(Code::HpkeSetupFailed {}), &string_of("HKDF expand returned the wrong length"))
                                        }
                                    }
                                }
                            } else {
                                let mut ___mcc_h128: Arc<Code> = _source8.code().clone();
                                let mut ___mcc_h129: Sequence<DafnyChar> = _source8.message().clone();
                                let mut message: Sequence<DafnyChar> = ___mcc_h129.clone();
                                let mut code: Arc<Code> = ___mcc_h128.clone();
                                _default::Abort(s, true, &code, &message)
                            }
                        }
                    } else {
                        if matches!((&_source0).as_ref(), Body{ .. }) {
                            let mut ___mcc_h11: Arc<Ctx> = _source0.keys().clone();
                            let mut ___mcc_h12: Arc<Dec> = _source0.dec().clone();
                            let mut ___mcc_h13: bool = _source0.done().clone();
                            let mut done: bool = ___mcc_h13;
                            let mut dec: Arc<Dec> = ___mcc_h12.clone();
                            let mut keys: Arc<Ctx> = ___mcc_h11.clone();
                            if !matches!(e.as_ref(), CallerRead{ .. }) {
                                _default::Unexpected(s)
                            } else {
                                if done {
                                    _default::End(s, false, &Arc::new(Action::Finished {}))
                                } else {
                                    (
                                        _default::WithResponse(s, &Arc::new(Response::BodyReading {
                                                    keys: keys.clone(),
                                                    dec: dec.clone()
                                                })),
                                        seq![Arc::new(Action::Read {
                                                    stream: Arc::new(Stream::ResponseBody {})
                                                })]
                                    )
                                }
                            }
                        } else {
                            if matches!((&_source0).as_ref(), BodyReading{ .. }) {
                                let mut ___mcc_h14: Arc<Ctx> = _source0.keys().clone();
                                let mut ___mcc_h15: Arc<Dec> = _source0.dec().clone();
                                let mut dec: Arc<Dec> = ___mcc_h15.clone();
                                let mut keys: Arc<Ctx> = ___mcc_h14.clone();
                                let mut _source9: Arc<Event> = e.clone();
                                if matches!((&_source9).as_ref(), Start{ .. }) {
                                    let mut ___mcc_h130: Sequence<DafnyChar> = _source9.verb().clone();
                                    let mut ___mcc_h131: Sequence<DafnyChar> = _source9.url().clone();
                                    let mut ___mcc_h132: Sequence<DafnyChar> = _source9.scheme().clone();
                                    let mut ___mcc_h133: Sequence<DafnyChar> = _source9.host().clone();
                                    let mut ___mcc_h134: DafnyInt = _source9.port().clone();
                                    let mut ___mcc_h135: bool = _source9.hasPort().clone();
                                    let mut ___mcc_h136: bool = _source9.hasUserinfo().clone();
                                    let mut ___mcc_h137: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source9.headers().clone();
                                    let mut ___mcc_h138: bool = _source9.hasBody().clone();
                                    _default::Unexpected(s)
                                } else {
                                    if matches!((&_source9).as_ref(), DiscoverStart{ .. }) {
                                        _default::Unexpected(s)
                                    } else {
                                        if matches!((&_source9).as_ref(), SessionBegun{ .. }) {
                                            let mut ___mcc_h148: u64 = _source9.generation().clone();
                                            _default::Unexpected(s)
                                        } else {
                                            if matches!((&_source9).as_ref(), RandomResult{ .. }) {
                                                let mut ___mcc_h150: Sequence<u8> = _source9.data().clone();
                                                _default::Unexpected(s)
                                            } else {
                                                if matches!((&_source9).as_ref(), X25519Result{ .. }) {
                                                    let mut ___mcc_h152: Sequence<u8> = _source9.point().clone();
                                                    _default::Unexpected(s)
                                                } else {
                                                    if matches!((&_source9).as_ref(), HmacResult{ .. }) {
                                                        let mut ___mcc_h154: Sequence<u8> = _source9.mac().clone();
                                                        _default::Unexpected(s)
                                                    } else {
                                                        if matches!((&_source9).as_ref(), AeadSealResult{ .. }) {
                                                            let mut ___mcc_h156: Sequence<u8> = _source9.ciphertext().clone();
                                                            _default::Unexpected(s)
                                                        } else {
                                                            if matches!((&_source9).as_ref(), AeadOpenResult{ .. }) {
                                                                let mut ___mcc_h158: bool = _source9.ok().clone();
                                                                let mut ___mcc_h159: Sequence<u8> = _source9.plaintext().clone();
                                                                _default::Unexpected(s)
                                                            } else {
                                                                if matches!((&_source9).as_ref(), ResponseHead{ .. }) {
                                                                    let mut ___mcc_h162: DafnyInt = _source9.status().clone();
                                                                    let mut ___mcc_h163: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> = _source9.headers().clone();
                                                                    let mut ___mcc_h164: bool = _source9.redirected().clone();
                                                                    _default::Unexpected(s)
                                                                } else {
                                                                    if matches!((&_source9).as_ref(), crate::EHBPEvents::Event::Chunk{ .. }) {
                                                                        let mut ___mcc_h168: Arc<Stream> = _source9.stream().clone();
                                                                        let mut ___mcc_h169: Sequence<u8> = _source9.data().clone();
                                                                        let mut ___mcc_h170: bool = _source9.eof().clone();
                                                                        let mut _source10: Arc<Stream> = ___mcc_h168.clone();
                                                                        if matches!((&_source10).as_ref(), RequestBody{ .. }) {
                                                                            _default::Unexpected(s)
                                                                        } else {
                                                                            let mut eof: bool = ___mcc_h170;
                                                                            let mut data: Sequence<u8> = ___mcc_h169.clone();
                                                                            let mut __let_tmp_rhs1: (Sequence<Arc<Framed>>, Arc<Dec>, Arc<Option<Arc<Code>>>) = _default::Push(&dec, &data);
                                                                            let mut frames: Sequence<Arc<Framed>> = __let_tmp_rhs1.0.clone();
                                                                            let mut next: Arc<Dec> = __let_tmp_rhs1.1.clone();
                                                                            let mut err: Arc<Option<Arc<Code>>> = __let_tmp_rhs1.2.clone();
                                                                            if matches!((&err).as_ref(), Some{ .. }) {
                                                                                _default::Abort(s, false, err.value(), &string_of(""))
                                                                            } else {
                                                                                _default::OpenNext(s, &keys, &next, &frames, &(seq![] as Sequence<Sequence<u8>>), eof)
                                                                            }
                                                                        }
                                                                    } else {
                                                                        if matches!((&_source9).as_ref(), StreamFailed{ .. }) {
                                                                            let mut ___mcc_h174: Arc<Stream> = _source9.stream().clone();
                                                                            let mut _source11: Arc<Stream> = ___mcc_h174.clone();
                                                                            if matches!((&_source11).as_ref(), RequestBody{ .. }) {
                                                                                _default::Unexpected(s)
                                                                            } else {
                                                                                _default::Abort(s, false, &Arc::new(Code::FramingTruncated {}), &string_of("response body failed"))
                                                                            }
                                                                        } else {
                                                                            if matches!((&_source9).as_ref(), CallerRead{ .. }) {
                                                                                _default::Unexpected(s)
                                                                            } else {
                                                                                _default::Unexpected(s)
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                if matches!((&_source0).as_ref(), Opening{ .. }) {
                                    let mut ___mcc_h16: Arc<Ctx> = _source0.keys().clone();
                                    let mut ___mcc_h17: Arc<Dec> = _source0.dec().clone();
                                    let mut ___mcc_h18: Sequence<Arc<Framed>> = _source0.frames().clone();
                                    let mut ___mcc_h19: Sequence<Sequence<u8>> = _source0.chunks().clone();
                                    let mut ___mcc_h20: bool = _source0.eof().clone();
                                    let mut eof: bool = ___mcc_h20;
                                    let mut chunks: Sequence<Sequence<u8>> = ___mcc_h19.clone();
                                    let mut frames: Sequence<Arc<Framed>> = ___mcc_h18.clone();
                                    let mut dec: Arc<Dec> = ___mcc_h17.clone();
                                    let mut keys: Arc<Ctx> = ___mcc_h16.clone();
                                    if !matches!(e.as_ref(), AeadOpenResult{ .. }) || frames.cardinality() == int!(0) {
                                        _default::Unexpected(s)
                                    } else {
                                        if !e.ok().clone() {
                                            _default::Abort(s, false, &Arc::new(Code::AeadDecryptFailed {}), &string_of("frame failed to authenticate"))
                                        } else {
                                            if e.plaintext().cardinality() + crate::EHBP::_default::AeadTagLength() != frames.get(&int!(0)).ciphertext().cardinality() {
                                                _default::Abort(s, false, &Arc::new(Code::AeadDecryptFailed {}), &string_of("AEAD returned the wrong length"))
                                            } else {
                                                _default::OpenNext(s, &keys, &dec, &frames.drop(&int!(1)), &(if int!(0) < e.plaintext().cardinality() {
                                                        chunks.concat(&seq![e.plaintext().clone()])
                                                    } else {
                                                        chunks.clone()
                                                    }), eof)
                                            }
                                        }
                                    }
                                } else {
                                    _default::Unexpected(s)
                                }
                            }
                        }
                    }
                }
            }
        }
        /// ehbp_events.dfy(1155,3)
        pub fn Emits(chunks: &Sequence<Sequence<u8>>) -> Sequence<Arc<Action>> {
            {
                let _initializer = {
                        let chunks: Sequence<Sequence<u8>> = chunks.clone();
                        {
                            let mut chunks = chunks.clone();
                            Arc::new(move |i: &DafnyInt| -> Arc<Action>{
            Arc::new(Action::EmitPlaintext {
                    data: chunks.get(i)
                })
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                        }
                    };
                integer_range(Zero::zero(), chunks.cardinality()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
            }
        }
        /// ehbp_events.dfy(1164,3)
        pub fn OpenNext(s: &Arc<State>, keys: &Arc<Ctx>, dec: &Arc<Dec>, frames: &Sequence<Arc<Framed>>, chunks: &Sequence<Sequence<u8>>, eof: bool) -> (Arc<State>, Sequence<Arc<Action>>) {
            if int!(0) < frames.cardinality() {
                if frames.get(&int!(0)).ciphertext().cardinality() < crate::EHBP::_default::AeadTagLength() {
                    _default::Abort(s, false, &Arc::new(Code::AeadDecryptFailed {}), &string_of("frame shorter than the AEAD tag"))
                } else {
                    (
                        _default::WithResponse(s, &Arc::new(Response::Opening {
                                    keys: keys.clone(),
                                    dec: dec.clone(),
                                    frames: frames.clone(),
                                    chunks: chunks.clone(),
                                    eof: eof
                                })),
                        seq![Arc::new(Action::AeadOpen {
                                    key: keys.key().clone(),
                                    nonce: crate::EHBP::_default::ComputeNonce(keys.baseNonce(), frames.get(&int!(0)).seqNo().clone()),
                                    ciphertext: frames.get(&int!(0)).ciphertext().clone()
                                })]
                    )
                }
            } else {
                if eof {
                    let mut _source0: Arc<Option<Arc<Code>>> = _default::Finish(dec);
                    if matches!((&_source0).as_ref(), None{ .. }) {
                        if int!(0) < chunks.cardinality() {
                            (
                                _default::WithResponse(s, &Arc::new(Response::Body {
                                            keys: keys.clone(),
                                            dec: dec.clone(),
                                            done: true
                                        })),
                                _default::Emits(chunks)
                            )
                        } else {
                            _default::End(s, false, &Arc::new(Action::Finished {}))
                        }
                    } else {
                        let mut ___mcc_h0: Arc<Code> = _source0.value().clone();
                        let mut code: Arc<Code> = ___mcc_h0.clone();
                        _default::Abort(s, false, &code, &string_of(""))
                    }
                } else {
                    if int!(0) < chunks.cardinality() {
                        (
                            _default::WithResponse(s, &Arc::new(Response::Body {
                                        keys: keys.clone(),
                                        dec: dec.clone(),
                                        done: false
                                    })),
                            _default::Emits(chunks)
                        )
                    } else {
                        (
                            _default::WithResponse(s, &Arc::new(Response::BodyReading {
                                        keys: keys.clone(),
                                        dec: dec.clone()
                                    })),
                            seq![Arc::new(Action::Read {
                                        stream: Arc::new(Stream::ResponseBody {})
                                    })]
                        )
                    }
                }
            }
        }
        /// ehbp_events.dfy(1188,3)
        pub fn Hex(s: &Sequence<DafnyChar>) -> Sequence<u8> {
            let mut _source0: Arc<Option<Sequence<u8>>> = crate::EHBP::_default::DecodeHex(s);
            if matches!((&_source0).as_ref(), None{ .. }) {
                seq![] as Sequence<u8>
            } else {
                let mut ___mcc_h0: Sequence<u8> = _source0.value().clone();
                let mut b: Sequence<u8> = ___mcc_h0.clone();
                b.clone()
            }
        }
        /// ehbp_events.dfy(1213,3)
        pub fn SelfCheckJudge(results: &Sequence<Arc<Event>>) -> Sequence<Sequence<DafnyChar>> {
            if results.cardinality() != _default::SelfCheckActions().cardinality() {
                seq![string_of("self-check: wrong number of results")]
            } else {
                (if results.get(&int!(0)) != Arc::new(Event::HmacResult {
                            mac: _default::HmacTag()
                        }) {
                    seq![string_of("HmacSha256: RFC 4231 test case 1")]
                } else {
                    seq![] as Sequence<Sequence<DafnyChar>>
                }).concat(&(if results.get(&int!(1)) != Arc::new(Event::X25519Result {
                                point: _default::AlicePk()
                            }) {
                        seq![string_of("X25519: RFC 7748 base point")]
                    } else {
                        seq![] as Sequence<Sequence<DafnyChar>>
                    })).concat(&(if results.get(&int!(2)) != Arc::new(Event::X25519Result {
                                point: _default::AliceBobShared()
                            }) {
                        seq![string_of("X25519: RFC 7748 shared secret")]
                    } else {
                        seq![] as Sequence<Sequence<DafnyChar>>
                    })).concat(&(if results.get(&int!(3)) != Arc::new(Event::AeadSealResult {
                                ciphertext: _default::GcmCt()
                            }) {
                        seq![string_of("AeadSeal: known answer")]
                    } else {
                        seq![] as Sequence<Sequence<DafnyChar>>
                    })).concat(&(if results.get(&int!(4)) != Arc::new(Event::AeadOpenResult {
                                ok: true,
                                plaintext: crate::EHBP::_default::Ascii(&string_of("ehbp"))
                            }) {
                        seq![string_of("AeadOpen: known answer")]
                    } else {
                        seq![] as Sequence<Sequence<DafnyChar>>
                    })).concat(&(if !matches!((&results.get(&int!(5))).as_ref(), AeadOpenResult{ .. }) || results.get(&int!(5)).ok().clone() {
                        seq![string_of("AeadOpen: accepted a tampered tag")]
                    } else {
                        seq![] as Sequence<Sequence<DafnyChar>>
                    })).concat(&(if !matches!((&results.get(&int!(6))).as_ref(), AeadOpenResult{ .. }) || results.get(&int!(6)).ok().clone() {
                        seq![string_of("AeadOpen: accepted a frame shorter than the tag")]
                    } else {
                        seq![] as Sequence<Sequence<DafnyChar>>
                    })).concat(&(if !matches!((&results.get(&int!(7))).as_ref(), RandomResult{ .. }) || !matches!((&results.get(&int!(8))).as_ref(), RandomResult{ .. }) || results.get(&int!(7)).data().cardinality() != int!(32) || results.get(&int!(8)).data().cardinality() != int!(32) {
                        seq![string_of("RandomBytes: length")]
                    } else {
                        seq![] as Sequence<Sequence<DafnyChar>>
                    })).concat(&(if results.get(&int!(7)) == results.get(&int!(8)) {
                        seq![string_of("RandomBytes: repeated output")]
                    } else {
                        seq![] as Sequence<Sequence<DafnyChar>>
                    }))
            }
        }
        /// ehbp_events.dfy(1244,3)
        pub fn Rotr(x: u32, n: &nat) -> u32 {
            x >> truncate!(n.clone(), u8) | x << truncate!(int!(32) - n.clone(), u8)
        }
        /// ehbp_events.dfy(1245,3)
        pub fn Word(b: &Sequence<u8>, i: &nat) -> u32 {
            truncate!(int!(crate::EHBP::_default::U32(b, i)), u32)
        }
        /// ehbp_events.dfy(1246,3)
        pub fn WordBytes(w: u32) -> Sequence<u8> {
            crate::EHBP::_default::BE32(truncate!(int!(w), u32))
        }
        /// ehbp_events.dfy(1248,3)
        pub fn MessageSchedule(w: &Sequence<u32>) -> Sequence<u32> {
            let mut _r0 = w.clone();
            'TAIL_CALL_START: loop {
                let w = _r0;
                if w.cardinality() == int!(64) {
                    return w.clone();
                } else {
                    let mut s0: u32 = _default::Rotr(w.get(&(w.cardinality() - int!(15))), &int!(7)) ^ _default::Rotr(w.get(&(w.cardinality() - int!(15))), &int!(18)) ^ w.get(&(w.cardinality() - int!(15))) >> 3;
                    let mut s1: u32 = _default::Rotr(w.get(&(w.cardinality() - int!(2))), &int!(17)) ^ _default::Rotr(w.get(&(w.cardinality() - int!(2))), &int!(19)) ^ w.get(&(w.cardinality() - int!(2))) >> 10;
                    let mut _in0: Sequence<u32> = w.concat(&seq![w.get(&(w.cardinality() - int!(16))).wrapping_add(s0).wrapping_add(w.get(&(w.cardinality() - int!(7)))).wrapping_add(s1)]);
                    _r0 = _in0.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp_events.dfy(1260,3)
        pub fn Rounds(w: &Sequence<u32>, t: &nat, v: &Sequence<u32>) -> Sequence<u32> {
            let mut _r0 = w.clone();
            let mut _r1 = t.clone();
            let mut _r2 = v.clone();
            'TAIL_CALL_START: loop {
                let w = _r0;
                let t = _r1;
                let v = _r2;
                if t.clone() == int!(64) {
                    return v.clone();
                } else {
                    let mut a: u32 = v.get(&int!(0));
                    let mut b: u32 = v.get(&int!(1));
                    let mut c: u32 = v.get(&int!(2));
                    let mut d: u32 = v.get(&int!(3));
                    let mut e: u32 = v.get(&int!(4));
                    let mut f: u32 = v.get(&int!(5));
                    let mut g: u32 = v.get(&int!(6));
                    let mut h: u32 = v.get(&int!(7));
                    let mut t1: u32 = h.wrapping_add(_default::Rotr(e, &int!(6)) ^ _default::Rotr(e, &int!(11)) ^ _default::Rotr(e, &int!(25))).wrapping_add(e & f ^ !e & g).wrapping_add(_default::K256().get(&t)).wrapping_add(w.get(&t));
                    let mut t2: u32 = (_default::Rotr(a, &int!(2)) ^ _default::Rotr(a, &int!(13)) ^ _default::Rotr(a, &int!(22))).wrapping_add(a & b ^ a & c ^ b & c);
                    let mut _in0: Sequence<u32> = w.clone();
                    let mut _in1: DafnyInt = t.clone() + int!(1);
                    let mut _in2: Sequence<u32> = seq![t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
                    _r0 = _in0.clone();
                    _r1 = _in1.clone();
                    _r2 = _in2.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp_events.dfy(1273,3)
        pub fn Blocks(p: &Sequence<u8>, i: &nat, h: &Sequence<u32>) -> Sequence<u32> {
            let mut _r0 = p.clone();
            let mut _r1 = i.clone();
            let mut _r2 = h.clone();
            'TAIL_CALL_START: loop {
                let p = _r0;
                let i = _r1;
                let h = _r2;
                if i.clone() == p.cardinality() {
                    return h.clone();
                } else {
                    let mut block: Sequence<u8> = p.slice(&i, &(i.clone() + int!(64)));
                    let mut w: Sequence<u32> = _default::MessageSchedule(&({
                                let _initializer = {
                                        let block: Sequence<u8> = block.clone();
                                        {
                                            let mut block = block.clone();
                                            Arc::new(move |j: &DafnyInt| -> u32{
            _default::Word(&block, &(int!(4) * j.clone()))
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                                        }
                                    };
                                integer_range(Zero::zero(), int!(16)).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
                            }));
                    let mut v: Sequence<u32> = _default::Rounds(&w, &int!(0), &h);
                    let mut _in0: Sequence<u8> = p.clone();
                    let mut _in1: DafnyInt = i.clone() + int!(64);
                    let mut _in2: Sequence<u32> = {
                            let _initializer = {
                                    let h: Sequence<u32> = h.clone();
                                    let v: Sequence<u32> = v.clone();
                                    {
                                        let mut h = h.clone();
                                        let mut v = v.clone();
                                        Arc::new(move |j: &DafnyInt| -> u32{
            h.get(j).wrapping_add(v.get(j))
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                                    }
                                };
                            integer_range(Zero::zero(), int!(8)).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
                        };
                    _r0 = _in0.clone();
                    _r1 = _in1.clone();
                    _r2 = _in2.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp_events.dfy(1287,3)
        pub fn Sha256(msg: &Sequence<u8>) -> Sequence<u8> {
            let mut pad: DafnyInt = euclidian_modulo(int!(119) - euclidian_modulo(msg.cardinality(), int!(64)), int!(64));
            let mut bits: DafnyInt = msg.cardinality() * int!(8);
            let mut padded: Sequence<u8> = msg.concat(&seq![128]).concat(&({
                        let _initializer = {
                                Arc::new(move |i: &DafnyInt| -> u8{
            0
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                            };
                        integer_range(Zero::zero(), pad.clone()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
                    })).concat(&crate::EHBP::_default::BE32(truncate!(euclidian_modulo(euclidian_division(bits.clone(), int!(b"4294967296")), int!(b"4294967296")), u32))).concat(&crate::EHBP::_default::BE32(truncate!(euclidian_modulo(bits.clone(), int!(b"4294967296")), u32)));
            let mut h: Sequence<u32> = _default::Blocks(&padded, &int!(0), &_default::H256());
            _default::WordBytes(h.get(&int!(0))).concat(&_default::WordBytes(h.get(&int!(1)))).concat(&_default::WordBytes(h.get(&int!(2)))).concat(&_default::WordBytes(h.get(&int!(3)))).concat(&_default::WordBytes(h.get(&int!(4)))).concat(&_default::WordBytes(h.get(&int!(5)))).concat(&_default::WordBytes(h.get(&int!(6)))).concat(&_default::WordBytes(h.get(&int!(7))))
        }
        /// ehbp_events.dfy(1298,3)
        pub fn XorPad(b: &Sequence<u8>, p: u8) -> Sequence<u8> {
            {
                let _initializer = {
                        let b: Sequence<u8> = b.clone();
                        let p: u8 = p;
                        {
                            let mut b = b.clone();
                            let mut p = p.clone();
                            Arc::new(move |i: &DafnyInt| -> u8{
            (b.get(i) as u8 ^ p as u8) as u8
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                        }
                    };
                integer_range(Zero::zero(), b.cardinality()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
            }
        }
        /// ehbp_events.dfy(1300,3)
        pub fn HmacRef(key: &Sequence<u8>, data: &Sequence<u8>) -> Sequence<u8> {
            let mut k: Sequence<u8> = if int!(64) < key.cardinality() {
                    _default::Sha256(key)
                } else {
                    key.clone()
                };
            let mut kp: Sequence<u8> = k.concat(&({
                        let _initializer = {
                                Arc::new(move |i: &DafnyInt| -> u8{
            0
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                            };
                        integer_range(Zero::zero(), int!(64) - k.cardinality()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
                    }));
            _default::Sha256(&_default::XorPad(&kp, 92).concat(&_default::Sha256(&_default::XorPad(&kp, 54).concat(data))))
        }
        /// ehbp_events.dfy(1309,3)
        pub fn Pow2(n: &nat) -> DafnyInt {
            let mut _accumulator: DafnyInt = int!(1);
            let mut _r0 = n.clone();
            'TAIL_CALL_START: loop {
                let n = _r0;
                if n.clone() == int!(0) {
                    return int!(1) * _accumulator.clone();
                } else {
                    _accumulator = _accumulator.clone() * int!(2);
                    let mut _in0: DafnyInt = n.clone() - int!(1);
                    _r0 = _in0.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp_events.dfy(1315,3)
        pub fn PowMod(b: &DafnyInt, e: &nat) -> DafnyInt {
            if e.clone() == int!(0) {
                euclidian_modulo(int!(1), _default::P25519())
            } else {
                if euclidian_modulo(e.clone(), int!(2)) == int!(0) {
                    let mut h: DafnyInt = _default::PowMod(b, &euclidian_division(e.clone(), int!(2)));
                    euclidian_modulo(h.clone() * h.clone(), _default::P25519())
                } else {
                    euclidian_modulo(b.clone() * _default::PowMod(b, &(e.clone() - int!(1))), _default::P25519())
                }
            }
        }
        /// ehbp_events.dfy(1323,3)
        pub fn LE(b: &Sequence<u8>) -> DafnyInt {
            if b.cardinality() == int!(0) {
                int!(0)
            } else {
                int!(b.get(&int!(0))) + int!(256) * _default::LE(&b.drop(&int!(1)))
            }
        }
        /// ehbp_events.dfy(1329,3)
        pub fn LEBytes(n: &DafnyInt, length: &nat) -> Sequence<u8> {
            {
                let _initializer = {
                        let n: DafnyInt = n.clone();
                        let length: nat = length.clone();
                        {
                            let mut n = n.clone();
                            Arc::new(move |i: &DafnyInt| -> u8{
            truncate!(euclidian_modulo(euclidian_division(n.clone(), _default::Pow2(&(int!(8) * i.clone()))), int!(256)), u8)
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                        }
                    };
                integer_range(Zero::zero(), length.clone()).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
            }
        }
        /// ehbp_events.dfy(1336,3)
        pub fn Clamp(k: &Sequence<u8>) -> Sequence<u8> {
            seq![(k.get(&int!(0)) as u8 & 248 as u8) as u8].concat(&k.slice(&int!(1), &int!(31))).concat(&seq![(k.get(&int!(31)) as u8 & 127 as u8 | 64 as u8) as u8])
        }
        /// ehbp_events.dfy(1343,3)
        pub fn Ladder(k: &DafnyInt, x1: &DafnyInt, t: &nat, x2: &DafnyInt, z2: &DafnyInt, x3: &DafnyInt, z3: &DafnyInt, swap: &DafnyInt) -> (DafnyInt, DafnyInt, DafnyInt, DafnyInt, DafnyInt) {
            let mut _r0 = k.clone();
            let mut _r1 = x1.clone();
            let mut _r2 = t.clone();
            let mut _r3 = x2.clone();
            let mut _r4 = z2.clone();
            let mut _r5 = x3.clone();
            let mut _r6 = z3.clone();
            let mut _r7 = swap.clone();
            'TAIL_CALL_START: loop {
                let k = _r0;
                let x1 = _r1;
                let t = _r2;
                let x2 = _r3;
                let z2 = _r4;
                let x3 = _r5;
                let z3 = _r6;
                let swap = _r7;
                let mut kt: DafnyInt = euclidian_modulo(euclidian_division(k.clone(), _default::Pow2(&t)), int!(2));
                let mut sw: DafnyInt = if swap.clone() != kt.clone() {
                        int!(1)
                    } else {
                        int!(0)
                    };
                let mut __let_tmp_rhs0: (DafnyInt, DafnyInt) = if sw.clone() == int!(1) {
                        (
                            x3.clone(),
                            x2.clone()
                        )
                    } else {
                        (
                            x2.clone(),
                            x3.clone()
                        )
                    };
                let mut x2s: DafnyInt = __let_tmp_rhs0.0.clone();
                let mut x3s: DafnyInt = __let_tmp_rhs0.1.clone();
                let mut __let_tmp_rhs1: (DafnyInt, DafnyInt) = if sw.clone() == int!(1) {
                        (
                            z3.clone(),
                            z2.clone()
                        )
                    } else {
                        (
                            z2.clone(),
                            z3.clone()
                        )
                    };
                let mut z2s: DafnyInt = __let_tmp_rhs1.0.clone();
                let mut z3s: DafnyInt = __let_tmp_rhs1.1.clone();
                let mut a: DafnyInt = euclidian_modulo(x2s.clone() + z2s.clone(), _default::P25519());
                let mut aa: DafnyInt = euclidian_modulo(a.clone() * a.clone(), _default::P25519());
                let mut b: DafnyInt = euclidian_modulo(x2s.clone() - z2s.clone(), _default::P25519());
                let mut bb: DafnyInt = euclidian_modulo(b.clone() * b.clone(), _default::P25519());
                let mut e: DafnyInt = euclidian_modulo(aa.clone() - bb.clone(), _default::P25519());
                let mut c: DafnyInt = euclidian_modulo(x3s.clone() + z3s.clone(), _default::P25519());
                let mut d: DafnyInt = euclidian_modulo(x3s.clone() - z3s.clone(), _default::P25519());
                let mut da: DafnyInt = euclidian_modulo(d.clone() * a.clone(), _default::P25519());
                let mut cb: DafnyInt = euclidian_modulo(c.clone() * b.clone(), _default::P25519());
                let mut nx3: DafnyInt = euclidian_modulo((da.clone() + cb.clone()) * (da.clone() + cb.clone()), _default::P25519());
                let mut nz3: DafnyInt = euclidian_modulo(x1.clone() * euclidian_modulo((da.clone() - cb.clone()) * (da.clone() - cb.clone()), _default::P25519()), _default::P25519());
                let mut nx2: DafnyInt = euclidian_modulo(aa.clone() * bb.clone(), _default::P25519());
                let mut nz2: DafnyInt = euclidian_modulo(e.clone() * euclidian_modulo(aa.clone() + int!(b"121665") * e.clone(), _default::P25519()), _default::P25519());
                if t.clone() == int!(0) {
                    return (
                            nx2.clone(),
                            nz2.clone(),
                            nx3.clone(),
                            nz3.clone(),
                            kt.clone()
                        );
                } else {
                    let mut _in0: DafnyInt = k.clone();
                    let mut _in1: DafnyInt = x1.clone();
                    let mut _in2: DafnyInt = t.clone() - int!(1);
                    let mut _in3: DafnyInt = nx2.clone();
                    let mut _in4: DafnyInt = nz2.clone();
                    let mut _in5: DafnyInt = nx3.clone();
                    let mut _in6: DafnyInt = nz3.clone();
                    let mut _in7: DafnyInt = kt.clone();
                    _r0 = _in0.clone();
                    _r1 = _in1.clone();
                    _r2 = _in2.clone();
                    _r3 = _in3.clone();
                    _r4 = _in4.clone();
                    _r5 = _in5.clone();
                    _r6 = _in6.clone();
                    _r7 = _in7.clone();
                    continue 'TAIL_CALL_START;
                }
            }
        }
        /// ehbp_events.dfy(1367,3)
        pub fn X25519Ref(scalar: &Sequence<u8>, point: &Sequence<u8>) -> Sequence<u8> {
            let mut k: DafnyInt = _default::LE(&_default::Clamp(scalar));
            let mut u: DafnyInt = euclidian_modulo(_default::LE(point), _default::Pow2(&int!(255)));
            let mut __let_tmp_rhs0: (DafnyInt, DafnyInt, DafnyInt, DafnyInt, DafnyInt) = _default::Ladder(&k, &u, &int!(255), &int!(1), &int!(0), &u, &int!(1), &int!(0));
            let mut x2: DafnyInt = __let_tmp_rhs0.0.clone();
            let mut z2: DafnyInt = __let_tmp_rhs0.1.clone();
            let mut x3: DafnyInt = __let_tmp_rhs0.2.clone();
            let mut z3: DafnyInt = __let_tmp_rhs0.3.clone();
            let mut swap: DafnyInt = __let_tmp_rhs0.4.clone();
            let mut __let_tmp_rhs1: (DafnyInt, DafnyInt) = if swap.clone() == int!(1) {
                    (
                        x3.clone(),
                        z3.clone()
                    )
                } else {
                    (
                        x2.clone(),
                        z2.clone()
                    )
                };
            let mut x: DafnyInt = __let_tmp_rhs1.0.clone();
            let mut z: DafnyInt = __let_tmp_rhs1.1.clone();
            _default::LEBytes(&euclidian_modulo(x.clone() * _default::PowMod(&z, &(_default::P25519() - int!(2))), _default::P25519()), &int!(32))
        }
        /// ehbp_events.dfy(208,3)
        pub fn BasePoint() -> Sequence<u8> {
            seq![9].concat(&_default::Repeat(&int!(31), 0))
        }
        /// ehbp_events.dfy(202,3)
        pub fn HpkeVersion() -> Sequence<u8> {
            crate::EHBP::_default::Ascii(&string_of("HPKE-v1"))
        }
        /// ehbp_events.dfy(203,3)
        pub fn KemSuiteId() -> Sequence<u8> {
            crate::EHBP::_default::Ascii(&string_of("KEM")).concat(&crate::EHBP::_default::BE16(crate::EHBP::_default::KemX25519()))
        }
        /// ehbp_events.dfy(204,3)
        pub fn HpkeSuiteId() -> Sequence<u8> {
            crate::EHBP::_default::Ascii(&string_of("HPKE")).concat(&crate::EHBP::_default::BE16(crate::EHBP::_default::KemX25519())).concat(&crate::EHBP::_default::BE16(crate::EHBP::_default::KdfHkdfSha256())).concat(&crate::EHBP::_default::BE16(crate::EHBP::_default::AeadAes256Gcm()))
        }
        /// ehbp_events.dfy(209,3)
        pub fn MaxSeq() -> u64 {
            18446744073709551615
        }
        /// ehbp_events.dfy(338,3)
        pub fn MaxJsonStringChars() -> nat {
            int!(1024)
        }
        /// ehbp_events.dfy(302,3)
        pub fn MaxJsonDepth() -> nat {
            int!(64)
        }
        /// ehbp_events.dfy(707,3)
        pub fn NewSession() -> Arc<SessionStore> {
            Arc::new(SessionStore::SessionStore {
                    generation: 0,
                    token: Arc::new(Option::None::<Arc<Token>> {})
                })
        }
        /// ehbp_events.dfy(811,3)
        pub fn NoCtx() -> Arc<Ctx> {
            Arc::new(Ctx::Ctx {
                    key: _default::Repeat(&int!(32), 0),
                    baseNonce: _default::Repeat(&int!(12), 0),
                    exporterSecret: seq![] as Sequence<u8>,
                    seqNo: 0
                })
        }
        /// ehbp_events.dfy(776,3)
        pub fn MaxReadBytes() -> nat {
            int!(b"4294967295")
        }
        /// ehbp_events.dfy(826,3)
        pub fn NoOrigin() -> Arc<Origin> {
            Arc::new(Origin::Origin {
                    scheme: string_of("https"),
                    host: string_of(""),
                    port: int!(443)
                })
        }
        /// ehbp_events.dfy(1190,3)
        pub fn GcmKey() -> Sequence<u8> {
            _default::Iota(&int!(32))
        }
        /// ehbp_events.dfy(1191,3)
        pub fn GcmNonce() -> Sequence<u8> {
            _default::Iota(&int!(12))
        }
        /// ehbp_events.dfy(1192,3)
        pub fn GcmCt() -> Sequence<u8> {
            _default::Hex(&string_of("226ab46b72d4be2b87fabbe9dbe0bfc2adbce017"))
        }
        /// ehbp_events.dfy(1194,3)
        pub fn AliceSk() -> Sequence<u8> {
            _default::Hex(&string_of("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        }
        /// ehbp_events.dfy(1195,3)
        pub fn AlicePk() -> Sequence<u8> {
            _default::Hex(&string_of("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
        }
        /// ehbp_events.dfy(1196,3)
        pub fn BobPk() -> Sequence<u8> {
            _default::Hex(&string_of("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
        }
        /// ehbp_events.dfy(1197,3)
        pub fn AliceBobShared() -> Sequence<u8> {
            _default::Hex(&string_of("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
        }
        /// ehbp_events.dfy(1199,3)
        pub fn HmacKey() -> Sequence<u8> {
            _default::Repeat(&int!(20), 11)
        }
        /// ehbp_events.dfy(1200,3)
        pub fn HmacTag() -> Sequence<u8> {
            _default::Hex(&string_of("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))
        }
        /// ehbp_events.dfy(1202,3)
        pub fn SelfCheckActions() -> Sequence<Arc<Action>> {
            seq![Arc::new(Action::HmacSha256 {
                        key: _default::HmacKey(),
                        data: crate::EHBP::_default::Ascii(&string_of("Hi There"))
                    }), Arc::new(Action::X25519 {
                        scalar: _default::AliceSk(),
                        point: _default::BasePoint()
                    }), Arc::new(Action::X25519 {
                        scalar: _default::AliceSk(),
                        point: _default::BobPk()
                    }), Arc::new(Action::AeadSeal {
                        key: _default::GcmKey(),
                        nonce: _default::GcmNonce(),
                        plaintext: crate::EHBP::_default::Ascii(&string_of("ehbp"))
                    }), Arc::new(Action::AeadOpen {
                        key: _default::GcmKey(),
                        nonce: _default::GcmNonce(),
                        ciphertext: _default::GcmCt()
                    }), Arc::new(Action::AeadOpen {
                        key: _default::GcmKey(),
                        nonce: _default::GcmNonce(),
                        ciphertext: _default::GcmCt().take(&(_default::GcmCt().cardinality() - int!(1))).concat(&seq![(_default::GcmCt().get(&(_default::GcmCt().cardinality() - int!(1))) as u8 ^ 1 as u8) as u8])
                    }), Arc::new(Action::AeadOpen {
                        key: _default::GcmKey(),
                        nonce: _default::GcmNonce(),
                        ciphertext: _default::GcmCt().take(&int!(8))
                    }), Arc::new(Action::RandomBytes {
                        length: int!(32)
                    }), Arc::new(Action::RandomBytes {
                        length: int!(32)
                    })]
        }
        /// ehbp_events.dfy(1233,3)
        pub fn K256() -> Sequence<u32> {
            seq![1116352408 as u32, 1899447441 as u32, 3049323471 as u32, 3921009573 as u32, 961987163 as u32, 1508970993 as u32, 2453635748 as u32, 2870763221 as u32, 3624381080 as u32, 310598401 as u32, 607225278 as u32, 1426881987 as u32, 1925078388 as u32, 2162078206 as u32, 2614888103 as u32, 3248222580 as u32, 3835390401 as u32, 4022224774 as u32, 264347078 as u32, 604807628 as u32, 770255983 as u32, 1249150122 as u32, 1555081692 as u32, 1996064986 as u32, 2554220882 as u32, 2821834349 as u32, 2952996808 as u32, 3210313671 as u32, 3336571891 as u32, 3584528711 as u32, 113926993 as u32, 338241895 as u32, 666307205 as u32, 773529912 as u32, 1294757372 as u32, 1396182291 as u32, 1695183700 as u32, 1986661051 as u32, 2177026350 as u32, 2456956037 as u32, 2730485921 as u32, 2820302411 as u32, 3259730800 as u32, 3345764771 as u32, 3516065817 as u32, 3600352804 as u32, 4094571909 as u32, 275423344 as u32, 430227734 as u32, 506948616 as u32, 659060556 as u32, 883997877 as u32, 958139571 as u32, 1322822218 as u32, 1537002063 as u32, 1747873779 as u32, 1955562222 as u32, 2024104815 as u32, 2227730452 as u32, 2361852424 as u32, 2428436474 as u32, 2756734187 as u32, 3204031479 as u32, 3329325298 as u32]
        }
        /// ehbp_events.dfy(1242,3)
        pub fn H256() -> Sequence<u32> {
            seq![1779033703 as u32, 3144134277 as u32, 1013904242 as u32, 2773480762 as u32, 1359893119 as u32, 2600822924 as u32, 528734635 as u32, 1541459225 as u32]
        }
        /// ehbp_events.dfy(1307,3)
        pub fn P25519() -> DafnyInt {
            int!(b"57896044618658097711785492504343953926634992332820282019728792003956564819949")
        }
    }

    /// ehbp_events.dfy(24,3)
    #[derive(Clone)]
    pub enum Stream {
        RequestBody {},
        ResponseBody {}
    }

    impl Stream {}

    impl Debug
        for Stream {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Stream {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Stream::RequestBody{} => {
                    write!(_formatter, "EHBPEvents.Stream.RequestBody")?;
                    Ok(())
                },
                Stream::ResponseBody{} => {
                    write!(_formatter, "EHBPEvents.Stream.ResponseBody")?;
                    Ok(())
                },
            }
        }
    }

    impl Stream {
        /// Enumerates all possible values of Stream
        pub fn _AllSingletonConstructors() -> SequenceIter<Arc<Stream>> {
            seq![Arc::new(Stream::RequestBody {}), Arc::new(Stream::ResponseBody {})].iter()
        }
    }

    impl PartialEq
        for Stream {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Stream::RequestBody{}, Stream::RequestBody{}) => {
                    true
                },
                (Stream::ResponseBody{}, Stream::ResponseBody{}) => {
                    true
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Stream {}

    impl Hash
        for Stream {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Stream::RequestBody{} => {
                    
                },
                Stream::ResponseBody{} => {
                    
                },
            }
        }
    }

    impl AsRef<Stream>
        for Stream {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(27,3)
    #[derive(Clone)]
    pub enum BodyEnd {
        More {},
        Done {},
        Aborted {
            code: Arc<Code>
        }
    }

    impl BodyEnd {
        /// Gets the field code for all enum members which have it
        pub fn code(&self) -> &Arc<Code> {
            match self {
                BodyEnd::More{} => panic!("field does not exist on this variant"),
                BodyEnd::Done{} => panic!("field does not exist on this variant"),
                BodyEnd::Aborted{code, } => code,
            }
        }
    }

    impl Debug
        for BodyEnd {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for BodyEnd {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                BodyEnd::More{} => {
                    write!(_formatter, "EHBPEvents.BodyEnd.More")?;
                    Ok(())
                },
                BodyEnd::Done{} => {
                    write!(_formatter, "EHBPEvents.BodyEnd.Done")?;
                    Ok(())
                },
                BodyEnd::Aborted{code, } => {
                    write!(_formatter, "EHBPEvents.BodyEnd.Aborted(")?;
                    DafnyPrint::fmt_print(code, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for BodyEnd {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (BodyEnd::More{}, BodyEnd::More{}) => {
                    true
                },
                (BodyEnd::Done{}, BodyEnd::Done{}) => {
                    true
                },
                (BodyEnd::Aborted{code, }, BodyEnd::Aborted{code: _2_code, }) => {
                    code == _2_code
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for BodyEnd {}

    impl Hash
        for BodyEnd {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                BodyEnd::More{} => {
                    
                },
                BodyEnd::Done{} => {
                    
                },
                BodyEnd::Aborted{code, } => {
                    Hash::hash(code, _state)
                },
            }
        }
    }

    impl AsRef<BodyEnd>
        for BodyEnd {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(29,3)
    #[derive(Clone)]
    pub enum Event {
        Start {
            verb: Sequence<DafnyChar>,
            url: Sequence<DafnyChar>,
            scheme: Sequence<DafnyChar>,
            host: Sequence<DafnyChar>,
            port: DafnyInt,
            hasPort: bool,
            hasUserinfo: bool,
            headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
            hasBody: bool
        },
        DiscoverStart {},
        SessionBegun {
            generation: u64
        },
        RandomResult {
            data: Sequence<u8>
        },
        X25519Result {
            point: Sequence<u8>
        },
        HmacResult {
            mac: Sequence<u8>
        },
        AeadSealResult {
            ciphertext: Sequence<u8>
        },
        AeadOpenResult {
            ok: bool,
            plaintext: Sequence<u8>
        },
        ResponseHead {
            status: DafnyInt,
            headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
            redirected: bool
        },
        Chunk {
            stream: Arc<Stream>,
            data: Sequence<u8>,
            eof: bool
        },
        StreamFailed {
            stream: Arc<Stream>
        },
        CallerRead {},
        CallerClose {}
    }

    impl Event {
        /// Gets the field verb for all enum members which have it
        pub fn verb(&self) -> &Sequence<DafnyChar> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => verb,
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field url for all enum members which have it
        pub fn url(&self) -> &Sequence<DafnyChar> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => url,
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field scheme for all enum members which have it
        pub fn scheme(&self) -> &Sequence<DafnyChar> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => scheme,
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field host for all enum members which have it
        pub fn host(&self) -> &Sequence<DafnyChar> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => host,
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field port for all enum members which have it
        pub fn port(&self) -> &DafnyInt {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => port,
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field hasPort for all enum members which have it
        pub fn hasPort(&self) -> &bool {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => hasPort,
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field hasUserinfo for all enum members which have it
        pub fn hasUserinfo(&self) -> &bool {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => hasUserinfo,
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field headers for all enum members which have it
        pub fn headers(&self) -> &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => headers,
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => headers,
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field hasBody for all enum members which have it
        pub fn hasBody(&self) -> &bool {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => hasBody,
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field generation for all enum members which have it
        pub fn generation(&self) -> &u64 {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => generation,
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field data for all enum members which have it
        pub fn data(&self) -> &Sequence<u8> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => data,
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => data,
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field point for all enum members which have it
        pub fn point(&self) -> &Sequence<u8> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => point,
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field mac for all enum members which have it
        pub fn mac(&self) -> &Sequence<u8> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => mac,
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field ciphertext for all enum members which have it
        pub fn ciphertext(&self) -> &Sequence<u8> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => ciphertext,
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field ok for all enum members which have it
        pub fn ok(&self) -> &bool {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => ok,
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field plaintext for all enum members which have it
        pub fn plaintext(&self) -> &Sequence<u8> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => plaintext,
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field status for all enum members which have it
        pub fn status(&self) -> &DafnyInt {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => status,
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field redirected for all enum members which have it
        pub fn redirected(&self) -> &bool {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => redirected,
                Event::Chunk{stream, data, eof, } => panic!("field does not exist on this variant"),
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field stream for all enum members which have it
        pub fn stream(&self) -> &Arc<Stream> {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => stream,
                Event::StreamFailed{stream, } => stream,
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field eof for all enum members which have it
        pub fn eof(&self) -> &bool {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => panic!("field does not exist on this variant"),
                Event::DiscoverStart{} => panic!("field does not exist on this variant"),
                Event::SessionBegun{generation, } => panic!("field does not exist on this variant"),
                Event::RandomResult{data, } => panic!("field does not exist on this variant"),
                Event::X25519Result{point, } => panic!("field does not exist on this variant"),
                Event::HmacResult{mac, } => panic!("field does not exist on this variant"),
                Event::AeadSealResult{ciphertext, } => panic!("field does not exist on this variant"),
                Event::AeadOpenResult{ok, plaintext, } => panic!("field does not exist on this variant"),
                Event::ResponseHead{status, headers, redirected, } => panic!("field does not exist on this variant"),
                Event::Chunk{stream, data, eof, } => eof,
                Event::StreamFailed{stream, } => panic!("field does not exist on this variant"),
                Event::CallerRead{} => panic!("field does not exist on this variant"),
                Event::CallerClose{} => panic!("field does not exist on this variant"),
            }
        }
    }

    impl Debug
        for Event {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Event {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => {
                    write!(_formatter, "EHBPEvents.Event.Start(")?;
                    DafnyPrint::fmt_print(verb, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(url, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(scheme, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(host, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(port, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(hasPort, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(hasUserinfo, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(headers, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(hasBody, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Event::DiscoverStart{} => {
                    write!(_formatter, "EHBPEvents.Event.DiscoverStart")?;
                    Ok(())
                },
                Event::SessionBegun{generation, } => {
                    write!(_formatter, "EHBPEvents.Event.SessionBegun(")?;
                    DafnyPrint::fmt_print(generation, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Event::RandomResult{data, } => {
                    write!(_formatter, "EHBPEvents.Event.RandomResult(<redacted>)")?;
                    Ok(())
                },
                Event::X25519Result{point, } => {
                    write!(_formatter, "EHBPEvents.Event.X25519Result(<redacted>)")?;
                    Ok(())
                },
                Event::HmacResult{mac, } => {
                    write!(_formatter, "EHBPEvents.Event.HmacResult(<redacted>)")?;
                    Ok(())
                },
                Event::AeadSealResult{ciphertext, } => {
                    write!(_formatter, "EHBPEvents.Event.AeadSealResult(")?;
                    DafnyPrint::fmt_print(ciphertext, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Event::AeadOpenResult{ok, plaintext, } => {
                    write!(_formatter, "EHBPEvents.Event.AeadOpenResult(")?;
                    DafnyPrint::fmt_print(ok, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(plaintext, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Event::ResponseHead{status, headers, redirected, } => {
                    write!(_formatter, "EHBPEvents.Event.ResponseHead(")?;
                    DafnyPrint::fmt_print(status, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(headers, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(redirected, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Event::Chunk{stream, data, eof, } => {
                    write!(_formatter, "EHBPEvents.Event.Chunk(")?;
                    DafnyPrint::fmt_print(stream, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(data, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(eof, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Event::StreamFailed{stream, } => {
                    write!(_formatter, "EHBPEvents.Event.StreamFailed(")?;
                    DafnyPrint::fmt_print(stream, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Event::CallerRead{} => {
                    write!(_formatter, "EHBPEvents.Event.CallerRead")?;
                    Ok(())
                },
                Event::CallerClose{} => {
                    write!(_formatter, "EHBPEvents.Event.CallerClose")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Event {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, }, Event::Start{verb: _2_verb, url: _2_url, scheme: _2_scheme, host: _2_host, port: _2_port, hasPort: _2_hasPort, hasUserinfo: _2_hasUserinfo, headers: _2_headers, hasBody: _2_hasBody, }) => {
                    verb == _2_verb && url == _2_url && scheme == _2_scheme && host == _2_host && port == _2_port && hasPort == _2_hasPort && hasUserinfo == _2_hasUserinfo && headers == _2_headers && hasBody == _2_hasBody
                },
                (Event::DiscoverStart{}, Event::DiscoverStart{}) => {
                    true
                },
                (Event::SessionBegun{generation, }, Event::SessionBegun{generation: _2_generation, }) => {
                    generation == _2_generation
                },
                (Event::RandomResult{data, }, Event::RandomResult{data: _2_data, }) => {
                    data == _2_data
                },
                (Event::X25519Result{point, }, Event::X25519Result{point: _2_point, }) => {
                    point == _2_point
                },
                (Event::HmacResult{mac, }, Event::HmacResult{mac: _2_mac, }) => {
                    mac == _2_mac
                },
                (Event::AeadSealResult{ciphertext, }, Event::AeadSealResult{ciphertext: _2_ciphertext, }) => {
                    ciphertext == _2_ciphertext
                },
                (Event::AeadOpenResult{ok, plaintext, }, Event::AeadOpenResult{ok: _2_ok, plaintext: _2_plaintext, }) => {
                    ok == _2_ok && plaintext == _2_plaintext
                },
                (Event::ResponseHead{status, headers, redirected, }, Event::ResponseHead{status: _2_status, headers: _2_headers, redirected: _2_redirected, }) => {
                    status == _2_status && headers == _2_headers && redirected == _2_redirected
                },
                (Event::Chunk{stream, data, eof, }, Event::Chunk{stream: _2_stream, data: _2_data, eof: _2_eof, }) => {
                    stream == _2_stream && data == _2_data && eof == _2_eof
                },
                (Event::StreamFailed{stream, }, Event::StreamFailed{stream: _2_stream, }) => {
                    stream == _2_stream
                },
                (Event::CallerRead{}, Event::CallerRead{}) => {
                    true
                },
                (Event::CallerClose{}, Event::CallerClose{}) => {
                    true
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Event {}

    impl Hash
        for Event {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Event::Start{verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody, } => {
                    Hash::hash(verb, _state);
                    Hash::hash(url, _state);
                    Hash::hash(scheme, _state);
                    Hash::hash(host, _state);
                    Hash::hash(port, _state);
                    Hash::hash(hasPort, _state);
                    Hash::hash(hasUserinfo, _state);
                    Hash::hash(headers, _state);
                    Hash::hash(hasBody, _state)
                },
                Event::DiscoverStart{} => {
                    
                },
                Event::SessionBegun{generation, } => {
                    Hash::hash(generation, _state)
                },
                Event::RandomResult{data, } => {
                    Hash::hash(data, _state)
                },
                Event::X25519Result{point, } => {
                    Hash::hash(point, _state)
                },
                Event::HmacResult{mac, } => {
                    Hash::hash(mac, _state)
                },
                Event::AeadSealResult{ciphertext, } => {
                    Hash::hash(ciphertext, _state)
                },
                Event::AeadOpenResult{ok, plaintext, } => {
                    Hash::hash(ok, _state);
                    Hash::hash(plaintext, _state)
                },
                Event::ResponseHead{status, headers, redirected, } => {
                    Hash::hash(status, _state);
                    Hash::hash(headers, _state);
                    Hash::hash(redirected, _state)
                },
                Event::Chunk{stream, data, eof, } => {
                    Hash::hash(stream, _state);
                    Hash::hash(data, _state);
                    Hash::hash(eof, _state)
                },
                Event::StreamFailed{stream, } => {
                    Hash::hash(stream, _state)
                },
                Event::CallerRead{} => {
                    
                },
                Event::CallerClose{} => {
                    
                },
            }
        }
    }

    impl AsRef<Event>
        for Event {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(51,3)
    #[derive(Clone)]
    pub enum Action {
        BeginSession {},
        PublishToken {
            generation: u64,
            exportedSecret: Sequence<u8>,
            requestEnc: Sequence<u8>
        },
        ClearToken {
            generation: u64
        },
        RandomBytes {
            length: nat
        },
        X25519 {
            scalar: Sequence<u8>,
            point: Sequence<u8>
        },
        HmacSha256 {
            key: Sequence<u8>,
            data: Sequence<u8>
        },
        AeadSeal {
            key: Sequence<u8>,
            nonce: Sequence<u8>,
            plaintext: Sequence<u8>
        },
        AeadOpen {
            key: Sequence<u8>,
            nonce: Sequence<u8>,
            ciphertext: Sequence<u8>
        },
        Send {
            verb: Sequence<DafnyChar>,
            url: Sequence<DafnyChar>,
            headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
            hasBody: bool
        },
        Write {
            data: Sequence<u8>,
            end: Arc<BodyEnd>
        },
        Read {
            stream: Arc<Stream>
        },
        Close {
            stream: Arc<Stream>
        },
        EmitPlaintext {
            data: Sequence<u8>
        },
        Passthrough {
            status: DafnyInt,
            headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
            prefix: Sequence<u8>
        },
        Done {
            status: DafnyInt,
            headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>
        },
        Finished {},
        Discovered {
            publicKey: Sequence<u8>
        },
        Fail {
            code: Arc<Code>,
            message: Sequence<DafnyChar>
        }
    }

    impl Action {
        /// Gets the field generation for all enum members which have it
        pub fn generation(&self) -> &u64 {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => generation,
                Action::ClearToken{generation, } => generation,
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field exportedSecret for all enum members which have it
        pub fn exportedSecret(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => exportedSecret,
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field requestEnc for all enum members which have it
        pub fn requestEnc(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => requestEnc,
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field length for all enum members which have it
        pub fn length(&self) -> &nat {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => length,
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field scalar for all enum members which have it
        pub fn scalar(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => scalar,
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field point for all enum members which have it
        pub fn point(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => point,
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field key for all enum members which have it
        pub fn key(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => key,
                Action::AeadSeal{key, nonce, plaintext, } => key,
                Action::AeadOpen{key, nonce, ciphertext, } => key,
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field data for all enum members which have it
        pub fn data(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => data,
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => data,
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => data,
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field nonce for all enum members which have it
        pub fn nonce(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => nonce,
                Action::AeadOpen{key, nonce, ciphertext, } => nonce,
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field plaintext for all enum members which have it
        pub fn plaintext(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => plaintext,
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field ciphertext for all enum members which have it
        pub fn ciphertext(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => ciphertext,
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field verb for all enum members which have it
        pub fn verb(&self) -> &Sequence<DafnyChar> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => verb,
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field url for all enum members which have it
        pub fn url(&self) -> &Sequence<DafnyChar> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => url,
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field headers for all enum members which have it
        pub fn headers(&self) -> &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => headers,
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => headers,
                Action::Done{status, headers, } => headers,
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field hasBody for all enum members which have it
        pub fn hasBody(&self) -> &bool {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => hasBody,
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field end for all enum members which have it
        pub fn end(&self) -> &Arc<BodyEnd> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => end,
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field stream for all enum members which have it
        pub fn stream(&self) -> &Arc<Stream> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => stream,
                Action::Close{stream, } => stream,
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field status for all enum members which have it
        pub fn status(&self) -> &DafnyInt {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => status,
                Action::Done{status, headers, } => status,
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field prefix for all enum members which have it
        pub fn prefix(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => prefix,
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field publicKey for all enum members which have it
        pub fn publicKey(&self) -> &Sequence<u8> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => publicKey,
                Action::Fail{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field code for all enum members which have it
        pub fn code(&self) -> &Arc<Code> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => code,
            }
        }
        /// Gets the field message for all enum members which have it
        pub fn message(&self) -> &Sequence<DafnyChar> {
            match self {
                Action::BeginSession{} => panic!("field does not exist on this variant"),
                Action::PublishToken{generation, exportedSecret, requestEnc, } => panic!("field does not exist on this variant"),
                Action::ClearToken{generation, } => panic!("field does not exist on this variant"),
                Action::RandomBytes{length, } => panic!("field does not exist on this variant"),
                Action::X25519{scalar, point, } => panic!("field does not exist on this variant"),
                Action::HmacSha256{key, data, } => panic!("field does not exist on this variant"),
                Action::AeadSeal{key, nonce, plaintext, } => panic!("field does not exist on this variant"),
                Action::AeadOpen{key, nonce, ciphertext, } => panic!("field does not exist on this variant"),
                Action::Send{verb, url, headers, hasBody, } => panic!("field does not exist on this variant"),
                Action::Write{data, end, } => panic!("field does not exist on this variant"),
                Action::Read{stream, } => panic!("field does not exist on this variant"),
                Action::Close{stream, } => panic!("field does not exist on this variant"),
                Action::EmitPlaintext{data, } => panic!("field does not exist on this variant"),
                Action::Passthrough{status, headers, prefix, } => panic!("field does not exist on this variant"),
                Action::Done{status, headers, } => panic!("field does not exist on this variant"),
                Action::Finished{} => panic!("field does not exist on this variant"),
                Action::Discovered{publicKey, } => panic!("field does not exist on this variant"),
                Action::Fail{code, message, } => message,
            }
        }
    }

    impl Debug
        for Action {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Action {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Action::BeginSession{} => {
                    write!(_formatter, "EHBPEvents.Action.BeginSession")?;
                    Ok(())
                },
                Action::PublishToken{generation, exportedSecret, requestEnc, } => {
                    write!(_formatter, "EHBPEvents.Action.PublishToken(<redacted>)")?;
                    Ok(())
                },
                Action::ClearToken{generation, } => {
                    write!(_formatter, "EHBPEvents.Action.ClearToken(")?;
                    DafnyPrint::fmt_print(generation, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::RandomBytes{length, } => {
                    write!(_formatter, "EHBPEvents.Action.RandomBytes(")?;
                    DafnyPrint::fmt_print(length, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::X25519{scalar, point, } => {
                    write!(_formatter, "EHBPEvents.Action.X25519(<redacted>)")?;
                    Ok(())
                },
                Action::HmacSha256{key, data, } => {
                    write!(_formatter, "EHBPEvents.Action.HmacSha256(<redacted>)")?;
                    Ok(())
                },
                Action::AeadSeal{key, nonce, plaintext, } => {
                    write!(_formatter, "EHBPEvents.Action.AeadSeal(<redacted>)")?;
                    Ok(())
                },
                Action::AeadOpen{key, nonce, ciphertext, } => {
                    write!(_formatter, "EHBPEvents.Action.AeadOpen(<redacted>)")?;
                    Ok(())
                },
                Action::Send{verb, url, headers, hasBody, } => {
                    write!(_formatter, "EHBPEvents.Action.Send(")?;
                    DafnyPrint::fmt_print(verb, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(url, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(headers, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(hasBody, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::Write{data, end, } => {
                    write!(_formatter, "EHBPEvents.Action.Write(")?;
                    DafnyPrint::fmt_print(data, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(end, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::Read{stream, } => {
                    write!(_formatter, "EHBPEvents.Action.Read(")?;
                    DafnyPrint::fmt_print(stream, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::Close{stream, } => {
                    write!(_formatter, "EHBPEvents.Action.Close(")?;
                    DafnyPrint::fmt_print(stream, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::EmitPlaintext{data, } => {
                    write!(_formatter, "EHBPEvents.Action.EmitPlaintext(")?;
                    DafnyPrint::fmt_print(data, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::Passthrough{status, headers, prefix, } => {
                    write!(_formatter, "EHBPEvents.Action.Passthrough(")?;
                    DafnyPrint::fmt_print(status, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(headers, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(prefix, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::Done{status, headers, } => {
                    write!(_formatter, "EHBPEvents.Action.Done(")?;
                    DafnyPrint::fmt_print(status, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(headers, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::Finished{} => {
                    write!(_formatter, "EHBPEvents.Action.Finished")?;
                    Ok(())
                },
                Action::Discovered{publicKey, } => {
                    write!(_formatter, "EHBPEvents.Action.Discovered(")?;
                    DafnyPrint::fmt_print(publicKey, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Action::Fail{code, message, } => {
                    write!(_formatter, "EHBPEvents.Action.Fail(")?;
                    DafnyPrint::fmt_print(code, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(message, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Action {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Action::BeginSession{}, Action::BeginSession{}) => {
                    true
                },
                (Action::PublishToken{generation, exportedSecret, requestEnc, }, Action::PublishToken{generation: _2_generation, exportedSecret: _2_exportedSecret, requestEnc: _2_requestEnc, }) => {
                    generation == _2_generation && exportedSecret == _2_exportedSecret && requestEnc == _2_requestEnc
                },
                (Action::ClearToken{generation, }, Action::ClearToken{generation: _2_generation, }) => {
                    generation == _2_generation
                },
                (Action::RandomBytes{length, }, Action::RandomBytes{length: _2_length, }) => {
                    length == _2_length
                },
                (Action::X25519{scalar, point, }, Action::X25519{scalar: _2_scalar, point: _2_point, }) => {
                    scalar == _2_scalar && point == _2_point
                },
                (Action::HmacSha256{key, data, }, Action::HmacSha256{key: _2_key, data: _2_data, }) => {
                    key == _2_key && data == _2_data
                },
                (Action::AeadSeal{key, nonce, plaintext, }, Action::AeadSeal{key: _2_key, nonce: _2_nonce, plaintext: _2_plaintext, }) => {
                    key == _2_key && nonce == _2_nonce && plaintext == _2_plaintext
                },
                (Action::AeadOpen{key, nonce, ciphertext, }, Action::AeadOpen{key: _2_key, nonce: _2_nonce, ciphertext: _2_ciphertext, }) => {
                    key == _2_key && nonce == _2_nonce && ciphertext == _2_ciphertext
                },
                (Action::Send{verb, url, headers, hasBody, }, Action::Send{verb: _2_verb, url: _2_url, headers: _2_headers, hasBody: _2_hasBody, }) => {
                    verb == _2_verb && url == _2_url && headers == _2_headers && hasBody == _2_hasBody
                },
                (Action::Write{data, end, }, Action::Write{data: _2_data, end: _2_end, }) => {
                    data == _2_data && end == _2_end
                },
                (Action::Read{stream, }, Action::Read{stream: _2_stream, }) => {
                    stream == _2_stream
                },
                (Action::Close{stream, }, Action::Close{stream: _2_stream, }) => {
                    stream == _2_stream
                },
                (Action::EmitPlaintext{data, }, Action::EmitPlaintext{data: _2_data, }) => {
                    data == _2_data
                },
                (Action::Passthrough{status, headers, prefix, }, Action::Passthrough{status: _2_status, headers: _2_headers, prefix: _2_prefix, }) => {
                    status == _2_status && headers == _2_headers && prefix == _2_prefix
                },
                (Action::Done{status, headers, }, Action::Done{status: _2_status, headers: _2_headers, }) => {
                    status == _2_status && headers == _2_headers
                },
                (Action::Finished{}, Action::Finished{}) => {
                    true
                },
                (Action::Discovered{publicKey, }, Action::Discovered{publicKey: _2_publicKey, }) => {
                    publicKey == _2_publicKey
                },
                (Action::Fail{code, message, }, Action::Fail{code: _2_code, message: _2_message, }) => {
                    code == _2_code && message == _2_message
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Action {}

    impl Hash
        for Action {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Action::BeginSession{} => {
                    
                },
                Action::PublishToken{generation, exportedSecret, requestEnc, } => {
                    Hash::hash(generation, _state);
                    Hash::hash(exportedSecret, _state);
                    Hash::hash(requestEnc, _state)
                },
                Action::ClearToken{generation, } => {
                    Hash::hash(generation, _state)
                },
                Action::RandomBytes{length, } => {
                    Hash::hash(length, _state)
                },
                Action::X25519{scalar, point, } => {
                    Hash::hash(scalar, _state);
                    Hash::hash(point, _state)
                },
                Action::HmacSha256{key, data, } => {
                    Hash::hash(key, _state);
                    Hash::hash(data, _state)
                },
                Action::AeadSeal{key, nonce, plaintext, } => {
                    Hash::hash(key, _state);
                    Hash::hash(nonce, _state);
                    Hash::hash(plaintext, _state)
                },
                Action::AeadOpen{key, nonce, ciphertext, } => {
                    Hash::hash(key, _state);
                    Hash::hash(nonce, _state);
                    Hash::hash(ciphertext, _state)
                },
                Action::Send{verb, url, headers, hasBody, } => {
                    Hash::hash(verb, _state);
                    Hash::hash(url, _state);
                    Hash::hash(headers, _state);
                    Hash::hash(hasBody, _state)
                },
                Action::Write{data, end, } => {
                    Hash::hash(data, _state);
                    Hash::hash(end, _state)
                },
                Action::Read{stream, } => {
                    Hash::hash(stream, _state)
                },
                Action::Close{stream, } => {
                    Hash::hash(stream, _state)
                },
                Action::EmitPlaintext{data, } => {
                    Hash::hash(data, _state)
                },
                Action::Passthrough{status, headers, prefix, } => {
                    Hash::hash(status, _state);
                    Hash::hash(headers, _state);
                    Hash::hash(prefix, _state)
                },
                Action::Done{status, headers, } => {
                    Hash::hash(status, _state);
                    Hash::hash(headers, _state)
                },
                Action::Finished{} => {
                    
                },
                Action::Discovered{publicKey, } => {
                    Hash::hash(publicKey, _state)
                },
                Action::Fail{code, message, } => {
                    Hash::hash(code, _state);
                    Hash::hash(message, _state)
                },
            }
        }
    }

    impl AsRef<Action>
        for Action {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(92,3)
    #[derive(Clone)]
    pub enum Performed {
        Quiet {},
        Got {
            e: Arc<Event>
        },
        Stop {}
    }

    impl Performed {
        /// Gets the field e for all enum members which have it
        pub fn e(&self) -> &Arc<Event> {
            match self {
                Performed::Quiet{} => panic!("field does not exist on this variant"),
                Performed::Got{e, } => e,
                Performed::Stop{} => panic!("field does not exist on this variant"),
            }
        }
    }

    impl Debug
        for Performed {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Performed {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Performed::Quiet{} => {
                    write!(_formatter, "EHBPEvents.Performed.Quiet")?;
                    Ok(())
                },
                Performed::Got{e, } => {
                    write!(_formatter, "EHBPEvents.Performed.Got(")?;
                    DafnyPrint::fmt_print(e, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Performed::Stop{} => {
                    write!(_formatter, "EHBPEvents.Performed.Stop")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Performed {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Performed::Quiet{}, Performed::Quiet{}) => {
                    true
                },
                (Performed::Got{e, }, Performed::Got{e: _2_e, }) => {
                    e == _2_e
                },
                (Performed::Stop{}, Performed::Stop{}) => {
                    true
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Performed {}

    impl Hash
        for Performed {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Performed::Quiet{} => {
                    
                },
                Performed::Got{e, } => {
                    Hash::hash(e, _state)
                },
                Performed::Stop{} => {
                    
                },
            }
        }
    }

    impl AsRef<Performed>
        for Performed {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(94,3)
    pub trait Performer: Any + Sync + ::std::marker::Send + UpcastObject<dyn Any + Sync + ::std::marker::Send> + Any + Sync + ::std::marker::Send + UpcastObject<dyn Any + Sync + ::std::marker::Send> {
        /// ehbp_events.dfy(95,5)
        fn BeginSession(&self) -> u64;
        /// ehbp_events.dfy(96,5)
        fn PublishToken(&self, generation: u64, exportedSecret: &Sequence<u8>, requestEnc: &Sequence<u8>) -> ();
        /// ehbp_events.dfy(97,5)
        fn ClearToken(&self, generation: u64) -> ();
        /// ehbp_events.dfy(98,5)
        fn RandomBytes(&self, length: &nat) -> Sequence<u8>;
        /// ehbp_events.dfy(99,5)
        fn X25519(&self, scalar: &Sequence<u8>, point: &Sequence<u8>) -> Sequence<u8>;
        /// ehbp_events.dfy(100,5)
        fn HmacSha256(&self, key: &Sequence<u8>, data: &Sequence<u8>) -> Sequence<u8>;
        /// ehbp_events.dfy(101,5)
        fn AeadSeal(&self, key: &Sequence<u8>, nonce: &Sequence<u8>, plaintext: &Sequence<u8>) -> Sequence<u8>;
        /// ehbp_events.dfy(102,5)
        fn AeadOpen(&self, key: &Sequence<u8>, nonce: &Sequence<u8>, ciphertext: &Sequence<u8>) -> (bool, Sequence<u8>);
        /// ehbp_events.dfy(104,5)
        fn Send(&self, verb: &Sequence<DafnyChar>, url: &Sequence<DafnyChar>, headers: &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>, hasBody: bool) -> (bool, DafnyInt, Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>, bool);
        /// ehbp_events.dfy(106,5)
        fn Write(&self, data: &Sequence<u8>, end: &Arc<BodyEnd>) -> bool;
        /// ehbp_events.dfy(107,5)
        fn Read(&self, stream: &Arc<Stream>) -> (bool, Sequence<u8>, bool);
        /// ehbp_events.dfy(108,5)
        fn Close(&self, stream: &Arc<Stream>) -> ();
        /// ehbp_events.dfy(110,5)
        fn EmitPlaintext(&self, data: &Sequence<u8>) -> ();
    }

    /// ehbp_events.dfy(166,3)
    #[derive(Clone)]
    pub enum Job {
        JExtract {
            salt: Sequence<u8>,
            ikm: Sequence<u8>
        },
        JExpand {
            prk: Sequence<u8>,
            info: Sequence<u8>,
            length: nat,
            acc: Sequence<u8>,
            prev: Sequence<u8>,
            i: u8
        }
    }

    impl Job {
        /// Gets the field salt for all enum members which have it
        pub fn salt(&self) -> &Sequence<u8> {
            match self {
                Job::JExtract{salt, ikm, } => salt,
                Job::JExpand{prk, info, length, acc, prev, i, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field ikm for all enum members which have it
        pub fn ikm(&self) -> &Sequence<u8> {
            match self {
                Job::JExtract{salt, ikm, } => ikm,
                Job::JExpand{prk, info, length, acc, prev, i, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field prk for all enum members which have it
        pub fn prk(&self) -> &Sequence<u8> {
            match self {
                Job::JExtract{salt, ikm, } => panic!("field does not exist on this variant"),
                Job::JExpand{prk, info, length, acc, prev, i, } => prk,
            }
        }
        /// Gets the field info for all enum members which have it
        pub fn info(&self) -> &Sequence<u8> {
            match self {
                Job::JExtract{salt, ikm, } => panic!("field does not exist on this variant"),
                Job::JExpand{prk, info, length, acc, prev, i, } => info,
            }
        }
        /// Gets the field length for all enum members which have it
        pub fn length(&self) -> &nat {
            match self {
                Job::JExtract{salt, ikm, } => panic!("field does not exist on this variant"),
                Job::JExpand{prk, info, length, acc, prev, i, } => length,
            }
        }
        /// Gets the field acc for all enum members which have it
        pub fn acc(&self) -> &Sequence<u8> {
            match self {
                Job::JExtract{salt, ikm, } => panic!("field does not exist on this variant"),
                Job::JExpand{prk, info, length, acc, prev, i, } => acc,
            }
        }
        /// Gets the field prev for all enum members which have it
        pub fn prev(&self) -> &Sequence<u8> {
            match self {
                Job::JExtract{salt, ikm, } => panic!("field does not exist on this variant"),
                Job::JExpand{prk, info, length, acc, prev, i, } => prev,
            }
        }
        /// Gets the field i for all enum members which have it
        pub fn i(&self) -> &u8 {
            match self {
                Job::JExtract{salt, ikm, } => panic!("field does not exist on this variant"),
                Job::JExpand{prk, info, length, acc, prev, i, } => i,
            }
        }
    }

    impl Debug
        for Job {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Job {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Job::JExtract{salt, ikm, } => {
                    write!(_formatter, "EHBPEvents.Job.JExtract(<redacted>)")?;
                    Ok(())
                },
                Job::JExpand{prk, info, length, acc, prev, i, } => {
                    write!(_formatter, "EHBPEvents.Job.JExpand(<redacted>)")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Job {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Job::JExtract{salt, ikm, }, Job::JExtract{salt: _2_salt, ikm: _2_ikm, }) => {
                    salt == _2_salt && ikm == _2_ikm
                },
                (Job::JExpand{prk, info, length, acc, prev, i, }, Job::JExpand{prk: _2_prk, info: _2_info, length: _2_length, acc: _2_acc, prev: _2_prev, i: _2_i, }) => {
                    prk == _2_prk && info == _2_info && length == _2_length && acc == _2_acc && prev == _2_prev && i == _2_i
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Job {}

    impl Hash
        for Job {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Job::JExtract{salt, ikm, } => {
                    Hash::hash(salt, _state);
                    Hash::hash(ikm, _state)
                },
                Job::JExpand{prk, info, length, acc, prev, i, } => {
                    Hash::hash(prk, _state);
                    Hash::hash(info, _state);
                    Hash::hash(length, _state);
                    Hash::hash(acc, _state);
                    Hash::hash(prev, _state);
                    Hash::hash(i, _state)
                },
            }
        }
    }

    impl AsRef<Job>
        for Job {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(180,3)
    #[derive(Clone)]
    pub enum JobOut {
        Pending {
            job: Arc<Job>,
            action: Arc<Action>
        },
        Output {
            data: Sequence<u8>
        },
        JobFailed {
            code: Arc<Code>,
            message: Sequence<DafnyChar>
        }
    }

    impl JobOut {
        /// Gets the field job for all enum members which have it
        pub fn job(&self) -> &Arc<Job> {
            match self {
                JobOut::Pending{job, action, } => job,
                JobOut::Output{data, } => panic!("field does not exist on this variant"),
                JobOut::JobFailed{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field action for all enum members which have it
        pub fn action(&self) -> &Arc<Action> {
            match self {
                JobOut::Pending{job, action, } => action,
                JobOut::Output{data, } => panic!("field does not exist on this variant"),
                JobOut::JobFailed{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field data for all enum members which have it
        pub fn data(&self) -> &Sequence<u8> {
            match self {
                JobOut::Pending{job, action, } => panic!("field does not exist on this variant"),
                JobOut::Output{data, } => data,
                JobOut::JobFailed{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field code for all enum members which have it
        pub fn code(&self) -> &Arc<Code> {
            match self {
                JobOut::Pending{job, action, } => panic!("field does not exist on this variant"),
                JobOut::Output{data, } => panic!("field does not exist on this variant"),
                JobOut::JobFailed{code, message, } => code,
            }
        }
        /// Gets the field message for all enum members which have it
        pub fn message(&self) -> &Sequence<DafnyChar> {
            match self {
                JobOut::Pending{job, action, } => panic!("field does not exist on this variant"),
                JobOut::Output{data, } => panic!("field does not exist on this variant"),
                JobOut::JobFailed{code, message, } => message,
            }
        }
    }

    impl Debug
        for JobOut {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for JobOut {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                JobOut::Pending{job, action, } => {
                    write!(_formatter, "EHBPEvents.JobOut.Pending(")?;
                    DafnyPrint::fmt_print(job, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(action, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                JobOut::Output{data, } => {
                    write!(_formatter, "EHBPEvents.JobOut.Output(<redacted>)")?;
                    Ok(())
                },
                JobOut::JobFailed{code, message, } => {
                    write!(_formatter, "EHBPEvents.JobOut.JobFailed(")?;
                    DafnyPrint::fmt_print(code, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(message, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for JobOut {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (JobOut::Pending{job, action, }, JobOut::Pending{job: _2_job, action: _2_action, }) => {
                    job == _2_job && action == _2_action
                },
                (JobOut::Output{data, }, JobOut::Output{data: _2_data, }) => {
                    data == _2_data
                },
                (JobOut::JobFailed{code, message, }, JobOut::JobFailed{code: _2_code, message: _2_message, }) => {
                    code == _2_code && message == _2_message
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for JobOut {}

    impl Hash
        for JobOut {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                JobOut::Pending{job, action, } => {
                    Hash::hash(job, _state);
                    Hash::hash(action, _state)
                },
                JobOut::Output{data, } => {
                    Hash::hash(data, _state)
                },
                JobOut::JobFailed{code, message, } => {
                    Hash::hash(code, _state);
                    Hash::hash(message, _state)
                },
            }
        }
    }

    impl AsRef<JobOut>
        for JobOut {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(223,3)
    pub type Key = Sequence<u8>;

    /// An element of Key
    pub fn __init_Key() -> Sequence<u8> {
        {
            let _initializer = {
                    Arc::new(move |i: &DafnyInt| -> u8{
            0
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                };
            integer_range(Zero::zero(), int!(32)).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
        }
    }

    /// ehbp_events.dfy(224,3)
    pub type NonceBase = Sequence<u8>;

    /// An element of NonceBase
    pub fn __init_NonceBase() -> Sequence<u8> {
        {
            let _initializer = {
                    Arc::new(move |i: &DafnyInt| -> u8{
            0
        }) as Arc<dyn ::std::ops::Fn(&_) -> _ + Sync + ::std::marker::Send>
                };
            integer_range(Zero::zero(), int!(12)).map(move |i| _initializer(&i)).collect::<Sequence<_>>()
        }
    }

    /// ehbp_events.dfy(227,3)
    #[derive(Clone)]
    pub enum Ctx {
        Ctx {
            key: Key,
            baseNonce: NonceBase,
            exporterSecret: Sequence<u8>,
            seqNo: u64
        }
    }

    impl Ctx {
        /// Returns a borrow of the field key
        pub fn key(&self) -> &Key {
            match self {
                Ctx::Ctx{key, baseNonce, exporterSecret, seqNo, } => key,
            }
        }
        /// Returns a borrow of the field baseNonce
        pub fn baseNonce(&self) -> &NonceBase {
            match self {
                Ctx::Ctx{key, baseNonce, exporterSecret, seqNo, } => baseNonce,
            }
        }
        /// Returns a borrow of the field exporterSecret
        pub fn exporterSecret(&self) -> &Sequence<u8> {
            match self {
                Ctx::Ctx{key, baseNonce, exporterSecret, seqNo, } => exporterSecret,
            }
        }
        /// Returns a borrow of the field seqNo
        pub fn seqNo(&self) -> &u64 {
            match self {
                Ctx::Ctx{key, baseNonce, exporterSecret, seqNo, } => seqNo,
            }
        }
    }

    impl Debug
        for Ctx {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Ctx {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Ctx::Ctx{key, baseNonce, exporterSecret, seqNo, } => {
                    write!(_formatter, "EHBPEvents.Ctx.Ctx(<redacted>)")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Ctx {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Ctx::Ctx{key, baseNonce, exporterSecret, seqNo, }, Ctx::Ctx{key: _2_key, baseNonce: _2_baseNonce, exporterSecret: _2_exporterSecret, seqNo: _2_seqNo, }) => {
                    key == _2_key && baseNonce == _2_baseNonce && exporterSecret == _2_exporterSecret && seqNo == _2_seqNo
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Ctx {}

    impl Hash
        for Ctx {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Ctx::Ctx{key, baseNonce, exporterSecret, seqNo, } => {
                    Hash::hash(key, _state);
                    Hash::hash(baseNonce, _state);
                    Hash::hash(exporterSecret, _state);
                    Hash::hash(seqNo, _state)
                },
            }
        }
    }

    impl AsRef<Ctx>
        for Ctx {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(229,3)
    #[derive(Clone)]
    pub enum Hpke {
        HRandom {
            pkR: Sequence<u8>,
            info: Sequence<u8>
        },
        HEnc {
            skE: Sequence<u8>,
            pkR: Sequence<u8>,
            info: Sequence<u8>
        },
        HDh {
            enc: Sequence<u8>,
            pkR: Sequence<u8>,
            info: Sequence<u8>
        },
        HSchedule {
            stage: nat,
            job: Arc<Job>,
            enc: Sequence<u8>,
            pkR: Sequence<u8>,
            info: Sequence<u8>,
            shared: Sequence<u8>,
            pskIdHash: Sequence<u8>,
            infoHash: Sequence<u8>,
            secret: Sequence<u8>,
            key: Sequence<u8>,
            baseNonce: Sequence<u8>
        }
    }

    impl Hpke {
        /// Gets the field pkR for all enum members which have it
        pub fn pkR(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => pkR,
                Hpke::HEnc{skE, pkR, info, } => pkR,
                Hpke::HDh{enc, pkR, info, } => pkR,
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => pkR,
            }
        }
        /// Gets the field info for all enum members which have it
        pub fn info(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => info,
                Hpke::HEnc{skE, pkR, info, } => info,
                Hpke::HDh{enc, pkR, info, } => info,
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => info,
            }
        }
        /// Gets the field skE for all enum members which have it
        pub fn skE(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => skE,
                Hpke::HDh{enc, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field enc for all enum members which have it
        pub fn enc(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HDh{enc, pkR, info, } => enc,
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => enc,
            }
        }
        /// Gets the field stage for all enum members which have it
        pub fn stage(&self) -> &nat {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HDh{enc, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => stage,
            }
        }
        /// Gets the field job for all enum members which have it
        pub fn job(&self) -> &Arc<Job> {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HDh{enc, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => job,
            }
        }
        /// Gets the field shared for all enum members which have it
        pub fn shared(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HDh{enc, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => shared,
            }
        }
        /// Gets the field pskIdHash for all enum members which have it
        pub fn pskIdHash(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HDh{enc, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => pskIdHash,
            }
        }
        /// Gets the field infoHash for all enum members which have it
        pub fn infoHash(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HDh{enc, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => infoHash,
            }
        }
        /// Gets the field secret for all enum members which have it
        pub fn secret(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HDh{enc, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => secret,
            }
        }
        /// Gets the field key for all enum members which have it
        pub fn key(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HDh{enc, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => key,
            }
        }
        /// Gets the field baseNonce for all enum members which have it
        pub fn baseNonce(&self) -> &Sequence<u8> {
            match self {
                Hpke::HRandom{pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HEnc{skE, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HDh{enc, pkR, info, } => panic!("field does not exist on this variant"),
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => baseNonce,
            }
        }
    }

    impl Debug
        for Hpke {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Hpke {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Hpke::HRandom{pkR, info, } => {
                    write!(_formatter, "EHBPEvents.Hpke.HRandom(")?;
                    DafnyPrint::fmt_print(pkR, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(info, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Hpke::HEnc{skE, pkR, info, } => {
                    write!(_formatter, "EHBPEvents.Hpke.HEnc(<redacted>)")?;
                    Ok(())
                },
                Hpke::HDh{enc, pkR, info, } => {
                    write!(_formatter, "EHBPEvents.Hpke.HDh(")?;
                    DafnyPrint::fmt_print(enc, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(pkR, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(info, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => {
                    write!(_formatter, "EHBPEvents.Hpke.HSchedule(<redacted>)")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Hpke {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Hpke::HRandom{pkR, info, }, Hpke::HRandom{pkR: _2_pkR, info: _2_info, }) => {
                    pkR == _2_pkR && info == _2_info
                },
                (Hpke::HEnc{skE, pkR, info, }, Hpke::HEnc{skE: _2_skE, pkR: _2_pkR, info: _2_info, }) => {
                    skE == _2_skE && pkR == _2_pkR && info == _2_info
                },
                (Hpke::HDh{enc, pkR, info, }, Hpke::HDh{enc: _2_enc, pkR: _2_pkR, info: _2_info, }) => {
                    enc == _2_enc && pkR == _2_pkR && info == _2_info
                },
                (Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, }, Hpke::HSchedule{stage: _2_stage, job: _2_job, enc: _2_enc, pkR: _2_pkR, info: _2_info, shared: _2_shared, pskIdHash: _2_pskIdHash, infoHash: _2_infoHash, secret: _2_secret, key: _2_key, baseNonce: _2_baseNonce, }) => {
                    stage == _2_stage && job == _2_job && enc == _2_enc && pkR == _2_pkR && info == _2_info && shared == _2_shared && pskIdHash == _2_pskIdHash && infoHash == _2_infoHash && secret == _2_secret && key == _2_key && baseNonce == _2_baseNonce
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Hpke {}

    impl Hash
        for Hpke {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Hpke::HRandom{pkR, info, } => {
                    Hash::hash(pkR, _state);
                    Hash::hash(info, _state)
                },
                Hpke::HEnc{skE, pkR, info, } => {
                    Hash::hash(skE, _state);
                    Hash::hash(pkR, _state);
                    Hash::hash(info, _state)
                },
                Hpke::HDh{enc, pkR, info, } => {
                    Hash::hash(enc, _state);
                    Hash::hash(pkR, _state);
                    Hash::hash(info, _state)
                },
                Hpke::HSchedule{stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce, } => {
                    Hash::hash(stage, _state);
                    Hash::hash(job, _state);
                    Hash::hash(enc, _state);
                    Hash::hash(pkR, _state);
                    Hash::hash(info, _state);
                    Hash::hash(shared, _state);
                    Hash::hash(pskIdHash, _state);
                    Hash::hash(infoHash, _state);
                    Hash::hash(secret, _state);
                    Hash::hash(key, _state);
                    Hash::hash(baseNonce, _state)
                },
            }
        }
    }

    impl AsRef<Hpke>
        for Hpke {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(235,3)
    #[derive(Clone)]
    pub enum HpkeOut {
        HContinue {
            h: Arc<Hpke>,
            action: Arc<Action>
        },
        HReady {
            ctx: Arc<Ctx>,
            enc: Sequence<u8>
        },
        HFailed {
            code: Arc<Code>,
            message: Sequence<DafnyChar>
        }
    }

    impl HpkeOut {
        /// Gets the field h for all enum members which have it
        pub fn h(&self) -> &Arc<Hpke> {
            match self {
                HpkeOut::HContinue{h, action, } => h,
                HpkeOut::HReady{ctx, enc, } => panic!("field does not exist on this variant"),
                HpkeOut::HFailed{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field action for all enum members which have it
        pub fn action(&self) -> &Arc<Action> {
            match self {
                HpkeOut::HContinue{h, action, } => action,
                HpkeOut::HReady{ctx, enc, } => panic!("field does not exist on this variant"),
                HpkeOut::HFailed{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field ctx for all enum members which have it
        pub fn ctx(&self) -> &Arc<Ctx> {
            match self {
                HpkeOut::HContinue{h, action, } => panic!("field does not exist on this variant"),
                HpkeOut::HReady{ctx, enc, } => ctx,
                HpkeOut::HFailed{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field enc for all enum members which have it
        pub fn enc(&self) -> &Sequence<u8> {
            match self {
                HpkeOut::HContinue{h, action, } => panic!("field does not exist on this variant"),
                HpkeOut::HReady{ctx, enc, } => enc,
                HpkeOut::HFailed{code, message, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field code for all enum members which have it
        pub fn code(&self) -> &Arc<Code> {
            match self {
                HpkeOut::HContinue{h, action, } => panic!("field does not exist on this variant"),
                HpkeOut::HReady{ctx, enc, } => panic!("field does not exist on this variant"),
                HpkeOut::HFailed{code, message, } => code,
            }
        }
        /// Gets the field message for all enum members which have it
        pub fn message(&self) -> &Sequence<DafnyChar> {
            match self {
                HpkeOut::HContinue{h, action, } => panic!("field does not exist on this variant"),
                HpkeOut::HReady{ctx, enc, } => panic!("field does not exist on this variant"),
                HpkeOut::HFailed{code, message, } => message,
            }
        }
    }

    impl Debug
        for HpkeOut {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for HpkeOut {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                HpkeOut::HContinue{h, action, } => {
                    write!(_formatter, "EHBPEvents.HpkeOut.HContinue(")?;
                    DafnyPrint::fmt_print(h, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(action, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                HpkeOut::HReady{ctx, enc, } => {
                    write!(_formatter, "EHBPEvents.HpkeOut.HReady(")?;
                    DafnyPrint::fmt_print(ctx, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(enc, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                HpkeOut::HFailed{code, message, } => {
                    write!(_formatter, "EHBPEvents.HpkeOut.HFailed(")?;
                    DafnyPrint::fmt_print(code, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(message, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for HpkeOut {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (HpkeOut::HContinue{h, action, }, HpkeOut::HContinue{h: _2_h, action: _2_action, }) => {
                    h == _2_h && action == _2_action
                },
                (HpkeOut::HReady{ctx, enc, }, HpkeOut::HReady{ctx: _2_ctx, enc: _2_enc, }) => {
                    ctx == _2_ctx && enc == _2_enc
                },
                (HpkeOut::HFailed{code, message, }, HpkeOut::HFailed{code: _2_code, message: _2_message, }) => {
                    code == _2_code && message == _2_message
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for HpkeOut {}

    impl Hash
        for HpkeOut {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                HpkeOut::HContinue{h, action, } => {
                    Hash::hash(h, _state);
                    Hash::hash(action, _state)
                },
                HpkeOut::HReady{ctx, enc, } => {
                    Hash::hash(ctx, _state);
                    Hash::hash(enc, _state)
                },
                HpkeOut::HFailed{code, message, } => {
                    Hash::hash(code, _state);
                    Hash::hash(message, _state)
                },
            }
        }
    }

    impl AsRef<HpkeOut>
        for HpkeOut {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(300,3)
    #[derive(Clone)]
    pub enum Json {
        JNull {},
        JBool {
            b: bool
        },
        JNumber {
            raw: Sequence<DafnyChar>
        },
        JString {
            s: Sequence<DafnyChar>
        },
        JArray {
            items: Sequence<Arc<Json>>
        },
        JObject {
            members: Sequence<(Sequence<DafnyChar>, Arc<Json>)>
        }
    }

    impl Json {
        /// Gets the field b for all enum members which have it
        pub fn b(&self) -> &bool {
            match self {
                Json::JNull{} => panic!("field does not exist on this variant"),
                Json::JBool{b, } => b,
                Json::JNumber{raw, } => panic!("field does not exist on this variant"),
                Json::JString{s, } => panic!("field does not exist on this variant"),
                Json::JArray{items, } => panic!("field does not exist on this variant"),
                Json::JObject{members, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field raw for all enum members which have it
        pub fn raw(&self) -> &Sequence<DafnyChar> {
            match self {
                Json::JNull{} => panic!("field does not exist on this variant"),
                Json::JBool{b, } => panic!("field does not exist on this variant"),
                Json::JNumber{raw, } => raw,
                Json::JString{s, } => panic!("field does not exist on this variant"),
                Json::JArray{items, } => panic!("field does not exist on this variant"),
                Json::JObject{members, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field s for all enum members which have it
        pub fn s(&self) -> &Sequence<DafnyChar> {
            match self {
                Json::JNull{} => panic!("field does not exist on this variant"),
                Json::JBool{b, } => panic!("field does not exist on this variant"),
                Json::JNumber{raw, } => panic!("field does not exist on this variant"),
                Json::JString{s, } => s,
                Json::JArray{items, } => panic!("field does not exist on this variant"),
                Json::JObject{members, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field items for all enum members which have it
        pub fn items(&self) -> &Sequence<Arc<Json>> {
            match self {
                Json::JNull{} => panic!("field does not exist on this variant"),
                Json::JBool{b, } => panic!("field does not exist on this variant"),
                Json::JNumber{raw, } => panic!("field does not exist on this variant"),
                Json::JString{s, } => panic!("field does not exist on this variant"),
                Json::JArray{items, } => items,
                Json::JObject{members, } => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field members for all enum members which have it
        pub fn members(&self) -> &Sequence<(Sequence<DafnyChar>, Arc<Json>)> {
            match self {
                Json::JNull{} => panic!("field does not exist on this variant"),
                Json::JBool{b, } => panic!("field does not exist on this variant"),
                Json::JNumber{raw, } => panic!("field does not exist on this variant"),
                Json::JString{s, } => panic!("field does not exist on this variant"),
                Json::JArray{items, } => panic!("field does not exist on this variant"),
                Json::JObject{members, } => members,
            }
        }
    }

    impl Debug
        for Json {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Json {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Json::JNull{} => {
                    write!(_formatter, "EHBPEvents.Json.JNull")?;
                    Ok(())
                },
                Json::JBool{b, } => {
                    write!(_formatter, "EHBPEvents.Json.JBool(")?;
                    DafnyPrint::fmt_print(b, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Json::JNumber{raw, } => {
                    write!(_formatter, "EHBPEvents.Json.JNumber(")?;
                    DafnyPrint::fmt_print(raw, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Json::JString{s, } => {
                    write!(_formatter, "EHBPEvents.Json.JString(")?;
                    DafnyPrint::fmt_print(s, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Json::JArray{items, } => {
                    write!(_formatter, "EHBPEvents.Json.JArray(")?;
                    DafnyPrint::fmt_print(items, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Json::JObject{members, } => {
                    write!(_formatter, "EHBPEvents.Json.JObject(")?;
                    DafnyPrint::fmt_print(members, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Json {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Json::JNull{}, Json::JNull{}) => {
                    true
                },
                (Json::JBool{b, }, Json::JBool{b: _2_b, }) => {
                    b == _2_b
                },
                (Json::JNumber{raw, }, Json::JNumber{raw: _2_raw, }) => {
                    raw == _2_raw
                },
                (Json::JString{s, }, Json::JString{s: _2_s, }) => {
                    s == _2_s
                },
                (Json::JArray{items, }, Json::JArray{items: _2_items, }) => {
                    items == _2_items
                },
                (Json::JObject{members, }, Json::JObject{members: _2_members, }) => {
                    members == _2_members
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Json {}

    impl Hash
        for Json {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Json::JNull{} => {
                    
                },
                Json::JBool{b, } => {
                    Hash::hash(b, _state)
                },
                Json::JNumber{raw, } => {
                    Hash::hash(raw, _state)
                },
                Json::JString{s, } => {
                    Hash::hash(s, _state)
                },
                Json::JArray{items, } => {
                    Hash::hash(items, _state)
                },
                Json::JObject{members, } => {
                    Hash::hash(members, _state)
                },
            }
        }
    }

    impl AsRef<Json>
        for Json {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(703,3)
    #[derive(Clone)]
    pub enum SessionStore {
        SessionStore {
            generation: u64,
            token: Arc<Option<Arc<Token>>>
        }
    }

    impl SessionStore {
        /// Returns a borrow of the field generation
        pub fn generation(&self) -> &u64 {
            match self {
                SessionStore::SessionStore{generation, token, } => generation,
            }
        }
        /// Returns a borrow of the field token
        pub fn token(&self) -> &Arc<Option<Arc<Token>>> {
            match self {
                SessionStore::SessionStore{generation, token, } => token,
            }
        }
    }

    impl Debug
        for SessionStore {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for SessionStore {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                SessionStore::SessionStore{generation, token, } => {
                    write!(_formatter, "EHBPEvents.SessionStore.SessionStore(")?;
                    DafnyPrint::fmt_print(generation, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(token, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for SessionStore {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (SessionStore::SessionStore{generation, token, }, SessionStore::SessionStore{generation: _2_generation, token: _2_token, }) => {
                    generation == _2_generation && token == _2_token
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for SessionStore {}

    impl Hash
        for SessionStore {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                SessionStore::SessionStore{generation, token, } => {
                    Hash::hash(generation, _state);
                    Hash::hash(token, _state)
                },
            }
        }
    }

    impl AsRef<SessionStore>
        for SessionStore {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(705,3)
    #[derive(Clone)]
    pub enum SessionAction {
        Begin {},
        Publish {
            generation: u64,
            token: Arc<Token>
        },
        Clear {
            generation: u64
        }
    }

    impl SessionAction {
        /// Gets the field generation for all enum members which have it
        pub fn generation(&self) -> &u64 {
            match self {
                SessionAction::Begin{} => panic!("field does not exist on this variant"),
                SessionAction::Publish{generation, token, } => generation,
                SessionAction::Clear{generation, } => generation,
            }
        }
        /// Gets the field token for all enum members which have it
        pub fn token(&self) -> &Arc<Token> {
            match self {
                SessionAction::Begin{} => panic!("field does not exist on this variant"),
                SessionAction::Publish{generation, token, } => token,
                SessionAction::Clear{generation, } => panic!("field does not exist on this variant"),
            }
        }
    }

    impl Debug
        for SessionAction {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for SessionAction {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                SessionAction::Begin{} => {
                    write!(_formatter, "EHBPEvents.SessionAction.Begin")?;
                    Ok(())
                },
                SessionAction::Publish{generation, token, } => {
                    write!(_formatter, "EHBPEvents.SessionAction.Publish(")?;
                    DafnyPrint::fmt_print(generation, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(token, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                SessionAction::Clear{generation, } => {
                    write!(_formatter, "EHBPEvents.SessionAction.Clear(")?;
                    DafnyPrint::fmt_print(generation, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for SessionAction {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (SessionAction::Begin{}, SessionAction::Begin{}) => {
                    true
                },
                (SessionAction::Publish{generation, token, }, SessionAction::Publish{generation: _2_generation, token: _2_token, }) => {
                    generation == _2_generation && token == _2_token
                },
                (SessionAction::Clear{generation, }, SessionAction::Clear{generation: _2_generation, }) => {
                    generation == _2_generation
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for SessionAction {}

    impl Hash
        for SessionAction {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                SessionAction::Begin{} => {
                    
                },
                SessionAction::Publish{generation, token, } => {
                    Hash::hash(generation, _state);
                    Hash::hash(token, _state)
                },
                SessionAction::Clear{generation, } => {
                    Hash::hash(generation, _state)
                },
            }
        }
    }

    impl AsRef<SessionAction>
        for SessionAction {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(723,3)
    #[derive(Clone)]
    pub enum Dec {
        Dec {
            pending: Sequence<u8>,
            next: u64,
            authenticated: bool,
            requireFrame: bool
        }
    }

    impl Dec {
        /// Returns a borrow of the field pending
        pub fn pending(&self) -> &Sequence<u8> {
            match self {
                Dec::Dec{pending, next, authenticated, requireFrame, } => pending,
            }
        }
        /// Returns a borrow of the field next
        pub fn next(&self) -> &u64 {
            match self {
                Dec::Dec{pending, next, authenticated, requireFrame, } => next,
            }
        }
        /// Returns a borrow of the field authenticated
        pub fn authenticated(&self) -> &bool {
            match self {
                Dec::Dec{pending, next, authenticated, requireFrame, } => authenticated,
            }
        }
        /// Returns a borrow of the field requireFrame
        pub fn requireFrame(&self) -> &bool {
            match self {
                Dec::Dec{pending, next, authenticated, requireFrame, } => requireFrame,
            }
        }
    }

    impl Debug
        for Dec {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Dec {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Dec::Dec{pending, next, authenticated, requireFrame, } => {
                    write!(_formatter, "EHBPEvents.Dec.Dec(")?;
                    DafnyPrint::fmt_print(pending, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(next, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(authenticated, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(requireFrame, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Dec {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Dec::Dec{pending, next, authenticated, requireFrame, }, Dec::Dec{pending: _2_pending, next: _2_next, authenticated: _2_authenticated, requireFrame: _2_requireFrame, }) => {
                    pending == _2_pending && next == _2_next && authenticated == _2_authenticated && requireFrame == _2_requireFrame
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Dec {}

    impl Hash
        for Dec {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Dec::Dec{pending, next, authenticated, requireFrame, } => {
                    Hash::hash(pending, _state);
                    Hash::hash(next, _state);
                    Hash::hash(authenticated, _state);
                    Hash::hash(requireFrame, _state)
                },
            }
        }
    }

    impl AsRef<Dec>
        for Dec {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(775,3)
    pub type Chunk = Sequence<u8>;

    /// An element of Chunk
    pub fn __init_Chunk() -> Sequence<u8> {
        seq![] as Sequence<u8>
    }

    /// ehbp_events.dfy(778,3)
    #[derive(Clone)]
    pub enum Upload {
        NoUpload {},
        Sealing {
            plaintext: Chunk,
            offset: u32,
            eof: bool
        },
        UpReading {
            empty: nat
        },
        UpDone {}
    }

    impl Upload {
        /// Gets the field plaintext for all enum members which have it
        pub fn plaintext(&self) -> &Chunk {
            match self {
                Upload::NoUpload{} => panic!("field does not exist on this variant"),
                Upload::Sealing{plaintext, offset, eof, } => plaintext,
                Upload::UpReading{empty, } => panic!("field does not exist on this variant"),
                Upload::UpDone{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field offset for all enum members which have it
        pub fn offset(&self) -> &u32 {
            match self {
                Upload::NoUpload{} => panic!("field does not exist on this variant"),
                Upload::Sealing{plaintext, offset, eof, } => offset,
                Upload::UpReading{empty, } => panic!("field does not exist on this variant"),
                Upload::UpDone{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field eof for all enum members which have it
        pub fn eof(&self) -> &bool {
            match self {
                Upload::NoUpload{} => panic!("field does not exist on this variant"),
                Upload::Sealing{plaintext, offset, eof, } => eof,
                Upload::UpReading{empty, } => panic!("field does not exist on this variant"),
                Upload::UpDone{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field empty for all enum members which have it
        pub fn empty(&self) -> &nat {
            match self {
                Upload::NoUpload{} => panic!("field does not exist on this variant"),
                Upload::Sealing{plaintext, offset, eof, } => panic!("field does not exist on this variant"),
                Upload::UpReading{empty, } => empty,
                Upload::UpDone{} => panic!("field does not exist on this variant"),
            }
        }
    }

    impl Debug
        for Upload {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Upload {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Upload::NoUpload{} => {
                    write!(_formatter, "EHBPEvents.Upload.NoUpload")?;
                    Ok(())
                },
                Upload::Sealing{plaintext, offset, eof, } => {
                    write!(_formatter, "EHBPEvents.Upload.Sealing(")?;
                    DafnyPrint::fmt_print(plaintext, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(offset, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(eof, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Upload::UpReading{empty, } => {
                    write!(_formatter, "EHBPEvents.Upload.UpReading(")?;
                    DafnyPrint::fmt_print(empty, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Upload::UpDone{} => {
                    write!(_formatter, "EHBPEvents.Upload.UpDone")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Upload {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Upload::NoUpload{}, Upload::NoUpload{}) => {
                    true
                },
                (Upload::Sealing{plaintext, offset, eof, }, Upload::Sealing{plaintext: _2_plaintext, offset: _2_offset, eof: _2_eof, }) => {
                    plaintext == _2_plaintext && offset == _2_offset && eof == _2_eof
                },
                (Upload::UpReading{empty, }, Upload::UpReading{empty: _2_empty, }) => {
                    empty == _2_empty
                },
                (Upload::UpDone{}, Upload::UpDone{}) => {
                    true
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Upload {}

    impl Hash
        for Upload {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Upload::NoUpload{} => {
                    
                },
                Upload::Sealing{plaintext, offset, eof, } => {
                    Hash::hash(plaintext, _state);
                    Hash::hash(offset, _state);
                    Hash::hash(eof, _state)
                },
                Upload::UpReading{empty, } => {
                    Hash::hash(empty, _state)
                },
                Upload::UpDone{} => {
                    
                },
            }
        }
    }

    impl AsRef<Upload>
        for Upload {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(787,3)
    #[derive(Clone)]
    pub enum Response {
        AwaitHead {
            encrypted: bool
        },
        ProblemReading {
            status: DafnyInt,
            headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
            data: Sequence<u8>
        },
        AwaitKeys {
            status: DafnyInt,
            headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
            requireFrame: bool,
            stage: nat,
            job: Arc<Job>,
            prk: Sequence<u8>,
            key: Sequence<u8>
        },
        Body {
            keys: Arc<Ctx>,
            dec: Arc<Dec>,
            done: bool
        },
        BodyReading {
            keys: Arc<Ctx>,
            dec: Arc<Dec>
        },
        Opening {
            keys: Arc<Ctx>,
            dec: Arc<Dec>,
            frames: Sequence<Arc<Framed>>,
            chunks: Sequence<Sequence<u8>>,
            eof: bool
        },
        RespEnded {}
    }

    impl Response {
        /// Gets the field encrypted for all enum members which have it
        pub fn encrypted(&self) -> &bool {
            match self {
                Response::AwaitHead{encrypted, } => encrypted,
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => panic!("field does not exist on this variant"),
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field status for all enum members which have it
        pub fn status(&self) -> &DafnyInt {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => status,
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => status,
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field headers for all enum members which have it
        pub fn headers(&self) -> &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => headers,
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => headers,
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field data for all enum members which have it
        pub fn data(&self) -> &Sequence<u8> {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => data,
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => panic!("field does not exist on this variant"),
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field requireFrame for all enum members which have it
        pub fn requireFrame(&self) -> &bool {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => requireFrame,
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field stage for all enum members which have it
        pub fn stage(&self) -> &nat {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => stage,
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field job for all enum members which have it
        pub fn job(&self) -> &Arc<Job> {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => job,
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field prk for all enum members which have it
        pub fn prk(&self) -> &Sequence<u8> {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => prk,
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field key for all enum members which have it
        pub fn key(&self) -> &Sequence<u8> {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => key,
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field keys for all enum members which have it
        pub fn keys(&self) -> &Arc<Ctx> {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => panic!("field does not exist on this variant"),
                Response::Body{keys, dec, done, } => keys,
                Response::BodyReading{keys, dec, } => keys,
                Response::Opening{keys, dec, frames, chunks, eof, } => keys,
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field dec for all enum members which have it
        pub fn dec(&self) -> &Arc<Dec> {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => panic!("field does not exist on this variant"),
                Response::Body{keys, dec, done, } => dec,
                Response::BodyReading{keys, dec, } => dec,
                Response::Opening{keys, dec, frames, chunks, eof, } => dec,
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field done for all enum members which have it
        pub fn done(&self) -> &bool {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => panic!("field does not exist on this variant"),
                Response::Body{keys, dec, done, } => done,
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => panic!("field does not exist on this variant"),
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field frames for all enum members which have it
        pub fn frames(&self) -> &Sequence<Arc<Framed>> {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => panic!("field does not exist on this variant"),
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => frames,
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field chunks for all enum members which have it
        pub fn chunks(&self) -> &Sequence<Sequence<u8>> {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => panic!("field does not exist on this variant"),
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => chunks,
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field eof for all enum members which have it
        pub fn eof(&self) -> &bool {
            match self {
                Response::AwaitHead{encrypted, } => panic!("field does not exist on this variant"),
                Response::ProblemReading{status, headers, data, } => panic!("field does not exist on this variant"),
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => panic!("field does not exist on this variant"),
                Response::Body{keys, dec, done, } => panic!("field does not exist on this variant"),
                Response::BodyReading{keys, dec, } => panic!("field does not exist on this variant"),
                Response::Opening{keys, dec, frames, chunks, eof, } => eof,
                Response::RespEnded{} => panic!("field does not exist on this variant"),
            }
        }
    }

    impl Debug
        for Response {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Response {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Response::AwaitHead{encrypted, } => {
                    write!(_formatter, "EHBPEvents.Response.AwaitHead(")?;
                    DafnyPrint::fmt_print(encrypted, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Response::ProblemReading{status, headers, data, } => {
                    write!(_formatter, "EHBPEvents.Response.ProblemReading(")?;
                    DafnyPrint::fmt_print(status, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(headers, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(data, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => {
                    write!(_formatter, "EHBPEvents.Response.AwaitKeys(<redacted>)")?;
                    Ok(())
                },
                Response::Body{keys, dec, done, } => {
                    write!(_formatter, "EHBPEvents.Response.Body(")?;
                    DafnyPrint::fmt_print(keys, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(dec, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(done, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Response::BodyReading{keys, dec, } => {
                    write!(_formatter, "EHBPEvents.Response.BodyReading(")?;
                    DafnyPrint::fmt_print(keys, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(dec, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Response::Opening{keys, dec, frames, chunks, eof, } => {
                    write!(_formatter, "EHBPEvents.Response.Opening(")?;
                    DafnyPrint::fmt_print(keys, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(dec, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(frames, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(chunks, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(eof, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Response::RespEnded{} => {
                    write!(_formatter, "EHBPEvents.Response.RespEnded")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Response {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Response::AwaitHead{encrypted, }, Response::AwaitHead{encrypted: _2_encrypted, }) => {
                    encrypted == _2_encrypted
                },
                (Response::ProblemReading{status, headers, data, }, Response::ProblemReading{status: _2_status, headers: _2_headers, data: _2_data, }) => {
                    status == _2_status && headers == _2_headers && data == _2_data
                },
                (Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, }, Response::AwaitKeys{status: _2_status, headers: _2_headers, requireFrame: _2_requireFrame, stage: _2_stage, job: _2_job, prk: _2_prk, key: _2_key, }) => {
                    status == _2_status && headers == _2_headers && requireFrame == _2_requireFrame && stage == _2_stage && job == _2_job && prk == _2_prk && key == _2_key
                },
                (Response::Body{keys, dec, done, }, Response::Body{keys: _2_keys, dec: _2_dec, done: _2_done, }) => {
                    keys == _2_keys && dec == _2_dec && done == _2_done
                },
                (Response::BodyReading{keys, dec, }, Response::BodyReading{keys: _2_keys, dec: _2_dec, }) => {
                    keys == _2_keys && dec == _2_dec
                },
                (Response::Opening{keys, dec, frames, chunks, eof, }, Response::Opening{keys: _2_keys, dec: _2_dec, frames: _2_frames, chunks: _2_chunks, eof: _2_eof, }) => {
                    keys == _2_keys && dec == _2_dec && frames == _2_frames && chunks == _2_chunks && eof == _2_eof
                },
                (Response::RespEnded{}, Response::RespEnded{}) => {
                    true
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Response {}

    impl Hash
        for Response {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Response::AwaitHead{encrypted, } => {
                    Hash::hash(encrypted, _state)
                },
                Response::ProblemReading{status, headers, data, } => {
                    Hash::hash(status, _state);
                    Hash::hash(headers, _state);
                    Hash::hash(data, _state)
                },
                Response::AwaitKeys{status, headers, requireFrame, stage, job, prk, key, } => {
                    Hash::hash(status, _state);
                    Hash::hash(headers, _state);
                    Hash::hash(requireFrame, _state);
                    Hash::hash(stage, _state);
                    Hash::hash(job, _state);
                    Hash::hash(prk, _state);
                    Hash::hash(key, _state)
                },
                Response::Body{keys, dec, done, } => {
                    Hash::hash(keys, _state);
                    Hash::hash(dec, _state);
                    Hash::hash(done, _state)
                },
                Response::BodyReading{keys, dec, } => {
                    Hash::hash(keys, _state);
                    Hash::hash(dec, _state)
                },
                Response::Opening{keys, dec, frames, chunks, eof, } => {
                    Hash::hash(keys, _state);
                    Hash::hash(dec, _state);
                    Hash::hash(frames, _state);
                    Hash::hash(chunks, _state);
                    Hash::hash(eof, _state)
                },
                Response::RespEnded{} => {
                    
                },
            }
        }
    }

    impl AsRef<Response>
        for Response {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(797,3)
    #[derive(Clone)]
    pub enum Phase {
        Idle {},
        AwaitSession {
            hasBody: bool
        },
        Peeking {
            empty: nat
        },
        AwaitSetup {
            first: Chunk,
            firstEof: bool,
            hpke: Arc<Hpke>
        },
        AwaitExport {
            first: Chunk,
            firstEof: bool,
            enc: Sequence<u8>,
            job: Arc<Job>
        },
        Exchanging {
            upload: Arc<Upload>,
            response: Arc<Response>
        },
        DiscAwaitHead {},
        DiscReading {
            data: Sequence<u8>
        },
        Ended {}
    }

    impl Phase {
        /// Gets the field hasBody for all enum members which have it
        pub fn hasBody(&self) -> &bool {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => hasBody,
                Phase::Peeking{empty, } => panic!("field does not exist on this variant"),
                Phase::AwaitSetup{first, firstEof, hpke, } => panic!("field does not exist on this variant"),
                Phase::AwaitExport{first, firstEof, enc, job, } => panic!("field does not exist on this variant"),
                Phase::Exchanging{upload, response, } => panic!("field does not exist on this variant"),
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => panic!("field does not exist on this variant"),
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field empty for all enum members which have it
        pub fn empty(&self) -> &nat {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => panic!("field does not exist on this variant"),
                Phase::Peeking{empty, } => empty,
                Phase::AwaitSetup{first, firstEof, hpke, } => panic!("field does not exist on this variant"),
                Phase::AwaitExport{first, firstEof, enc, job, } => panic!("field does not exist on this variant"),
                Phase::Exchanging{upload, response, } => panic!("field does not exist on this variant"),
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => panic!("field does not exist on this variant"),
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field first for all enum members which have it
        pub fn first(&self) -> &Chunk {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => panic!("field does not exist on this variant"),
                Phase::Peeking{empty, } => panic!("field does not exist on this variant"),
                Phase::AwaitSetup{first, firstEof, hpke, } => first,
                Phase::AwaitExport{first, firstEof, enc, job, } => first,
                Phase::Exchanging{upload, response, } => panic!("field does not exist on this variant"),
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => panic!("field does not exist on this variant"),
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field firstEof for all enum members which have it
        pub fn firstEof(&self) -> &bool {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => panic!("field does not exist on this variant"),
                Phase::Peeking{empty, } => panic!("field does not exist on this variant"),
                Phase::AwaitSetup{first, firstEof, hpke, } => firstEof,
                Phase::AwaitExport{first, firstEof, enc, job, } => firstEof,
                Phase::Exchanging{upload, response, } => panic!("field does not exist on this variant"),
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => panic!("field does not exist on this variant"),
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field hpke for all enum members which have it
        pub fn hpke(&self) -> &Arc<Hpke> {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => panic!("field does not exist on this variant"),
                Phase::Peeking{empty, } => panic!("field does not exist on this variant"),
                Phase::AwaitSetup{first, firstEof, hpke, } => hpke,
                Phase::AwaitExport{first, firstEof, enc, job, } => panic!("field does not exist on this variant"),
                Phase::Exchanging{upload, response, } => panic!("field does not exist on this variant"),
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => panic!("field does not exist on this variant"),
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field enc for all enum members which have it
        pub fn enc(&self) -> &Sequence<u8> {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => panic!("field does not exist on this variant"),
                Phase::Peeking{empty, } => panic!("field does not exist on this variant"),
                Phase::AwaitSetup{first, firstEof, hpke, } => panic!("field does not exist on this variant"),
                Phase::AwaitExport{first, firstEof, enc, job, } => enc,
                Phase::Exchanging{upload, response, } => panic!("field does not exist on this variant"),
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => panic!("field does not exist on this variant"),
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field job for all enum members which have it
        pub fn job(&self) -> &Arc<Job> {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => panic!("field does not exist on this variant"),
                Phase::Peeking{empty, } => panic!("field does not exist on this variant"),
                Phase::AwaitSetup{first, firstEof, hpke, } => panic!("field does not exist on this variant"),
                Phase::AwaitExport{first, firstEof, enc, job, } => job,
                Phase::Exchanging{upload, response, } => panic!("field does not exist on this variant"),
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => panic!("field does not exist on this variant"),
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field upload for all enum members which have it
        pub fn upload(&self) -> &Arc<Upload> {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => panic!("field does not exist on this variant"),
                Phase::Peeking{empty, } => panic!("field does not exist on this variant"),
                Phase::AwaitSetup{first, firstEof, hpke, } => panic!("field does not exist on this variant"),
                Phase::AwaitExport{first, firstEof, enc, job, } => panic!("field does not exist on this variant"),
                Phase::Exchanging{upload, response, } => upload,
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => panic!("field does not exist on this variant"),
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field response for all enum members which have it
        pub fn response(&self) -> &Arc<Response> {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => panic!("field does not exist on this variant"),
                Phase::Peeking{empty, } => panic!("field does not exist on this variant"),
                Phase::AwaitSetup{first, firstEof, hpke, } => panic!("field does not exist on this variant"),
                Phase::AwaitExport{first, firstEof, enc, job, } => panic!("field does not exist on this variant"),
                Phase::Exchanging{upload, response, } => response,
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => panic!("field does not exist on this variant"),
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
        /// Gets the field data for all enum members which have it
        pub fn data(&self) -> &Sequence<u8> {
            match self {
                Phase::Idle{} => panic!("field does not exist on this variant"),
                Phase::AwaitSession{hasBody, } => panic!("field does not exist on this variant"),
                Phase::Peeking{empty, } => panic!("field does not exist on this variant"),
                Phase::AwaitSetup{first, firstEof, hpke, } => panic!("field does not exist on this variant"),
                Phase::AwaitExport{first, firstEof, enc, job, } => panic!("field does not exist on this variant"),
                Phase::Exchanging{upload, response, } => panic!("field does not exist on this variant"),
                Phase::DiscAwaitHead{} => panic!("field does not exist on this variant"),
                Phase::DiscReading{data, } => data,
                Phase::Ended{} => panic!("field does not exist on this variant"),
            }
        }
    }

    impl Debug
        for Phase {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for Phase {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                Phase::Idle{} => {
                    write!(_formatter, "EHBPEvents.Phase.Idle")?;
                    Ok(())
                },
                Phase::AwaitSession{hasBody, } => {
                    write!(_formatter, "EHBPEvents.Phase.AwaitSession(")?;
                    DafnyPrint::fmt_print(hasBody, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Phase::Peeking{empty, } => {
                    write!(_formatter, "EHBPEvents.Phase.Peeking(")?;
                    DafnyPrint::fmt_print(empty, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Phase::AwaitSetup{first, firstEof, hpke, } => {
                    write!(_formatter, "EHBPEvents.Phase.AwaitSetup(")?;
                    DafnyPrint::fmt_print(first, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(firstEof, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(hpke, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Phase::AwaitExport{first, firstEof, enc, job, } => {
                    write!(_formatter, "EHBPEvents.Phase.AwaitExport(")?;
                    DafnyPrint::fmt_print(first, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(firstEof, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(enc, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(job, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Phase::Exchanging{upload, response, } => {
                    write!(_formatter, "EHBPEvents.Phase.Exchanging(")?;
                    DafnyPrint::fmt_print(upload, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(response, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Phase::DiscAwaitHead{} => {
                    write!(_formatter, "EHBPEvents.Phase.DiscAwaitHead")?;
                    Ok(())
                },
                Phase::DiscReading{data, } => {
                    write!(_formatter, "EHBPEvents.Phase.DiscReading(")?;
                    DafnyPrint::fmt_print(data, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
                Phase::Ended{} => {
                    write!(_formatter, "EHBPEvents.Phase.Ended")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for Phase {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (Phase::Idle{}, Phase::Idle{}) => {
                    true
                },
                (Phase::AwaitSession{hasBody, }, Phase::AwaitSession{hasBody: _2_hasBody, }) => {
                    hasBody == _2_hasBody
                },
                (Phase::Peeking{empty, }, Phase::Peeking{empty: _2_empty, }) => {
                    empty == _2_empty
                },
                (Phase::AwaitSetup{first, firstEof, hpke, }, Phase::AwaitSetup{first: _2_first, firstEof: _2_firstEof, hpke: _2_hpke, }) => {
                    first == _2_first && firstEof == _2_firstEof && hpke == _2_hpke
                },
                (Phase::AwaitExport{first, firstEof, enc, job, }, Phase::AwaitExport{first: _2_first, firstEof: _2_firstEof, enc: _2_enc, job: _2_job, }) => {
                    first == _2_first && firstEof == _2_firstEof && enc == _2_enc && job == _2_job
                },
                (Phase::Exchanging{upload, response, }, Phase::Exchanging{upload: _2_upload, response: _2_response, }) => {
                    upload == _2_upload && response == _2_response
                },
                (Phase::DiscAwaitHead{}, Phase::DiscAwaitHead{}) => {
                    true
                },
                (Phase::DiscReading{data, }, Phase::DiscReading{data: _2_data, }) => {
                    data == _2_data
                },
                (Phase::Ended{}, Phase::Ended{}) => {
                    true
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for Phase {}

    impl Hash
        for Phase {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                Phase::Idle{} => {
                    
                },
                Phase::AwaitSession{hasBody, } => {
                    Hash::hash(hasBody, _state)
                },
                Phase::Peeking{empty, } => {
                    Hash::hash(empty, _state)
                },
                Phase::AwaitSetup{first, firstEof, hpke, } => {
                    Hash::hash(first, _state);
                    Hash::hash(firstEof, _state);
                    Hash::hash(hpke, _state)
                },
                Phase::AwaitExport{first, firstEof, enc, job, } => {
                    Hash::hash(first, _state);
                    Hash::hash(firstEof, _state);
                    Hash::hash(enc, _state);
                    Hash::hash(job, _state)
                },
                Phase::Exchanging{upload, response, } => {
                    Hash::hash(upload, _state);
                    Hash::hash(response, _state)
                },
                Phase::DiscAwaitHead{} => {
                    
                },
                Phase::DiscReading{data, } => {
                    Hash::hash(data, _state)
                },
                Phase::Ended{} => {
                    
                },
            }
        }
    }

    impl AsRef<Phase>
        for Phase {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// ehbp_events.dfy(808,3)
    #[derive(Clone)]
    pub enum State {
        State {
            phase: Arc<Phase>,
            origin: Arc<Origin>,
            publicKey: Sequence<u8>,
            verb: Sequence<DafnyChar>,
            url: Sequence<DafnyChar>,
            headers: Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)>,
            generation: u64,
            published: bool,
            token: Arc<Token>,
            ctx: Arc<Ctx>
        }
    }

    impl State {
        /// Returns a borrow of the field phase
        pub fn phase(&self) -> &Arc<Phase> {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => phase,
            }
        }
        /// Returns a borrow of the field origin
        pub fn origin(&self) -> &Arc<Origin> {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => origin,
            }
        }
        /// Returns a borrow of the field publicKey
        pub fn publicKey(&self) -> &Sequence<u8> {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => publicKey,
            }
        }
        /// Returns a borrow of the field verb
        pub fn verb(&self) -> &Sequence<DafnyChar> {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => verb,
            }
        }
        /// Returns a borrow of the field url
        pub fn url(&self) -> &Sequence<DafnyChar> {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => url,
            }
        }
        /// Returns a borrow of the field headers
        pub fn headers(&self) -> &Sequence<(Sequence<DafnyChar>, Sequence<DafnyChar>)> {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => headers,
            }
        }
        /// Returns a borrow of the field generation
        pub fn generation(&self) -> &u64 {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => generation,
            }
        }
        /// Returns a borrow of the field published
        pub fn published(&self) -> &bool {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => published,
            }
        }
        /// Returns a borrow of the field token
        pub fn token(&self) -> &Arc<Token> {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => token,
            }
        }
        /// Returns a borrow of the field ctx
        pub fn ctx(&self) -> &Arc<Ctx> {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => ctx,
            }
        }
    }

    impl Debug
        for State {
        fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
            DafnyPrint::fmt_print(self, f, true)
        }
    }

    impl DafnyPrint
        for State {
        fn fmt_print(&self, _formatter: &mut Formatter, _in_seq: bool) -> std::fmt::Result {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => {
                    write!(_formatter, "EHBPEvents.State.State(")?;
                    DafnyPrint::fmt_print(phase, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(origin, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(publicKey, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(verb, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(url, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(headers, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(generation, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(published, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(token, _formatter, false)?;
                    write!(_formatter, ", ")?;
                    DafnyPrint::fmt_print(ctx, _formatter, false)?;
                    write!(_formatter, ")")?;
                    Ok(())
                },
            }
        }
    }

    impl PartialEq
        for State {
        fn eq(&self, other: &Self) -> bool {
            match (
                    self,
                    other
                ) {
                (State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, }, State::State{phase: _2_phase, origin: _2_origin, publicKey: _2_publicKey, verb: _2_verb, url: _2_url, headers: _2_headers, generation: _2_generation, published: _2_published, token: _2_token, ctx: _2_ctx, }) => {
                    phase == _2_phase && origin == _2_origin && publicKey == _2_publicKey && verb == _2_verb && url == _2_url && headers == _2_headers && generation == _2_generation && published == _2_published && token == _2_token && ctx == _2_ctx
                },
                _ => {
                    false
                },
            }
        }
    }

    impl Eq
        for State {}

    impl Hash
        for State {
        fn hash<_H: Hasher>(&self, _state: &mut _H) {
            match self {
                State::State{phase, origin, publicKey, verb, url, headers, generation, published, token, ctx, } => {
                    Hash::hash(phase, _state);
                    Hash::hash(origin, _state);
                    Hash::hash(publicKey, _state);
                    Hash::hash(verb, _state);
                    Hash::hash(url, _state);
                    Hash::hash(headers, _state);
                    Hash::hash(generation, _state);
                    Hash::hash(published, _state);
                    Hash::hash(token, _state);
                    Hash::hash(ctx, _state)
                },
            }
        }
    }

    impl AsRef<State>
        for State {
        fn as_ref(&self) -> &Self {
            self
        }
    }
}