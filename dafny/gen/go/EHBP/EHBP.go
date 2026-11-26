// Package EHBP
// Dafny module EHBP compiled into Go

package EHBP

import (
	os "os"

	m__System "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/System_"
	_dafny "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/dafny"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__

type Dummy__ struct{}

// Definition of class Default__
type Default__ struct {
	dummy byte
}

func New_Default___() *Default__ {
	_this := Default__{}

	return &_this
}

type CompanionStruct_Default___ struct {
}

var Companion_Default___ = CompanionStruct_Default___{}

func (_this *Default__) Equals(other *Default__) bool {
	return _this == other
}

func (_this *Default__) EqualsGeneric(x interface{}) bool {
	other, ok := x.(*Default__)
	return ok && _this.Equals(other)
}

func (*Default__) String() string {
	return "EHBP.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) CheckPublicKey(b _dafny.Sequence) Result {
	if (_dafny.IntOfUint32((b).Cardinality())).Cmp(_dafny.IntOfInt64(32)) == 0 {
		var _0_key _dafny.Sequence = b
		_ = _0_key
		return Companion_Result_.Create_Ok_(_0_key)
	} else {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidKeyConfig_(), _dafny.UnicodeSeqOfUtf8Bytes("public key must be 32 bytes"))
	}
}
func (_static *CompanionStruct_Default___) CodeString(c Code) _dafny.Sequence {
	var _source0 Code = c
	_ = _source0
	{
		if _source0.Is_InvalidKeyConfig() {
			return _dafny.UnicodeSeqOfUtf8Bytes("INVALID_KEY_CONFIG")
		}
	}
	{
		if _source0.Is_UnsupportedSuite() {
			return _dafny.UnicodeSeqOfUtf8Bytes("UNSUPPORTED_SUITE")
		}
	}
	{
		if _source0.Is_InvalidEncapsulatedKey() {
			return _dafny.UnicodeSeqOfUtf8Bytes("INVALID_ENCAPSULATED_KEY")
		}
	}
	{
		if _source0.Is_HpkeSetupFailed() {
			return _dafny.UnicodeSeqOfUtf8Bytes("HPKE_SETUP_FAILED")
		}
	}
	{
		if _source0.Is_MissingResponseNonce() {
			return _dafny.UnicodeSeqOfUtf8Bytes("MISSING_RESPONSE_NONCE")
		}
	}
	{
		if _source0.Is_UnexpectedRedirect() {
			return _dafny.UnicodeSeqOfUtf8Bytes("UNEXPECTED_REDIRECT")
		}
	}
	{
		if _source0.Is_InvalidResponseNonce() {
			return _dafny.UnicodeSeqOfUtf8Bytes("INVALID_RESPONSE_NONCE")
		}
	}
	{
		if _source0.Is_DuplicateResponseNonce() {
			return _dafny.UnicodeSeqOfUtf8Bytes("DUPLICATE_RESPONSE_NONCE")
		}
	}
	{
		if _source0.Is_KeyConfigMismatch() {
			return _dafny.UnicodeSeqOfUtf8Bytes("KEY_CONFIG_MISMATCH")
		}
	}
	{
		if _source0.Is_FramingTruncated() {
			return _dafny.UnicodeSeqOfUtf8Bytes("FRAMING_TRUNCATED")
		}
	}
	{
		if _source0.Is_ChunkTooLarge() {
			return _dafny.UnicodeSeqOfUtf8Bytes("CHUNK_TOO_LARGE")
		}
	}
	{
		if _source0.Is_AeadDecryptFailed() {
			return _dafny.UnicodeSeqOfUtf8Bytes("AEAD_DECRYPT_FAILED")
		}
	}
	{
		if _source0.Is_SequenceOverflow() {
			return _dafny.UnicodeSeqOfUtf8Bytes("SEQUENCE_OVERFLOW")
		}
	}
	{
		if _source0.Is_InvalidToken() {
			return _dafny.UnicodeSeqOfUtf8Bytes("INVALID_TOKEN")
		}
	}
	{
		if _source0.Is_InvalidInput() {
			return _dafny.UnicodeSeqOfUtf8Bytes("INVALID_INPUT")
		}
	}
	{
		return _dafny.UnicodeSeqOfUtf8Bytes("")
	}
}
func (_static *CompanionStruct_Default___) U16(b _dafny.Sequence, i _dafny.Int) uint16 {
	return ((uint16((b).Select((i).Uint32()).(uint8))) * (uint16(256))) + (uint16((b).Select(((i).Plus(_dafny.One)).Uint32()).(uint8)))
}
func (_static *CompanionStruct_Default___) U32(b _dafny.Sequence, i _dafny.Int) uint32 {
	return ((uint32(Companion_Default___.U16(b, i))) * (uint32(65536))) + (uint32(Companion_Default___.U16(b, (i).Plus(_dafny.IntOfInt64(2)))))
}
func (_static *CompanionStruct_Default___) BE16(v uint16) _dafny.Sequence {
	return _dafny.SeqOf(uint8((v)/(uint16(256))), uint8((v)%(uint16(256))))
}
func (_static *CompanionStruct_Default___) BE32(v uint32) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(Companion_Default___.BE16(uint16((v)/(uint32(65536)))), Companion_Default___.BE16(uint16((v)%(uint32(65536)))))
}
func (_static *CompanionStruct_Default___) IsAscii(s _dafny.Sequence) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((s).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0)) || ((_dafny.IntOfInt32(rune((s).Select((_0_i).Uint32()).(_dafny.CodePoint)))).Cmp(_dafny.IntOfInt64(128)) < 0)
	})
}
func (_static *CompanionStruct_Default___) Ascii(s _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((s).Cardinality())).Uint32(), func(coer0 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg0 _dafny.Int) interface{} {
			return coer0(arg0)
		}
	}((func(_0_s _dafny.Sequence) func(_dafny.Int) uint8 {
		return func(_1_i _dafny.Int) uint8 {
			return (_dafny.IntOfInt32(rune((_0_s).Select((_1_i).Uint32()).(_dafny.CodePoint)))).Uint8()
		}
	})(s)))
}
func (_static *CompanionStruct_Default___) LowerChar(c _dafny.CodePoint) _dafny.CodePoint {
	if ((_dafny.CodePoint('A')) <= (c)) && ((c) <= (_dafny.CodePoint('Z'))) {
		return _dafny.CodePoint(((_dafny.IntOfInt32(rune(c))).Plus(_dafny.IntOfInt64(32))).Int32())
	} else {
		return c
	}
}
func (_static *CompanionStruct_Default___) Lower(s _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((s).Cardinality())).Uint32(), func(coer1 func(_dafny.Int) _dafny.CodePoint) func(_dafny.Int) interface{} {
		return func(arg1 _dafny.Int) interface{} {
			return coer1(arg1)
		}
	}((func(_0_s _dafny.Sequence) func(_dafny.Int) _dafny.CodePoint {
		return func(_1_i _dafny.Int) _dafny.CodePoint {
			return Companion_Default___.LowerChar((_0_s).Select((_1_i).Uint32()).(_dafny.CodePoint))
		}
	})(s)))
}
func (_static *CompanionStruct_Default___) EqualFold(a _dafny.Sequence, b _dafny.Sequence) bool {
	return _dafny.Companion_Sequence_.Equal(Companion_Default___.Lower(a), Companion_Default___.Lower(b))
}
func (_static *CompanionStruct_Default___) IsSpace(c _dafny.CodePoint) bool {
	return ((c) == (_dafny.CodePoint(' '))) || ((c) == (_dafny.CodePoint('\t')))
}
func (_static *CompanionStruct_Default___) TrimLeft(s _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if ((_dafny.IntOfUint32((s).Cardinality())).Sign() == 1) && (Companion_Default___.IsSpace((s).Select(0).(_dafny.CodePoint))) {
		var _in0 _dafny.Sequence = (s).Drop(1)
		_ = _in0
		s = _in0
		goto TAIL_CALL_START
	} else {
		return s
	}
}
func (_static *CompanionStruct_Default___) TrimRight(s _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if ((_dafny.IntOfUint32((s).Cardinality())).Sign() == 1) && (Companion_Default___.IsSpace((s).Select(((_dafny.IntOfUint32((s).Cardinality())).Minus(_dafny.One)).Uint32()).(_dafny.CodePoint))) {
		var _in0 _dafny.Sequence = (s).Take(((_dafny.IntOfUint32((s).Cardinality())).Minus(_dafny.One)).Uint32())
		_ = _in0
		s = _in0
		goto TAIL_CALL_START
	} else {
		return s
	}
}
func (_static *CompanionStruct_Default___) Trim(s _dafny.Sequence) _dafny.Sequence {
	return Companion_Default___.TrimRight(Companion_Default___.TrimLeft(s))
}
func (_static *CompanionStruct_Default___) Before(s _dafny.Sequence, sep _dafny.CodePoint) _dafny.Sequence {
	return Companion_Default___.BeforeFrom(s, sep, _dafny.Zero)
}
func (_static *CompanionStruct_Default___) BeforeFrom(s _dafny.Sequence, sep _dafny.CodePoint, i _dafny.Int) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if ((i).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0) || (((s).Select((i).Uint32()).(_dafny.CodePoint)) == (sep)) {
		return (s).Take((i).Uint32())
	} else {
		var _in0 _dafny.Sequence = s
		_ = _in0
		var _in1 _dafny.CodePoint = sep
		_ = _in1
		var _in2 _dafny.Int = (i).Plus(_dafny.One)
		_ = _in2
		s = _in0
		sep = _in1
		i = _in2
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) MediaType(contentType _dafny.Sequence) _dafny.Sequence {
	return Companion_Default___.Lower(Companion_Default___.Trim(Companion_Default___.Before(contentType, _dafny.CodePoint(';'))))
}
func (_static *CompanionStruct_Default___) HasMediaType(contentType Option, want _dafny.Sequence) bool {
	return ((contentType).Is_Some()) && (_dafny.Companion_Sequence_.Equal(Companion_Default___.MediaType((contentType).Dtor_value().(_dafny.Sequence)), Companion_Default___.Lower(want)))
}
func (_static *CompanionStruct_Default___) HexDigitValue(c _dafny.CodePoint) Option {
	if ((_dafny.CodePoint('0')) <= (c)) && ((c) <= (_dafny.CodePoint('9'))) {
		return Companion_Option_.Create_Some_(((_dafny.IntOfInt32(rune(c))).Minus(_dafny.IntOfInt32(rune(_dafny.CodePoint('0'))))).Uint8())
	} else if ((_dafny.CodePoint('a')) <= (c)) && ((c) <= (_dafny.CodePoint('f'))) {
		return Companion_Option_.Create_Some_((((_dafny.IntOfInt32(rune(c))).Minus(_dafny.IntOfInt32(rune(_dafny.CodePoint('a'))))).Plus(_dafny.IntOfInt64(10))).Uint8())
	} else if ((_dafny.CodePoint('A')) <= (c)) && ((c) <= (_dafny.CodePoint('F'))) {
		return Companion_Option_.Create_Some_((((_dafny.IntOfInt32(rune(c))).Minus(_dafny.IntOfInt32(rune(_dafny.CodePoint('A'))))).Plus(_dafny.IntOfInt64(10))).Uint8())
	} else {
		return Companion_Option_.Create_None_()
	}
}
func (_static *CompanionStruct_Default___) IsHex(s _dafny.Sequence) bool {
	return (((_dafny.IntOfUint32((s).Cardinality())).Modulo(_dafny.IntOfInt64(2))).Sign() == 0) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((s).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0)) || ((Companion_Default___.HexDigitValue((s).Select((_0_i).Uint32()).(_dafny.CodePoint))).Is_Some())
	}))
}
func (_static *CompanionStruct_Default___) DecodeHex(s _dafny.Sequence) Option {
	if !(Companion_Default___.IsHex(s)) {
		return Companion_Option_.Create_None_()
	} else {
		return Companion_Option_.Create_Some_(_dafny.SeqCreate(((_dafny.IntOfUint32((s).Cardinality())).DivBy(_dafny.IntOfInt64(2))).Uint32(), func(coer2 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
			return func(arg2 _dafny.Int) interface{} {
				return coer2(arg2)
			}
		}((func(_0_s _dafny.Sequence) func(_dafny.Int) uint8 {
			return func(_1_i _dafny.Int) uint8 {
				return (((Companion_Default___.HexDigitValue((_0_s).Select(((_dafny.IntOfInt64(2)).Times(_1_i)).Uint32()).(_dafny.CodePoint))).Dtor_value().(uint8)) * (uint8(16))) + ((Companion_Default___.HexDigitValue((_0_s).Select((((_dafny.IntOfInt64(2)).Times(_1_i)).Plus(_dafny.One)).Uint32()).(_dafny.CodePoint))).Dtor_value().(uint8))
			}
		})(s))))
	}
}
func (_static *CompanionStruct_Default___) EncodeHex(b _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate(((_dafny.IntOfInt64(2)).Times(_dafny.IntOfUint32((b).Cardinality()))).Uint32(), func(coer3 func(_dafny.Int) _dafny.CodePoint) func(_dafny.Int) interface{} {
		return func(arg3 _dafny.Int) interface{} {
			return coer3(arg3)
		}
	}((func(_0_b _dafny.Sequence) func(_dafny.Int) _dafny.CodePoint {
		return func(_1_i _dafny.Int) _dafny.CodePoint {
			return (func() _dafny.CodePoint {
				if ((_1_i).Modulo(_dafny.IntOfInt64(2))).Sign() == 0 {
					return (Companion_Default___.HexDigits()).Select(((_dafny.IntOfUint8((_0_b).Select(((_1_i).DivBy(_dafny.IntOfInt64(2))).Uint32()).(uint8))).DivBy(_dafny.IntOfInt64(16))).Uint32()).(_dafny.CodePoint)
				}
				return (Companion_Default___.HexDigits()).Select(((_dafny.IntOfUint8((_0_b).Select(((_1_i).DivBy(_dafny.IntOfInt64(2))).Uint32()).(uint8))).Modulo(_dafny.IntOfInt64(16))).Uint32()).(_dafny.CodePoint)
			})()
		}
	})(b)))
}
func (_static *CompanionStruct_Default___) ComputeNonce(nonceBase _dafny.Sequence, seqNo uint64) _dafny.Sequence {
	return _dafny.SeqCreate((Companion_Default___.NonceLength()).Uint32(), func(coer4 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg4 _dafny.Int) interface{} {
			return coer4(arg4)
		}
	}((func(_0_nonceBase _dafny.Sequence, _1_seqNo uint64) func(_dafny.Int) uint8 {
		return func(_2_i _dafny.Int) uint8 {
			return func(_pat_let0_0 uint32) uint8 {
				return func(_3_j uint32) uint8 {
					return (func() uint8 {
						if (_3_j) < (uint32(4)) {
							return (_0_nonceBase).Select(uint32(_3_j)).(uint8)
						}
						return uint8((uint8((_0_nonceBase).Select(uint32(_3_j)).(uint8))) ^ (uint8(Companion_Default___.ByteAt(_1_seqNo, (uint32(11))-(func() uint32 { return (_3_j) })()))))
					})()
				}(_pat_let0_0)
			}((_2_i).Uint32())
		}
	})(nonceBase, seqNo)))
}
func (_static *CompanionStruct_Default___) NonceFor(nonceBase _dafny.Sequence, seqNo uint64) Result {
	if (_dafny.IntOfUint32((nonceBase).Cardinality())).Cmp(Companion_Default___.NonceLength()) != 0 {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidInput_(), _dafny.UnicodeSeqOfUtf8Bytes("nonce base must be 12 bytes"))
	} else {
		return Companion_Result_.Create_Ok_(Companion_Default___.ComputeNonce(nonceBase, seqNo))
	}
}
func (_static *CompanionStruct_Default___) ByteAt(x uint64, k uint32) uint8 {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (k) == (uint32(0)) {
		return uint8((x) % (uint64(256)))
	} else {
		var _in0 uint64 = (x) / (uint64(256))
		_ = _in0
		var _in1 uint32 = (k) - (func() uint32 { return (uint32(1)) })()
		_ = _in1
		x = _in0
		k = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) KnownKdf(id uint16) bool {
	return (((id) == (uint16(1))) || ((id) == (uint16(2)))) || ((id) == (uint16(3)))
}
func (_static *CompanionStruct_Default___) KnownAead(id uint16) bool {
	return (((id) == (uint16(1))) || ((id) == (uint16(2)))) || ((id) == (uint16(3)))
}
func (_static *CompanionStruct_Default___) ParseConfig(data _dafny.Sequence) Result {
	if (_dafny.IntOfUint32((data).Cardinality())).Cmp(_dafny.IntOfInt64(3)) < 0 {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidKeyConfig_(), _dafny.UnicodeSeqOfUtf8Bytes("invalid config"))
	} else if (Companion_Default___.U16(data, _dafny.One)) != (Companion_Default___.KemX25519()) /* dircomp */ {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_UnsupportedSuite_(), _dafny.UnicodeSeqOfUtf8Bytes("unsupported KEM"))
	} else if (_dafny.IntOfUint32((data).Cardinality())).Cmp(((_dafny.IntOfInt64(3)).Plus(Companion_Default___.PublicKeyLength())).Plus(_dafny.IntOfInt64(2))) < 0 {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidKeyConfig_(), _dafny.UnicodeSeqOfUtf8Bytes("invalid config"))
	} else {
		var _0_pk _dafny.Sequence = (data).Subsequence(3, ((_dafny.IntOfInt64(3)).Plus(Companion_Default___.PublicKeyLength())).Uint32())
		_ = _0_pk
		var _1_suitesLen _dafny.Int = _dafny.IntOfUint16(Companion_Default___.U16(data, (_dafny.IntOfInt64(3)).Plus(Companion_Default___.PublicKeyLength())))
		_ = _1_suitesLen
		var _2_start _dafny.Int = ((_dafny.IntOfInt64(3)).Plus(Companion_Default___.PublicKeyLength())).Plus(_dafny.IntOfInt64(2))
		_ = _2_start
		if (_dafny.IntOfUint32((data).Cardinality())).Cmp((_2_start).Plus(_1_suitesLen)) < 0 {
			return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidKeyConfig_(), _dafny.UnicodeSeqOfUtf8Bytes("invalid config"))
		} else {
			var _source0 Result = Companion_Default___.ParseSuites((data).Subsequence((_2_start).Uint32(), ((_2_start).Plus(_1_suitesLen)).Uint32()))
			_ = _source0
			{
				if _source0.Is_Err() {
					var _3_code Code = _source0.Get_().(Result_Err).Code
					_ = _3_code
					var _4_message _dafny.Sequence = _source0.Get_().(Result_Err).Message
					_ = _4_message
					return Companion_Result_.Create_Err_(_3_code, _4_message)
				}
			}
			{
				var _5_suites _dafny.Sequence = _source0.Get_().(Result_Ok).Value.(_dafny.Sequence)
				_ = _5_suites
				if (_dafny.IntOfUint32((_5_suites).Cardinality())).Sign() == 0 {
					return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidKeyConfig_(), _dafny.UnicodeSeqOfUtf8Bytes("no cipher suites found in config"))
				} else if (_dafny.IntOfUint32((_5_suites).Cardinality())).Cmp(_dafny.One) != 0 {
					return Companion_Result_.Create_Err_(Companion_Code_.Create_UnsupportedSuite_(), _dafny.UnicodeSeqOfUtf8Bytes("expected exactly one cipher suite"))
				} else if !((_5_suites).Select(0).(_dafny.Tuple)).Equals(_dafny.TupleOf(Companion_Default___.KdfHkdfSha256(), Companion_Default___.AeadAes256Gcm())) {
					return Companion_Result_.Create_Err_(Companion_Code_.Create_UnsupportedSuite_(), _dafny.UnicodeSeqOfUtf8Bytes("unsupported cipher suite"))
				} else {
					return Companion_Result_.Create_Ok_(_0_pk)
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) ParseSuites(s _dafny.Sequence) Result {
	return Companion_Default___.ParseSuitesFrom(s, _dafny.Zero, _dafny.SeqOf())
}
func (_static *CompanionStruct_Default___) ParseSuitesFrom(s _dafny.Sequence, i _dafny.Int, acc _dafny.Sequence) Result {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (i).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
		return Companion_Result_.Create_Ok_(acc)
	} else if ((_dafny.IntOfUint32((s).Cardinality())).Minus(i)).Cmp(_dafny.IntOfInt64(4)) < 0 {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidKeyConfig_(), _dafny.UnicodeSeqOfUtf8Bytes("invalid config"))
	} else {
		var _0_kdf uint16 = Companion_Default___.U16(s, i)
		_ = _0_kdf
		var _1_aead uint16 = Companion_Default___.U16(s, (i).Plus(_dafny.IntOfInt64(2)))
		_ = _1_aead
		if !(Companion_Default___.KnownKdf(_0_kdf)) {
			return Companion_Result_.Create_Err_(Companion_Code_.Create_UnsupportedSuite_(), _dafny.UnicodeSeqOfUtf8Bytes("invalid KDF"))
		} else if !(Companion_Default___.KnownAead(_1_aead)) {
			return Companion_Result_.Create_Err_(Companion_Code_.Create_UnsupportedSuite_(), _dafny.UnicodeSeqOfUtf8Bytes("invalid AEAD"))
		} else {
			var _in0 _dafny.Sequence = s
			_ = _in0
			var _in1 _dafny.Int = (i).Plus(_dafny.IntOfInt64(4))
			_ = _in1
			var _in2 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.TupleOf(_0_kdf, _1_aead)))
			_ = _in2
			s = _in0
			i = _in1
			acc = _in2
			goto TAIL_CALL_START
		}
	}
}
func (_static *CompanionStruct_Default___) MarshalConfig(publicKey _dafny.Sequence) Result {
	if (_dafny.IntOfUint32((publicKey).Cardinality())).Cmp(Companion_Default___.PublicKeyLength()) != 0 {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidKeyConfig_(), _dafny.UnicodeSeqOfUtf8Bytes("invalid public key"))
	} else {
		return Companion_Result_.Create_Ok_(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(uint8(0)), Companion_Default___.BE16(Companion_Default___.KemX25519())), publicKey), Companion_Default___.BE16(uint16(4))), Companion_Default___.BE16(Companion_Default___.KdfHkdfSha256())), Companion_Default___.BE16(Companion_Default___.AeadAes256Gcm())))
	}
}
func (_static *CompanionStruct_Default___) ValidToken(t Token) bool {
	return ((_dafny.IntOfUint32(((t).Dtor_exportedSecret()).Cardinality())).Cmp(Companion_Default___.ExportLength()) == 0) && ((_dafny.IntOfUint32(((t).Dtor_requestEnc()).Cardinality())).Cmp(Companion_Default___.RequestEncLength()) == 0)
}
func (_static *CompanionStruct_Default___) ValidateTokenFields(exportedSecretHex Option, requestEncHex Option) Result {
	if ((exportedSecretHex).Is_None()) || ((requestEncHex).Is_None()) {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidToken_(), _dafny.UnicodeSeqOfUtf8Bytes("token field missing"))
	} else {
		var _source0 _dafny.Tuple = _dafny.TupleOf(Companion_Default___.DecodeHex((exportedSecretHex).Dtor_value().(_dafny.Sequence)), Companion_Default___.DecodeHex((requestEncHex).Dtor_value().(_dafny.Sequence)))
		_ = _source0
		{
			var _00 Option = (*(_source0).IndexInt(0)).(Option)
			_ = _00
			if _00.Is_Some() {
				var _0_secret _dafny.Sequence = _00.Get_().(Option_Some).Value.(_dafny.Sequence)
				_ = _0_secret
				var _10 Option = (*(_source0).IndexInt(1)).(Option)
				_ = _10
				if _10.Is_Some() {
					var _1_enc _dafny.Sequence = _10.Get_().(Option_Some).Value.(_dafny.Sequence)
					_ = _1_enc
					if ((_dafny.IntOfUint32((_0_secret).Cardinality())).Cmp(Companion_Default___.ExportLength()) != 0) || ((_dafny.IntOfUint32((_1_enc).Cardinality())).Cmp(Companion_Default___.RequestEncLength()) != 0) {
						return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidToken_(), _dafny.UnicodeSeqOfUtf8Bytes("token field has wrong length"))
					} else {
						return Companion_Result_.Create_Ok_(Companion_Token_.Create_Token_(_0_secret, _1_enc))
					}
				}
			}
		}
		{
			return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidToken_(), _dafny.UnicodeSeqOfUtf8Bytes("token field is not hex"))
		}
	}
}
func (_static *CompanionStruct_Default___) Frame(ciphertext _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(Companion_Default___.BE32(uint32((ciphertext).Cardinality())), ciphertext)
}
func (_static *CompanionStruct_Default___) HeaderValues(headers _dafny.Sequence, name _dafny.Sequence) _dafny.Sequence {
	return Companion_Default___.HeaderValuesFrom(headers, name, _dafny.Zero, _dafny.SeqOf())
}
func (_static *CompanionStruct_Default___) HeaderValuesFrom(headers _dafny.Sequence, name _dafny.Sequence, i _dafny.Int, acc _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (i).Cmp(_dafny.IntOfUint32((headers).Cardinality())) == 0 {
		return acc
	} else {
		var _in0 _dafny.Sequence = headers
		_ = _in0
		var _in1 _dafny.Sequence = name
		_ = _in1
		var _in2 _dafny.Int = (i).Plus(_dafny.One)
		_ = _in2
		var _in3 _dafny.Sequence = (func() _dafny.Sequence {
			if Companion_Default___.EqualFold((*((headers).Select((i).Uint32()).(_dafny.Tuple)).IndexInt(0)).(_dafny.Sequence), name) {
				return _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf((*((headers).Select((i).Uint32()).(_dafny.Tuple)).IndexInt(1)).(_dafny.Sequence)))
			}
			return acc
		})()
		_ = _in3
		headers = _in0
		name = _in1
		i = _in2
		acc = _in3
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) FirstHeader(headers _dafny.Sequence, name _dafny.Sequence) Option {
	var _0_values _dafny.Sequence = Companion_Default___.HeaderValues(headers, name)
	_ = _0_values
	if (_dafny.IntOfUint32((_0_values).Cardinality())).Sign() == 0 {
		return Companion_Option_.Create_None_()
	} else {
		return Companion_Option_.Create_Some_((_0_values).Select(0).(_dafny.Sequence))
	}
}
func (_static *CompanionStruct_Default___) BodylessSuccess(status _dafny.Int) bool {
	return ((status).Cmp(_dafny.IntOfInt64(204)) == 0) || ((status).Cmp(_dafny.IntOfInt64(205)) == 0)
}
func (_static *CompanionStruct_Default___) Classify(encrypted bool, head Head) Disposition {
	var _0_nonces _dafny.Sequence = Companion_Default___.HeaderValues((head).Dtor_headers(), Companion_Default___.ResponseNonceHeader())
	_ = _0_nonces
	if !(encrypted) {
		return Companion_Disposition_.Create_PassThrough_()
	} else if ((head).Dtor_redirected()) || (((_dafny.IntOfInt64(300)).Cmp((head).Dtor_status()) <= 0) && (((head).Dtor_status()).Cmp(_dafny.IntOfInt64(400)) < 0)) {
		return Companion_Disposition_.Create_Refuse_(Companion_Code_.Create_UnexpectedRedirect_(), _dafny.UnicodeSeqOfUtf8Bytes("redirect in response to an encrypted request"))
	} else if (_dafny.IntOfUint32((_0_nonces).Cardinality())).Sign() == 0 {
		if ((head).Dtor_status()).Cmp(_dafny.IntOfInt64(400)) < 0 {
			return Companion_Disposition_.Create_Refuse_(Companion_Code_.Create_MissingResponseNonce_(), _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.UnicodeSeqOfUtf8Bytes("missing "), Companion_Default___.ResponseNonceHeader()), _dafny.UnicodeSeqOfUtf8Bytes(" header")))
		} else if (((head).Dtor_status()).Cmp(_dafny.IntOfInt64(422)) == 0) && (Companion_Default___.HasMediaType(Companion_Default___.FirstHeader((head).Dtor_headers(), _dafny.UnicodeSeqOfUtf8Bytes("Content-Type")), Companion_Default___.ProblemJsonMediaType())) {
			return Companion_Disposition_.Create_NeedProblemBody_()
		} else {
			return Companion_Disposition_.Create_PassThrough_()
		}
	} else if (_dafny.IntOfUint32((_0_nonces).Cardinality())).Cmp(_dafny.One) > 0 {
		return Companion_Disposition_.Create_Refuse_(Companion_Code_.Create_DuplicateResponseNonce_(), _dafny.UnicodeSeqOfUtf8Bytes("duplicate response nonce"))
	} else if _dafny.Companion_Sequence_.Equal((_0_nonces).Select(0).(_dafny.Sequence), _dafny.UnicodeSeqOfUtf8Bytes("")) {
		return Companion_Disposition_.Create_Refuse_(Companion_Code_.Create_InvalidResponseNonce_(), _dafny.UnicodeSeqOfUtf8Bytes("empty response nonce"))
	} else {
		var _source0 Option = Companion_Default___.DecodeHex((_0_nonces).Select(0).(_dafny.Sequence))
		_ = _source0
		{
			if _source0.Is_None() {
				return Companion_Disposition_.Create_Refuse_(Companion_Code_.Create_InvalidResponseNonce_(), _dafny.UnicodeSeqOfUtf8Bytes("response nonce is not hex"))
			}
		}
		{
			var _1_nonce _dafny.Sequence = _source0.Get_().(Option_Some).Value.(_dafny.Sequence)
			_ = _1_nonce
			if (_dafny.IntOfUint32((_1_nonce).Cardinality())).Cmp(Companion_Default___.ResponseNonceLength()) != 0 {
				return Companion_Disposition_.Create_Refuse_(Companion_Code_.Create_InvalidResponseNonce_(), _dafny.UnicodeSeqOfUtf8Bytes("response nonce has wrong length"))
			} else if Companion_Default___.BodylessSuccess((head).Dtor_status()) {
				return Companion_Disposition_.Create_Refuse_(Companion_Code_.Create_FramingTruncated_(), _dafny.UnicodeSeqOfUtf8Bytes("status cannot carry an authenticated frame"))
			} else {
				return Companion_Disposition_.Create_Decrypt_(_1_nonce, ((head).Dtor_status()).Cmp(_dafny.IntOfInt64(400)) < 0)
			}
		}
	}
}
func (_static *CompanionStruct_Default___) ClassifyProblem(oversized bool, isObject bool, typeValue Option, title Option) Disposition {
	if ((oversized) || (!(isObject))) || (!(typeValue).Equals(Companion_Option_.Create_Some_(Companion_Default___.KeyConfigProblemType()))) {
		return Companion_Disposition_.Create_PassThrough_()
	} else {
		return Companion_Disposition_.Create_Refuse_(Companion_Code_.Create_KeyConfigMismatch_(), (func() _dafny.Sequence {
			if ((title).Is_Some()) && (!_dafny.Companion_Sequence_.Equal((title).Dtor_value().(_dafny.Sequence), _dafny.UnicodeSeqOfUtf8Bytes(""))) {
				return (title).Dtor_value().(_dafny.Sequence)
			}
			return Companion_Default___.DefaultKeyConfigTitle()
		})())
	}
}
func (_static *CompanionStruct_Default___) ClassifyDiscovery(head Head) Result {
	if ((head).Dtor_redirected()) || (((head).Dtor_status()).Cmp(_dafny.IntOfInt64(200)) != 0) {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidKeyConfig_(), _dafny.UnicodeSeqOfUtf8Bytes("discovery returned a non-200 status"))
	} else if !(Companion_Default___.HasMediaType(Companion_Default___.FirstHeader((head).Dtor_headers(), _dafny.UnicodeSeqOfUtf8Bytes("Content-Type")), Companion_Default___.KeysMediaType())) {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidKeyConfig_(), _dafny.UnicodeSeqOfUtf8Bytes("discovery returned the wrong media type"))
	} else {
		return Companion_Result_.Create_Ok_(_dafny.TupleOf())
	}
}
func (_static *CompanionStruct_Default___) DefaultPort(scheme _dafny.Sequence) _dafny.Int {
	if _dafny.Companion_Sequence_.Equal(Companion_Default___.Lower(scheme), _dafny.UnicodeSeqOfUtf8Bytes("https")) {
		return _dafny.IntOfInt64(443)
	} else {
		return _dafny.IntOfInt64(80)
	}
}
func (_static *CompanionStruct_Default___) MakeOrigin(scheme _dafny.Sequence, host _dafny.Sequence, port Option, hasUserinfo bool) Result {
	var _0_s _dafny.Sequence = Companion_Default___.Lower(scheme)
	_ = _0_s
	if (!_dafny.Companion_Sequence_.Equal(_0_s, _dafny.UnicodeSeqOfUtf8Bytes("http"))) && (!_dafny.Companion_Sequence_.Equal(_0_s, _dafny.UnicodeSeqOfUtf8Bytes("https"))) {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidInput_(), _dafny.UnicodeSeqOfUtf8Bytes("base URL must include an HTTP origin"))
	} else if _dafny.Companion_Sequence_.Equal(host, _dafny.UnicodeSeqOfUtf8Bytes("")) {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidInput_(), _dafny.UnicodeSeqOfUtf8Bytes("base URL must include an HTTP origin"))
	} else if hasUserinfo {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidInput_(), _dafny.UnicodeSeqOfUtf8Bytes("base URL must not include credentials"))
	} else {
		return Companion_Result_.Create_Ok_(Companion_Origin_.Create_Origin_(_0_s, Companion_Default___.Lower(host), (func() _dafny.Int {
			if (port).Is_Some() {
				return (port).Dtor_value().(_dafny.Int)
			}
			return Companion_Default___.DefaultPort(_0_s)
		})()))
	}
}
func (_static *CompanionStruct_Default___) SameOrigin(a Origin, b Origin) bool {
	return ((_dafny.Companion_Sequence_.Equal((a).Dtor_scheme(), (b).Dtor_scheme())) && (_dafny.Companion_Sequence_.Equal((a).Dtor_host(), (b).Dtor_host()))) && (((a).Dtor_port()).Cmp((b).Dtor_port()) == 0)
}
func (_static *CompanionStruct_Default___) ReservedHeader(name _dafny.Sequence) bool {
	return ((Companion_Default___.EqualFold(name, Companion_Default___.EncapsulatedKeyHeader())) || (Companion_Default___.EqualFold(name, Companion_Default___.ResponseNonceHeader()))) || (Companion_Default___.EqualFold(name, _dafny.UnicodeSeqOfUtf8Bytes("Host")))
}
func (_static *CompanionStruct_Default___) FramingHeader(name _dafny.Sequence) bool {
	return (Companion_Default___.EqualFold(name, _dafny.UnicodeSeqOfUtf8Bytes("Content-Length"))) || (Companion_Default___.EqualFold(name, _dafny.UnicodeSeqOfUtf8Bytes("Transfer-Encoding")))
}
func (_static *CompanionStruct_Default___) ValidateRequest(origin Origin, target Result, headers _dafny.Sequence) Result {
	if (target).Is_Err() {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidInput_(), (target).Dtor_message())
	} else if !(Companion_Default___.SameOrigin(origin, (target).Dtor_value().(Origin))) {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidInput_(), _dafny.UnicodeSeqOfUtf8Bytes("request URL must use the configured origin"))
	} else {
		return Companion_Default___.ValidateHeadersFrom(headers, _dafny.Zero)
	}
}
func (_static *CompanionStruct_Default___) ValidateHeadersFrom(headers _dafny.Sequence, i _dafny.Int) Result {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (i).Cmp(_dafny.IntOfUint32((headers).Cardinality())) == 0 {
		return Companion_Result_.Create_Ok_(_dafny.TupleOf())
	} else if Companion_Default___.ReservedHeader((*((headers).Select((i).Uint32()).(_dafny.Tuple)).IndexInt(0)).(_dafny.Sequence)) {
		return Companion_Result_.Create_Err_(Companion_Code_.Create_InvalidInput_(), _dafny.Companion_Sequence_.Concatenate(_dafny.UnicodeSeqOfUtf8Bytes("reserved request header cannot be set by callers: "), (*((headers).Select((i).Uint32()).(_dafny.Tuple)).IndexInt(0)).(_dafny.Sequence)))
	} else {
		var _in0 _dafny.Sequence = headers
		_ = _in0
		var _in1 _dafny.Int = (i).Plus(_dafny.One)
		_ = _in1
		headers = _in0
		i = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) DropFraming(headers _dafny.Sequence) _dafny.Sequence {
	return Companion_Default___.DropFramingFrom(headers, _dafny.Zero, _dafny.SeqOf())
}
func (_static *CompanionStruct_Default___) DropFramingFrom(headers _dafny.Sequence, i _dafny.Int, acc _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (i).Cmp(_dafny.IntOfUint32((headers).Cardinality())) == 0 {
		return acc
	} else {
		var _in0 _dafny.Sequence = headers
		_ = _in0
		var _in1 _dafny.Int = (i).Plus(_dafny.One)
		_ = _in1
		var _in2 _dafny.Sequence = (func() _dafny.Sequence {
			if Companion_Default___.FramingHeader((*((headers).Select((i).Uint32()).(_dafny.Tuple)).IndexInt(0)).(_dafny.Sequence)) {
				return acc
			}
			return _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf((headers).Select((i).Uint32()).(_dafny.Tuple)))
		})()
		_ = _in2
		headers = _in0
		i = _in1
		acc = _in2
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) OriginUrl(origin Origin) _dafny.Sequence {
	var _0_portPart _dafny.Sequence = (func() _dafny.Sequence {
		if ((origin).Dtor_port()).Cmp(Companion_Default___.DefaultPort((origin).Dtor_scheme())) == 0 {
			return _dafny.UnicodeSeqOfUtf8Bytes("")
		}
		return _dafny.Companion_Sequence_.Concatenate(_dafny.UnicodeSeqOfUtf8Bytes(":"), Companion_Default___.IntToString((origin).Dtor_port()))
	})()
	_ = _0_portPart
	return _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate((origin).Dtor_scheme(), _dafny.UnicodeSeqOfUtf8Bytes("://")), (origin).Dtor_host()), _0_portPart)
}
func (_static *CompanionStruct_Default___) IntToString(n _dafny.Int) _dafny.Sequence {
	if (n).Sign() == -1 {
		return _dafny.Companion_Sequence_.Concatenate(_dafny.UnicodeSeqOfUtf8Bytes("-"), Companion_Default___.IntToString((_dafny.Zero).Minus(n)))
	} else if (n).Cmp(_dafny.IntOfInt64(10)) < 0 {
		return _dafny.SeqOf(_dafny.CodePoint(((_dafny.IntOfInt32(rune(_dafny.CodePoint('0')))).Plus(n)).Int32()))
	} else {
		return _dafny.Companion_Sequence_.Concatenate(Companion_Default___.IntToString((n).DivBy(_dafny.IntOfInt64(10))), _dafny.SeqOf(_dafny.CodePoint(((_dafny.IntOfInt32(rune(_dafny.CodePoint('0')))).Plus((n).Modulo(_dafny.IntOfInt64(10)))).Int32())))
	}
}
func (_static *CompanionStruct_Default___) Codes() _dafny.Sequence {
	return _dafny.SeqOf(Companion_Code_.Create_InvalidKeyConfig_(), Companion_Code_.Create_UnsupportedSuite_(), Companion_Code_.Create_InvalidEncapsulatedKey_(), Companion_Code_.Create_HpkeSetupFailed_(), Companion_Code_.Create_MissingResponseNonce_(), Companion_Code_.Create_UnexpectedRedirect_(), Companion_Code_.Create_InvalidResponseNonce_(), Companion_Code_.Create_DuplicateResponseNonce_(), Companion_Code_.Create_KeyConfigMismatch_(), Companion_Code_.Create_FramingTruncated_(), Companion_Code_.Create_ChunkTooLarge_(), Companion_Code_.Create_AeadDecryptFailed_(), Companion_Code_.Create_SequenceOverflow_(), Companion_Code_.Create_InvalidToken_(), Companion_Code_.Create_InvalidInput_())
}
func (_static *CompanionStruct_Default___) KemX25519() uint16 {
	return uint16(32)
}
func (_static *CompanionStruct_Default___) KdfHkdfSha256() uint16 {
	return uint16(1)
}
func (_static *CompanionStruct_Default___) AeadAes256Gcm() uint16 {
	return uint16(2)
}
func (_static *CompanionStruct_Default___) MaxChunkBytes() uint32 {
	return ((uint32(64)) * (uint32(1024))) * (uint32(1024))
}
func (_static *CompanionStruct_Default___) RequestFrameBytes() uint32 {
	return uint32(65536)
}
func (_static *CompanionStruct_Default___) HexDigits() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("0123456789abcdef")
}
func (_static *CompanionStruct_Default___) NonceLength() _dafny.Int {
	return _dafny.IntOfInt64(12)
}
func (_static *CompanionStruct_Default___) PublicKeyLength() _dafny.Int {
	return _dafny.IntOfInt64(32)
}
func (_static *CompanionStruct_Default___) ExportLength() _dafny.Int {
	return _dafny.IntOfInt64(32)
}
func (_static *CompanionStruct_Default___) RequestEncLength() _dafny.Int {
	return _dafny.IntOfInt64(32)
}
func (_static *CompanionStruct_Default___) ResponseNonceHeader() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("Ehbp-Response-Nonce")
}
func (_static *CompanionStruct_Default___) ProblemJsonMediaType() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("application/problem+json")
}
func (_static *CompanionStruct_Default___) ResponseNonceLength() _dafny.Int {
	return _dafny.IntOfInt64(32)
}
func (_static *CompanionStruct_Default___) KeyConfigProblemType() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("urn:ietf:params:ehbp:error:key-config")
}
func (_static *CompanionStruct_Default___) DefaultKeyConfigTitle() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("key configuration mismatch")
}
func (_static *CompanionStruct_Default___) KeysMediaType() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("application/ohttp-keys")
}
func (_static *CompanionStruct_Default___) EncapsulatedKeyHeader() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("Ehbp-Encapsulated-Key")
}
func (_static *CompanionStruct_Default___) KeyLength() _dafny.Int {
	return _dafny.IntOfInt64(32)
}
func (_static *CompanionStruct_Default___) HpkeRequestInfo() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("ehbp request")
}
func (_static *CompanionStruct_Default___) ExportLabel() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("ehbp response")
}
func (_static *CompanionStruct_Default___) ResponseKeyLabel() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("key")
}
func (_static *CompanionStruct_Default___) ResponseNonceLabel() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("nonce")
}
func (_static *CompanionStruct_Default___) KeysPath() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("/.well-known/hpke-keys")
}
func (_static *CompanionStruct_Default___) MaxProblemBytes() _dafny.Int {
	return (_dafny.IntOfInt64(64)).Times(_dafny.IntOfInt64(1024))
}
func (_static *CompanionStruct_Default___) MaxKeyConfigBytes() _dafny.Int {
	return (_dafny.IntOfInt64(37)).Plus(_dafny.IntOfInt64(65535))
}
func (_static *CompanionStruct_Default___) MaxEmptyReads() _dafny.Int {
	return _dafny.IntOfInt64(100)
}
func (_static *CompanionStruct_Default___) AeadTagLength() _dafny.Int {
	return _dafny.IntOfInt64(16)
}
func (_static *CompanionStruct_Default___) HashLength() _dafny.Int {
	return _dafny.IntOfInt64(32)
}

// End of class Default__

// Definition of class Uint8
type Uint8 struct {
}

func New_Uint8_() *Uint8 {
	_this := Uint8{}

	return &_this
}

type CompanionStruct_Uint8_ struct {
}

var Companion_Uint8_ = CompanionStruct_Uint8_{}

func (*Uint8) String() string {
	return "EHBP.Uint8"
}
func (_this *Uint8) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Uint8{}

func (_this *CompanionStruct_Uint8_) IntegerRange(lo _dafny.Int, hi _dafny.Int) _dafny.Iterator {
	iter := _dafny.IntegerRange(lo, hi)
	return func() (interface{}, bool) {
		next, ok := iter()
		if !ok {
			return uint8(0), false
		}
		return next.(_dafny.Int).Uint8(), true
	}
}

// End of class Uint8

func Type_Uint8_() _dafny.TypeDescriptor {
	return type_Uint8_{}
}

type type_Uint8_ struct {
}

func (_this type_Uint8_) Default() interface{} {
	return uint8(0)
}

func (_this type_Uint8_) String() string {
	return "EHBP.Uint8"
}
func (_this *CompanionStruct_Uint8_) Is_(__source uint8) bool {
	return true
}

// Definition of class Uint16
type Uint16 struct {
}

func New_Uint16_() *Uint16 {
	_this := Uint16{}

	return &_this
}

type CompanionStruct_Uint16_ struct {
}

var Companion_Uint16_ = CompanionStruct_Uint16_{}

func (*Uint16) String() string {
	return "EHBP.Uint16"
}
func (_this *Uint16) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Uint16{}

func (_this *CompanionStruct_Uint16_) IntegerRange(lo _dafny.Int, hi _dafny.Int) _dafny.Iterator {
	iter := _dafny.IntegerRange(lo, hi)
	return func() (interface{}, bool) {
		next, ok := iter()
		if !ok {
			return uint16(0), false
		}
		return next.(_dafny.Int).Uint16(), true
	}
}

// End of class Uint16

func Type_Uint16_() _dafny.TypeDescriptor {
	return type_Uint16_{}
}

type type_Uint16_ struct {
}

func (_this type_Uint16_) Default() interface{} {
	return uint16(0)
}

func (_this type_Uint16_) String() string {
	return "EHBP.Uint16"
}
func (_this *CompanionStruct_Uint16_) Is_(__source uint16) bool {
	return true
}

// Definition of class Uint32
type Uint32 struct {
}

func New_Uint32_() *Uint32 {
	_this := Uint32{}

	return &_this
}

type CompanionStruct_Uint32_ struct {
}

var Companion_Uint32_ = CompanionStruct_Uint32_{}

func (*Uint32) String() string {
	return "EHBP.Uint32"
}
func (_this *Uint32) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Uint32{}

func (_this *CompanionStruct_Uint32_) IntegerRange(lo _dafny.Int, hi _dafny.Int) _dafny.Iterator {
	iter := _dafny.IntegerRange(lo, hi)
	return func() (interface{}, bool) {
		next, ok := iter()
		if !ok {
			return uint32(0), false
		}
		return next.(_dafny.Int).Uint32(), true
	}
}

// End of class Uint32

func Type_Uint32_() _dafny.TypeDescriptor {
	return type_Uint32_{}
}

type type_Uint32_ struct {
}

func (_this type_Uint32_) Default() interface{} {
	return uint32(0)
}

func (_this type_Uint32_) String() string {
	return "EHBP.Uint32"
}
func (_this *CompanionStruct_Uint32_) Is_(__source uint32) bool {
	return true
}

// Definition of class Uint64
type Uint64 struct {
}

func New_Uint64_() *Uint64 {
	_this := Uint64{}

	return &_this
}

type CompanionStruct_Uint64_ struct {
}

var Companion_Uint64_ = CompanionStruct_Uint64_{}

func (*Uint64) String() string {
	return "EHBP.Uint64"
}
func (_this *Uint64) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Uint64{}

func (_this *CompanionStruct_Uint64_) IntegerRange(lo _dafny.Int, hi _dafny.Int) _dafny.Iterator {
	iter := _dafny.IntegerRange(lo, hi)
	return func() (interface{}, bool) {
		next, ok := iter()
		if !ok {
			return uint64(0), false
		}
		return next.(_dafny.Int).Uint64(), true
	}
}

// End of class Uint64

func Type_Uint64_() _dafny.TypeDescriptor {
	return type_Uint64_{}
}

type type_Uint64_ struct {
}

func (_this type_Uint64_) Default() interface{} {
	return uint64(0)
}

func (_this type_Uint64_) String() string {
	return "EHBP.Uint64"
}
func (_this *CompanionStruct_Uint64_) Is_(__source uint64) bool {
	return true
}

// Definition of class PublicKey
type PublicKey struct {
}

func New_PublicKey_() *PublicKey {
	_this := PublicKey{}

	return &_this
}

type CompanionStruct_PublicKey_ struct {
}

var Companion_PublicKey_ = CompanionStruct_PublicKey_{}

func (*PublicKey) String() string {
	return "EHBP.PublicKey"
}
func (_this *CompanionStruct_PublicKey_) Witness() _dafny.Sequence {
	return _dafny.SeqCreate(32, func(coer5 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg5 _dafny.Int) interface{} {
			return coer5(arg5)
		}
	}(func(_0_i _dafny.Int) uint8 {
		return uint8(0)
	}))
}

// End of class PublicKey

func Type_PublicKey_() _dafny.TypeDescriptor {
	return type_PublicKey_{}
}

type type_PublicKey_ struct {
}

func (_this type_PublicKey_) Default() interface{} {
	return Companion_PublicKey_.Witness()
}

func (_this type_PublicKey_) String() string {
	return "EHBP.PublicKey"
}
func (_this *CompanionStruct_PublicKey_) Is_(__source _dafny.Sequence) bool {
	var _1_b _dafny.Sequence = (__source)
	_ = _1_b
	return (_dafny.IntOfUint32((_1_b).Cardinality())).Cmp(_dafny.IntOfInt64(32)) == 0
}

// Definition of datatype Code
type Code struct {
	Data_Code_
}

func (_this Code) Get_() Data_Code_ {
	return _this.Data_Code_
}

type Data_Code_ interface {
	isCode()
}

type CompanionStruct_Code_ struct {
}

var Companion_Code_ = CompanionStruct_Code_{}

type Code_InvalidKeyConfig struct {
}

func (Code_InvalidKeyConfig) isCode() {}

func (CompanionStruct_Code_) Create_InvalidKeyConfig_() Code {
	return Code{Code_InvalidKeyConfig{}}
}

func (_this Code) Is_InvalidKeyConfig() bool {
	_, ok := _this.Get_().(Code_InvalidKeyConfig)
	return ok
}

type Code_UnsupportedSuite struct {
}

func (Code_UnsupportedSuite) isCode() {}

func (CompanionStruct_Code_) Create_UnsupportedSuite_() Code {
	return Code{Code_UnsupportedSuite{}}
}

func (_this Code) Is_UnsupportedSuite() bool {
	_, ok := _this.Get_().(Code_UnsupportedSuite)
	return ok
}

type Code_InvalidEncapsulatedKey struct {
}

func (Code_InvalidEncapsulatedKey) isCode() {}

func (CompanionStruct_Code_) Create_InvalidEncapsulatedKey_() Code {
	return Code{Code_InvalidEncapsulatedKey{}}
}

func (_this Code) Is_InvalidEncapsulatedKey() bool {
	_, ok := _this.Get_().(Code_InvalidEncapsulatedKey)
	return ok
}

type Code_HpkeSetupFailed struct {
}

func (Code_HpkeSetupFailed) isCode() {}

func (CompanionStruct_Code_) Create_HpkeSetupFailed_() Code {
	return Code{Code_HpkeSetupFailed{}}
}

func (_this Code) Is_HpkeSetupFailed() bool {
	_, ok := _this.Get_().(Code_HpkeSetupFailed)
	return ok
}

type Code_MissingResponseNonce struct {
}

func (Code_MissingResponseNonce) isCode() {}

func (CompanionStruct_Code_) Create_MissingResponseNonce_() Code {
	return Code{Code_MissingResponseNonce{}}
}

func (_this Code) Is_MissingResponseNonce() bool {
	_, ok := _this.Get_().(Code_MissingResponseNonce)
	return ok
}

type Code_UnexpectedRedirect struct {
}

func (Code_UnexpectedRedirect) isCode() {}

func (CompanionStruct_Code_) Create_UnexpectedRedirect_() Code {
	return Code{Code_UnexpectedRedirect{}}
}

func (_this Code) Is_UnexpectedRedirect() bool {
	_, ok := _this.Get_().(Code_UnexpectedRedirect)
	return ok
}

type Code_InvalidResponseNonce struct {
}

func (Code_InvalidResponseNonce) isCode() {}

func (CompanionStruct_Code_) Create_InvalidResponseNonce_() Code {
	return Code{Code_InvalidResponseNonce{}}
}

func (_this Code) Is_InvalidResponseNonce() bool {
	_, ok := _this.Get_().(Code_InvalidResponseNonce)
	return ok
}

type Code_DuplicateResponseNonce struct {
}

func (Code_DuplicateResponseNonce) isCode() {}

func (CompanionStruct_Code_) Create_DuplicateResponseNonce_() Code {
	return Code{Code_DuplicateResponseNonce{}}
}

func (_this Code) Is_DuplicateResponseNonce() bool {
	_, ok := _this.Get_().(Code_DuplicateResponseNonce)
	return ok
}

type Code_KeyConfigMismatch struct {
}

func (Code_KeyConfigMismatch) isCode() {}

func (CompanionStruct_Code_) Create_KeyConfigMismatch_() Code {
	return Code{Code_KeyConfigMismatch{}}
}

func (_this Code) Is_KeyConfigMismatch() bool {
	_, ok := _this.Get_().(Code_KeyConfigMismatch)
	return ok
}

type Code_FramingTruncated struct {
}

func (Code_FramingTruncated) isCode() {}

func (CompanionStruct_Code_) Create_FramingTruncated_() Code {
	return Code{Code_FramingTruncated{}}
}

func (_this Code) Is_FramingTruncated() bool {
	_, ok := _this.Get_().(Code_FramingTruncated)
	return ok
}

type Code_ChunkTooLarge struct {
}

func (Code_ChunkTooLarge) isCode() {}

func (CompanionStruct_Code_) Create_ChunkTooLarge_() Code {
	return Code{Code_ChunkTooLarge{}}
}

func (_this Code) Is_ChunkTooLarge() bool {
	_, ok := _this.Get_().(Code_ChunkTooLarge)
	return ok
}

type Code_AeadDecryptFailed struct {
}

func (Code_AeadDecryptFailed) isCode() {}

func (CompanionStruct_Code_) Create_AeadDecryptFailed_() Code {
	return Code{Code_AeadDecryptFailed{}}
}

func (_this Code) Is_AeadDecryptFailed() bool {
	_, ok := _this.Get_().(Code_AeadDecryptFailed)
	return ok
}

type Code_SequenceOverflow struct {
}

func (Code_SequenceOverflow) isCode() {}

func (CompanionStruct_Code_) Create_SequenceOverflow_() Code {
	return Code{Code_SequenceOverflow{}}
}

func (_this Code) Is_SequenceOverflow() bool {
	_, ok := _this.Get_().(Code_SequenceOverflow)
	return ok
}

type Code_InvalidToken struct {
}

func (Code_InvalidToken) isCode() {}

func (CompanionStruct_Code_) Create_InvalidToken_() Code {
	return Code{Code_InvalidToken{}}
}

func (_this Code) Is_InvalidToken() bool {
	_, ok := _this.Get_().(Code_InvalidToken)
	return ok
}

type Code_InvalidInput struct {
}

func (Code_InvalidInput) isCode() {}

func (CompanionStruct_Code_) Create_InvalidInput_() Code {
	return Code{Code_InvalidInput{}}
}

func (_this Code) Is_InvalidInput() bool {
	_, ok := _this.Get_().(Code_InvalidInput)
	return ok
}

type Code_Transport struct {
}

func (Code_Transport) isCode() {}

func (CompanionStruct_Code_) Create_Transport_() Code {
	return Code{Code_Transport{}}
}

func (_this Code) Is_Transport() bool {
	_, ok := _this.Get_().(Code_Transport)
	return ok
}

func (CompanionStruct_Code_) Default() Code {
	return Companion_Code_.Create_InvalidKeyConfig_()
}

func (_ CompanionStruct_Code_) AllSingletonConstructors() _dafny.Iterator {
	i := -1
	return func() (interface{}, bool) {
		i++
		switch i {
		case 0:
			return Companion_Code_.Create_InvalidKeyConfig_(), true
		case 1:
			return Companion_Code_.Create_UnsupportedSuite_(), true
		case 2:
			return Companion_Code_.Create_InvalidEncapsulatedKey_(), true
		case 3:
			return Companion_Code_.Create_HpkeSetupFailed_(), true
		case 4:
			return Companion_Code_.Create_MissingResponseNonce_(), true
		case 5:
			return Companion_Code_.Create_UnexpectedRedirect_(), true
		case 6:
			return Companion_Code_.Create_InvalidResponseNonce_(), true
		case 7:
			return Companion_Code_.Create_DuplicateResponseNonce_(), true
		case 8:
			return Companion_Code_.Create_KeyConfigMismatch_(), true
		case 9:
			return Companion_Code_.Create_FramingTruncated_(), true
		case 10:
			return Companion_Code_.Create_ChunkTooLarge_(), true
		case 11:
			return Companion_Code_.Create_AeadDecryptFailed_(), true
		case 12:
			return Companion_Code_.Create_SequenceOverflow_(), true
		case 13:
			return Companion_Code_.Create_InvalidToken_(), true
		case 14:
			return Companion_Code_.Create_InvalidInput_(), true
		case 15:
			return Companion_Code_.Create_Transport_(), true
		default:
			return Code{}, false
		}
	}
}

func (_this Code) String() string {
	switch _this.Get_().(type) {
	case nil:
		return "null"
	case Code_InvalidKeyConfig:
		{
			return "EHBP.Code.InvalidKeyConfig"
		}
	case Code_UnsupportedSuite:
		{
			return "EHBP.Code.UnsupportedSuite"
		}
	case Code_InvalidEncapsulatedKey:
		{
			return "EHBP.Code.InvalidEncapsulatedKey"
		}
	case Code_HpkeSetupFailed:
		{
			return "EHBP.Code.HpkeSetupFailed"
		}
	case Code_MissingResponseNonce:
		{
			return "EHBP.Code.MissingResponseNonce"
		}
	case Code_UnexpectedRedirect:
		{
			return "EHBP.Code.UnexpectedRedirect"
		}
	case Code_InvalidResponseNonce:
		{
			return "EHBP.Code.InvalidResponseNonce"
		}
	case Code_DuplicateResponseNonce:
		{
			return "EHBP.Code.DuplicateResponseNonce"
		}
	case Code_KeyConfigMismatch:
		{
			return "EHBP.Code.KeyConfigMismatch"
		}
	case Code_FramingTruncated:
		{
			return "EHBP.Code.FramingTruncated"
		}
	case Code_ChunkTooLarge:
		{
			return "EHBP.Code.ChunkTooLarge"
		}
	case Code_AeadDecryptFailed:
		{
			return "EHBP.Code.AeadDecryptFailed"
		}
	case Code_SequenceOverflow:
		{
			return "EHBP.Code.SequenceOverflow"
		}
	case Code_InvalidToken:
		{
			return "EHBP.Code.InvalidToken"
		}
	case Code_InvalidInput:
		{
			return "EHBP.Code.InvalidInput"
		}
	case Code_Transport:
		{
			return "EHBP.Code.Transport"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Code) Equals(other Code) bool {
	switch _this.Get_().(type) {
	case Code_InvalidKeyConfig:
		{
			_, ok := other.Get_().(Code_InvalidKeyConfig)
			return ok
		}
	case Code_UnsupportedSuite:
		{
			_, ok := other.Get_().(Code_UnsupportedSuite)
			return ok
		}
	case Code_InvalidEncapsulatedKey:
		{
			_, ok := other.Get_().(Code_InvalidEncapsulatedKey)
			return ok
		}
	case Code_HpkeSetupFailed:
		{
			_, ok := other.Get_().(Code_HpkeSetupFailed)
			return ok
		}
	case Code_MissingResponseNonce:
		{
			_, ok := other.Get_().(Code_MissingResponseNonce)
			return ok
		}
	case Code_UnexpectedRedirect:
		{
			_, ok := other.Get_().(Code_UnexpectedRedirect)
			return ok
		}
	case Code_InvalidResponseNonce:
		{
			_, ok := other.Get_().(Code_InvalidResponseNonce)
			return ok
		}
	case Code_DuplicateResponseNonce:
		{
			_, ok := other.Get_().(Code_DuplicateResponseNonce)
			return ok
		}
	case Code_KeyConfigMismatch:
		{
			_, ok := other.Get_().(Code_KeyConfigMismatch)
			return ok
		}
	case Code_FramingTruncated:
		{
			_, ok := other.Get_().(Code_FramingTruncated)
			return ok
		}
	case Code_ChunkTooLarge:
		{
			_, ok := other.Get_().(Code_ChunkTooLarge)
			return ok
		}
	case Code_AeadDecryptFailed:
		{
			_, ok := other.Get_().(Code_AeadDecryptFailed)
			return ok
		}
	case Code_SequenceOverflow:
		{
			_, ok := other.Get_().(Code_SequenceOverflow)
			return ok
		}
	case Code_InvalidToken:
		{
			_, ok := other.Get_().(Code_InvalidToken)
			return ok
		}
	case Code_InvalidInput:
		{
			_, ok := other.Get_().(Code_InvalidInput)
			return ok
		}
	case Code_Transport:
		{
			_, ok := other.Get_().(Code_Transport)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Code) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Code)
	return ok && _this.Equals(typed)
}

func Type_Code_() _dafny.TypeDescriptor {
	return type_Code_{}
}

type type_Code_ struct {
}

func (_this type_Code_) Default() interface{} {
	return Companion_Code_.Default()
}

func (_this type_Code_) String() string {
	return "EHBP.Code"
}
func (_this Code) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Code{}

// End of datatype Code

// Definition of datatype Result
type Result struct {
	Data_Result_
}

func (_this Result) Get_() Data_Result_ {
	return _this.Data_Result_
}

type Data_Result_ interface {
	isResult()
}

type CompanionStruct_Result_ struct {
}

var Companion_Result_ = CompanionStruct_Result_{}

type Result_Ok struct {
	Value interface{}
}

func (Result_Ok) isResult() {}

func (CompanionStruct_Result_) Create_Ok_(Value interface{}) Result {
	return Result{Result_Ok{Value}}
}

func (_this Result) Is_Ok() bool {
	_, ok := _this.Get_().(Result_Ok)
	return ok
}

type Result_Err struct {
	Code    Code
	Message _dafny.Sequence
}

func (Result_Err) isResult() {}

func (CompanionStruct_Result_) Create_Err_(Code Code, Message _dafny.Sequence) Result {
	return Result{Result_Err{Code, Message}}
}

func (_this Result) Is_Err() bool {
	_, ok := _this.Get_().(Result_Err)
	return ok
}

func (CompanionStruct_Result_) Default() Result {
	return Companion_Result_.Create_Err_(Companion_Code_.Default(), _dafny.EmptySeq)
}

func (_this Result) Dtor_value() interface{} {
	return _this.Get_().(Result_Ok).Value
}

func (_this Result) Dtor_code() Code {
	return _this.Get_().(Result_Err).Code
}

func (_this Result) Dtor_message() _dafny.Sequence {
	return _this.Get_().(Result_Err).Message
}

func (_this Result) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Result_Ok:
		{
			return "EHBP.Result.Ok" + "(" + _dafny.String(data.Value) + ")"
		}
	case Result_Err:
		{
			return "EHBP.Result.Err" + "(" + _dafny.String(data.Code) + ", " + data.Message.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Result) Equals(other Result) bool {
	switch data1 := _this.Get_().(type) {
	case Result_Ok:
		{
			data2, ok := other.Get_().(Result_Ok)
			return ok && _dafny.AreEqual(data1.Value, data2.Value)
		}
	case Result_Err:
		{
			data2, ok := other.Get_().(Result_Err)
			return ok && data1.Code.Equals(data2.Code) && data1.Message.Equals(data2.Message)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Result) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Result)
	return ok && _this.Equals(typed)
}

func Type_Result_() _dafny.TypeDescriptor {
	return type_Result_{}
}

type type_Result_ struct {
}

func (_this type_Result_) Default() interface{} {
	return Companion_Result_.Default()
}

func (_this type_Result_) String() string {
	return "EHBP.Result"
}
func (_this Result) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Result{}

// End of datatype Result

// Definition of datatype Option
type Option struct {
	Data_Option_
}

func (_this Option) Get_() Data_Option_ {
	return _this.Data_Option_
}

type Data_Option_ interface {
	isOption()
}

type CompanionStruct_Option_ struct {
}

var Companion_Option_ = CompanionStruct_Option_{}

type Option_None struct {
}

func (Option_None) isOption() {}

func (CompanionStruct_Option_) Create_None_() Option {
	return Option{Option_None{}}
}

func (_this Option) Is_None() bool {
	_, ok := _this.Get_().(Option_None)
	return ok
}

type Option_Some struct {
	Value interface{}
}

func (Option_Some) isOption() {}

func (CompanionStruct_Option_) Create_Some_(Value interface{}) Option {
	return Option{Option_Some{Value}}
}

func (_this Option) Is_Some() bool {
	_, ok := _this.Get_().(Option_Some)
	return ok
}

func (CompanionStruct_Option_) Default() Option {
	return Companion_Option_.Create_None_()
}

func (_this Option) Dtor_value() interface{} {
	return _this.Get_().(Option_Some).Value
}

func (_this Option) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Option_None:
		{
			return "EHBP.Option.None"
		}
	case Option_Some:
		{
			return "EHBP.Option.Some" + "(" + _dafny.String(data.Value) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Option) Equals(other Option) bool {
	switch data1 := _this.Get_().(type) {
	case Option_None:
		{
			_, ok := other.Get_().(Option_None)
			return ok
		}
	case Option_Some:
		{
			data2, ok := other.Get_().(Option_Some)
			return ok && _dafny.AreEqual(data1.Value, data2.Value)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Option) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Option)
	return ok && _this.Equals(typed)
}

func Type_Option_() _dafny.TypeDescriptor {
	return type_Option_{}
}

type type_Option_ struct {
}

func (_this type_Option_) Default() interface{} {
	return Companion_Option_.Default()
}

func (_this type_Option_) String() string {
	return "EHBP.Option"
}
func (_this Option) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Option{}

// End of datatype Option

// Definition of datatype Token
type Token struct {
	Data_Token_
}

func (_this Token) Get_() Data_Token_ {
	return _this.Data_Token_
}

type Data_Token_ interface {
	isToken()
}

type CompanionStruct_Token_ struct {
}

var Companion_Token_ = CompanionStruct_Token_{}

type Token_Token struct {
	ExportedSecret _dafny.Sequence
	RequestEnc     _dafny.Sequence
}

func (Token_Token) isToken() {}

func (CompanionStruct_Token_) Create_Token_(ExportedSecret _dafny.Sequence, RequestEnc _dafny.Sequence) Token {
	return Token{Token_Token{ExportedSecret, RequestEnc}}
}

func (_this Token) Is_Token() bool {
	_, ok := _this.Get_().(Token_Token)
	return ok
}

func (CompanionStruct_Token_) Default() Token {
	return Companion_Token_.Create_Token_(_dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this Token) Dtor_exportedSecret() _dafny.Sequence {
	return _this.Get_().(Token_Token).ExportedSecret
}

func (_this Token) Dtor_requestEnc() _dafny.Sequence {
	return _this.Get_().(Token_Token).RequestEnc
}

func (_this Token) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Token_Token:
		{
			_ = data
			return "EHBP.Token.Token(<redacted>)"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Token) Equals(other Token) bool {
	switch data1 := _this.Get_().(type) {
	case Token_Token:
		{
			data2, ok := other.Get_().(Token_Token)
			return ok && data1.ExportedSecret.Equals(data2.ExportedSecret) && data1.RequestEnc.Equals(data2.RequestEnc)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Token) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Token)
	return ok && _this.Equals(typed)
}

func Type_Token_() _dafny.TypeDescriptor {
	return type_Token_{}
}

type type_Token_ struct {
}

func (_this type_Token_) Default() interface{} {
	return Companion_Token_.Default()
}

func (_this type_Token_) String() string {
	return "EHBP.Token"
}
func (_this Token) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Token{}

// End of datatype Token

// Definition of datatype Framed
type Framed struct {
	Data_Framed_
}

func (_this Framed) Get_() Data_Framed_ {
	return _this.Data_Framed_
}

type Data_Framed_ interface {
	isFramed()
}

type CompanionStruct_Framed_ struct {
}

var Companion_Framed_ = CompanionStruct_Framed_{}

type Framed_Framed struct {
	SeqNo      uint64
	Ciphertext _dafny.Sequence
}

func (Framed_Framed) isFramed() {}

func (CompanionStruct_Framed_) Create_Framed_(SeqNo uint64, Ciphertext _dafny.Sequence) Framed {
	return Framed{Framed_Framed{SeqNo, Ciphertext}}
}

func (_this Framed) Is_Framed() bool {
	_, ok := _this.Get_().(Framed_Framed)
	return ok
}

func (CompanionStruct_Framed_) Default() Framed {
	return Companion_Framed_.Create_Framed_(uint64(0), _dafny.EmptySeq)
}

func (_this Framed) Dtor_seqNo() uint64 {
	return _this.Get_().(Framed_Framed).SeqNo
}

func (_this Framed) Dtor_ciphertext() _dafny.Sequence {
	return _this.Get_().(Framed_Framed).Ciphertext
}

func (_this Framed) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Framed_Framed:
		{
			return "EHBP.Framed.Framed" + "(" + _dafny.String(data.SeqNo) + ", " + _dafny.String(data.Ciphertext) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Framed) Equals(other Framed) bool {
	switch data1 := _this.Get_().(type) {
	case Framed_Framed:
		{
			data2, ok := other.Get_().(Framed_Framed)
			return ok && data1.SeqNo == data2.SeqNo && data1.Ciphertext.Equals(data2.Ciphertext)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Framed) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Framed)
	return ok && _this.Equals(typed)
}

func Type_Framed_() _dafny.TypeDescriptor {
	return type_Framed_{}
}

type type_Framed_ struct {
}

func (_this type_Framed_) Default() interface{} {
	return Companion_Framed_.Default()
}

func (_this type_Framed_) String() string {
	return "EHBP.Framed"
}
func (_this Framed) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Framed{}

// End of datatype Framed

// Definition of datatype Head
type Head struct {
	Data_Head_
}

func (_this Head) Get_() Data_Head_ {
	return _this.Data_Head_
}

type Data_Head_ interface {
	isHead()
}

type CompanionStruct_Head_ struct {
}

var Companion_Head_ = CompanionStruct_Head_{}

type Head_Head struct {
	Status     _dafny.Int
	Headers    _dafny.Sequence
	Redirected bool
}

func (Head_Head) isHead() {}

func (CompanionStruct_Head_) Create_Head_(Status _dafny.Int, Headers _dafny.Sequence, Redirected bool) Head {
	return Head{Head_Head{Status, Headers, Redirected}}
}

func (_this Head) Is_Head() bool {
	_, ok := _this.Get_().(Head_Head)
	return ok
}

func (CompanionStruct_Head_) Default() Head {
	return Companion_Head_.Create_Head_(_dafny.Zero, _dafny.EmptySeq, false)
}

func (_this Head) Dtor_status() _dafny.Int {
	return _this.Get_().(Head_Head).Status
}

func (_this Head) Dtor_headers() _dafny.Sequence {
	return _this.Get_().(Head_Head).Headers
}

func (_this Head) Dtor_redirected() bool {
	return _this.Get_().(Head_Head).Redirected
}

func (_this Head) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Head_Head:
		{
			return "EHBP.Head.Head" + "(" + _dafny.String(data.Status) + ", " + _dafny.String(data.Headers) + ", " + _dafny.String(data.Redirected) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Head) Equals(other Head) bool {
	switch data1 := _this.Get_().(type) {
	case Head_Head:
		{
			data2, ok := other.Get_().(Head_Head)
			return ok && data1.Status.Cmp(data2.Status) == 0 && data1.Headers.Equals(data2.Headers) && data1.Redirected == data2.Redirected
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Head) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Head)
	return ok && _this.Equals(typed)
}

func Type_Head_() _dafny.TypeDescriptor {
	return type_Head_{}
}

type type_Head_ struct {
}

func (_this type_Head_) Default() interface{} {
	return Companion_Head_.Default()
}

func (_this type_Head_) String() string {
	return "EHBP.Head"
}
func (_this Head) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Head{}

// End of datatype Head

// Definition of datatype Disposition
type Disposition struct {
	Data_Disposition_
}

func (_this Disposition) Get_() Data_Disposition_ {
	return _this.Data_Disposition_
}

type Data_Disposition_ interface {
	isDisposition()
}

type CompanionStruct_Disposition_ struct {
}

var Companion_Disposition_ = CompanionStruct_Disposition_{}

type Disposition_PassThrough struct {
}

func (Disposition_PassThrough) isDisposition() {}

func (CompanionStruct_Disposition_) Create_PassThrough_() Disposition {
	return Disposition{Disposition_PassThrough{}}
}

func (_this Disposition) Is_PassThrough() bool {
	_, ok := _this.Get_().(Disposition_PassThrough)
	return ok
}

type Disposition_Decrypt struct {
	Nonce        _dafny.Sequence
	RequireFrame bool
}

func (Disposition_Decrypt) isDisposition() {}

func (CompanionStruct_Disposition_) Create_Decrypt_(Nonce _dafny.Sequence, RequireFrame bool) Disposition {
	return Disposition{Disposition_Decrypt{Nonce, RequireFrame}}
}

func (_this Disposition) Is_Decrypt() bool {
	_, ok := _this.Get_().(Disposition_Decrypt)
	return ok
}

type Disposition_NeedProblemBody struct {
}

func (Disposition_NeedProblemBody) isDisposition() {}

func (CompanionStruct_Disposition_) Create_NeedProblemBody_() Disposition {
	return Disposition{Disposition_NeedProblemBody{}}
}

func (_this Disposition) Is_NeedProblemBody() bool {
	_, ok := _this.Get_().(Disposition_NeedProblemBody)
	return ok
}

type Disposition_Refuse struct {
	Code    Code
	Message _dafny.Sequence
}

func (Disposition_Refuse) isDisposition() {}

func (CompanionStruct_Disposition_) Create_Refuse_(Code Code, Message _dafny.Sequence) Disposition {
	return Disposition{Disposition_Refuse{Code, Message}}
}

func (_this Disposition) Is_Refuse() bool {
	_, ok := _this.Get_().(Disposition_Refuse)
	return ok
}

func (CompanionStruct_Disposition_) Default() Disposition {
	return Companion_Disposition_.Create_PassThrough_()
}

func (_this Disposition) Dtor_nonce() _dafny.Sequence {
	return _this.Get_().(Disposition_Decrypt).Nonce
}

func (_this Disposition) Dtor_requireFrame() bool {
	return _this.Get_().(Disposition_Decrypt).RequireFrame
}

func (_this Disposition) Dtor_code() Code {
	return _this.Get_().(Disposition_Refuse).Code
}

func (_this Disposition) Dtor_message() _dafny.Sequence {
	return _this.Get_().(Disposition_Refuse).Message
}

func (_this Disposition) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Disposition_PassThrough:
		{
			return "EHBP.Disposition.PassThrough"
		}
	case Disposition_Decrypt:
		{
			return "EHBP.Disposition.Decrypt" + "(" + _dafny.String(data.Nonce) + ", " + _dafny.String(data.RequireFrame) + ")"
		}
	case Disposition_NeedProblemBody:
		{
			return "EHBP.Disposition.NeedProblemBody"
		}
	case Disposition_Refuse:
		{
			return "EHBP.Disposition.Refuse" + "(" + _dafny.String(data.Code) + ", " + data.Message.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Disposition) Equals(other Disposition) bool {
	switch data1 := _this.Get_().(type) {
	case Disposition_PassThrough:
		{
			_, ok := other.Get_().(Disposition_PassThrough)
			return ok
		}
	case Disposition_Decrypt:
		{
			data2, ok := other.Get_().(Disposition_Decrypt)
			return ok && data1.Nonce.Equals(data2.Nonce) && data1.RequireFrame == data2.RequireFrame
		}
	case Disposition_NeedProblemBody:
		{
			_, ok := other.Get_().(Disposition_NeedProblemBody)
			return ok
		}
	case Disposition_Refuse:
		{
			data2, ok := other.Get_().(Disposition_Refuse)
			return ok && data1.Code.Equals(data2.Code) && data1.Message.Equals(data2.Message)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Disposition) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Disposition)
	return ok && _this.Equals(typed)
}

func Type_Disposition_() _dafny.TypeDescriptor {
	return type_Disposition_{}
}

type type_Disposition_ struct {
}

func (_this type_Disposition_) Default() interface{} {
	return Companion_Disposition_.Default()
}

func (_this type_Disposition_) String() string {
	return "EHBP.Disposition"
}
func (_this Disposition) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Disposition{}

// End of datatype Disposition

// Definition of datatype Origin
type Origin struct {
	Data_Origin_
}

func (_this Origin) Get_() Data_Origin_ {
	return _this.Data_Origin_
}

type Data_Origin_ interface {
	isOrigin()
}

type CompanionStruct_Origin_ struct {
}

var Companion_Origin_ = CompanionStruct_Origin_{}

type Origin_Origin struct {
	Scheme _dafny.Sequence
	Host   _dafny.Sequence
	Port   _dafny.Int
}

func (Origin_Origin) isOrigin() {}

func (CompanionStruct_Origin_) Create_Origin_(Scheme _dafny.Sequence, Host _dafny.Sequence, Port _dafny.Int) Origin {
	return Origin{Origin_Origin{Scheme, Host, Port}}
}

func (_this Origin) Is_Origin() bool {
	_, ok := _this.Get_().(Origin_Origin)
	return ok
}

func (CompanionStruct_Origin_) Default() Origin {
	return Companion_Origin_.Create_Origin_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.Zero)
}

func (_this Origin) Dtor_scheme() _dafny.Sequence {
	return _this.Get_().(Origin_Origin).Scheme
}

func (_this Origin) Dtor_host() _dafny.Sequence {
	return _this.Get_().(Origin_Origin).Host
}

func (_this Origin) Dtor_port() _dafny.Int {
	return _this.Get_().(Origin_Origin).Port
}

func (_this Origin) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Origin_Origin:
		{
			return "EHBP.Origin.Origin" + "(" + data.Scheme.VerbatimString(true) + ", " + data.Host.VerbatimString(true) + ", " + _dafny.String(data.Port) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Origin) Equals(other Origin) bool {
	switch data1 := _this.Get_().(type) {
	case Origin_Origin:
		{
			data2, ok := other.Get_().(Origin_Origin)
			return ok && data1.Scheme.Equals(data2.Scheme) && data1.Host.Equals(data2.Host) && data1.Port.Cmp(data2.Port) == 0
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Origin) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Origin)
	return ok && _this.Equals(typed)
}

func Type_Origin_() _dafny.TypeDescriptor {
	return type_Origin_{}
}

type type_Origin_ struct {
}

func (_this type_Origin_) Default() interface{} {
	return Companion_Origin_.Default()
}

func (_this type_Origin_) String() string {
	return "EHBP.Origin"
}
func (_this Origin) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Origin{}

// End of datatype Origin
