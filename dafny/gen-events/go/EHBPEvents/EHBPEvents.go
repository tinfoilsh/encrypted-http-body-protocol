// Package EHBPEvents
// Dafny module EHBPEvents compiled into Go

package EHBPEvents

import (
	os "os"

	m_EHBP "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/EHBP"
	m__System "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/System_"
	_dafny "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/dafny"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__
var _ m_EHBP.Dummy__

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
	return "EHBPEvents.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) Terminal(a Action) bool {
	return (((((a).Is_Fail()) || ((a).Is_Finished())) || ((a).Is_Passthrough())) || ((a).Is_Discovered())) || ((a).Is_Close())
}
func (_static *CompanionStruct_Default___) Ends(acts _dafny.Sequence) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((acts).Cardinality())), false, func(_exists_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_exists_var_0).(_dafny.Int)
		return (((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((acts).Cardinality())) < 0)) && (Companion_Default___.Terminal((acts).Select((_0_i).Uint32()).(Action)))
	})
}
func (_static *CompanionStruct_Default___) NoClear(acts _dafny.Sequence) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((acts).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((acts).Cardinality())) < 0)) || (!(((acts).Select((_0_i).Uint32()).(Action)).Is_ClearToken()))
	})
}
func (_static *CompanionStruct_Default___) ClearsOnce(acts _dafny.Sequence, g uint64) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((acts).Cardinality())), false, func(_exists_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_exists_var_0).(_dafny.Int)
		return ((((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((acts).Cardinality())) < 0)) && (((acts).Select((_0_i).Uint32()).(Action)).Equals(Companion_Action_.Create_ClearToken_(g)))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((acts).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
			var _1_j _dafny.Int
			_1_j = interface{}(_forall_var_0).(_dafny.Int)
			return !((((_1_j).Sign() != -1) && ((_1_j).Cmp(_dafny.IntOfUint32((acts).Cardinality())) < 0)) && ((_1_j).Cmp(_0_i) != 0)) || (!(((acts).Select((_1_j).Uint32()).(Action)).Is_ClearToken()))
		}))
	})
}
func (_static *CompanionStruct_Default___) NoEmit(acts _dafny.Sequence) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((acts).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((acts).Cardinality())) < 0)) || (!(((acts).Select((_0_i).Uint32()).(Action)).Is_EmitPlaintext()))
	})
}
func (_static *CompanionStruct_Default___) Perform(p Performer, a Action) Performed {
	var r Performed = Companion_Performed_.Default()
	_ = r
	var _source0 Action = a
	_ = _source0
	{
		{
			if _source0.Is_BeginSession() {
				var _0_generation uint64
				_ = _0_generation
				var _out0 uint64
				_ = _out0
				_out0 = (p).BeginSession()
				_0_generation = _out0
				r = Companion_Performed_.Create_Got_(Companion_Event_.Create_SessionBegun_(_0_generation))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_PublishToken() {
				var _1_generation uint64 = _source0.Get_().(Action_PublishToken).Generation
				_ = _1_generation
				var _2_exportedSecret _dafny.Sequence = _source0.Get_().(Action_PublishToken).ExportedSecret
				_ = _2_exportedSecret
				var _3_requestEnc _dafny.Sequence = _source0.Get_().(Action_PublishToken).RequestEnc
				_ = _3_requestEnc
				(p).PublishToken(_1_generation, _2_exportedSecret, _3_requestEnc)
				r = Companion_Performed_.Create_Quiet_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_ClearToken() {
				var _4_generation uint64 = _source0.Get_().(Action_ClearToken).Generation
				_ = _4_generation
				(p).ClearToken(_4_generation)
				r = Companion_Performed_.Create_Quiet_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_RandomBytes() {
				var _5_length _dafny.Int = _source0.Get_().(Action_RandomBytes).Length
				_ = _5_length
				var _6_data _dafny.Sequence
				_ = _6_data
				var _out1 _dafny.Sequence
				_ = _out1
				_out1 = (p).RandomBytes(_5_length)
				_6_data = _out1
				r = Companion_Performed_.Create_Got_(Companion_Event_.Create_RandomResult_(_6_data))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_X25519() {
				var _7_scalar _dafny.Sequence = _source0.Get_().(Action_X25519).Scalar
				_ = _7_scalar
				var _8_point _dafny.Sequence = _source0.Get_().(Action_X25519).Point
				_ = _8_point
				var _9_shared _dafny.Sequence
				_ = _9_shared
				var _out2 _dafny.Sequence
				_ = _out2
				_out2 = (p).X25519(_7_scalar, _8_point)
				_9_shared = _out2
				r = Companion_Performed_.Create_Got_(Companion_Event_.Create_X25519Result_(_9_shared))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_HmacSha256() {
				var _10_key _dafny.Sequence = _source0.Get_().(Action_HmacSha256).Key
				_ = _10_key
				var _11_data _dafny.Sequence = _source0.Get_().(Action_HmacSha256).Data
				_ = _11_data
				var _12_mac _dafny.Sequence
				_ = _12_mac
				var _out3 _dafny.Sequence
				_ = _out3
				_out3 = (p).HmacSha256(_10_key, _11_data)
				_12_mac = _out3
				r = Companion_Performed_.Create_Got_(Companion_Event_.Create_HmacResult_(_12_mac))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_AeadSeal() {
				var _13_key _dafny.Sequence = _source0.Get_().(Action_AeadSeal).Key
				_ = _13_key
				var _14_nonce _dafny.Sequence = _source0.Get_().(Action_AeadSeal).Nonce
				_ = _14_nonce
				var _15_plaintext _dafny.Sequence = _source0.Get_().(Action_AeadSeal).Plaintext
				_ = _15_plaintext
				var _16_ciphertext _dafny.Sequence
				_ = _16_ciphertext
				var _out4 _dafny.Sequence
				_ = _out4
				_out4 = (p).AeadSeal(_13_key, _14_nonce, _15_plaintext)
				_16_ciphertext = _out4
				r = Companion_Performed_.Create_Got_(Companion_Event_.Create_AeadSealResult_(_16_ciphertext))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_AeadOpen() {
				var _17_key _dafny.Sequence = _source0.Get_().(Action_AeadOpen).Key
				_ = _17_key
				var _18_nonce _dafny.Sequence = _source0.Get_().(Action_AeadOpen).Nonce
				_ = _18_nonce
				var _19_ciphertext _dafny.Sequence = _source0.Get_().(Action_AeadOpen).Ciphertext
				_ = _19_ciphertext
				var _20_ok bool
				_ = _20_ok
				var _21_plaintext _dafny.Sequence
				_ = _21_plaintext
				var _out5 bool
				_ = _out5
				var _out6 _dafny.Sequence
				_ = _out6
				_out5, _out6 = (p).AeadOpen(_17_key, _18_nonce, _19_ciphertext)
				_20_ok = _out5
				_21_plaintext = _out6
				r = Companion_Performed_.Create_Got_(Companion_Event_.Create_AeadOpenResult_(_20_ok, _21_plaintext))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Send() {
				var _22_verb _dafny.Sequence = _source0.Get_().(Action_Send).Verb
				_ = _22_verb
				var _23_url _dafny.Sequence = _source0.Get_().(Action_Send).Url
				_ = _23_url
				var _24_headers _dafny.Sequence = _source0.Get_().(Action_Send).Headers
				_ = _24_headers
				var _25_hasBody bool = _source0.Get_().(Action_Send).HasBody
				_ = _25_hasBody
				var _26_ok bool
				_ = _26_ok
				var _27_status _dafny.Int
				_ = _27_status
				var _28_head _dafny.Sequence
				_ = _28_head
				var _29_redirected bool
				_ = _29_redirected
				var _out7 bool
				_ = _out7
				var _out8 _dafny.Int
				_ = _out8
				var _out9 _dafny.Sequence
				_ = _out9
				var _out10 bool
				_ = _out10
				_out7, _out8, _out9, _out10 = (p).Send(_22_verb, _23_url, _24_headers, _25_hasBody)
				_26_ok = _out7
				_27_status = _out8
				_28_head = _out9
				_29_redirected = _out10
				r = Companion_Performed_.Create_Got_((func() Event {
					if _26_ok {
						return Companion_Event_.Create_ResponseHead_(_27_status, _28_head, _29_redirected)
					}
					return Companion_Event_.Create_StreamFailed_(Companion_Stream_.Create_ResponseBody_())
				})())
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Write() {
				var _30_data _dafny.Sequence = _source0.Get_().(Action_Write).Data
				_ = _30_data
				var _31_end BodyEnd = _source0.Get_().(Action_Write).End
				_ = _31_end
				var _32_ok bool
				_ = _32_ok
				var _out11 bool
				_ = _out11
				_out11 = (p).Write(_30_data, _31_end)
				_32_ok = _out11
				if _32_ok {
					r = Companion_Performed_.Create_Quiet_()
				} else {
					r = Companion_Performed_.Create_Stop_()
				}
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Read() {
				var _33_stream Stream = _source0.Get_().(Action_Read).Stream
				_ = _33_stream
				var _34_ok bool
				_ = _34_ok
				var _35_data _dafny.Sequence
				_ = _35_data
				var _36_eof bool
				_ = _36_eof
				var _out12 bool
				_ = _out12
				var _out13 _dafny.Sequence
				_ = _out13
				var _out14 bool
				_ = _out14
				_out12, _out13, _out14 = (p).Read(_33_stream)
				_34_ok = _out12
				_35_data = _out13
				_36_eof = _out14
				r = Companion_Performed_.Create_Got_((func() Event {
					if _34_ok {
						return Companion_Event_.Create_Chunk_(_33_stream, _35_data, _36_eof)
					}
					return Companion_Event_.Create_StreamFailed_(_33_stream)
				})())
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Close() {
				var _37_stream Stream = _source0.Get_().(Action_Close).Stream
				_ = _37_stream
				(p).Close(_37_stream)
				r = Companion_Performed_.Create_Quiet_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_EmitPlaintext() {
				var _38_data _dafny.Sequence = _source0.Get_().(Action_EmitPlaintext).Data
				_ = _38_data
				(p).EmitPlaintext(_38_data)
				r = Companion_Performed_.Create_Quiet_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Passthrough() {
				r = Companion_Performed_.Create_Quiet_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Done() {
				r = Companion_Performed_.Create_Quiet_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Finished() {
				r = Companion_Performed_.Create_Quiet_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Discovered() {
				r = Companion_Performed_.Create_Quiet_()
				return r
				goto Lmatch0
			}
		}
		{
			r = Companion_Performed_.Create_Quiet_()
			return r
		}
		goto Lmatch0
	}
Lmatch0:
	return r
}
func (_static *CompanionStruct_Default___) Extract(salt _dafny.Sequence, ikm _dafny.Sequence) Job {
	return Companion_Job_.Create_JExtract_(salt, ikm)
}
func (_static *CompanionStruct_Default___) Expand(prk _dafny.Sequence, info _dafny.Sequence, length _dafny.Int) Job {
	return Companion_Job_.Create_JExpand_(prk, info, length, _dafny.SeqOf(), _dafny.SeqOf(), uint8(1))
}
func (_static *CompanionStruct_Default___) JobAction(j Job) Action {
	var _source0 Job = j
	_ = _source0
	{
		if _source0.Is_JExtract() {
			var _0_salt _dafny.Sequence = _source0.Get_().(Job_JExtract).Salt
			_ = _0_salt
			var _1_ikm _dafny.Sequence = _source0.Get_().(Job_JExtract).Ikm
			_ = _1_ikm
			return Companion_Action_.Create_HmacSha256_(_0_salt, _1_ikm)
		}
	}
	{
		var _2_prk _dafny.Sequence = _source0.Get_().(Job_JExpand).Prk
		_ = _2_prk
		var _3_info _dafny.Sequence = _source0.Get_().(Job_JExpand).Info
		_ = _3_info
		var _4_prev _dafny.Sequence = _source0.Get_().(Job_JExpand).Prev
		_ = _4_prev
		var _5_i uint8 = _source0.Get_().(Job_JExpand).I
		_ = _5_i
		return Companion_Action_.Create_HmacSha256_(_2_prk, _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_4_prev, _3_info), _dafny.SeqOf(_5_i)))
	}
}
func (_static *CompanionStruct_Default___) JobStep(j Job, e Event) JobOut {
	if !((e).Is_HmacResult()) {
		return Companion_JobOut_.Create_JobFailed_(m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event"))
	} else if (_dafny.IntOfUint32(((e).Dtor_mac()).Cardinality())).Cmp(m_EHBP.Companion_Default___.HashLength()) != 0 {
		return Companion_JobOut_.Create_JobFailed_(m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("HMAC returned the wrong length"))
	} else {
		var _source0 Job = j
		_ = _source0
		{
			if _source0.Is_JExtract() {
				return Companion_JobOut_.Create_Output_((e).Dtor_mac())
			}
		}
		{
			var _0_prk _dafny.Sequence = _source0.Get_().(Job_JExpand).Prk
			_ = _0_prk
			var _1_info _dafny.Sequence = _source0.Get_().(Job_JExpand).Info
			_ = _1_info
			var _2_length _dafny.Int = _source0.Get_().(Job_JExpand).Length
			_ = _2_length
			var _3_acc _dafny.Sequence = _source0.Get_().(Job_JExpand).Acc
			_ = _3_acc
			var _4_i uint8 = _source0.Get_().(Job_JExpand).I
			_ = _4_i
			var _5_grown _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(_3_acc, (e).Dtor_mac())
			_ = _5_grown
			if (_dafny.IntOfUint32((_5_grown).Cardinality())).Cmp(_2_length) >= 0 {
				return Companion_JobOut_.Create_Output_((_5_grown).Take((_2_length).Uint32()))
			} else if (_4_i) == (uint8(255)) {
				return Companion_JobOut_.Create_JobFailed_(m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("HKDF expand length too large"))
			} else {
				var _6_next Job = Companion_Job_.Create_JExpand_(_0_prk, _1_info, _2_length, _5_grown, (e).Dtor_mac(), (_4_i)+(uint8(1)))
				_ = _6_next
				return Companion_JobOut_.Create_Pending_(_6_next, Companion_Default___.JobAction(_6_next))
			}
		}
	}
}
func (_static *CompanionStruct_Default___) Repeat(n _dafny.Int, v uint8) _dafny.Sequence {
	return _dafny.SeqCreate((n).Uint32(), func(coer6 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg6 _dafny.Int) interface{} {
			return coer6(arg6)
		}
	}((func(_0_v uint8) func(_dafny.Int) uint8 {
		return func(_1_i _dafny.Int) uint8 {
			return _0_v
		}
	})(v)))
}
func (_static *CompanionStruct_Default___) Iota(n _dafny.Int) _dafny.Sequence {
	return _dafny.SeqCreate((n).Uint32(), func(coer7 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg7 _dafny.Int) interface{} {
			return coer7(arg7)
		}
	}((func(_0_n _dafny.Int) func(_dafny.Int) uint8 {
		return func(_1_i _dafny.Int) uint8 {
			return (_1_i).Uint8()
		}
	})(n)))
}
func (_static *CompanionStruct_Default___) LabeledExtract(suite _dafny.Sequence, salt _dafny.Sequence, tag _dafny.Sequence, ikm _dafny.Sequence) Job {
	return Companion_Default___.Extract(salt, _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(Companion_Default___.HpkeVersion(), suite), m_EHBP.Companion_Default___.Ascii(tag)), ikm))
}
func (_static *CompanionStruct_Default___) LabeledExpand(suite _dafny.Sequence, prk _dafny.Sequence, tag _dafny.Sequence, info _dafny.Sequence, length _dafny.Int) Job {
	return Companion_Default___.Expand(prk, _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(m_EHBP.Companion_Default___.BE16((length).Uint16()), Companion_Default___.HpkeVersion()), suite), m_EHBP.Companion_Default___.Ascii(tag)), info), length)
}
func (_static *CompanionStruct_Default___) SenderStart(pkR _dafny.Sequence, info _dafny.Sequence) HpkeOut {
	return Companion_HpkeOut_.Create_HContinue_(Companion_Hpke_.Create_HRandom_(pkR, info), Companion_Action_.Create_RandomBytes_(_dafny.IntOfInt64(32)))
}
func (_static *CompanionStruct_Default___) RecipientStart(skR _dafny.Sequence, pkR _dafny.Sequence, enc _dafny.Sequence, info _dafny.Sequence) HpkeOut {
	return Companion_HpkeOut_.Create_HContinue_(Companion_Hpke_.Create_HDh_(enc, pkR, info), Companion_Action_.Create_X25519_(skR, enc))
}
func (_static *CompanionStruct_Default___) Schedule(h Hpke, job Job) HpkeOut {
	var _pat_let_tv0 = job
	_ = _pat_let_tv0
	return Companion_HpkeOut_.Create_HContinue_(func(_pat_let1_0 Hpke) Hpke {
		return func(_0_dt__update__tmp_h0 Hpke) Hpke {
			return func(_pat_let2_0 Job) Hpke {
				return func(_1_dt__update_hjob_h0 Job) Hpke {
					return Companion_Hpke_.Create_HSchedule_((_0_dt__update__tmp_h0).Dtor_stage(), _1_dt__update_hjob_h0, (_0_dt__update__tmp_h0).Dtor_enc(), (_0_dt__update__tmp_h0).Dtor_pkR(), (_0_dt__update__tmp_h0).Dtor_info(), (_0_dt__update__tmp_h0).Dtor_shared(), (_0_dt__update__tmp_h0).Dtor_pskIdHash(), (_0_dt__update__tmp_h0).Dtor_infoHash(), (_0_dt__update__tmp_h0).Dtor_secret(), (_0_dt__update__tmp_h0).Dtor_key(), (_0_dt__update__tmp_h0).Dtor_baseNonce())
				}(_pat_let2_0)
			}(_pat_let_tv0)
		}(_pat_let1_0)
	}(h), Companion_Default___.JobAction(job))
}
func (_static *CompanionStruct_Default___) HpkeStep(h Hpke, e Event) HpkeOut {
	var _source0 Hpke = h
	_ = _source0
	{
		if _source0.Is_HRandom() {
			var _0_pkR _dafny.Sequence = _source0.Get_().(Hpke_HRandom).PkR
			_ = _0_pkR
			var _1_info _dafny.Sequence = _source0.Get_().(Hpke_HRandom).Info
			_ = _1_info
			if !((e).Is_RandomResult()) {
				return Companion_HpkeOut_.Create_HFailed_(m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event"))
			} else if (_dafny.IntOfUint32(((e).Dtor_data()).Cardinality())).Cmp(_dafny.IntOfInt64(32)) != 0 {
				return Companion_HpkeOut_.Create_HFailed_(m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("random bytes have the wrong length"))
			} else {
				return Companion_HpkeOut_.Create_HContinue_(Companion_Hpke_.Create_HEnc_((e).Dtor_data(), _0_pkR, _1_info), Companion_Action_.Create_X25519_((e).Dtor_data(), Companion_Default___.BasePoint()))
			}
		}
	}
	{
		if _source0.Is_HEnc() {
			var _2_skE _dafny.Sequence = _source0.Get_().(Hpke_HEnc).SkE
			_ = _2_skE
			var _3_pkR _dafny.Sequence = _source0.Get_().(Hpke_HEnc).PkR
			_ = _3_pkR
			var _4_info _dafny.Sequence = _source0.Get_().(Hpke_HEnc).Info
			_ = _4_info
			if !((e).Is_X25519Result()) {
				return Companion_HpkeOut_.Create_HFailed_(m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event"))
			} else if (_dafny.IntOfUint32(((e).Dtor_point()).Cardinality())).Cmp(_dafny.IntOfInt64(32)) != 0 {
				return Companion_HpkeOut_.Create_HFailed_(m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("X25519 failed"))
			} else {
				return Companion_HpkeOut_.Create_HContinue_(Companion_Hpke_.Create_HDh_((e).Dtor_point(), _3_pkR, _4_info), Companion_Action_.Create_X25519_(_2_skE, _3_pkR))
			}
		}
	}
	{
		if _source0.Is_HDh() {
			var _5_enc _dafny.Sequence = _source0.Get_().(Hpke_HDh).Enc
			_ = _5_enc
			var _6_pkR _dafny.Sequence = _source0.Get_().(Hpke_HDh).PkR
			_ = _6_pkR
			var _7_info _dafny.Sequence = _source0.Get_().(Hpke_HDh).Info
			_ = _7_info
			if !((e).Is_X25519Result()) {
				return Companion_HpkeOut_.Create_HFailed_(m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event"))
			} else if (_dafny.IntOfUint32(((e).Dtor_point()).Cardinality())).Cmp(_dafny.IntOfInt64(32)) != 0 {
				return Companion_HpkeOut_.Create_HFailed_(m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("X25519 failed"))
			} else {
				return Companion_Default___.Schedule(Companion_Hpke_.Create_HSchedule_(_dafny.Zero, Companion_Default___.Extract(_dafny.SeqOf(), _dafny.SeqOf()), _5_enc, _6_pkR, _7_info, _dafny.SeqOf(), _dafny.SeqOf(), _dafny.SeqOf(), _dafny.SeqOf(), _dafny.SeqOf(), _dafny.SeqOf()), Companion_Default___.LabeledExtract(Companion_Default___.KemSuiteId(), _dafny.SeqOf(), _dafny.UnicodeSeqOfUtf8Bytes("eae_prk"), (e).Dtor_point()))
			}
		}
	}
	{
		var _8_stage _dafny.Int = _source0.Get_().(Hpke_HSchedule).Stage
		_ = _8_stage
		var _9_job Job = _source0.Get_().(Hpke_HSchedule).Job
		_ = _9_job
		var _10_enc _dafny.Sequence = _source0.Get_().(Hpke_HSchedule).Enc
		_ = _10_enc
		var _11_pkR _dafny.Sequence = _source0.Get_().(Hpke_HSchedule).PkR
		_ = _11_pkR
		var _12_info _dafny.Sequence = _source0.Get_().(Hpke_HSchedule).Info
		_ = _12_info
		var _13_shared _dafny.Sequence = _source0.Get_().(Hpke_HSchedule).Shared
		_ = _13_shared
		var _14_pskIdHash _dafny.Sequence = _source0.Get_().(Hpke_HSchedule).PskIdHash
		_ = _14_pskIdHash
		var _15_infoHash _dafny.Sequence = _source0.Get_().(Hpke_HSchedule).InfoHash
		_ = _15_infoHash
		var _16_secret _dafny.Sequence = _source0.Get_().(Hpke_HSchedule).Secret
		_ = _16_secret
		var _17_key _dafny.Sequence = _source0.Get_().(Hpke_HSchedule).Key
		_ = _17_key
		var _18_baseNonce _dafny.Sequence = _source0.Get_().(Hpke_HSchedule).BaseNonce
		_ = _18_baseNonce
		var _source1 JobOut = Companion_Default___.JobStep(_9_job, e)
		_ = _source1
		{
			if _source1.Is_JobFailed() {
				var _19_code m_EHBP.Code = _source1.Get_().(JobOut_JobFailed).Code
				_ = _19_code
				var _20_message _dafny.Sequence = _source1.Get_().(JobOut_JobFailed).Message
				_ = _20_message
				return Companion_HpkeOut_.Create_HFailed_(_19_code, _20_message)
			}
		}
		{
			if _source1.Is_Pending() {
				var _21_next Job = _source1.Get_().(JobOut_Pending).Job
				_ = _21_next
				var _22_action Action = _source1.Get_().(JobOut_Pending).Action
				_ = _22_action
				return Companion_HpkeOut_.Create_HContinue_(func(_pat_let3_0 Hpke) Hpke {
					return func(_23_dt__update__tmp_h0 Hpke) Hpke {
						return func(_pat_let4_0 Job) Hpke {
							return func(_24_dt__update_hjob_h0 Job) Hpke {
								return Companion_Hpke_.Create_HSchedule_((_23_dt__update__tmp_h0).Dtor_stage(), _24_dt__update_hjob_h0, (_23_dt__update__tmp_h0).Dtor_enc(), (_23_dt__update__tmp_h0).Dtor_pkR(), (_23_dt__update__tmp_h0).Dtor_info(), (_23_dt__update__tmp_h0).Dtor_shared(), (_23_dt__update__tmp_h0).Dtor_pskIdHash(), (_23_dt__update__tmp_h0).Dtor_infoHash(), (_23_dt__update__tmp_h0).Dtor_secret(), (_23_dt__update__tmp_h0).Dtor_key(), (_23_dt__update__tmp_h0).Dtor_baseNonce())
							}(_pat_let4_0)
						}(_21_next)
					}(_pat_let3_0)
				}(h), _22_action)
			}
		}
		{
			var _25_out _dafny.Sequence = _source1.Get_().(JobOut_Output).Data
			_ = _25_out
			var _26_ksc _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(uint8(0)), _14_pskIdHash), _15_infoHash)
			_ = _26_ksc
			if (_8_stage).Sign() == 0 {
				return Companion_Default___.Schedule(func(_pat_let5_0 Hpke) Hpke {
					return func(_27_dt__update__tmp_h1 Hpke) Hpke {
						return func(_pat_let6_0 _dafny.Int) Hpke {
							return func(_28_dt__update_hstage_h0 _dafny.Int) Hpke {
								return Companion_Hpke_.Create_HSchedule_(_28_dt__update_hstage_h0, (_27_dt__update__tmp_h1).Dtor_job(), (_27_dt__update__tmp_h1).Dtor_enc(), (_27_dt__update__tmp_h1).Dtor_pkR(), (_27_dt__update__tmp_h1).Dtor_info(), (_27_dt__update__tmp_h1).Dtor_shared(), (_27_dt__update__tmp_h1).Dtor_pskIdHash(), (_27_dt__update__tmp_h1).Dtor_infoHash(), (_27_dt__update__tmp_h1).Dtor_secret(), (_27_dt__update__tmp_h1).Dtor_key(), (_27_dt__update__tmp_h1).Dtor_baseNonce())
							}(_pat_let6_0)
						}(_dafny.One)
					}(_pat_let5_0)
				}(h), Companion_Default___.LabeledExpand(Companion_Default___.KemSuiteId(), _25_out, _dafny.UnicodeSeqOfUtf8Bytes("shared_secret"), _dafny.Companion_Sequence_.Concatenate(_10_enc, _11_pkR), m_EHBP.Companion_Default___.HashLength()))
			} else if (_8_stage).Cmp(_dafny.One) == 0 {
				return Companion_Default___.Schedule(func(_pat_let7_0 Hpke) Hpke {
					return func(_29_dt__update__tmp_h2 Hpke) Hpke {
						return func(_pat_let8_0 _dafny.Sequence) Hpke {
							return func(_30_dt__update_hshared_h0 _dafny.Sequence) Hpke {
								return func(_pat_let9_0 _dafny.Int) Hpke {
									return func(_31_dt__update_hstage_h1 _dafny.Int) Hpke {
										return Companion_Hpke_.Create_HSchedule_(_31_dt__update_hstage_h1, (_29_dt__update__tmp_h2).Dtor_job(), (_29_dt__update__tmp_h2).Dtor_enc(), (_29_dt__update__tmp_h2).Dtor_pkR(), (_29_dt__update__tmp_h2).Dtor_info(), _30_dt__update_hshared_h0, (_29_dt__update__tmp_h2).Dtor_pskIdHash(), (_29_dt__update__tmp_h2).Dtor_infoHash(), (_29_dt__update__tmp_h2).Dtor_secret(), (_29_dt__update__tmp_h2).Dtor_key(), (_29_dt__update__tmp_h2).Dtor_baseNonce())
									}(_pat_let9_0)
								}(_dafny.IntOfInt64(2))
							}(_pat_let8_0)
						}(_25_out)
					}(_pat_let7_0)
				}(h), Companion_Default___.LabeledExtract(Companion_Default___.HpkeSuiteId(), _dafny.SeqOf(), _dafny.UnicodeSeqOfUtf8Bytes("psk_id_hash"), _dafny.SeqOf()))
			} else if (_8_stage).Cmp(_dafny.IntOfInt64(2)) == 0 {
				return Companion_Default___.Schedule(func(_pat_let10_0 Hpke) Hpke {
					return func(_32_dt__update__tmp_h3 Hpke) Hpke {
						return func(_pat_let11_0 _dafny.Sequence) Hpke {
							return func(_33_dt__update_hpskIdHash_h0 _dafny.Sequence) Hpke {
								return func(_pat_let12_0 _dafny.Int) Hpke {
									return func(_34_dt__update_hstage_h2 _dafny.Int) Hpke {
										return Companion_Hpke_.Create_HSchedule_(_34_dt__update_hstage_h2, (_32_dt__update__tmp_h3).Dtor_job(), (_32_dt__update__tmp_h3).Dtor_enc(), (_32_dt__update__tmp_h3).Dtor_pkR(), (_32_dt__update__tmp_h3).Dtor_info(), (_32_dt__update__tmp_h3).Dtor_shared(), _33_dt__update_hpskIdHash_h0, (_32_dt__update__tmp_h3).Dtor_infoHash(), (_32_dt__update__tmp_h3).Dtor_secret(), (_32_dt__update__tmp_h3).Dtor_key(), (_32_dt__update__tmp_h3).Dtor_baseNonce())
									}(_pat_let12_0)
								}(_dafny.IntOfInt64(3))
							}(_pat_let11_0)
						}(_25_out)
					}(_pat_let10_0)
				}(h), Companion_Default___.LabeledExtract(Companion_Default___.HpkeSuiteId(), _dafny.SeqOf(), _dafny.UnicodeSeqOfUtf8Bytes("info_hash"), _12_info))
			} else if (_8_stage).Cmp(_dafny.IntOfInt64(3)) == 0 {
				return Companion_Default___.Schedule(func(_pat_let13_0 Hpke) Hpke {
					return func(_35_dt__update__tmp_h4 Hpke) Hpke {
						return func(_pat_let14_0 _dafny.Sequence) Hpke {
							return func(_36_dt__update_hinfoHash_h0 _dafny.Sequence) Hpke {
								return func(_pat_let15_0 _dafny.Int) Hpke {
									return func(_37_dt__update_hstage_h3 _dafny.Int) Hpke {
										return Companion_Hpke_.Create_HSchedule_(_37_dt__update_hstage_h3, (_35_dt__update__tmp_h4).Dtor_job(), (_35_dt__update__tmp_h4).Dtor_enc(), (_35_dt__update__tmp_h4).Dtor_pkR(), (_35_dt__update__tmp_h4).Dtor_info(), (_35_dt__update__tmp_h4).Dtor_shared(), (_35_dt__update__tmp_h4).Dtor_pskIdHash(), _36_dt__update_hinfoHash_h0, (_35_dt__update__tmp_h4).Dtor_secret(), (_35_dt__update__tmp_h4).Dtor_key(), (_35_dt__update__tmp_h4).Dtor_baseNonce())
									}(_pat_let15_0)
								}(_dafny.IntOfInt64(4))
							}(_pat_let14_0)
						}(_25_out)
					}(_pat_let13_0)
				}(h), Companion_Default___.LabeledExtract(Companion_Default___.HpkeSuiteId(), _13_shared, _dafny.UnicodeSeqOfUtf8Bytes("secret"), _dafny.SeqOf()))
			} else if (_8_stage).Cmp(_dafny.IntOfInt64(4)) == 0 {
				return Companion_Default___.Schedule(func(_pat_let16_0 Hpke) Hpke {
					return func(_38_dt__update__tmp_h5 Hpke) Hpke {
						return func(_pat_let17_0 _dafny.Sequence) Hpke {
							return func(_39_dt__update_hsecret_h0 _dafny.Sequence) Hpke {
								return func(_pat_let18_0 _dafny.Int) Hpke {
									return func(_40_dt__update_hstage_h4 _dafny.Int) Hpke {
										return Companion_Hpke_.Create_HSchedule_(_40_dt__update_hstage_h4, (_38_dt__update__tmp_h5).Dtor_job(), (_38_dt__update__tmp_h5).Dtor_enc(), (_38_dt__update__tmp_h5).Dtor_pkR(), (_38_dt__update__tmp_h5).Dtor_info(), (_38_dt__update__tmp_h5).Dtor_shared(), (_38_dt__update__tmp_h5).Dtor_pskIdHash(), (_38_dt__update__tmp_h5).Dtor_infoHash(), _39_dt__update_hsecret_h0, (_38_dt__update__tmp_h5).Dtor_key(), (_38_dt__update__tmp_h5).Dtor_baseNonce())
									}(_pat_let18_0)
								}(_dafny.IntOfInt64(5))
							}(_pat_let17_0)
						}(_25_out)
					}(_pat_let16_0)
				}(h), Companion_Default___.LabeledExpand(Companion_Default___.HpkeSuiteId(), _25_out, _dafny.UnicodeSeqOfUtf8Bytes("key"), _26_ksc, m_EHBP.Companion_Default___.KeyLength()))
			} else if (_8_stage).Cmp(_dafny.IntOfInt64(5)) == 0 {
				return Companion_Default___.Schedule(func(_pat_let19_0 Hpke) Hpke {
					return func(_41_dt__update__tmp_h6 Hpke) Hpke {
						return func(_pat_let20_0 _dafny.Sequence) Hpke {
							return func(_42_dt__update_hkey_h0 _dafny.Sequence) Hpke {
								return func(_pat_let21_0 _dafny.Int) Hpke {
									return func(_43_dt__update_hstage_h5 _dafny.Int) Hpke {
										return Companion_Hpke_.Create_HSchedule_(_43_dt__update_hstage_h5, (_41_dt__update__tmp_h6).Dtor_job(), (_41_dt__update__tmp_h6).Dtor_enc(), (_41_dt__update__tmp_h6).Dtor_pkR(), (_41_dt__update__tmp_h6).Dtor_info(), (_41_dt__update__tmp_h6).Dtor_shared(), (_41_dt__update__tmp_h6).Dtor_pskIdHash(), (_41_dt__update__tmp_h6).Dtor_infoHash(), (_41_dt__update__tmp_h6).Dtor_secret(), _42_dt__update_hkey_h0, (_41_dt__update__tmp_h6).Dtor_baseNonce())
									}(_pat_let21_0)
								}(_dafny.IntOfInt64(6))
							}(_pat_let20_0)
						}(_25_out)
					}(_pat_let19_0)
				}(h), Companion_Default___.LabeledExpand(Companion_Default___.HpkeSuiteId(), _16_secret, _dafny.UnicodeSeqOfUtf8Bytes("base_nonce"), _26_ksc, m_EHBP.Companion_Default___.NonceLength()))
			} else if (_8_stage).Cmp(_dafny.IntOfInt64(6)) == 0 {
				return Companion_Default___.Schedule(func(_pat_let22_0 Hpke) Hpke {
					return func(_44_dt__update__tmp_h7 Hpke) Hpke {
						return func(_pat_let23_0 _dafny.Sequence) Hpke {
							return func(_45_dt__update_hbaseNonce_h0 _dafny.Sequence) Hpke {
								return func(_pat_let24_0 _dafny.Int) Hpke {
									return func(_46_dt__update_hstage_h6 _dafny.Int) Hpke {
										return Companion_Hpke_.Create_HSchedule_(_46_dt__update_hstage_h6, (_44_dt__update__tmp_h7).Dtor_job(), (_44_dt__update__tmp_h7).Dtor_enc(), (_44_dt__update__tmp_h7).Dtor_pkR(), (_44_dt__update__tmp_h7).Dtor_info(), (_44_dt__update__tmp_h7).Dtor_shared(), (_44_dt__update__tmp_h7).Dtor_pskIdHash(), (_44_dt__update__tmp_h7).Dtor_infoHash(), (_44_dt__update__tmp_h7).Dtor_secret(), (_44_dt__update__tmp_h7).Dtor_key(), _45_dt__update_hbaseNonce_h0)
									}(_pat_let24_0)
								}(_dafny.IntOfInt64(7))
							}(_pat_let23_0)
						}(_25_out)
					}(_pat_let22_0)
				}(h), Companion_Default___.LabeledExpand(Companion_Default___.HpkeSuiteId(), _16_secret, _dafny.UnicodeSeqOfUtf8Bytes("exp"), _26_ksc, m_EHBP.Companion_Default___.HashLength()))
			} else if (((_8_stage).Cmp(_dafny.IntOfInt64(7)) == 0) && ((_dafny.IntOfUint32((_17_key).Cardinality())).Cmp(m_EHBP.Companion_Default___.KeyLength()) == 0)) && ((_dafny.IntOfUint32((_18_baseNonce).Cardinality())).Cmp(m_EHBP.Companion_Default___.NonceLength()) == 0) {
				var _47_k _dafny.Sequence = _17_key
				_ = _47_k
				var _48_n _dafny.Sequence = _18_baseNonce
				_ = _48_n
				return Companion_HpkeOut_.Create_HReady_(Companion_Ctx_.Create_Ctx_(_47_k, _48_n, _25_out, uint64(0)), _10_enc)
			} else {
				return Companion_HpkeOut_.Create_HFailed_(m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("key schedule produced the wrong lengths"))
			}
		}
	}
}
func (_static *CompanionStruct_Default___) SealAction(ctx Ctx, plaintext _dafny.Sequence) Action {
	return Companion_Action_.Create_AeadSeal_((ctx).Dtor_key(), m_EHBP.Companion_Default___.ComputeNonce((ctx).Dtor_baseNonce(), (ctx).Dtor_seqNo()), plaintext)
}
func (_static *CompanionStruct_Default___) OpenAction(ctx Ctx, ciphertext _dafny.Sequence) Action {
	return Companion_Action_.Create_AeadOpen_((ctx).Dtor_key(), m_EHBP.Companion_Default___.ComputeNonce((ctx).Dtor_baseNonce(), (ctx).Dtor_seqNo()), ciphertext)
}
func (_static *CompanionStruct_Default___) Bump(ctx Ctx) Ctx {
	var _0_dt__update__tmp_h0 Ctx = ctx
	_ = _0_dt__update__tmp_h0
	var _1_dt__update_hseqNo_h0 uint64 = ((ctx).Dtor_seqNo()) + (uint64(1))
	_ = _1_dt__update_hseqNo_h0
	return Companion_Ctx_.Create_Ctx_((_0_dt__update__tmp_h0).Dtor_key(), (_0_dt__update__tmp_h0).Dtor_baseNonce(), (_0_dt__update__tmp_h0).Dtor_exporterSecret(), _1_dt__update_hseqNo_h0)
}
func (_static *CompanionStruct_Default___) ExportJob(ctx Ctx, context _dafny.Sequence, length _dafny.Int) Job {
	return Companion_Default___.LabeledExpand(Companion_Default___.HpkeSuiteId(), (ctx).Dtor_exporterSecret(), _dafny.UnicodeSeqOfUtf8Bytes("sec"), context, length)
}
func (_static *CompanionStruct_Default___) JsonWs(c _dafny.CodePoint) bool {
	return ((((c) == (_dafny.CodePoint(' '))) || ((c) == (_dafny.CodePoint('\t')))) || ((c) == (_dafny.CodePoint('\n')))) || ((c) == (_dafny.CodePoint('\r')))
}
func (_static *CompanionStruct_Default___) IsDigit(c _dafny.CodePoint) bool {
	return ((_dafny.CodePoint('0')) <= (c)) && ((c) <= (_dafny.CodePoint('9')))
}
func (_static *CompanionStruct_Default___) SkipWs(s _dafny.Sequence, i _dafny.Int) _dafny.Int {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if ((i).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0) && (Companion_Default___.JsonWs((s).Select((i).Uint32()).(_dafny.CodePoint))) {
		var _in0 _dafny.Sequence = s
		_ = _in0
		var _in1 _dafny.Int = (i).Plus(_dafny.One)
		_ = _in1
		s = _in0
		i = _in1
		goto TAIL_CALL_START
	} else {
		return i
	}
}
func (_static *CompanionStruct_Default___) Digits(s _dafny.Sequence, i _dafny.Int) _dafny.Int {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if ((i).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0) && (Companion_Default___.IsDigit((s).Select((i).Uint32()).(_dafny.CodePoint))) {
		var _in0 _dafny.Sequence = s
		_ = _in0
		var _in1 _dafny.Int = (i).Plus(_dafny.One)
		_ = _in1
		s = _in0
		i = _in1
		goto TAIL_CALL_START
	} else {
		return i
	}
}
func (_static *CompanionStruct_Default___) Hex4(s _dafny.Sequence, i _dafny.Int) m_EHBP.Option {
	if ((i).Plus(_dafny.IntOfInt64(4))).Cmp(_dafny.IntOfUint32((s).Cardinality())) > 0 {
		return m_EHBP.Companion_Option_.Create_None_()
	} else {
		var _source0 _dafny.Tuple = _dafny.TupleOf(m_EHBP.Companion_Default___.HexDigitValue((s).Select((i).Uint32()).(_dafny.CodePoint)), m_EHBP.Companion_Default___.HexDigitValue((s).Select(((i).Plus(_dafny.One)).Uint32()).(_dafny.CodePoint)), m_EHBP.Companion_Default___.HexDigitValue((s).Select(((i).Plus(_dafny.IntOfInt64(2))).Uint32()).(_dafny.CodePoint)), m_EHBP.Companion_Default___.HexDigitValue((s).Select(((i).Plus(_dafny.IntOfInt64(3))).Uint32()).(_dafny.CodePoint)))
		_ = _source0
		{
			var _00 m_EHBP.Option = (*(_source0).IndexInt(0)).(m_EHBP.Option)
			_ = _00
			if _00.Is_Some() {
				var _0_a uint8 = _00.Get_().(m_EHBP.Option_Some).Value.(uint8)
				_ = _0_a
				var _10 m_EHBP.Option = (*(_source0).IndexInt(1)).(m_EHBP.Option)
				_ = _10
				if _10.Is_Some() {
					var _1_b uint8 = _10.Get_().(m_EHBP.Option_Some).Value.(uint8)
					_ = _1_b
					var _20 m_EHBP.Option = (*(_source0).IndexInt(2)).(m_EHBP.Option)
					_ = _20
					if _20.Is_Some() {
						var _2_c uint8 = _20.Get_().(m_EHBP.Option_Some).Value.(uint8)
						_ = _2_c
						var _30 m_EHBP.Option = (*(_source0).IndexInt(3)).(m_EHBP.Option)
						_ = _30
						if _30.Is_Some() {
							var _3_d uint8 = _30.Get_().(m_EHBP.Option_Some).Value.(uint8)
							_ = _3_d
							return m_EHBP.Companion_Option_.Create_Some_(((((_dafny.IntOfUint8(_0_a)).Times(_dafny.IntOfInt64(4096))).Plus((_dafny.IntOfUint8(_1_b)).Times(_dafny.IntOfInt64(256)))).Plus((_dafny.IntOfUint8(_2_c)).Times(_dafny.IntOfInt64(16)))).Plus(_dafny.IntOfUint8(_3_d)))
						}
					}
				}
			}
		}
		{
			return m_EHBP.Companion_Option_.Create_None_()
		}
	}
}
func (_static *CompanionStruct_Default___) Keep(acc _dafny.Sequence, add _dafny.Sequence) _dafny.Sequence {
	if (_dafny.IntOfUint32((acc).Cardinality())).Cmp(Companion_Default___.MaxJsonStringChars()) >= 0 {
		return acc
	} else if ((_dafny.IntOfUint32((acc).Cardinality())).Plus(_dafny.IntOfUint32((add).Cardinality()))).Cmp(Companion_Default___.MaxJsonStringChars()) <= 0 {
		return _dafny.Companion_Sequence_.Concatenate(acc, add)
	} else {
		return _dafny.Companion_Sequence_.Concatenate(acc, (add).Take(((Companion_Default___.MaxJsonStringChars()).Minus(_dafny.IntOfUint32((acc).Cardinality()))).Uint32()))
	}
}
func (_static *CompanionStruct_Default___) Max(a _dafny.Int, b _dafny.Int) _dafny.Int {
	if (a).Cmp(b) >= 0 {
		return a
	} else {
		return b
	}
}
func (_static *CompanionStruct_Default___) LiteralEnd(s _dafny.Sequence, i _dafny.Int) _dafny.Int {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if ((((i).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0) || (((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('"')))) || (((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('\\')))) || ((_dafny.IntOfInt32(rune((s).Select((i).Uint32()).(_dafny.CodePoint)))).Cmp(_dafny.IntOfInt64(32)) < 0) {
		return i
	} else {
		var _in0 _dafny.Sequence = s
		_ = _in0
		var _in1 _dafny.Int = (i).Plus(_dafny.One)
		_ = _in1
		s = _in0
		i = _in1
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) ParseString(s _dafny.Sequence, i _dafny.Int, acc _dafny.Sequence) m_EHBP.Option {
	goto TAIL_CALL_START
TAIL_CALL_START:
	var _0_j _dafny.Int = Companion_Default___.LiteralEnd(s, i)
	_ = _0_j
	var _1_run _dafny.Sequence = Companion_Default___.Keep(acc, (s).Subsequence((i).Uint32(), (_0_j).Uint32()))
	_ = _1_run
	if (_0_j).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
		return m_EHBP.Companion_Option_.Create_None_()
	} else if ((s).Select((_0_j).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('"')) {
		return m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(_1_run, (_0_j).Plus(_dafny.One)))
	} else if (_dafny.IntOfInt32(rune((s).Select((_0_j).Uint32()).(_dafny.CodePoint)))).Cmp(_dafny.IntOfInt64(32)) < 0 {
		return m_EHBP.Companion_Option_.Create_None_()
	} else if ((_0_j).Plus(_dafny.One)).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
		return m_EHBP.Companion_Option_.Create_None_()
	} else {
		var _2_c _dafny.CodePoint = (s).Select(((_0_j).Plus(_dafny.One)).Uint32()).(_dafny.CodePoint)
		_ = _2_c
		if (((_2_c) == (_dafny.CodePoint('"'))) || ((_2_c) == (_dafny.CodePoint('\\')))) || ((_2_c) == (_dafny.CodePoint('/'))) {
			var _in0 _dafny.Sequence = s
			_ = _in0
			var _in1 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(2))
			_ = _in1
			var _in2 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_2_c))
			_ = _in2
			s = _in0
			i = _in1
			acc = _in2
			goto TAIL_CALL_START
		} else if (_2_c) == (_dafny.CodePoint('b')) {
			var _in3 _dafny.Sequence = s
			_ = _in3
			var _in4 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(2))
			_ = _in4
			var _in5 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_dafny.CodePoint((_dafny.IntOfInt64(8)).Int32())))
			_ = _in5
			s = _in3
			i = _in4
			acc = _in5
			goto TAIL_CALL_START
		} else if (_2_c) == (_dafny.CodePoint('f')) {
			var _in6 _dafny.Sequence = s
			_ = _in6
			var _in7 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(2))
			_ = _in7
			var _in8 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_dafny.CodePoint((_dafny.IntOfInt64(12)).Int32())))
			_ = _in8
			s = _in6
			i = _in7
			acc = _in8
			goto TAIL_CALL_START
		} else if (_2_c) == (_dafny.CodePoint('n')) {
			var _in9 _dafny.Sequence = s
			_ = _in9
			var _in10 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(2))
			_ = _in10
			var _in11 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_dafny.CodePoint('\n')))
			_ = _in11
			s = _in9
			i = _in10
			acc = _in11
			goto TAIL_CALL_START
		} else if (_2_c) == (_dafny.CodePoint('r')) {
			var _in12 _dafny.Sequence = s
			_ = _in12
			var _in13 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(2))
			_ = _in13
			var _in14 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_dafny.CodePoint('\r')))
			_ = _in14
			s = _in12
			i = _in13
			acc = _in14
			goto TAIL_CALL_START
		} else if (_2_c) == (_dafny.CodePoint('t')) {
			var _in15 _dafny.Sequence = s
			_ = _in15
			var _in16 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(2))
			_ = _in16
			var _in17 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_dafny.CodePoint('\t')))
			_ = _in17
			s = _in15
			i = _in16
			acc = _in17
			goto TAIL_CALL_START
		} else if (_2_c) != (_dafny.CodePoint('u')) /* dircomp */ {
			return m_EHBP.Companion_Option_.Create_None_()
		} else {
			var _source0 m_EHBP.Option = Companion_Default___.Hex4(s, (_0_j).Plus(_dafny.IntOfInt64(2)))
			_ = _source0
			{
				if _source0.Is_None() {
					return m_EHBP.Companion_Option_.Create_None_()
				}
			}
			{
				var _3_cp _dafny.Int = _source0.Get_().(m_EHBP.Option_Some).Value.(_dafny.Int)
				_ = _3_cp
				if ((_dafny.IntOfInt64(55296)).Cmp(_3_cp) <= 0) && ((_3_cp).Cmp(_dafny.IntOfInt64(56319)) <= 0) {
					var _4_lo m_EHBP.Option = (func() m_EHBP.Option {
						if ((((_0_j).Plus(_dafny.IntOfInt64(8))).Cmp(_dafny.IntOfUint32((s).Cardinality())) <= 0) && (((s).Select(((_0_j).Plus(_dafny.IntOfInt64(6))).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('\\')))) && (((s).Select(((_0_j).Plus(_dafny.IntOfInt64(7))).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('u'))) {
							return Companion_Default___.Hex4(s, (_0_j).Plus(_dafny.IntOfInt64(8)))
						}
						return m_EHBP.Companion_Option_.Create_None_()
					})()
					_ = _4_lo
					if ((_4_lo).Is_Some()) && (((_dafny.IntOfInt64(56320)).Cmp((_4_lo).Dtor_value().(_dafny.Int)) <= 0) && (((_4_lo).Dtor_value().(_dafny.Int)).Cmp(_dafny.IntOfInt64(57343)) <= 0)) {
						var _in18 _dafny.Sequence = s
						_ = _in18
						var _in19 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(12))
						_ = _in19
						var _in20 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_dafny.CodePoint((((_dafny.IntOfInt64(65536)).Plus(((_3_cp).Minus(_dafny.IntOfInt64(55296))).Times(_dafny.IntOfInt64(1024)))).Plus(((_4_lo).Dtor_value().(_dafny.Int)).Minus(_dafny.IntOfInt64(56320)))).Int32())))
						_ = _in20
						s = _in18
						i = _in19
						acc = _in20
						goto TAIL_CALL_START
					} else {
						var _in21 _dafny.Sequence = s
						_ = _in21
						var _in22 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(6))
						_ = _in22
						var _in23 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_dafny.CodePoint((_dafny.IntOfInt64(65533)).Int32())))
						_ = _in23
						s = _in21
						i = _in22
						acc = _in23
						goto TAIL_CALL_START
					}
				} else if ((_dafny.IntOfInt64(56320)).Cmp(_3_cp) <= 0) && ((_3_cp).Cmp(_dafny.IntOfInt64(57343)) <= 0) {
					var _in24 _dafny.Sequence = s
					_ = _in24
					var _in25 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(6))
					_ = _in25
					var _in26 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_dafny.CodePoint((_dafny.IntOfInt64(65533)).Int32())))
					_ = _in26
					s = _in24
					i = _in25
					acc = _in26
					goto TAIL_CALL_START
				} else {
					var _in27 _dafny.Sequence = s
					_ = _in27
					var _in28 _dafny.Int = (_0_j).Plus(_dafny.IntOfInt64(6))
					_ = _in28
					var _in29 _dafny.Sequence = Companion_Default___.Keep(_1_run, _dafny.SeqOf(_dafny.CodePoint((_3_cp).Int32())))
					_ = _in29
					s = _in27
					i = _in28
					acc = _in29
					goto TAIL_CALL_START
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) Frac(s _dafny.Sequence, i _dafny.Int) m_EHBP.Option {
	if ((i).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0) && (((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('.'))) {
		if (((i).Plus(_dafny.One)).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0) && (Companion_Default___.IsDigit((s).Select(((i).Plus(_dafny.One)).Uint32()).(_dafny.CodePoint))) {
			return m_EHBP.Companion_Option_.Create_Some_(Companion_Default___.Digits(s, (i).Plus(_dafny.One)))
		} else {
			return m_EHBP.Companion_Option_.Create_None_()
		}
	} else {
		return m_EHBP.Companion_Option_.Create_Some_(i)
	}
}
func (_static *CompanionStruct_Default___) Exponent(s _dafny.Sequence, i _dafny.Int) m_EHBP.Option {
	if ((i).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0) && ((((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('e'))) || (((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('E')))) {
		var _0_j _dafny.Int = (func() _dafny.Int {
			if (((i).Plus(_dafny.One)).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0) && ((((s).Select(((i).Plus(_dafny.One)).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('+'))) || (((s).Select(((i).Plus(_dafny.One)).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('-')))) {
				return (i).Plus(_dafny.IntOfInt64(2))
			}
			return (i).Plus(_dafny.One)
		})()
		_ = _0_j
		if ((_0_j).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0) && (Companion_Default___.IsDigit((s).Select((_0_j).Uint32()).(_dafny.CodePoint))) {
			return m_EHBP.Companion_Option_.Create_Some_(Companion_Default___.Digits(s, _0_j))
		} else {
			return m_EHBP.Companion_Option_.Create_None_()
		}
	} else {
		return m_EHBP.Companion_Option_.Create_Some_(i)
	}
}
func (_static *CompanionStruct_Default___) ParseNumber(s _dafny.Sequence, i _dafny.Int) m_EHBP.Option {
	var _0_j _dafny.Int = (func() _dafny.Int {
		if ((i).Cmp(_dafny.IntOfUint32((s).Cardinality())) < 0) && (((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('-'))) {
			return (i).Plus(_dafny.One)
		}
		return i
	})()
	_ = _0_j
	if (_0_j).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
		return m_EHBP.Companion_Option_.Create_None_()
	} else {
		var _1_k m_EHBP.Option = (func() m_EHBP.Option {
			if ((s).Select((_0_j).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('0')) {
				return m_EHBP.Companion_Option_.Create_Some_((_0_j).Plus(_dafny.One))
			}
			return (func() m_EHBP.Option {
				if Companion_Default___.IsDigit((s).Select((_0_j).Uint32()).(_dafny.CodePoint)) {
					return m_EHBP.Companion_Option_.Create_Some_(Companion_Default___.Digits(s, (_0_j).Plus(_dafny.One)))
				}
				return m_EHBP.Companion_Option_.Create_None_()
			})()
		})()
		_ = _1_k
		if (_1_k).Is_None() {
			return m_EHBP.Companion_Option_.Create_None_()
		} else {
			var _source0 m_EHBP.Option = Companion_Default___.Frac(s, (_1_k).Dtor_value().(_dafny.Int))
			_ = _source0
			{
				if _source0.Is_None() {
					return m_EHBP.Companion_Option_.Create_None_()
				}
			}
			{
				var _2_f _dafny.Int = _source0.Get_().(m_EHBP.Option_Some).Value.(_dafny.Int)
				_ = _2_f
				var _source1 m_EHBP.Option = Companion_Default___.Exponent(s, _2_f)
				_ = _source1
				{
					if _source1.Is_None() {
						return m_EHBP.Companion_Option_.Create_None_()
					}
				}
				{
					var _3_end _dafny.Int = _source1.Get_().(m_EHBP.Option_Some).Value.(_dafny.Int)
					_ = _3_end
					return m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JNumber_((s).Subsequence((i).Uint32(), (_3_end).Uint32())), _3_end))
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) Literal(s _dafny.Sequence, i _dafny.Int, word _dafny.Sequence, value Json) m_EHBP.Option {
	if (((i).Plus(_dafny.IntOfUint32((word).Cardinality()))).Cmp(_dafny.IntOfUint32((s).Cardinality())) <= 0) && (_dafny.Companion_Sequence_.Equal((s).Subsequence((i).Uint32(), ((i).Plus(_dafny.IntOfUint32((word).Cardinality()))).Uint32()), word)) {
		return m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(value, (i).Plus(_dafny.IntOfUint32((word).Cardinality()))))
	} else {
		return m_EHBP.Companion_Option_.Create_None_()
	}
}
func (_static *CompanionStruct_Default___) ParseValue(s _dafny.Sequence, i _dafny.Int, depth _dafny.Int) m_EHBP.Option {
	if (i).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
		return m_EHBP.Companion_Option_.Create_None_()
	} else if ((((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('{'))) || (((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('[')))) && ((depth).Cmp(Companion_Default___.MaxJsonDepth()) >= 0) {
		return m_EHBP.Companion_Option_.Create_None_()
	} else if ((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('{')) {
		return Companion_Default___.ParseMembers(s, Companion_Default___.SkipWs(s, (i).Plus(_dafny.One)), (depth).Plus(_dafny.One), _dafny.SeqOf(), true)
	} else if ((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('[')) {
		return Companion_Default___.ParseItems(s, Companion_Default___.SkipWs(s, (i).Plus(_dafny.One)), (depth).Plus(_dafny.One), _dafny.SeqOf(), true)
	} else if ((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('"')) {
		var _source0 m_EHBP.Option = Companion_Default___.ParseString(s, (i).Plus(_dafny.One), _dafny.SeqOf())
		_ = _source0
		{
			if _source0.Is_None() {
				return m_EHBP.Companion_Option_.Create_None_()
			}
		}
		{
			var value0 _dafny.Tuple = _source0.Get_().(m_EHBP.Option_Some).Value.(_dafny.Tuple)
			_ = value0
			var _0_str _dafny.Sequence = (*(value0).IndexInt(0)).(_dafny.Sequence)
			_ = _0_str
			var _1_j _dafny.Int = (*(value0).IndexInt(1)).(_dafny.Int)
			_ = _1_j
			return m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JString_(_0_str), _1_j))
		}
	} else if ((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('t')) {
		return Companion_Default___.Literal(s, i, _dafny.UnicodeSeqOfUtf8Bytes("true"), Companion_Json_.Create_JBool_(true))
	} else if ((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('f')) {
		return Companion_Default___.Literal(s, i, _dafny.UnicodeSeqOfUtf8Bytes("false"), Companion_Json_.Create_JBool_(false))
	} else if ((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('n')) {
		return Companion_Default___.Literal(s, i, _dafny.UnicodeSeqOfUtf8Bytes("null"), Companion_Json_.Create_JNull_())
	} else {
		return Companion_Default___.ParseNumber(s, i)
	}
}
func (_static *CompanionStruct_Default___) ItemsFrom(s _dafny.Sequence, i _dafny.Int, depth _dafny.Int, acc _dafny.Sequence, first bool) m_EHBP.Option {
	if (i).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
		return m_EHBP.Companion_Option_.Create_None_()
	} else if (first) && (((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint(']'))) {
		return m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JArray_(acc), (i).Plus(_dafny.One)))
	} else {
		var _source0 m_EHBP.Option = Companion_Default___.ParseValue(s, i, depth)
		_ = _source0
		{
			if _source0.Is_None() {
				return m_EHBP.Companion_Option_.Create_None_()
			}
		}
		{
			var value0 _dafny.Tuple = _source0.Get_().(m_EHBP.Option_Some).Value.(_dafny.Tuple)
			_ = value0
			var _0_v Json = (*(value0).IndexInt(0)).(Json)
			_ = _0_v
			var _1_k _dafny.Int = (*(value0).IndexInt(1)).(_dafny.Int)
			_ = _1_k
			var _2_m _dafny.Int = Companion_Default___.SkipWs(s, _1_k)
			_ = _2_m
			if (_2_m).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
				return m_EHBP.Companion_Option_.Create_None_()
			} else if ((s).Select((_2_m).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint(',')) {
				return Companion_Default___.ItemsFrom(s, Companion_Default___.SkipWs(s, (_2_m).Plus(_dafny.One)), depth, _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_0_v)), false)
			} else if ((s).Select((_2_m).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint(']')) {
				return m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JArray_(_dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_0_v))), (_2_m).Plus(_dafny.One)))
			} else {
				return m_EHBP.Companion_Option_.Create_None_()
			}
		}
	}
}
func (_static *CompanionStruct_Default___) ParseItems(s _dafny.Sequence, i _dafny.Int, depth _dafny.Int, acc _dafny.Sequence, first bool) m_EHBP.Option {
	var r m_EHBP.Option = m_EHBP.Companion_Option_.Default()
	_ = r
	var _0_a _dafny.Array
	_ = _0_a
	var _len0_0 _dafny.Int = _dafny.Zero
	_ = _len0_0
	var _nw0 _dafny.Array
	_ = _nw0
	if _len0_0.Cmp(_dafny.Zero) == 0 {
		_nw0 = _dafny.NewArray(_len0_0)
	} else {
		var _init0 func(_dafny.Int) Json = func(_1___v14 _dafny.Int) Json {
			return Companion_Json_.Create_JNull_()
		}
		_ = _init0
		var _element0_0 = _init0(_dafny.Zero)
		_ = _element0_0
		_nw0 = _dafny.NewArrayFromExample(_element0_0, nil, _len0_0)
		(_nw0).ArraySet1(_element0_0, 0)
		var _nativeLen0_0 = (_len0_0).Int()
		_ = _nativeLen0_0
		for _i0_0 := 1; _i0_0 < _nativeLen0_0; _i0_0++ {
			(_nw0).ArraySet1(_init0(_dafny.IntOf(_i0_0)), _i0_0)
		}
	}
	_0_a = _nw0
	var _2_n _dafny.Int
	_ = _2_n
	var _3_j _dafny.Int
	_ = _3_j
	var _4_f bool
	_ = _4_f
	var _rhs0 _dafny.Int = _dafny.Zero
	_ = _rhs0
	var _rhs1 _dafny.Int = i
	_ = _rhs1
	var _rhs2 bool = first
	_ = _rhs2
	_2_n = _rhs0
	_3_j = _rhs1
	_4_f = _rhs2
	for true {
		if (_3_j).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		if (_4_f) && (((s).Select((_3_j).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint(']'))) {
			r = m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JArray_(_dafny.Companion_Sequence_.Concatenate(acc, _dafny.ArrayRangeToSeq(_0_a, _dafny.NilInt, (_2_n)))), (_3_j).Plus(_dafny.One)))
			return r
		}
		var _5_r m_EHBP.Option
		_ = _5_r
		_5_r = Companion_Default___.ParseValue(s, _3_j, depth)
		if (_5_r).Is_None() {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		var _let_tmp_rhs0 _dafny.Tuple = (_5_r).Dtor_value().(_dafny.Tuple)
		_ = _let_tmp_rhs0
		var _6_v Json = (*(_let_tmp_rhs0).IndexInt(0)).(Json)
		_ = _6_v
		var _7_k _dafny.Int = (*(_let_tmp_rhs0).IndexInt(1)).(_dafny.Int)
		_ = _7_k
		var _8_m _dafny.Int
		_ = _8_m
		_8_m = Companion_Default___.SkipWs(s, _7_k)
		if (_8_m).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		if ((s).Select((_8_m).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint(']')) {
			r = m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JArray_(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(acc, _dafny.ArrayRangeToSeq(_0_a, _dafny.NilInt, (_2_n))), _dafny.SeqOf(_6_v))), (_8_m).Plus(_dafny.One)))
			return r
		}
		if ((s).Select((_8_m).Uint32()).(_dafny.CodePoint)) != (_dafny.CodePoint(',')) /* dircomp */ {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		var _out0 _dafny.Array
		_ = _out0
		_out0 = Companion_Default___.Append(_0_a, _2_n, _6_v)
		_0_a = _out0
		var _rhs3 _dafny.Int = (_2_n).Plus(_dafny.One)
		_ = _rhs3
		var _rhs4 _dafny.Int = Companion_Default___.SkipWs(s, (_8_m).Plus(_dafny.One))
		_ = _rhs4
		var _rhs5 bool = false
		_ = _rhs5
		_2_n = _rhs3
		_3_j = _rhs4
		_4_f = _rhs5
	}
	return r
}
func (_static *CompanionStruct_Default___) MembersFrom(s _dafny.Sequence, i _dafny.Int, depth _dafny.Int, acc _dafny.Sequence, first bool) m_EHBP.Option {
	if (i).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
		return m_EHBP.Companion_Option_.Create_None_()
	} else if (first) && (((s).Select((i).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('}'))) {
		return m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JObject_(acc), (i).Plus(_dafny.One)))
	} else if ((s).Select((i).Uint32()).(_dafny.CodePoint)) != (_dafny.CodePoint('"')) /* dircomp */ {
		return m_EHBP.Companion_Option_.Create_None_()
	} else {
		var _source0 m_EHBP.Option = Companion_Default___.ParseString(s, (i).Plus(_dafny.One), _dafny.SeqOf())
		_ = _source0
		{
			if _source0.Is_None() {
				return m_EHBP.Companion_Option_.Create_None_()
			}
		}
		{
			var value0 _dafny.Tuple = _source0.Get_().(m_EHBP.Option_Some).Value.(_dafny.Tuple)
			_ = value0
			var _0_name _dafny.Sequence = (*(value0).IndexInt(0)).(_dafny.Sequence)
			_ = _0_name
			var _1_k _dafny.Int = (*(value0).IndexInt(1)).(_dafny.Int)
			_ = _1_k
			var _2_c _dafny.Int = Companion_Default___.SkipWs(s, _1_k)
			_ = _2_c
			if ((_2_c).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0) || (((s).Select((_2_c).Uint32()).(_dafny.CodePoint)) != (_dafny.CodePoint(':')) /* dircomp */) {
				return m_EHBP.Companion_Option_.Create_None_()
			} else {
				var _source1 m_EHBP.Option = Companion_Default___.ParseValue(s, Companion_Default___.SkipWs(s, (_2_c).Plus(_dafny.One)), depth)
				_ = _source1
				{
					if _source1.Is_None() {
						return m_EHBP.Companion_Option_.Create_None_()
					}
				}
				{
					var value1 _dafny.Tuple = _source1.Get_().(m_EHBP.Option_Some).Value.(_dafny.Tuple)
					_ = value1
					var _3_v Json = (*(value1).IndexInt(0)).(Json)
					_ = _3_v
					var _4_k2 _dafny.Int = (*(value1).IndexInt(1)).(_dafny.Int)
					_ = _4_k2
					var _5_m _dafny.Int = Companion_Default___.SkipWs(s, _4_k2)
					_ = _5_m
					if (_5_m).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
						return m_EHBP.Companion_Option_.Create_None_()
					} else if ((s).Select((_5_m).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint(',')) {
						return Companion_Default___.MembersFrom(s, Companion_Default___.SkipWs(s, (_5_m).Plus(_dafny.One)), depth, _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.TupleOf(_0_name, _3_v))), false)
					} else if ((s).Select((_5_m).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('}')) {
						return m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JObject_(_dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.TupleOf(_0_name, _3_v)))), (_5_m).Plus(_dafny.One)))
					} else {
						return m_EHBP.Companion_Option_.Create_None_()
					}
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) ParseMembers(s _dafny.Sequence, i _dafny.Int, depth _dafny.Int, acc _dafny.Sequence, first bool) m_EHBP.Option {
	var r m_EHBP.Option = m_EHBP.Companion_Option_.Default()
	_ = r
	var _0_a _dafny.Array
	_ = _0_a
	var _len0_0 _dafny.Int = _dafny.Zero
	_ = _len0_0
	var _nw0 _dafny.Array
	_ = _nw0
	if _len0_0.Cmp(_dafny.Zero) == 0 {
		_nw0 = _dafny.NewArray(_len0_0)
	} else {
		var _init0 func(_dafny.Int) _dafny.Tuple = func(_1___v15 _dafny.Int) _dafny.Tuple {
			return _dafny.TupleOf(_dafny.UnicodeSeqOfUtf8Bytes(""), Companion_Json_.Create_JNull_())
		}
		_ = _init0
		var _element0_0 = _init0(_dafny.Zero)
		_ = _element0_0
		_nw0 = _dafny.NewArrayFromExample(_element0_0, nil, _len0_0)
		(_nw0).ArraySet1(_element0_0, 0)
		var _nativeLen0_0 = (_len0_0).Int()
		_ = _nativeLen0_0
		for _i0_0 := 1; _i0_0 < _nativeLen0_0; _i0_0++ {
			(_nw0).ArraySet1(_init0(_dafny.IntOf(_i0_0)), _i0_0)
		}
	}
	_0_a = _nw0
	var _2_n _dafny.Int
	_ = _2_n
	var _3_j _dafny.Int
	_ = _3_j
	var _4_f bool
	_ = _4_f
	var _rhs0 _dafny.Int = _dafny.Zero
	_ = _rhs0
	var _rhs1 _dafny.Int = i
	_ = _rhs1
	var _rhs2 bool = first
	_ = _rhs2
	_2_n = _rhs0
	_3_j = _rhs1
	_4_f = _rhs2
	for true {
		if (_3_j).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		if (_4_f) && (((s).Select((_3_j).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('}'))) {
			r = m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JObject_(_dafny.Companion_Sequence_.Concatenate(acc, _dafny.ArrayRangeToSeq(_0_a, _dafny.NilInt, (_2_n)))), (_3_j).Plus(_dafny.One)))
			return r
		}
		if ((s).Select((_3_j).Uint32()).(_dafny.CodePoint)) != (_dafny.CodePoint('"')) /* dircomp */ {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		var _5_rn m_EHBP.Option
		_ = _5_rn
		_5_rn = Companion_Default___.ParseString(s, (_3_j).Plus(_dafny.One), _dafny.SeqOf())
		if (_5_rn).Is_None() {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		var _let_tmp_rhs0 _dafny.Tuple = (_5_rn).Dtor_value().(_dafny.Tuple)
		_ = _let_tmp_rhs0
		var _6_name _dafny.Sequence = (*(_let_tmp_rhs0).IndexInt(0)).(_dafny.Sequence)
		_ = _6_name
		var _7_k _dafny.Int = (*(_let_tmp_rhs0).IndexInt(1)).(_dafny.Int)
		_ = _7_k
		var _8_c _dafny.Int
		_ = _8_c
		_8_c = Companion_Default___.SkipWs(s, _7_k)
		if ((_8_c).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0) || (((s).Select((_8_c).Uint32()).(_dafny.CodePoint)) != (_dafny.CodePoint(':')) /* dircomp */) {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		var _9_r m_EHBP.Option
		_ = _9_r
		_9_r = Companion_Default___.ParseValue(s, Companion_Default___.SkipWs(s, (_8_c).Plus(_dafny.One)), depth)
		if (_9_r).Is_None() {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		var _let_tmp_rhs1 _dafny.Tuple = (_9_r).Dtor_value().(_dafny.Tuple)
		_ = _let_tmp_rhs1
		var _10_v Json = (*(_let_tmp_rhs1).IndexInt(0)).(Json)
		_ = _10_v
		var _11_k2 _dafny.Int = (*(_let_tmp_rhs1).IndexInt(1)).(_dafny.Int)
		_ = _11_k2
		var _12_m _dafny.Int
		_ = _12_m
		_12_m = Companion_Default___.SkipWs(s, _11_k2)
		if (_12_m).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		if ((s).Select((_12_m).Uint32()).(_dafny.CodePoint)) == (_dafny.CodePoint('}')) {
			r = m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(Companion_Json_.Create_JObject_(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(acc, _dafny.ArrayRangeToSeq(_0_a, _dafny.NilInt, (_2_n))), _dafny.SeqOf(_dafny.TupleOf(_6_name, _10_v)))), (_12_m).Plus(_dafny.One)))
			return r
		}
		if ((s).Select((_12_m).Uint32()).(_dafny.CodePoint)) != (_dafny.CodePoint(',')) /* dircomp */ {
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		var _out0 _dafny.Array
		_ = _out0
		_out0 = Companion_Default___.Append(_0_a, _2_n, _dafny.TupleOf(_6_name, _10_v))
		_0_a = _out0
		var _rhs3 _dafny.Int = (_2_n).Plus(_dafny.One)
		_ = _rhs3
		var _rhs4 _dafny.Int = Companion_Default___.SkipWs(s, (_12_m).Plus(_dafny.One))
		_ = _rhs4
		var _rhs5 bool = false
		_ = _rhs5
		_2_n = _rhs3
		_3_j = _rhs4
		_4_f = _rhs5
	}
	return r
}
func (_static *CompanionStruct_Default___) Append(a _dafny.Array, n _dafny.Int, v interface{}) _dafny.Array {
	var b _dafny.Array = _dafny.NewArrayWithValue(nil, _dafny.IntOf(0))
	_ = b
	if (n).Cmp(_dafny.ArrayLen((a), 0)) < 0 {
		(a).ArraySet1(v, (n).Int())
		b = a
		return b
	}
	var _len0_0 _dafny.Int = ((_dafny.IntOfInt64(2)).Times(n)).Plus(_dafny.One)
	_ = _len0_0
	var _nw0 _dafny.Array
	_ = _nw0
	if _len0_0.Cmp(_dafny.Zero) == 0 {
		_nw0 = _dafny.NewArray(_len0_0)
	} else {
		var _init0 func(_dafny.Int) interface{} = (func(_0_n _dafny.Int, _1_a _dafny.Array, _2_v interface{}) func(_dafny.Int) interface{} {
			return func(_3_k _dafny.Int) interface{} {
				return (func() interface{} {
					if ((_3_k).Sign() != -1) && ((_3_k).Cmp(_0_n) < 0) {
						return (_1_a).ArrayGet1((_3_k).Int())
					}
					return _2_v
				})()
			}
		})(n, a, v)
		_ = _init0
		var _element0_0 = _init0(_dafny.Zero)
		_ = _element0_0
		_nw0 = _dafny.NewArrayFromExample(_element0_0, nil, _len0_0)
		(_nw0).ArraySet1(_element0_0, 0)
		var _nativeLen0_0 = (_len0_0).Int()
		_ = _nativeLen0_0
		for _i0_0 := 1; _i0_0 < _nativeLen0_0; _i0_0++ {
			(_nw0).ArraySet1(_init0(_dafny.IntOf(_i0_0)), _i0_0)
		}
	}
	b = _nw0
	return b
}
func (_static *CompanionStruct_Default___) ParseJson(s _dafny.Sequence) m_EHBP.Option {
	var _source0 m_EHBP.Option = Companion_Default___.ParseValue(s, Companion_Default___.SkipWs(s, _dafny.Zero), _dafny.Zero)
	_ = _source0
	{
		if _source0.Is_None() {
			return m_EHBP.Companion_Option_.Create_None_()
		}
	}
	{
		var value0 _dafny.Tuple = _source0.Get_().(m_EHBP.Option_Some).Value.(_dafny.Tuple)
		_ = value0
		var _0_v Json = (*(value0).IndexInt(0)).(Json)
		_ = _0_v
		var _1_j _dafny.Int = (*(value0).IndexInt(1)).(_dafny.Int)
		_ = _1_j
		if (Companion_Default___.SkipWs(s, _1_j)).Cmp(_dafny.IntOfUint32((s).Cardinality())) == 0 {
			return m_EHBP.Companion_Option_.Create_Some_(_0_v)
		} else {
			return m_EHBP.Companion_Option_.Create_None_()
		}
	}
}
func (_static *CompanionStruct_Default___) Member(members _dafny.Sequence, name _dafny.Sequence) m_EHBP.Option {
	return Companion_Default___.MemberFrom(members, _dafny.IntOfUint32((members).Cardinality()), name)
}
func (_static *CompanionStruct_Default___) MemberFrom(members _dafny.Sequence, n _dafny.Int, name _dafny.Sequence) m_EHBP.Option {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (n).Sign() == 0 {
		return m_EHBP.Companion_Option_.Create_None_()
	} else if _dafny.Companion_Sequence_.Equal((*((members).Select(((n).Minus(_dafny.One)).Uint32()).(_dafny.Tuple)).IndexInt(0)).(_dafny.Sequence), name) {
		return m_EHBP.Companion_Option_.Create_Some_((*((members).Select(((n).Minus(_dafny.One)).Uint32()).(_dafny.Tuple)).IndexInt(1)).(Json))
	} else {
		var _in0 _dafny.Sequence = members
		_ = _in0
		var _in1 _dafny.Int = (n).Minus(_dafny.One)
		_ = _in1
		var _in2 _dafny.Sequence = name
		_ = _in2
		members = _in0
		n = _in1
		name = _in2
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) StringMember(members _dafny.Sequence, name _dafny.Sequence) m_EHBP.Option {
	var _source0 m_EHBP.Option = Companion_Default___.Member(members, name)
	_ = _source0
	{
		if _source0.Is_Some() {
			var value0 Json = _source0.Get_().(m_EHBP.Option_Some).Value.(Json)
			_ = value0
			if value0.Is_JString() {
				var _0_v _dafny.Sequence = value0.Get_().(Json_JString).S
				_ = _0_v
				return m_EHBP.Companion_Option_.Create_Some_(_0_v)
			}
		}
	}
	{
		return m_EHBP.Companion_Option_.Create_None_()
	}
}
func (_static *CompanionStruct_Default___) Cont(b uint8) bool {
	return ((uint8(128)) <= (b)) && ((b) <= (uint8(191)))
}
func (_static *CompanionStruct_Default___) Utf8From(b _dafny.Sequence, i _dafny.Int, acc _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (i).Cmp(_dafny.IntOfUint32((b).Cardinality())) == 0 {
		return acc
	} else {
		var _0_c uint8 = (b).Select((i).Uint32()).(uint8)
		_ = _0_c
		if (_0_c) < (uint8(128)) {
			var _in0 _dafny.Sequence = b
			_ = _in0
			var _in1 _dafny.Int = (i).Plus(_dafny.One)
			_ = _in1
			var _in2 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.CodePoint((_0_c))))
			_ = _in2
			b = _in0
			i = _in1
			acc = _in2
			goto TAIL_CALL_START
		} else if ((((uint8(194)) <= (_0_c)) && ((_0_c) <= (uint8(223)))) && (((i).Plus(_dafny.IntOfInt64(2))).Cmp(_dafny.IntOfUint32((b).Cardinality())) <= 0)) && (Companion_Default___.Cont((b).Select(((i).Plus(_dafny.One)).Uint32()).(uint8))) {
			var _in3 _dafny.Sequence = b
			_ = _in3
			var _in4 _dafny.Int = (i).Plus(_dafny.IntOfInt64(2))
			_ = _in4
			var _in5 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.CodePoint(((((_dafny.IntOfUint8(_0_c)).Minus(_dafny.IntOfInt64(192))).Times(_dafny.IntOfInt64(64))).Plus((_dafny.IntOfUint8((b).Select(((i).Plus(_dafny.One)).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128)))).Int32())))
			_ = _in5
			b = _in3
			i = _in4
			acc = _in5
			goto TAIL_CALL_START
		} else if (((((uint8(224)) <= (_0_c)) && ((_0_c) <= (uint8(239)))) && (((i).Plus(_dafny.IntOfInt64(3))).Cmp(_dafny.IntOfUint32((b).Cardinality())) <= 0)) && (Companion_Default___.Cont((b).Select(((i).Plus(_dafny.One)).Uint32()).(uint8)))) && (Companion_Default___.Cont((b).Select(((i).Plus(_dafny.IntOfInt64(2))).Uint32()).(uint8))) {
			var _1_cp _dafny.Int = ((((_dafny.IntOfUint8(_0_c)).Minus(_dafny.IntOfInt64(224))).Times(_dafny.IntOfInt64(4096))).Plus(((_dafny.IntOfUint8((b).Select(((i).Plus(_dafny.One)).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128))).Times(_dafny.IntOfInt64(64)))).Plus((_dafny.IntOfUint8((b).Select(((i).Plus(_dafny.IntOfInt64(2))).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128)))
			_ = _1_cp
			if ((_1_cp).Cmp(_dafny.IntOfInt64(2048)) < 0) || (((_dafny.IntOfInt64(55296)).Cmp(_1_cp) <= 0) && ((_1_cp).Cmp(_dafny.IntOfInt64(57343)) <= 0)) {
				var _in6 _dafny.Sequence = b
				_ = _in6
				var _in7 _dafny.Int = (i).Plus(_dafny.One)
				_ = _in7
				var _in8 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.CodePoint((_dafny.IntOfInt64(65533)).Int32())))
				_ = _in8
				b = _in6
				i = _in7
				acc = _in8
				goto TAIL_CALL_START
			} else {
				var _in9 _dafny.Sequence = b
				_ = _in9
				var _in10 _dafny.Int = (i).Plus(_dafny.IntOfInt64(3))
				_ = _in10
				var _in11 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.CodePoint((_1_cp).Int32())))
				_ = _in11
				b = _in9
				i = _in10
				acc = _in11
				goto TAIL_CALL_START
			}
		} else if ((((((uint8(240)) <= (_0_c)) && ((_0_c) <= (uint8(244)))) && (((i).Plus(_dafny.IntOfInt64(4))).Cmp(_dafny.IntOfUint32((b).Cardinality())) <= 0)) && (Companion_Default___.Cont((b).Select(((i).Plus(_dafny.One)).Uint32()).(uint8)))) && (Companion_Default___.Cont((b).Select(((i).Plus(_dafny.IntOfInt64(2))).Uint32()).(uint8)))) && (Companion_Default___.Cont((b).Select(((i).Plus(_dafny.IntOfInt64(3))).Uint32()).(uint8))) {
			var _2_cp _dafny.Int = (((((_dafny.IntOfUint8(_0_c)).Minus(_dafny.IntOfInt64(240))).Times(_dafny.IntOfInt64(262144))).Plus(((_dafny.IntOfUint8((b).Select(((i).Plus(_dafny.One)).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128))).Times(_dafny.IntOfInt64(4096)))).Plus(((_dafny.IntOfUint8((b).Select(((i).Plus(_dafny.IntOfInt64(2))).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128))).Times(_dafny.IntOfInt64(64)))).Plus((_dafny.IntOfUint8((b).Select(((i).Plus(_dafny.IntOfInt64(3))).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128)))
			_ = _2_cp
			if ((_2_cp).Cmp(_dafny.IntOfInt64(65536)) < 0) || ((_2_cp).Cmp(_dafny.IntOfInt64(1114111)) > 0) {
				var _in12 _dafny.Sequence = b
				_ = _in12
				var _in13 _dafny.Int = (i).Plus(_dafny.One)
				_ = _in13
				var _in14 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.CodePoint((_dafny.IntOfInt64(65533)).Int32())))
				_ = _in14
				b = _in12
				i = _in13
				acc = _in14
				goto TAIL_CALL_START
			} else {
				var _in15 _dafny.Sequence = b
				_ = _in15
				var _in16 _dafny.Int = (i).Plus(_dafny.IntOfInt64(4))
				_ = _in16
				var _in17 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.CodePoint((_2_cp).Int32())))
				_ = _in17
				b = _in15
				i = _in16
				acc = _in17
				goto TAIL_CALL_START
			}
		} else {
			var _in18 _dafny.Sequence = b
			_ = _in18
			var _in19 _dafny.Int = (i).Plus(_dafny.One)
			_ = _in19
			var _in20 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(_dafny.CodePoint((_dafny.IntOfInt64(65533)).Int32())))
			_ = _in20
			b = _in18
			i = _in19
			acc = _in20
			goto TAIL_CALL_START
		}
	}
}
func (_static *CompanionStruct_Default___) Utf8(b _dafny.Sequence) _dafny.Sequence {
	var _hresult _dafny.Sequence = _dafny.EmptySeq
	_ = _hresult
	var _0_a _dafny.Array
	_ = _0_a
	var _len0_0 _dafny.Int = _dafny.IntOfUint32((b).Cardinality())
	_ = _len0_0
	var _nw0 _dafny.Array
	_ = _nw0
	if _len0_0.Cmp(_dafny.Zero) == 0 {
		_nw0 = _dafny.NewArray(_len0_0)
	} else {
		var _init0 func(_dafny.Int) _dafny.CodePoint = func(_1___v17 _dafny.Int) _dafny.CodePoint {
			return _dafny.CodePoint(' ')
		}
		_ = _init0
		var _element0_0 = _init0(_dafny.Zero)
		_ = _element0_0
		_nw0 = _dafny.NewArrayFromExample(_element0_0, nil, _len0_0)
		(_nw0).ArraySet1CodePoint(_element0_0, 0)
		var _nativeLen0_0 = (_len0_0).Int()
		_ = _nativeLen0_0
		for _i0_0 := 1; _i0_0 < _nativeLen0_0; _i0_0++ {
			(_nw0).ArraySet1CodePoint(_init0(_dafny.IntOf(_i0_0)), _i0_0)
		}
	}
	_0_a = _nw0
	var _2_i _dafny.Int
	_ = _2_i
	var _3_n _dafny.Int
	_ = _3_n
	var _rhs0 _dafny.Int = _dafny.Zero
	_ = _rhs0
	var _rhs1 _dafny.Int = _dafny.Zero
	_ = _rhs1
	_2_i = _rhs0
	_3_n = _rhs1
	for (_2_i).Cmp(_dafny.IntOfUint32((b).Cardinality())) < 0 {
		var _4_c uint8
		_ = _4_c
		_4_c = (b).Select((_2_i).Uint32()).(uint8)
		var _5_cp _dafny.Int
		_ = _5_cp
		var _6_w _dafny.Int
		_ = _6_w
		var _rhs2 _dafny.Int = _dafny.IntOfInt64(65533)
		_ = _rhs2
		var _rhs3 _dafny.Int = _dafny.One
		_ = _rhs3
		_5_cp = _rhs2
		_6_w = _rhs3
		if (_4_c) < (uint8(128)) {
			_5_cp = _dafny.IntOfUint8(_4_c)
		} else if ((((uint8(194)) <= (_4_c)) && ((_4_c) <= (uint8(223)))) && (((_2_i).Plus(_dafny.IntOfInt64(2))).Cmp(_dafny.IntOfUint32((b).Cardinality())) <= 0)) && (Companion_Default___.Cont((b).Select(((_2_i).Plus(_dafny.One)).Uint32()).(uint8))) {
			var _rhs4 _dafny.Int = (((_dafny.IntOfUint8(_4_c)).Minus(_dafny.IntOfInt64(192))).Times(_dafny.IntOfInt64(64))).Plus((_dafny.IntOfUint8((b).Select(((_2_i).Plus(_dafny.One)).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128)))
			_ = _rhs4
			var _rhs5 _dafny.Int = _dafny.IntOfInt64(2)
			_ = _rhs5
			_5_cp = _rhs4
			_6_w = _rhs5
		} else if (((((uint8(224)) <= (_4_c)) && ((_4_c) <= (uint8(239)))) && (((_2_i).Plus(_dafny.IntOfInt64(3))).Cmp(_dafny.IntOfUint32((b).Cardinality())) <= 0)) && (Companion_Default___.Cont((b).Select(((_2_i).Plus(_dafny.One)).Uint32()).(uint8)))) && (Companion_Default___.Cont((b).Select(((_2_i).Plus(_dafny.IntOfInt64(2))).Uint32()).(uint8))) {
			var _7_v _dafny.Int
			_ = _7_v
			_7_v = ((((_dafny.IntOfUint8(_4_c)).Minus(_dafny.IntOfInt64(224))).Times(_dafny.IntOfInt64(4096))).Plus(((_dafny.IntOfUint8((b).Select(((_2_i).Plus(_dafny.One)).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128))).Times(_dafny.IntOfInt64(64)))).Plus((_dafny.IntOfUint8((b).Select(((_2_i).Plus(_dafny.IntOfInt64(2))).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128)))
			if !(((_7_v).Cmp(_dafny.IntOfInt64(2048)) < 0) || (((_dafny.IntOfInt64(55296)).Cmp(_7_v) <= 0) && ((_7_v).Cmp(_dafny.IntOfInt64(57343)) <= 0))) {
				var _rhs6 _dafny.Int = _7_v
				_ = _rhs6
				var _rhs7 _dafny.Int = _dafny.IntOfInt64(3)
				_ = _rhs7
				_5_cp = _rhs6
				_6_w = _rhs7
			}
		} else if ((((((uint8(240)) <= (_4_c)) && ((_4_c) <= (uint8(244)))) && (((_2_i).Plus(_dafny.IntOfInt64(4))).Cmp(_dafny.IntOfUint32((b).Cardinality())) <= 0)) && (Companion_Default___.Cont((b).Select(((_2_i).Plus(_dafny.One)).Uint32()).(uint8)))) && (Companion_Default___.Cont((b).Select(((_2_i).Plus(_dafny.IntOfInt64(2))).Uint32()).(uint8)))) && (Companion_Default___.Cont((b).Select(((_2_i).Plus(_dafny.IntOfInt64(3))).Uint32()).(uint8))) {
			var _8_v _dafny.Int
			_ = _8_v
			_8_v = (((((_dafny.IntOfUint8(_4_c)).Minus(_dafny.IntOfInt64(240))).Times(_dafny.IntOfInt64(262144))).Plus(((_dafny.IntOfUint8((b).Select(((_2_i).Plus(_dafny.One)).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128))).Times(_dafny.IntOfInt64(4096)))).Plus(((_dafny.IntOfUint8((b).Select(((_2_i).Plus(_dafny.IntOfInt64(2))).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128))).Times(_dafny.IntOfInt64(64)))).Plus((_dafny.IntOfUint8((b).Select(((_2_i).Plus(_dafny.IntOfInt64(3))).Uint32()).(uint8))).Minus(_dafny.IntOfInt64(128)))
			if !(((_8_v).Cmp(_dafny.IntOfInt64(65536)) < 0) || ((_8_v).Cmp(_dafny.IntOfInt64(1114111)) > 0)) {
				var _rhs8 _dafny.Int = _8_v
				_ = _rhs8
				var _rhs9 _dafny.Int = _dafny.IntOfInt64(4)
				_ = _rhs9
				_5_cp = _rhs8
				_6_w = _rhs9
			}
		}
		(_0_a).ArraySet1CodePoint(_dafny.CodePoint((_5_cp).Int32()), (_3_n).Int())
		var _rhs10 _dafny.Int = (_2_i).Plus(_6_w)
		_ = _rhs10
		var _rhs11 _dafny.Int = (_3_n).Plus(_dafny.One)
		_ = _rhs11
		_2_i = _rhs10
		_3_n = _rhs11
	}
	_hresult = _dafny.ArrayRangeToSeq(_0_a, _dafny.NilInt, (_3_n))
	return _hresult
	return _hresult
}
func (_static *CompanionStruct_Default___) ParseProblem(body _dafny.Sequence) _dafny.Tuple {
	var _source0 m_EHBP.Option = Companion_Default___.ParseJson(Companion_Default___.Utf8(body))
	_ = _source0
	{
		if _source0.Is_Some() {
			var value0 Json = _source0.Get_().(m_EHBP.Option_Some).Value.(Json)
			_ = value0
			if value0.Is_JObject() {
				var _0_members _dafny.Sequence = value0.Get_().(Json_JObject).Members
				_ = _0_members
				return _dafny.TupleOf(true, Companion_Default___.StringMember(_0_members, _dafny.UnicodeSeqOfUtf8Bytes("type")), Companion_Default___.StringMember(_0_members, _dafny.UnicodeSeqOfUtf8Bytes("title")))
			}
		}
	}
	{
		return _dafny.TupleOf(false, m_EHBP.Companion_Option_.Create_None_(), m_EHBP.Companion_Option_.Create_None_())
	}
}
func (_static *CompanionStruct_Default___) ParseToken(json _dafny.Sequence) _dafny.Tuple {
	var _source0 m_EHBP.Option = Companion_Default___.ParseJson(json)
	_ = _source0
	{
		if _source0.Is_Some() {
			var value0 Json = _source0.Get_().(m_EHBP.Option_Some).Value.(Json)
			_ = value0
			if value0.Is_JObject() {
				var _0_members _dafny.Sequence = value0.Get_().(Json_JObject).Members
				_ = _0_members
				return _dafny.TupleOf(Companion_Default___.StringMember(_0_members, _dafny.UnicodeSeqOfUtf8Bytes("exportedSecret")), Companion_Default___.StringMember(_0_members, _dafny.UnicodeSeqOfUtf8Bytes("requestEnc")))
			}
		}
	}
	{
		return _dafny.TupleOf(m_EHBP.Companion_Option_.Create_None_(), m_EHBP.Companion_Option_.Create_None_())
	}
}
func (_static *CompanionStruct_Default___) Escape(s _dafny.Sequence) _dafny.Sequence {
	var _0___accumulator _dafny.Sequence = _dafny.SeqOf()
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((s).Cardinality())).Sign() == 0 {
		return _dafny.Companion_Sequence_.Concatenate(_0___accumulator, _dafny.SeqOf())
	} else {
		var _1_c _dafny.CodePoint = (s).Select(0).(_dafny.CodePoint)
		_ = _1_c
		_0___accumulator = _dafny.Companion_Sequence_.Concatenate(_0___accumulator, (func() _dafny.Sequence {
			if (_1_c) == (_dafny.CodePoint('"')) {
				return _dafny.UnicodeSeqOfUtf8Bytes("\\\"")
			}
			return (func() _dafny.Sequence {
				if (_1_c) == (_dafny.CodePoint('\\')) {
					return _dafny.UnicodeSeqOfUtf8Bytes("\\\\")
				}
				return (func() _dafny.Sequence {
					if (_dafny.IntOfInt32(rune(_1_c))).Cmp(_dafny.IntOfInt64(32)) < 0 {
						return _dafny.Companion_Sequence_.Concatenate(_dafny.UnicodeSeqOfUtf8Bytes("\\u00"), _dafny.SeqOf((m_EHBP.Companion_Default___.HexDigits()).Select(((_dafny.IntOfInt32(rune(_1_c))).DivBy(_dafny.IntOfInt64(16))).Uint32()).(_dafny.CodePoint), (m_EHBP.Companion_Default___.HexDigits()).Select(((_dafny.IntOfInt32(rune(_1_c))).Modulo(_dafny.IntOfInt64(16))).Uint32()).(_dafny.CodePoint)))
					}
					return _dafny.SeqOf(_1_c)
				})()
			})()
		})())
		var _in0 _dafny.Sequence = (s).Drop(1)
		_ = _in0
		s = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) FormatToken(exportedSecretHex _dafny.Sequence, requestEncHex _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.UnicodeSeqOfUtf8Bytes("{\"exportedSecret\":\""), Companion_Default___.Escape(exportedSecretHex)), _dafny.UnicodeSeqOfUtf8Bytes("\",\"requestEnc\":\"")), Companion_Default___.Escape(requestEncHex)), _dafny.UnicodeSeqOfUtf8Bytes("\"}"))
}
func (_static *CompanionStruct_Default___) SessionApply(store SessionStore, action SessionAction) SessionStore {
	var _source0 SessionAction = action
	_ = _source0
	{
		if _source0.Is_Begin() {
			return Companion_SessionStore_.Create_SessionStore_((func() uint64 {
				if ((store).Dtor_generation()) == (Companion_Default___.MaxSeq()) {
					return uint64(0)
				}
				return ((store).Dtor_generation()) + (uint64(1))
			})(), m_EHBP.Companion_Option_.Create_None_())
		}
	}
	{
		if _source0.Is_Publish() {
			var _0_generation uint64 = _source0.Get_().(SessionAction_Publish).Generation
			_ = _0_generation
			var _1_token m_EHBP.Token = _source0.Get_().(SessionAction_Publish).Token
			_ = _1_token
			if (_0_generation) == ((store).Dtor_generation()) {
				var _2_dt__update__tmp_h0 SessionStore = store
				_ = _2_dt__update__tmp_h0
				var _3_dt__update_htoken_h0 m_EHBP.Option = m_EHBP.Companion_Option_.Create_Some_(_1_token)
				_ = _3_dt__update_htoken_h0
				return Companion_SessionStore_.Create_SessionStore_((_2_dt__update__tmp_h0).Dtor_generation(), _3_dt__update_htoken_h0)
			} else {
				return store
			}
		}
	}
	{
		var _4_generation uint64 = _source0.Get_().(SessionAction_Clear).Generation
		_ = _4_generation
		if (_4_generation) == ((store).Dtor_generation()) {
			var _5_dt__update__tmp_h1 SessionStore = store
			_ = _5_dt__update__tmp_h1
			var _6_dt__update_htoken_h1 m_EHBP.Option = m_EHBP.Companion_Option_.Create_None_()
			_ = _6_dt__update_htoken_h1
			return Companion_SessionStore_.Create_SessionStore_((_5_dt__update__tmp_h1).Dtor_generation(), _6_dt__update_htoken_h1)
		} else {
			return store
		}
	}
}
func (_static *CompanionStruct_Default___) Frames(d Dec, buf _dafny.Sequence, i _dafny.Int, acc _dafny.Sequence) _dafny.Tuple {
	goto TAIL_CALL_START
TAIL_CALL_START:
	var _pat_let_tv0 = buf
	_ = _pat_let_tv0
	var _pat_let_tv1 = i
	_ = _pat_let_tv1
	var _pat_let_tv2 = buf
	_ = _pat_let_tv2
	var _pat_let_tv3 = i
	_ = _pat_let_tv3
	if ((_dafny.IntOfUint32((buf).Cardinality())).Minus(i)).Cmp(_dafny.IntOfInt64(4)) < 0 {
		return _dafny.TupleOf(acc, func(_pat_let25_0 Dec) Dec {
			return func(_0_dt__update__tmp_h0 Dec) Dec {
				return func(_pat_let26_0 _dafny.Sequence) Dec {
					return func(_1_dt__update_hpending_h0 _dafny.Sequence) Dec {
						return Companion_Dec_.Create_Dec_(_1_dt__update_hpending_h0, (_0_dt__update__tmp_h0).Dtor_next(), (_0_dt__update__tmp_h0).Dtor_authenticated(), (_0_dt__update__tmp_h0).Dtor_requireFrame())
					}(_pat_let26_0)
				}((_pat_let_tv0).Drop((_pat_let_tv1).Uint32()))
			}(_pat_let25_0)
		}(d), m_EHBP.Companion_Option_.Create_None_())
	} else {
		var _2_length uint32 = m_EHBP.Companion_Default___.U32(buf, i)
		_ = _2_length
		if (_2_length) == (uint32(0)) {
			var _in0 Dec = d
			_ = _in0
			var _in1 _dafny.Sequence = buf
			_ = _in1
			var _in2 _dafny.Int = (i).Plus(_dafny.IntOfInt64(4))
			_ = _in2
			var _in3 _dafny.Sequence = acc
			_ = _in3
			d = _in0
			buf = _in1
			i = _in2
			acc = _in3
			goto TAIL_CALL_START
		} else if (_2_length) > (m_EHBP.Companion_Default___.MaxChunkBytes()) {
			return _dafny.TupleOf(acc, d, m_EHBP.Companion_Option_.Create_Some_(m_EHBP.Companion_Code_.Create_ChunkTooLarge_()))
		} else if ((_dafny.IntOfUint32((buf).Cardinality())).Minus(i)).Cmp((_dafny.IntOfInt64(4)).Plus(_dafny.IntOfUint32(_2_length))) < 0 {
			return _dafny.TupleOf(acc, func(_pat_let27_0 Dec) Dec {
				return func(_3_dt__update__tmp_h1 Dec) Dec {
					return func(_pat_let28_0 _dafny.Sequence) Dec {
						return func(_4_dt__update_hpending_h1 _dafny.Sequence) Dec {
							return Companion_Dec_.Create_Dec_(_4_dt__update_hpending_h1, (_3_dt__update__tmp_h1).Dtor_next(), (_3_dt__update__tmp_h1).Dtor_authenticated(), (_3_dt__update__tmp_h1).Dtor_requireFrame())
						}(_pat_let28_0)
					}((_pat_let_tv2).Drop((_pat_let_tv3).Uint32()))
				}(_pat_let27_0)
			}(d), m_EHBP.Companion_Option_.Create_None_())
		} else if ((d).Dtor_next()) == (Companion_Default___.MaxSeq()) {
			return _dafny.TupleOf(acc, d, m_EHBP.Companion_Option_.Create_Some_(m_EHBP.Companion_Code_.Create_SequenceOverflow_()))
		} else {
			var _in4 Dec = Companion_Dec_.Create_Dec_(_dafny.SeqOf(), ((d).Dtor_next())+(uint64(1)), true, (d).Dtor_requireFrame())
			_ = _in4
			var _in5 _dafny.Sequence = buf
			_ = _in5
			var _in6 _dafny.Int = ((i).Plus(_dafny.IntOfInt64(4))).Plus(_dafny.IntOfUint32(_2_length))
			_ = _in6
			var _in7 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(acc, _dafny.SeqOf(m_EHBP.Companion_Framed_.Create_Framed_((d).Dtor_next(), (buf).Subsequence(((i).Plus(_dafny.IntOfInt64(4))).Uint32(), (((i).Plus(_dafny.IntOfInt64(4))).Plus(_dafny.IntOfUint32(_2_length))).Uint32()))))
			_ = _in7
			d = _in4
			buf = _in5
			i = _in6
			acc = _in7
			goto TAIL_CALL_START
		}
	}
}
func (_static *CompanionStruct_Default___) FrameNeed(pending _dafny.Sequence) _dafny.Int {
	if (_dafny.IntOfUint32((pending).Cardinality())).Cmp(_dafny.IntOfInt64(4)) < 0 {
		return (_dafny.IntOfInt64(4)).Minus(_dafny.IntOfUint32((pending).Cardinality()))
	} else {
		var _0_whole _dafny.Int = (_dafny.IntOfInt64(4)).Plus(_dafny.IntOfUint32(m_EHBP.Companion_Default___.U32(pending, _dafny.Zero)))
		_ = _0_whole
		if (_0_whole).Cmp(_dafny.IntOfUint32((pending).Cardinality())) > 0 {
			return (_0_whole).Minus(_dafny.IntOfUint32((pending).Cardinality()))
		} else {
			return _dafny.One
		}
	}
}
func (_static *CompanionStruct_Default___) Push(d Dec, data _dafny.Sequence) _dafny.Tuple {
	return Companion_Default___.PushFrom(d, data, _dafny.Zero, _dafny.SeqOf())
}
func (_static *CompanionStruct_Default___) PushFrom(d Dec, data _dafny.Sequence, i _dafny.Int, acc _dafny.Sequence) _dafny.Tuple {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32(((d).Dtor_pending()).Cardinality())).Sign() == 0 {
		return Companion_Default___.Frames(d, data, i, acc)
	} else if (i).Cmp(_dafny.IntOfUint32((data).Cardinality())) == 0 {
		return _dafny.TupleOf(acc, d, m_EHBP.Companion_Option_.Create_None_())
	} else {
		var _0_take _dafny.Int = Companion_Default___.Min((_dafny.IntOfUint32((data).Cardinality())).Minus(i), Companion_Default___.FrameNeed((d).Dtor_pending()))
		_ = _0_take
		var _let_tmp_rhs0 _dafny.Tuple = Companion_Default___.Frames(d, _dafny.Companion_Sequence_.Concatenate((d).Dtor_pending(), (data).Subsequence((i).Uint32(), ((i).Plus(_0_take)).Uint32())), _dafny.Zero, acc)
		_ = _let_tmp_rhs0
		var _1_frames _dafny.Sequence = (*(_let_tmp_rhs0).IndexInt(0)).(_dafny.Sequence)
		_ = _1_frames
		var _2_next Dec = (*(_let_tmp_rhs0).IndexInt(1)).(Dec)
		_ = _2_next
		var _3_err m_EHBP.Option = (*(_let_tmp_rhs0).IndexInt(2)).(m_EHBP.Option)
		_ = _3_err
		if (_3_err).Is_Some() {
			return _dafny.TupleOf(_1_frames, _2_next, _3_err)
		} else {
			var _in0 Dec = _2_next
			_ = _in0
			var _in1 _dafny.Sequence = data
			_ = _in1
			var _in2 _dafny.Int = (i).Plus(_0_take)
			_ = _in2
			var _in3 _dafny.Sequence = _1_frames
			_ = _in3
			d = _in0
			data = _in1
			i = _in2
			acc = _in3
			goto TAIL_CALL_START
		}
	}
}
func (_static *CompanionStruct_Default___) Finish(d Dec) m_EHBP.Option {
	if ((_dafny.IntOfUint32(((d).Dtor_pending()).Cardinality())).Sign() != 0) || (((d).Dtor_requireFrame()) && (!((d).Dtor_authenticated()))) {
		return m_EHBP.Companion_Option_.Create_Some_(m_EHBP.Companion_Code_.Create_FramingTruncated_())
	} else {
		return m_EHBP.Companion_Option_.Create_None_()
	}
}
func (_static *CompanionStruct_Default___) Initial(origin m_EHBP.Origin, publicKey _dafny.Sequence) State {
	return Companion_State_.Create_State_(Companion_Phase_.Create_Idle_(), origin, publicKey, _dafny.UnicodeSeqOfUtf8Bytes(""), _dafny.UnicodeSeqOfUtf8Bytes(""), _dafny.SeqOf(), uint64(0), false, m_EHBP.Companion_Token_.Create_Token_(_dafny.SeqOf(), _dafny.SeqOf()), Companion_Default___.NoCtx())
}
func (_static *CompanionStruct_Default___) ResponseOnly(origin m_EHBP.Origin, token m_EHBP.Token) State {
	return Companion_State_.Create_State_(Companion_Phase_.Create_Exchanging_(Companion_Upload_.Create_UpDone_(), Companion_Response_.Create_AwaitHead_(true)), origin, _dafny.SeqOf(), _dafny.UnicodeSeqOfUtf8Bytes(""), _dafny.UnicodeSeqOfUtf8Bytes(""), _dafny.SeqOf(), uint64(0), false, token, Companion_Default___.NoCtx())
}
func (_static *CompanionStruct_Default___) DecryptStart(token m_EHBP.Token, status _dafny.Int, headers _dafny.Sequence) _dafny.Tuple {
	return Companion_Default___.Step(Companion_Default___.ResponseOnly(Companion_Default___.NoOrigin(), token), Companion_Event_.Create_ResponseHead_(status, headers, false))
}
func (_static *CompanionStruct_Default___) DeriveStart(token m_EHBP.Token, responseNonce _dafny.Sequence) _dafny.Tuple {
	return Companion_Default___.Step(Companion_Default___.ResponseOnly(Companion_Default___.NoOrigin(), token), Companion_Event_.Create_ResponseHead_(_dafny.IntOfInt64(200), _dafny.SeqOf(_dafny.TupleOf(m_EHBP.Companion_Default___.ResponseNonceHeader(), m_EHBP.Companion_Default___.EncodeHex(responseNonce))), false))
}
func (_static *CompanionStruct_Default___) KeysOf(s State) m_EHBP.Option {
	if (((s).Dtor_phase()).Is_Exchanging()) && ((((s).Dtor_phase()).Dtor_response()).Is_Body()) {
		return m_EHBP.Companion_Option_.Create_Some_(_dafny.TupleOf(((((s).Dtor_phase()).Dtor_response()).Dtor_keys()).Dtor_key(), ((((s).Dtor_phase()).Dtor_response()).Dtor_keys()).Dtor_baseNonce()))
	} else {
		return m_EHBP.Companion_Option_.Create_None_()
	}
}
func (_static *CompanionStruct_Default___) Contract(s State, e Event, r _dafny.Tuple) bool {
	return ((!(Companion_Default___.Ends((*(r).IndexInt(1)).(_dafny.Sequence))) || ((!(((*(r).IndexInt(0)).(State)).Dtor_published())) && ((func() bool {
		if (s).Dtor_published() {
			return Companion_Default___.ClearsOnce((*(r).IndexInt(1)).(_dafny.Sequence), (s).Dtor_generation())
		}
		return Companion_Default___.NoClear((*(r).IndexInt(1)).(_dafny.Sequence))
	})()))) && (!(!(Companion_Default___.Ends((*(r).IndexInt(1)).(_dafny.Sequence)))) || (Companion_Default___.NoClear((*(r).IndexInt(1)).(_dafny.Sequence))))) && (!(!(Companion_Default___.NoEmit((*(r).IndexInt(1)).(_dafny.Sequence)))) || (((((e).Is_AeadOpenResult()) && ((e).Dtor_ok())) && (((s).Dtor_phase()).Is_Exchanging())) && ((((s).Dtor_phase()).Dtor_response()).Is_Opening())))
}
func (_static *CompanionStruct_Default___) Ending(s State, r _dafny.Tuple) bool {
	return (((Companion_Default___.Ends((*(r).IndexInt(1)).(_dafny.Sequence))) && (!(((*(r).IndexInt(0)).(State)).Dtor_published()))) && ((func() bool {
		if (s).Dtor_published() {
			return Companion_Default___.ClearsOnce((*(r).IndexInt(1)).(_dafny.Sequence), (s).Dtor_generation())
		}
		return Companion_Default___.NoClear((*(r).IndexInt(1)).(_dafny.Sequence))
	})())) && (Companion_Default___.NoEmit((*(r).IndexInt(1)).(_dafny.Sequence)))
}
func (_static *CompanionStruct_Default___) End(s State, close_ bool, last Action) _dafny.Tuple {
	var _0_phase Phase = func() Phase {
		var _source0 Phase = (s).Dtor_phase()
		_ = _source0
		{
			if _source0.Is_Exchanging() {
				var _1_up Upload = _source0.Get_().(Phase_Exchanging).Upload
				_ = _1_up
				return Companion_Phase_.Create_Exchanging_(_1_up, Companion_Response_.Create_RespEnded_())
			}
		}
		{
			return Companion_Phase_.Create_Ended_()
		}
	}()
	_ = _0_phase
	var _2_g uint64 = (s).Dtor_generation()
	_ = _2_g
	var _3_acts _dafny.Sequence = (func() _dafny.Sequence {
		if (close_) && ((s).Dtor_published()) {
			return _dafny.SeqOf(Companion_Action_.Create_Close_(Companion_Stream_.Create_ResponseBody_()), Companion_Action_.Create_ClearToken_(_2_g), last)
		}
		return (func() _dafny.Sequence {
			if close_ {
				return _dafny.SeqOf(Companion_Action_.Create_Close_(Companion_Stream_.Create_ResponseBody_()), last)
			}
			return (func() _dafny.Sequence {
				if (s).Dtor_published() {
					return _dafny.SeqOf(Companion_Action_.Create_ClearToken_(_2_g), last)
				}
				return _dafny.SeqOf(last)
			})()
		})()
	})()
	_ = _3_acts
	return _dafny.TupleOf(func(_pat_let29_0 State) State {
		return func(_4_dt__update__tmp_h0 State) State {
			return func(_pat_let30_0 bool) State {
				return func(_5_dt__update_hpublished_h0 bool) State {
					return func(_pat_let31_0 Phase) State {
						return func(_6_dt__update_hphase_h0 Phase) State {
							return Companion_State_.Create_State_(_6_dt__update_hphase_h0, (_4_dt__update__tmp_h0).Dtor_origin(), (_4_dt__update__tmp_h0).Dtor_publicKey(), (_4_dt__update__tmp_h0).Dtor_verb(), (_4_dt__update__tmp_h0).Dtor_url(), (_4_dt__update__tmp_h0).Dtor_headers(), (_4_dt__update__tmp_h0).Dtor_generation(), _5_dt__update_hpublished_h0, (_4_dt__update__tmp_h0).Dtor_token(), (_4_dt__update__tmp_h0).Dtor_ctx())
						}(_pat_let31_0)
					}(_0_phase)
				}(_pat_let30_0)
			}(false)
		}(_pat_let29_0)
	}(s), _3_acts)
}
func (_static *CompanionStruct_Default___) Abort(s State, close_ bool, code m_EHBP.Code, message _dafny.Sequence) _dafny.Tuple {
	return Companion_Default___.End(s, close_, Companion_Action_.Create_Fail_(code, message))
}
func (_static *CompanionStruct_Default___) Unexpected(s State) _dafny.Tuple {
	return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event"))
}
func (_static *CompanionStruct_Default___) Min(a _dafny.Int, b _dafny.Int) _dafny.Int {
	if (a).Cmp(b) < 0 {
		return a
	} else {
		return b
	}
}
func (_static *CompanionStruct_Default___) Min32(a uint32, b uint32) uint32 {
	if (a) < (b) {
		return a
	} else {
		return b
	}
}
func (_static *CompanionStruct_Default___) Piece(chunk _dafny.Sequence, at uint32, n uint32) _dafny.Sequence {
	if ((at) == (uint32(0))) && ((_dafny.IntOfUint32(n)).Cmp(_dafny.IntOfUint32((chunk).Cardinality())) == 0) {
		return chunk
	} else {
		return (chunk).Subsequence(uint32(at), uint32((at)+(n)))
	}
}
func (_static *CompanionStruct_Default___) FrameWrites(ciphertext _dafny.Sequence, end BodyEnd) _dafny.Sequence {
	return _dafny.SeqOf(Companion_Action_.Create_Write_(m_EHBP.Companion_Default___.BE32(uint32((ciphertext).Cardinality())), Companion_BodyEnd_.Create_More_()), Companion_Action_.Create_Write_(ciphertext, end))
}
func (_static *CompanionStruct_Default___) WithUpload(s State, up Upload) State {
	var _0_dt__update__tmp_h0 State = s
	_ = _0_dt__update__tmp_h0
	var _1_dt__update_hphase_h0 Phase = Companion_Phase_.Create_Exchanging_(up, ((s).Dtor_phase()).Dtor_response())
	_ = _1_dt__update_hphase_h0
	return Companion_State_.Create_State_(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).Dtor_origin(), (_0_dt__update__tmp_h0).Dtor_publicKey(), (_0_dt__update__tmp_h0).Dtor_verb(), (_0_dt__update__tmp_h0).Dtor_url(), (_0_dt__update__tmp_h0).Dtor_headers(), (_0_dt__update__tmp_h0).Dtor_generation(), (_0_dt__update__tmp_h0).Dtor_published(), (_0_dt__update__tmp_h0).Dtor_token(), (_0_dt__update__tmp_h0).Dtor_ctx())
}
func (_static *CompanionStruct_Default___) WithResponse(s State, rs Response) State {
	var _0_dt__update__tmp_h0 State = s
	_ = _0_dt__update__tmp_h0
	var _1_dt__update_hphase_h0 Phase = Companion_Phase_.Create_Exchanging_(((s).Dtor_phase()).Dtor_upload(), rs)
	_ = _1_dt__update_hphase_h0
	return Companion_State_.Create_State_(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).Dtor_origin(), (_0_dt__update__tmp_h0).Dtor_publicKey(), (_0_dt__update__tmp_h0).Dtor_verb(), (_0_dt__update__tmp_h0).Dtor_url(), (_0_dt__update__tmp_h0).Dtor_headers(), (_0_dt__update__tmp_h0).Dtor_generation(), (_0_dt__update__tmp_h0).Dtor_published(), (_0_dt__update__tmp_h0).Dtor_token(), (_0_dt__update__tmp_h0).Dtor_ctx())
}
func (_static *CompanionStruct_Default___) SendPlain(s State) _dafny.Tuple {
	return _dafny.TupleOf(func(_pat_let32_0 State) State {
		return func(_0_dt__update__tmp_h0 State) State {
			return func(_pat_let33_0 Phase) State {
				return func(_1_dt__update_hphase_h0 Phase) State {
					return Companion_State_.Create_State_(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).Dtor_origin(), (_0_dt__update__tmp_h0).Dtor_publicKey(), (_0_dt__update__tmp_h0).Dtor_verb(), (_0_dt__update__tmp_h0).Dtor_url(), (_0_dt__update__tmp_h0).Dtor_headers(), (_0_dt__update__tmp_h0).Dtor_generation(), (_0_dt__update__tmp_h0).Dtor_published(), (_0_dt__update__tmp_h0).Dtor_token(), (_0_dt__update__tmp_h0).Dtor_ctx())
				}(_pat_let33_0)
			}(Companion_Phase_.Create_Exchanging_(Companion_Upload_.Create_NoUpload_(), Companion_Response_.Create_AwaitHead_(false)))
		}(_pat_let32_0)
	}(s), _dafny.SeqOf(Companion_Action_.Create_Send_((s).Dtor_verb(), (s).Dtor_url(), (s).Dtor_headers(), false)))
}
func (_static *CompanionStruct_Default___) ForUpload(e Event) bool {
	return ((((e).Is_Chunk()) || ((e).Is_StreamFailed())) && (((e).Dtor_stream()).Is_RequestBody())) || ((e).Is_AeadSealResult())
}
func (_static *CompanionStruct_Default___) AbortUpload(s State, code m_EHBP.Code) _dafny.Tuple {
	return _dafny.TupleOf(Companion_Default___.WithUpload(s, Companion_Upload_.Create_UpDone_()), _dafny.SeqOf(Companion_Action_.Create_Write_(_dafny.SeqOf(), Companion_BodyEnd_.Create_Aborted_(code))))
}
func (_static *CompanionStruct_Default___) Step(s State, e Event) _dafny.Tuple {
	var _pat_let_tv0 = e
	_ = _pat_let_tv0
	if (e).Is_CallerClose() {
		return Companion_Default___.End(s, false, Companion_Action_.Create_Close_(Companion_Stream_.Create_ResponseBody_()))
	} else {
		var _source0 Phase = (s).Dtor_phase()
		_ = _source0
		{
			if _source0.Is_Idle() {
				if (e).Is_Start() {
					return Companion_Default___.StepStart(s, e)
				} else if (e).Is_DiscoverStart() {
					return _dafny.TupleOf(func(_pat_let34_0 State) State {
						return func(_0_dt__update__tmp_h0 State) State {
							return func(_pat_let35_0 Phase) State {
								return func(_1_dt__update_hphase_h0 Phase) State {
									return Companion_State_.Create_State_(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).Dtor_origin(), (_0_dt__update__tmp_h0).Dtor_publicKey(), (_0_dt__update__tmp_h0).Dtor_verb(), (_0_dt__update__tmp_h0).Dtor_url(), (_0_dt__update__tmp_h0).Dtor_headers(), (_0_dt__update__tmp_h0).Dtor_generation(), (_0_dt__update__tmp_h0).Dtor_published(), (_0_dt__update__tmp_h0).Dtor_token(), (_0_dt__update__tmp_h0).Dtor_ctx())
								}(_pat_let35_0)
							}(Companion_Phase_.Create_DiscAwaitHead_())
						}(_pat_let34_0)
					}(s), _dafny.SeqOf(Companion_Action_.Create_Send_(_dafny.UnicodeSeqOfUtf8Bytes("GET"), _dafny.Companion_Sequence_.Concatenate(m_EHBP.Companion_Default___.OriginUrl((s).Dtor_origin()), m_EHBP.Companion_Default___.KeysPath()), _dafny.SeqOf(), false)))
				} else {
					return Companion_Default___.Unexpected(s)
				}
			}
		}
		{
			if _source0.Is_AwaitSession() {
				var _2_hasBody bool = _source0.Get_().(Phase_AwaitSession).HasBody
				_ = _2_hasBody
				if !((e).Is_SessionBegun()) {
					return Companion_Default___.Unexpected(s)
				} else {
					var _3_begun State = func(_pat_let36_0 State) State {
						return func(_4_dt__update__tmp_h1 State) State {
							return func(_pat_let37_0 uint64) State {
								return func(_5_dt__update_hgeneration_h0 uint64) State {
									return Companion_State_.Create_State_((_4_dt__update__tmp_h1).Dtor_phase(), (_4_dt__update__tmp_h1).Dtor_origin(), (_4_dt__update__tmp_h1).Dtor_publicKey(), (_4_dt__update__tmp_h1).Dtor_verb(), (_4_dt__update__tmp_h1).Dtor_url(), (_4_dt__update__tmp_h1).Dtor_headers(), _5_dt__update_hgeneration_h0, (_4_dt__update__tmp_h1).Dtor_published(), (_4_dt__update__tmp_h1).Dtor_token(), (_4_dt__update__tmp_h1).Dtor_ctx())
								}(_pat_let37_0)
							}((_pat_let_tv0).Dtor_generation())
						}(_pat_let36_0)
					}(s)
					_ = _3_begun
					if _2_hasBody {
						return _dafny.TupleOf(func(_pat_let38_0 State) State {
							return func(_6_dt__update__tmp_h2 State) State {
								return func(_pat_let39_0 Phase) State {
									return func(_7_dt__update_hphase_h1 Phase) State {
										return Companion_State_.Create_State_(_7_dt__update_hphase_h1, (_6_dt__update__tmp_h2).Dtor_origin(), (_6_dt__update__tmp_h2).Dtor_publicKey(), (_6_dt__update__tmp_h2).Dtor_verb(), (_6_dt__update__tmp_h2).Dtor_url(), (_6_dt__update__tmp_h2).Dtor_headers(), (_6_dt__update__tmp_h2).Dtor_generation(), (_6_dt__update__tmp_h2).Dtor_published(), (_6_dt__update__tmp_h2).Dtor_token(), (_6_dt__update__tmp_h2).Dtor_ctx())
									}(_pat_let39_0)
								}(Companion_Phase_.Create_Peeking_(_dafny.Zero))
							}(_pat_let38_0)
						}(_3_begun), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_RequestBody_())))
					} else {
						return Companion_Default___.SendPlain(_3_begun)
					}
				}
			}
		}
		{
			if _source0.Is_Peeking() {
				var _8_empty _dafny.Int = _source0.Get_().(Phase_Peeking).Empty
				_ = _8_empty
				var _source1 Event = e
				_ = _source1
				{
					if _source1.Is_StreamFailed() {
						var stream0 Stream = _source1.Get_().(Event_StreamFailed).Stream
						_ = stream0
						if stream0.Is_RequestBody() {
							return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("failed to read request body"))
						}
					}
				}
				{
					if _source1.Is_Chunk() {
						var stream1 Stream = _source1.Get_().(Event_Chunk).Stream
						_ = stream1
						if stream1.Is_RequestBody() {
							var _9_data _dafny.Sequence = _source1.Get_().(Event_Chunk).Data
							_ = _9_data
							var _10_eof bool = _source1.Get_().(Event_Chunk).Eof
							_ = _10_eof
							if (_dafny.IntOfUint32((_9_data).Cardinality())).Cmp(Companion_Default___.MaxReadBytes()) > 0 {
								return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("request body chunk too large"))
							} else if (_dafny.IntOfUint32((_9_data).Cardinality())).Sign() == 1 {
								var _source2 HpkeOut = Companion_Default___.SenderStart((s).Dtor_publicKey(), m_EHBP.Companion_Default___.Ascii(m_EHBP.Companion_Default___.HpkeRequestInfo()))
								_ = _source2
								{
									if _source2.Is_HContinue() {
										var _11_h Hpke = _source2.Get_().(HpkeOut_HContinue).H
										_ = _11_h
										var _12_a Action = _source2.Get_().(HpkeOut_HContinue).Action
										_ = _12_a
										return _dafny.TupleOf(func(_pat_let40_0 State) State {
											return func(_13_dt__update__tmp_h3 State) State {
												return func(_pat_let41_0 Phase) State {
													return func(_14_dt__update_hphase_h2 Phase) State {
														return Companion_State_.Create_State_(_14_dt__update_hphase_h2, (_13_dt__update__tmp_h3).Dtor_origin(), (_13_dt__update__tmp_h3).Dtor_publicKey(), (_13_dt__update__tmp_h3).Dtor_verb(), (_13_dt__update__tmp_h3).Dtor_url(), (_13_dt__update__tmp_h3).Dtor_headers(), (_13_dt__update__tmp_h3).Dtor_generation(), (_13_dt__update__tmp_h3).Dtor_published(), (_13_dt__update__tmp_h3).Dtor_token(), (_13_dt__update__tmp_h3).Dtor_ctx())
													}(_pat_let41_0)
												}(Companion_Phase_.Create_AwaitSetup_(_9_data, _10_eof, _11_h))
											}(_pat_let40_0)
										}(s), _dafny.SeqOf(_12_a))
									}
								}
								{
									return Companion_Default___.Unexpected(s)
								}
							} else if _10_eof {
								return Companion_Default___.SendPlain(s)
							} else if ((_8_empty).Plus(_dafny.One)).Cmp(m_EHBP.Companion_Default___.MaxEmptyReads()) == 0 {
								return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("request body made no progress"))
							} else {
								return _dafny.TupleOf(func(_pat_let42_0 State) State {
									return func(_15_dt__update__tmp_h4 State) State {
										return func(_pat_let43_0 Phase) State {
											return func(_16_dt__update_hphase_h3 Phase) State {
												return Companion_State_.Create_State_(_16_dt__update_hphase_h3, (_15_dt__update__tmp_h4).Dtor_origin(), (_15_dt__update__tmp_h4).Dtor_publicKey(), (_15_dt__update__tmp_h4).Dtor_verb(), (_15_dt__update__tmp_h4).Dtor_url(), (_15_dt__update__tmp_h4).Dtor_headers(), (_15_dt__update__tmp_h4).Dtor_generation(), (_15_dt__update__tmp_h4).Dtor_published(), (_15_dt__update__tmp_h4).Dtor_token(), (_15_dt__update__tmp_h4).Dtor_ctx())
											}(_pat_let43_0)
										}(Companion_Phase_.Create_Peeking_((_8_empty).Plus(_dafny.One)))
									}(_pat_let42_0)
								}(s), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_RequestBody_())))
							}
						}
					}
				}
				{
					return Companion_Default___.Unexpected(s)
				}
			}
		}
		{
			if _source0.Is_AwaitSetup() {
				var _17_first _dafny.Sequence = _source0.Get_().(Phase_AwaitSetup).First
				_ = _17_first
				var _18_firstEof bool = _source0.Get_().(Phase_AwaitSetup).FirstEof
				_ = _18_firstEof
				var _19_h Hpke = _source0.Get_().(Phase_AwaitSetup).Hpke
				_ = _19_h
				var _source3 HpkeOut = Companion_Default___.HpkeStep(_19_h, e)
				_ = _source3
				{
					if _source3.Is_HFailed() {
						var _20_code m_EHBP.Code = _source3.Get_().(HpkeOut_HFailed).Code
						_ = _20_code
						var _21_message _dafny.Sequence = _source3.Get_().(HpkeOut_HFailed).Message
						_ = _21_message
						return Companion_Default___.Abort(s, false, _20_code, _21_message)
					}
				}
				{
					if _source3.Is_HContinue() {
						var _22_next Hpke = _source3.Get_().(HpkeOut_HContinue).H
						_ = _22_next
						var _23_a Action = _source3.Get_().(HpkeOut_HContinue).Action
						_ = _23_a
						return _dafny.TupleOf(func(_pat_let44_0 State) State {
							return func(_24_dt__update__tmp_h5 State) State {
								return func(_pat_let45_0 Phase) State {
									return func(_25_dt__update_hphase_h4 Phase) State {
										return Companion_State_.Create_State_(_25_dt__update_hphase_h4, (_24_dt__update__tmp_h5).Dtor_origin(), (_24_dt__update__tmp_h5).Dtor_publicKey(), (_24_dt__update__tmp_h5).Dtor_verb(), (_24_dt__update__tmp_h5).Dtor_url(), (_24_dt__update__tmp_h5).Dtor_headers(), (_24_dt__update__tmp_h5).Dtor_generation(), (_24_dt__update__tmp_h5).Dtor_published(), (_24_dt__update__tmp_h5).Dtor_token(), (_24_dt__update__tmp_h5).Dtor_ctx())
									}(_pat_let45_0)
								}(Companion_Phase_.Create_AwaitSetup_(_17_first, _18_firstEof, _22_next))
							}(_pat_let44_0)
						}(s), _dafny.SeqOf(_23_a))
					}
				}
				{
					var _26_ctx Ctx = _source3.Get_().(HpkeOut_HReady).Ctx
					_ = _26_ctx
					var _27_enc _dafny.Sequence = _source3.Get_().(HpkeOut_HReady).Enc
					_ = _27_enc
					var _28_job Job = Companion_Default___.ExportJob(_26_ctx, m_EHBP.Companion_Default___.Ascii(m_EHBP.Companion_Default___.ExportLabel()), m_EHBP.Companion_Default___.ExportLength())
					_ = _28_job
					return _dafny.TupleOf(func(_pat_let46_0 State) State {
						return func(_29_dt__update__tmp_h6 State) State {
							return func(_pat_let47_0 Ctx) State {
								return func(_30_dt__update_hctx_h0 Ctx) State {
									return func(_pat_let48_0 Phase) State {
										return func(_31_dt__update_hphase_h5 Phase) State {
											return Companion_State_.Create_State_(_31_dt__update_hphase_h5, (_29_dt__update__tmp_h6).Dtor_origin(), (_29_dt__update__tmp_h6).Dtor_publicKey(), (_29_dt__update__tmp_h6).Dtor_verb(), (_29_dt__update__tmp_h6).Dtor_url(), (_29_dt__update__tmp_h6).Dtor_headers(), (_29_dt__update__tmp_h6).Dtor_generation(), (_29_dt__update__tmp_h6).Dtor_published(), (_29_dt__update__tmp_h6).Dtor_token(), _30_dt__update_hctx_h0)
										}(_pat_let48_0)
									}(Companion_Phase_.Create_AwaitExport_(_17_first, _18_firstEof, _27_enc, _28_job))
								}(_pat_let47_0)
							}(_26_ctx)
						}(_pat_let46_0)
					}(s), _dafny.SeqOf(Companion_Default___.JobAction(_28_job)))
				}
			}
		}
		{
			if _source0.Is_AwaitExport() {
				var _32_first _dafny.Sequence = _source0.Get_().(Phase_AwaitExport).First
				_ = _32_first
				var _33_firstEof bool = _source0.Get_().(Phase_AwaitExport).FirstEof
				_ = _33_firstEof
				var _34_enc _dafny.Sequence = _source0.Get_().(Phase_AwaitExport).Enc
				_ = _34_enc
				var _35_job Job = _source0.Get_().(Phase_AwaitExport).Job
				_ = _35_job
				var _source4 JobOut = Companion_Default___.JobStep(_35_job, e)
				_ = _source4
				{
					if _source4.Is_JobFailed() {
						var _36_code m_EHBP.Code = _source4.Get_().(JobOut_JobFailed).Code
						_ = _36_code
						var _37_message _dafny.Sequence = _source4.Get_().(JobOut_JobFailed).Message
						_ = _37_message
						return Companion_Default___.Abort(s, false, _36_code, _37_message)
					}
				}
				{
					if _source4.Is_Pending() {
						var _38_next Job = _source4.Get_().(JobOut_Pending).Job
						_ = _38_next
						var _39_a Action = _source4.Get_().(JobOut_Pending).Action
						_ = _39_a
						return _dafny.TupleOf(func(_pat_let49_0 State) State {
							return func(_40_dt__update__tmp_h7 State) State {
								return func(_pat_let50_0 Phase) State {
									return func(_41_dt__update_hphase_h6 Phase) State {
										return Companion_State_.Create_State_(_41_dt__update_hphase_h6, (_40_dt__update__tmp_h7).Dtor_origin(), (_40_dt__update__tmp_h7).Dtor_publicKey(), (_40_dt__update__tmp_h7).Dtor_verb(), (_40_dt__update__tmp_h7).Dtor_url(), (_40_dt__update__tmp_h7).Dtor_headers(), (_40_dt__update__tmp_h7).Dtor_generation(), (_40_dt__update__tmp_h7).Dtor_published(), (_40_dt__update__tmp_h7).Dtor_token(), (_40_dt__update__tmp_h7).Dtor_ctx())
									}(_pat_let50_0)
								}(Companion_Phase_.Create_AwaitExport_(_32_first, _33_firstEof, _34_enc, _38_next))
							}(_pat_let49_0)
						}(s), _dafny.SeqOf(_39_a))
					}
				}
				{
					var _42_secret _dafny.Sequence = _source4.Get_().(JobOut_Output).Data
					_ = _42_secret
					if (_dafny.IntOfUint32((_34_enc).Cardinality())).Cmp(m_EHBP.Companion_Default___.RequestEncLength()) != 0 {
						return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("HPKE sender setup failed"))
					} else if (_dafny.IntOfUint32((_42_secret).Cardinality())).Cmp(m_EHBP.Companion_Default___.ExportLength()) != 0 {
						return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("HPKE export failed"))
					} else {
						var _43_token m_EHBP.Token = m_EHBP.Companion_Token_.Create_Token_(_42_secret, _34_enc)
						_ = _43_token
						var _44_headers _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate((s).Dtor_headers(), _dafny.SeqOf(_dafny.TupleOf(m_EHBP.Companion_Default___.EncapsulatedKeyHeader(), m_EHBP.Companion_Default___.EncodeHex(_34_enc))))
						_ = _44_headers
						return _dafny.TupleOf(func(_pat_let51_0 State) State {
							return func(_45_dt__update__tmp_h8 State) State {
								return func(_pat_let52_0 m_EHBP.Token) State {
									return func(_46_dt__update_htoken_h0 m_EHBP.Token) State {
										return func(_pat_let53_0 bool) State {
											return func(_47_dt__update_hpublished_h0 bool) State {
												return func(_pat_let54_0 Phase) State {
													return func(_48_dt__update_hphase_h7 Phase) State {
														return Companion_State_.Create_State_(_48_dt__update_hphase_h7, (_45_dt__update__tmp_h8).Dtor_origin(), (_45_dt__update__tmp_h8).Dtor_publicKey(), (_45_dt__update__tmp_h8).Dtor_verb(), (_45_dt__update__tmp_h8).Dtor_url(), (_45_dt__update__tmp_h8).Dtor_headers(), (_45_dt__update__tmp_h8).Dtor_generation(), _47_dt__update_hpublished_h0, _46_dt__update_htoken_h0, (_45_dt__update__tmp_h8).Dtor_ctx())
													}(_pat_let54_0)
												}(Companion_Phase_.Create_Exchanging_(Companion_Upload_.Create_Sealing_(_32_first, uint32(0), _33_firstEof), Companion_Response_.Create_AwaitHead_(true)))
											}(_pat_let53_0)
										}(true)
									}(_pat_let52_0)
								}(_43_token)
							}(_pat_let51_0)
						}(s), _dafny.SeqOf(Companion_Action_.Create_PublishToken_((s).Dtor_generation(), _42_secret, _34_enc), Companion_Action_.Create_Send_((s).Dtor_verb(), (s).Dtor_url(), _44_headers, true), Companion_Default___.SealAction((s).Dtor_ctx(), Companion_Default___.Piece(_32_first, uint32(0), Companion_Default___.Min32(uint32((_32_first).Cardinality()), m_EHBP.Companion_Default___.RequestFrameBytes())))))
					}
				}
			}
		}
		{
			if _source0.Is_Exchanging() {
				var _49_up Upload = _source0.Get_().(Phase_Exchanging).Upload
				_ = _49_up
				var _50_rs Response = _source0.Get_().(Phase_Exchanging).Response
				_ = _50_rs
				if Companion_Default___.ForUpload(e) {
					return Companion_Default___.StepUpload(s, _49_up, e)
				} else {
					return Companion_Default___.StepResponse(s, _50_rs, e)
				}
			}
		}
		{
			if _source0.Is_DiscAwaitHead() {
				var _source5 Event = e
				_ = _source5
				{
					if _source5.Is_StreamFailed() {
						var stream2 Stream = _source5.Get_().(Event_StreamFailed).Stream
						_ = stream2
						if stream2.Is_ResponseBody() {
							return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("failed to get server public key"))
						}
					}
				}
				{
					if _source5.Is_ResponseHead() {
						var _51_status _dafny.Int = _source5.Get_().(Event_ResponseHead).Status
						_ = _51_status
						var _52_headers _dafny.Sequence = _source5.Get_().(Event_ResponseHead).Headers
						_ = _52_headers
						var _53_redirected bool = _source5.Get_().(Event_ResponseHead).Redirected
						_ = _53_redirected
						if ((_51_status).Cmp(_dafny.IntOfInt64(100)) < 0) || ((_51_status).Cmp(_dafny.IntOfInt64(599)) > 0) {
							return Companion_Default___.Abort(s, true, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("failed to get server public key"))
						} else {
							var _source6 m_EHBP.Result = m_EHBP.Companion_Default___.ClassifyDiscovery(m_EHBP.Companion_Head_.Create_Head_(_51_status, _52_headers, _53_redirected))
							_ = _source6
							{
								if _source6.Is_Err() {
									var _54_code m_EHBP.Code = _source6.Get_().(m_EHBP.Result_Err).Code
									_ = _54_code
									var _55_message _dafny.Sequence = _source6.Get_().(m_EHBP.Result_Err).Message
									_ = _55_message
									return Companion_Default___.Abort(s, true, _54_code, _55_message)
								}
							}
							{
								return _dafny.TupleOf(func(_pat_let55_0 State) State {
									return func(_56_dt__update__tmp_h9 State) State {
										return func(_pat_let56_0 Phase) State {
											return func(_57_dt__update_hphase_h8 Phase) State {
												return Companion_State_.Create_State_(_57_dt__update_hphase_h8, (_56_dt__update__tmp_h9).Dtor_origin(), (_56_dt__update__tmp_h9).Dtor_publicKey(), (_56_dt__update__tmp_h9).Dtor_verb(), (_56_dt__update__tmp_h9).Dtor_url(), (_56_dt__update__tmp_h9).Dtor_headers(), (_56_dt__update__tmp_h9).Dtor_generation(), (_56_dt__update__tmp_h9).Dtor_published(), (_56_dt__update__tmp_h9).Dtor_token(), (_56_dt__update__tmp_h9).Dtor_ctx())
											}(_pat_let56_0)
										}(Companion_Phase_.Create_DiscReading_(_dafny.SeqOf()))
									}(_pat_let55_0)
								}(s), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_ResponseBody_())))
							}
						}
					}
				}
				{
					return Companion_Default___.Unexpected(s)
				}
			}
		}
		{
			if _source0.Is_DiscReading() {
				var _58_data _dafny.Sequence = _source0.Get_().(Phase_DiscReading).Data
				_ = _58_data
				var _source7 Event = e
				_ = _source7
				{
					if _source7.Is_StreamFailed() {
						var stream3 Stream = _source7.Get_().(Event_StreamFailed).Stream
						_ = stream3
						if stream3.Is_ResponseBody() {
							return Companion_Default___.Abort(s, true, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("failed to read key configuration"))
						}
					}
				}
				{
					if _source7.Is_Chunk() {
						var stream4 Stream = _source7.Get_().(Event_Chunk).Stream
						_ = stream4
						if stream4.Is_ResponseBody() {
							var _59_chunk _dafny.Sequence = _source7.Get_().(Event_Chunk).Data
							_ = _59_chunk
							var _60_eof bool = _source7.Get_().(Event_Chunk).Eof
							_ = _60_eof
							var _61_grown _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(_58_data, _59_chunk)
							_ = _61_grown
							if ((_dafny.IntOfUint32((_61_grown).Cardinality())).Cmp(m_EHBP.Companion_Default___.MaxKeyConfigBytes()) <= 0) && (!(_60_eof)) {
								return _dafny.TupleOf(func(_pat_let57_0 State) State {
									return func(_62_dt__update__tmp_h10 State) State {
										return func(_pat_let58_0 Phase) State {
											return func(_63_dt__update_hphase_h9 Phase) State {
												return Companion_State_.Create_State_(_63_dt__update_hphase_h9, (_62_dt__update__tmp_h10).Dtor_origin(), (_62_dt__update__tmp_h10).Dtor_publicKey(), (_62_dt__update__tmp_h10).Dtor_verb(), (_62_dt__update__tmp_h10).Dtor_url(), (_62_dt__update__tmp_h10).Dtor_headers(), (_62_dt__update__tmp_h10).Dtor_generation(), (_62_dt__update__tmp_h10).Dtor_published(), (_62_dt__update__tmp_h10).Dtor_token(), (_62_dt__update__tmp_h10).Dtor_ctx())
											}(_pat_let58_0)
										}(Companion_Phase_.Create_DiscReading_(_61_grown))
									}(_pat_let57_0)
								}(s), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_ResponseBody_())))
							} else {
								var _source8 m_EHBP.Result = m_EHBP.Companion_Default___.ParseConfig(_61_grown)
								_ = _source8
								{
									if _source8.Is_Ok() {
										var _64_pk _dafny.Sequence = _source8.Get_().(m_EHBP.Result_Ok).Value.(_dafny.Sequence)
										_ = _64_pk
										return Companion_Default___.End(s, true, Companion_Action_.Create_Discovered_(_64_pk))
									}
								}
								{
									var _65_code m_EHBP.Code = _source8.Get_().(m_EHBP.Result_Err).Code
									_ = _65_code
									var _66_message _dafny.Sequence = _source8.Get_().(m_EHBP.Result_Err).Message
									_ = _66_message
									return Companion_Default___.Abort(s, true, _65_code, _66_message)
								}
							}
						}
					}
				}
				{
					return Companion_Default___.Unexpected(s)
				}
			}
		}
		{
			return Companion_Default___.Unexpected(s)
		}
	}
}
func (_static *CompanionStruct_Default___) StepStart(s State, e Event) _dafny.Tuple {
	var _pat_let_tv0 = e
	_ = _pat_let_tv0
	var _pat_let_tv1 = e
	_ = _pat_let_tv1
	var _pat_let_tv2 = e
	_ = _pat_let_tv2
	var _pat_let_tv3 = e
	_ = _pat_let_tv3
	var _0_target m_EHBP.Result = m_EHBP.Companion_Default___.MakeOrigin((e).Dtor_scheme(), (e).Dtor_host(), (func() m_EHBP.Option {
		if (e).Dtor_hasPort() {
			return m_EHBP.Companion_Option_.Create_Some_((e).Dtor_port())
		}
		return m_EHBP.Companion_Option_.Create_None_()
	})(), (e).Dtor_hasUserinfo())
	_ = _0_target
	var _source0 m_EHBP.Result = m_EHBP.Companion_Default___.ValidateRequest((s).Dtor_origin(), _0_target, (e).Dtor_headers())
	_ = _source0
	{
		if _source0.Is_Err() {
			var _1_code m_EHBP.Code = _source0.Get_().(m_EHBP.Result_Err).Code
			_ = _1_code
			var _2_message _dafny.Sequence = _source0.Get_().(m_EHBP.Result_Err).Message
			_ = _2_message
			return Companion_Default___.Abort(s, false, _1_code, _2_message)
		}
	}
	{
		return _dafny.TupleOf(func(_pat_let59_0 State) State {
			return func(_3_dt__update__tmp_h0 State) State {
				return func(_pat_let60_0 _dafny.Sequence) State {
					return func(_4_dt__update_hheaders_h0 _dafny.Sequence) State {
						return func(_pat_let61_0 _dafny.Sequence) State {
							return func(_5_dt__update_hurl_h0 _dafny.Sequence) State {
								return func(_pat_let62_0 _dafny.Sequence) State {
									return func(_6_dt__update_hverb_h0 _dafny.Sequence) State {
										return func(_pat_let63_0 Phase) State {
											return func(_7_dt__update_hphase_h0 Phase) State {
												return Companion_State_.Create_State_(_7_dt__update_hphase_h0, (_3_dt__update__tmp_h0).Dtor_origin(), (_3_dt__update__tmp_h0).Dtor_publicKey(), _6_dt__update_hverb_h0, _5_dt__update_hurl_h0, _4_dt__update_hheaders_h0, (_3_dt__update__tmp_h0).Dtor_generation(), (_3_dt__update__tmp_h0).Dtor_published(), (_3_dt__update__tmp_h0).Dtor_token(), (_3_dt__update__tmp_h0).Dtor_ctx())
											}(_pat_let63_0)
										}(Companion_Phase_.Create_AwaitSession_((_pat_let_tv3).Dtor_hasBody()))
									}(_pat_let62_0)
								}((_pat_let_tv2).Dtor_verb())
							}(_pat_let61_0)
						}((_pat_let_tv1).Dtor_url())
					}(_pat_let60_0)
				}(m_EHBP.Companion_Default___.DropFraming((_pat_let_tv0).Dtor_headers()))
			}(_pat_let59_0)
		}(s), _dafny.SeqOf(Companion_Action_.Create_BeginSession_()))
	}
}
func (_static *CompanionStruct_Default___) StepUpload(s State, up Upload, e Event) _dafny.Tuple {
	var _pat_let_tv0 = s
	_ = _pat_let_tv0
	var _source0 Upload = up
	_ = _source0
	{
		if _source0.Is_Sealing() {
			var _0_plaintext _dafny.Sequence = _source0.Get_().(Upload_Sealing).Plaintext
			_ = _0_plaintext
			var _1_offset uint32 = _source0.Get_().(Upload_Sealing).Offset
			_ = _1_offset
			var _2_eof bool = _source0.Get_().(Upload_Sealing).Eof
			_ = _2_eof
			var _3_size uint32 = uint32((_0_plaintext).Cardinality())
			_ = _3_size
			var _4_at uint32 = Companion_Default___.Min32(_1_offset, _3_size)
			_ = _4_at
			var _5_n uint32 = Companion_Default___.Min32((_3_size)-(func() uint32 { return (_4_at) })(), m_EHBP.Companion_Default___.RequestFrameBytes())
			_ = _5_n
			if !((e).Is_AeadSealResult()) {
				return Companion_Default___.AbortUpload(s, m_EHBP.Companion_Code_.Create_Transport_())
			} else if (_dafny.IntOfUint32(((e).Dtor_ciphertext()).Cardinality())).Cmp((_dafny.IntOfUint32(_5_n)).Plus(m_EHBP.Companion_Default___.AeadTagLength())) != 0 {
				return Companion_Default___.AbortUpload(s, m_EHBP.Companion_Code_.Create_HpkeSetupFailed_())
			} else if (((s).Dtor_ctx()).Dtor_seqNo()) == (Companion_Default___.MaxSeq()) {
				return Companion_Default___.AbortUpload(s, m_EHBP.Companion_Code_.Create_SequenceOverflow_())
			} else {
				var _6_bumped State = func(_pat_let64_0 State) State {
					return func(_7_dt__update__tmp_h0 State) State {
						return func(_pat_let65_0 Ctx) State {
							return func(_8_dt__update_hctx_h0 Ctx) State {
								return Companion_State_.Create_State_((_7_dt__update__tmp_h0).Dtor_phase(), (_7_dt__update__tmp_h0).Dtor_origin(), (_7_dt__update__tmp_h0).Dtor_publicKey(), (_7_dt__update__tmp_h0).Dtor_verb(), (_7_dt__update__tmp_h0).Dtor_url(), (_7_dt__update__tmp_h0).Dtor_headers(), (_7_dt__update__tmp_h0).Dtor_generation(), (_7_dt__update__tmp_h0).Dtor_published(), (_7_dt__update__tmp_h0).Dtor_token(), _8_dt__update_hctx_h0)
							}(_pat_let65_0)
						}(Companion_Default___.Bump((_pat_let_tv0).Dtor_ctx()))
					}(_pat_let64_0)
				}(s)
				_ = _6_bumped
				var _9_next uint32 = (_4_at) + (_5_n)
				_ = _9_next
				if (_9_next) < (_3_size) {
					return _dafny.TupleOf(Companion_Default___.WithUpload(_6_bumped, Companion_Upload_.Create_Sealing_(_0_plaintext, _9_next, _2_eof)), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.FrameWrites((e).Dtor_ciphertext(), Companion_BodyEnd_.Create_More_()), _dafny.SeqOf(Companion_Default___.SealAction((_6_bumped).Dtor_ctx(), Companion_Default___.Piece(_0_plaintext, _9_next, Companion_Default___.Min32((_3_size)-(func() uint32 { return (_9_next) })(), m_EHBP.Companion_Default___.RequestFrameBytes()))))))
				} else if _2_eof {
					return _dafny.TupleOf(Companion_Default___.WithUpload(_6_bumped, Companion_Upload_.Create_UpDone_()), Companion_Default___.FrameWrites((e).Dtor_ciphertext(), Companion_BodyEnd_.Create_Done_()))
				} else {
					return _dafny.TupleOf(Companion_Default___.WithUpload(_6_bumped, Companion_Upload_.Create_UpReading_(_dafny.Zero)), _dafny.Companion_Sequence_.Concatenate(Companion_Default___.FrameWrites((e).Dtor_ciphertext(), Companion_BodyEnd_.Create_More_()), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_RequestBody_()))))
				}
			}
		}
	}
	{
		if _source0.Is_UpReading() {
			var _10_empty _dafny.Int = _source0.Get_().(Upload_UpReading).Empty
			_ = _10_empty
			var _source1 Event = e
			_ = _source1
			{
				if _source1.Is_StreamFailed() {
					var stream0 Stream = _source1.Get_().(Event_StreamFailed).Stream
					_ = stream0
					if stream0.Is_RequestBody() {
						return Companion_Default___.AbortUpload(s, m_EHBP.Companion_Code_.Create_Transport_())
					}
				}
			}
			{
				if _source1.Is_Chunk() {
					var stream1 Stream = _source1.Get_().(Event_Chunk).Stream
					_ = stream1
					if stream1.Is_RequestBody() {
						var _11_data _dafny.Sequence = _source1.Get_().(Event_Chunk).Data
						_ = _11_data
						var _12_eof bool = _source1.Get_().(Event_Chunk).Eof
						_ = _12_eof
						if (_dafny.IntOfUint32((_11_data).Cardinality())).Cmp(Companion_Default___.MaxReadBytes()) > 0 {
							return Companion_Default___.AbortUpload(s, m_EHBP.Companion_Code_.Create_Transport_())
						} else if (_dafny.IntOfUint32((_11_data).Cardinality())).Sign() == 1 {
							return _dafny.TupleOf(Companion_Default___.WithUpload(s, Companion_Upload_.Create_Sealing_(_11_data, uint32(0), _12_eof)), _dafny.SeqOf(Companion_Default___.SealAction((s).Dtor_ctx(), Companion_Default___.Piece(_11_data, uint32(0), Companion_Default___.Min32(uint32((_11_data).Cardinality()), m_EHBP.Companion_Default___.RequestFrameBytes())))))
						} else if _12_eof {
							return _dafny.TupleOf(Companion_Default___.WithUpload(s, Companion_Upload_.Create_UpDone_()), _dafny.SeqOf(Companion_Action_.Create_Write_(_dafny.SeqOf(), Companion_BodyEnd_.Create_Done_())))
						} else if ((_10_empty).Plus(_dafny.One)).Cmp(m_EHBP.Companion_Default___.MaxEmptyReads()) == 0 {
							return Companion_Default___.AbortUpload(s, m_EHBP.Companion_Code_.Create_Transport_())
						} else {
							return _dafny.TupleOf(Companion_Default___.WithUpload(s, Companion_Upload_.Create_UpReading_((_10_empty).Plus(_dafny.One))), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_RequestBody_())))
						}
					}
				}
			}
			{
				return Companion_Default___.AbortUpload(s, m_EHBP.Companion_Code_.Create_Transport_())
			}
		}
	}
	{
		return Companion_Default___.AbortUpload(s, m_EHBP.Companion_Code_.Create_Transport_())
	}
}
func (_static *CompanionStruct_Default___) StepResponse(s State, rs Response, e Event) _dafny.Tuple {
	var _source0 Response = rs
	_ = _source0
	{
		if _source0.Is_AwaitHead() {
			var _0_encrypted bool = _source0.Get_().(Response_AwaitHead).Encrypted
			_ = _0_encrypted
			var _source1 Event = e
			_ = _source1
			{
				if _source1.Is_StreamFailed() {
					var stream0 Stream = _source1.Get_().(Event_StreamFailed).Stream
					_ = stream0
					if stream0.Is_ResponseBody() {
						return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("failed to make request"))
					}
				}
			}
			{
				if _source1.Is_ResponseHead() {
					var _1_status _dafny.Int = _source1.Get_().(Event_ResponseHead).Status
					_ = _1_status
					var _2_headers _dafny.Sequence = _source1.Get_().(Event_ResponseHead).Headers
					_ = _2_headers
					var _3_redirected bool = _source1.Get_().(Event_ResponseHead).Redirected
					_ = _3_redirected
					if (!(_3_redirected)) && (((_1_status).Cmp(_dafny.IntOfInt64(100)) < 0) || ((_1_status).Cmp(_dafny.IntOfInt64(599)) > 0)) {
						return Companion_Default___.Abort(s, true, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("transport reported an impossible status"))
					} else {
						var _source2 m_EHBP.Disposition = m_EHBP.Companion_Default___.Classify(_0_encrypted, m_EHBP.Companion_Head_.Create_Head_(_1_status, _2_headers, _3_redirected))
						_ = _source2
						{
							if _source2.Is_PassThrough() {
								return Companion_Default___.End(s, false, Companion_Action_.Create_Passthrough_(_1_status, _2_headers, _dafny.SeqOf()))
							}
						}
						{
							if _source2.Is_Refuse() {
								var _4_code m_EHBP.Code = _source2.Get_().(m_EHBP.Disposition_Refuse).Code
								_ = _4_code
								var _5_message _dafny.Sequence = _source2.Get_().(m_EHBP.Disposition_Refuse).Message
								_ = _5_message
								return Companion_Default___.Abort(s, true, _4_code, _5_message)
							}
						}
						{
							if _source2.Is_NeedProblemBody() {
								return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_ProblemReading_(_1_status, _2_headers, _dafny.SeqOf())), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_ResponseBody_())))
							}
						}
						{
							var _6_nonce _dafny.Sequence = _source2.Get_().(m_EHBP.Disposition_Decrypt).Nonce
							_ = _6_nonce
							var _7_requireFrame bool = _source2.Get_().(m_EHBP.Disposition_Decrypt).RequireFrame
							_ = _7_requireFrame
							if !(m_EHBP.Companion_Default___.ValidToken((s).Dtor_token())) {
								return Companion_Default___.Abort(s, true, m_EHBP.Companion_Code_.Create_InvalidInput_(), _dafny.UnicodeSeqOfUtf8Bytes("token fields must be 32 bytes"))
							} else if (_dafny.IntOfUint32((_6_nonce).Cardinality())).Cmp(m_EHBP.Companion_Default___.ResponseNonceLength()) != 0 {
								return Companion_Default___.Abort(s, true, m_EHBP.Companion_Code_.Create_InvalidInput_(), _dafny.UnicodeSeqOfUtf8Bytes("response nonce must be 32 bytes"))
							} else {
								var _8_job Job = Companion_Default___.Extract(_dafny.Companion_Sequence_.Concatenate(((s).Dtor_token()).Dtor_requestEnc(), _6_nonce), ((s).Dtor_token()).Dtor_exportedSecret())
								_ = _8_job
								return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_AwaitKeys_(_1_status, _2_headers, _7_requireFrame, _dafny.Zero, _8_job, _dafny.SeqOf(), _dafny.SeqOf())), _dafny.SeqOf(Companion_Default___.JobAction(_8_job)))
							}
						}
					}
				}
			}
			{
				return Companion_Default___.Unexpected(s)
			}
		}
	}
	{
		if _source0.Is_ProblemReading() {
			var _9_status _dafny.Int = _source0.Get_().(Response_ProblemReading).Status
			_ = _9_status
			var _10_headers _dafny.Sequence = _source0.Get_().(Response_ProblemReading).Headers
			_ = _10_headers
			var _11_data _dafny.Sequence = _source0.Get_().(Response_ProblemReading).Data
			_ = _11_data
			var _source3 Event = e
			_ = _source3
			{
				if _source3.Is_StreamFailed() {
					var stream1 Stream = _source3.Get_().(Event_StreamFailed).Stream
					_ = stream1
					if stream1.Is_ResponseBody() {
						return Companion_Default___.Abort(s, true, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("failed to read problem response"))
					}
				}
			}
			{
				if _source3.Is_Chunk() {
					var stream2 Stream = _source3.Get_().(Event_Chunk).Stream
					_ = stream2
					if stream2.Is_ResponseBody() {
						var _12_chunk _dafny.Sequence = _source3.Get_().(Event_Chunk).Data
						_ = _12_chunk
						var _13_eof bool = _source3.Get_().(Event_Chunk).Eof
						_ = _13_eof
						var _14_grown _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(_11_data, _12_chunk)
						_ = _14_grown
						if ((_dafny.IntOfUint32((_14_grown).Cardinality())).Cmp((m_EHBP.Companion_Default___.MaxProblemBytes()).Plus(_dafny.One)) <= 0) && (!(_13_eof)) {
							return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_ProblemReading_(_9_status, _10_headers, _14_grown)), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_ResponseBody_())))
						} else {
							var _15_oversized bool = (_dafny.IntOfUint32((_14_grown).Cardinality())).Cmp(m_EHBP.Companion_Default___.MaxProblemBytes()) > 0
							_ = _15_oversized
							var _let_tmp_rhs0 _dafny.Tuple = (func() _dafny.Tuple {
								if _15_oversized {
									return _dafny.TupleOf(false, m_EHBP.Companion_Option_.Create_None_(), m_EHBP.Companion_Option_.Create_None_())
								}
								return Companion_Default___.ParseProblem(_14_grown)
							})()
							_ = _let_tmp_rhs0
							var _16_isObject bool = (*(_let_tmp_rhs0).IndexInt(0)).(bool)
							_ = _16_isObject
							var _17_typeValue m_EHBP.Option = (*(_let_tmp_rhs0).IndexInt(1)).(m_EHBP.Option)
							_ = _17_typeValue
							var _18_title m_EHBP.Option = (*(_let_tmp_rhs0).IndexInt(2)).(m_EHBP.Option)
							_ = _18_title
							var _source4 m_EHBP.Disposition = m_EHBP.Companion_Default___.ClassifyProblem(_15_oversized, _16_isObject, _17_typeValue, _18_title)
							_ = _source4
							{
								if _source4.Is_Refuse() {
									var _19_code m_EHBP.Code = _source4.Get_().(m_EHBP.Disposition_Refuse).Code
									_ = _19_code
									var _20_message _dafny.Sequence = _source4.Get_().(m_EHBP.Disposition_Refuse).Message
									_ = _20_message
									return Companion_Default___.Abort(s, true, _19_code, _20_message)
								}
							}
							{
								if _source4.Is_PassThrough() {
									return Companion_Default___.End(s, false, Companion_Action_.Create_Passthrough_(_9_status, _10_headers, _14_grown))
								}
							}
							{
								return Companion_Default___.Abort(s, true, m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unreachable"))
							}
						}
					}
				}
			}
			{
				return Companion_Default___.Unexpected(s)
			}
		}
	}
	{
		if _source0.Is_AwaitKeys() {
			var _21_status _dafny.Int = _source0.Get_().(Response_AwaitKeys).Status
			_ = _21_status
			var _22_headers _dafny.Sequence = _source0.Get_().(Response_AwaitKeys).Headers
			_ = _22_headers
			var _23_requireFrame bool = _source0.Get_().(Response_AwaitKeys).RequireFrame
			_ = _23_requireFrame
			var _24_stage _dafny.Int = _source0.Get_().(Response_AwaitKeys).Stage
			_ = _24_stage
			var _25_job Job = _source0.Get_().(Response_AwaitKeys).Job
			_ = _25_job
			var _26_prk _dafny.Sequence = _source0.Get_().(Response_AwaitKeys).Prk
			_ = _26_prk
			var _27_key _dafny.Sequence = _source0.Get_().(Response_AwaitKeys).Key
			_ = _27_key
			var _source5 JobOut = Companion_Default___.JobStep(_25_job, e)
			_ = _source5
			{
				if _source5.Is_JobFailed() {
					var _28_code m_EHBP.Code = _source5.Get_().(JobOut_JobFailed).Code
					_ = _28_code
					var _29_message _dafny.Sequence = _source5.Get_().(JobOut_JobFailed).Message
					_ = _29_message
					return Companion_Default___.Abort(s, true, _28_code, _29_message)
				}
			}
			{
				if _source5.Is_Pending() {
					var _30_next Job = _source5.Get_().(JobOut_Pending).Job
					_ = _30_next
					var _31_a Action = _source5.Get_().(JobOut_Pending).Action
					_ = _31_a
					return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_AwaitKeys_(_21_status, _22_headers, _23_requireFrame, _24_stage, _30_next, _26_prk, _27_key)), _dafny.SeqOf(_31_a))
				}
			}
			{
				var _32_out _dafny.Sequence = _source5.Get_().(JobOut_Output).Data
				_ = _32_out
				if (_24_stage).Sign() == 0 {
					var _33_next Job = Companion_Default___.Expand(_32_out, m_EHBP.Companion_Default___.Ascii(m_EHBP.Companion_Default___.ResponseKeyLabel()), m_EHBP.Companion_Default___.KeyLength())
					_ = _33_next
					return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_AwaitKeys_(_21_status, _22_headers, _23_requireFrame, _dafny.One, _33_next, _32_out, _dafny.SeqOf())), _dafny.SeqOf(Companion_Default___.JobAction(_33_next)))
				} else if (_24_stage).Cmp(_dafny.One) == 0 {
					var _34_next Job = Companion_Default___.Expand(_26_prk, m_EHBP.Companion_Default___.Ascii(m_EHBP.Companion_Default___.ResponseNonceLabel()), m_EHBP.Companion_Default___.NonceLength())
					_ = _34_next
					return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_AwaitKeys_(_21_status, _22_headers, _23_requireFrame, _dafny.IntOfInt64(2), _34_next, _26_prk, _32_out)), _dafny.SeqOf(Companion_Default___.JobAction(_34_next)))
				} else if ((_dafny.IntOfUint32((_27_key).Cardinality())).Cmp(m_EHBP.Companion_Default___.KeyLength()) == 0) && ((_dafny.IntOfUint32((_32_out).Cardinality())).Cmp(m_EHBP.Companion_Default___.NonceLength()) == 0) {
					var _35_k _dafny.Sequence = _27_key
					_ = _35_k
					var _36_n _dafny.Sequence = _32_out
					_ = _36_n
					return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_Body_(Companion_Ctx_.Create_Ctx_(_35_k, _36_n, _dafny.SeqOf(), uint64(0)), Companion_Dec_.Create_Dec_(_dafny.SeqOf(), uint64(0), false, _23_requireFrame), false)), _dafny.SeqOf(Companion_Action_.Create_Done_(_21_status, m_EHBP.Companion_Default___.DropFraming(_22_headers))))
				} else {
					return Companion_Default___.Abort(s, true, m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("HKDF expand returned the wrong length"))
				}
			}
		}
	}
	{
		if _source0.Is_Body() {
			var _37_keys Ctx = _source0.Get_().(Response_Body).Keys
			_ = _37_keys
			var _38_dec Dec = _source0.Get_().(Response_Body).Dec
			_ = _38_dec
			var _39_done bool = _source0.Get_().(Response_Body).Done
			_ = _39_done
			if !((e).Is_CallerRead()) {
				return Companion_Default___.Unexpected(s)
			} else if _39_done {
				return Companion_Default___.End(s, false, Companion_Action_.Create_Finished_())
			} else {
				return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_BodyReading_(_37_keys, _38_dec)), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_ResponseBody_())))
			}
		}
	}
	{
		if _source0.Is_BodyReading() {
			var _40_keys Ctx = _source0.Get_().(Response_BodyReading).Keys
			_ = _40_keys
			var _41_dec Dec = _source0.Get_().(Response_BodyReading).Dec
			_ = _41_dec
			var _source6 Event = e
			_ = _source6
			{
				if _source6.Is_StreamFailed() {
					var stream3 Stream = _source6.Get_().(Event_StreamFailed).Stream
					_ = stream3
					if stream3.Is_ResponseBody() {
						return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_FramingTruncated_(), _dafny.UnicodeSeqOfUtf8Bytes("response body failed"))
					}
				}
			}
			{
				if _source6.Is_Chunk() {
					var stream4 Stream = _source6.Get_().(Event_Chunk).Stream
					_ = stream4
					if stream4.Is_ResponseBody() {
						var _42_data _dafny.Sequence = _source6.Get_().(Event_Chunk).Data
						_ = _42_data
						var _43_eof bool = _source6.Get_().(Event_Chunk).Eof
						_ = _43_eof
						var _let_tmp_rhs1 _dafny.Tuple = Companion_Default___.Push(_41_dec, _42_data)
						_ = _let_tmp_rhs1
						var _44_frames _dafny.Sequence = (*(_let_tmp_rhs1).IndexInt(0)).(_dafny.Sequence)
						_ = _44_frames
						var _45_next Dec = (*(_let_tmp_rhs1).IndexInt(1)).(Dec)
						_ = _45_next
						var _46_err m_EHBP.Option = (*(_let_tmp_rhs1).IndexInt(2)).(m_EHBP.Option)
						_ = _46_err
						if (_46_err).Is_Some() {
							return Companion_Default___.Abort(s, false, (_46_err).Dtor_value().(m_EHBP.Code), _dafny.UnicodeSeqOfUtf8Bytes(""))
						} else {
							return Companion_Default___.OpenNext(s, _40_keys, _45_next, _44_frames, _dafny.SeqOf(), _43_eof)
						}
					}
				}
			}
			{
				return Companion_Default___.Unexpected(s)
			}
		}
	}
	{
		if _source0.Is_Opening() {
			var _47_keys Ctx = _source0.Get_().(Response_Opening).Keys
			_ = _47_keys
			var _48_dec Dec = _source0.Get_().(Response_Opening).Dec
			_ = _48_dec
			var _49_frames _dafny.Sequence = _source0.Get_().(Response_Opening).Frames
			_ = _49_frames
			var _50_chunks _dafny.Sequence = _source0.Get_().(Response_Opening).Chunks
			_ = _50_chunks
			var _51_eof bool = _source0.Get_().(Response_Opening).Eof
			_ = _51_eof
			if (!((e).Is_AeadOpenResult())) || ((_dafny.IntOfUint32((_49_frames).Cardinality())).Sign() == 0) {
				return Companion_Default___.Unexpected(s)
			} else if !((e).Dtor_ok()) {
				return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_AeadDecryptFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("frame failed to authenticate"))
			} else if ((_dafny.IntOfUint32(((e).Dtor_plaintext()).Cardinality())).Plus(m_EHBP.Companion_Default___.AeadTagLength())).Cmp(_dafny.IntOfUint32((((_49_frames).Select(0).(m_EHBP.Framed)).Dtor_ciphertext()).Cardinality())) != 0 {
				return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_AeadDecryptFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("AEAD returned the wrong length"))
			} else {
				return Companion_Default___.OpenNext(s, _47_keys, _48_dec, (_49_frames).Drop(1), (func() _dafny.Sequence {
					if (_dafny.IntOfUint32(((e).Dtor_plaintext()).Cardinality())).Sign() == 1 {
						return _dafny.Companion_Sequence_.Concatenate(_50_chunks, _dafny.SeqOf((e).Dtor_plaintext()))
					}
					return _50_chunks
				})(), _51_eof)
			}
		}
	}
	{
		return Companion_Default___.Unexpected(s)
	}
}
func (_static *CompanionStruct_Default___) Emits(chunks _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((chunks).Cardinality())).Uint32(), func(coer8 func(_dafny.Int) Action) func(_dafny.Int) interface{} {
		return func(arg8 _dafny.Int) interface{} {
			return coer8(arg8)
		}
	}((func(_0_chunks _dafny.Sequence) func(_dafny.Int) Action {
		return func(_1_i _dafny.Int) Action {
			return Companion_Action_.Create_EmitPlaintext_((_0_chunks).Select((_1_i).Uint32()).(_dafny.Sequence))
		}
	})(chunks)))
}
func (_static *CompanionStruct_Default___) OpenNext(s State, keys Ctx, dec Dec, frames _dafny.Sequence, chunks _dafny.Sequence, eof bool) _dafny.Tuple {
	if (_dafny.IntOfUint32((frames).Cardinality())).Sign() == 1 {
		if (_dafny.IntOfUint32((((frames).Select(0).(m_EHBP.Framed)).Dtor_ciphertext()).Cardinality())).Cmp(m_EHBP.Companion_Default___.AeadTagLength()) < 0 {
			return Companion_Default___.Abort(s, false, m_EHBP.Companion_Code_.Create_AeadDecryptFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("frame shorter than the AEAD tag"))
		} else {
			return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_Opening_(keys, dec, frames, chunks, eof)), _dafny.SeqOf(Companion_Action_.Create_AeadOpen_((keys).Dtor_key(), m_EHBP.Companion_Default___.ComputeNonce((keys).Dtor_baseNonce(), ((frames).Select(0).(m_EHBP.Framed)).Dtor_seqNo()), ((frames).Select(0).(m_EHBP.Framed)).Dtor_ciphertext())))
		}
	} else if eof {
		var _source0 m_EHBP.Option = Companion_Default___.Finish(dec)
		_ = _source0
		{
			if _source0.Is_Some() {
				var _0_code m_EHBP.Code = _source0.Get_().(m_EHBP.Option_Some).Value.(m_EHBP.Code)
				_ = _0_code
				return Companion_Default___.Abort(s, false, _0_code, _dafny.UnicodeSeqOfUtf8Bytes(""))
			}
		}
		{
			if (_dafny.IntOfUint32((chunks).Cardinality())).Sign() == 1 {
				return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_Body_(keys, dec, true)), Companion_Default___.Emits(chunks))
			} else {
				return Companion_Default___.End(s, false, Companion_Action_.Create_Finished_())
			}
		}
	} else if (_dafny.IntOfUint32((chunks).Cardinality())).Sign() == 1 {
		return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_Body_(keys, dec, false)), Companion_Default___.Emits(chunks))
	} else {
		return _dafny.TupleOf(Companion_Default___.WithResponse(s, Companion_Response_.Create_BodyReading_(keys, dec)), _dafny.SeqOf(Companion_Action_.Create_Read_(Companion_Stream_.Create_ResponseBody_())))
	}
}
func (_static *CompanionStruct_Default___) Hex(s _dafny.Sequence) _dafny.Sequence {
	var _source0 m_EHBP.Option = m_EHBP.Companion_Default___.DecodeHex(s)
	_ = _source0
	{
		if _source0.Is_Some() {
			var _0_b _dafny.Sequence = _source0.Get_().(m_EHBP.Option_Some).Value.(_dafny.Sequence)
			_ = _0_b
			return _0_b
		}
	}
	{
		return _dafny.SeqOf()
	}
}
func (_static *CompanionStruct_Default___) SelfCheckJudge(results _dafny.Sequence) _dafny.Sequence {
	if (_dafny.IntOfUint32((results).Cardinality())).Cmp(_dafny.IntOfUint32((Companion_Default___.SelfCheckActions()).Cardinality())) != 0 {
		return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("self-check: wrong number of results"))
	} else {
		return _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate((func() _dafny.Sequence {
			if !((results).Select(0).(Event)).Equals(Companion_Event_.Create_HmacResult_(Companion_Default___.HmacTag())) {
				return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("HmacSha256: RFC 4231 test case 1"))
			}
			return _dafny.SeqOf()
		})(), (func() _dafny.Sequence {
			if !((results).Select(1).(Event)).Equals(Companion_Event_.Create_X25519Result_(Companion_Default___.AlicePk())) {
				return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("X25519: RFC 7748 base point"))
			}
			return _dafny.SeqOf()
		})()), (func() _dafny.Sequence {
			if !((results).Select(2).(Event)).Equals(Companion_Event_.Create_X25519Result_(Companion_Default___.AliceBobShared())) {
				return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("X25519: RFC 7748 shared secret"))
			}
			return _dafny.SeqOf()
		})()), (func() _dafny.Sequence {
			if !((results).Select(3).(Event)).Equals(Companion_Event_.Create_AeadSealResult_(Companion_Default___.GcmCt())) {
				return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("AeadSeal: known answer"))
			}
			return _dafny.SeqOf()
		})()), (func() _dafny.Sequence {
			if !((results).Select(4).(Event)).Equals(Companion_Event_.Create_AeadOpenResult_(true, m_EHBP.Companion_Default___.Ascii(_dafny.UnicodeSeqOfUtf8Bytes("ehbp")))) {
				return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("AeadOpen: known answer"))
			}
			return _dafny.SeqOf()
		})()), (func() _dafny.Sequence {
			if (!(((results).Select(5).(Event)).Is_AeadOpenResult())) || (((results).Select(5).(Event)).Dtor_ok()) {
				return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("AeadOpen: accepted a tampered tag"))
			}
			return _dafny.SeqOf()
		})()), (func() _dafny.Sequence {
			if (!(((results).Select(6).(Event)).Is_AeadOpenResult())) || (((results).Select(6).(Event)).Dtor_ok()) {
				return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("AeadOpen: accepted a frame shorter than the tag"))
			}
			return _dafny.SeqOf()
		})()), (func() _dafny.Sequence {
			if (((!(((results).Select(7).(Event)).Is_RandomResult())) || (!(((results).Select(8).(Event)).Is_RandomResult()))) || ((_dafny.IntOfUint32((((results).Select(7).(Event)).Dtor_data()).Cardinality())).Cmp(_dafny.IntOfInt64(32)) != 0)) || ((_dafny.IntOfUint32((((results).Select(8).(Event)).Dtor_data()).Cardinality())).Cmp(_dafny.IntOfInt64(32)) != 0) {
				return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("RandomBytes: length"))
			}
			return _dafny.SeqOf()
		})()), (func() _dafny.Sequence {
			if ((results).Select(7).(Event)).Equals((results).Select(8).(Event)) {
				return _dafny.SeqOf(_dafny.UnicodeSeqOfUtf8Bytes("RandomBytes: repeated output"))
			}
			return _dafny.SeqOf()
		})())
	}
}
func (_static *CompanionStruct_Default___) Rotr(x uint32, n _dafny.Int) uint32 {
	return ((x) >> ((n).Uint8())) | ((x) << (((_dafny.IntOfInt64(32)).Minus(n)).Uint8()))
}
func (_static *CompanionStruct_Default___) Word(b _dafny.Sequence, i _dafny.Int) uint32 {
	return (_dafny.IntOfUint32(m_EHBP.Companion_Default___.U32(b, i))).Uint32()
}
func (_static *CompanionStruct_Default___) WordBytes(w uint32) _dafny.Sequence {
	return m_EHBP.Companion_Default___.BE32((_dafny.IntOfUint32(w)).Uint32())
}
func (_static *CompanionStruct_Default___) MessageSchedule(w _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (_dafny.IntOfUint32((w).Cardinality())).Cmp(_dafny.IntOfInt64(64)) == 0 {
		return w
	} else {
		var _0_s0 uint32 = ((Companion_Default___.Rotr((w).Select(((_dafny.IntOfUint32((w).Cardinality())).Minus(_dafny.IntOfInt64(15))).Uint32()).(uint32), _dafny.IntOfInt64(7))) ^ (Companion_Default___.Rotr((w).Select(((_dafny.IntOfUint32((w).Cardinality())).Minus(_dafny.IntOfInt64(15))).Uint32()).(uint32), _dafny.IntOfInt64(18)))) ^ (((w).Select(((_dafny.IntOfUint32((w).Cardinality())).Minus(_dafny.IntOfInt64(15))).Uint32()).(uint32)) >> (uint8(3)))
		_ = _0_s0
		var _1_s1 uint32 = ((Companion_Default___.Rotr((w).Select(((_dafny.IntOfUint32((w).Cardinality())).Minus(_dafny.IntOfInt64(2))).Uint32()).(uint32), _dafny.IntOfInt64(17))) ^ (Companion_Default___.Rotr((w).Select(((_dafny.IntOfUint32((w).Cardinality())).Minus(_dafny.IntOfInt64(2))).Uint32()).(uint32), _dafny.IntOfInt64(19)))) ^ (((w).Select(((_dafny.IntOfUint32((w).Cardinality())).Minus(_dafny.IntOfInt64(2))).Uint32()).(uint32)) >> (uint8(10)))
		_ = _1_s1
		var _in0 _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(w, _dafny.SeqOf(((((w).Select(((_dafny.IntOfUint32((w).Cardinality())).Minus(_dafny.IntOfInt64(16))).Uint32()).(uint32))+(_0_s0))+((w).Select(((_dafny.IntOfUint32((w).Cardinality())).Minus(_dafny.IntOfInt64(7))).Uint32()).(uint32)))+(_1_s1)))
		_ = _in0
		w = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) Rounds(w _dafny.Sequence, t _dafny.Int, v _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (t).Cmp(_dafny.IntOfInt64(64)) == 0 {
		return v
	} else {
		var _0_a uint32 = (v).Select(0).(uint32)
		_ = _0_a
		var _1_b uint32 = (v).Select(1).(uint32)
		_ = _1_b
		var _2_c uint32 = (v).Select(2).(uint32)
		_ = _2_c
		var _3_d uint32 = (v).Select(3).(uint32)
		_ = _3_d
		var _4_e uint32 = (v).Select(4).(uint32)
		_ = _4_e
		var _5_f uint32 = (v).Select(5).(uint32)
		_ = _5_f
		var _6_g uint32 = (v).Select(6).(uint32)
		_ = _6_g
		var _7_h uint32 = (v).Select(7).(uint32)
		_ = _7_h
		var _8_t1 uint32 = ((((_7_h) + (((Companion_Default___.Rotr(_4_e, _dafny.IntOfInt64(6))) ^ (Companion_Default___.Rotr(_4_e, _dafny.IntOfInt64(11)))) ^ (Companion_Default___.Rotr(_4_e, _dafny.IntOfInt64(25))))) + (((_4_e) & (_5_f)) ^ ((^(_4_e)) & (_6_g)))) + ((Companion_Default___.K256()).Select((t).Uint32()).(uint32))) + ((w).Select((t).Uint32()).(uint32))
		_ = _8_t1
		var _9_t2 uint32 = (((Companion_Default___.Rotr(_0_a, _dafny.IntOfInt64(2))) ^ (Companion_Default___.Rotr(_0_a, _dafny.IntOfInt64(13)))) ^ (Companion_Default___.Rotr(_0_a, _dafny.IntOfInt64(22)))) + ((((_0_a) & (_1_b)) ^ ((_0_a) & (_2_c))) ^ ((_1_b) & (_2_c)))
		_ = _9_t2
		var _in0 _dafny.Sequence = w
		_ = _in0
		var _in1 _dafny.Int = (t).Plus(_dafny.One)
		_ = _in1
		var _in2 _dafny.Sequence = _dafny.SeqOf((_8_t1)+(_9_t2), _0_a, _1_b, _2_c, (_3_d)+(_8_t1), _4_e, _5_f, _6_g)
		_ = _in2
		w = _in0
		t = _in1
		v = _in2
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) Blocks(p _dafny.Sequence, i _dafny.Int, h _dafny.Sequence) _dafny.Sequence {
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (i).Cmp(_dafny.IntOfUint32((p).Cardinality())) == 0 {
		return h
	} else {
		var _0_block _dafny.Sequence = (p).Subsequence((i).Uint32(), ((i).Plus(_dafny.IntOfInt64(64))).Uint32())
		_ = _0_block
		var _1_w _dafny.Sequence = Companion_Default___.MessageSchedule(_dafny.SeqCreate(16, func(coer9 func(_dafny.Int) uint32) func(_dafny.Int) interface{} {
			return func(arg9 _dafny.Int) interface{} {
				return coer9(arg9)
			}
		}((func(_2_block _dafny.Sequence) func(_dafny.Int) uint32 {
			return func(_3_j _dafny.Int) uint32 {
				return Companion_Default___.Word(_2_block, (_dafny.IntOfInt64(4)).Times(_3_j))
			}
		})(_0_block))))
		_ = _1_w
		var _4_v _dafny.Sequence = Companion_Default___.Rounds(_1_w, _dafny.Zero, h)
		_ = _4_v
		var _in0 _dafny.Sequence = p
		_ = _in0
		var _in1 _dafny.Int = (i).Plus(_dafny.IntOfInt64(64))
		_ = _in1
		var _in2 _dafny.Sequence = _dafny.SeqCreate(8, func(coer10 func(_dafny.Int) uint32) func(_dafny.Int) interface{} {
			return func(arg10 _dafny.Int) interface{} {
				return coer10(arg10)
			}
		}((func(_5_h _dafny.Sequence, _6_v _dafny.Sequence) func(_dafny.Int) uint32 {
			return func(_7_j _dafny.Int) uint32 {
				return ((_5_h).Select((_7_j).Uint32()).(uint32)) + ((_6_v).Select((_7_j).Uint32()).(uint32))
			}
		})(h, _4_v)))
		_ = _in2
		p = _in0
		i = _in1
		h = _in2
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) Sha256(msg _dafny.Sequence) _dafny.Sequence {
	var _0_pad _dafny.Int = ((_dafny.IntOfInt64(119)).Minus((_dafny.IntOfUint32((msg).Cardinality())).Modulo(_dafny.IntOfInt64(64)))).Modulo(_dafny.IntOfInt64(64))
	_ = _0_pad
	var _1_bits _dafny.Int = (_dafny.IntOfUint32((msg).Cardinality())).Times(_dafny.IntOfInt64(8))
	_ = _1_bits
	var _2_padded _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(msg, _dafny.SeqOf(uint8(128))), _dafny.SeqCreate((_0_pad).Uint32(), func(coer11 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg11 _dafny.Int) interface{} {
			return coer11(arg11)
		}
	}(func(_3_i _dafny.Int) uint8 {
		return uint8(0)
	}))), m_EHBP.Companion_Default___.BE32((((_1_bits).DivBy(_dafny.IntOfInt64(4294967296))).Modulo(_dafny.IntOfInt64(4294967296))).Uint32())), m_EHBP.Companion_Default___.BE32(((_1_bits).Modulo(_dafny.IntOfInt64(4294967296))).Uint32()))
	_ = _2_padded
	var _4_h _dafny.Sequence = Companion_Default___.Blocks(_2_padded, _dafny.Zero, Companion_Default___.H256())
	_ = _4_h
	return _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(Companion_Default___.WordBytes((_4_h).Select(0).(uint32)), Companion_Default___.WordBytes((_4_h).Select(1).(uint32))), Companion_Default___.WordBytes((_4_h).Select(2).(uint32))), Companion_Default___.WordBytes((_4_h).Select(3).(uint32))), Companion_Default___.WordBytes((_4_h).Select(4).(uint32))), Companion_Default___.WordBytes((_4_h).Select(5).(uint32))), Companion_Default___.WordBytes((_4_h).Select(6).(uint32))), Companion_Default___.WordBytes((_4_h).Select(7).(uint32)))
}
func (_static *CompanionStruct_Default___) XorPad(b _dafny.Sequence, p uint8) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((b).Cardinality())).Uint32(), func(coer12 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg12 _dafny.Int) interface{} {
			return coer12(arg12)
		}
	}((func(_0_b _dafny.Sequence, _1_p uint8) func(_dafny.Int) uint8 {
		return func(_2_i _dafny.Int) uint8 {
			return uint8((uint8((_0_b).Select((_2_i).Uint32()).(uint8))) ^ (uint8(_1_p)))
		}
	})(b, p)))
}
func (_static *CompanionStruct_Default___) HmacRef(key _dafny.Sequence, data _dafny.Sequence) _dafny.Sequence {
	var _0_k _dafny.Sequence = (func() _dafny.Sequence {
		if (_dafny.IntOfUint32((key).Cardinality())).Cmp(_dafny.IntOfInt64(64)) > 0 {
			return Companion_Default___.Sha256(key)
		}
		return key
	})()
	_ = _0_k
	var _1_kp _dafny.Sequence = _dafny.Companion_Sequence_.Concatenate(_0_k, _dafny.SeqCreate(((_dafny.IntOfInt64(64)).Minus(_dafny.IntOfUint32((_0_k).Cardinality()))).Uint32(), func(coer13 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg13 _dafny.Int) interface{} {
			return coer13(arg13)
		}
	}(func(_2_i _dafny.Int) uint8 {
		return uint8(0)
	})))
	_ = _1_kp
	return Companion_Default___.Sha256(_dafny.Companion_Sequence_.Concatenate(Companion_Default___.XorPad(_1_kp, uint8(92)), Companion_Default___.Sha256(_dafny.Companion_Sequence_.Concatenate(Companion_Default___.XorPad(_1_kp, uint8(54)), data))))
}
func (_static *CompanionStruct_Default___) Pow2(n _dafny.Int) _dafny.Int {
	var _0___accumulator _dafny.Int = _dafny.One
	_ = _0___accumulator
	goto TAIL_CALL_START
TAIL_CALL_START:
	if (n).Sign() == 0 {
		return (_dafny.One).Times(_0___accumulator)
	} else {
		_0___accumulator = (_0___accumulator).Times(_dafny.IntOfInt64(2))
		var _in0 _dafny.Int = (n).Minus(_dafny.One)
		_ = _in0
		n = _in0
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) PowMod(b _dafny.Int, e _dafny.Int) _dafny.Int {
	if (e).Sign() == 0 {
		return (_dafny.One).Modulo(Companion_Default___.P25519())
	} else if ((e).Modulo(_dafny.IntOfInt64(2))).Sign() == 0 {
		var _0_h _dafny.Int = Companion_Default___.PowMod(b, (e).DivBy(_dafny.IntOfInt64(2)))
		_ = _0_h
		return ((_0_h).Times(_0_h)).Modulo(Companion_Default___.P25519())
	} else {
		return ((b).Times(Companion_Default___.PowMod(b, (e).Minus(_dafny.One)))).Modulo(Companion_Default___.P25519())
	}
}
func (_static *CompanionStruct_Default___) LE(b _dafny.Sequence) _dafny.Int {
	if (_dafny.IntOfUint32((b).Cardinality())).Sign() == 0 {
		return _dafny.Zero
	} else {
		return (_dafny.IntOfUint8((b).Select(0).(uint8))).Plus((_dafny.IntOfInt64(256)).Times(Companion_Default___.LE((b).Drop(1))))
	}
}
func (_static *CompanionStruct_Default___) LEBytes(n _dafny.Int, length _dafny.Int) _dafny.Sequence {
	return _dafny.SeqCreate((length).Uint32(), func(coer14 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg14 _dafny.Int) interface{} {
			return coer14(arg14)
		}
	}((func(_0_n _dafny.Int, _1_length _dafny.Int) func(_dafny.Int) uint8 {
		return func(_2_i _dafny.Int) uint8 {
			return (((_0_n).DivBy(Companion_Default___.Pow2((_dafny.IntOfInt64(8)).Times(_2_i)))).Modulo(_dafny.IntOfInt64(256))).Uint8()
		}
	})(n, length)))
}
func (_static *CompanionStruct_Default___) Clamp(k _dafny.Sequence) _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(uint8((uint8((k).Select(0).(uint8)))&(uint8(248)))), (k).Subsequence(1, 31)), _dafny.SeqOf(uint8(((uint8((k).Select(31).(uint8)))&(uint8(127)))|(uint8(64)))))
}
func (_static *CompanionStruct_Default___) Ladder(k _dafny.Int, x1 _dafny.Int, t _dafny.Int, x2 _dafny.Int, z2 _dafny.Int, x3 _dafny.Int, z3 _dafny.Int, swap _dafny.Int) _dafny.Tuple {
	goto TAIL_CALL_START
TAIL_CALL_START:
	var _0_kt _dafny.Int = ((k).DivBy(Companion_Default___.Pow2(t))).Modulo(_dafny.IntOfInt64(2))
	_ = _0_kt
	var _1_sw _dafny.Int = (func() _dafny.Int {
		if (swap).Cmp(_0_kt) != 0 {
			return _dafny.One
		}
		return _dafny.Zero
	})()
	_ = _1_sw
	var _let_tmp_rhs0 _dafny.Tuple = (func() _dafny.Tuple {
		if (_1_sw).Cmp(_dafny.One) == 0 {
			return _dafny.TupleOf(x3, x2)
		}
		return _dafny.TupleOf(x2, x3)
	})()
	_ = _let_tmp_rhs0
	var _2_x2s _dafny.Int = (*(_let_tmp_rhs0).IndexInt(0)).(_dafny.Int)
	_ = _2_x2s
	var _3_x3s _dafny.Int = (*(_let_tmp_rhs0).IndexInt(1)).(_dafny.Int)
	_ = _3_x3s
	var _let_tmp_rhs1 _dafny.Tuple = (func() _dafny.Tuple {
		if (_1_sw).Cmp(_dafny.One) == 0 {
			return _dafny.TupleOf(z3, z2)
		}
		return _dafny.TupleOf(z2, z3)
	})()
	_ = _let_tmp_rhs1
	var _4_z2s _dafny.Int = (*(_let_tmp_rhs1).IndexInt(0)).(_dafny.Int)
	_ = _4_z2s
	var _5_z3s _dafny.Int = (*(_let_tmp_rhs1).IndexInt(1)).(_dafny.Int)
	_ = _5_z3s
	var _6_a _dafny.Int = ((_2_x2s).Plus(_4_z2s)).Modulo(Companion_Default___.P25519())
	_ = _6_a
	var _7_aa _dafny.Int = ((_6_a).Times(_6_a)).Modulo(Companion_Default___.P25519())
	_ = _7_aa
	var _8_b _dafny.Int = ((_2_x2s).Minus(_4_z2s)).Modulo(Companion_Default___.P25519())
	_ = _8_b
	var _9_bb _dafny.Int = ((_8_b).Times(_8_b)).Modulo(Companion_Default___.P25519())
	_ = _9_bb
	var _10_e _dafny.Int = ((_7_aa).Minus(_9_bb)).Modulo(Companion_Default___.P25519())
	_ = _10_e
	var _11_c _dafny.Int = ((_3_x3s).Plus(_5_z3s)).Modulo(Companion_Default___.P25519())
	_ = _11_c
	var _12_d _dafny.Int = ((_3_x3s).Minus(_5_z3s)).Modulo(Companion_Default___.P25519())
	_ = _12_d
	var _13_da _dafny.Int = ((_12_d).Times(_6_a)).Modulo(Companion_Default___.P25519())
	_ = _13_da
	var _14_cb _dafny.Int = ((_11_c).Times(_8_b)).Modulo(Companion_Default___.P25519())
	_ = _14_cb
	var _15_nx3 _dafny.Int = (((_13_da).Plus(_14_cb)).Times((_13_da).Plus(_14_cb))).Modulo(Companion_Default___.P25519())
	_ = _15_nx3
	var _16_nz3 _dafny.Int = ((x1).Times((((_13_da).Minus(_14_cb)).Times((_13_da).Minus(_14_cb))).Modulo(Companion_Default___.P25519()))).Modulo(Companion_Default___.P25519())
	_ = _16_nz3
	var _17_nx2 _dafny.Int = ((_7_aa).Times(_9_bb)).Modulo(Companion_Default___.P25519())
	_ = _17_nx2
	var _18_nz2 _dafny.Int = ((_10_e).Times(((_7_aa).Plus((_dafny.IntOfInt64(121665)).Times(_10_e))).Modulo(Companion_Default___.P25519()))).Modulo(Companion_Default___.P25519())
	_ = _18_nz2
	if (t).Sign() == 0 {
		return _dafny.TupleOf(_17_nx2, _18_nz2, _15_nx3, _16_nz3, _0_kt)
	} else {
		var _in0 _dafny.Int = k
		_ = _in0
		var _in1 _dafny.Int = x1
		_ = _in1
		var _in2 _dafny.Int = (t).Minus(_dafny.One)
		_ = _in2
		var _in3 _dafny.Int = _17_nx2
		_ = _in3
		var _in4 _dafny.Int = _18_nz2
		_ = _in4
		var _in5 _dafny.Int = _15_nx3
		_ = _in5
		var _in6 _dafny.Int = _16_nz3
		_ = _in6
		var _in7 _dafny.Int = _0_kt
		_ = _in7
		k = _in0
		x1 = _in1
		t = _in2
		x2 = _in3
		z2 = _in4
		x3 = _in5
		z3 = _in6
		swap = _in7
		goto TAIL_CALL_START
	}
}
func (_static *CompanionStruct_Default___) X25519Ref(scalar _dafny.Sequence, point _dafny.Sequence) _dafny.Sequence {
	var _0_k _dafny.Int = Companion_Default___.LE(Companion_Default___.Clamp(scalar))
	_ = _0_k
	var _1_u _dafny.Int = (Companion_Default___.LE(point)).Modulo(Companion_Default___.Pow2(_dafny.IntOfInt64(255)))
	_ = _1_u
	var _let_tmp_rhs0 _dafny.Tuple = Companion_Default___.Ladder(_0_k, _1_u, _dafny.IntOfInt64(255), _dafny.One, _dafny.Zero, _1_u, _dafny.One, _dafny.Zero)
	_ = _let_tmp_rhs0
	var _2_x2 _dafny.Int = (*(_let_tmp_rhs0).IndexInt(0)).(_dafny.Int)
	_ = _2_x2
	var _3_z2 _dafny.Int = (*(_let_tmp_rhs0).IndexInt(1)).(_dafny.Int)
	_ = _3_z2
	var _4_x3 _dafny.Int = (*(_let_tmp_rhs0).IndexInt(2)).(_dafny.Int)
	_ = _4_x3
	var _5_z3 _dafny.Int = (*(_let_tmp_rhs0).IndexInt(3)).(_dafny.Int)
	_ = _5_z3
	var _6_swap _dafny.Int = (*(_let_tmp_rhs0).IndexInt(4)).(_dafny.Int)
	_ = _6_swap
	var _let_tmp_rhs1 _dafny.Tuple = (func() _dafny.Tuple {
		if (_6_swap).Cmp(_dafny.One) == 0 {
			return _dafny.TupleOf(_4_x3, _5_z3)
		}
		return _dafny.TupleOf(_2_x2, _3_z2)
	})()
	_ = _let_tmp_rhs1
	var _7_x _dafny.Int = (*(_let_tmp_rhs1).IndexInt(0)).(_dafny.Int)
	_ = _7_x
	var _8_z _dafny.Int = (*(_let_tmp_rhs1).IndexInt(1)).(_dafny.Int)
	_ = _8_z
	return Companion_Default___.LEBytes(((_7_x).Times(Companion_Default___.PowMod(_8_z, (Companion_Default___.P25519()).Minus(_dafny.IntOfInt64(2))))).Modulo(Companion_Default___.P25519()), _dafny.IntOfInt64(32))
}
func (_static *CompanionStruct_Default___) BasePoint() _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(uint8(9)), Companion_Default___.Repeat(_dafny.IntOfInt64(31), uint8(0)))
}
func (_static *CompanionStruct_Default___) HpkeVersion() _dafny.Sequence {
	return m_EHBP.Companion_Default___.Ascii(_dafny.UnicodeSeqOfUtf8Bytes("HPKE-v1"))
}
func (_static *CompanionStruct_Default___) KemSuiteId() _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(m_EHBP.Companion_Default___.Ascii(_dafny.UnicodeSeqOfUtf8Bytes("KEM")), m_EHBP.Companion_Default___.BE16(m_EHBP.Companion_Default___.KemX25519()))
}
func (_static *CompanionStruct_Default___) HpkeSuiteId() _dafny.Sequence {
	return _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(m_EHBP.Companion_Default___.Ascii(_dafny.UnicodeSeqOfUtf8Bytes("HPKE")), m_EHBP.Companion_Default___.BE16(m_EHBP.Companion_Default___.KemX25519())), m_EHBP.Companion_Default___.BE16(m_EHBP.Companion_Default___.KdfHkdfSha256())), m_EHBP.Companion_Default___.BE16(m_EHBP.Companion_Default___.AeadAes256Gcm()))
}
func (_static *CompanionStruct_Default___) MaxSeq() uint64 {
	return uint64(18446744073709551615)
}
func (_static *CompanionStruct_Default___) MaxJsonStringChars() _dafny.Int {
	return _dafny.IntOfInt64(1024)
}
func (_static *CompanionStruct_Default___) MaxJsonDepth() _dafny.Int {
	return _dafny.IntOfInt64(64)
}
func (_static *CompanionStruct_Default___) NewSession() SessionStore {
	return Companion_SessionStore_.Create_SessionStore_(uint64(0), m_EHBP.Companion_Option_.Create_None_())
}
func (_static *CompanionStruct_Default___) NoCtx() Ctx {
	return Companion_Ctx_.Create_Ctx_(Companion_Default___.Repeat(_dafny.IntOfInt64(32), uint8(0)), Companion_Default___.Repeat(_dafny.IntOfInt64(12), uint8(0)), _dafny.SeqOf(), uint64(0))
}
func (_static *CompanionStruct_Default___) MaxReadBytes() _dafny.Int {
	return _dafny.IntOfInt64(4294967295)
}
func (_static *CompanionStruct_Default___) NoOrigin() m_EHBP.Origin {
	return m_EHBP.Companion_Origin_.Create_Origin_(_dafny.UnicodeSeqOfUtf8Bytes("https"), _dafny.UnicodeSeqOfUtf8Bytes(""), _dafny.IntOfInt64(443))
}
func (_static *CompanionStruct_Default___) GcmKey() _dafny.Sequence {
	return Companion_Default___.Iota(_dafny.IntOfInt64(32))
}
func (_static *CompanionStruct_Default___) GcmNonce() _dafny.Sequence {
	return Companion_Default___.Iota(_dafny.IntOfInt64(12))
}
func (_static *CompanionStruct_Default___) GcmCt() _dafny.Sequence {
	return Companion_Default___.Hex(_dafny.UnicodeSeqOfUtf8Bytes("226ab46b72d4be2b87fabbe9dbe0bfc2adbce017"))
}
func (_static *CompanionStruct_Default___) AliceSk() _dafny.Sequence {
	return Companion_Default___.Hex(_dafny.UnicodeSeqOfUtf8Bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
}
func (_static *CompanionStruct_Default___) AlicePk() _dafny.Sequence {
	return Companion_Default___.Hex(_dafny.UnicodeSeqOfUtf8Bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
}
func (_static *CompanionStruct_Default___) BobPk() _dafny.Sequence {
	return Companion_Default___.Hex(_dafny.UnicodeSeqOfUtf8Bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
}
func (_static *CompanionStruct_Default___) AliceBobShared() _dafny.Sequence {
	return Companion_Default___.Hex(_dafny.UnicodeSeqOfUtf8Bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
}
func (_static *CompanionStruct_Default___) HmacKey() _dafny.Sequence {
	return Companion_Default___.Repeat(_dafny.IntOfInt64(20), uint8(11))
}
func (_static *CompanionStruct_Default___) HmacTag() _dafny.Sequence {
	return Companion_Default___.Hex(_dafny.UnicodeSeqOfUtf8Bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))
}
func (_static *CompanionStruct_Default___) SelfCheckActions() _dafny.Sequence {
	return _dafny.SeqOf(Companion_Action_.Create_HmacSha256_(Companion_Default___.HmacKey(), m_EHBP.Companion_Default___.Ascii(_dafny.UnicodeSeqOfUtf8Bytes("Hi There"))), Companion_Action_.Create_X25519_(Companion_Default___.AliceSk(), Companion_Default___.BasePoint()), Companion_Action_.Create_X25519_(Companion_Default___.AliceSk(), Companion_Default___.BobPk()), Companion_Action_.Create_AeadSeal_(Companion_Default___.GcmKey(), Companion_Default___.GcmNonce(), m_EHBP.Companion_Default___.Ascii(_dafny.UnicodeSeqOfUtf8Bytes("ehbp"))), Companion_Action_.Create_AeadOpen_(Companion_Default___.GcmKey(), Companion_Default___.GcmNonce(), Companion_Default___.GcmCt()), Companion_Action_.Create_AeadOpen_(Companion_Default___.GcmKey(), Companion_Default___.GcmNonce(), _dafny.Companion_Sequence_.Concatenate((Companion_Default___.GcmCt()).Take(((_dafny.IntOfUint32((Companion_Default___.GcmCt()).Cardinality())).Minus(_dafny.One)).Uint32()), _dafny.SeqOf(uint8((uint8((Companion_Default___.GcmCt()).Select(((_dafny.IntOfUint32((Companion_Default___.GcmCt()).Cardinality())).Minus(_dafny.One)).Uint32()).(uint8)))^(uint8(1)))))), Companion_Action_.Create_AeadOpen_(Companion_Default___.GcmKey(), Companion_Default___.GcmNonce(), (Companion_Default___.GcmCt()).Take(8)), Companion_Action_.Create_RandomBytes_(_dafny.IntOfInt64(32)), Companion_Action_.Create_RandomBytes_(_dafny.IntOfInt64(32)))
}
func (_static *CompanionStruct_Default___) K256() _dafny.Sequence {
	return _dafny.SeqOf(uint32(1116352408), uint32(1899447441), uint32(3049323471), uint32(3921009573), uint32(961987163), uint32(1508970993), uint32(2453635748), uint32(2870763221), uint32(3624381080), uint32(310598401), uint32(607225278), uint32(1426881987), uint32(1925078388), uint32(2162078206), uint32(2614888103), uint32(3248222580), uint32(3835390401), uint32(4022224774), uint32(264347078), uint32(604807628), uint32(770255983), uint32(1249150122), uint32(1555081692), uint32(1996064986), uint32(2554220882), uint32(2821834349), uint32(2952996808), uint32(3210313671), uint32(3336571891), uint32(3584528711), uint32(113926993), uint32(338241895), uint32(666307205), uint32(773529912), uint32(1294757372), uint32(1396182291), uint32(1695183700), uint32(1986661051), uint32(2177026350), uint32(2456956037), uint32(2730485921), uint32(2820302411), uint32(3259730800), uint32(3345764771), uint32(3516065817), uint32(3600352804), uint32(4094571909), uint32(275423344), uint32(430227734), uint32(506948616), uint32(659060556), uint32(883997877), uint32(958139571), uint32(1322822218), uint32(1537002063), uint32(1747873779), uint32(1955562222), uint32(2024104815), uint32(2227730452), uint32(2361852424), uint32(2428436474), uint32(2756734187), uint32(3204031479), uint32(3329325298))
}
func (_static *CompanionStruct_Default___) H256() _dafny.Sequence {
	return _dafny.SeqOf(uint32(1779033703), uint32(3144134277), uint32(1013904242), uint32(2773480762), uint32(1359893119), uint32(2600822924), uint32(528734635), uint32(1541459225))
}
func (_static *CompanionStruct_Default___) P25519() _dafny.Int {
	return _dafny.IntOfString("57896044618658097711785492504343953926634992332820282019728792003956564819949")
}

// End of class Default__

// Definition of datatype Stream
type Stream struct {
	Data_Stream_
}

func (_this Stream) Get_() Data_Stream_ {
	return _this.Data_Stream_
}

type Data_Stream_ interface {
	isStream()
}

type CompanionStruct_Stream_ struct {
}

var Companion_Stream_ = CompanionStruct_Stream_{}

type Stream_RequestBody struct {
}

func (Stream_RequestBody) isStream() {}

func (CompanionStruct_Stream_) Create_RequestBody_() Stream {
	return Stream{Stream_RequestBody{}}
}

func (_this Stream) Is_RequestBody() bool {
	_, ok := _this.Get_().(Stream_RequestBody)
	return ok
}

type Stream_ResponseBody struct {
}

func (Stream_ResponseBody) isStream() {}

func (CompanionStruct_Stream_) Create_ResponseBody_() Stream {
	return Stream{Stream_ResponseBody{}}
}

func (_this Stream) Is_ResponseBody() bool {
	_, ok := _this.Get_().(Stream_ResponseBody)
	return ok
}

func (CompanionStruct_Stream_) Default() Stream {
	return Companion_Stream_.Create_RequestBody_()
}

func (_ CompanionStruct_Stream_) AllSingletonConstructors() _dafny.Iterator {
	i := -1
	return func() (interface{}, bool) {
		i++
		switch i {
		case 0:
			return Companion_Stream_.Create_RequestBody_(), true
		case 1:
			return Companion_Stream_.Create_ResponseBody_(), true
		default:
			return Stream{}, false
		}
	}
}

func (_this Stream) String() string {
	switch _this.Get_().(type) {
	case nil:
		return "null"
	case Stream_RequestBody:
		{
			return "EHBPEvents.Stream.RequestBody"
		}
	case Stream_ResponseBody:
		{
			return "EHBPEvents.Stream.ResponseBody"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Stream) Equals(other Stream) bool {
	switch _this.Get_().(type) {
	case Stream_RequestBody:
		{
			_, ok := other.Get_().(Stream_RequestBody)
			return ok
		}
	case Stream_ResponseBody:
		{
			_, ok := other.Get_().(Stream_ResponseBody)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Stream) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Stream)
	return ok && _this.Equals(typed)
}

func Type_Stream_() _dafny.TypeDescriptor {
	return type_Stream_{}
}

type type_Stream_ struct {
}

func (_this type_Stream_) Default() interface{} {
	return Companion_Stream_.Default()
}

func (_this type_Stream_) String() string {
	return "EHBPEvents.Stream"
}
func (_this Stream) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Stream{}

// End of datatype Stream

// Definition of datatype BodyEnd
type BodyEnd struct {
	Data_BodyEnd_
}

func (_this BodyEnd) Get_() Data_BodyEnd_ {
	return _this.Data_BodyEnd_
}

type Data_BodyEnd_ interface {
	isBodyEnd()
}

type CompanionStruct_BodyEnd_ struct {
}

var Companion_BodyEnd_ = CompanionStruct_BodyEnd_{}

type BodyEnd_More struct {
}

func (BodyEnd_More) isBodyEnd() {}

func (CompanionStruct_BodyEnd_) Create_More_() BodyEnd {
	return BodyEnd{BodyEnd_More{}}
}

func (_this BodyEnd) Is_More() bool {
	_, ok := _this.Get_().(BodyEnd_More)
	return ok
}

type BodyEnd_Done struct {
}

func (BodyEnd_Done) isBodyEnd() {}

func (CompanionStruct_BodyEnd_) Create_Done_() BodyEnd {
	return BodyEnd{BodyEnd_Done{}}
}

func (_this BodyEnd) Is_Done() bool {
	_, ok := _this.Get_().(BodyEnd_Done)
	return ok
}

type BodyEnd_Aborted struct {
	Code m_EHBP.Code
}

func (BodyEnd_Aborted) isBodyEnd() {}

func (CompanionStruct_BodyEnd_) Create_Aborted_(Code m_EHBP.Code) BodyEnd {
	return BodyEnd{BodyEnd_Aborted{Code}}
}

func (_this BodyEnd) Is_Aborted() bool {
	_, ok := _this.Get_().(BodyEnd_Aborted)
	return ok
}

func (CompanionStruct_BodyEnd_) Default() BodyEnd {
	return Companion_BodyEnd_.Create_More_()
}

func (_this BodyEnd) Dtor_code() m_EHBP.Code {
	return _this.Get_().(BodyEnd_Aborted).Code
}

func (_this BodyEnd) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case BodyEnd_More:
		{
			return "EHBPEvents.BodyEnd.More"
		}
	case BodyEnd_Done:
		{
			return "EHBPEvents.BodyEnd.Done"
		}
	case BodyEnd_Aborted:
		{
			return "EHBPEvents.BodyEnd.Aborted" + "(" + _dafny.String(data.Code) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this BodyEnd) Equals(other BodyEnd) bool {
	switch data1 := _this.Get_().(type) {
	case BodyEnd_More:
		{
			_, ok := other.Get_().(BodyEnd_More)
			return ok
		}
	case BodyEnd_Done:
		{
			_, ok := other.Get_().(BodyEnd_Done)
			return ok
		}
	case BodyEnd_Aborted:
		{
			data2, ok := other.Get_().(BodyEnd_Aborted)
			return ok && data1.Code.Equals(data2.Code)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this BodyEnd) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(BodyEnd)
	return ok && _this.Equals(typed)
}

func Type_BodyEnd_() _dafny.TypeDescriptor {
	return type_BodyEnd_{}
}

type type_BodyEnd_ struct {
}

func (_this type_BodyEnd_) Default() interface{} {
	return Companion_BodyEnd_.Default()
}

func (_this type_BodyEnd_) String() string {
	return "EHBPEvents.BodyEnd"
}
func (_this BodyEnd) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = BodyEnd{}

// End of datatype BodyEnd

// Definition of datatype Event
type Event struct {
	Data_Event_
}

func (_this Event) Get_() Data_Event_ {
	return _this.Data_Event_
}

type Data_Event_ interface {
	isEvent()
}

type CompanionStruct_Event_ struct {
}

var Companion_Event_ = CompanionStruct_Event_{}

type Event_Start struct {
	Verb        _dafny.Sequence
	Url         _dafny.Sequence
	Scheme      _dafny.Sequence
	Host        _dafny.Sequence
	Port        _dafny.Int
	HasPort     bool
	HasUserinfo bool
	Headers     _dafny.Sequence
	HasBody     bool
}

func (Event_Start) isEvent() {}

func (CompanionStruct_Event_) Create_Start_(Verb _dafny.Sequence, Url _dafny.Sequence, Scheme _dafny.Sequence, Host _dafny.Sequence, Port _dafny.Int, HasPort bool, HasUserinfo bool, Headers _dafny.Sequence, HasBody bool) Event {
	return Event{Event_Start{Verb, Url, Scheme, Host, Port, HasPort, HasUserinfo, Headers, HasBody}}
}

func (_this Event) Is_Start() bool {
	_, ok := _this.Get_().(Event_Start)
	return ok
}

type Event_DiscoverStart struct {
}

func (Event_DiscoverStart) isEvent() {}

func (CompanionStruct_Event_) Create_DiscoverStart_() Event {
	return Event{Event_DiscoverStart{}}
}

func (_this Event) Is_DiscoverStart() bool {
	_, ok := _this.Get_().(Event_DiscoverStart)
	return ok
}

type Event_SessionBegun struct {
	Generation uint64
}

func (Event_SessionBegun) isEvent() {}

func (CompanionStruct_Event_) Create_SessionBegun_(Generation uint64) Event {
	return Event{Event_SessionBegun{Generation}}
}

func (_this Event) Is_SessionBegun() bool {
	_, ok := _this.Get_().(Event_SessionBegun)
	return ok
}

type Event_RandomResult struct {
	Data _dafny.Sequence
}

func (Event_RandomResult) isEvent() {}

func (CompanionStruct_Event_) Create_RandomResult_(Data _dafny.Sequence) Event {
	return Event{Event_RandomResult{Data}}
}

func (_this Event) Is_RandomResult() bool {
	_, ok := _this.Get_().(Event_RandomResult)
	return ok
}

type Event_X25519Result struct {
	Point _dafny.Sequence
}

func (Event_X25519Result) isEvent() {}

func (CompanionStruct_Event_) Create_X25519Result_(Point _dafny.Sequence) Event {
	return Event{Event_X25519Result{Point}}
}

func (_this Event) Is_X25519Result() bool {
	_, ok := _this.Get_().(Event_X25519Result)
	return ok
}

type Event_HmacResult struct {
	Mac _dafny.Sequence
}

func (Event_HmacResult) isEvent() {}

func (CompanionStruct_Event_) Create_HmacResult_(Mac _dafny.Sequence) Event {
	return Event{Event_HmacResult{Mac}}
}

func (_this Event) Is_HmacResult() bool {
	_, ok := _this.Get_().(Event_HmacResult)
	return ok
}

type Event_AeadSealResult struct {
	Ciphertext _dafny.Sequence
}

func (Event_AeadSealResult) isEvent() {}

func (CompanionStruct_Event_) Create_AeadSealResult_(Ciphertext _dafny.Sequence) Event {
	return Event{Event_AeadSealResult{Ciphertext}}
}

func (_this Event) Is_AeadSealResult() bool {
	_, ok := _this.Get_().(Event_AeadSealResult)
	return ok
}

type Event_AeadOpenResult struct {
	Ok        bool
	Plaintext _dafny.Sequence
}

func (Event_AeadOpenResult) isEvent() {}

func (CompanionStruct_Event_) Create_AeadOpenResult_(Ok bool, Plaintext _dafny.Sequence) Event {
	return Event{Event_AeadOpenResult{Ok, Plaintext}}
}

func (_this Event) Is_AeadOpenResult() bool {
	_, ok := _this.Get_().(Event_AeadOpenResult)
	return ok
}

type Event_ResponseHead struct {
	Status     _dafny.Int
	Headers    _dafny.Sequence
	Redirected bool
}

func (Event_ResponseHead) isEvent() {}

func (CompanionStruct_Event_) Create_ResponseHead_(Status _dafny.Int, Headers _dafny.Sequence, Redirected bool) Event {
	return Event{Event_ResponseHead{Status, Headers, Redirected}}
}

func (_this Event) Is_ResponseHead() bool {
	_, ok := _this.Get_().(Event_ResponseHead)
	return ok
}

type Event_Chunk struct {
	Stream Stream
	Data   _dafny.Sequence
	Eof    bool
}

func (Event_Chunk) isEvent() {}

func (CompanionStruct_Event_) Create_Chunk_(Stream Stream, Data _dafny.Sequence, Eof bool) Event {
	return Event{Event_Chunk{Stream, Data, Eof}}
}

func (_this Event) Is_Chunk() bool {
	_, ok := _this.Get_().(Event_Chunk)
	return ok
}

type Event_StreamFailed struct {
	Stream Stream
}

func (Event_StreamFailed) isEvent() {}

func (CompanionStruct_Event_) Create_StreamFailed_(Stream Stream) Event {
	return Event{Event_StreamFailed{Stream}}
}

func (_this Event) Is_StreamFailed() bool {
	_, ok := _this.Get_().(Event_StreamFailed)
	return ok
}

type Event_CallerRead struct {
}

func (Event_CallerRead) isEvent() {}

func (CompanionStruct_Event_) Create_CallerRead_() Event {
	return Event{Event_CallerRead{}}
}

func (_this Event) Is_CallerRead() bool {
	_, ok := _this.Get_().(Event_CallerRead)
	return ok
}

type Event_CallerClose struct {
}

func (Event_CallerClose) isEvent() {}

func (CompanionStruct_Event_) Create_CallerClose_() Event {
	return Event{Event_CallerClose{}}
}

func (_this Event) Is_CallerClose() bool {
	_, ok := _this.Get_().(Event_CallerClose)
	return ok
}

func (CompanionStruct_Event_) Default() Event {
	return Companion_Event_.Create_Start_(_dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.Zero, false, false, _dafny.EmptySeq, false)
}

func (_this Event) Dtor_verb() _dafny.Sequence {
	return _this.Get_().(Event_Start).Verb
}

func (_this Event) Dtor_url() _dafny.Sequence {
	return _this.Get_().(Event_Start).Url
}

func (_this Event) Dtor_scheme() _dafny.Sequence {
	return _this.Get_().(Event_Start).Scheme
}

func (_this Event) Dtor_host() _dafny.Sequence {
	return _this.Get_().(Event_Start).Host
}

func (_this Event) Dtor_port() _dafny.Int {
	return _this.Get_().(Event_Start).Port
}

func (_this Event) Dtor_hasPort() bool {
	return _this.Get_().(Event_Start).HasPort
}

func (_this Event) Dtor_hasUserinfo() bool {
	return _this.Get_().(Event_Start).HasUserinfo
}

func (_this Event) Dtor_headers() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Event_Start:
		return data.Headers
	default:
		return data.(Event_ResponseHead).Headers
	}
}

func (_this Event) Dtor_hasBody() bool {
	return _this.Get_().(Event_Start).HasBody
}

func (_this Event) Dtor_generation() uint64 {
	return _this.Get_().(Event_SessionBegun).Generation
}

func (_this Event) Dtor_data() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Event_RandomResult:
		return data.Data
	default:
		return data.(Event_Chunk).Data
	}
}

func (_this Event) Dtor_point() _dafny.Sequence {
	return _this.Get_().(Event_X25519Result).Point
}

func (_this Event) Dtor_mac() _dafny.Sequence {
	return _this.Get_().(Event_HmacResult).Mac
}

func (_this Event) Dtor_ciphertext() _dafny.Sequence {
	return _this.Get_().(Event_AeadSealResult).Ciphertext
}

func (_this Event) Dtor_ok() bool {
	return _this.Get_().(Event_AeadOpenResult).Ok
}

func (_this Event) Dtor_plaintext() _dafny.Sequence {
	return _this.Get_().(Event_AeadOpenResult).Plaintext
}

func (_this Event) Dtor_status() _dafny.Int {
	return _this.Get_().(Event_ResponseHead).Status
}

func (_this Event) Dtor_redirected() bool {
	return _this.Get_().(Event_ResponseHead).Redirected
}

func (_this Event) Dtor_stream() Stream {
	switch data := _this.Get_().(type) {
	case Event_Chunk:
		return data.Stream
	default:
		return data.(Event_StreamFailed).Stream
	}
}

func (_this Event) Dtor_eof() bool {
	return _this.Get_().(Event_Chunk).Eof
}

func (_this Event) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Event_Start:
		{
			return "EHBPEvents.Event.Start" + "(" + data.Verb.VerbatimString(true) + ", " + data.Url.VerbatimString(true) + ", " + data.Scheme.VerbatimString(true) + ", " + data.Host.VerbatimString(true) + ", " + _dafny.String(data.Port) + ", " + _dafny.String(data.HasPort) + ", " + _dafny.String(data.HasUserinfo) + ", " + _dafny.String(data.Headers) + ", " + _dafny.String(data.HasBody) + ")"
		}
	case Event_DiscoverStart:
		{
			return "EHBPEvents.Event.DiscoverStart"
		}
	case Event_SessionBegun:
		{
			return "EHBPEvents.Event.SessionBegun" + "(" + _dafny.String(data.Generation) + ")"
		}
	case Event_RandomResult:
		{
			_ = data
			return "EHBPEvents.Event.RandomResult(<redacted>)"
		}
	case Event_X25519Result:
		{
			_ = data
			return "EHBPEvents.Event.X25519Result(<redacted>)"
		}
	case Event_HmacResult:
		{
			_ = data
			return "EHBPEvents.Event.HmacResult(<redacted>)"
		}
	case Event_AeadSealResult:
		{
			return "EHBPEvents.Event.AeadSealResult" + "(" + _dafny.String(data.Ciphertext) + ")"
		}
	case Event_AeadOpenResult:
		{
			return "EHBPEvents.Event.AeadOpenResult" + "(" + _dafny.String(data.Ok) + ", " + _dafny.String(data.Plaintext) + ")"
		}
	case Event_ResponseHead:
		{
			return "EHBPEvents.Event.ResponseHead" + "(" + _dafny.String(data.Status) + ", " + _dafny.String(data.Headers) + ", " + _dafny.String(data.Redirected) + ")"
		}
	case Event_Chunk:
		{
			return "EHBPEvents.Event.Chunk" + "(" + _dafny.String(data.Stream) + ", " + _dafny.String(data.Data) + ", " + _dafny.String(data.Eof) + ")"
		}
	case Event_StreamFailed:
		{
			return "EHBPEvents.Event.StreamFailed" + "(" + _dafny.String(data.Stream) + ")"
		}
	case Event_CallerRead:
		{
			return "EHBPEvents.Event.CallerRead"
		}
	case Event_CallerClose:
		{
			return "EHBPEvents.Event.CallerClose"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Event) Equals(other Event) bool {
	switch data1 := _this.Get_().(type) {
	case Event_Start:
		{
			data2, ok := other.Get_().(Event_Start)
			return ok && data1.Verb.Equals(data2.Verb) && data1.Url.Equals(data2.Url) && data1.Scheme.Equals(data2.Scheme) && data1.Host.Equals(data2.Host) && data1.Port.Cmp(data2.Port) == 0 && data1.HasPort == data2.HasPort && data1.HasUserinfo == data2.HasUserinfo && data1.Headers.Equals(data2.Headers) && data1.HasBody == data2.HasBody
		}
	case Event_DiscoverStart:
		{
			_, ok := other.Get_().(Event_DiscoverStart)
			return ok
		}
	case Event_SessionBegun:
		{
			data2, ok := other.Get_().(Event_SessionBegun)
			return ok && data1.Generation == data2.Generation
		}
	case Event_RandomResult:
		{
			data2, ok := other.Get_().(Event_RandomResult)
			return ok && data1.Data.Equals(data2.Data)
		}
	case Event_X25519Result:
		{
			data2, ok := other.Get_().(Event_X25519Result)
			return ok && data1.Point.Equals(data2.Point)
		}
	case Event_HmacResult:
		{
			data2, ok := other.Get_().(Event_HmacResult)
			return ok && data1.Mac.Equals(data2.Mac)
		}
	case Event_AeadSealResult:
		{
			data2, ok := other.Get_().(Event_AeadSealResult)
			return ok && data1.Ciphertext.Equals(data2.Ciphertext)
		}
	case Event_AeadOpenResult:
		{
			data2, ok := other.Get_().(Event_AeadOpenResult)
			return ok && data1.Ok == data2.Ok && data1.Plaintext.Equals(data2.Plaintext)
		}
	case Event_ResponseHead:
		{
			data2, ok := other.Get_().(Event_ResponseHead)
			return ok && data1.Status.Cmp(data2.Status) == 0 && data1.Headers.Equals(data2.Headers) && data1.Redirected == data2.Redirected
		}
	case Event_Chunk:
		{
			data2, ok := other.Get_().(Event_Chunk)
			return ok && data1.Stream.Equals(data2.Stream) && data1.Data.Equals(data2.Data) && data1.Eof == data2.Eof
		}
	case Event_StreamFailed:
		{
			data2, ok := other.Get_().(Event_StreamFailed)
			return ok && data1.Stream.Equals(data2.Stream)
		}
	case Event_CallerRead:
		{
			_, ok := other.Get_().(Event_CallerRead)
			return ok
		}
	case Event_CallerClose:
		{
			_, ok := other.Get_().(Event_CallerClose)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Event) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Event)
	return ok && _this.Equals(typed)
}

func Type_Event_() _dafny.TypeDescriptor {
	return type_Event_{}
}

type type_Event_ struct {
}

func (_this type_Event_) Default() interface{} {
	return Companion_Event_.Default()
}

func (_this type_Event_) String() string {
	return "EHBPEvents.Event"
}
func (_this Event) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Event{}

// End of datatype Event

// Definition of datatype Action
type Action struct {
	Data_Action_
}

func (_this Action) Get_() Data_Action_ {
	return _this.Data_Action_
}

type Data_Action_ interface {
	isAction()
}

type CompanionStruct_Action_ struct {
}

var Companion_Action_ = CompanionStruct_Action_{}

type Action_BeginSession struct {
}

func (Action_BeginSession) isAction() {}

func (CompanionStruct_Action_) Create_BeginSession_() Action {
	return Action{Action_BeginSession{}}
}

func (_this Action) Is_BeginSession() bool {
	_, ok := _this.Get_().(Action_BeginSession)
	return ok
}

type Action_PublishToken struct {
	Generation     uint64
	ExportedSecret _dafny.Sequence
	RequestEnc     _dafny.Sequence
}

func (Action_PublishToken) isAction() {}

func (CompanionStruct_Action_) Create_PublishToken_(Generation uint64, ExportedSecret _dafny.Sequence, RequestEnc _dafny.Sequence) Action {
	return Action{Action_PublishToken{Generation, ExportedSecret, RequestEnc}}
}

func (_this Action) Is_PublishToken() bool {
	_, ok := _this.Get_().(Action_PublishToken)
	return ok
}

type Action_ClearToken struct {
	Generation uint64
}

func (Action_ClearToken) isAction() {}

func (CompanionStruct_Action_) Create_ClearToken_(Generation uint64) Action {
	return Action{Action_ClearToken{Generation}}
}

func (_this Action) Is_ClearToken() bool {
	_, ok := _this.Get_().(Action_ClearToken)
	return ok
}

type Action_RandomBytes struct {
	Length _dafny.Int
}

func (Action_RandomBytes) isAction() {}

func (CompanionStruct_Action_) Create_RandomBytes_(Length _dafny.Int) Action {
	return Action{Action_RandomBytes{Length}}
}

func (_this Action) Is_RandomBytes() bool {
	_, ok := _this.Get_().(Action_RandomBytes)
	return ok
}

type Action_X25519 struct {
	Scalar _dafny.Sequence
	Point  _dafny.Sequence
}

func (Action_X25519) isAction() {}

func (CompanionStruct_Action_) Create_X25519_(Scalar _dafny.Sequence, Point _dafny.Sequence) Action {
	return Action{Action_X25519{Scalar, Point}}
}

func (_this Action) Is_X25519() bool {
	_, ok := _this.Get_().(Action_X25519)
	return ok
}

type Action_HmacSha256 struct {
	Key  _dafny.Sequence
	Data _dafny.Sequence
}

func (Action_HmacSha256) isAction() {}

func (CompanionStruct_Action_) Create_HmacSha256_(Key _dafny.Sequence, Data _dafny.Sequence) Action {
	return Action{Action_HmacSha256{Key, Data}}
}

func (_this Action) Is_HmacSha256() bool {
	_, ok := _this.Get_().(Action_HmacSha256)
	return ok
}

type Action_AeadSeal struct {
	Key       _dafny.Sequence
	Nonce     _dafny.Sequence
	Plaintext _dafny.Sequence
}

func (Action_AeadSeal) isAction() {}

func (CompanionStruct_Action_) Create_AeadSeal_(Key _dafny.Sequence, Nonce _dafny.Sequence, Plaintext _dafny.Sequence) Action {
	return Action{Action_AeadSeal{Key, Nonce, Plaintext}}
}

func (_this Action) Is_AeadSeal() bool {
	_, ok := _this.Get_().(Action_AeadSeal)
	return ok
}

type Action_AeadOpen struct {
	Key        _dafny.Sequence
	Nonce      _dafny.Sequence
	Ciphertext _dafny.Sequence
}

func (Action_AeadOpen) isAction() {}

func (CompanionStruct_Action_) Create_AeadOpen_(Key _dafny.Sequence, Nonce _dafny.Sequence, Ciphertext _dafny.Sequence) Action {
	return Action{Action_AeadOpen{Key, Nonce, Ciphertext}}
}

func (_this Action) Is_AeadOpen() bool {
	_, ok := _this.Get_().(Action_AeadOpen)
	return ok
}

type Action_Send struct {
	Verb    _dafny.Sequence
	Url     _dafny.Sequence
	Headers _dafny.Sequence
	HasBody bool
}

func (Action_Send) isAction() {}

func (CompanionStruct_Action_) Create_Send_(Verb _dafny.Sequence, Url _dafny.Sequence, Headers _dafny.Sequence, HasBody bool) Action {
	return Action{Action_Send{Verb, Url, Headers, HasBody}}
}

func (_this Action) Is_Send() bool {
	_, ok := _this.Get_().(Action_Send)
	return ok
}

type Action_Write struct {
	Data _dafny.Sequence
	End  BodyEnd
}

func (Action_Write) isAction() {}

func (CompanionStruct_Action_) Create_Write_(Data _dafny.Sequence, End BodyEnd) Action {
	return Action{Action_Write{Data, End}}
}

func (_this Action) Is_Write() bool {
	_, ok := _this.Get_().(Action_Write)
	return ok
}

type Action_Read struct {
	Stream Stream
}

func (Action_Read) isAction() {}

func (CompanionStruct_Action_) Create_Read_(Stream Stream) Action {
	return Action{Action_Read{Stream}}
}

func (_this Action) Is_Read() bool {
	_, ok := _this.Get_().(Action_Read)
	return ok
}

type Action_Close struct {
	Stream Stream
}

func (Action_Close) isAction() {}

func (CompanionStruct_Action_) Create_Close_(Stream Stream) Action {
	return Action{Action_Close{Stream}}
}

func (_this Action) Is_Close() bool {
	_, ok := _this.Get_().(Action_Close)
	return ok
}

type Action_EmitPlaintext struct {
	Data _dafny.Sequence
}

func (Action_EmitPlaintext) isAction() {}

func (CompanionStruct_Action_) Create_EmitPlaintext_(Data _dafny.Sequence) Action {
	return Action{Action_EmitPlaintext{Data}}
}

func (_this Action) Is_EmitPlaintext() bool {
	_, ok := _this.Get_().(Action_EmitPlaintext)
	return ok
}

type Action_Passthrough struct {
	Status  _dafny.Int
	Headers _dafny.Sequence
	Prefix  _dafny.Sequence
}

func (Action_Passthrough) isAction() {}

func (CompanionStruct_Action_) Create_Passthrough_(Status _dafny.Int, Headers _dafny.Sequence, Prefix _dafny.Sequence) Action {
	return Action{Action_Passthrough{Status, Headers, Prefix}}
}

func (_this Action) Is_Passthrough() bool {
	_, ok := _this.Get_().(Action_Passthrough)
	return ok
}

type Action_Done struct {
	Status  _dafny.Int
	Headers _dafny.Sequence
}

func (Action_Done) isAction() {}

func (CompanionStruct_Action_) Create_Done_(Status _dafny.Int, Headers _dafny.Sequence) Action {
	return Action{Action_Done{Status, Headers}}
}

func (_this Action) Is_Done() bool {
	_, ok := _this.Get_().(Action_Done)
	return ok
}

type Action_Finished struct {
}

func (Action_Finished) isAction() {}

func (CompanionStruct_Action_) Create_Finished_() Action {
	return Action{Action_Finished{}}
}

func (_this Action) Is_Finished() bool {
	_, ok := _this.Get_().(Action_Finished)
	return ok
}

type Action_Discovered struct {
	PublicKey _dafny.Sequence
}

func (Action_Discovered) isAction() {}

func (CompanionStruct_Action_) Create_Discovered_(PublicKey _dafny.Sequence) Action {
	return Action{Action_Discovered{PublicKey}}
}

func (_this Action) Is_Discovered() bool {
	_, ok := _this.Get_().(Action_Discovered)
	return ok
}

type Action_Fail struct {
	Code    m_EHBP.Code
	Message _dafny.Sequence
}

func (Action_Fail) isAction() {}

func (CompanionStruct_Action_) Create_Fail_(Code m_EHBP.Code, Message _dafny.Sequence) Action {
	return Action{Action_Fail{Code, Message}}
}

func (_this Action) Is_Fail() bool {
	_, ok := _this.Get_().(Action_Fail)
	return ok
}

func (CompanionStruct_Action_) Default() Action {
	return Companion_Action_.Create_BeginSession_()
}

func (_this Action) Dtor_generation() uint64 {
	switch data := _this.Get_().(type) {
	case Action_PublishToken:
		return data.Generation
	default:
		return data.(Action_ClearToken).Generation
	}
}

func (_this Action) Dtor_exportedSecret() _dafny.Sequence {
	return _this.Get_().(Action_PublishToken).ExportedSecret
}

func (_this Action) Dtor_requestEnc() _dafny.Sequence {
	return _this.Get_().(Action_PublishToken).RequestEnc
}

func (_this Action) Dtor_length() _dafny.Int {
	return _this.Get_().(Action_RandomBytes).Length
}

func (_this Action) Dtor_scalar() _dafny.Sequence {
	return _this.Get_().(Action_X25519).Scalar
}

func (_this Action) Dtor_point() _dafny.Sequence {
	return _this.Get_().(Action_X25519).Point
}

func (_this Action) Dtor_key() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Action_HmacSha256:
		return data.Key
	case Action_AeadSeal:
		return data.Key
	default:
		return data.(Action_AeadOpen).Key
	}
}

func (_this Action) Dtor_data() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Action_HmacSha256:
		return data.Data
	case Action_Write:
		return data.Data
	default:
		return data.(Action_EmitPlaintext).Data
	}
}

func (_this Action) Dtor_nonce() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Action_AeadSeal:
		return data.Nonce
	default:
		return data.(Action_AeadOpen).Nonce
	}
}

func (_this Action) Dtor_plaintext() _dafny.Sequence {
	return _this.Get_().(Action_AeadSeal).Plaintext
}

func (_this Action) Dtor_ciphertext() _dafny.Sequence {
	return _this.Get_().(Action_AeadOpen).Ciphertext
}

func (_this Action) Dtor_verb() _dafny.Sequence {
	return _this.Get_().(Action_Send).Verb
}

func (_this Action) Dtor_url() _dafny.Sequence {
	return _this.Get_().(Action_Send).Url
}

func (_this Action) Dtor_headers() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Action_Send:
		return data.Headers
	case Action_Passthrough:
		return data.Headers
	default:
		return data.(Action_Done).Headers
	}
}

func (_this Action) Dtor_hasBody() bool {
	return _this.Get_().(Action_Send).HasBody
}

func (_this Action) Dtor_end() BodyEnd {
	return _this.Get_().(Action_Write).End
}

func (_this Action) Dtor_stream() Stream {
	switch data := _this.Get_().(type) {
	case Action_Read:
		return data.Stream
	default:
		return data.(Action_Close).Stream
	}
}

func (_this Action) Dtor_status() _dafny.Int {
	switch data := _this.Get_().(type) {
	case Action_Passthrough:
		return data.Status
	default:
		return data.(Action_Done).Status
	}
}

func (_this Action) Dtor_prefix() _dafny.Sequence {
	return _this.Get_().(Action_Passthrough).Prefix
}

func (_this Action) Dtor_publicKey() _dafny.Sequence {
	return _this.Get_().(Action_Discovered).PublicKey
}

func (_this Action) Dtor_code() m_EHBP.Code {
	return _this.Get_().(Action_Fail).Code
}

func (_this Action) Dtor_message() _dafny.Sequence {
	return _this.Get_().(Action_Fail).Message
}

func (_this Action) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Action_BeginSession:
		{
			return "EHBPEvents.Action.BeginSession"
		}
	case Action_PublishToken:
		{
			_ = data
			return "EHBPEvents.Action.PublishToken(<redacted>)"
		}
	case Action_ClearToken:
		{
			return "EHBPEvents.Action.ClearToken" + "(" + _dafny.String(data.Generation) + ")"
		}
	case Action_RandomBytes:
		{
			return "EHBPEvents.Action.RandomBytes" + "(" + _dafny.String(data.Length) + ")"
		}
	case Action_X25519:
		{
			_ = data
			return "EHBPEvents.Action.X25519(<redacted>)"
		}
	case Action_HmacSha256:
		{
			_ = data
			return "EHBPEvents.Action.HmacSha256(<redacted>)"
		}
	case Action_AeadSeal:
		{
			_ = data
			return "EHBPEvents.Action.AeadSeal(<redacted>)"
		}
	case Action_AeadOpen:
		{
			_ = data
			return "EHBPEvents.Action.AeadOpen(<redacted>)"
		}
	case Action_Send:
		{
			return "EHBPEvents.Action.Send" + "(" + data.Verb.VerbatimString(true) + ", " + data.Url.VerbatimString(true) + ", " + _dafny.String(data.Headers) + ", " + _dafny.String(data.HasBody) + ")"
		}
	case Action_Write:
		{
			return "EHBPEvents.Action.Write" + "(" + _dafny.String(data.Data) + ", " + _dafny.String(data.End) + ")"
		}
	case Action_Read:
		{
			return "EHBPEvents.Action.Read" + "(" + _dafny.String(data.Stream) + ")"
		}
	case Action_Close:
		{
			return "EHBPEvents.Action.Close" + "(" + _dafny.String(data.Stream) + ")"
		}
	case Action_EmitPlaintext:
		{
			return "EHBPEvents.Action.EmitPlaintext" + "(" + _dafny.String(data.Data) + ")"
		}
	case Action_Passthrough:
		{
			return "EHBPEvents.Action.Passthrough" + "(" + _dafny.String(data.Status) + ", " + _dafny.String(data.Headers) + ", " + _dafny.String(data.Prefix) + ")"
		}
	case Action_Done:
		{
			return "EHBPEvents.Action.Done" + "(" + _dafny.String(data.Status) + ", " + _dafny.String(data.Headers) + ")"
		}
	case Action_Finished:
		{
			return "EHBPEvents.Action.Finished"
		}
	case Action_Discovered:
		{
			return "EHBPEvents.Action.Discovered" + "(" + _dafny.String(data.PublicKey) + ")"
		}
	case Action_Fail:
		{
			return "EHBPEvents.Action.Fail" + "(" + _dafny.String(data.Code) + ", " + data.Message.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Action) Equals(other Action) bool {
	switch data1 := _this.Get_().(type) {
	case Action_BeginSession:
		{
			_, ok := other.Get_().(Action_BeginSession)
			return ok
		}
	case Action_PublishToken:
		{
			data2, ok := other.Get_().(Action_PublishToken)
			return ok && data1.Generation == data2.Generation && data1.ExportedSecret.Equals(data2.ExportedSecret) && data1.RequestEnc.Equals(data2.RequestEnc)
		}
	case Action_ClearToken:
		{
			data2, ok := other.Get_().(Action_ClearToken)
			return ok && data1.Generation == data2.Generation
		}
	case Action_RandomBytes:
		{
			data2, ok := other.Get_().(Action_RandomBytes)
			return ok && data1.Length.Cmp(data2.Length) == 0
		}
	case Action_X25519:
		{
			data2, ok := other.Get_().(Action_X25519)
			return ok && data1.Scalar.Equals(data2.Scalar) && data1.Point.Equals(data2.Point)
		}
	case Action_HmacSha256:
		{
			data2, ok := other.Get_().(Action_HmacSha256)
			return ok && data1.Key.Equals(data2.Key) && data1.Data.Equals(data2.Data)
		}
	case Action_AeadSeal:
		{
			data2, ok := other.Get_().(Action_AeadSeal)
			return ok && data1.Key.Equals(data2.Key) && data1.Nonce.Equals(data2.Nonce) && data1.Plaintext.Equals(data2.Plaintext)
		}
	case Action_AeadOpen:
		{
			data2, ok := other.Get_().(Action_AeadOpen)
			return ok && data1.Key.Equals(data2.Key) && data1.Nonce.Equals(data2.Nonce) && data1.Ciphertext.Equals(data2.Ciphertext)
		}
	case Action_Send:
		{
			data2, ok := other.Get_().(Action_Send)
			return ok && data1.Verb.Equals(data2.Verb) && data1.Url.Equals(data2.Url) && data1.Headers.Equals(data2.Headers) && data1.HasBody == data2.HasBody
		}
	case Action_Write:
		{
			data2, ok := other.Get_().(Action_Write)
			return ok && data1.Data.Equals(data2.Data) && data1.End.Equals(data2.End)
		}
	case Action_Read:
		{
			data2, ok := other.Get_().(Action_Read)
			return ok && data1.Stream.Equals(data2.Stream)
		}
	case Action_Close:
		{
			data2, ok := other.Get_().(Action_Close)
			return ok && data1.Stream.Equals(data2.Stream)
		}
	case Action_EmitPlaintext:
		{
			data2, ok := other.Get_().(Action_EmitPlaintext)
			return ok && data1.Data.Equals(data2.Data)
		}
	case Action_Passthrough:
		{
			data2, ok := other.Get_().(Action_Passthrough)
			return ok && data1.Status.Cmp(data2.Status) == 0 && data1.Headers.Equals(data2.Headers) && data1.Prefix.Equals(data2.Prefix)
		}
	case Action_Done:
		{
			data2, ok := other.Get_().(Action_Done)
			return ok && data1.Status.Cmp(data2.Status) == 0 && data1.Headers.Equals(data2.Headers)
		}
	case Action_Finished:
		{
			_, ok := other.Get_().(Action_Finished)
			return ok
		}
	case Action_Discovered:
		{
			data2, ok := other.Get_().(Action_Discovered)
			return ok && data1.PublicKey.Equals(data2.PublicKey)
		}
	case Action_Fail:
		{
			data2, ok := other.Get_().(Action_Fail)
			return ok && data1.Code.Equals(data2.Code) && data1.Message.Equals(data2.Message)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Action) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Action)
	return ok && _this.Equals(typed)
}

func Type_Action_() _dafny.TypeDescriptor {
	return type_Action_{}
}

type type_Action_ struct {
}

func (_this type_Action_) Default() interface{} {
	return Companion_Action_.Default()
}

func (_this type_Action_) String() string {
	return "EHBPEvents.Action"
}
func (_this Action) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Action{}

// End of datatype Action

// Definition of datatype Performed
type Performed struct {
	Data_Performed_
}

func (_this Performed) Get_() Data_Performed_ {
	return _this.Data_Performed_
}

type Data_Performed_ interface {
	isPerformed()
}

type CompanionStruct_Performed_ struct {
}

var Companion_Performed_ = CompanionStruct_Performed_{}

type Performed_Quiet struct {
}

func (Performed_Quiet) isPerformed() {}

func (CompanionStruct_Performed_) Create_Quiet_() Performed {
	return Performed{Performed_Quiet{}}
}

func (_this Performed) Is_Quiet() bool {
	_, ok := _this.Get_().(Performed_Quiet)
	return ok
}

type Performed_Got struct {
	E Event
}

func (Performed_Got) isPerformed() {}

func (CompanionStruct_Performed_) Create_Got_(E Event) Performed {
	return Performed{Performed_Got{E}}
}

func (_this Performed) Is_Got() bool {
	_, ok := _this.Get_().(Performed_Got)
	return ok
}

type Performed_Stop struct {
}

func (Performed_Stop) isPerformed() {}

func (CompanionStruct_Performed_) Create_Stop_() Performed {
	return Performed{Performed_Stop{}}
}

func (_this Performed) Is_Stop() bool {
	_, ok := _this.Get_().(Performed_Stop)
	return ok
}

func (CompanionStruct_Performed_) Default() Performed {
	return Companion_Performed_.Create_Quiet_()
}

func (_this Performed) Dtor_e() Event {
	return _this.Get_().(Performed_Got).E
}

func (_this Performed) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Performed_Quiet:
		{
			return "EHBPEvents.Performed.Quiet"
		}
	case Performed_Got:
		{
			return "EHBPEvents.Performed.Got" + "(" + _dafny.String(data.E) + ")"
		}
	case Performed_Stop:
		{
			return "EHBPEvents.Performed.Stop"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Performed) Equals(other Performed) bool {
	switch data1 := _this.Get_().(type) {
	case Performed_Quiet:
		{
			_, ok := other.Get_().(Performed_Quiet)
			return ok
		}
	case Performed_Got:
		{
			data2, ok := other.Get_().(Performed_Got)
			return ok && data1.E.Equals(data2.E)
		}
	case Performed_Stop:
		{
			_, ok := other.Get_().(Performed_Stop)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Performed) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Performed)
	return ok && _this.Equals(typed)
}

func Type_Performed_() _dafny.TypeDescriptor {
	return type_Performed_{}
}

type type_Performed_ struct {
}

func (_this type_Performed_) Default() interface{} {
	return Companion_Performed_.Default()
}

func (_this type_Performed_) String() string {
	return "EHBPEvents.Performed"
}
func (_this Performed) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Performed{}

// End of datatype Performed

// Definition of trait Performer
type Performer interface {
	String() string
	BeginSession() uint64
	PublishToken(generation uint64, exportedSecret _dafny.Sequence, requestEnc _dafny.Sequence)
	ClearToken(generation uint64)
	RandomBytes(length _dafny.Int) _dafny.Sequence
	X25519(scalar _dafny.Sequence, point _dafny.Sequence) _dafny.Sequence
	HmacSha256(key _dafny.Sequence, data _dafny.Sequence) _dafny.Sequence
	AeadSeal(key _dafny.Sequence, nonce _dafny.Sequence, plaintext _dafny.Sequence) _dafny.Sequence
	AeadOpen(key _dafny.Sequence, nonce _dafny.Sequence, ciphertext _dafny.Sequence) (bool, _dafny.Sequence)
	Send(verb _dafny.Sequence, url _dafny.Sequence, headers _dafny.Sequence, hasBody bool) (bool, _dafny.Int, _dafny.Sequence, bool)
	Write(data _dafny.Sequence, end BodyEnd) bool
	Read(stream Stream) (bool, _dafny.Sequence, bool)
	Close(stream Stream)
	EmitPlaintext(data _dafny.Sequence)
}
type CompanionStruct_Performer_ struct {
	TraitID_ *_dafny.TraitID
}

var Companion_Performer_ = CompanionStruct_Performer_{
	TraitID_: &_dafny.TraitID{},
}

func (CompanionStruct_Performer_) CastTo_(x interface{}) Performer {
	var t Performer
	t, _ = x.(Performer)
	return t
}

// End of trait Performer

// Definition of datatype Job
type Job struct {
	Data_Job_
}

func (_this Job) Get_() Data_Job_ {
	return _this.Data_Job_
}

type Data_Job_ interface {
	isJob()
}

type CompanionStruct_Job_ struct {
}

var Companion_Job_ = CompanionStruct_Job_{}

type Job_JExtract struct {
	Salt _dafny.Sequence
	Ikm  _dafny.Sequence
}

func (Job_JExtract) isJob() {}

func (CompanionStruct_Job_) Create_JExtract_(Salt _dafny.Sequence, Ikm _dafny.Sequence) Job {
	return Job{Job_JExtract{Salt, Ikm}}
}

func (_this Job) Is_JExtract() bool {
	_, ok := _this.Get_().(Job_JExtract)
	return ok
}

type Job_JExpand struct {
	Prk    _dafny.Sequence
	Info   _dafny.Sequence
	Length _dafny.Int
	Acc    _dafny.Sequence
	Prev   _dafny.Sequence
	I      uint8
}

func (Job_JExpand) isJob() {}

func (CompanionStruct_Job_) Create_JExpand_(Prk _dafny.Sequence, Info _dafny.Sequence, Length _dafny.Int, Acc _dafny.Sequence, Prev _dafny.Sequence, I uint8) Job {
	return Job{Job_JExpand{Prk, Info, Length, Acc, Prev, I}}
}

func (_this Job) Is_JExpand() bool {
	_, ok := _this.Get_().(Job_JExpand)
	return ok
}

func (CompanionStruct_Job_) Default() Job {
	return Companion_Job_.Create_JExtract_(_dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this Job) Dtor_salt() _dafny.Sequence {
	return _this.Get_().(Job_JExtract).Salt
}

func (_this Job) Dtor_ikm() _dafny.Sequence {
	return _this.Get_().(Job_JExtract).Ikm
}

func (_this Job) Dtor_prk() _dafny.Sequence {
	return _this.Get_().(Job_JExpand).Prk
}

func (_this Job) Dtor_info() _dafny.Sequence {
	return _this.Get_().(Job_JExpand).Info
}

func (_this Job) Dtor_length() _dafny.Int {
	return _this.Get_().(Job_JExpand).Length
}

func (_this Job) Dtor_acc() _dafny.Sequence {
	return _this.Get_().(Job_JExpand).Acc
}

func (_this Job) Dtor_prev() _dafny.Sequence {
	return _this.Get_().(Job_JExpand).Prev
}

func (_this Job) Dtor_i() uint8 {
	return _this.Get_().(Job_JExpand).I
}

func (_this Job) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Job_JExtract:
		{
			_ = data
			return "EHBPEvents.Job.JExtract(<redacted>)"
		}
	case Job_JExpand:
		{
			_ = data
			return "EHBPEvents.Job.JExpand(<redacted>)"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Job) Equals(other Job) bool {
	switch data1 := _this.Get_().(type) {
	case Job_JExtract:
		{
			data2, ok := other.Get_().(Job_JExtract)
			return ok && data1.Salt.Equals(data2.Salt) && data1.Ikm.Equals(data2.Ikm)
		}
	case Job_JExpand:
		{
			data2, ok := other.Get_().(Job_JExpand)
			return ok && data1.Prk.Equals(data2.Prk) && data1.Info.Equals(data2.Info) && data1.Length.Cmp(data2.Length) == 0 && data1.Acc.Equals(data2.Acc) && data1.Prev.Equals(data2.Prev) && data1.I == data2.I
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Job) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Job)
	return ok && _this.Equals(typed)
}

func Type_Job_() _dafny.TypeDescriptor {
	return type_Job_{}
}

type type_Job_ struct {
}

func (_this type_Job_) Default() interface{} {
	return Companion_Job_.Default()
}

func (_this type_Job_) String() string {
	return "EHBPEvents.Job"
}
func (_this Job) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Job{}

// End of datatype Job

// Definition of datatype JobOut
type JobOut struct {
	Data_JobOut_
}

func (_this JobOut) Get_() Data_JobOut_ {
	return _this.Data_JobOut_
}

type Data_JobOut_ interface {
	isJobOut()
}

type CompanionStruct_JobOut_ struct {
}

var Companion_JobOut_ = CompanionStruct_JobOut_{}

type JobOut_Pending struct {
	Job    Job
	Action Action
}

func (JobOut_Pending) isJobOut() {}

func (CompanionStruct_JobOut_) Create_Pending_(Job Job, Action Action) JobOut {
	return JobOut{JobOut_Pending{Job, Action}}
}

func (_this JobOut) Is_Pending() bool {
	_, ok := _this.Get_().(JobOut_Pending)
	return ok
}

type JobOut_Output struct {
	Data _dafny.Sequence
}

func (JobOut_Output) isJobOut() {}

func (CompanionStruct_JobOut_) Create_Output_(Data _dafny.Sequence) JobOut {
	return JobOut{JobOut_Output{Data}}
}

func (_this JobOut) Is_Output() bool {
	_, ok := _this.Get_().(JobOut_Output)
	return ok
}

type JobOut_JobFailed struct {
	Code    m_EHBP.Code
	Message _dafny.Sequence
}

func (JobOut_JobFailed) isJobOut() {}

func (CompanionStruct_JobOut_) Create_JobFailed_(Code m_EHBP.Code, Message _dafny.Sequence) JobOut {
	return JobOut{JobOut_JobFailed{Code, Message}}
}

func (_this JobOut) Is_JobFailed() bool {
	_, ok := _this.Get_().(JobOut_JobFailed)
	return ok
}

func (CompanionStruct_JobOut_) Default() JobOut {
	return Companion_JobOut_.Create_Pending_(Companion_Job_.Default(), Companion_Action_.Default())
}

func (_this JobOut) Dtor_job() Job {
	return _this.Get_().(JobOut_Pending).Job
}

func (_this JobOut) Dtor_action() Action {
	return _this.Get_().(JobOut_Pending).Action
}

func (_this JobOut) Dtor_data() _dafny.Sequence {
	return _this.Get_().(JobOut_Output).Data
}

func (_this JobOut) Dtor_code() m_EHBP.Code {
	return _this.Get_().(JobOut_JobFailed).Code
}

func (_this JobOut) Dtor_message() _dafny.Sequence {
	return _this.Get_().(JobOut_JobFailed).Message
}

func (_this JobOut) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case JobOut_Pending:
		{
			return "EHBPEvents.JobOut.Pending" + "(" + _dafny.String(data.Job) + ", " + _dafny.String(data.Action) + ")"
		}
	case JobOut_Output:
		{
			_ = data
			return "EHBPEvents.JobOut.Output(<redacted>)"
		}
	case JobOut_JobFailed:
		{
			return "EHBPEvents.JobOut.JobFailed" + "(" + _dafny.String(data.Code) + ", " + data.Message.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this JobOut) Equals(other JobOut) bool {
	switch data1 := _this.Get_().(type) {
	case JobOut_Pending:
		{
			data2, ok := other.Get_().(JobOut_Pending)
			return ok && data1.Job.Equals(data2.Job) && data1.Action.Equals(data2.Action)
		}
	case JobOut_Output:
		{
			data2, ok := other.Get_().(JobOut_Output)
			return ok && data1.Data.Equals(data2.Data)
		}
	case JobOut_JobFailed:
		{
			data2, ok := other.Get_().(JobOut_JobFailed)
			return ok && data1.Code.Equals(data2.Code) && data1.Message.Equals(data2.Message)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this JobOut) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(JobOut)
	return ok && _this.Equals(typed)
}

func Type_JobOut_() _dafny.TypeDescriptor {
	return type_JobOut_{}
}

type type_JobOut_ struct {
}

func (_this type_JobOut_) Default() interface{} {
	return Companion_JobOut_.Default()
}

func (_this type_JobOut_) String() string {
	return "EHBPEvents.JobOut"
}
func (_this JobOut) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = JobOut{}

// End of datatype JobOut

// Definition of class Key
type Key struct {
}

func New_Key_() *Key {
	_this := Key{}

	return &_this
}

type CompanionStruct_Key_ struct {
}

var Companion_Key_ = CompanionStruct_Key_{}

func (*Key) String() string {
	return "EHBPEvents.Key"
}
func (_this *CompanionStruct_Key_) Witness() _dafny.Sequence {
	return _dafny.SeqCreate(32, func(coer15 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg15 _dafny.Int) interface{} {
			return coer15(arg15)
		}
	}(func(_0_i _dafny.Int) uint8 {
		return uint8(0)
	}))
}

// End of class Key

func Type_Key_() _dafny.TypeDescriptor {
	return type_Key_{}
}

type type_Key_ struct {
}

func (_this type_Key_) Default() interface{} {
	return Companion_Key_.Witness()
}

func (_this type_Key_) String() string {
	return "EHBPEvents.Key"
}
func (_this *CompanionStruct_Key_) Is_(__source _dafny.Sequence) bool {
	var _1_b _dafny.Sequence = (__source)
	_ = _1_b
	return (_dafny.IntOfUint32((_1_b).Cardinality())).Cmp(m_EHBP.Companion_Default___.KeyLength()) == 0
}

// Definition of class NonceBase
type NonceBase struct {
}

func New_NonceBase_() *NonceBase {
	_this := NonceBase{}

	return &_this
}

type CompanionStruct_NonceBase_ struct {
}

var Companion_NonceBase_ = CompanionStruct_NonceBase_{}

func (*NonceBase) String() string {
	return "EHBPEvents.NonceBase"
}
func (_this *CompanionStruct_NonceBase_) Witness() _dafny.Sequence {
	return _dafny.SeqCreate(12, func(coer16 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg16 _dafny.Int) interface{} {
			return coer16(arg16)
		}
	}(func(_2_i _dafny.Int) uint8 {
		return uint8(0)
	}))
}

// End of class NonceBase

func Type_NonceBase_() _dafny.TypeDescriptor {
	return type_NonceBase_{}
}

type type_NonceBase_ struct {
}

func (_this type_NonceBase_) Default() interface{} {
	return Companion_NonceBase_.Witness()
}

func (_this type_NonceBase_) String() string {
	return "EHBPEvents.NonceBase"
}
func (_this *CompanionStruct_NonceBase_) Is_(__source _dafny.Sequence) bool {
	var _3_b _dafny.Sequence = (__source)
	_ = _3_b
	return (_dafny.IntOfUint32((_3_b).Cardinality())).Cmp(m_EHBP.Companion_Default___.NonceLength()) == 0
}

// Definition of datatype Ctx
type Ctx struct {
	Data_Ctx_
}

func (_this Ctx) Get_() Data_Ctx_ {
	return _this.Data_Ctx_
}

type Data_Ctx_ interface {
	isCtx()
}

type CompanionStruct_Ctx_ struct {
}

var Companion_Ctx_ = CompanionStruct_Ctx_{}

type Ctx_Ctx struct {
	Key            _dafny.Sequence
	BaseNonce      _dafny.Sequence
	ExporterSecret _dafny.Sequence
	SeqNo          uint64
}

func (Ctx_Ctx) isCtx() {}

func (CompanionStruct_Ctx_) Create_Ctx_(Key _dafny.Sequence, BaseNonce _dafny.Sequence, ExporterSecret _dafny.Sequence, SeqNo uint64) Ctx {
	return Ctx{Ctx_Ctx{Key, BaseNonce, ExporterSecret, SeqNo}}
}

func (_this Ctx) Is_Ctx() bool {
	_, ok := _this.Get_().(Ctx_Ctx)
	return ok
}

func (CompanionStruct_Ctx_) Default() Ctx {
	return Companion_Ctx_.Create_Ctx_(Companion_Key_.Witness(), Companion_NonceBase_.Witness(), _dafny.EmptySeq, uint64(0))
}

func (_this Ctx) Dtor_key() _dafny.Sequence {
	return _this.Get_().(Ctx_Ctx).Key
}

func (_this Ctx) Dtor_baseNonce() _dafny.Sequence {
	return _this.Get_().(Ctx_Ctx).BaseNonce
}

func (_this Ctx) Dtor_exporterSecret() _dafny.Sequence {
	return _this.Get_().(Ctx_Ctx).ExporterSecret
}

func (_this Ctx) Dtor_seqNo() uint64 {
	return _this.Get_().(Ctx_Ctx).SeqNo
}

func (_this Ctx) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Ctx_Ctx:
		{
			_ = data
			return "EHBPEvents.Ctx.Ctx(<redacted>)"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Ctx) Equals(other Ctx) bool {
	switch data1 := _this.Get_().(type) {
	case Ctx_Ctx:
		{
			data2, ok := other.Get_().(Ctx_Ctx)
			return ok && data1.Key.Equals(data2.Key) && data1.BaseNonce.Equals(data2.BaseNonce) && data1.ExporterSecret.Equals(data2.ExporterSecret) && data1.SeqNo == data2.SeqNo
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Ctx) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Ctx)
	return ok && _this.Equals(typed)
}

func Type_Ctx_() _dafny.TypeDescriptor {
	return type_Ctx_{}
}

type type_Ctx_ struct {
}

func (_this type_Ctx_) Default() interface{} {
	return Companion_Ctx_.Default()
}

func (_this type_Ctx_) String() string {
	return "EHBPEvents.Ctx"
}
func (_this Ctx) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Ctx{}

// End of datatype Ctx

// Definition of datatype Hpke
type Hpke struct {
	Data_Hpke_
}

func (_this Hpke) Get_() Data_Hpke_ {
	return _this.Data_Hpke_
}

type Data_Hpke_ interface {
	isHpke()
}

type CompanionStruct_Hpke_ struct {
}

var Companion_Hpke_ = CompanionStruct_Hpke_{}

type Hpke_HRandom struct {
	PkR  _dafny.Sequence
	Info _dafny.Sequence
}

func (Hpke_HRandom) isHpke() {}

func (CompanionStruct_Hpke_) Create_HRandom_(PkR _dafny.Sequence, Info _dafny.Sequence) Hpke {
	return Hpke{Hpke_HRandom{PkR, Info}}
}

func (_this Hpke) Is_HRandom() bool {
	_, ok := _this.Get_().(Hpke_HRandom)
	return ok
}

type Hpke_HEnc struct {
	SkE  _dafny.Sequence
	PkR  _dafny.Sequence
	Info _dafny.Sequence
}

func (Hpke_HEnc) isHpke() {}

func (CompanionStruct_Hpke_) Create_HEnc_(SkE _dafny.Sequence, PkR _dafny.Sequence, Info _dafny.Sequence) Hpke {
	return Hpke{Hpke_HEnc{SkE, PkR, Info}}
}

func (_this Hpke) Is_HEnc() bool {
	_, ok := _this.Get_().(Hpke_HEnc)
	return ok
}

type Hpke_HDh struct {
	Enc  _dafny.Sequence
	PkR  _dafny.Sequence
	Info _dafny.Sequence
}

func (Hpke_HDh) isHpke() {}

func (CompanionStruct_Hpke_) Create_HDh_(Enc _dafny.Sequence, PkR _dafny.Sequence, Info _dafny.Sequence) Hpke {
	return Hpke{Hpke_HDh{Enc, PkR, Info}}
}

func (_this Hpke) Is_HDh() bool {
	_, ok := _this.Get_().(Hpke_HDh)
	return ok
}

type Hpke_HSchedule struct {
	Stage     _dafny.Int
	Job       Job
	Enc       _dafny.Sequence
	PkR       _dafny.Sequence
	Info      _dafny.Sequence
	Shared    _dafny.Sequence
	PskIdHash _dafny.Sequence
	InfoHash  _dafny.Sequence
	Secret    _dafny.Sequence
	Key       _dafny.Sequence
	BaseNonce _dafny.Sequence
}

func (Hpke_HSchedule) isHpke() {}

func (CompanionStruct_Hpke_) Create_HSchedule_(Stage _dafny.Int, Job Job, Enc _dafny.Sequence, PkR _dafny.Sequence, Info _dafny.Sequence, Shared _dafny.Sequence, PskIdHash _dafny.Sequence, InfoHash _dafny.Sequence, Secret _dafny.Sequence, Key _dafny.Sequence, BaseNonce _dafny.Sequence) Hpke {
	return Hpke{Hpke_HSchedule{Stage, Job, Enc, PkR, Info, Shared, PskIdHash, InfoHash, Secret, Key, BaseNonce}}
}

func (_this Hpke) Is_HSchedule() bool {
	_, ok := _this.Get_().(Hpke_HSchedule)
	return ok
}

func (CompanionStruct_Hpke_) Default() Hpke {
	return Companion_Hpke_.Create_HRandom_(_dafny.EmptySeq, _dafny.EmptySeq)
}

func (_this Hpke) Dtor_pkR() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Hpke_HRandom:
		return data.PkR
	case Hpke_HEnc:
		return data.PkR
	case Hpke_HDh:
		return data.PkR
	default:
		return data.(Hpke_HSchedule).PkR
	}
}

func (_this Hpke) Dtor_info() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Hpke_HRandom:
		return data.Info
	case Hpke_HEnc:
		return data.Info
	case Hpke_HDh:
		return data.Info
	default:
		return data.(Hpke_HSchedule).Info
	}
}

func (_this Hpke) Dtor_skE() _dafny.Sequence {
	return _this.Get_().(Hpke_HEnc).SkE
}

func (_this Hpke) Dtor_enc() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Hpke_HDh:
		return data.Enc
	default:
		return data.(Hpke_HSchedule).Enc
	}
}

func (_this Hpke) Dtor_stage() _dafny.Int {
	return _this.Get_().(Hpke_HSchedule).Stage
}

func (_this Hpke) Dtor_job() Job {
	return _this.Get_().(Hpke_HSchedule).Job
}

func (_this Hpke) Dtor_shared() _dafny.Sequence {
	return _this.Get_().(Hpke_HSchedule).Shared
}

func (_this Hpke) Dtor_pskIdHash() _dafny.Sequence {
	return _this.Get_().(Hpke_HSchedule).PskIdHash
}

func (_this Hpke) Dtor_infoHash() _dafny.Sequence {
	return _this.Get_().(Hpke_HSchedule).InfoHash
}

func (_this Hpke) Dtor_secret() _dafny.Sequence {
	return _this.Get_().(Hpke_HSchedule).Secret
}

func (_this Hpke) Dtor_key() _dafny.Sequence {
	return _this.Get_().(Hpke_HSchedule).Key
}

func (_this Hpke) Dtor_baseNonce() _dafny.Sequence {
	return _this.Get_().(Hpke_HSchedule).BaseNonce
}

func (_this Hpke) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Hpke_HRandom:
		{
			return "EHBPEvents.Hpke.HRandom" + "(" + _dafny.String(data.PkR) + ", " + _dafny.String(data.Info) + ")"
		}
	case Hpke_HEnc:
		{
			_ = data
			return "EHBPEvents.Hpke.HEnc(<redacted>)"
		}
	case Hpke_HDh:
		{
			return "EHBPEvents.Hpke.HDh" + "(" + _dafny.String(data.Enc) + ", " + _dafny.String(data.PkR) + ", " + _dafny.String(data.Info) + ")"
		}
	case Hpke_HSchedule:
		{
			_ = data
			return "EHBPEvents.Hpke.HSchedule(<redacted>)"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Hpke) Equals(other Hpke) bool {
	switch data1 := _this.Get_().(type) {
	case Hpke_HRandom:
		{
			data2, ok := other.Get_().(Hpke_HRandom)
			return ok && data1.PkR.Equals(data2.PkR) && data1.Info.Equals(data2.Info)
		}
	case Hpke_HEnc:
		{
			data2, ok := other.Get_().(Hpke_HEnc)
			return ok && data1.SkE.Equals(data2.SkE) && data1.PkR.Equals(data2.PkR) && data1.Info.Equals(data2.Info)
		}
	case Hpke_HDh:
		{
			data2, ok := other.Get_().(Hpke_HDh)
			return ok && data1.Enc.Equals(data2.Enc) && data1.PkR.Equals(data2.PkR) && data1.Info.Equals(data2.Info)
		}
	case Hpke_HSchedule:
		{
			data2, ok := other.Get_().(Hpke_HSchedule)
			return ok && data1.Stage.Cmp(data2.Stage) == 0 && data1.Job.Equals(data2.Job) && data1.Enc.Equals(data2.Enc) && data1.PkR.Equals(data2.PkR) && data1.Info.Equals(data2.Info) && data1.Shared.Equals(data2.Shared) && data1.PskIdHash.Equals(data2.PskIdHash) && data1.InfoHash.Equals(data2.InfoHash) && data1.Secret.Equals(data2.Secret) && data1.Key.Equals(data2.Key) && data1.BaseNonce.Equals(data2.BaseNonce)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Hpke) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Hpke)
	return ok && _this.Equals(typed)
}

func Type_Hpke_() _dafny.TypeDescriptor {
	return type_Hpke_{}
}

type type_Hpke_ struct {
}

func (_this type_Hpke_) Default() interface{} {
	return Companion_Hpke_.Default()
}

func (_this type_Hpke_) String() string {
	return "EHBPEvents.Hpke"
}
func (_this Hpke) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Hpke{}

// End of datatype Hpke

// Definition of datatype HpkeOut
type HpkeOut struct {
	Data_HpkeOut_
}

func (_this HpkeOut) Get_() Data_HpkeOut_ {
	return _this.Data_HpkeOut_
}

type Data_HpkeOut_ interface {
	isHpkeOut()
}

type CompanionStruct_HpkeOut_ struct {
}

var Companion_HpkeOut_ = CompanionStruct_HpkeOut_{}

type HpkeOut_HContinue struct {
	H      Hpke
	Action Action
}

func (HpkeOut_HContinue) isHpkeOut() {}

func (CompanionStruct_HpkeOut_) Create_HContinue_(H Hpke, Action Action) HpkeOut {
	return HpkeOut{HpkeOut_HContinue{H, Action}}
}

func (_this HpkeOut) Is_HContinue() bool {
	_, ok := _this.Get_().(HpkeOut_HContinue)
	return ok
}

type HpkeOut_HReady struct {
	Ctx Ctx
	Enc _dafny.Sequence
}

func (HpkeOut_HReady) isHpkeOut() {}

func (CompanionStruct_HpkeOut_) Create_HReady_(Ctx Ctx, Enc _dafny.Sequence) HpkeOut {
	return HpkeOut{HpkeOut_HReady{Ctx, Enc}}
}

func (_this HpkeOut) Is_HReady() bool {
	_, ok := _this.Get_().(HpkeOut_HReady)
	return ok
}

type HpkeOut_HFailed struct {
	Code    m_EHBP.Code
	Message _dafny.Sequence
}

func (HpkeOut_HFailed) isHpkeOut() {}

func (CompanionStruct_HpkeOut_) Create_HFailed_(Code m_EHBP.Code, Message _dafny.Sequence) HpkeOut {
	return HpkeOut{HpkeOut_HFailed{Code, Message}}
}

func (_this HpkeOut) Is_HFailed() bool {
	_, ok := _this.Get_().(HpkeOut_HFailed)
	return ok
}

func (CompanionStruct_HpkeOut_) Default() HpkeOut {
	return Companion_HpkeOut_.Create_HContinue_(Companion_Hpke_.Default(), Companion_Action_.Default())
}

func (_this HpkeOut) Dtor_h() Hpke {
	return _this.Get_().(HpkeOut_HContinue).H
}

func (_this HpkeOut) Dtor_action() Action {
	return _this.Get_().(HpkeOut_HContinue).Action
}

func (_this HpkeOut) Dtor_ctx() Ctx {
	return _this.Get_().(HpkeOut_HReady).Ctx
}

func (_this HpkeOut) Dtor_enc() _dafny.Sequence {
	return _this.Get_().(HpkeOut_HReady).Enc
}

func (_this HpkeOut) Dtor_code() m_EHBP.Code {
	return _this.Get_().(HpkeOut_HFailed).Code
}

func (_this HpkeOut) Dtor_message() _dafny.Sequence {
	return _this.Get_().(HpkeOut_HFailed).Message
}

func (_this HpkeOut) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case HpkeOut_HContinue:
		{
			return "EHBPEvents.HpkeOut.HContinue" + "(" + _dafny.String(data.H) + ", " + _dafny.String(data.Action) + ")"
		}
	case HpkeOut_HReady:
		{
			return "EHBPEvents.HpkeOut.HReady" + "(" + _dafny.String(data.Ctx) + ", " + _dafny.String(data.Enc) + ")"
		}
	case HpkeOut_HFailed:
		{
			return "EHBPEvents.HpkeOut.HFailed" + "(" + _dafny.String(data.Code) + ", " + data.Message.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this HpkeOut) Equals(other HpkeOut) bool {
	switch data1 := _this.Get_().(type) {
	case HpkeOut_HContinue:
		{
			data2, ok := other.Get_().(HpkeOut_HContinue)
			return ok && data1.H.Equals(data2.H) && data1.Action.Equals(data2.Action)
		}
	case HpkeOut_HReady:
		{
			data2, ok := other.Get_().(HpkeOut_HReady)
			return ok && data1.Ctx.Equals(data2.Ctx) && data1.Enc.Equals(data2.Enc)
		}
	case HpkeOut_HFailed:
		{
			data2, ok := other.Get_().(HpkeOut_HFailed)
			return ok && data1.Code.Equals(data2.Code) && data1.Message.Equals(data2.Message)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this HpkeOut) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(HpkeOut)
	return ok && _this.Equals(typed)
}

func Type_HpkeOut_() _dafny.TypeDescriptor {
	return type_HpkeOut_{}
}

type type_HpkeOut_ struct {
}

func (_this type_HpkeOut_) Default() interface{} {
	return Companion_HpkeOut_.Default()
}

func (_this type_HpkeOut_) String() string {
	return "EHBPEvents.HpkeOut"
}
func (_this HpkeOut) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = HpkeOut{}

// End of datatype HpkeOut

// Definition of datatype Json
type Json struct {
	Data_Json_
}

func (_this Json) Get_() Data_Json_ {
	return _this.Data_Json_
}

type Data_Json_ interface {
	isJson()
}

type CompanionStruct_Json_ struct {
}

var Companion_Json_ = CompanionStruct_Json_{}

type Json_JNull struct {
}

func (Json_JNull) isJson() {}

func (CompanionStruct_Json_) Create_JNull_() Json {
	return Json{Json_JNull{}}
}

func (_this Json) Is_JNull() bool {
	_, ok := _this.Get_().(Json_JNull)
	return ok
}

type Json_JBool struct {
	B bool
}

func (Json_JBool) isJson() {}

func (CompanionStruct_Json_) Create_JBool_(B bool) Json {
	return Json{Json_JBool{B}}
}

func (_this Json) Is_JBool() bool {
	_, ok := _this.Get_().(Json_JBool)
	return ok
}

type Json_JNumber struct {
	Raw _dafny.Sequence
}

func (Json_JNumber) isJson() {}

func (CompanionStruct_Json_) Create_JNumber_(Raw _dafny.Sequence) Json {
	return Json{Json_JNumber{Raw}}
}

func (_this Json) Is_JNumber() bool {
	_, ok := _this.Get_().(Json_JNumber)
	return ok
}

type Json_JString struct {
	S _dafny.Sequence
}

func (Json_JString) isJson() {}

func (CompanionStruct_Json_) Create_JString_(S _dafny.Sequence) Json {
	return Json{Json_JString{S}}
}

func (_this Json) Is_JString() bool {
	_, ok := _this.Get_().(Json_JString)
	return ok
}

type Json_JArray struct {
	Items _dafny.Sequence
}

func (Json_JArray) isJson() {}

func (CompanionStruct_Json_) Create_JArray_(Items _dafny.Sequence) Json {
	return Json{Json_JArray{Items}}
}

func (_this Json) Is_JArray() bool {
	_, ok := _this.Get_().(Json_JArray)
	return ok
}

type Json_JObject struct {
	Members _dafny.Sequence
}

func (Json_JObject) isJson() {}

func (CompanionStruct_Json_) Create_JObject_(Members _dafny.Sequence) Json {
	return Json{Json_JObject{Members}}
}

func (_this Json) Is_JObject() bool {
	_, ok := _this.Get_().(Json_JObject)
	return ok
}

func (CompanionStruct_Json_) Default() Json {
	return Companion_Json_.Create_JNull_()
}

func (_this Json) Dtor_b() bool {
	return _this.Get_().(Json_JBool).B
}

func (_this Json) Dtor_raw() _dafny.Sequence {
	return _this.Get_().(Json_JNumber).Raw
}

func (_this Json) Dtor_s() _dafny.Sequence {
	return _this.Get_().(Json_JString).S
}

func (_this Json) Dtor_items() _dafny.Sequence {
	return _this.Get_().(Json_JArray).Items
}

func (_this Json) Dtor_members() _dafny.Sequence {
	return _this.Get_().(Json_JObject).Members
}

func (_this Json) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Json_JNull:
		{
			return "EHBPEvents.Json.JNull"
		}
	case Json_JBool:
		{
			return "EHBPEvents.Json.JBool" + "(" + _dafny.String(data.B) + ")"
		}
	case Json_JNumber:
		{
			return "EHBPEvents.Json.JNumber" + "(" + data.Raw.VerbatimString(true) + ")"
		}
	case Json_JString:
		{
			return "EHBPEvents.Json.JString" + "(" + data.S.VerbatimString(true) + ")"
		}
	case Json_JArray:
		{
			return "EHBPEvents.Json.JArray" + "(" + _dafny.String(data.Items) + ")"
		}
	case Json_JObject:
		{
			return "EHBPEvents.Json.JObject" + "(" + _dafny.String(data.Members) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Json) Equals(other Json) bool {
	switch data1 := _this.Get_().(type) {
	case Json_JNull:
		{
			_, ok := other.Get_().(Json_JNull)
			return ok
		}
	case Json_JBool:
		{
			data2, ok := other.Get_().(Json_JBool)
			return ok && data1.B == data2.B
		}
	case Json_JNumber:
		{
			data2, ok := other.Get_().(Json_JNumber)
			return ok && data1.Raw.Equals(data2.Raw)
		}
	case Json_JString:
		{
			data2, ok := other.Get_().(Json_JString)
			return ok && data1.S.Equals(data2.S)
		}
	case Json_JArray:
		{
			data2, ok := other.Get_().(Json_JArray)
			return ok && data1.Items.Equals(data2.Items)
		}
	case Json_JObject:
		{
			data2, ok := other.Get_().(Json_JObject)
			return ok && data1.Members.Equals(data2.Members)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Json) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Json)
	return ok && _this.Equals(typed)
}

func Type_Json_() _dafny.TypeDescriptor {
	return type_Json_{}
}

type type_Json_ struct {
}

func (_this type_Json_) Default() interface{} {
	return Companion_Json_.Default()
}

func (_this type_Json_) String() string {
	return "EHBPEvents.Json"
}
func (_this Json) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Json{}

// End of datatype Json

// Definition of datatype SessionStore
type SessionStore struct {
	Data_SessionStore_
}

func (_this SessionStore) Get_() Data_SessionStore_ {
	return _this.Data_SessionStore_
}

type Data_SessionStore_ interface {
	isSessionStore()
}

type CompanionStruct_SessionStore_ struct {
}

var Companion_SessionStore_ = CompanionStruct_SessionStore_{}

type SessionStore_SessionStore struct {
	Generation uint64
	Token      m_EHBP.Option
}

func (SessionStore_SessionStore) isSessionStore() {}

func (CompanionStruct_SessionStore_) Create_SessionStore_(Generation uint64, Token m_EHBP.Option) SessionStore {
	return SessionStore{SessionStore_SessionStore{Generation, Token}}
}

func (_this SessionStore) Is_SessionStore() bool {
	_, ok := _this.Get_().(SessionStore_SessionStore)
	return ok
}

func (CompanionStruct_SessionStore_) Default() SessionStore {
	return Companion_SessionStore_.Create_SessionStore_(uint64(0), m_EHBP.Companion_Option_.Default())
}

func (_this SessionStore) Dtor_generation() uint64 {
	return _this.Get_().(SessionStore_SessionStore).Generation
}

func (_this SessionStore) Dtor_token() m_EHBP.Option {
	return _this.Get_().(SessionStore_SessionStore).Token
}

func (_this SessionStore) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case SessionStore_SessionStore:
		{
			return "EHBPEvents.SessionStore.SessionStore" + "(" + _dafny.String(data.Generation) + ", " + _dafny.String(data.Token) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this SessionStore) Equals(other SessionStore) bool {
	switch data1 := _this.Get_().(type) {
	case SessionStore_SessionStore:
		{
			data2, ok := other.Get_().(SessionStore_SessionStore)
			return ok && data1.Generation == data2.Generation && data1.Token.Equals(data2.Token)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this SessionStore) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(SessionStore)
	return ok && _this.Equals(typed)
}

func Type_SessionStore_() _dafny.TypeDescriptor {
	return type_SessionStore_{}
}

type type_SessionStore_ struct {
}

func (_this type_SessionStore_) Default() interface{} {
	return Companion_SessionStore_.Default()
}

func (_this type_SessionStore_) String() string {
	return "EHBPEvents.SessionStore"
}
func (_this SessionStore) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = SessionStore{}

// End of datatype SessionStore

// Definition of datatype SessionAction
type SessionAction struct {
	Data_SessionAction_
}

func (_this SessionAction) Get_() Data_SessionAction_ {
	return _this.Data_SessionAction_
}

type Data_SessionAction_ interface {
	isSessionAction()
}

type CompanionStruct_SessionAction_ struct {
}

var Companion_SessionAction_ = CompanionStruct_SessionAction_{}

type SessionAction_Begin struct {
}

func (SessionAction_Begin) isSessionAction() {}

func (CompanionStruct_SessionAction_) Create_Begin_() SessionAction {
	return SessionAction{SessionAction_Begin{}}
}

func (_this SessionAction) Is_Begin() bool {
	_, ok := _this.Get_().(SessionAction_Begin)
	return ok
}

type SessionAction_Publish struct {
	Generation uint64
	Token      m_EHBP.Token
}

func (SessionAction_Publish) isSessionAction() {}

func (CompanionStruct_SessionAction_) Create_Publish_(Generation uint64, Token m_EHBP.Token) SessionAction {
	return SessionAction{SessionAction_Publish{Generation, Token}}
}

func (_this SessionAction) Is_Publish() bool {
	_, ok := _this.Get_().(SessionAction_Publish)
	return ok
}

type SessionAction_Clear struct {
	Generation uint64
}

func (SessionAction_Clear) isSessionAction() {}

func (CompanionStruct_SessionAction_) Create_Clear_(Generation uint64) SessionAction {
	return SessionAction{SessionAction_Clear{Generation}}
}

func (_this SessionAction) Is_Clear() bool {
	_, ok := _this.Get_().(SessionAction_Clear)
	return ok
}

func (CompanionStruct_SessionAction_) Default() SessionAction {
	return Companion_SessionAction_.Create_Begin_()
}

func (_this SessionAction) Dtor_generation() uint64 {
	switch data := _this.Get_().(type) {
	case SessionAction_Publish:
		return data.Generation
	default:
		return data.(SessionAction_Clear).Generation
	}
}

func (_this SessionAction) Dtor_token() m_EHBP.Token {
	return _this.Get_().(SessionAction_Publish).Token
}

func (_this SessionAction) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case SessionAction_Begin:
		{
			return "EHBPEvents.SessionAction.Begin"
		}
	case SessionAction_Publish:
		{
			return "EHBPEvents.SessionAction.Publish" + "(" + _dafny.String(data.Generation) + ", " + _dafny.String(data.Token) + ")"
		}
	case SessionAction_Clear:
		{
			return "EHBPEvents.SessionAction.Clear" + "(" + _dafny.String(data.Generation) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this SessionAction) Equals(other SessionAction) bool {
	switch data1 := _this.Get_().(type) {
	case SessionAction_Begin:
		{
			_, ok := other.Get_().(SessionAction_Begin)
			return ok
		}
	case SessionAction_Publish:
		{
			data2, ok := other.Get_().(SessionAction_Publish)
			return ok && data1.Generation == data2.Generation && data1.Token.Equals(data2.Token)
		}
	case SessionAction_Clear:
		{
			data2, ok := other.Get_().(SessionAction_Clear)
			return ok && data1.Generation == data2.Generation
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this SessionAction) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(SessionAction)
	return ok && _this.Equals(typed)
}

func Type_SessionAction_() _dafny.TypeDescriptor {
	return type_SessionAction_{}
}

type type_SessionAction_ struct {
}

func (_this type_SessionAction_) Default() interface{} {
	return Companion_SessionAction_.Default()
}

func (_this type_SessionAction_) String() string {
	return "EHBPEvents.SessionAction"
}
func (_this SessionAction) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = SessionAction{}

// End of datatype SessionAction

// Definition of datatype Dec
type Dec struct {
	Data_Dec_
}

func (_this Dec) Get_() Data_Dec_ {
	return _this.Data_Dec_
}

type Data_Dec_ interface {
	isDec()
}

type CompanionStruct_Dec_ struct {
}

var Companion_Dec_ = CompanionStruct_Dec_{}

type Dec_Dec struct {
	Pending       _dafny.Sequence
	Next          uint64
	Authenticated bool
	RequireFrame  bool
}

func (Dec_Dec) isDec() {}

func (CompanionStruct_Dec_) Create_Dec_(Pending _dafny.Sequence, Next uint64, Authenticated bool, RequireFrame bool) Dec {
	return Dec{Dec_Dec{Pending, Next, Authenticated, RequireFrame}}
}

func (_this Dec) Is_Dec() bool {
	_, ok := _this.Get_().(Dec_Dec)
	return ok
}

func (CompanionStruct_Dec_) Default() Dec {
	return Companion_Dec_.Create_Dec_(_dafny.EmptySeq, uint64(0), false, false)
}

func (_this Dec) Dtor_pending() _dafny.Sequence {
	return _this.Get_().(Dec_Dec).Pending
}

func (_this Dec) Dtor_next() uint64 {
	return _this.Get_().(Dec_Dec).Next
}

func (_this Dec) Dtor_authenticated() bool {
	return _this.Get_().(Dec_Dec).Authenticated
}

func (_this Dec) Dtor_requireFrame() bool {
	return _this.Get_().(Dec_Dec).RequireFrame
}

func (_this Dec) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Dec_Dec:
		{
			return "EHBPEvents.Dec.Dec" + "(" + _dafny.String(data.Pending) + ", " + _dafny.String(data.Next) + ", " + _dafny.String(data.Authenticated) + ", " + _dafny.String(data.RequireFrame) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Dec) Equals(other Dec) bool {
	switch data1 := _this.Get_().(type) {
	case Dec_Dec:
		{
			data2, ok := other.Get_().(Dec_Dec)
			return ok && data1.Pending.Equals(data2.Pending) && data1.Next == data2.Next && data1.Authenticated == data2.Authenticated && data1.RequireFrame == data2.RequireFrame
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Dec) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Dec)
	return ok && _this.Equals(typed)
}

func Type_Dec_() _dafny.TypeDescriptor {
	return type_Dec_{}
}

type type_Dec_ struct {
}

func (_this type_Dec_) Default() interface{} {
	return Companion_Dec_.Default()
}

func (_this type_Dec_) String() string {
	return "EHBPEvents.Dec"
}
func (_this Dec) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Dec{}

// End of datatype Dec

// Definition of class Chunk
type Chunk struct {
}

func New_Chunk_() *Chunk {
	_this := Chunk{}

	return &_this
}

type CompanionStruct_Chunk_ struct {
}

var Companion_Chunk_ = CompanionStruct_Chunk_{}

func (*Chunk) String() string {
	return "EHBPEvents.Chunk"
}
func (_this *CompanionStruct_Chunk_) Witness() _dafny.Sequence {
	return _dafny.SeqOf()
}

// End of class Chunk

func Type_Chunk_() _dafny.TypeDescriptor {
	return type_Chunk_{}
}

type type_Chunk_ struct {
}

func (_this type_Chunk_) Default() interface{} {
	return Companion_Chunk_.Witness()
}

func (_this type_Chunk_) String() string {
	return "EHBPEvents.Chunk"
}
func (_this *CompanionStruct_Chunk_) Is_(__source _dafny.Sequence) bool {
	var _4_b _dafny.Sequence = (__source)
	_ = _4_b
	return (_dafny.IntOfUint32((_4_b).Cardinality())).Cmp(_dafny.IntOfInt64(4294967296)) < 0
}

// Definition of datatype Upload
type Upload struct {
	Data_Upload_
}

func (_this Upload) Get_() Data_Upload_ {
	return _this.Data_Upload_
}

type Data_Upload_ interface {
	isUpload()
}

type CompanionStruct_Upload_ struct {
}

var Companion_Upload_ = CompanionStruct_Upload_{}

type Upload_NoUpload struct {
}

func (Upload_NoUpload) isUpload() {}

func (CompanionStruct_Upload_) Create_NoUpload_() Upload {
	return Upload{Upload_NoUpload{}}
}

func (_this Upload) Is_NoUpload() bool {
	_, ok := _this.Get_().(Upload_NoUpload)
	return ok
}

type Upload_Sealing struct {
	Plaintext _dafny.Sequence
	Offset    uint32
	Eof       bool
}

func (Upload_Sealing) isUpload() {}

func (CompanionStruct_Upload_) Create_Sealing_(Plaintext _dafny.Sequence, Offset uint32, Eof bool) Upload {
	return Upload{Upload_Sealing{Plaintext, Offset, Eof}}
}

func (_this Upload) Is_Sealing() bool {
	_, ok := _this.Get_().(Upload_Sealing)
	return ok
}

type Upload_UpReading struct {
	Empty _dafny.Int
}

func (Upload_UpReading) isUpload() {}

func (CompanionStruct_Upload_) Create_UpReading_(Empty _dafny.Int) Upload {
	return Upload{Upload_UpReading{Empty}}
}

func (_this Upload) Is_UpReading() bool {
	_, ok := _this.Get_().(Upload_UpReading)
	return ok
}

type Upload_UpDone struct {
}

func (Upload_UpDone) isUpload() {}

func (CompanionStruct_Upload_) Create_UpDone_() Upload {
	return Upload{Upload_UpDone{}}
}

func (_this Upload) Is_UpDone() bool {
	_, ok := _this.Get_().(Upload_UpDone)
	return ok
}

func (CompanionStruct_Upload_) Default() Upload {
	return Companion_Upload_.Create_NoUpload_()
}

func (_this Upload) Dtor_plaintext() _dafny.Sequence {
	return _this.Get_().(Upload_Sealing).Plaintext
}

func (_this Upload) Dtor_offset() uint32 {
	return _this.Get_().(Upload_Sealing).Offset
}

func (_this Upload) Dtor_eof() bool {
	return _this.Get_().(Upload_Sealing).Eof
}

func (_this Upload) Dtor_empty() _dafny.Int {
	return _this.Get_().(Upload_UpReading).Empty
}

func (_this Upload) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Upload_NoUpload:
		{
			return "EHBPEvents.Upload.NoUpload"
		}
	case Upload_Sealing:
		{
			return "EHBPEvents.Upload.Sealing" + "(" + _dafny.String(data.Plaintext) + ", " + _dafny.String(data.Offset) + ", " + _dafny.String(data.Eof) + ")"
		}
	case Upload_UpReading:
		{
			return "EHBPEvents.Upload.UpReading" + "(" + _dafny.String(data.Empty) + ")"
		}
	case Upload_UpDone:
		{
			return "EHBPEvents.Upload.UpDone"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Upload) Equals(other Upload) bool {
	switch data1 := _this.Get_().(type) {
	case Upload_NoUpload:
		{
			_, ok := other.Get_().(Upload_NoUpload)
			return ok
		}
	case Upload_Sealing:
		{
			data2, ok := other.Get_().(Upload_Sealing)
			return ok && data1.Plaintext.Equals(data2.Plaintext) && data1.Offset == data2.Offset && data1.Eof == data2.Eof
		}
	case Upload_UpReading:
		{
			data2, ok := other.Get_().(Upload_UpReading)
			return ok && data1.Empty.Cmp(data2.Empty) == 0
		}
	case Upload_UpDone:
		{
			_, ok := other.Get_().(Upload_UpDone)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Upload) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Upload)
	return ok && _this.Equals(typed)
}

func Type_Upload_() _dafny.TypeDescriptor {
	return type_Upload_{}
}

type type_Upload_ struct {
}

func (_this type_Upload_) Default() interface{} {
	return Companion_Upload_.Default()
}

func (_this type_Upload_) String() string {
	return "EHBPEvents.Upload"
}
func (_this Upload) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Upload{}

// End of datatype Upload

// Definition of datatype Response
type Response struct {
	Data_Response_
}

func (_this Response) Get_() Data_Response_ {
	return _this.Data_Response_
}

type Data_Response_ interface {
	isResponse()
}

type CompanionStruct_Response_ struct {
}

var Companion_Response_ = CompanionStruct_Response_{}

type Response_AwaitHead struct {
	Encrypted bool
}

func (Response_AwaitHead) isResponse() {}

func (CompanionStruct_Response_) Create_AwaitHead_(Encrypted bool) Response {
	return Response{Response_AwaitHead{Encrypted}}
}

func (_this Response) Is_AwaitHead() bool {
	_, ok := _this.Get_().(Response_AwaitHead)
	return ok
}

type Response_ProblemReading struct {
	Status  _dafny.Int
	Headers _dafny.Sequence
	Data    _dafny.Sequence
}

func (Response_ProblemReading) isResponse() {}

func (CompanionStruct_Response_) Create_ProblemReading_(Status _dafny.Int, Headers _dafny.Sequence, Data _dafny.Sequence) Response {
	return Response{Response_ProblemReading{Status, Headers, Data}}
}

func (_this Response) Is_ProblemReading() bool {
	_, ok := _this.Get_().(Response_ProblemReading)
	return ok
}

type Response_AwaitKeys struct {
	Status       _dafny.Int
	Headers      _dafny.Sequence
	RequireFrame bool
	Stage        _dafny.Int
	Job          Job
	Prk          _dafny.Sequence
	Key          _dafny.Sequence
}

func (Response_AwaitKeys) isResponse() {}

func (CompanionStruct_Response_) Create_AwaitKeys_(Status _dafny.Int, Headers _dafny.Sequence, RequireFrame bool, Stage _dafny.Int, Job Job, Prk _dafny.Sequence, Key _dafny.Sequence) Response {
	return Response{Response_AwaitKeys{Status, Headers, RequireFrame, Stage, Job, Prk, Key}}
}

func (_this Response) Is_AwaitKeys() bool {
	_, ok := _this.Get_().(Response_AwaitKeys)
	return ok
}

type Response_Body struct {
	Keys Ctx
	Dec  Dec
	Done bool
}

func (Response_Body) isResponse() {}

func (CompanionStruct_Response_) Create_Body_(Keys Ctx, Dec Dec, Done bool) Response {
	return Response{Response_Body{Keys, Dec, Done}}
}

func (_this Response) Is_Body() bool {
	_, ok := _this.Get_().(Response_Body)
	return ok
}

type Response_BodyReading struct {
	Keys Ctx
	Dec  Dec
}

func (Response_BodyReading) isResponse() {}

func (CompanionStruct_Response_) Create_BodyReading_(Keys Ctx, Dec Dec) Response {
	return Response{Response_BodyReading{Keys, Dec}}
}

func (_this Response) Is_BodyReading() bool {
	_, ok := _this.Get_().(Response_BodyReading)
	return ok
}

type Response_Opening struct {
	Keys   Ctx
	Dec    Dec
	Frames _dafny.Sequence
	Chunks _dafny.Sequence
	Eof    bool
}

func (Response_Opening) isResponse() {}

func (CompanionStruct_Response_) Create_Opening_(Keys Ctx, Dec Dec, Frames _dafny.Sequence, Chunks _dafny.Sequence, Eof bool) Response {
	return Response{Response_Opening{Keys, Dec, Frames, Chunks, Eof}}
}

func (_this Response) Is_Opening() bool {
	_, ok := _this.Get_().(Response_Opening)
	return ok
}

type Response_RespEnded struct {
}

func (Response_RespEnded) isResponse() {}

func (CompanionStruct_Response_) Create_RespEnded_() Response {
	return Response{Response_RespEnded{}}
}

func (_this Response) Is_RespEnded() bool {
	_, ok := _this.Get_().(Response_RespEnded)
	return ok
}

func (CompanionStruct_Response_) Default() Response {
	return Companion_Response_.Create_AwaitHead_(false)
}

func (_this Response) Dtor_encrypted() bool {
	return _this.Get_().(Response_AwaitHead).Encrypted
}

func (_this Response) Dtor_status() _dafny.Int {
	switch data := _this.Get_().(type) {
	case Response_ProblemReading:
		return data.Status
	default:
		return data.(Response_AwaitKeys).Status
	}
}

func (_this Response) Dtor_headers() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Response_ProblemReading:
		return data.Headers
	default:
		return data.(Response_AwaitKeys).Headers
	}
}

func (_this Response) Dtor_data() _dafny.Sequence {
	return _this.Get_().(Response_ProblemReading).Data
}

func (_this Response) Dtor_requireFrame() bool {
	return _this.Get_().(Response_AwaitKeys).RequireFrame
}

func (_this Response) Dtor_stage() _dafny.Int {
	return _this.Get_().(Response_AwaitKeys).Stage
}

func (_this Response) Dtor_job() Job {
	return _this.Get_().(Response_AwaitKeys).Job
}

func (_this Response) Dtor_prk() _dafny.Sequence {
	return _this.Get_().(Response_AwaitKeys).Prk
}

func (_this Response) Dtor_key() _dafny.Sequence {
	return _this.Get_().(Response_AwaitKeys).Key
}

func (_this Response) Dtor_keys() Ctx {
	switch data := _this.Get_().(type) {
	case Response_Body:
		return data.Keys
	case Response_BodyReading:
		return data.Keys
	default:
		return data.(Response_Opening).Keys
	}
}

func (_this Response) Dtor_dec() Dec {
	switch data := _this.Get_().(type) {
	case Response_Body:
		return data.Dec
	case Response_BodyReading:
		return data.Dec
	default:
		return data.(Response_Opening).Dec
	}
}

func (_this Response) Dtor_done() bool {
	return _this.Get_().(Response_Body).Done
}

func (_this Response) Dtor_frames() _dafny.Sequence {
	return _this.Get_().(Response_Opening).Frames
}

func (_this Response) Dtor_chunks() _dafny.Sequence {
	return _this.Get_().(Response_Opening).Chunks
}

func (_this Response) Dtor_eof() bool {
	return _this.Get_().(Response_Opening).Eof
}

func (_this Response) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Response_AwaitHead:
		{
			return "EHBPEvents.Response.AwaitHead" + "(" + _dafny.String(data.Encrypted) + ")"
		}
	case Response_ProblemReading:
		{
			return "EHBPEvents.Response.ProblemReading" + "(" + _dafny.String(data.Status) + ", " + _dafny.String(data.Headers) + ", " + _dafny.String(data.Data) + ")"
		}
	case Response_AwaitKeys:
		{
			_ = data
			return "EHBPEvents.Response.AwaitKeys(<redacted>)"
		}
	case Response_Body:
		{
			return "EHBPEvents.Response.Body" + "(" + _dafny.String(data.Keys) + ", " + _dafny.String(data.Dec) + ", " + _dafny.String(data.Done) + ")"
		}
	case Response_BodyReading:
		{
			return "EHBPEvents.Response.BodyReading" + "(" + _dafny.String(data.Keys) + ", " + _dafny.String(data.Dec) + ")"
		}
	case Response_Opening:
		{
			return "EHBPEvents.Response.Opening" + "(" + _dafny.String(data.Keys) + ", " + _dafny.String(data.Dec) + ", " + _dafny.String(data.Frames) + ", " + _dafny.String(data.Chunks) + ", " + _dafny.String(data.Eof) + ")"
		}
	case Response_RespEnded:
		{
			return "EHBPEvents.Response.RespEnded"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Response) Equals(other Response) bool {
	switch data1 := _this.Get_().(type) {
	case Response_AwaitHead:
		{
			data2, ok := other.Get_().(Response_AwaitHead)
			return ok && data1.Encrypted == data2.Encrypted
		}
	case Response_ProblemReading:
		{
			data2, ok := other.Get_().(Response_ProblemReading)
			return ok && data1.Status.Cmp(data2.Status) == 0 && data1.Headers.Equals(data2.Headers) && data1.Data.Equals(data2.Data)
		}
	case Response_AwaitKeys:
		{
			data2, ok := other.Get_().(Response_AwaitKeys)
			return ok && data1.Status.Cmp(data2.Status) == 0 && data1.Headers.Equals(data2.Headers) && data1.RequireFrame == data2.RequireFrame && data1.Stage.Cmp(data2.Stage) == 0 && data1.Job.Equals(data2.Job) && data1.Prk.Equals(data2.Prk) && data1.Key.Equals(data2.Key)
		}
	case Response_Body:
		{
			data2, ok := other.Get_().(Response_Body)
			return ok && data1.Keys.Equals(data2.Keys) && data1.Dec.Equals(data2.Dec) && data1.Done == data2.Done
		}
	case Response_BodyReading:
		{
			data2, ok := other.Get_().(Response_BodyReading)
			return ok && data1.Keys.Equals(data2.Keys) && data1.Dec.Equals(data2.Dec)
		}
	case Response_Opening:
		{
			data2, ok := other.Get_().(Response_Opening)
			return ok && data1.Keys.Equals(data2.Keys) && data1.Dec.Equals(data2.Dec) && data1.Frames.Equals(data2.Frames) && data1.Chunks.Equals(data2.Chunks) && data1.Eof == data2.Eof
		}
	case Response_RespEnded:
		{
			_, ok := other.Get_().(Response_RespEnded)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Response) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Response)
	return ok && _this.Equals(typed)
}

func Type_Response_() _dafny.TypeDescriptor {
	return type_Response_{}
}

type type_Response_ struct {
}

func (_this type_Response_) Default() interface{} {
	return Companion_Response_.Default()
}

func (_this type_Response_) String() string {
	return "EHBPEvents.Response"
}
func (_this Response) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Response{}

// End of datatype Response

// Definition of datatype Phase
type Phase struct {
	Data_Phase_
}

func (_this Phase) Get_() Data_Phase_ {
	return _this.Data_Phase_
}

type Data_Phase_ interface {
	isPhase()
}

type CompanionStruct_Phase_ struct {
}

var Companion_Phase_ = CompanionStruct_Phase_{}

type Phase_Idle struct {
}

func (Phase_Idle) isPhase() {}

func (CompanionStruct_Phase_) Create_Idle_() Phase {
	return Phase{Phase_Idle{}}
}

func (_this Phase) Is_Idle() bool {
	_, ok := _this.Get_().(Phase_Idle)
	return ok
}

type Phase_AwaitSession struct {
	HasBody bool
}

func (Phase_AwaitSession) isPhase() {}

func (CompanionStruct_Phase_) Create_AwaitSession_(HasBody bool) Phase {
	return Phase{Phase_AwaitSession{HasBody}}
}

func (_this Phase) Is_AwaitSession() bool {
	_, ok := _this.Get_().(Phase_AwaitSession)
	return ok
}

type Phase_Peeking struct {
	Empty _dafny.Int
}

func (Phase_Peeking) isPhase() {}

func (CompanionStruct_Phase_) Create_Peeking_(Empty _dafny.Int) Phase {
	return Phase{Phase_Peeking{Empty}}
}

func (_this Phase) Is_Peeking() bool {
	_, ok := _this.Get_().(Phase_Peeking)
	return ok
}

type Phase_AwaitSetup struct {
	First    _dafny.Sequence
	FirstEof bool
	Hpke     Hpke
}

func (Phase_AwaitSetup) isPhase() {}

func (CompanionStruct_Phase_) Create_AwaitSetup_(First _dafny.Sequence, FirstEof bool, Hpke Hpke) Phase {
	return Phase{Phase_AwaitSetup{First, FirstEof, Hpke}}
}

func (_this Phase) Is_AwaitSetup() bool {
	_, ok := _this.Get_().(Phase_AwaitSetup)
	return ok
}

type Phase_AwaitExport struct {
	First    _dafny.Sequence
	FirstEof bool
	Enc      _dafny.Sequence
	Job      Job
}

func (Phase_AwaitExport) isPhase() {}

func (CompanionStruct_Phase_) Create_AwaitExport_(First _dafny.Sequence, FirstEof bool, Enc _dafny.Sequence, Job Job) Phase {
	return Phase{Phase_AwaitExport{First, FirstEof, Enc, Job}}
}

func (_this Phase) Is_AwaitExport() bool {
	_, ok := _this.Get_().(Phase_AwaitExport)
	return ok
}

type Phase_Exchanging struct {
	Upload   Upload
	Response Response
}

func (Phase_Exchanging) isPhase() {}

func (CompanionStruct_Phase_) Create_Exchanging_(Upload Upload, Response Response) Phase {
	return Phase{Phase_Exchanging{Upload, Response}}
}

func (_this Phase) Is_Exchanging() bool {
	_, ok := _this.Get_().(Phase_Exchanging)
	return ok
}

type Phase_DiscAwaitHead struct {
}

func (Phase_DiscAwaitHead) isPhase() {}

func (CompanionStruct_Phase_) Create_DiscAwaitHead_() Phase {
	return Phase{Phase_DiscAwaitHead{}}
}

func (_this Phase) Is_DiscAwaitHead() bool {
	_, ok := _this.Get_().(Phase_DiscAwaitHead)
	return ok
}

type Phase_DiscReading struct {
	Data _dafny.Sequence
}

func (Phase_DiscReading) isPhase() {}

func (CompanionStruct_Phase_) Create_DiscReading_(Data _dafny.Sequence) Phase {
	return Phase{Phase_DiscReading{Data}}
}

func (_this Phase) Is_DiscReading() bool {
	_, ok := _this.Get_().(Phase_DiscReading)
	return ok
}

type Phase_Ended struct {
}

func (Phase_Ended) isPhase() {}

func (CompanionStruct_Phase_) Create_Ended_() Phase {
	return Phase{Phase_Ended{}}
}

func (_this Phase) Is_Ended() bool {
	_, ok := _this.Get_().(Phase_Ended)
	return ok
}

func (CompanionStruct_Phase_) Default() Phase {
	return Companion_Phase_.Create_Idle_()
}

func (_this Phase) Dtor_hasBody() bool {
	return _this.Get_().(Phase_AwaitSession).HasBody
}

func (_this Phase) Dtor_empty() _dafny.Int {
	return _this.Get_().(Phase_Peeking).Empty
}

func (_this Phase) Dtor_first() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case Phase_AwaitSetup:
		return data.First
	default:
		return data.(Phase_AwaitExport).First
	}
}

func (_this Phase) Dtor_firstEof() bool {
	switch data := _this.Get_().(type) {
	case Phase_AwaitSetup:
		return data.FirstEof
	default:
		return data.(Phase_AwaitExport).FirstEof
	}
}

func (_this Phase) Dtor_hpke() Hpke {
	return _this.Get_().(Phase_AwaitSetup).Hpke
}

func (_this Phase) Dtor_enc() _dafny.Sequence {
	return _this.Get_().(Phase_AwaitExport).Enc
}

func (_this Phase) Dtor_job() Job {
	return _this.Get_().(Phase_AwaitExport).Job
}

func (_this Phase) Dtor_upload() Upload {
	return _this.Get_().(Phase_Exchanging).Upload
}

func (_this Phase) Dtor_response() Response {
	return _this.Get_().(Phase_Exchanging).Response
}

func (_this Phase) Dtor_data() _dafny.Sequence {
	return _this.Get_().(Phase_DiscReading).Data
}

func (_this Phase) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Phase_Idle:
		{
			return "EHBPEvents.Phase.Idle"
		}
	case Phase_AwaitSession:
		{
			return "EHBPEvents.Phase.AwaitSession" + "(" + _dafny.String(data.HasBody) + ")"
		}
	case Phase_Peeking:
		{
			return "EHBPEvents.Phase.Peeking" + "(" + _dafny.String(data.Empty) + ")"
		}
	case Phase_AwaitSetup:
		{
			return "EHBPEvents.Phase.AwaitSetup" + "(" + _dafny.String(data.First) + ", " + _dafny.String(data.FirstEof) + ", " + _dafny.String(data.Hpke) + ")"
		}
	case Phase_AwaitExport:
		{
			return "EHBPEvents.Phase.AwaitExport" + "(" + _dafny.String(data.First) + ", " + _dafny.String(data.FirstEof) + ", " + _dafny.String(data.Enc) + ", " + _dafny.String(data.Job) + ")"
		}
	case Phase_Exchanging:
		{
			return "EHBPEvents.Phase.Exchanging" + "(" + _dafny.String(data.Upload) + ", " + _dafny.String(data.Response) + ")"
		}
	case Phase_DiscAwaitHead:
		{
			return "EHBPEvents.Phase.DiscAwaitHead"
		}
	case Phase_DiscReading:
		{
			return "EHBPEvents.Phase.DiscReading" + "(" + _dafny.String(data.Data) + ")"
		}
	case Phase_Ended:
		{
			return "EHBPEvents.Phase.Ended"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Phase) Equals(other Phase) bool {
	switch data1 := _this.Get_().(type) {
	case Phase_Idle:
		{
			_, ok := other.Get_().(Phase_Idle)
			return ok
		}
	case Phase_AwaitSession:
		{
			data2, ok := other.Get_().(Phase_AwaitSession)
			return ok && data1.HasBody == data2.HasBody
		}
	case Phase_Peeking:
		{
			data2, ok := other.Get_().(Phase_Peeking)
			return ok && data1.Empty.Cmp(data2.Empty) == 0
		}
	case Phase_AwaitSetup:
		{
			data2, ok := other.Get_().(Phase_AwaitSetup)
			return ok && data1.First.Equals(data2.First) && data1.FirstEof == data2.FirstEof && data1.Hpke.Equals(data2.Hpke)
		}
	case Phase_AwaitExport:
		{
			data2, ok := other.Get_().(Phase_AwaitExport)
			return ok && data1.First.Equals(data2.First) && data1.FirstEof == data2.FirstEof && data1.Enc.Equals(data2.Enc) && data1.Job.Equals(data2.Job)
		}
	case Phase_Exchanging:
		{
			data2, ok := other.Get_().(Phase_Exchanging)
			return ok && data1.Upload.Equals(data2.Upload) && data1.Response.Equals(data2.Response)
		}
	case Phase_DiscAwaitHead:
		{
			_, ok := other.Get_().(Phase_DiscAwaitHead)
			return ok
		}
	case Phase_DiscReading:
		{
			data2, ok := other.Get_().(Phase_DiscReading)
			return ok && data1.Data.Equals(data2.Data)
		}
	case Phase_Ended:
		{
			_, ok := other.Get_().(Phase_Ended)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Phase) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Phase)
	return ok && _this.Equals(typed)
}

func Type_Phase_() _dafny.TypeDescriptor {
	return type_Phase_{}
}

type type_Phase_ struct {
}

func (_this type_Phase_) Default() interface{} {
	return Companion_Phase_.Default()
}

func (_this type_Phase_) String() string {
	return "EHBPEvents.Phase"
}
func (_this Phase) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Phase{}

// End of datatype Phase

// Definition of datatype State
type State struct {
	Data_State_
}

func (_this State) Get_() Data_State_ {
	return _this.Data_State_
}

type Data_State_ interface {
	isState()
}

type CompanionStruct_State_ struct {
}

var Companion_State_ = CompanionStruct_State_{}

type State_State struct {
	Phase      Phase
	Origin     m_EHBP.Origin
	PublicKey  _dafny.Sequence
	Verb       _dafny.Sequence
	Url        _dafny.Sequence
	Headers    _dafny.Sequence
	Generation uint64
	Published  bool
	Token      m_EHBP.Token
	Ctx        Ctx
}

func (State_State) isState() {}

func (CompanionStruct_State_) Create_State_(Phase Phase, Origin m_EHBP.Origin, PublicKey _dafny.Sequence, Verb _dafny.Sequence, Url _dafny.Sequence, Headers _dafny.Sequence, Generation uint64, Published bool, Token m_EHBP.Token, Ctx Ctx) State {
	return State{State_State{Phase, Origin, PublicKey, Verb, Url, Headers, Generation, Published, Token, Ctx}}
}

func (_this State) Is_State() bool {
	_, ok := _this.Get_().(State_State)
	return ok
}

func (CompanionStruct_State_) Default() State {
	return Companion_State_.Create_State_(Companion_Phase_.Default(), m_EHBP.Companion_Origin_.Default(), _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, uint64(0), false, m_EHBP.Companion_Token_.Default(), Companion_Ctx_.Default())
}

func (_this State) Dtor_phase() Phase {
	return _this.Get_().(State_State).Phase
}

func (_this State) Dtor_origin() m_EHBP.Origin {
	return _this.Get_().(State_State).Origin
}

func (_this State) Dtor_publicKey() _dafny.Sequence {
	return _this.Get_().(State_State).PublicKey
}

func (_this State) Dtor_verb() _dafny.Sequence {
	return _this.Get_().(State_State).Verb
}

func (_this State) Dtor_url() _dafny.Sequence {
	return _this.Get_().(State_State).Url
}

func (_this State) Dtor_headers() _dafny.Sequence {
	return _this.Get_().(State_State).Headers
}

func (_this State) Dtor_generation() uint64 {
	return _this.Get_().(State_State).Generation
}

func (_this State) Dtor_published() bool {
	return _this.Get_().(State_State).Published
}

func (_this State) Dtor_token() m_EHBP.Token {
	return _this.Get_().(State_State).Token
}

func (_this State) Dtor_ctx() Ctx {
	return _this.Get_().(State_State).Ctx
}

func (_this State) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case State_State:
		{
			return "EHBPEvents.State.State" + "(" + _dafny.String(data.Phase) + ", " + _dafny.String(data.Origin) + ", " + _dafny.String(data.PublicKey) + ", " + data.Verb.VerbatimString(true) + ", " + data.Url.VerbatimString(true) + ", " + _dafny.String(data.Headers) + ", " + _dafny.String(data.Generation) + ", " + _dafny.String(data.Published) + ", " + _dafny.String(data.Token) + ", " + _dafny.String(data.Ctx) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this State) Equals(other State) bool {
	switch data1 := _this.Get_().(type) {
	case State_State:
		{
			data2, ok := other.Get_().(State_State)
			return ok && data1.Phase.Equals(data2.Phase) && data1.Origin.Equals(data2.Origin) && data1.PublicKey.Equals(data2.PublicKey) && data1.Verb.Equals(data2.Verb) && data1.Url.Equals(data2.Url) && data1.Headers.Equals(data2.Headers) && data1.Generation == data2.Generation && data1.Published == data2.Published && data1.Token.Equals(data2.Token) && data1.Ctx.Equals(data2.Ctx)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this State) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(State)
	return ok && _this.Equals(typed)
}

func Type_State_() _dafny.TypeDescriptor {
	return type_State_{}
}

type type_State_ struct {
}

func (_this type_State_) Default() interface{} {
	return Companion_State_.Default()
}

func (_this type_State_) String() string {
	return "EHBPEvents.State"
}
func (_this State) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = State{}

// End of datatype State
