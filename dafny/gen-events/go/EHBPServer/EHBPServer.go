// Package EHBPServer
// Dafny module EHBPServer compiled into Go

package EHBPServer

import (
	os "os"

	m_EHBPEvents "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen-events/go/EHBPEvents"
	m_EHBP "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/EHBP"
	m__System "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/System_"
	_dafny "github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/dafny"
)

var _ = os.Args
var _ _dafny.Dummy__
var _ m__System.Dummy__
var _ m_EHBP.Dummy__
var _ m_EHBPEvents.Dummy__

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
	return "EHBPServer.Default__"
}
func (_this *Default__) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = &Default__{}

func (_static *CompanionStruct_Default___) ToEvent(e SEvent) m_EHBPEvents.Event {
	var _source0 SEvent = e
	_ = _source0
	{
		if _source0.Is_RandomResult() {
			var _0_d _dafny.Sequence = _source0.Get_().(SEvent_RandomResult).Data
			_ = _0_d
			return m_EHBPEvents.Companion_Event_.Create_RandomResult_(_0_d)
		}
	}
	{
		if _source0.Is_X25519Result() {
			var _1_p _dafny.Sequence = _source0.Get_().(SEvent_X25519Result).Point
			_ = _1_p
			return m_EHBPEvents.Companion_Event_.Create_X25519Result_(_1_p)
		}
	}
	{
		if _source0.Is_HmacResult() {
			var _2_m _dafny.Sequence = _source0.Get_().(SEvent_HmacResult).Mac
			_ = _2_m
			return m_EHBPEvents.Companion_Event_.Create_HmacResult_(_2_m)
		}
	}
	{
		if _source0.Is_AeadSealResult() {
			var _3_c _dafny.Sequence = _source0.Get_().(SEvent_AeadSealResult).Ciphertext
			_ = _3_c
			return m_EHBPEvents.Companion_Event_.Create_AeadSealResult_(_3_c)
		}
	}
	{
		if _source0.Is_AeadOpenResult() {
			var _4_ok bool = _source0.Get_().(SEvent_AeadOpenResult).Ok
			_ = _4_ok
			var _5_p _dafny.Sequence = _source0.Get_().(SEvent_AeadOpenResult).Plaintext
			_ = _5_p
			return m_EHBPEvents.Companion_Event_.Create_AeadOpenResult_(_4_ok, _5_p)
		}
	}
	{
		return m_EHBPEvents.Companion_Event_.Create_CallerClose_()
	}
}
func (_static *CompanionStruct_Default___) ToAction(a m_EHBPEvents.Action) SAction {
	var _source0 m_EHBPEvents.Action = a
	_ = _source0
	{
		if _source0.Is_RandomBytes() {
			var _0_n _dafny.Int = _source0.Get_().(m_EHBPEvents.Action_RandomBytes).Length
			_ = _0_n
			return Companion_SAction_.Create_RandomBytes_(_0_n)
		}
	}
	{
		if _source0.Is_X25519() {
			var _1_s _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_X25519).Scalar
			_ = _1_s
			var _2_p _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_X25519).Point
			_ = _2_p
			return Companion_SAction_.Create_X25519_(_1_s, _2_p)
		}
	}
	{
		if _source0.Is_HmacSha256() {
			var _3_k _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_HmacSha256).Key
			_ = _3_k
			var _4_d _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_HmacSha256).Data
			_ = _4_d
			return Companion_SAction_.Create_HmacSha256_(_3_k, _4_d)
		}
	}
	{
		if _source0.Is_AeadSeal() {
			var _5_k _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_AeadSeal).Key
			_ = _5_k
			var _6_n _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_AeadSeal).Nonce
			_ = _6_n
			var _7_p _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_AeadSeal).Plaintext
			_ = _7_p
			return Companion_SAction_.Create_AeadSeal_(_5_k, _6_n, _7_p)
		}
	}
	{
		if _source0.Is_AeadOpen() {
			var _8_k _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_AeadOpen).Key
			_ = _8_k
			var _9_n _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_AeadOpen).Nonce
			_ = _9_n
			var _10_c _dafny.Sequence = _source0.Get_().(m_EHBPEvents.Action_AeadOpen).Ciphertext
			_ = _10_c
			return Companion_SAction_.Create_AeadOpen_(_8_k, _9_n, _10_c)
		}
	}
	{
		return Companion_SAction_.Create_Fail_(m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected action"))
	}
}
func (_static *CompanionStruct_Default___) ServerInitial(sk _dafny.Sequence, pk _dafny.Sequence) SState {
	return Companion_SState_.Create_SState_(Companion_Phase_.Create_Idle_(), sk, pk, _dafny.SeqOf(), m_EHBPEvents.Companion_Default___.NoCtx(), m_EHBPEvents.Companion_Dec_.Create_Dec_(_dafny.SeqOf(), uint64(0), false, false), false)
}
func (_static *CompanionStruct_Default___) Inv(s SState) bool {
	return !((((s).Dtor_phase()).Is_Deriving()) || (((s).Dtor_phase()).Is_Running())) || ((s).Dtor_payload())
}
func (_static *CompanionStruct_Default___) NoEmit(acts _dafny.Sequence) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((acts).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !(((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((acts).Cardinality())) < 0)) || (!(((acts).Select((_0_i).Uint32()).(SAction)).Is_EmitPlaintext()))
	})
}
func (_static *CompanionStruct_Default___) Dispatches(acts _dafny.Sequence) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((acts).Cardinality())), false, func(_exists_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_exists_var_0).(_dafny.Int)
		return (((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((acts).Cardinality())) < 0)) && (((acts).Select((_0_i).Uint32()).(SAction)).Is_Dispatch())
	})
}
func (_static *CompanionStruct_Default___) Terminal(a SAction) bool {
	return (((((a).Is_PassRequest()) || ((a).Is_Respond())) || ((a).Is_Dispatch())) || (((a).Is_Close()) && (((a).Dtor_stream()).Is_ResponseBody()))) || (((a).Is_Write()) && (((a).Dtor_end()).Is_Aborted()))
}
func (_static *CompanionStruct_Default___) TerminalLast(acts _dafny.Sequence) bool {
	return _dafny.Quantifier(_dafny.IntegerRange(_dafny.Zero, _dafny.IntOfUint32((acts).Cardinality())), true, func(_forall_var_0 _dafny.Int) bool {
		var _0_i _dafny.Int
		_0_i = interface{}(_forall_var_0).(_dafny.Int)
		return !((((_0_i).Sign() != -1) && ((_0_i).Cmp(_dafny.IntOfUint32((acts).Cardinality())) < 0)) && (Companion_Default___.Terminal((acts).Select((_0_i).Uint32()).(SAction)))) || ((_0_i).Cmp((_dafny.IntOfUint32((acts).Cardinality())).Minus(_dafny.One)) == 0)
	})
}
func (_static *CompanionStruct_Default___) SPerform(p SPerformer, a SAction) m_EHBP.Option {
	var r m_EHBP.Option = m_EHBP.Companion_Option_.Default()
	_ = r
	var _source0 SAction = a
	_ = _source0
	{
		{
			if _source0.Is_RandomBytes() {
				var _0_length _dafny.Int = _source0.Get_().(SAction_RandomBytes).Length
				_ = _0_length
				var _1_data _dafny.Sequence
				_ = _1_data
				var _out0 _dafny.Sequence
				_ = _out0
				_out0 = (p).RandomBytes(_0_length)
				_1_data = _out0
				r = m_EHBP.Companion_Option_.Create_Some_(Companion_SEvent_.Create_RandomResult_(_1_data))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_X25519() {
				var _2_scalar _dafny.Sequence = _source0.Get_().(SAction_X25519).Scalar
				_ = _2_scalar
				var _3_point _dafny.Sequence = _source0.Get_().(SAction_X25519).Point
				_ = _3_point
				var _4_shared _dafny.Sequence
				_ = _4_shared
				var _out1 _dafny.Sequence
				_ = _out1
				_out1 = (p).X25519(_2_scalar, _3_point)
				_4_shared = _out1
				r = m_EHBP.Companion_Option_.Create_Some_(Companion_SEvent_.Create_X25519Result_(_4_shared))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_HmacSha256() {
				var _5_key _dafny.Sequence = _source0.Get_().(SAction_HmacSha256).Key
				_ = _5_key
				var _6_data _dafny.Sequence = _source0.Get_().(SAction_HmacSha256).Data
				_ = _6_data
				var _7_mac _dafny.Sequence
				_ = _7_mac
				var _out2 _dafny.Sequence
				_ = _out2
				_out2 = (p).HmacSha256(_5_key, _6_data)
				_7_mac = _out2
				r = m_EHBP.Companion_Option_.Create_Some_(Companion_SEvent_.Create_HmacResult_(_7_mac))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_AeadSeal() {
				var _8_key _dafny.Sequence = _source0.Get_().(SAction_AeadSeal).Key
				_ = _8_key
				var _9_nonce _dafny.Sequence = _source0.Get_().(SAction_AeadSeal).Nonce
				_ = _9_nonce
				var _10_plaintext _dafny.Sequence = _source0.Get_().(SAction_AeadSeal).Plaintext
				_ = _10_plaintext
				var _11_ciphertext _dafny.Sequence
				_ = _11_ciphertext
				var _out3 _dafny.Sequence
				_ = _out3
				_out3 = (p).AeadSeal(_8_key, _9_nonce, _10_plaintext)
				_11_ciphertext = _out3
				r = m_EHBP.Companion_Option_.Create_Some_(Companion_SEvent_.Create_AeadSealResult_(_11_ciphertext))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_AeadOpen() {
				var _12_key _dafny.Sequence = _source0.Get_().(SAction_AeadOpen).Key
				_ = _12_key
				var _13_nonce _dafny.Sequence = _source0.Get_().(SAction_AeadOpen).Nonce
				_ = _13_nonce
				var _14_ciphertext _dafny.Sequence = _source0.Get_().(SAction_AeadOpen).Ciphertext
				_ = _14_ciphertext
				var _15_ok bool
				_ = _15_ok
				var _16_plaintext _dafny.Sequence
				_ = _16_plaintext
				var _out4 bool
				_ = _out4
				var _out5 _dafny.Sequence
				_ = _out5
				_out4, _out5 = (p).AeadOpen(_12_key, _13_nonce, _14_ciphertext)
				_15_ok = _out4
				_16_plaintext = _out5
				r = m_EHBP.Companion_Option_.Create_Some_(Companion_SEvent_.Create_AeadOpenResult_(_15_ok, _16_plaintext))
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_PassRequest() {
				(p).PassRequest()
				r = m_EHBP.Companion_Option_.Create_None_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Respond() {
				var _17_status _dafny.Int = _source0.Get_().(SAction_Respond).Status
				_ = _17_status
				var _18_code m_EHBP.Code = _source0.Get_().(SAction_Respond).Code
				_ = _18_code
				var _19_message _dafny.Sequence = _source0.Get_().(SAction_Respond).Message
				_ = _19_message
				var _20_headers _dafny.Sequence = _source0.Get_().(SAction_Respond).Headers
				_ = _20_headers
				var _21_body _dafny.Sequence = _source0.Get_().(SAction_Respond).Body
				_ = _21_body
				(p).Respond(_17_status, _18_code, _19_message, _20_headers, _21_body)
				r = m_EHBP.Companion_Option_.Create_None_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Read() {
				var _22_stream m_EHBPEvents.Stream = _source0.Get_().(SAction_Read).Stream
				_ = _22_stream
				var _23_ok bool
				_ = _23_ok
				var _24_data _dafny.Sequence
				_ = _24_data
				var _25_eof bool
				_ = _25_eof
				var _out6 bool
				_ = _out6
				var _out7 _dafny.Sequence
				_ = _out7
				var _out8 bool
				_ = _out8
				_out6, _out7, _out8 = (p).Read(_22_stream)
				_23_ok = _out6
				_24_data = _out7
				_25_eof = _out8
				r = m_EHBP.Companion_Option_.Create_Some_((func() SEvent {
					if _23_ok {
						return Companion_SEvent_.Create_Chunk_(_24_data, _25_eof)
					}
					return Companion_SEvent_.Create_StreamFailed_()
				})())
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_EmitPlaintext() {
				var _26_data _dafny.Sequence = _source0.Get_().(SAction_EmitPlaintext).Data
				_ = _26_data
				(p).EmitPlaintext(_26_data)
				r = m_EHBP.Companion_Option_.Create_None_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Close() {
				var _27_stream m_EHBPEvents.Stream = _source0.Get_().(SAction_Close).Stream
				_ = _27_stream
				(p).Close(_27_stream)
				r = m_EHBP.Companion_Option_.Create_None_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Dispatch() {
				var _28_ran bool
				_ = _28_ran
				var _out9 bool
				_ = _out9
				_out9 = (p).Dispatch()
				_28_ran = _out9
				if _28_ran {
					r = m_EHBP.Companion_Option_.Create_Some_(Companion_SEvent_.Create_HandlerDone_())
				} else {
					r = m_EHBP.Companion_Option_.Create_None_()
				}
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_StartResponse() {
				var _29_status _dafny.Int = _source0.Get_().(SAction_StartResponse).Status
				_ = _29_status
				var _30_headers _dafny.Sequence = _source0.Get_().(SAction_StartResponse).Headers
				_ = _30_headers
				(p).StartResponse(_29_status, _30_headers)
				r = m_EHBP.Companion_Option_.Create_None_()
				return r
				goto Lmatch0
			}
		}
		{
			if _source0.Is_Write() {
				var _31_data _dafny.Sequence = _source0.Get_().(SAction_Write).Data
				_ = _31_data
				var _32_end m_EHBPEvents.BodyEnd = _source0.Get_().(SAction_Write).End
				_ = _32_end
				(p).Write(_31_data, _32_end)
				r = m_EHBP.Companion_Option_.Create_None_()
				return r
				goto Lmatch0
			}
		}
		{
			var _33_code m_EHBP.Code = _source0.Get_().(SAction_Fail).Code
			_ = _33_code
			var _34_message _dafny.Sequence = _source0.Get_().(SAction_Fail).Message
			_ = _34_message
			(p).Fail(_33_code, _34_message)
			r = m_EHBP.Companion_Option_.Create_None_()
			return r
		}
		goto Lmatch0
	}
Lmatch0:
	return r
}
func (_static *CompanionStruct_Default___) Contract(s SState, e SEvent, r _dafny.Tuple) bool {
	return (((!(!(Companion_Default___.NoEmit((*(r).IndexInt(1)).(_dafny.Sequence)))) || (((e).Is_AeadOpenResult()) && ((e).Dtor_ok()))) && (!(Companion_Default___.Dispatches((*(r).IndexInt(1)).(_dafny.Sequence))) || (((((*(r).IndexInt(0)).(SState)).Dtor_phase()).Is_Running()) && (((*(r).IndexInt(0)).(SState)).Dtor_payload())))) && (Companion_Default___.TerminalLast((*(r).IndexInt(1)).(_dafny.Sequence)))) && (Companion_Default___.Inv((*(r).IndexInt(0)).(SState)))
}
func (_static *CompanionStruct_Default___) Text(s _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqCreate((_dafny.IntOfUint32((s).Cardinality())).Uint32(), func(coer17 func(_dafny.Int) uint8) func(_dafny.Int) interface{} {
		return func(arg17 _dafny.Int) interface{} {
			return coer17(arg17)
		}
	}((func(_0_s _dafny.Sequence) func(_dafny.Int) uint8 {
		return func(_1_i _dafny.Int) uint8 {
			return (func() uint8 {
				if (_dafny.IntOfInt32(rune((_0_s).Select((_1_i).Uint32()).(_dafny.CodePoint)))).Cmp(_dafny.IntOfInt64(128)) < 0 {
					return (_dafny.IntOfInt32(rune((_0_s).Select((_1_i).Uint32()).(_dafny.CodePoint)))).Uint8()
				}
				return uint8(63)
			})()
		}
	})(s)))
}
func (_static *CompanionStruct_Default___) Answer(s SState, status _dafny.Int, code m_EHBP.Code, message _dafny.Sequence, text _dafny.Sequence) _dafny.Tuple {
	var _0_ended SState = func(_pat_let66_0 SState) SState {
		return func(_1_dt__update__tmp_h0 SState) SState {
			return func(_pat_let67_0 Phase) SState {
				return func(_2_dt__update_hphase_h0 Phase) SState {
					return Companion_SState_.Create_SState_(_2_dt__update_hphase_h0, (_1_dt__update__tmp_h0).Dtor_sk(), (_1_dt__update__tmp_h0).Dtor_pk(), (_1_dt__update__tmp_h0).Dtor_enc(), (_1_dt__update__tmp_h0).Dtor_ctx(), (_1_dt__update__tmp_h0).Dtor_dec(), (_1_dt__update__tmp_h0).Dtor_payload())
				}(_pat_let67_0)
			}(Companion_Phase_.Create_Ended_())
		}(_pat_let66_0)
	}(s)
	_ = _0_ended
	if (status).Cmp(_dafny.IntOfInt64(422)) == 0 {
		return _dafny.TupleOf(_0_ended, _dafny.SeqOf(Companion_SAction_.Create_Respond_(status, code, message, _dafny.SeqOf(_dafny.TupleOf(_dafny.UnicodeSeqOfUtf8Bytes("Content-Type"), m_EHBP.Companion_Default___.ProblemJsonMediaType())), Companion_Default___.Text(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.UnicodeSeqOfUtf8Bytes("{\"type\":\""), m_EHBPEvents.Companion_Default___.Escape(m_EHBP.Companion_Default___.KeyConfigProblemType())), _dafny.UnicodeSeqOfUtf8Bytes("\",\"title\":\"")), m_EHBPEvents.Companion_Default___.Escape(Companion_Default___.DecryptText())), _dafny.UnicodeSeqOfUtf8Bytes("\"}\n"))))))
	} else {
		return _dafny.TupleOf(_0_ended, _dafny.SeqOf(Companion_SAction_.Create_Respond_(status, code, message, Companion_Default___.TextHeaders(), Companion_Default___.Text(_dafny.Companion_Sequence_.Concatenate(text, _dafny.UnicodeSeqOfUtf8Bytes("\n"))))))
	}
}
func (_static *CompanionStruct_Default___) Refuse(s SState, code m_EHBP.Code, message _dafny.Sequence) _dafny.Tuple {
	return Companion_Default___.Answer(s, _dafny.IntOfInt64(400), code, message, Companion_Default___.DecryptText())
}
func (_static *CompanionStruct_Default___) AbortResponse(s SState, code m_EHBP.Code) _dafny.Tuple {
	return _dafny.TupleOf(func(_pat_let68_0 SState) SState {
		return func(_0_dt__update__tmp_h0 SState) SState {
			return func(_pat_let69_0 Phase) SState {
				return func(_1_dt__update_hphase_h0 Phase) SState {
					return Companion_SState_.Create_SState_(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).Dtor_sk(), (_0_dt__update__tmp_h0).Dtor_pk(), (_0_dt__update__tmp_h0).Dtor_enc(), (_0_dt__update__tmp_h0).Dtor_ctx(), (_0_dt__update__tmp_h0).Dtor_dec(), (_0_dt__update__tmp_h0).Dtor_payload())
				}(_pat_let69_0)
			}(Companion_Phase_.Create_Ended_())
		}(_pat_let68_0)
	}(s), _dafny.SeqOf(Companion_SAction_.Create_Write_(_dafny.SeqOf(), m_EHBPEvents.Companion_BodyEnd_.Create_Aborted_(code))))
}
func (_static *CompanionStruct_Default___) OpenFrame(keys m_EHBPEvents.Ctx, f m_EHBP.Framed) SAction {
	return Companion_SAction_.Create_AeadOpen_((keys).Dtor_key(), m_EHBP.Companion_Default___.ComputeNonce((keys).Dtor_baseNonce(), (f).Dtor_seqNo()), (f).Dtor_ciphertext())
}
func (_static *CompanionStruct_Default___) NextFrame(s SState, dec m_EHBPEvents.Dec, frames _dafny.Sequence, eof bool, emitted bool, payload bool, emits _dafny.Sequence) Lane {
	if (_dafny.IntOfUint32((frames).Cardinality())).Sign() == 1 {
		if (_dafny.IntOfUint32((((frames).Select(0).(m_EHBP.Framed)).Dtor_ciphertext()).Cardinality())).Cmp(m_EHBP.Companion_Default___.AeadTagLength()) < 0 {
			return Companion_Lane_.Create_Lane_(Companion_Req_.Create_ReqFailed_((func() _dafny.Int {
				if (((frames).Select(0).(m_EHBP.Framed)).Dtor_seqNo()) == (uint64(0)) {
					return _dafny.IntOfInt64(422)
				}
				return _dafny.IntOfInt64(400)
			})(), m_EHBP.Companion_Code_.Create_AeadDecryptFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("frame shorter than the AEAD tag")), dec, payload, emits)
		} else {
			return Companion_Lane_.Create_Lane_(Companion_Req_.Create_Opening_(frames, eof, emitted), dec, payload, _dafny.Companion_Sequence_.Concatenate(emits, _dafny.SeqOf(Companion_Default___.OpenFrame((s).Dtor_ctx(), (frames).Select(0).(m_EHBP.Framed)))))
		}
	} else if eof {
		return Companion_Lane_.Create_Lane_((func() Req {
			if (m_EHBPEvents.Companion_Default___.Finish(dec)).Is_Some() {
				return Companion_Req_.Create_ReqFailed_(_dafny.IntOfInt64(400), m_EHBP.Companion_Code_.Create_FramingTruncated_(), _dafny.UnicodeSeqOfUtf8Bytes("truncated request frame"))
			}
			return Companion_Req_.Create_ReqDone_()
		})(), dec, payload, emits)
	} else if emitted {
		return Companion_Lane_.Create_Lane_(Companion_Req_.Create_Waiting_(), dec, payload, emits)
	} else {
		return Companion_Lane_.Create_Lane_(Companion_Req_.Create_Reading_(_dafny.Zero), dec, payload, _dafny.Companion_Sequence_.Concatenate(emits, _dafny.SeqOf(Companion_SAction_.Create_Read_(m_EHBPEvents.Companion_Stream_.Create_RequestBody_()))))
	}
}
func (_static *CompanionStruct_Default___) LaneStep(s SState, req Req, e SEvent) Lane {
	var _0_unexpected Lane = Companion_Lane_.Create_Lane_(Companion_Req_.Create_ReqFailed_(_dafny.IntOfInt64(500), m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event")), (s).Dtor_dec(), (s).Dtor_payload(), _dafny.SeqOf())
	_ = _0_unexpected
	var _source0 Req = req
	_ = _source0
	{
		if _source0.Is_Reading() {
			var _1_empty _dafny.Int = _source0.Get_().(Req_Reading).Empty
			_ = _1_empty
			var _source1 SEvent = e
			_ = _source1
			{
				if _source1.Is_StreamFailed() {
					return Companion_Lane_.Create_Lane_(Companion_Req_.Create_ReqFailed_(_dafny.IntOfInt64(400), m_EHBP.Companion_Code_.Create_FramingTruncated_(), _dafny.UnicodeSeqOfUtf8Bytes("failed to read request body")), (s).Dtor_dec(), (s).Dtor_payload(), _dafny.SeqOf())
				}
			}
			{
				if _source1.Is_Chunk() {
					var _2_data _dafny.Sequence = _source1.Get_().(SEvent_Chunk).Data
					_ = _2_data
					var _3_eof bool = _source1.Get_().(SEvent_Chunk).Eof
					_ = _3_eof
					var _let_tmp_rhs0 _dafny.Tuple = m_EHBPEvents.Companion_Default___.Push((s).Dtor_dec(), _2_data)
					_ = _let_tmp_rhs0
					var _4_frames _dafny.Sequence = (*(_let_tmp_rhs0).IndexInt(0)).(_dafny.Sequence)
					_ = _4_frames
					var _5_dec m_EHBPEvents.Dec = (*(_let_tmp_rhs0).IndexInt(1)).(m_EHBPEvents.Dec)
					_ = _5_dec
					var _6_err m_EHBP.Option = (*(_let_tmp_rhs0).IndexInt(2)).(m_EHBP.Option)
					_ = _6_err
					if (_6_err).Is_Some() {
						return Companion_Lane_.Create_Lane_(Companion_Req_.Create_ReqFailed_(_dafny.IntOfInt64(400), (_6_err).Dtor_value().(m_EHBP.Code), _dafny.UnicodeSeqOfUtf8Bytes("invalid request framing")), _5_dec, (s).Dtor_payload(), _dafny.SeqOf())
					} else if (((_dafny.IntOfUint32((_4_frames).Cardinality())).Sign() == 0) && ((_dafny.IntOfUint32((_2_data).Cardinality())).Sign() == 0)) && (!(_3_eof)) {
						if ((_1_empty).Plus(_dafny.One)).Cmp(m_EHBP.Companion_Default___.MaxEmptyReads()) == 0 {
							return Companion_Lane_.Create_Lane_(Companion_Req_.Create_ReqFailed_(_dafny.IntOfInt64(400), m_EHBP.Companion_Code_.Create_FramingTruncated_(), _dafny.UnicodeSeqOfUtf8Bytes("request body made no progress")), _5_dec, (s).Dtor_payload(), _dafny.SeqOf())
						} else {
							return Companion_Lane_.Create_Lane_(Companion_Req_.Create_Reading_((_1_empty).Plus(_dafny.One)), _5_dec, (s).Dtor_payload(), _dafny.SeqOf(Companion_SAction_.Create_Read_(m_EHBPEvents.Companion_Stream_.Create_RequestBody_())))
						}
					} else {
						return Companion_Default___.NextFrame(s, _5_dec, _4_frames, _3_eof, false, (s).Dtor_payload(), _dafny.SeqOf())
					}
				}
			}
			{
				return _0_unexpected
			}
		}
	}
	{
		if _source0.Is_Opening() {
			var _7_frames _dafny.Sequence = _source0.Get_().(Req_Opening).Frames
			_ = _7_frames
			var _8_eof bool = _source0.Get_().(Req_Opening).Eof
			_ = _8_eof
			var _9_emitted bool = _source0.Get_().(Req_Opening).Emitted
			_ = _9_emitted
			if (!((e).Is_AeadOpenResult())) || ((_dafny.IntOfUint32((_7_frames).Cardinality())).Sign() == 0) {
				return _0_unexpected
			} else if (!((e).Dtor_ok())) || (((_dafny.IntOfUint32(((e).Dtor_plaintext()).Cardinality())).Plus(m_EHBP.Companion_Default___.AeadTagLength())).Cmp(_dafny.IntOfUint32((((_7_frames).Select(0).(m_EHBP.Framed)).Dtor_ciphertext()).Cardinality())) != 0) {
				return Companion_Lane_.Create_Lane_(Companion_Req_.Create_ReqFailed_((func() _dafny.Int {
					if (((_7_frames).Select(0).(m_EHBP.Framed)).Dtor_seqNo()) == (uint64(0)) {
						return _dafny.IntOfInt64(422)
					}
					return _dafny.IntOfInt64(400)
				})(), m_EHBP.Companion_Code_.Create_AeadDecryptFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("frame failed to authenticate")), (s).Dtor_dec(), (s).Dtor_payload(), _dafny.SeqOf())
			} else {
				var _10_got bool = (_dafny.IntOfUint32(((e).Dtor_plaintext()).Cardinality())).Sign() == 1
				_ = _10_got
				return Companion_Default___.NextFrame(s, (s).Dtor_dec(), (_7_frames).Drop(1), _8_eof, (_9_emitted) || (_10_got), ((s).Dtor_payload()) || (_10_got), (func() _dafny.Sequence {
					if _10_got {
						return _dafny.SeqOf(Companion_SAction_.Create_EmitPlaintext_((e).Dtor_plaintext()))
					}
					return _dafny.SeqOf()
				})())
			}
		}
	}
	{
		return _0_unexpected
	}
}
func (_static *CompanionStruct_Default___) RespHeaders(nonce _dafny.Sequence) _dafny.Sequence {
	return _dafny.SeqOf(_dafny.TupleOf(m_EHBP.Companion_Default___.ResponseNonceHeader(), m_EHBP.Companion_Default___.EncodeHex(nonce)), _dafny.TupleOf(_dafny.UnicodeSeqOfUtf8Bytes("Transfer-Encoding"), _dafny.UnicodeSeqOfUtf8Bytes("chunked")))
}
func (_static *CompanionStruct_Default___) Head(resp Resp, status _dafny.Int) _dafny.Tuple {
	if (resp).Dtor_started() {
		return _dafny.TupleOf(resp, _dafny.SeqOf())
	} else if (((_dafny.IntOfInt64(100)).Cmp(status) <= 0) && ((status).Cmp(_dafny.IntOfInt64(200)) < 0)) && ((status).Cmp(_dafny.IntOfInt64(101)) != 0) {
		return _dafny.TupleOf(resp, _dafny.SeqOf(Companion_SAction_.Create_StartResponse_(status, _dafny.SeqOf())))
	} else {
		var _0_final _dafny.Int = (func() _dafny.Int {
			if ((status).Cmp(_dafny.IntOfInt64(204)) == 0) || ((status).Cmp(_dafny.IntOfInt64(205)) == 0) {
				return _dafny.IntOfInt64(200)
			}
			return status
		})()
		_ = _0_final
		return _dafny.TupleOf(func(_pat_let70_0 Resp) Resp {
			return func(_1_dt__update__tmp_h0 Resp) Resp {
				return func(_pat_let71_0 _dafny.Int) Resp {
					return func(_2_dt__update_hstatus_h0 _dafny.Int) Resp {
						return func(_pat_let72_0 bool) Resp {
							return func(_3_dt__update_hstarted_h0 bool) Resp {
								return Companion_Resp_.Create_Resp_((_1_dt__update__tmp_h0).Dtor_keys(), (_1_dt__update__tmp_h0).Dtor_nonce(), _3_dt__update_hstarted_h0, _2_dt__update_hstatus_h0, (_1_dt__update__tmp_h0).Dtor_framed(), (_1_dt__update__tmp_h0).Dtor_seal())
							}(_pat_let72_0)
						}(true)
					}(_pat_let71_0)
				}(_0_final)
			}(_pat_let70_0)
		}(resp), _dafny.SeqOf(Companion_SAction_.Create_StartResponse_(_0_final, Companion_Default___.RespHeaders((resp).Dtor_nonce()))))
	}
}
func (_static *CompanionStruct_Default___) SealNext(resp Resp, plaintext _dafny.Sequence, at uint32, final bool) _dafny.Tuple {
	var _pat_let_tv0 = plaintext
	_ = _pat_let_tv0
	var _pat_let_tv1 = at
	_ = _pat_let_tv1
	var _pat_let_tv2 = final
	_ = _pat_let_tv2
	var _0_n uint32 = m_EHBPEvents.Companion_Default___.Min32((uint32((plaintext).Cardinality()))-(func() uint32 { return (at) })(), m_EHBP.Companion_Default___.RequestFrameBytes())
	_ = _0_n
	return _dafny.TupleOf(func(_pat_let73_0 Resp) Resp {
		return func(_1_dt__update__tmp_h0 Resp) Resp {
			return func(_pat_let74_0 Sealing) Resp {
				return func(_2_dt__update_hseal_h0 Sealing) Resp {
					return Companion_Resp_.Create_Resp_((_1_dt__update__tmp_h0).Dtor_keys(), (_1_dt__update__tmp_h0).Dtor_nonce(), (_1_dt__update__tmp_h0).Dtor_started(), (_1_dt__update__tmp_h0).Dtor_status(), (_1_dt__update__tmp_h0).Dtor_framed(), _2_dt__update_hseal_h0)
				}(_pat_let74_0)
			}(Companion_Sealing_.Create_Sealing_(_pat_let_tv0, _pat_let_tv1, _pat_let_tv2))
		}(_pat_let73_0)
	}(resp), _dafny.SeqOf(Companion_SAction_.Create_AeadSeal_(((resp).Dtor_keys()).Dtor_key(), m_EHBP.Companion_Default___.ComputeNonce(((resp).Dtor_keys()).Dtor_baseNonce(), ((resp).Dtor_keys()).Dtor_seqNo()), m_EHBPEvents.Companion_Default___.Piece(plaintext, at, _0_n))))
}
func (_static *CompanionStruct_Default___) ForRequest(e SEvent) bool {
	return ((((e).Is_HandlerRead()) || ((e).Is_Chunk())) || ((e).Is_StreamFailed())) || ((e).Is_AeadOpenResult())
}
func (_static *CompanionStruct_Default___) ServerStep(s SState, e SEvent) _dafny.Tuple {
	var _pat_let_tv0 = e
	_ = _pat_let_tv0
	var _source0 Phase = (s).Dtor_phase()
	_ = _source0
	{
		if _source0.Is_Idle() {
			if (e).Is_RequestStart() {
				return Companion_Default___.StepStart(s, e)
			} else {
				return Companion_Default___.Answer(s, _dafny.IntOfInt64(500), m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event"), Companion_Default___.DecryptText())
			}
		}
	}
	{
		if _source0.Is_Decap() {
			var _0_h m_EHBPEvents.Hpke = _source0.Get_().(Phase_Decap).Hpke
			_ = _0_h
			var _source1 m_EHBPEvents.HpkeOut = m_EHBPEvents.Companion_Default___.HpkeStep(_0_h, Companion_Default___.ToEvent(e))
			_ = _source1
			{
				if _source1.Is_HFailed() {
					var _1_code m_EHBP.Code = _source1.Get_().(m_EHBPEvents.HpkeOut_HFailed).Code
					_ = _1_code
					var _2_message _dafny.Sequence = _source1.Get_().(m_EHBPEvents.HpkeOut_HFailed).Message
					_ = _2_message
					return Companion_Default___.Answer(s, (func() _dafny.Int {
						if (_1_code).Equals(m_EHBP.Companion_Code_.Create_Transport_()) {
							return _dafny.IntOfInt64(500)
						}
						return _dafny.IntOfInt64(422)
					})(), _1_code, _2_message, Companion_Default___.DecryptText())
				}
			}
			{
				if _source1.Is_HContinue() {
					var _3_next m_EHBPEvents.Hpke = _source1.Get_().(m_EHBPEvents.HpkeOut_HContinue).H
					_ = _3_next
					var _4_a m_EHBPEvents.Action = _source1.Get_().(m_EHBPEvents.HpkeOut_HContinue).Action
					_ = _4_a
					return _dafny.TupleOf(func(_pat_let75_0 SState) SState {
						return func(_5_dt__update__tmp_h0 SState) SState {
							return func(_pat_let76_0 Phase) SState {
								return func(_6_dt__update_hphase_h0 Phase) SState {
									return Companion_SState_.Create_SState_(_6_dt__update_hphase_h0, (_5_dt__update__tmp_h0).Dtor_sk(), (_5_dt__update__tmp_h0).Dtor_pk(), (_5_dt__update__tmp_h0).Dtor_enc(), (_5_dt__update__tmp_h0).Dtor_ctx(), (_5_dt__update__tmp_h0).Dtor_dec(), (_5_dt__update__tmp_h0).Dtor_payload())
								}(_pat_let76_0)
							}(Companion_Phase_.Create_Decap_(_3_next))
						}(_pat_let75_0)
					}(s), _dafny.SeqOf(Companion_Default___.ToAction(_4_a)))
				}
			}
			{
				var _7_ctx m_EHBPEvents.Ctx = _source1.Get_().(m_EHBPEvents.HpkeOut_HReady).Ctx
				_ = _7_ctx
				return _dafny.TupleOf(func(_pat_let77_0 SState) SState {
					return func(_8_dt__update__tmp_h1 SState) SState {
						return func(_pat_let78_0 m_EHBPEvents.Ctx) SState {
							return func(_9_dt__update_hctx_h0 m_EHBPEvents.Ctx) SState {
								return func(_pat_let79_0 Phase) SState {
									return func(_10_dt__update_hphase_h1 Phase) SState {
										return Companion_SState_.Create_SState_(_10_dt__update_hphase_h1, (_8_dt__update__tmp_h1).Dtor_sk(), (_8_dt__update__tmp_h1).Dtor_pk(), (_8_dt__update__tmp_h1).Dtor_enc(), _9_dt__update_hctx_h0, (_8_dt__update__tmp_h1).Dtor_dec(), (_8_dt__update__tmp_h1).Dtor_payload())
									}(_pat_let79_0)
								}(Companion_Phase_.Create_Peek_(Companion_Req_.Create_Reading_(_dafny.Zero)))
							}(_pat_let78_0)
						}(_7_ctx)
					}(_pat_let77_0)
				}(s), _dafny.SeqOf(Companion_SAction_.Create_Read_(m_EHBPEvents.Companion_Stream_.Create_RequestBody_())))
			}
		}
	}
	{
		if _source0.Is_Peek() {
			var _11_req Req = _source0.Get_().(Phase_Peek).Req
			_ = _11_req
			var _12_l Lane = Companion_Default___.LaneStep(s, _11_req, e)
			_ = _12_l
			var _13_s_k SState = func(_pat_let80_0 SState) SState {
				return func(_14_dt__update__tmp_h2 SState) SState {
					return func(_pat_let81_0 bool) SState {
						return func(_15_dt__update_hpayload_h0 bool) SState {
							return func(_pat_let82_0 m_EHBPEvents.Dec) SState {
								return func(_16_dt__update_hdec_h0 m_EHBPEvents.Dec) SState {
									return Companion_SState_.Create_SState_((_14_dt__update__tmp_h2).Dtor_phase(), (_14_dt__update__tmp_h2).Dtor_sk(), (_14_dt__update__tmp_h2).Dtor_pk(), (_14_dt__update__tmp_h2).Dtor_enc(), (_14_dt__update__tmp_h2).Dtor_ctx(), _16_dt__update_hdec_h0, _15_dt__update_hpayload_h0)
								}(_pat_let82_0)
							}((_12_l).Dtor_dec())
						}(_pat_let81_0)
					}((_12_l).Dtor_payload())
				}(_pat_let80_0)
			}(s)
			_ = _13_s_k
			var _source2 Req = (_12_l).Dtor_req()
			_ = _source2
			{
				if _source2.Is_ReqFailed() {
					var _17_status _dafny.Int = _source2.Get_().(Req_ReqFailed).Status
					_ = _17_status
					var _18_code m_EHBP.Code = _source2.Get_().(Req_ReqFailed).Code
					_ = _18_code
					var _19_message _dafny.Sequence = _source2.Get_().(Req_ReqFailed).Message
					_ = _19_message
					if (_12_l).Dtor_payload() {
						return Companion_Default___.Derive(_13_s_k, (_12_l).Dtor_req(), (_12_l).Dtor_acts())
					} else {
						return Companion_Default___.Answer(_13_s_k, _17_status, _18_code, _19_message, Companion_Default___.ReadText())
					}
				}
			}
			{
				if _source2.Is_ReqDone() {
					if (_12_l).Dtor_payload() {
						return Companion_Default___.Derive(_13_s_k, Companion_Req_.Create_ReqDone_(), (_12_l).Dtor_acts())
					} else {
						return Companion_Default___.Answer(_13_s_k, _dafny.IntOfInt64(400), m_EHBP.Companion_Code_.Create_FramingTruncated_(), _dafny.UnicodeSeqOfUtf8Bytes("encrypted request ended before any plaintext"), Companion_Default___.ReadText())
					}
				}
			}
			{
				if _source2.Is_Waiting() {
					if (_12_l).Dtor_payload() {
						return Companion_Default___.Derive(_13_s_k, Companion_Req_.Create_Waiting_(), (_12_l).Dtor_acts())
					} else {
						return _dafny.TupleOf(func(_pat_let83_0 SState) SState {
							return func(_20_dt__update__tmp_h3 SState) SState {
								return func(_pat_let84_0 Phase) SState {
									return func(_21_dt__update_hphase_h2 Phase) SState {
										return Companion_SState_.Create_SState_(_21_dt__update_hphase_h2, (_20_dt__update__tmp_h3).Dtor_sk(), (_20_dt__update__tmp_h3).Dtor_pk(), (_20_dt__update__tmp_h3).Dtor_enc(), (_20_dt__update__tmp_h3).Dtor_ctx(), (_20_dt__update__tmp_h3).Dtor_dec(), (_20_dt__update__tmp_h3).Dtor_payload())
									}(_pat_let84_0)
								}(Companion_Phase_.Create_Peek_(Companion_Req_.Create_Reading_(_dafny.Zero)))
							}(_pat_let83_0)
						}(_13_s_k), _dafny.Companion_Sequence_.Concatenate((_12_l).Dtor_acts(), _dafny.SeqOf(Companion_SAction_.Create_Read_(m_EHBPEvents.Companion_Stream_.Create_RequestBody_()))))
					}
				}
			}
			{
				return _dafny.TupleOf(func(_pat_let85_0 SState) SState {
					return func(_22_dt__update__tmp_h4 SState) SState {
						return func(_pat_let86_0 Phase) SState {
							return func(_23_dt__update_hphase_h3 Phase) SState {
								return Companion_SState_.Create_SState_(_23_dt__update_hphase_h3, (_22_dt__update__tmp_h4).Dtor_sk(), (_22_dt__update__tmp_h4).Dtor_pk(), (_22_dt__update__tmp_h4).Dtor_enc(), (_22_dt__update__tmp_h4).Dtor_ctx(), (_22_dt__update__tmp_h4).Dtor_dec(), (_22_dt__update__tmp_h4).Dtor_payload())
							}(_pat_let86_0)
						}(Companion_Phase_.Create_Peek_((_12_l).Dtor_req()))
					}(_pat_let85_0)
				}(_13_s_k), (_12_l).Dtor_acts())
			}
		}
	}
	{
		if _source0.Is_Deriving() {
			var _24_stage _dafny.Int = _source0.Get_().(Phase_Deriving).Stage
			_ = _24_stage
			var _25_job m_EHBPEvents.Job = _source0.Get_().(Phase_Deriving).Job
			_ = _25_job
			var _26_req Req = _source0.Get_().(Phase_Deriving).Req
			_ = _26_req
			var _27_nonce _dafny.Sequence = _source0.Get_().(Phase_Deriving).Nonce
			_ = _27_nonce
			var _28_secret _dafny.Sequence = _source0.Get_().(Phase_Deriving).Secret
			_ = _28_secret
			var _29_prk _dafny.Sequence = _source0.Get_().(Phase_Deriving).Prk
			_ = _29_prk
			var _30_key _dafny.Sequence = _source0.Get_().(Phase_Deriving).Key
			_ = _30_key
			if (_24_stage).Cmp(_dafny.One) == 0 {
				if !((e).Is_RandomResult()) {
					return Companion_Default___.Answer(s, _dafny.IntOfInt64(500), m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event"), Companion_Default___.SetupText())
				} else if (_dafny.IntOfUint32(((e).Dtor_data()).Cardinality())).Cmp(m_EHBP.Companion_Default___.ResponseNonceLength()) != 0 {
					return Companion_Default___.Answer(s, _dafny.IntOfInt64(500), m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("random bytes have the wrong length"), Companion_Default___.SetupText())
				} else {
					var _31_next m_EHBPEvents.Job = m_EHBPEvents.Companion_Default___.Extract(_dafny.Companion_Sequence_.Concatenate((s).Dtor_enc(), (e).Dtor_data()), _28_secret)
					_ = _31_next
					return _dafny.TupleOf(func(_pat_let87_0 SState) SState {
						return func(_32_dt__update__tmp_h5 SState) SState {
							return func(_pat_let88_0 Phase) SState {
								return func(_33_dt__update_hphase_h4 Phase) SState {
									return Companion_SState_.Create_SState_(_33_dt__update_hphase_h4, (_32_dt__update__tmp_h5).Dtor_sk(), (_32_dt__update__tmp_h5).Dtor_pk(), (_32_dt__update__tmp_h5).Dtor_enc(), (_32_dt__update__tmp_h5).Dtor_ctx(), (_32_dt__update__tmp_h5).Dtor_dec(), (_32_dt__update__tmp_h5).Dtor_payload())
								}(_pat_let88_0)
							}(Companion_Phase_.Create_Deriving_(_dafny.IntOfInt64(2), _31_next, _26_req, (_pat_let_tv0).Dtor_data(), _28_secret, _dafny.SeqOf(), _dafny.SeqOf()))
						}(_pat_let87_0)
					}(s), _dafny.SeqOf(Companion_Default___.ToAction(m_EHBPEvents.Companion_Default___.JobAction(_31_next))))
				}
			} else {
				var _source3 m_EHBPEvents.JobOut = m_EHBPEvents.Companion_Default___.JobStep(_25_job, Companion_Default___.ToEvent(e))
				_ = _source3
				{
					if _source3.Is_JobFailed() {
						var _34_code m_EHBP.Code = _source3.Get_().(m_EHBPEvents.JobOut_JobFailed).Code
						_ = _34_code
						var _35_message _dafny.Sequence = _source3.Get_().(m_EHBPEvents.JobOut_JobFailed).Message
						_ = _35_message
						return Companion_Default___.Answer(s, _dafny.IntOfInt64(500), _34_code, _35_message, Companion_Default___.SetupText())
					}
				}
				{
					if _source3.Is_Pending() {
						var _36_next m_EHBPEvents.Job = _source3.Get_().(m_EHBPEvents.JobOut_Pending).Job
						_ = _36_next
						var _37_a m_EHBPEvents.Action = _source3.Get_().(m_EHBPEvents.JobOut_Pending).Action
						_ = _37_a
						return _dafny.TupleOf(func(_pat_let89_0 SState) SState {
							return func(_38_dt__update__tmp_h6 SState) SState {
								return func(_pat_let90_0 Phase) SState {
									return func(_39_dt__update_hphase_h5 Phase) SState {
										return Companion_SState_.Create_SState_(_39_dt__update_hphase_h5, (_38_dt__update__tmp_h6).Dtor_sk(), (_38_dt__update__tmp_h6).Dtor_pk(), (_38_dt__update__tmp_h6).Dtor_enc(), (_38_dt__update__tmp_h6).Dtor_ctx(), (_38_dt__update__tmp_h6).Dtor_dec(), (_38_dt__update__tmp_h6).Dtor_payload())
									}(_pat_let90_0)
								}(Companion_Phase_.Create_Deriving_(_24_stage, _36_next, _26_req, _27_nonce, _28_secret, _29_prk, _30_key))
							}(_pat_let89_0)
						}(s), _dafny.SeqOf(Companion_Default___.ToAction(_37_a)))
					}
				}
				{
					var _40_out _dafny.Sequence = _source3.Get_().(m_EHBPEvents.JobOut_Output).Data
					_ = _40_out
					if (_24_stage).Sign() == 0 {
						return _dafny.TupleOf(func(_pat_let91_0 SState) SState {
							return func(_41_dt__update__tmp_h7 SState) SState {
								return func(_pat_let92_0 Phase) SState {
									return func(_42_dt__update_hphase_h6 Phase) SState {
										return Companion_SState_.Create_SState_(_42_dt__update_hphase_h6, (_41_dt__update__tmp_h7).Dtor_sk(), (_41_dt__update__tmp_h7).Dtor_pk(), (_41_dt__update__tmp_h7).Dtor_enc(), (_41_dt__update__tmp_h7).Dtor_ctx(), (_41_dt__update__tmp_h7).Dtor_dec(), (_41_dt__update__tmp_h7).Dtor_payload())
									}(_pat_let92_0)
								}(Companion_Phase_.Create_Deriving_(_dafny.One, _25_job, _26_req, _27_nonce, _40_out, _dafny.SeqOf(), _dafny.SeqOf()))
							}(_pat_let91_0)
						}(s), _dafny.SeqOf(Companion_SAction_.Create_RandomBytes_(m_EHBP.Companion_Default___.ResponseNonceLength())))
					} else if (_24_stage).Cmp(_dafny.IntOfInt64(2)) == 0 {
						var _43_next m_EHBPEvents.Job = m_EHBPEvents.Companion_Default___.Expand(_40_out, m_EHBP.Companion_Default___.Ascii(m_EHBP.Companion_Default___.ResponseKeyLabel()), m_EHBP.Companion_Default___.KeyLength())
						_ = _43_next
						return _dafny.TupleOf(func(_pat_let93_0 SState) SState {
							return func(_44_dt__update__tmp_h8 SState) SState {
								return func(_pat_let94_0 Phase) SState {
									return func(_45_dt__update_hphase_h7 Phase) SState {
										return Companion_SState_.Create_SState_(_45_dt__update_hphase_h7, (_44_dt__update__tmp_h8).Dtor_sk(), (_44_dt__update__tmp_h8).Dtor_pk(), (_44_dt__update__tmp_h8).Dtor_enc(), (_44_dt__update__tmp_h8).Dtor_ctx(), (_44_dt__update__tmp_h8).Dtor_dec(), (_44_dt__update__tmp_h8).Dtor_payload())
									}(_pat_let94_0)
								}(Companion_Phase_.Create_Deriving_(_dafny.IntOfInt64(3), _43_next, _26_req, _27_nonce, _28_secret, _40_out, _dafny.SeqOf()))
							}(_pat_let93_0)
						}(s), _dafny.SeqOf(Companion_Default___.ToAction(m_EHBPEvents.Companion_Default___.JobAction(_43_next))))
					} else if (_24_stage).Cmp(_dafny.IntOfInt64(3)) == 0 {
						var _46_next m_EHBPEvents.Job = m_EHBPEvents.Companion_Default___.Expand(_29_prk, m_EHBP.Companion_Default___.Ascii(m_EHBP.Companion_Default___.ResponseNonceLabel()), m_EHBP.Companion_Default___.NonceLength())
						_ = _46_next
						return _dafny.TupleOf(func(_pat_let95_0 SState) SState {
							return func(_47_dt__update__tmp_h9 SState) SState {
								return func(_pat_let96_0 Phase) SState {
									return func(_48_dt__update_hphase_h8 Phase) SState {
										return Companion_SState_.Create_SState_(_48_dt__update_hphase_h8, (_47_dt__update__tmp_h9).Dtor_sk(), (_47_dt__update__tmp_h9).Dtor_pk(), (_47_dt__update__tmp_h9).Dtor_enc(), (_47_dt__update__tmp_h9).Dtor_ctx(), (_47_dt__update__tmp_h9).Dtor_dec(), (_47_dt__update__tmp_h9).Dtor_payload())
									}(_pat_let96_0)
								}(Companion_Phase_.Create_Deriving_(_dafny.IntOfInt64(4), _46_next, _26_req, _27_nonce, _28_secret, _29_prk, _40_out))
							}(_pat_let95_0)
						}(s), _dafny.SeqOf(Companion_Default___.ToAction(m_EHBPEvents.Companion_Default___.JobAction(_46_next))))
					} else if ((_dafny.IntOfUint32((_30_key).Cardinality())).Cmp(m_EHBP.Companion_Default___.KeyLength()) == 0) && ((_dafny.IntOfUint32((_40_out).Cardinality())).Cmp(m_EHBP.Companion_Default___.NonceLength()) == 0) {
						var _49_k _dafny.Sequence = _30_key
						_ = _49_k
						var _50_n _dafny.Sequence = _40_out
						_ = _50_n
						return _dafny.TupleOf(func(_pat_let97_0 SState) SState {
							return func(_51_dt__update__tmp_h10 SState) SState {
								return func(_pat_let98_0 Phase) SState {
									return func(_52_dt__update_hphase_h9 Phase) SState {
										return Companion_SState_.Create_SState_(_52_dt__update_hphase_h9, (_51_dt__update__tmp_h10).Dtor_sk(), (_51_dt__update__tmp_h10).Dtor_pk(), (_51_dt__update__tmp_h10).Dtor_enc(), (_51_dt__update__tmp_h10).Dtor_ctx(), (_51_dt__update__tmp_h10).Dtor_dec(), (_51_dt__update__tmp_h10).Dtor_payload())
									}(_pat_let98_0)
								}(Companion_Phase_.Create_Running_(_26_req, Companion_Resp_.Create_Resp_(m_EHBPEvents.Companion_Ctx_.Create_Ctx_(_49_k, _50_n, _dafny.SeqOf(), uint64(0)), _27_nonce, false, _dafny.Zero, false, Companion_Sealing_.Create_NoSeal_())))
							}(_pat_let97_0)
						}(s), _dafny.SeqOf(Companion_SAction_.Create_Dispatch_()))
					} else {
						return Companion_Default___.Answer(s, _dafny.IntOfInt64(500), m_EHBP.Companion_Code_.Create_HpkeSetupFailed_(), _dafny.UnicodeSeqOfUtf8Bytes("HKDF expand returned the wrong length"), Companion_Default___.SetupText())
					}
				}
			}
		}
	}
	{
		if _source0.Is_Running() {
			var _53_req Req = _source0.Get_().(Phase_Running).Req
			_ = _53_req
			var _54_resp Resp = _source0.Get_().(Phase_Running).Resp
			_ = _54_resp
			if Companion_Default___.ForRequest(e) {
				return Companion_Default___.StepRequest(s, _53_req, _54_resp, e)
			} else {
				return Companion_Default___.StepResponse(s, _53_req, _54_resp, e)
			}
		}
	}
	{
		return _dafny.TupleOf(s, (func() _dafny.Sequence {
			if (e).Is_HandlerRead() {
				return _dafny.SeqOf(Companion_SAction_.Create_Close_(m_EHBPEvents.Companion_Stream_.Create_RequestBody_()))
			}
			return _dafny.SeqOf()
		})())
	}
}
func (_static *CompanionStruct_Default___) StepStart(s SState, e SEvent) _dafny.Tuple {
	var _0_keys _dafny.Sequence = m_EHBP.Companion_Default___.HeaderValues((e).Dtor_headers(), m_EHBP.Companion_Default___.EncapsulatedKeyHeader())
	_ = _0_keys
	if (_dafny.IntOfUint32((_0_keys).Cardinality())).Sign() == 0 {
		return _dafny.TupleOf(func(_pat_let99_0 SState) SState {
			return func(_1_dt__update__tmp_h0 SState) SState {
				return func(_pat_let100_0 Phase) SState {
					return func(_2_dt__update_hphase_h0 Phase) SState {
						return Companion_SState_.Create_SState_(_2_dt__update_hphase_h0, (_1_dt__update__tmp_h0).Dtor_sk(), (_1_dt__update__tmp_h0).Dtor_pk(), (_1_dt__update__tmp_h0).Dtor_enc(), (_1_dt__update__tmp_h0).Dtor_ctx(), (_1_dt__update__tmp_h0).Dtor_dec(), (_1_dt__update__tmp_h0).Dtor_payload())
					}(_pat_let100_0)
				}(Companion_Phase_.Create_Ended_())
			}(_pat_let99_0)
		}(s), _dafny.SeqOf(Companion_SAction_.Create_PassRequest_()))
	} else if (_dafny.IntOfUint32((_0_keys).Cardinality())).Cmp(_dafny.One) > 0 {
		return Companion_Default___.Refuse(s, m_EHBP.Companion_Code_.Create_InvalidEncapsulatedKey_(), _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.UnicodeSeqOfUtf8Bytes("duplicate "), m_EHBP.Companion_Default___.EncapsulatedKeyHeader()), _dafny.UnicodeSeqOfUtf8Bytes(" header")))
	} else if _dafny.Companion_Sequence_.Equal((_0_keys).Select(0).(_dafny.Sequence), _dafny.UnicodeSeqOfUtf8Bytes("")) {
		return Companion_Default___.Refuse(s, m_EHBP.Companion_Code_.Create_InvalidEncapsulatedKey_(), _dafny.Companion_Sequence_.Concatenate(_dafny.Companion_Sequence_.Concatenate(_dafny.UnicodeSeqOfUtf8Bytes("missing "), m_EHBP.Companion_Default___.EncapsulatedKeyHeader()), _dafny.UnicodeSeqOfUtf8Bytes(" header")))
	} else {
		var _source0 m_EHBP.Option = m_EHBP.Companion_Default___.DecodeHex((_0_keys).Select(0).(_dafny.Sequence))
		_ = _source0
		{
			if _source0.Is_None() {
				return Companion_Default___.Refuse(s, m_EHBP.Companion_Code_.Create_InvalidEncapsulatedKey_(), _dafny.UnicodeSeqOfUtf8Bytes("invalid encapsulated key"))
			}
		}
		{
			var _3_enc _dafny.Sequence = _source0.Get_().(m_EHBP.Option_Some).Value.(_dafny.Sequence)
			_ = _3_enc
			if (_dafny.IntOfUint32((_3_enc).Cardinality())).Cmp(m_EHBP.Companion_Default___.RequestEncLength()) != 0 {
				return Companion_Default___.Refuse(s, m_EHBP.Companion_Code_.Create_InvalidEncapsulatedKey_(), _dafny.UnicodeSeqOfUtf8Bytes("encapsulated key has the wrong length"))
			} else if !((e).Dtor_hasBody()) {
				return Companion_Default___.Refuse(s, m_EHBP.Companion_Code_.Create_FramingTruncated_(), _dafny.UnicodeSeqOfUtf8Bytes("encrypted request has no frame"))
			} else {
				var _source1 m_EHBPEvents.HpkeOut = m_EHBPEvents.Companion_Default___.RecipientStart((s).Dtor_sk(), (s).Dtor_pk(), _3_enc, m_EHBP.Companion_Default___.Ascii(m_EHBP.Companion_Default___.HpkeRequestInfo()))
				_ = _source1
				{
					if _source1.Is_HContinue() {
						var _4_h m_EHBPEvents.Hpke = _source1.Get_().(m_EHBPEvents.HpkeOut_HContinue).H
						_ = _4_h
						var _5_a m_EHBPEvents.Action = _source1.Get_().(m_EHBPEvents.HpkeOut_HContinue).Action
						_ = _5_a
						return _dafny.TupleOf(func(_pat_let101_0 SState) SState {
							return func(_6_dt__update__tmp_h1 SState) SState {
								return func(_pat_let102_0 _dafny.Sequence) SState {
									return func(_7_dt__update_henc_h0 _dafny.Sequence) SState {
										return func(_pat_let103_0 Phase) SState {
											return func(_8_dt__update_hphase_h1 Phase) SState {
												return Companion_SState_.Create_SState_(_8_dt__update_hphase_h1, (_6_dt__update__tmp_h1).Dtor_sk(), (_6_dt__update__tmp_h1).Dtor_pk(), _7_dt__update_henc_h0, (_6_dt__update__tmp_h1).Dtor_ctx(), (_6_dt__update__tmp_h1).Dtor_dec(), (_6_dt__update__tmp_h1).Dtor_payload())
											}(_pat_let103_0)
										}(Companion_Phase_.Create_Decap_(_4_h))
									}(_pat_let102_0)
								}(_3_enc)
							}(_pat_let101_0)
						}(s), _dafny.SeqOf(Companion_Default___.ToAction(_5_a)))
					}
				}
				{
					return Companion_Default___.Answer(s, _dafny.IntOfInt64(500), m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event"), Companion_Default___.DecryptText())
				}
			}
		}
	}
}
func (_static *CompanionStruct_Default___) Derive(s SState, req Req, emits _dafny.Sequence) _dafny.Tuple {
	var _pat_let_tv0 = req
	_ = _pat_let_tv0
	var _0_job m_EHBPEvents.Job = m_EHBPEvents.Companion_Default___.ExportJob((s).Dtor_ctx(), m_EHBP.Companion_Default___.Ascii(m_EHBP.Companion_Default___.ExportLabel()), m_EHBP.Companion_Default___.ExportLength())
	_ = _0_job
	return _dafny.TupleOf(func(_pat_let104_0 SState) SState {
		return func(_1_dt__update__tmp_h0 SState) SState {
			return func(_pat_let105_0 Phase) SState {
				return func(_2_dt__update_hphase_h0 Phase) SState {
					return Companion_SState_.Create_SState_(_2_dt__update_hphase_h0, (_1_dt__update__tmp_h0).Dtor_sk(), (_1_dt__update__tmp_h0).Dtor_pk(), (_1_dt__update__tmp_h0).Dtor_enc(), (_1_dt__update__tmp_h0).Dtor_ctx(), (_1_dt__update__tmp_h0).Dtor_dec(), (_1_dt__update__tmp_h0).Dtor_payload())
				}(_pat_let105_0)
			}(Companion_Phase_.Create_Deriving_(_dafny.Zero, _0_job, _pat_let_tv0, _dafny.SeqOf(), _dafny.SeqOf(), _dafny.SeqOf(), _dafny.SeqOf()))
		}(_pat_let104_0)
	}(s), _dafny.Companion_Sequence_.Concatenate(emits, _dafny.SeqOf(Companion_Default___.ToAction(m_EHBPEvents.Companion_Default___.JobAction(_0_job)))))
}
func (_static *CompanionStruct_Default___) StepRequest(s SState, req Req, resp Resp, e SEvent) _dafny.Tuple {
	var _pat_let_tv0 = resp
	_ = _pat_let_tv0
	var _pat_let_tv1 = resp
	_ = _pat_let_tv1
	var _pat_let_tv2 = resp
	_ = _pat_let_tv2
	if (e).Is_HandlerRead() {
		var _source0 Req = req
		_ = _source0
		{
			if _source0.Is_Waiting() {
				return _dafny.TupleOf(func(_pat_let106_0 SState) SState {
					return func(_0_dt__update__tmp_h0 SState) SState {
						return func(_pat_let107_0 Phase) SState {
							return func(_1_dt__update_hphase_h0 Phase) SState {
								return Companion_SState_.Create_SState_(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).Dtor_sk(), (_0_dt__update__tmp_h0).Dtor_pk(), (_0_dt__update__tmp_h0).Dtor_enc(), (_0_dt__update__tmp_h0).Dtor_ctx(), (_0_dt__update__tmp_h0).Dtor_dec(), (_0_dt__update__tmp_h0).Dtor_payload())
							}(_pat_let107_0)
						}(Companion_Phase_.Create_Running_(Companion_Req_.Create_Reading_(_dafny.Zero), _pat_let_tv0))
					}(_pat_let106_0)
				}(s), _dafny.SeqOf(Companion_SAction_.Create_Read_(m_EHBPEvents.Companion_Stream_.Create_RequestBody_())))
			}
		}
		{
			if _source0.Is_ReqDone() {
				return _dafny.TupleOf(s, _dafny.SeqOf(Companion_SAction_.Create_Close_(m_EHBPEvents.Companion_Stream_.Create_RequestBody_())))
			}
		}
		{
			if _source0.Is_ReqFailed() {
				var _2_code m_EHBP.Code = _source0.Get_().(Req_ReqFailed).Code
				_ = _2_code
				var _3_message _dafny.Sequence = _source0.Get_().(Req_ReqFailed).Message
				_ = _3_message
				return _dafny.TupleOf(s, _dafny.SeqOf(Companion_SAction_.Create_Fail_(_2_code, _3_message)))
			}
		}
		{
			return _dafny.TupleOf(func(_pat_let108_0 SState) SState {
				return func(_4_dt__update__tmp_h1 SState) SState {
					return func(_pat_let109_0 Phase) SState {
						return func(_5_dt__update_hphase_h1 Phase) SState {
							return Companion_SState_.Create_SState_(_5_dt__update_hphase_h1, (_4_dt__update__tmp_h1).Dtor_sk(), (_4_dt__update__tmp_h1).Dtor_pk(), (_4_dt__update__tmp_h1).Dtor_enc(), (_4_dt__update__tmp_h1).Dtor_ctx(), (_4_dt__update__tmp_h1).Dtor_dec(), (_4_dt__update__tmp_h1).Dtor_payload())
						}(_pat_let109_0)
					}(Companion_Phase_.Create_Running_(Companion_Req_.Create_ReqFailed_(_dafny.IntOfInt64(400), m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event")), _pat_let_tv1))
				}(_pat_let108_0)
			}(s), _dafny.SeqOf(Companion_SAction_.Create_Fail_(m_EHBP.Companion_Code_.Create_Transport_(), _dafny.UnicodeSeqOfUtf8Bytes("unexpected event"))))
		}
	} else {
		var _6_l Lane = Companion_Default___.LaneStep(s, req, e)
		_ = _6_l
		var _7_s_k SState = func(_pat_let110_0 SState) SState {
			return func(_8_dt__update__tmp_h2 SState) SState {
				return func(_pat_let111_0 Phase) SState {
					return func(_9_dt__update_hphase_h2 Phase) SState {
						return func(_pat_let112_0 bool) SState {
							return func(_10_dt__update_hpayload_h0 bool) SState {
								return func(_pat_let113_0 m_EHBPEvents.Dec) SState {
									return func(_11_dt__update_hdec_h0 m_EHBPEvents.Dec) SState {
										return Companion_SState_.Create_SState_(_9_dt__update_hphase_h2, (_8_dt__update__tmp_h2).Dtor_sk(), (_8_dt__update__tmp_h2).Dtor_pk(), (_8_dt__update__tmp_h2).Dtor_enc(), (_8_dt__update__tmp_h2).Dtor_ctx(), _11_dt__update_hdec_h0, _10_dt__update_hpayload_h0)
									}(_pat_let113_0)
								}((_6_l).Dtor_dec())
							}(_pat_let112_0)
						}((_6_l).Dtor_payload())
					}(_pat_let111_0)
				}(Companion_Phase_.Create_Running_((_6_l).Dtor_req(), _pat_let_tv2))
			}(_pat_let110_0)
		}(s)
		_ = _7_s_k
		var _source1 Req = (_6_l).Dtor_req()
		_ = _source1
		{
			if _source1.Is_ReqFailed() {
				var _12_code m_EHBP.Code = _source1.Get_().(Req_ReqFailed).Code
				_ = _12_code
				var _13_message _dafny.Sequence = _source1.Get_().(Req_ReqFailed).Message
				_ = _13_message
				return _dafny.TupleOf(_7_s_k, _dafny.Companion_Sequence_.Concatenate((_6_l).Dtor_acts(), _dafny.SeqOf(Companion_SAction_.Create_Fail_(_12_code, _13_message))))
			}
		}
		{
			if _source1.Is_ReqDone() {
				return _dafny.TupleOf(_7_s_k, _dafny.Companion_Sequence_.Concatenate((_6_l).Dtor_acts(), _dafny.SeqOf(Companion_SAction_.Create_Close_(m_EHBPEvents.Companion_Stream_.Create_RequestBody_()))))
			}
		}
		{
			return _dafny.TupleOf(_7_s_k, (_6_l).Dtor_acts())
		}
	}
}
func (_static *CompanionStruct_Default___) StepResponse(s SState, req Req, resp Resp, e SEvent) _dafny.Tuple {
	var _pat_let_tv0 = req
	_ = _pat_let_tv0
	var _pat_let_tv1 = req
	_ = _pat_let_tv1
	var _pat_let_tv2 = req
	_ = _pat_let_tv2
	var _pat_let_tv3 = resp
	_ = _pat_let_tv3
	var _pat_let_tv4 = req
	_ = _pat_let_tv4
	var _pat_let_tv5 = req
	_ = _pat_let_tv5
	var _pat_let_tv6 = req
	_ = _pat_let_tv6
	var _source0 SEvent = e
	_ = _source0
	{
		if _source0.Is_HandlerHead() {
			var _0_status _dafny.Int = _source0.Get_().(SEvent_HandlerHead).Status
			_ = _0_status
			var _let_tmp_rhs0 _dafny.Tuple = Companion_Default___.Head(resp, _0_status)
			_ = _let_tmp_rhs0
			var _1_r Resp = (*(_let_tmp_rhs0).IndexInt(0)).(Resp)
			_ = _1_r
			var _2_acts _dafny.Sequence = (*(_let_tmp_rhs0).IndexInt(1)).(_dafny.Sequence)
			_ = _2_acts
			return _dafny.TupleOf(func(_pat_let114_0 SState) SState {
				return func(_3_dt__update__tmp_h0 SState) SState {
					return func(_pat_let115_0 Phase) SState {
						return func(_4_dt__update_hphase_h0 Phase) SState {
							return Companion_SState_.Create_SState_(_4_dt__update_hphase_h0, (_3_dt__update__tmp_h0).Dtor_sk(), (_3_dt__update__tmp_h0).Dtor_pk(), (_3_dt__update__tmp_h0).Dtor_enc(), (_3_dt__update__tmp_h0).Dtor_ctx(), (_3_dt__update__tmp_h0).Dtor_dec(), (_3_dt__update__tmp_h0).Dtor_payload())
						}(_pat_let115_0)
					}(Companion_Phase_.Create_Running_(_pat_let_tv0, _1_r))
				}(_pat_let114_0)
			}(s), _2_acts)
		}
	}
	{
		if _source0.Is_HandlerChunk() {
			var _5_data _dafny.Sequence = _source0.Get_().(SEvent_HandlerChunk).Data
			_ = _5_data
			if (!(((resp).Dtor_seal()).Is_NoSeal())) || ((_dafny.IntOfUint32((_5_data).Cardinality())).Cmp(m_EHBPEvents.Companion_Default___.MaxReadBytes()) > 0) {
				return Companion_Default___.AbortResponse(s, m_EHBP.Companion_Code_.Create_Transport_())
			} else {
				var _let_tmp_rhs1 _dafny.Tuple = Companion_Default___.Head(resp, _dafny.IntOfInt64(200))
				_ = _let_tmp_rhs1
				var _6_r Resp = (*(_let_tmp_rhs1).IndexInt(0)).(Resp)
				_ = _6_r
				var _7_acts _dafny.Sequence = (*(_let_tmp_rhs1).IndexInt(1)).(_dafny.Sequence)
				_ = _7_acts
				if (_dafny.IntOfUint32((_5_data).Cardinality())).Sign() == 0 {
					return _dafny.TupleOf(func(_pat_let116_0 SState) SState {
						return func(_8_dt__update__tmp_h1 SState) SState {
							return func(_pat_let117_0 Phase) SState {
								return func(_9_dt__update_hphase_h1 Phase) SState {
									return Companion_SState_.Create_SState_(_9_dt__update_hphase_h1, (_8_dt__update__tmp_h1).Dtor_sk(), (_8_dt__update__tmp_h1).Dtor_pk(), (_8_dt__update__tmp_h1).Dtor_enc(), (_8_dt__update__tmp_h1).Dtor_ctx(), (_8_dt__update__tmp_h1).Dtor_dec(), (_8_dt__update__tmp_h1).Dtor_payload())
								}(_pat_let117_0)
							}(Companion_Phase_.Create_Running_(_pat_let_tv1, _6_r))
						}(_pat_let116_0)
					}(s), _7_acts)
				} else {
					var _let_tmp_rhs2 _dafny.Tuple = Companion_Default___.SealNext(_6_r, _5_data, uint32(0), false)
					_ = _let_tmp_rhs2
					var _10_r2 Resp = (*(_let_tmp_rhs2).IndexInt(0)).(Resp)
					_ = _10_r2
					var _11_acts2 _dafny.Sequence = (*(_let_tmp_rhs2).IndexInt(1)).(_dafny.Sequence)
					_ = _11_acts2
					return _dafny.TupleOf(func(_pat_let118_0 SState) SState {
						return func(_12_dt__update__tmp_h2 SState) SState {
							return func(_pat_let119_0 Phase) SState {
								return func(_13_dt__update_hphase_h2 Phase) SState {
									return Companion_SState_.Create_SState_(_13_dt__update_hphase_h2, (_12_dt__update__tmp_h2).Dtor_sk(), (_12_dt__update__tmp_h2).Dtor_pk(), (_12_dt__update__tmp_h2).Dtor_enc(), (_12_dt__update__tmp_h2).Dtor_ctx(), (_12_dt__update__tmp_h2).Dtor_dec(), (_12_dt__update__tmp_h2).Dtor_payload())
								}(_pat_let119_0)
							}(Companion_Phase_.Create_Running_(_pat_let_tv2, _10_r2))
						}(_pat_let118_0)
					}(s), _dafny.Companion_Sequence_.Concatenate(_7_acts, _11_acts2))
				}
			}
		}
	}
	{
		if _source0.Is_AeadSealResult() {
			var _14_ct _dafny.Sequence = _source0.Get_().(SEvent_AeadSealResult).Ciphertext
			_ = _14_ct
			var _source1 Sealing = (resp).Dtor_seal()
			_ = _source1
			{
				if _source1.Is_Sealing() {
					var _15_plaintext _dafny.Sequence = _source1.Get_().(Sealing_Sealing).Plaintext
					_ = _15_plaintext
					var _16_offset uint32 = _source1.Get_().(Sealing_Sealing).Offset
					_ = _16_offset
					var _17_final bool = _source1.Get_().(Sealing_Sealing).Final
					_ = _17_final
					var _18_size uint32 = uint32((_15_plaintext).Cardinality())
					_ = _18_size
					var _19_at uint32 = m_EHBPEvents.Companion_Default___.Min32(_16_offset, _18_size)
					_ = _19_at
					var _20_n uint32 = m_EHBPEvents.Companion_Default___.Min32((_18_size)-(func() uint32 { return (_19_at) })(), m_EHBP.Companion_Default___.RequestFrameBytes())
					_ = _20_n
					if (_dafny.IntOfUint32((_14_ct).Cardinality())).Cmp((_dafny.IntOfUint32(_20_n)).Plus(m_EHBP.Companion_Default___.AeadTagLength())) != 0 {
						return Companion_Default___.AbortResponse(s, m_EHBP.Companion_Code_.Create_HpkeSetupFailed_())
					} else if (((resp).Dtor_keys()).Dtor_seqNo()) == (m_EHBPEvents.Companion_Default___.MaxSeq()) {
						return Companion_Default___.AbortResponse(s, m_EHBP.Companion_Code_.Create_SequenceOverflow_())
					} else {
						var _21_bumped Resp = func(_pat_let120_0 Resp) Resp {
							return func(_22_dt__update__tmp_h3 Resp) Resp {
								return func(_pat_let121_0 Sealing) Resp {
									return func(_23_dt__update_hseal_h0 Sealing) Resp {
										return func(_pat_let122_0 bool) Resp {
											return func(_24_dt__update_hframed_h0 bool) Resp {
												return func(_pat_let123_0 m_EHBPEvents.Ctx) Resp {
													return func(_25_dt__update_hkeys_h0 m_EHBPEvents.Ctx) Resp {
														return Companion_Resp_.Create_Resp_(_25_dt__update_hkeys_h0, (_22_dt__update__tmp_h3).Dtor_nonce(), (_22_dt__update__tmp_h3).Dtor_started(), (_22_dt__update__tmp_h3).Dtor_status(), _24_dt__update_hframed_h0, _23_dt__update_hseal_h0)
													}(_pat_let123_0)
												}(m_EHBPEvents.Companion_Default___.Bump((_pat_let_tv3).Dtor_keys()))
											}(_pat_let122_0)
										}(true)
									}(_pat_let121_0)
								}(Companion_Sealing_.Create_NoSeal_())
							}(_pat_let120_0)
						}(resp)
						_ = _21_bumped
						var _26_frame SAction = Companion_SAction_.Create_Write_(m_EHBP.Companion_Default___.Frame(_14_ct), m_EHBPEvents.Companion_BodyEnd_.Create_More_())
						_ = _26_frame
						if ((_19_at) + (_20_n)) < (_18_size) {
							var _let_tmp_rhs3 _dafny.Tuple = Companion_Default___.SealNext(_21_bumped, _15_plaintext, (_19_at)+(_20_n), _17_final)
							_ = _let_tmp_rhs3
							var _27_r Resp = (*(_let_tmp_rhs3).IndexInt(0)).(Resp)
							_ = _27_r
							var _28_acts _dafny.Sequence = (*(_let_tmp_rhs3).IndexInt(1)).(_dafny.Sequence)
							_ = _28_acts
							return _dafny.TupleOf(func(_pat_let124_0 SState) SState {
								return func(_29_dt__update__tmp_h4 SState) SState {
									return func(_pat_let125_0 Phase) SState {
										return func(_30_dt__update_hphase_h3 Phase) SState {
											return Companion_SState_.Create_SState_(_30_dt__update_hphase_h3, (_29_dt__update__tmp_h4).Dtor_sk(), (_29_dt__update__tmp_h4).Dtor_pk(), (_29_dt__update__tmp_h4).Dtor_enc(), (_29_dt__update__tmp_h4).Dtor_ctx(), (_29_dt__update__tmp_h4).Dtor_dec(), (_29_dt__update__tmp_h4).Dtor_payload())
										}(_pat_let125_0)
									}(Companion_Phase_.Create_Running_(_pat_let_tv4, _27_r))
								}(_pat_let124_0)
							}(s), _dafny.Companion_Sequence_.Concatenate(_dafny.SeqOf(_26_frame), _28_acts))
						} else if _17_final {
							return _dafny.TupleOf(func(_pat_let126_0 SState) SState {
								return func(_31_dt__update__tmp_h5 SState) SState {
									return func(_pat_let127_0 Phase) SState {
										return func(_32_dt__update_hphase_h4 Phase) SState {
											return Companion_SState_.Create_SState_(_32_dt__update_hphase_h4, (_31_dt__update__tmp_h5).Dtor_sk(), (_31_dt__update__tmp_h5).Dtor_pk(), (_31_dt__update__tmp_h5).Dtor_enc(), (_31_dt__update__tmp_h5).Dtor_ctx(), (_31_dt__update__tmp_h5).Dtor_dec(), (_31_dt__update__tmp_h5).Dtor_payload())
										}(_pat_let127_0)
									}(Companion_Phase_.Create_Ended_())
								}(_pat_let126_0)
							}(s), _dafny.SeqOf(_26_frame, Companion_SAction_.Create_Close_(m_EHBPEvents.Companion_Stream_.Create_ResponseBody_())))
						} else {
							return _dafny.TupleOf(func(_pat_let128_0 SState) SState {
								return func(_33_dt__update__tmp_h6 SState) SState {
									return func(_pat_let129_0 Phase) SState {
										return func(_34_dt__update_hphase_h5 Phase) SState {
											return Companion_SState_.Create_SState_(_34_dt__update_hphase_h5, (_33_dt__update__tmp_h6).Dtor_sk(), (_33_dt__update__tmp_h6).Dtor_pk(), (_33_dt__update__tmp_h6).Dtor_enc(), (_33_dt__update__tmp_h6).Dtor_ctx(), (_33_dt__update__tmp_h6).Dtor_dec(), (_33_dt__update__tmp_h6).Dtor_payload())
										}(_pat_let129_0)
									}(Companion_Phase_.Create_Running_(_pat_let_tv5, _21_bumped))
								}(_pat_let128_0)
							}(s), _dafny.SeqOf(_26_frame))
						}
					}
				}
			}
			{
				return Companion_Default___.AbortResponse(s, m_EHBP.Companion_Code_.Create_Transport_())
			}
		}
	}
	{
		if _source0.Is_HandlerDone() {
			if !(((resp).Dtor_seal()).Is_NoSeal()) {
				return Companion_Default___.AbortResponse(s, m_EHBP.Companion_Code_.Create_Transport_())
			} else {
				var _source2 Req = req
				_ = _source2
				{
					if _source2.Is_ReqFailed() {
						var _35_status _dafny.Int = _source2.Get_().(Req_ReqFailed).Status
						_ = _35_status
						var _36_code m_EHBP.Code = _source2.Get_().(Req_ReqFailed).Code
						_ = _36_code
						var _37_message _dafny.Sequence = _source2.Get_().(Req_ReqFailed).Message
						_ = _37_message
						if (resp).Dtor_started() {
							return Companion_Default___.AbortResponse(s, _36_code)
						} else {
							return Companion_Default___.Answer(s, _35_status, _36_code, _37_message, Companion_Default___.ReadText())
						}
					}
				}
				{
					var _let_tmp_rhs4 _dafny.Tuple = Companion_Default___.Head(resp, _dafny.IntOfInt64(200))
					_ = _let_tmp_rhs4
					var _38_r Resp = (*(_let_tmp_rhs4).IndexInt(0)).(Resp)
					_ = _38_r
					var _39_acts _dafny.Sequence = (*(_let_tmp_rhs4).IndexInt(1)).(_dafny.Sequence)
					_ = _39_acts
					if (((_38_r).Dtor_framed()) || (((_38_r).Dtor_status()).Cmp(_dafny.IntOfInt64(101)) == 0)) || (((_38_r).Dtor_status()).Cmp(_dafny.IntOfInt64(304)) == 0) {
						return _dafny.TupleOf(func(_pat_let130_0 SState) SState {
							return func(_40_dt__update__tmp_h7 SState) SState {
								return func(_pat_let131_0 Phase) SState {
									return func(_41_dt__update_hphase_h6 Phase) SState {
										return Companion_SState_.Create_SState_(_41_dt__update_hphase_h6, (_40_dt__update__tmp_h7).Dtor_sk(), (_40_dt__update__tmp_h7).Dtor_pk(), (_40_dt__update__tmp_h7).Dtor_enc(), (_40_dt__update__tmp_h7).Dtor_ctx(), (_40_dt__update__tmp_h7).Dtor_dec(), (_40_dt__update__tmp_h7).Dtor_payload())
									}(_pat_let131_0)
								}(Companion_Phase_.Create_Ended_())
							}(_pat_let130_0)
						}(s), _dafny.Companion_Sequence_.Concatenate(_39_acts, _dafny.SeqOf(Companion_SAction_.Create_Close_(m_EHBPEvents.Companion_Stream_.Create_ResponseBody_()))))
					} else {
						var _let_tmp_rhs5 _dafny.Tuple = Companion_Default___.SealNext(_38_r, _dafny.SeqOf(), uint32(0), true)
						_ = _let_tmp_rhs5
						var _42_r2 Resp = (*(_let_tmp_rhs5).IndexInt(0)).(Resp)
						_ = _42_r2
						var _43_acts2 _dafny.Sequence = (*(_let_tmp_rhs5).IndexInt(1)).(_dafny.Sequence)
						_ = _43_acts2
						return _dafny.TupleOf(func(_pat_let132_0 SState) SState {
							return func(_44_dt__update__tmp_h8 SState) SState {
								return func(_pat_let133_0 Phase) SState {
									return func(_45_dt__update_hphase_h7 Phase) SState {
										return Companion_SState_.Create_SState_(_45_dt__update_hphase_h7, (_44_dt__update__tmp_h8).Dtor_sk(), (_44_dt__update__tmp_h8).Dtor_pk(), (_44_dt__update__tmp_h8).Dtor_enc(), (_44_dt__update__tmp_h8).Dtor_ctx(), (_44_dt__update__tmp_h8).Dtor_dec(), (_44_dt__update__tmp_h8).Dtor_payload())
									}(_pat_let133_0)
								}(Companion_Phase_.Create_Running_(_pat_let_tv6, _42_r2))
							}(_pat_let132_0)
						}(s), _dafny.Companion_Sequence_.Concatenate(_39_acts, _43_acts2))
					}
				}
			}
		}
	}
	{
		return Companion_Default___.AbortResponse(s, m_EHBP.Companion_Code_.Create_Transport_())
	}
}
func (_static *CompanionStruct_Default___) DecryptText() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("failed to decrypt request")
}
func (_static *CompanionStruct_Default___) TextHeaders() _dafny.Sequence {
	return _dafny.SeqOf(_dafny.TupleOf(_dafny.UnicodeSeqOfUtf8Bytes("Content-Type"), _dafny.UnicodeSeqOfUtf8Bytes("text/plain; charset=utf-8")), _dafny.TupleOf(_dafny.UnicodeSeqOfUtf8Bytes("X-Content-Type-Options"), _dafny.UnicodeSeqOfUtf8Bytes("nosniff")))
}
func (_static *CompanionStruct_Default___) ReadText() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("failed to read decrypted request body")
}
func (_static *CompanionStruct_Default___) SetupText() _dafny.Sequence {
	return _dafny.UnicodeSeqOfUtf8Bytes("failed to setup response encryption")
}

// End of class Default__

// Definition of datatype SEvent
type SEvent struct {
	Data_SEvent_
}

func (_this SEvent) Get_() Data_SEvent_ {
	return _this.Data_SEvent_
}

type Data_SEvent_ interface {
	isSEvent()
}

type CompanionStruct_SEvent_ struct {
}

var Companion_SEvent_ = CompanionStruct_SEvent_{}

type SEvent_RequestStart struct {
	Headers _dafny.Sequence
	HasBody bool
}

func (SEvent_RequestStart) isSEvent() {}

func (CompanionStruct_SEvent_) Create_RequestStart_(Headers _dafny.Sequence, HasBody bool) SEvent {
	return SEvent{SEvent_RequestStart{Headers, HasBody}}
}

func (_this SEvent) Is_RequestStart() bool {
	_, ok := _this.Get_().(SEvent_RequestStart)
	return ok
}

type SEvent_RandomResult struct {
	Data _dafny.Sequence
}

func (SEvent_RandomResult) isSEvent() {}

func (CompanionStruct_SEvent_) Create_RandomResult_(Data _dafny.Sequence) SEvent {
	return SEvent{SEvent_RandomResult{Data}}
}

func (_this SEvent) Is_RandomResult() bool {
	_, ok := _this.Get_().(SEvent_RandomResult)
	return ok
}

type SEvent_X25519Result struct {
	Point _dafny.Sequence
}

func (SEvent_X25519Result) isSEvent() {}

func (CompanionStruct_SEvent_) Create_X25519Result_(Point _dafny.Sequence) SEvent {
	return SEvent{SEvent_X25519Result{Point}}
}

func (_this SEvent) Is_X25519Result() bool {
	_, ok := _this.Get_().(SEvent_X25519Result)
	return ok
}

type SEvent_HmacResult struct {
	Mac _dafny.Sequence
}

func (SEvent_HmacResult) isSEvent() {}

func (CompanionStruct_SEvent_) Create_HmacResult_(Mac _dafny.Sequence) SEvent {
	return SEvent{SEvent_HmacResult{Mac}}
}

func (_this SEvent) Is_HmacResult() bool {
	_, ok := _this.Get_().(SEvent_HmacResult)
	return ok
}

type SEvent_AeadSealResult struct {
	Ciphertext _dafny.Sequence
}

func (SEvent_AeadSealResult) isSEvent() {}

func (CompanionStruct_SEvent_) Create_AeadSealResult_(Ciphertext _dafny.Sequence) SEvent {
	return SEvent{SEvent_AeadSealResult{Ciphertext}}
}

func (_this SEvent) Is_AeadSealResult() bool {
	_, ok := _this.Get_().(SEvent_AeadSealResult)
	return ok
}

type SEvent_AeadOpenResult struct {
	Ok        bool
	Plaintext _dafny.Sequence
}

func (SEvent_AeadOpenResult) isSEvent() {}

func (CompanionStruct_SEvent_) Create_AeadOpenResult_(Ok bool, Plaintext _dafny.Sequence) SEvent {
	return SEvent{SEvent_AeadOpenResult{Ok, Plaintext}}
}

func (_this SEvent) Is_AeadOpenResult() bool {
	_, ok := _this.Get_().(SEvent_AeadOpenResult)
	return ok
}

type SEvent_Chunk struct {
	Data _dafny.Sequence
	Eof  bool
}

func (SEvent_Chunk) isSEvent() {}

func (CompanionStruct_SEvent_) Create_Chunk_(Data _dafny.Sequence, Eof bool) SEvent {
	return SEvent{SEvent_Chunk{Data, Eof}}
}

func (_this SEvent) Is_Chunk() bool {
	_, ok := _this.Get_().(SEvent_Chunk)
	return ok
}

type SEvent_StreamFailed struct {
}

func (SEvent_StreamFailed) isSEvent() {}

func (CompanionStruct_SEvent_) Create_StreamFailed_() SEvent {
	return SEvent{SEvent_StreamFailed{}}
}

func (_this SEvent) Is_StreamFailed() bool {
	_, ok := _this.Get_().(SEvent_StreamFailed)
	return ok
}

type SEvent_HandlerRead struct {
}

func (SEvent_HandlerRead) isSEvent() {}

func (CompanionStruct_SEvent_) Create_HandlerRead_() SEvent {
	return SEvent{SEvent_HandlerRead{}}
}

func (_this SEvent) Is_HandlerRead() bool {
	_, ok := _this.Get_().(SEvent_HandlerRead)
	return ok
}

type SEvent_HandlerHead struct {
	Status _dafny.Int
}

func (SEvent_HandlerHead) isSEvent() {}

func (CompanionStruct_SEvent_) Create_HandlerHead_(Status _dafny.Int) SEvent {
	return SEvent{SEvent_HandlerHead{Status}}
}

func (_this SEvent) Is_HandlerHead() bool {
	_, ok := _this.Get_().(SEvent_HandlerHead)
	return ok
}

type SEvent_HandlerChunk struct {
	Data _dafny.Sequence
}

func (SEvent_HandlerChunk) isSEvent() {}

func (CompanionStruct_SEvent_) Create_HandlerChunk_(Data _dafny.Sequence) SEvent {
	return SEvent{SEvent_HandlerChunk{Data}}
}

func (_this SEvent) Is_HandlerChunk() bool {
	_, ok := _this.Get_().(SEvent_HandlerChunk)
	return ok
}

type SEvent_HandlerDone struct {
}

func (SEvent_HandlerDone) isSEvent() {}

func (CompanionStruct_SEvent_) Create_HandlerDone_() SEvent {
	return SEvent{SEvent_HandlerDone{}}
}

func (_this SEvent) Is_HandlerDone() bool {
	_, ok := _this.Get_().(SEvent_HandlerDone)
	return ok
}

func (CompanionStruct_SEvent_) Default() SEvent {
	return Companion_SEvent_.Create_RequestStart_(_dafny.EmptySeq, false)
}

func (_this SEvent) Dtor_headers() _dafny.Sequence {
	return _this.Get_().(SEvent_RequestStart).Headers
}

func (_this SEvent) Dtor_hasBody() bool {
	return _this.Get_().(SEvent_RequestStart).HasBody
}

func (_this SEvent) Dtor_data() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case SEvent_RandomResult:
		return data.Data
	case SEvent_Chunk:
		return data.Data
	default:
		return data.(SEvent_HandlerChunk).Data
	}
}

func (_this SEvent) Dtor_point() _dafny.Sequence {
	return _this.Get_().(SEvent_X25519Result).Point
}

func (_this SEvent) Dtor_mac() _dafny.Sequence {
	return _this.Get_().(SEvent_HmacResult).Mac
}

func (_this SEvent) Dtor_ciphertext() _dafny.Sequence {
	return _this.Get_().(SEvent_AeadSealResult).Ciphertext
}

func (_this SEvent) Dtor_ok() bool {
	return _this.Get_().(SEvent_AeadOpenResult).Ok
}

func (_this SEvent) Dtor_plaintext() _dafny.Sequence {
	return _this.Get_().(SEvent_AeadOpenResult).Plaintext
}

func (_this SEvent) Dtor_eof() bool {
	return _this.Get_().(SEvent_Chunk).Eof
}

func (_this SEvent) Dtor_status() _dafny.Int {
	return _this.Get_().(SEvent_HandlerHead).Status
}

func (_this SEvent) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case SEvent_RequestStart:
		{
			return "EHBPServer.SEvent.RequestStart" + "(" + _dafny.String(data.Headers) + ", " + _dafny.String(data.HasBody) + ")"
		}
	case SEvent_RandomResult:
		{
			return "EHBPServer.SEvent.RandomResult" + "(" + _dafny.String(data.Data) + ")"
		}
	case SEvent_X25519Result:
		{
			_ = data
			return "EHBPServer.SEvent.X25519Result(<redacted>)"
		}
	case SEvent_HmacResult:
		{
			_ = data
			return "EHBPServer.SEvent.HmacResult(<redacted>)"
		}
	case SEvent_AeadSealResult:
		{
			return "EHBPServer.SEvent.AeadSealResult" + "(" + _dafny.String(data.Ciphertext) + ")"
		}
	case SEvent_AeadOpenResult:
		{
			return "EHBPServer.SEvent.AeadOpenResult" + "(" + _dafny.String(data.Ok) + ", " + _dafny.String(data.Plaintext) + ")"
		}
	case SEvent_Chunk:
		{
			return "EHBPServer.SEvent.Chunk" + "(" + _dafny.String(data.Data) + ", " + _dafny.String(data.Eof) + ")"
		}
	case SEvent_StreamFailed:
		{
			return "EHBPServer.SEvent.StreamFailed"
		}
	case SEvent_HandlerRead:
		{
			return "EHBPServer.SEvent.HandlerRead"
		}
	case SEvent_HandlerHead:
		{
			return "EHBPServer.SEvent.HandlerHead" + "(" + _dafny.String(data.Status) + ")"
		}
	case SEvent_HandlerChunk:
		{
			return "EHBPServer.SEvent.HandlerChunk" + "(" + _dafny.String(data.Data) + ")"
		}
	case SEvent_HandlerDone:
		{
			return "EHBPServer.SEvent.HandlerDone"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this SEvent) Equals(other SEvent) bool {
	switch data1 := _this.Get_().(type) {
	case SEvent_RequestStart:
		{
			data2, ok := other.Get_().(SEvent_RequestStart)
			return ok && data1.Headers.Equals(data2.Headers) && data1.HasBody == data2.HasBody
		}
	case SEvent_RandomResult:
		{
			data2, ok := other.Get_().(SEvent_RandomResult)
			return ok && data1.Data.Equals(data2.Data)
		}
	case SEvent_X25519Result:
		{
			data2, ok := other.Get_().(SEvent_X25519Result)
			return ok && data1.Point.Equals(data2.Point)
		}
	case SEvent_HmacResult:
		{
			data2, ok := other.Get_().(SEvent_HmacResult)
			return ok && data1.Mac.Equals(data2.Mac)
		}
	case SEvent_AeadSealResult:
		{
			data2, ok := other.Get_().(SEvent_AeadSealResult)
			return ok && data1.Ciphertext.Equals(data2.Ciphertext)
		}
	case SEvent_AeadOpenResult:
		{
			data2, ok := other.Get_().(SEvent_AeadOpenResult)
			return ok && data1.Ok == data2.Ok && data1.Plaintext.Equals(data2.Plaintext)
		}
	case SEvent_Chunk:
		{
			data2, ok := other.Get_().(SEvent_Chunk)
			return ok && data1.Data.Equals(data2.Data) && data1.Eof == data2.Eof
		}
	case SEvent_StreamFailed:
		{
			_, ok := other.Get_().(SEvent_StreamFailed)
			return ok
		}
	case SEvent_HandlerRead:
		{
			_, ok := other.Get_().(SEvent_HandlerRead)
			return ok
		}
	case SEvent_HandlerHead:
		{
			data2, ok := other.Get_().(SEvent_HandlerHead)
			return ok && data1.Status.Cmp(data2.Status) == 0
		}
	case SEvent_HandlerChunk:
		{
			data2, ok := other.Get_().(SEvent_HandlerChunk)
			return ok && data1.Data.Equals(data2.Data)
		}
	case SEvent_HandlerDone:
		{
			_, ok := other.Get_().(SEvent_HandlerDone)
			return ok
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this SEvent) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(SEvent)
	return ok && _this.Equals(typed)
}

func Type_SEvent_() _dafny.TypeDescriptor {
	return type_SEvent_{}
}

type type_SEvent_ struct {
}

func (_this type_SEvent_) Default() interface{} {
	return Companion_SEvent_.Default()
}

func (_this type_SEvent_) String() string {
	return "EHBPServer.SEvent"
}
func (_this SEvent) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = SEvent{}

// End of datatype SEvent

// Definition of datatype SAction
type SAction struct {
	Data_SAction_
}

func (_this SAction) Get_() Data_SAction_ {
	return _this.Data_SAction_
}

type Data_SAction_ interface {
	isSAction()
}

type CompanionStruct_SAction_ struct {
}

var Companion_SAction_ = CompanionStruct_SAction_{}

type SAction_RandomBytes struct {
	Length _dafny.Int
}

func (SAction_RandomBytes) isSAction() {}

func (CompanionStruct_SAction_) Create_RandomBytes_(Length _dafny.Int) SAction {
	return SAction{SAction_RandomBytes{Length}}
}

func (_this SAction) Is_RandomBytes() bool {
	_, ok := _this.Get_().(SAction_RandomBytes)
	return ok
}

type SAction_X25519 struct {
	Scalar _dafny.Sequence
	Point  _dafny.Sequence
}

func (SAction_X25519) isSAction() {}

func (CompanionStruct_SAction_) Create_X25519_(Scalar _dafny.Sequence, Point _dafny.Sequence) SAction {
	return SAction{SAction_X25519{Scalar, Point}}
}

func (_this SAction) Is_X25519() bool {
	_, ok := _this.Get_().(SAction_X25519)
	return ok
}

type SAction_HmacSha256 struct {
	Key  _dafny.Sequence
	Data _dafny.Sequence
}

func (SAction_HmacSha256) isSAction() {}

func (CompanionStruct_SAction_) Create_HmacSha256_(Key _dafny.Sequence, Data _dafny.Sequence) SAction {
	return SAction{SAction_HmacSha256{Key, Data}}
}

func (_this SAction) Is_HmacSha256() bool {
	_, ok := _this.Get_().(SAction_HmacSha256)
	return ok
}

type SAction_AeadSeal struct {
	Key       _dafny.Sequence
	Nonce     _dafny.Sequence
	Plaintext _dafny.Sequence
}

func (SAction_AeadSeal) isSAction() {}

func (CompanionStruct_SAction_) Create_AeadSeal_(Key _dafny.Sequence, Nonce _dafny.Sequence, Plaintext _dafny.Sequence) SAction {
	return SAction{SAction_AeadSeal{Key, Nonce, Plaintext}}
}

func (_this SAction) Is_AeadSeal() bool {
	_, ok := _this.Get_().(SAction_AeadSeal)
	return ok
}

type SAction_AeadOpen struct {
	Key        _dafny.Sequence
	Nonce      _dafny.Sequence
	Ciphertext _dafny.Sequence
}

func (SAction_AeadOpen) isSAction() {}

func (CompanionStruct_SAction_) Create_AeadOpen_(Key _dafny.Sequence, Nonce _dafny.Sequence, Ciphertext _dafny.Sequence) SAction {
	return SAction{SAction_AeadOpen{Key, Nonce, Ciphertext}}
}

func (_this SAction) Is_AeadOpen() bool {
	_, ok := _this.Get_().(SAction_AeadOpen)
	return ok
}

type SAction_PassRequest struct {
}

func (SAction_PassRequest) isSAction() {}

func (CompanionStruct_SAction_) Create_PassRequest_() SAction {
	return SAction{SAction_PassRequest{}}
}

func (_this SAction) Is_PassRequest() bool {
	_, ok := _this.Get_().(SAction_PassRequest)
	return ok
}

type SAction_Respond struct {
	Status  _dafny.Int
	Code    m_EHBP.Code
	Message _dafny.Sequence
	Headers _dafny.Sequence
	Body    _dafny.Sequence
}

func (SAction_Respond) isSAction() {}

func (CompanionStruct_SAction_) Create_Respond_(Status _dafny.Int, Code m_EHBP.Code, Message _dafny.Sequence, Headers _dafny.Sequence, Body _dafny.Sequence) SAction {
	return SAction{SAction_Respond{Status, Code, Message, Headers, Body}}
}

func (_this SAction) Is_Respond() bool {
	_, ok := _this.Get_().(SAction_Respond)
	return ok
}

type SAction_Read struct {
	Stream m_EHBPEvents.Stream
}

func (SAction_Read) isSAction() {}

func (CompanionStruct_SAction_) Create_Read_(Stream m_EHBPEvents.Stream) SAction {
	return SAction{SAction_Read{Stream}}
}

func (_this SAction) Is_Read() bool {
	_, ok := _this.Get_().(SAction_Read)
	return ok
}

type SAction_EmitPlaintext struct {
	Data _dafny.Sequence
}

func (SAction_EmitPlaintext) isSAction() {}

func (CompanionStruct_SAction_) Create_EmitPlaintext_(Data _dafny.Sequence) SAction {
	return SAction{SAction_EmitPlaintext{Data}}
}

func (_this SAction) Is_EmitPlaintext() bool {
	_, ok := _this.Get_().(SAction_EmitPlaintext)
	return ok
}

type SAction_Close struct {
	Stream m_EHBPEvents.Stream
}

func (SAction_Close) isSAction() {}

func (CompanionStruct_SAction_) Create_Close_(Stream m_EHBPEvents.Stream) SAction {
	return SAction{SAction_Close{Stream}}
}

func (_this SAction) Is_Close() bool {
	_, ok := _this.Get_().(SAction_Close)
	return ok
}

type SAction_Dispatch struct {
}

func (SAction_Dispatch) isSAction() {}

func (CompanionStruct_SAction_) Create_Dispatch_() SAction {
	return SAction{SAction_Dispatch{}}
}

func (_this SAction) Is_Dispatch() bool {
	_, ok := _this.Get_().(SAction_Dispatch)
	return ok
}

type SAction_StartResponse struct {
	Status  _dafny.Int
	Headers _dafny.Sequence
}

func (SAction_StartResponse) isSAction() {}

func (CompanionStruct_SAction_) Create_StartResponse_(Status _dafny.Int, Headers _dafny.Sequence) SAction {
	return SAction{SAction_StartResponse{Status, Headers}}
}

func (_this SAction) Is_StartResponse() bool {
	_, ok := _this.Get_().(SAction_StartResponse)
	return ok
}

type SAction_Write struct {
	Data _dafny.Sequence
	End  m_EHBPEvents.BodyEnd
}

func (SAction_Write) isSAction() {}

func (CompanionStruct_SAction_) Create_Write_(Data _dafny.Sequence, End m_EHBPEvents.BodyEnd) SAction {
	return SAction{SAction_Write{Data, End}}
}

func (_this SAction) Is_Write() bool {
	_, ok := _this.Get_().(SAction_Write)
	return ok
}

type SAction_Fail struct {
	Code    m_EHBP.Code
	Message _dafny.Sequence
}

func (SAction_Fail) isSAction() {}

func (CompanionStruct_SAction_) Create_Fail_(Code m_EHBP.Code, Message _dafny.Sequence) SAction {
	return SAction{SAction_Fail{Code, Message}}
}

func (_this SAction) Is_Fail() bool {
	_, ok := _this.Get_().(SAction_Fail)
	return ok
}

func (CompanionStruct_SAction_) Default() SAction {
	return Companion_SAction_.Create_RandomBytes_(_dafny.Zero)
}

func (_this SAction) Dtor_length() _dafny.Int {
	return _this.Get_().(SAction_RandomBytes).Length
}

func (_this SAction) Dtor_scalar() _dafny.Sequence {
	return _this.Get_().(SAction_X25519).Scalar
}

func (_this SAction) Dtor_point() _dafny.Sequence {
	return _this.Get_().(SAction_X25519).Point
}

func (_this SAction) Dtor_key() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case SAction_HmacSha256:
		return data.Key
	case SAction_AeadSeal:
		return data.Key
	default:
		return data.(SAction_AeadOpen).Key
	}
}

func (_this SAction) Dtor_data() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case SAction_HmacSha256:
		return data.Data
	case SAction_EmitPlaintext:
		return data.Data
	default:
		return data.(SAction_Write).Data
	}
}

func (_this SAction) Dtor_nonce() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case SAction_AeadSeal:
		return data.Nonce
	default:
		return data.(SAction_AeadOpen).Nonce
	}
}

func (_this SAction) Dtor_plaintext() _dafny.Sequence {
	return _this.Get_().(SAction_AeadSeal).Plaintext
}

func (_this SAction) Dtor_ciphertext() _dafny.Sequence {
	return _this.Get_().(SAction_AeadOpen).Ciphertext
}

func (_this SAction) Dtor_status() _dafny.Int {
	switch data := _this.Get_().(type) {
	case SAction_Respond:
		return data.Status
	default:
		return data.(SAction_StartResponse).Status
	}
}

func (_this SAction) Dtor_code() m_EHBP.Code {
	switch data := _this.Get_().(type) {
	case SAction_Respond:
		return data.Code
	default:
		return data.(SAction_Fail).Code
	}
}

func (_this SAction) Dtor_message() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case SAction_Respond:
		return data.Message
	default:
		return data.(SAction_Fail).Message
	}
}

func (_this SAction) Dtor_headers() _dafny.Sequence {
	switch data := _this.Get_().(type) {
	case SAction_Respond:
		return data.Headers
	default:
		return data.(SAction_StartResponse).Headers
	}
}

func (_this SAction) Dtor_body() _dafny.Sequence {
	return _this.Get_().(SAction_Respond).Body
}

func (_this SAction) Dtor_stream() m_EHBPEvents.Stream {
	switch data := _this.Get_().(type) {
	case SAction_Read:
		return data.Stream
	default:
		return data.(SAction_Close).Stream
	}
}

func (_this SAction) Dtor_end() m_EHBPEvents.BodyEnd {
	return _this.Get_().(SAction_Write).End
}

func (_this SAction) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case SAction_RandomBytes:
		{
			return "EHBPServer.SAction.RandomBytes" + "(" + _dafny.String(data.Length) + ")"
		}
	case SAction_X25519:
		{
			_ = data
			return "EHBPServer.SAction.X25519(<redacted>)"
		}
	case SAction_HmacSha256:
		{
			_ = data
			return "EHBPServer.SAction.HmacSha256(<redacted>)"
		}
	case SAction_AeadSeal:
		{
			_ = data
			return "EHBPServer.SAction.AeadSeal(<redacted>)"
		}
	case SAction_AeadOpen:
		{
			_ = data
			return "EHBPServer.SAction.AeadOpen(<redacted>)"
		}
	case SAction_PassRequest:
		{
			return "EHBPServer.SAction.PassRequest"
		}
	case SAction_Respond:
		{
			return "EHBPServer.SAction.Respond" + "(" + _dafny.String(data.Status) + ", " + _dafny.String(data.Code) + ", " + data.Message.VerbatimString(true) + ", " + _dafny.String(data.Headers) + ", " + _dafny.String(data.Body) + ")"
		}
	case SAction_Read:
		{
			return "EHBPServer.SAction.Read" + "(" + _dafny.String(data.Stream) + ")"
		}
	case SAction_EmitPlaintext:
		{
			return "EHBPServer.SAction.EmitPlaintext" + "(" + _dafny.String(data.Data) + ")"
		}
	case SAction_Close:
		{
			return "EHBPServer.SAction.Close" + "(" + _dafny.String(data.Stream) + ")"
		}
	case SAction_Dispatch:
		{
			return "EHBPServer.SAction.Dispatch"
		}
	case SAction_StartResponse:
		{
			return "EHBPServer.SAction.StartResponse" + "(" + _dafny.String(data.Status) + ", " + _dafny.String(data.Headers) + ")"
		}
	case SAction_Write:
		{
			return "EHBPServer.SAction.Write" + "(" + _dafny.String(data.Data) + ", " + _dafny.String(data.End) + ")"
		}
	case SAction_Fail:
		{
			return "EHBPServer.SAction.Fail" + "(" + _dafny.String(data.Code) + ", " + data.Message.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this SAction) Equals(other SAction) bool {
	switch data1 := _this.Get_().(type) {
	case SAction_RandomBytes:
		{
			data2, ok := other.Get_().(SAction_RandomBytes)
			return ok && data1.Length.Cmp(data2.Length) == 0
		}
	case SAction_X25519:
		{
			data2, ok := other.Get_().(SAction_X25519)
			return ok && data1.Scalar.Equals(data2.Scalar) && data1.Point.Equals(data2.Point)
		}
	case SAction_HmacSha256:
		{
			data2, ok := other.Get_().(SAction_HmacSha256)
			return ok && data1.Key.Equals(data2.Key) && data1.Data.Equals(data2.Data)
		}
	case SAction_AeadSeal:
		{
			data2, ok := other.Get_().(SAction_AeadSeal)
			return ok && data1.Key.Equals(data2.Key) && data1.Nonce.Equals(data2.Nonce) && data1.Plaintext.Equals(data2.Plaintext)
		}
	case SAction_AeadOpen:
		{
			data2, ok := other.Get_().(SAction_AeadOpen)
			return ok && data1.Key.Equals(data2.Key) && data1.Nonce.Equals(data2.Nonce) && data1.Ciphertext.Equals(data2.Ciphertext)
		}
	case SAction_PassRequest:
		{
			_, ok := other.Get_().(SAction_PassRequest)
			return ok
		}
	case SAction_Respond:
		{
			data2, ok := other.Get_().(SAction_Respond)
			return ok && data1.Status.Cmp(data2.Status) == 0 && data1.Code.Equals(data2.Code) && data1.Message.Equals(data2.Message) && data1.Headers.Equals(data2.Headers) && data1.Body.Equals(data2.Body)
		}
	case SAction_Read:
		{
			data2, ok := other.Get_().(SAction_Read)
			return ok && data1.Stream.Equals(data2.Stream)
		}
	case SAction_EmitPlaintext:
		{
			data2, ok := other.Get_().(SAction_EmitPlaintext)
			return ok && data1.Data.Equals(data2.Data)
		}
	case SAction_Close:
		{
			data2, ok := other.Get_().(SAction_Close)
			return ok && data1.Stream.Equals(data2.Stream)
		}
	case SAction_Dispatch:
		{
			_, ok := other.Get_().(SAction_Dispatch)
			return ok
		}
	case SAction_StartResponse:
		{
			data2, ok := other.Get_().(SAction_StartResponse)
			return ok && data1.Status.Cmp(data2.Status) == 0 && data1.Headers.Equals(data2.Headers)
		}
	case SAction_Write:
		{
			data2, ok := other.Get_().(SAction_Write)
			return ok && data1.Data.Equals(data2.Data) && data1.End.Equals(data2.End)
		}
	case SAction_Fail:
		{
			data2, ok := other.Get_().(SAction_Fail)
			return ok && data1.Code.Equals(data2.Code) && data1.Message.Equals(data2.Message)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this SAction) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(SAction)
	return ok && _this.Equals(typed)
}

func Type_SAction_() _dafny.TypeDescriptor {
	return type_SAction_{}
}

type type_SAction_ struct {
}

func (_this type_SAction_) Default() interface{} {
	return Companion_SAction_.Default()
}

func (_this type_SAction_) String() string {
	return "EHBPServer.SAction"
}
func (_this SAction) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = SAction{}

// End of datatype SAction

// Definition of datatype Req
type Req struct {
	Data_Req_
}

func (_this Req) Get_() Data_Req_ {
	return _this.Data_Req_
}

type Data_Req_ interface {
	isReq()
}

type CompanionStruct_Req_ struct {
}

var Companion_Req_ = CompanionStruct_Req_{}

type Req_Waiting struct {
}

func (Req_Waiting) isReq() {}

func (CompanionStruct_Req_) Create_Waiting_() Req {
	return Req{Req_Waiting{}}
}

func (_this Req) Is_Waiting() bool {
	_, ok := _this.Get_().(Req_Waiting)
	return ok
}

type Req_Reading struct {
	Empty _dafny.Int
}

func (Req_Reading) isReq() {}

func (CompanionStruct_Req_) Create_Reading_(Empty _dafny.Int) Req {
	return Req{Req_Reading{Empty}}
}

func (_this Req) Is_Reading() bool {
	_, ok := _this.Get_().(Req_Reading)
	return ok
}

type Req_Opening struct {
	Frames  _dafny.Sequence
	Eof     bool
	Emitted bool
}

func (Req_Opening) isReq() {}

func (CompanionStruct_Req_) Create_Opening_(Frames _dafny.Sequence, Eof bool, Emitted bool) Req {
	return Req{Req_Opening{Frames, Eof, Emitted}}
}

func (_this Req) Is_Opening() bool {
	_, ok := _this.Get_().(Req_Opening)
	return ok
}

type Req_ReqDone struct {
}

func (Req_ReqDone) isReq() {}

func (CompanionStruct_Req_) Create_ReqDone_() Req {
	return Req{Req_ReqDone{}}
}

func (_this Req) Is_ReqDone() bool {
	_, ok := _this.Get_().(Req_ReqDone)
	return ok
}

type Req_ReqFailed struct {
	Status  _dafny.Int
	Code    m_EHBP.Code
	Message _dafny.Sequence
}

func (Req_ReqFailed) isReq() {}

func (CompanionStruct_Req_) Create_ReqFailed_(Status _dafny.Int, Code m_EHBP.Code, Message _dafny.Sequence) Req {
	return Req{Req_ReqFailed{Status, Code, Message}}
}

func (_this Req) Is_ReqFailed() bool {
	_, ok := _this.Get_().(Req_ReqFailed)
	return ok
}

func (CompanionStruct_Req_) Default() Req {
	return Companion_Req_.Create_Waiting_()
}

func (_this Req) Dtor_empty() _dafny.Int {
	return _this.Get_().(Req_Reading).Empty
}

func (_this Req) Dtor_frames() _dafny.Sequence {
	return _this.Get_().(Req_Opening).Frames
}

func (_this Req) Dtor_eof() bool {
	return _this.Get_().(Req_Opening).Eof
}

func (_this Req) Dtor_emitted() bool {
	return _this.Get_().(Req_Opening).Emitted
}

func (_this Req) Dtor_status() _dafny.Int {
	return _this.Get_().(Req_ReqFailed).Status
}

func (_this Req) Dtor_code() m_EHBP.Code {
	return _this.Get_().(Req_ReqFailed).Code
}

func (_this Req) Dtor_message() _dafny.Sequence {
	return _this.Get_().(Req_ReqFailed).Message
}

func (_this Req) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Req_Waiting:
		{
			return "EHBPServer.Req.Waiting"
		}
	case Req_Reading:
		{
			return "EHBPServer.Req.Reading" + "(" + _dafny.String(data.Empty) + ")"
		}
	case Req_Opening:
		{
			return "EHBPServer.Req.Opening" + "(" + _dafny.String(data.Frames) + ", " + _dafny.String(data.Eof) + ", " + _dafny.String(data.Emitted) + ")"
		}
	case Req_ReqDone:
		{
			return "EHBPServer.Req.ReqDone"
		}
	case Req_ReqFailed:
		{
			return "EHBPServer.Req.ReqFailed" + "(" + _dafny.String(data.Status) + ", " + _dafny.String(data.Code) + ", " + data.Message.VerbatimString(true) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Req) Equals(other Req) bool {
	switch data1 := _this.Get_().(type) {
	case Req_Waiting:
		{
			_, ok := other.Get_().(Req_Waiting)
			return ok
		}
	case Req_Reading:
		{
			data2, ok := other.Get_().(Req_Reading)
			return ok && data1.Empty.Cmp(data2.Empty) == 0
		}
	case Req_Opening:
		{
			data2, ok := other.Get_().(Req_Opening)
			return ok && data1.Frames.Equals(data2.Frames) && data1.Eof == data2.Eof && data1.Emitted == data2.Emitted
		}
	case Req_ReqDone:
		{
			_, ok := other.Get_().(Req_ReqDone)
			return ok
		}
	case Req_ReqFailed:
		{
			data2, ok := other.Get_().(Req_ReqFailed)
			return ok && data1.Status.Cmp(data2.Status) == 0 && data1.Code.Equals(data2.Code) && data1.Message.Equals(data2.Message)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Req) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Req)
	return ok && _this.Equals(typed)
}

func Type_Req_() _dafny.TypeDescriptor {
	return type_Req_{}
}

type type_Req_ struct {
}

func (_this type_Req_) Default() interface{} {
	return Companion_Req_.Default()
}

func (_this type_Req_) String() string {
	return "EHBPServer.Req"
}
func (_this Req) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Req{}

// End of datatype Req

// Definition of datatype Sealing
type Sealing struct {
	Data_Sealing_
}

func (_this Sealing) Get_() Data_Sealing_ {
	return _this.Data_Sealing_
}

type Data_Sealing_ interface {
	isSealing()
}

type CompanionStruct_Sealing_ struct {
}

var Companion_Sealing_ = CompanionStruct_Sealing_{}

type Sealing_NoSeal struct {
}

func (Sealing_NoSeal) isSealing() {}

func (CompanionStruct_Sealing_) Create_NoSeal_() Sealing {
	return Sealing{Sealing_NoSeal{}}
}

func (_this Sealing) Is_NoSeal() bool {
	_, ok := _this.Get_().(Sealing_NoSeal)
	return ok
}

type Sealing_Sealing struct {
	Plaintext _dafny.Sequence
	Offset    uint32
	Final     bool
}

func (Sealing_Sealing) isSealing() {}

func (CompanionStruct_Sealing_) Create_Sealing_(Plaintext _dafny.Sequence, Offset uint32, Final bool) Sealing {
	return Sealing{Sealing_Sealing{Plaintext, Offset, Final}}
}

func (_this Sealing) Is_Sealing() bool {
	_, ok := _this.Get_().(Sealing_Sealing)
	return ok
}

func (CompanionStruct_Sealing_) Default() Sealing {
	return Companion_Sealing_.Create_NoSeal_()
}

func (_this Sealing) Dtor_plaintext() _dafny.Sequence {
	return _this.Get_().(Sealing_Sealing).Plaintext
}

func (_this Sealing) Dtor_offset() uint32 {
	return _this.Get_().(Sealing_Sealing).Offset
}

func (_this Sealing) Dtor_final() bool {
	return _this.Get_().(Sealing_Sealing).Final
}

func (_this Sealing) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Sealing_NoSeal:
		{
			return "EHBPServer.Sealing.NoSeal"
		}
	case Sealing_Sealing:
		{
			return "EHBPServer.Sealing.Sealing" + "(" + _dafny.String(data.Plaintext) + ", " + _dafny.String(data.Offset) + ", " + _dafny.String(data.Final) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Sealing) Equals(other Sealing) bool {
	switch data1 := _this.Get_().(type) {
	case Sealing_NoSeal:
		{
			_, ok := other.Get_().(Sealing_NoSeal)
			return ok
		}
	case Sealing_Sealing:
		{
			data2, ok := other.Get_().(Sealing_Sealing)
			return ok && data1.Plaintext.Equals(data2.Plaintext) && data1.Offset == data2.Offset && data1.Final == data2.Final
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Sealing) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Sealing)
	return ok && _this.Equals(typed)
}

func Type_Sealing_() _dafny.TypeDescriptor {
	return type_Sealing_{}
}

type type_Sealing_ struct {
}

func (_this type_Sealing_) Default() interface{} {
	return Companion_Sealing_.Default()
}

func (_this type_Sealing_) String() string {
	return "EHBPServer.Sealing"
}
func (_this Sealing) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Sealing{}

// End of datatype Sealing

// Definition of datatype Resp
type Resp struct {
	Data_Resp_
}

func (_this Resp) Get_() Data_Resp_ {
	return _this.Data_Resp_
}

type Data_Resp_ interface {
	isResp()
}

type CompanionStruct_Resp_ struct {
}

var Companion_Resp_ = CompanionStruct_Resp_{}

type Resp_Resp struct {
	Keys    m_EHBPEvents.Ctx
	Nonce   _dafny.Sequence
	Started bool
	Status  _dafny.Int
	Framed  bool
	Seal    Sealing
}

func (Resp_Resp) isResp() {}

func (CompanionStruct_Resp_) Create_Resp_(Keys m_EHBPEvents.Ctx, Nonce _dafny.Sequence, Started bool, Status _dafny.Int, Framed bool, Seal Sealing) Resp {
	return Resp{Resp_Resp{Keys, Nonce, Started, Status, Framed, Seal}}
}

func (_this Resp) Is_Resp() bool {
	_, ok := _this.Get_().(Resp_Resp)
	return ok
}

func (CompanionStruct_Resp_) Default() Resp {
	return Companion_Resp_.Create_Resp_(m_EHBPEvents.Companion_Ctx_.Default(), _dafny.EmptySeq, false, _dafny.Zero, false, Companion_Sealing_.Default())
}

func (_this Resp) Dtor_keys() m_EHBPEvents.Ctx {
	return _this.Get_().(Resp_Resp).Keys
}

func (_this Resp) Dtor_nonce() _dafny.Sequence {
	return _this.Get_().(Resp_Resp).Nonce
}

func (_this Resp) Dtor_started() bool {
	return _this.Get_().(Resp_Resp).Started
}

func (_this Resp) Dtor_status() _dafny.Int {
	return _this.Get_().(Resp_Resp).Status
}

func (_this Resp) Dtor_framed() bool {
	return _this.Get_().(Resp_Resp).Framed
}

func (_this Resp) Dtor_seal() Sealing {
	return _this.Get_().(Resp_Resp).Seal
}

func (_this Resp) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Resp_Resp:
		{
			return "EHBPServer.Resp.Resp" + "(" + _dafny.String(data.Keys) + ", " + _dafny.String(data.Nonce) + ", " + _dafny.String(data.Started) + ", " + _dafny.String(data.Status) + ", " + _dafny.String(data.Framed) + ", " + _dafny.String(data.Seal) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Resp) Equals(other Resp) bool {
	switch data1 := _this.Get_().(type) {
	case Resp_Resp:
		{
			data2, ok := other.Get_().(Resp_Resp)
			return ok && data1.Keys.Equals(data2.Keys) && data1.Nonce.Equals(data2.Nonce) && data1.Started == data2.Started && data1.Status.Cmp(data2.Status) == 0 && data1.Framed == data2.Framed && data1.Seal.Equals(data2.Seal)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Resp) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Resp)
	return ok && _this.Equals(typed)
}

func Type_Resp_() _dafny.TypeDescriptor {
	return type_Resp_{}
}

type type_Resp_ struct {
}

func (_this type_Resp_) Default() interface{} {
	return Companion_Resp_.Default()
}

func (_this type_Resp_) String() string {
	return "EHBPServer.Resp"
}
func (_this Resp) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Resp{}

// End of datatype Resp

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

type Phase_Decap struct {
	Hpke m_EHBPEvents.Hpke
}

func (Phase_Decap) isPhase() {}

func (CompanionStruct_Phase_) Create_Decap_(Hpke m_EHBPEvents.Hpke) Phase {
	return Phase{Phase_Decap{Hpke}}
}

func (_this Phase) Is_Decap() bool {
	_, ok := _this.Get_().(Phase_Decap)
	return ok
}

type Phase_Peek struct {
	Req Req
}

func (Phase_Peek) isPhase() {}

func (CompanionStruct_Phase_) Create_Peek_(Req Req) Phase {
	return Phase{Phase_Peek{Req}}
}

func (_this Phase) Is_Peek() bool {
	_, ok := _this.Get_().(Phase_Peek)
	return ok
}

type Phase_Deriving struct {
	Stage  _dafny.Int
	Job    m_EHBPEvents.Job
	Req    Req
	Nonce  _dafny.Sequence
	Secret _dafny.Sequence
	Prk    _dafny.Sequence
	Key    _dafny.Sequence
}

func (Phase_Deriving) isPhase() {}

func (CompanionStruct_Phase_) Create_Deriving_(Stage _dafny.Int, Job m_EHBPEvents.Job, Req Req, Nonce _dafny.Sequence, Secret _dafny.Sequence, Prk _dafny.Sequence, Key _dafny.Sequence) Phase {
	return Phase{Phase_Deriving{Stage, Job, Req, Nonce, Secret, Prk, Key}}
}

func (_this Phase) Is_Deriving() bool {
	_, ok := _this.Get_().(Phase_Deriving)
	return ok
}

type Phase_Running struct {
	Req  Req
	Resp Resp
}

func (Phase_Running) isPhase() {}

func (CompanionStruct_Phase_) Create_Running_(Req Req, Resp Resp) Phase {
	return Phase{Phase_Running{Req, Resp}}
}

func (_this Phase) Is_Running() bool {
	_, ok := _this.Get_().(Phase_Running)
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

func (_this Phase) Dtor_hpke() m_EHBPEvents.Hpke {
	return _this.Get_().(Phase_Decap).Hpke
}

func (_this Phase) Dtor_req() Req {
	switch data := _this.Get_().(type) {
	case Phase_Peek:
		return data.Req
	case Phase_Deriving:
		return data.Req
	default:
		return data.(Phase_Running).Req
	}
}

func (_this Phase) Dtor_stage() _dafny.Int {
	return _this.Get_().(Phase_Deriving).Stage
}

func (_this Phase) Dtor_job() m_EHBPEvents.Job {
	return _this.Get_().(Phase_Deriving).Job
}

func (_this Phase) Dtor_nonce() _dafny.Sequence {
	return _this.Get_().(Phase_Deriving).Nonce
}

func (_this Phase) Dtor_secret() _dafny.Sequence {
	return _this.Get_().(Phase_Deriving).Secret
}

func (_this Phase) Dtor_prk() _dafny.Sequence {
	return _this.Get_().(Phase_Deriving).Prk
}

func (_this Phase) Dtor_key() _dafny.Sequence {
	return _this.Get_().(Phase_Deriving).Key
}

func (_this Phase) Dtor_resp() Resp {
	return _this.Get_().(Phase_Running).Resp
}

func (_this Phase) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Phase_Idle:
		{
			return "EHBPServer.Phase.Idle"
		}
	case Phase_Decap:
		{
			return "EHBPServer.Phase.Decap" + "(" + _dafny.String(data.Hpke) + ")"
		}
	case Phase_Peek:
		{
			return "EHBPServer.Phase.Peek" + "(" + _dafny.String(data.Req) + ")"
		}
	case Phase_Deriving:
		{
			_ = data
			return "EHBPServer.Phase.Deriving(<redacted>)"
		}
	case Phase_Running:
		{
			return "EHBPServer.Phase.Running" + "(" + _dafny.String(data.Req) + ", " + _dafny.String(data.Resp) + ")"
		}
	case Phase_Ended:
		{
			return "EHBPServer.Phase.Ended"
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
	case Phase_Decap:
		{
			data2, ok := other.Get_().(Phase_Decap)
			return ok && data1.Hpke.Equals(data2.Hpke)
		}
	case Phase_Peek:
		{
			data2, ok := other.Get_().(Phase_Peek)
			return ok && data1.Req.Equals(data2.Req)
		}
	case Phase_Deriving:
		{
			data2, ok := other.Get_().(Phase_Deriving)
			return ok && data1.Stage.Cmp(data2.Stage) == 0 && data1.Job.Equals(data2.Job) && data1.Req.Equals(data2.Req) && data1.Nonce.Equals(data2.Nonce) && data1.Secret.Equals(data2.Secret) && data1.Prk.Equals(data2.Prk) && data1.Key.Equals(data2.Key)
		}
	case Phase_Running:
		{
			data2, ok := other.Get_().(Phase_Running)
			return ok && data1.Req.Equals(data2.Req) && data1.Resp.Equals(data2.Resp)
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
	return "EHBPServer.Phase"
}
func (_this Phase) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Phase{}

// End of datatype Phase

// Definition of datatype SState
type SState struct {
	Data_SState_
}

func (_this SState) Get_() Data_SState_ {
	return _this.Data_SState_
}

type Data_SState_ interface {
	isSState()
}

type CompanionStruct_SState_ struct {
}

var Companion_SState_ = CompanionStruct_SState_{}

type SState_SState struct {
	Phase   Phase
	Sk      _dafny.Sequence
	Pk      _dafny.Sequence
	Enc     _dafny.Sequence
	Ctx     m_EHBPEvents.Ctx
	Dec     m_EHBPEvents.Dec
	Payload bool
}

func (SState_SState) isSState() {}

func (CompanionStruct_SState_) Create_SState_(Phase Phase, Sk _dafny.Sequence, Pk _dafny.Sequence, Enc _dafny.Sequence, Ctx m_EHBPEvents.Ctx, Dec m_EHBPEvents.Dec, Payload bool) SState {
	return SState{SState_SState{Phase, Sk, Pk, Enc, Ctx, Dec, Payload}}
}

func (_this SState) Is_SState() bool {
	_, ok := _this.Get_().(SState_SState)
	return ok
}

func (CompanionStruct_SState_) Default() SState {
	return Companion_SState_.Create_SState_(Companion_Phase_.Default(), _dafny.EmptySeq, _dafny.EmptySeq, _dafny.EmptySeq, m_EHBPEvents.Companion_Ctx_.Default(), m_EHBPEvents.Companion_Dec_.Default(), false)
}

func (_this SState) Dtor_phase() Phase {
	return _this.Get_().(SState_SState).Phase
}

func (_this SState) Dtor_sk() _dafny.Sequence {
	return _this.Get_().(SState_SState).Sk
}

func (_this SState) Dtor_pk() _dafny.Sequence {
	return _this.Get_().(SState_SState).Pk
}

func (_this SState) Dtor_enc() _dafny.Sequence {
	return _this.Get_().(SState_SState).Enc
}

func (_this SState) Dtor_ctx() m_EHBPEvents.Ctx {
	return _this.Get_().(SState_SState).Ctx
}

func (_this SState) Dtor_dec() m_EHBPEvents.Dec {
	return _this.Get_().(SState_SState).Dec
}

func (_this SState) Dtor_payload() bool {
	return _this.Get_().(SState_SState).Payload
}

func (_this SState) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case SState_SState:
		{
			_ = data
			return "EHBPServer.SState.SState(<redacted>)"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this SState) Equals(other SState) bool {
	switch data1 := _this.Get_().(type) {
	case SState_SState:
		{
			data2, ok := other.Get_().(SState_SState)
			return ok && data1.Phase.Equals(data2.Phase) && data1.Sk.Equals(data2.Sk) && data1.Pk.Equals(data2.Pk) && data1.Enc.Equals(data2.Enc) && data1.Ctx.Equals(data2.Ctx) && data1.Dec.Equals(data2.Dec) && data1.Payload == data2.Payload
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this SState) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(SState)
	return ok && _this.Equals(typed)
}

func Type_SState_() _dafny.TypeDescriptor {
	return type_SState_{}
}

type type_SState_ struct {
}

func (_this type_SState_) Default() interface{} {
	return Companion_SState_.Default()
}

func (_this type_SState_) String() string {
	return "EHBPServer.SState"
}
func (_this SState) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = SState{}

// End of datatype SState

// Definition of trait SPerformer
type SPerformer interface {
	String() string
	RandomBytes(length _dafny.Int) _dafny.Sequence
	X25519(scalar _dafny.Sequence, point _dafny.Sequence) _dafny.Sequence
	HmacSha256(key _dafny.Sequence, data _dafny.Sequence) _dafny.Sequence
	AeadSeal(key _dafny.Sequence, nonce _dafny.Sequence, plaintext _dafny.Sequence) _dafny.Sequence
	AeadOpen(key _dafny.Sequence, nonce _dafny.Sequence, ciphertext _dafny.Sequence) (bool, _dafny.Sequence)
	PassRequest()
	Respond(status _dafny.Int, code m_EHBP.Code, message _dafny.Sequence, headers _dafny.Sequence, body _dafny.Sequence)
	Read(stream m_EHBPEvents.Stream) (bool, _dafny.Sequence, bool)
	EmitPlaintext(data _dafny.Sequence)
	Close(stream m_EHBPEvents.Stream)
	Dispatch() bool
	StartResponse(status _dafny.Int, headers _dafny.Sequence)
	Write(data _dafny.Sequence, end m_EHBPEvents.BodyEnd)
	Fail(code m_EHBP.Code, message _dafny.Sequence)
}
type CompanionStruct_SPerformer_ struct {
	TraitID_ *_dafny.TraitID
}

var Companion_SPerformer_ = CompanionStruct_SPerformer_{
	TraitID_: &_dafny.TraitID{},
}

func (CompanionStruct_SPerformer_) CastTo_(x interface{}) SPerformer {
	var t SPerformer
	t, _ = x.(SPerformer)
	return t
}

// End of trait SPerformer

// Definition of datatype Lane
type Lane struct {
	Data_Lane_
}

func (_this Lane) Get_() Data_Lane_ {
	return _this.Data_Lane_
}

type Data_Lane_ interface {
	isLane()
}

type CompanionStruct_Lane_ struct {
}

var Companion_Lane_ = CompanionStruct_Lane_{}

type Lane_Lane struct {
	Req     Req
	Dec     m_EHBPEvents.Dec
	Payload bool
	Acts    _dafny.Sequence
}

func (Lane_Lane) isLane() {}

func (CompanionStruct_Lane_) Create_Lane_(Req Req, Dec m_EHBPEvents.Dec, Payload bool, Acts _dafny.Sequence) Lane {
	return Lane{Lane_Lane{Req, Dec, Payload, Acts}}
}

func (_this Lane) Is_Lane() bool {
	_, ok := _this.Get_().(Lane_Lane)
	return ok
}

func (CompanionStruct_Lane_) Default() Lane {
	return Companion_Lane_.Create_Lane_(Companion_Req_.Default(), m_EHBPEvents.Companion_Dec_.Default(), false, _dafny.EmptySeq)
}

func (_this Lane) Dtor_req() Req {
	return _this.Get_().(Lane_Lane).Req
}

func (_this Lane) Dtor_dec() m_EHBPEvents.Dec {
	return _this.Get_().(Lane_Lane).Dec
}

func (_this Lane) Dtor_payload() bool {
	return _this.Get_().(Lane_Lane).Payload
}

func (_this Lane) Dtor_acts() _dafny.Sequence {
	return _this.Get_().(Lane_Lane).Acts
}

func (_this Lane) String() string {
	switch data := _this.Get_().(type) {
	case nil:
		return "null"
	case Lane_Lane:
		{
			return "EHBPServer.Lane.Lane" + "(" + _dafny.String(data.Req) + ", " + _dafny.String(data.Dec) + ", " + _dafny.String(data.Payload) + ", " + _dafny.String(data.Acts) + ")"
		}
	default:
		{
			return "<unexpected>"
		}
	}
}

func (_this Lane) Equals(other Lane) bool {
	switch data1 := _this.Get_().(type) {
	case Lane_Lane:
		{
			data2, ok := other.Get_().(Lane_Lane)
			return ok && data1.Req.Equals(data2.Req) && data1.Dec.Equals(data2.Dec) && data1.Payload == data2.Payload && data1.Acts.Equals(data2.Acts)
		}
	default:
		{
			return false // unexpected
		}
	}
}

func (_this Lane) EqualsGeneric(other interface{}) bool {
	typed, ok := other.(Lane)
	return ok && _this.Equals(typed)
}

func Type_Lane_() _dafny.TypeDescriptor {
	return type_Lane_{}
}

type type_Lane_ struct {
}

func (_this type_Lane_) Default() interface{} {
	return Companion_Lane_.Default()
}

func (_this type_Lane_) String() string {
	return "EHBPServer.Lane"
}
func (_this Lane) ParentTraits_() []*_dafny.TraitID {
	return [](*_dafny.TraitID){}
}

var _ _dafny.TraitOffspring = Lane{}

// End of datatype Lane
