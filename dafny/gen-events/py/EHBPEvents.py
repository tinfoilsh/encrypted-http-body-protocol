import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_
import EHBP as EHBP

# Module: EHBPEvents

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Terminal(a):
        return (((((a).is_Fail) or ((a).is_Finished)) or ((a).is_Passthrough)) or ((a).is_Discovered)) or ((a).is_Close)

    @staticmethod
    def Ends(acts):
        def lambda0_(exists_var_0_):
            d_0_i_: int = exists_var_0_
            return (((0) <= (d_0_i_)) and ((d_0_i_) < (len(acts)))) and (default__.Terminal((acts)[d_0_i_]))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(acts)), False, lambda0_)

    @staticmethod
    def NoClear(acts):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(acts)))) or (not(((acts)[d_0_i_]).is_ClearToken))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(acts)), True, lambda0_)

    @staticmethod
    def ClearsOnce(acts, g):
        def lambda0_(exists_var_0_):
            def lambda1_(forall_var_0_):
                d_1_j_: int = forall_var_0_
                return not ((((0) <= (d_1_j_)) and ((d_1_j_) < (len(acts)))) and ((d_1_j_) != (d_0_i_))) or (not(((acts)[d_1_j_]).is_ClearToken))

            d_0_i_: int = exists_var_0_
            return ((((0) <= (d_0_i_)) and ((d_0_i_) < (len(acts)))) and (((acts)[d_0_i_]) == (Action_ClearToken(g)))) and (_dafny.quantifier(_dafny.IntegerRange(0, len(acts)), True, lambda1_))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(acts)), False, lambda0_)

    @staticmethod
    def NoEmit(acts):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(acts)))) or (not(((acts)[d_0_i_]).is_EmitPlaintext))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(acts)), True, lambda0_)

    @staticmethod
    def Perform(p, a):
        r: Performed = Performed.default()()
        source0_ = a
        with _dafny.label("match0"):
            if True:
                if source0_.is_BeginSession:
                    d_0_generation_: int
                    out0_: int
                    out0_ = (p).BeginSession()
                    d_0_generation_ = out0_
                    r = Performed_Got(Event_SessionBegun(d_0_generation_))
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_PublishToken:
                    d_1_generation_ = source0_.generation
                    d_2_exportedSecret_ = source0_.exportedSecret
                    d_3_requestEnc_ = source0_.requestEnc
                    (p).PublishToken(d_1_generation_, d_2_exportedSecret_, d_3_requestEnc_)
                    r = Performed_Quiet()
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_ClearToken:
                    d_4_generation_ = source0_.generation
                    (p).ClearToken(d_4_generation_)
                    r = Performed_Quiet()
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_RandomBytes:
                    d_5_length_ = source0_.length
                    d_6_data_: _dafny.Seq
                    out1_: _dafny.Seq
                    out1_ = (p).RandomBytes(d_5_length_)
                    d_6_data_ = out1_
                    r = Performed_Got(Event_RandomResult(d_6_data_))
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_X25519:
                    d_7_scalar_ = source0_.scalar
                    d_8_point_ = source0_.point
                    d_9_shared_: _dafny.Seq
                    out2_: _dafny.Seq
                    out2_ = (p).X25519(d_7_scalar_, d_8_point_)
                    d_9_shared_ = out2_
                    r = Performed_Got(Event_X25519Result(d_9_shared_))
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_HmacSha256:
                    d_10_key_ = source0_.key
                    d_11_data_ = source0_.data
                    d_12_mac_: _dafny.Seq
                    out3_: _dafny.Seq
                    out3_ = (p).HmacSha256(d_10_key_, d_11_data_)
                    d_12_mac_ = out3_
                    r = Performed_Got(Event_HmacResult(d_12_mac_))
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_AeadSeal:
                    d_13_key_ = source0_.key
                    d_14_nonce_ = source0_.nonce
                    d_15_plaintext_ = source0_.plaintext
                    d_16_ciphertext_: _dafny.Seq
                    out4_: _dafny.Seq
                    out4_ = (p).AeadSeal(d_13_key_, d_14_nonce_, d_15_plaintext_)
                    d_16_ciphertext_ = out4_
                    r = Performed_Got(Event_AeadSealResult(d_16_ciphertext_))
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_AeadOpen:
                    d_17_key_ = source0_.key
                    d_18_nonce_ = source0_.nonce
                    d_19_ciphertext_ = source0_.ciphertext
                    d_20_ok_: bool
                    d_21_plaintext_: _dafny.Seq
                    out5_: bool
                    out6_: _dafny.Seq
                    out5_, out6_ = (p).AeadOpen(d_17_key_, d_18_nonce_, d_19_ciphertext_)
                    d_20_ok_ = out5_
                    d_21_plaintext_ = out6_
                    r = Performed_Got(Event_AeadOpenResult(d_20_ok_, d_21_plaintext_))
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_Send:
                    d_22_verb_ = source0_.verb
                    d_23_url_ = source0_.url
                    d_24_headers_ = source0_.headers
                    d_25_hasBody_ = source0_.hasBody
                    d_26_ok_: bool
                    d_27_status_: int
                    d_28_head_: _dafny.Seq
                    d_29_redirected_: bool
                    out7_: bool
                    out8_: int
                    out9_: _dafny.Seq
                    out10_: bool
                    out7_, out8_, out9_, out10_ = (p).Send(d_22_verb_, d_23_url_, d_24_headers_, d_25_hasBody_)
                    d_26_ok_ = out7_
                    d_27_status_ = out8_
                    d_28_head_ = out9_
                    d_29_redirected_ = out10_
                    r = Performed_Got((Event_ResponseHead(d_27_status_, d_28_head_, d_29_redirected_) if d_26_ok_ else Event_StreamFailed(Stream_ResponseBody())))
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_Write:
                    d_30_data_ = source0_.data
                    d_31_end_ = source0_.end
                    d_32_ok_: bool
                    out11_: bool
                    out11_ = (p).Write(d_30_data_, d_31_end_)
                    d_32_ok_ = out11_
                    if d_32_ok_:
                        r = Performed_Quiet()
                    elif True:
                        r = Performed_Stop()
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_Read:
                    d_33_stream_ = source0_.stream
                    d_34_ok_: bool
                    d_35_data_: _dafny.Seq
                    d_36_eof_: bool
                    out12_: bool
                    out13_: _dafny.Seq
                    out14_: bool
                    out12_, out13_, out14_ = (p).Read(d_33_stream_)
                    d_34_ok_ = out12_
                    d_35_data_ = out13_
                    d_36_eof_ = out14_
                    r = Performed_Got((Event_Chunk(d_33_stream_, d_35_data_, d_36_eof_) if d_34_ok_ else Event_StreamFailed(d_33_stream_)))
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_Close:
                    d_37_stream_ = source0_.stream
                    (p).Close(d_37_stream_)
                    r = Performed_Quiet()
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_EmitPlaintext:
                    d_38_data_ = source0_.data
                    (p).EmitPlaintext(d_38_data_)
                    r = Performed_Quiet()
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_Passthrough:
                    r = Performed_Quiet()
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_Done:
                    r = Performed_Quiet()
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_Finished:
                    r = Performed_Quiet()
                    return r
                    raise _dafny.Break("match0")
            if True:
                if source0_.is_Discovered:
                    r = Performed_Quiet()
                    return r
                    raise _dafny.Break("match0")
            if True:
                r = Performed_Quiet()
                return r
            pass
        return r

    @staticmethod
    def Extract(salt, ikm):
        return Job_JExtract(salt, ikm)

    @staticmethod
    def Expand(prk, info, length):
        return Job_JExpand(prk, info, length, _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference([]), 1)

    @staticmethod
    def JobAction(j):
        source0_ = j
        if True:
            if source0_.is_JExtract:
                d_0_salt_ = source0_.salt
                d_1_ikm_ = source0_.ikm
                return Action_HmacSha256(d_0_salt_, d_1_ikm_)
        if True:
            d_2_prk_ = source0_.prk
            d_3_info_ = source0_.info
            d_4_prev_ = source0_.prev
            d_5_i_ = source0_.i
            return Action_HmacSha256(d_2_prk_, ((d_4_prev_) + (d_3_info_)) + (_dafny.SeqWithoutIsStrInference([d_5_i_])))

    @staticmethod
    def JobStep(j, e):
        if not((e).is_HmacResult):
            return JobOut_JobFailed(EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "unexpected event")))
        elif (len((e).mac)) != (EHBP.default__.HashLength):
            return JobOut_JobFailed(EHBP.Code_HpkeSetupFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "HMAC returned the wrong length")))
        elif True:
            source0_ = j
            if True:
                if source0_.is_JExtract:
                    return JobOut_Output((e).mac)
            if True:
                d_0_prk_ = source0_.prk
                d_1_info_ = source0_.info
                d_2_length_ = source0_.length
                d_3_acc_ = source0_.acc
                d_4_i_ = source0_.i
                d_5_grown_ = (d_3_acc_) + ((e).mac)
                if (len(d_5_grown_)) >= (d_2_length_):
                    return JobOut_Output(_dafny.SeqWithoutIsStrInference((d_5_grown_)[:d_2_length_:]))
                elif (d_4_i_) == (255):
                    return JobOut_JobFailed(EHBP.Code_HpkeSetupFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "HKDF expand length too large")))
                elif True:
                    d_6_next_ = Job_JExpand(d_0_prk_, d_1_info_, d_2_length_, d_5_grown_, (e).mac, (d_4_i_) + (1))
                    return JobOut_Pending(d_6_next_, default__.JobAction(d_6_next_))

    @staticmethod
    def Repeat(n, v):
        return _dafny.SeqWithoutIsStrInference([v for d_0_i_ in range(n)])

    @staticmethod
    def Iota(n):
        return _dafny.SeqWithoutIsStrInference([d_0_i_ for d_0_i_ in range(n)])

    @staticmethod
    def LabeledExtract(suite, salt, tag, ikm):
        return default__.Extract(salt, (((default__.HpkeVersion) + (suite)) + (EHBP.default__.Ascii(tag))) + (ikm))

    @staticmethod
    def LabeledExpand(suite, prk, tag, info, length):
        return default__.Expand(prk, ((((EHBP.default__.BE16(length)) + (default__.HpkeVersion)) + (suite)) + (EHBP.default__.Ascii(tag))) + (info), length)

    @staticmethod
    def SenderStart(pkR, info):
        return HpkeOut_HContinue(Hpke_HRandom(pkR, info), Action_RandomBytes(32))

    @staticmethod
    def RecipientStart(skR, pkR, enc, info):
        return HpkeOut_HContinue(Hpke_HDh(enc, pkR, info), Action_X25519(skR, enc))

    @staticmethod
    def Schedule(h, job):
        pat_let_tv0_ = job
        def iife0_(_pat_let1_0):
            def iife1_(d_0_dt__update__tmp_h0_):
                def iife2_(_pat_let2_0):
                    def iife3_(d_1_dt__update_hjob_h0_):
                        return Hpke_HSchedule((d_0_dt__update__tmp_h0_).stage, d_1_dt__update_hjob_h0_, (d_0_dt__update__tmp_h0_).enc, (d_0_dt__update__tmp_h0_).pkR, (d_0_dt__update__tmp_h0_).info, (d_0_dt__update__tmp_h0_).shared, (d_0_dt__update__tmp_h0_).pskIdHash, (d_0_dt__update__tmp_h0_).infoHash, (d_0_dt__update__tmp_h0_).secret, (d_0_dt__update__tmp_h0_).key, (d_0_dt__update__tmp_h0_).baseNonce)
                    return iife3_(_pat_let2_0)
                return iife2_(pat_let_tv0_)
            return iife1_(_pat_let1_0)
        return HpkeOut_HContinue(iife0_(h), default__.JobAction(job))

    @staticmethod
    def HpkeStep(h, e):
        source0_ = h
        if True:
            if source0_.is_HRandom:
                d_0_pkR_ = source0_.pkR
                d_1_info_ = source0_.info
                if not((e).is_RandomResult):
                    return HpkeOut_HFailed(EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "unexpected event")))
                elif (len((e).data)) != (32):
                    return HpkeOut_HFailed(EHBP.Code_HpkeSetupFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "random bytes have the wrong length")))
                elif True:
                    return HpkeOut_HContinue(Hpke_HEnc((e).data, d_0_pkR_, d_1_info_), Action_X25519((e).data, default__.BasePoint))
        if True:
            if source0_.is_HEnc:
                d_2_skE_ = source0_.skE
                d_3_pkR_ = source0_.pkR
                d_4_info_ = source0_.info
                if not((e).is_X25519Result):
                    return HpkeOut_HFailed(EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "unexpected event")))
                elif (len((e).point)) != (32):
                    return HpkeOut_HFailed(EHBP.Code_HpkeSetupFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "X25519 failed")))
                elif True:
                    return HpkeOut_HContinue(Hpke_HDh((e).point, d_3_pkR_, d_4_info_), Action_X25519(d_2_skE_, d_3_pkR_))
        if True:
            if source0_.is_HDh:
                d_5_enc_ = source0_.enc
                d_6_pkR_ = source0_.pkR
                d_7_info_ = source0_.info
                if not((e).is_X25519Result):
                    return HpkeOut_HFailed(EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "unexpected event")))
                elif (len((e).point)) != (32):
                    return HpkeOut_HFailed(EHBP.Code_HpkeSetupFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "X25519 failed")))
                elif True:
                    return default__.Schedule(Hpke_HSchedule(0, default__.Extract(_dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference([])), d_5_enc_, d_6_pkR_, d_7_info_, _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference([])), default__.LabeledExtract(default__.KemSuiteId, _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "eae_prk")), (e).point))
        if True:
            d_8_stage_ = source0_.stage
            d_9_job_ = source0_.job
            d_10_enc_ = source0_.enc
            d_11_pkR_ = source0_.pkR
            d_12_info_ = source0_.info
            d_13_shared_ = source0_.shared
            d_14_pskIdHash_ = source0_.pskIdHash
            d_15_infoHash_ = source0_.infoHash
            d_16_secret_ = source0_.secret
            d_17_key_ = source0_.key
            d_18_baseNonce_ = source0_.baseNonce
            source1_ = default__.JobStep(d_9_job_, e)
            if True:
                if source1_.is_JobFailed:
                    d_19_code_ = source1_.code
                    d_20_message_ = source1_.message
                    return HpkeOut_HFailed(d_19_code_, d_20_message_)
            if True:
                if source1_.is_Pending:
                    d_21_next_ = source1_.job
                    d_22_action_ = source1_.action
                    def iife0_(_pat_let3_0):
                        def iife1_(d_23_dt__update__tmp_h0_):
                            def iife2_(_pat_let4_0):
                                def iife3_(d_24_dt__update_hjob_h0_):
                                    return Hpke_HSchedule((d_23_dt__update__tmp_h0_).stage, d_24_dt__update_hjob_h0_, (d_23_dt__update__tmp_h0_).enc, (d_23_dt__update__tmp_h0_).pkR, (d_23_dt__update__tmp_h0_).info, (d_23_dt__update__tmp_h0_).shared, (d_23_dt__update__tmp_h0_).pskIdHash, (d_23_dt__update__tmp_h0_).infoHash, (d_23_dt__update__tmp_h0_).secret, (d_23_dt__update__tmp_h0_).key, (d_23_dt__update__tmp_h0_).baseNonce)
                                return iife3_(_pat_let4_0)
                            return iife2_(d_21_next_)
                        return iife1_(_pat_let3_0)
                    return HpkeOut_HContinue(iife0_(h), d_22_action_)
            if True:
                d_25_out_ = source1_.data
                d_26_ksc_ = ((_dafny.SeqWithoutIsStrInference([0])) + (d_14_pskIdHash_)) + (d_15_infoHash_)
                if (d_8_stage_) == (0):
                    def iife4_(_pat_let5_0):
                        def iife5_(d_27_dt__update__tmp_h1_):
                            def iife6_(_pat_let6_0):
                                def iife7_(d_28_dt__update_hstage_h0_):
                                    return Hpke_HSchedule(d_28_dt__update_hstage_h0_, (d_27_dt__update__tmp_h1_).job, (d_27_dt__update__tmp_h1_).enc, (d_27_dt__update__tmp_h1_).pkR, (d_27_dt__update__tmp_h1_).info, (d_27_dt__update__tmp_h1_).shared, (d_27_dt__update__tmp_h1_).pskIdHash, (d_27_dt__update__tmp_h1_).infoHash, (d_27_dt__update__tmp_h1_).secret, (d_27_dt__update__tmp_h1_).key, (d_27_dt__update__tmp_h1_).baseNonce)
                                return iife7_(_pat_let6_0)
                            return iife6_(1)
                        return iife5_(_pat_let5_0)
                    return default__.Schedule(iife4_(h), default__.LabeledExpand(default__.KemSuiteId, d_25_out_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "shared_secret")), (d_10_enc_) + (d_11_pkR_), EHBP.default__.HashLength))
                elif (d_8_stage_) == (1):
                    def iife8_(_pat_let7_0):
                        def iife9_(d_29_dt__update__tmp_h2_):
                            def iife10_(_pat_let8_0):
                                def iife11_(d_30_dt__update_hshared_h0_):
                                    def iife12_(_pat_let9_0):
                                        def iife13_(d_31_dt__update_hstage_h1_):
                                            return Hpke_HSchedule(d_31_dt__update_hstage_h1_, (d_29_dt__update__tmp_h2_).job, (d_29_dt__update__tmp_h2_).enc, (d_29_dt__update__tmp_h2_).pkR, (d_29_dt__update__tmp_h2_).info, d_30_dt__update_hshared_h0_, (d_29_dt__update__tmp_h2_).pskIdHash, (d_29_dt__update__tmp_h2_).infoHash, (d_29_dt__update__tmp_h2_).secret, (d_29_dt__update__tmp_h2_).key, (d_29_dt__update__tmp_h2_).baseNonce)
                                        return iife13_(_pat_let9_0)
                                    return iife12_(2)
                                return iife11_(_pat_let8_0)
                            return iife10_(d_25_out_)
                        return iife9_(_pat_let7_0)
                    return default__.Schedule(iife8_(h), default__.LabeledExtract(default__.HpkeSuiteId, _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "psk_id_hash")), _dafny.SeqWithoutIsStrInference([])))
                elif (d_8_stage_) == (2):
                    def iife14_(_pat_let10_0):
                        def iife15_(d_32_dt__update__tmp_h3_):
                            def iife16_(_pat_let11_0):
                                def iife17_(d_33_dt__update_hpskIdHash_h0_):
                                    def iife18_(_pat_let12_0):
                                        def iife19_(d_34_dt__update_hstage_h2_):
                                            return Hpke_HSchedule(d_34_dt__update_hstage_h2_, (d_32_dt__update__tmp_h3_).job, (d_32_dt__update__tmp_h3_).enc, (d_32_dt__update__tmp_h3_).pkR, (d_32_dt__update__tmp_h3_).info, (d_32_dt__update__tmp_h3_).shared, d_33_dt__update_hpskIdHash_h0_, (d_32_dt__update__tmp_h3_).infoHash, (d_32_dt__update__tmp_h3_).secret, (d_32_dt__update__tmp_h3_).key, (d_32_dt__update__tmp_h3_).baseNonce)
                                        return iife19_(_pat_let12_0)
                                    return iife18_(3)
                                return iife17_(_pat_let11_0)
                            return iife16_(d_25_out_)
                        return iife15_(_pat_let10_0)
                    return default__.Schedule(iife14_(h), default__.LabeledExtract(default__.HpkeSuiteId, _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "info_hash")), d_12_info_))
                elif (d_8_stage_) == (3):
                    def iife20_(_pat_let13_0):
                        def iife21_(d_35_dt__update__tmp_h4_):
                            def iife22_(_pat_let14_0):
                                def iife23_(d_36_dt__update_hinfoHash_h0_):
                                    def iife24_(_pat_let15_0):
                                        def iife25_(d_37_dt__update_hstage_h3_):
                                            return Hpke_HSchedule(d_37_dt__update_hstage_h3_, (d_35_dt__update__tmp_h4_).job, (d_35_dt__update__tmp_h4_).enc, (d_35_dt__update__tmp_h4_).pkR, (d_35_dt__update__tmp_h4_).info, (d_35_dt__update__tmp_h4_).shared, (d_35_dt__update__tmp_h4_).pskIdHash, d_36_dt__update_hinfoHash_h0_, (d_35_dt__update__tmp_h4_).secret, (d_35_dt__update__tmp_h4_).key, (d_35_dt__update__tmp_h4_).baseNonce)
                                        return iife25_(_pat_let15_0)
                                    return iife24_(4)
                                return iife23_(_pat_let14_0)
                            return iife22_(d_25_out_)
                        return iife21_(_pat_let13_0)
                    return default__.Schedule(iife20_(h), default__.LabeledExtract(default__.HpkeSuiteId, d_13_shared_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "secret")), _dafny.SeqWithoutIsStrInference([])))
                elif (d_8_stage_) == (4):
                    def iife26_(_pat_let16_0):
                        def iife27_(d_38_dt__update__tmp_h5_):
                            def iife28_(_pat_let17_0):
                                def iife29_(d_39_dt__update_hsecret_h0_):
                                    def iife30_(_pat_let18_0):
                                        def iife31_(d_40_dt__update_hstage_h4_):
                                            return Hpke_HSchedule(d_40_dt__update_hstage_h4_, (d_38_dt__update__tmp_h5_).job, (d_38_dt__update__tmp_h5_).enc, (d_38_dt__update__tmp_h5_).pkR, (d_38_dt__update__tmp_h5_).info, (d_38_dt__update__tmp_h5_).shared, (d_38_dt__update__tmp_h5_).pskIdHash, (d_38_dt__update__tmp_h5_).infoHash, d_39_dt__update_hsecret_h0_, (d_38_dt__update__tmp_h5_).key, (d_38_dt__update__tmp_h5_).baseNonce)
                                        return iife31_(_pat_let18_0)
                                    return iife30_(5)
                                return iife29_(_pat_let17_0)
                            return iife28_(d_25_out_)
                        return iife27_(_pat_let16_0)
                    return default__.Schedule(iife26_(h), default__.LabeledExpand(default__.HpkeSuiteId, d_25_out_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "key")), d_26_ksc_, EHBP.default__.KeyLength))
                elif (d_8_stage_) == (5):
                    def iife32_(_pat_let19_0):
                        def iife33_(d_41_dt__update__tmp_h6_):
                            def iife34_(_pat_let20_0):
                                def iife35_(d_42_dt__update_hkey_h0_):
                                    def iife36_(_pat_let21_0):
                                        def iife37_(d_43_dt__update_hstage_h5_):
                                            return Hpke_HSchedule(d_43_dt__update_hstage_h5_, (d_41_dt__update__tmp_h6_).job, (d_41_dt__update__tmp_h6_).enc, (d_41_dt__update__tmp_h6_).pkR, (d_41_dt__update__tmp_h6_).info, (d_41_dt__update__tmp_h6_).shared, (d_41_dt__update__tmp_h6_).pskIdHash, (d_41_dt__update__tmp_h6_).infoHash, (d_41_dt__update__tmp_h6_).secret, d_42_dt__update_hkey_h0_, (d_41_dt__update__tmp_h6_).baseNonce)
                                        return iife37_(_pat_let21_0)
                                    return iife36_(6)
                                return iife35_(_pat_let20_0)
                            return iife34_(d_25_out_)
                        return iife33_(_pat_let19_0)
                    return default__.Schedule(iife32_(h), default__.LabeledExpand(default__.HpkeSuiteId, d_16_secret_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "base_nonce")), d_26_ksc_, EHBP.default__.NonceLength))
                elif (d_8_stage_) == (6):
                    def iife38_(_pat_let22_0):
                        def iife39_(d_44_dt__update__tmp_h7_):
                            def iife40_(_pat_let23_0):
                                def iife41_(d_45_dt__update_hbaseNonce_h0_):
                                    def iife42_(_pat_let24_0):
                                        def iife43_(d_46_dt__update_hstage_h6_):
                                            return Hpke_HSchedule(d_46_dt__update_hstage_h6_, (d_44_dt__update__tmp_h7_).job, (d_44_dt__update__tmp_h7_).enc, (d_44_dt__update__tmp_h7_).pkR, (d_44_dt__update__tmp_h7_).info, (d_44_dt__update__tmp_h7_).shared, (d_44_dt__update__tmp_h7_).pskIdHash, (d_44_dt__update__tmp_h7_).infoHash, (d_44_dt__update__tmp_h7_).secret, (d_44_dt__update__tmp_h7_).key, d_45_dt__update_hbaseNonce_h0_)
                                        return iife43_(_pat_let24_0)
                                    return iife42_(7)
                                return iife41_(_pat_let23_0)
                            return iife40_(d_25_out_)
                        return iife39_(_pat_let22_0)
                    return default__.Schedule(iife38_(h), default__.LabeledExpand(default__.HpkeSuiteId, d_16_secret_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "exp")), d_26_ksc_, EHBP.default__.HashLength))
                elif (((d_8_stage_) == (7)) and ((len(d_17_key_)) == (EHBP.default__.KeyLength))) and ((len(d_18_baseNonce_)) == (EHBP.default__.NonceLength)):
                    d_47_k_ = d_17_key_
                    d_48_n_ = d_18_baseNonce_
                    return HpkeOut_HReady(Ctx_Ctx(d_47_k_, d_48_n_, d_25_out_, 0), d_10_enc_)
                elif True:
                    return HpkeOut_HFailed(EHBP.Code_HpkeSetupFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "key schedule produced the wrong lengths")))

    @staticmethod
    def SealAction(ctx, plaintext):
        return Action_AeadSeal((ctx).key, EHBP.default__.ComputeNonce((ctx).baseNonce, (ctx).seqNo), plaintext)

    @staticmethod
    def OpenAction(ctx, ciphertext):
        return Action_AeadOpen((ctx).key, EHBP.default__.ComputeNonce((ctx).baseNonce, (ctx).seqNo), ciphertext)

    @staticmethod
    def Bump(ctx):
        d_0_dt__update__tmp_h0_ = ctx
        d_1_dt__update_hseqNo_h0_ = ((ctx).seqNo) + (1)
        return Ctx_Ctx((d_0_dt__update__tmp_h0_).key, (d_0_dt__update__tmp_h0_).baseNonce, (d_0_dt__update__tmp_h0_).exporterSecret, d_1_dt__update_hseqNo_h0_)

    @staticmethod
    def ExportJob(ctx, context, length):
        return default__.LabeledExpand(default__.HpkeSuiteId, (ctx).exporterSecret, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "sec")), context, length)

    @staticmethod
    def JsonWs(c):
        return ((((c) == (_dafny.CodePoint(' '))) or ((c) == (_dafny.CodePoint('\t')))) or ((c) == (_dafny.CodePoint('\n')))) or ((c) == (_dafny.CodePoint('\r')))

    @staticmethod
    def IsDigit(c):
        return ((_dafny.CodePoint('0')) <= (c)) and ((c) <= (_dafny.CodePoint('9')))

    @staticmethod
    def SkipWs(s, i):
        while True:
            with _dafny.label():
                if ((i) < (len(s))) and (default__.JsonWs((s)[i])):
                    in0_ = s
                    in1_ = (i) + (1)
                    s = in0_
                    i = in1_
                    raise _dafny.TailCall()
                elif True:
                    return i
                break

    @staticmethod
    def Digits(s, i):
        while True:
            with _dafny.label():
                if ((i) < (len(s))) and (default__.IsDigit((s)[i])):
                    in0_ = s
                    in1_ = (i) + (1)
                    s = in0_
                    i = in1_
                    raise _dafny.TailCall()
                elif True:
                    return i
                break

    @staticmethod
    def Hex4(s, i):
        if ((i) + (4)) > (len(s)):
            return EHBP.Option_None()
        elif True:
            source0_ = (EHBP.default__.HexDigitValue((s)[i]), EHBP.default__.HexDigitValue((s)[(i) + (1)]), EHBP.default__.HexDigitValue((s)[(i) + (2)]), EHBP.default__.HexDigitValue((s)[(i) + (3)]))
            if True:
                d_00_ = source0_[0]
                if d_00_.is_Some:
                    d_0_a_ = d_00_.value
                    d_10_ = source0_[1]
                    if d_10_.is_Some:
                        d_1_b_ = d_10_.value
                        d_20_ = source0_[2]
                        if d_20_.is_Some:
                            d_2_c_ = d_20_.value
                            d_30_ = source0_[3]
                            if d_30_.is_Some:
                                d_3_d_ = d_30_.value
                                return EHBP.Option_Some(((((d_0_a_) * (4096)) + ((d_1_b_) * (256))) + ((d_2_c_) * (16))) + (d_3_d_))
            if True:
                return EHBP.Option_None()

    @staticmethod
    def Keep(acc, add):
        if (len(acc)) >= (default__.MaxJsonStringChars):
            return acc
        elif ((len(acc)) + (len(add))) <= (default__.MaxJsonStringChars):
            return (acc) + (add)
        elif True:
            return (acc) + (_dafny.SeqWithoutIsStrInference((add)[:(default__.MaxJsonStringChars) - (len(acc)):]))

    @staticmethod
    def Max(a, b):
        if (a) >= (b):
            return a
        elif True:
            return b

    @staticmethod
    def LiteralEnd(s, i):
        while True:
            with _dafny.label():
                if ((((i) == (len(s))) or (((s)[i]) == (_dafny.CodePoint('"')))) or (((s)[i]) == (_dafny.CodePoint('\\')))) or ((ord((s)[i])) < (32)):
                    return i
                elif True:
                    in0_ = s
                    in1_ = (i) + (1)
                    s = in0_
                    i = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def ParseString(s, i, acc):
        while True:
            with _dafny.label():
                d_0_j_ = default__.LiteralEnd(s, i)
                d_1_run_ = default__.Keep(acc, _dafny.SeqWithoutIsStrInference((s)[i:d_0_j_:]))
                if (d_0_j_) == (len(s)):
                    return EHBP.Option_None()
                elif ((s)[d_0_j_]) == (_dafny.CodePoint('"')):
                    return EHBP.Option_Some((d_1_run_, (d_0_j_) + (1)))
                elif (ord((s)[d_0_j_])) < (32):
                    return EHBP.Option_None()
                elif ((d_0_j_) + (1)) == (len(s)):
                    return EHBP.Option_None()
                elif True:
                    d_2_c_ = (s)[(d_0_j_) + (1)]
                    if (((d_2_c_) == (_dafny.CodePoint('"'))) or ((d_2_c_) == (_dafny.CodePoint('\\')))) or ((d_2_c_) == (_dafny.CodePoint('/'))):
                        in0_ = s
                        in1_ = (d_0_j_) + (2)
                        in2_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([d_2_c_]))
                        s = in0_
                        i = in1_
                        acc = in2_
                        raise _dafny.TailCall()
                    elif (d_2_c_) == (_dafny.CodePoint('b')):
                        in3_ = s
                        in4_ = (d_0_j_) + (2)
                        in5_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(8))]))
                        s = in3_
                        i = in4_
                        acc = in5_
                        raise _dafny.TailCall()
                    elif (d_2_c_) == (_dafny.CodePoint('f')):
                        in6_ = s
                        in7_ = (d_0_j_) + (2)
                        in8_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(12))]))
                        s = in6_
                        i = in7_
                        acc = in8_
                        raise _dafny.TailCall()
                    elif (d_2_c_) == (_dafny.CodePoint('n')):
                        in9_ = s
                        in10_ = (d_0_j_) + (2)
                        in11_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([_dafny.CodePoint('\n')]))
                        s = in9_
                        i = in10_
                        acc = in11_
                        raise _dafny.TailCall()
                    elif (d_2_c_) == (_dafny.CodePoint('r')):
                        in12_ = s
                        in13_ = (d_0_j_) + (2)
                        in14_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([_dafny.CodePoint('\r')]))
                        s = in12_
                        i = in13_
                        acc = in14_
                        raise _dafny.TailCall()
                    elif (d_2_c_) == (_dafny.CodePoint('t')):
                        in15_ = s
                        in16_ = (d_0_j_) + (2)
                        in17_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([_dafny.CodePoint('\t')]))
                        s = in15_
                        i = in16_
                        acc = in17_
                        raise _dafny.TailCall()
                    elif (d_2_c_) != (_dafny.CodePoint('u')):
                        return EHBP.Option_None()
                    elif True:
                        source0_ = default__.Hex4(s, (d_0_j_) + (2))
                        if True:
                            if source0_.is_None:
                                return EHBP.Option_None()
                        if True:
                            d_3_cp_ = source0_.value
                            if ((55296) <= (d_3_cp_)) and ((d_3_cp_) <= (56319)):
                                d_4_lo_ = (default__.Hex4(s, (d_0_j_) + (8)) if ((((d_0_j_) + (8)) <= (len(s))) and (((s)[(d_0_j_) + (6)]) == (_dafny.CodePoint('\\')))) and (((s)[(d_0_j_) + (7)]) == (_dafny.CodePoint('u'))) else EHBP.Option_None())
                                if ((d_4_lo_).is_Some) and (((56320) <= ((d_4_lo_).value)) and (((d_4_lo_).value) <= (57343))):
                                    in18_ = s
                                    in19_ = (d_0_j_) + (12)
                                    in20_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(((65536) + (((d_3_cp_) - (55296)) * (1024))) + (((d_4_lo_).value) - (56320))))]))
                                    s = in18_
                                    i = in19_
                                    acc = in20_
                                    raise _dafny.TailCall()
                                elif True:
                                    in21_ = s
                                    in22_ = (d_0_j_) + (6)
                                    in23_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(65533))]))
                                    s = in21_
                                    i = in22_
                                    acc = in23_
                                    raise _dafny.TailCall()
                            elif ((56320) <= (d_3_cp_)) and ((d_3_cp_) <= (57343)):
                                in24_ = s
                                in25_ = (d_0_j_) + (6)
                                in26_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(65533))]))
                                s = in24_
                                i = in25_
                                acc = in26_
                                raise _dafny.TailCall()
                            elif True:
                                in27_ = s
                                in28_ = (d_0_j_) + (6)
                                in29_ = default__.Keep(d_1_run_, _dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(d_3_cp_))]))
                                s = in27_
                                i = in28_
                                acc = in29_
                                raise _dafny.TailCall()
                break

    @staticmethod
    def Frac(s, i):
        if ((i) < (len(s))) and (((s)[i]) == (_dafny.CodePoint('.'))):
            if (((i) + (1)) < (len(s))) and (default__.IsDigit((s)[(i) + (1)])):
                return EHBP.Option_Some(default__.Digits(s, (i) + (1)))
            elif True:
                return EHBP.Option_None()
        elif True:
            return EHBP.Option_Some(i)

    @staticmethod
    def Exponent(s, i):
        if ((i) < (len(s))) and ((((s)[i]) == (_dafny.CodePoint('e'))) or (((s)[i]) == (_dafny.CodePoint('E')))):
            d_0_j_ = ((i) + (2) if (((i) + (1)) < (len(s))) and ((((s)[(i) + (1)]) == (_dafny.CodePoint('+'))) or (((s)[(i) + (1)]) == (_dafny.CodePoint('-')))) else (i) + (1))
            if ((d_0_j_) < (len(s))) and (default__.IsDigit((s)[d_0_j_])):
                return EHBP.Option_Some(default__.Digits(s, d_0_j_))
            elif True:
                return EHBP.Option_None()
        elif True:
            return EHBP.Option_Some(i)

    @staticmethod
    def ParseNumber(s, i):
        d_0_j_ = ((i) + (1) if ((i) < (len(s))) and (((s)[i]) == (_dafny.CodePoint('-'))) else i)
        if (d_0_j_) == (len(s)):
            return EHBP.Option_None()
        elif True:
            d_1_k_ = (EHBP.Option_Some((d_0_j_) + (1)) if ((s)[d_0_j_]) == (_dafny.CodePoint('0')) else (EHBP.Option_Some(default__.Digits(s, (d_0_j_) + (1))) if default__.IsDigit((s)[d_0_j_]) else EHBP.Option_None()))
            if (d_1_k_).is_None:
                return EHBP.Option_None()
            elif True:
                source0_ = default__.Frac(s, (d_1_k_).value)
                if True:
                    if source0_.is_None:
                        return EHBP.Option_None()
                if True:
                    d_2_f_ = source0_.value
                    source1_ = default__.Exponent(s, d_2_f_)
                    if True:
                        if source1_.is_None:
                            return EHBP.Option_None()
                    if True:
                        d_3_end_ = source1_.value
                        return EHBP.Option_Some((Json_JNumber(_dafny.SeqWithoutIsStrInference((s)[i:d_3_end_:])), d_3_end_))

    @staticmethod
    def Literal(s, i, word, value):
        if (((i) + (len(word))) <= (len(s))) and ((_dafny.SeqWithoutIsStrInference((s)[i:(i) + (len(word)):])) == (word)):
            return EHBP.Option_Some((value, (i) + (len(word))))
        elif True:
            return EHBP.Option_None()

    @staticmethod
    def ParseValue(s, i, depth):
        if (i) == (len(s)):
            return EHBP.Option_None()
        elif ((((s)[i]) == (_dafny.CodePoint('{'))) or (((s)[i]) == (_dafny.CodePoint('[')))) and ((depth) >= (default__.MaxJsonDepth)):
            return EHBP.Option_None()
        elif ((s)[i]) == (_dafny.CodePoint('{')):
            return default__.ParseMembers(s, default__.SkipWs(s, (i) + (1)), (depth) + (1), _dafny.SeqWithoutIsStrInference([]), True)
        elif ((s)[i]) == (_dafny.CodePoint('[')):
            return default__.ParseItems(s, default__.SkipWs(s, (i) + (1)), (depth) + (1), _dafny.SeqWithoutIsStrInference([]), True)
        elif ((s)[i]) == (_dafny.CodePoint('"')):
            source0_ = default__.ParseString(s, (i) + (1), _dafny.SeqWithoutIsStrInference([]))
            if True:
                if source0_.is_None:
                    return EHBP.Option_None()
            if True:
                value0 = source0_.value
                d_0_str_ = value0[0]
                d_1_j_ = value0[1]
                return EHBP.Option_Some((Json_JString(d_0_str_), d_1_j_))
        elif ((s)[i]) == (_dafny.CodePoint('t')):
            return default__.Literal(s, i, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "true")), Json_JBool(True))
        elif ((s)[i]) == (_dafny.CodePoint('f')):
            return default__.Literal(s, i, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "false")), Json_JBool(False))
        elif ((s)[i]) == (_dafny.CodePoint('n')):
            return default__.Literal(s, i, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "null")), Json_JNull())
        elif True:
            return default__.ParseNumber(s, i)

    @staticmethod
    def ItemsFrom(s, i, depth, acc, first):
        if (i) == (len(s)):
            return EHBP.Option_None()
        elif (first) and (((s)[i]) == (_dafny.CodePoint(']'))):
            return EHBP.Option_Some((Json_JArray(acc), (i) + (1)))
        elif True:
            source0_ = default__.ParseValue(s, i, depth)
            if True:
                if source0_.is_None:
                    return EHBP.Option_None()
            if True:
                value0 = source0_.value
                d_0_v_ = value0[0]
                d_1_k_ = value0[1]
                d_2_m_ = default__.SkipWs(s, d_1_k_)
                if (d_2_m_) == (len(s)):
                    return EHBP.Option_None()
                elif ((s)[d_2_m_]) == (_dafny.CodePoint(',')):
                    return default__.ItemsFrom(s, default__.SkipWs(s, (d_2_m_) + (1)), depth, (acc) + (_dafny.SeqWithoutIsStrInference([d_0_v_])), False)
                elif ((s)[d_2_m_]) == (_dafny.CodePoint(']')):
                    return EHBP.Option_Some((Json_JArray((acc) + (_dafny.SeqWithoutIsStrInference([d_0_v_]))), (d_2_m_) + (1)))
                elif True:
                    return EHBP.Option_None()

    @staticmethod
    def ParseItems(s, i, depth, acc, first):
        r: EHBP.Option = EHBP.Option.default()()
        d_0_a_: _dafny.Array
        def lambda0_(d_1___v14_):
            return Json_JNull()

        init0_ = lambda0_
        nw0_ = _dafny.Array(None, 0)
        for i0_0_ in range(nw0_.length(0)):
            nw0_[i0_0_] = init0_(i0_0_)
        d_0_a_ = nw0_
        d_2_n_: int
        d_3_j_: int
        d_4_f_: bool
        rhs0_ = 0
        rhs1_ = i
        rhs2_ = first
        d_2_n_ = rhs0_
        d_3_j_ = rhs1_
        d_4_f_ = rhs2_
        while True:
            if (d_3_j_) == (len(s)):
                r = EHBP.Option_None()
                return r
            if (d_4_f_) and (((s)[d_3_j_]) == (_dafny.CodePoint(']'))):
                r = EHBP.Option_Some((Json_JArray((acc) + (_dafny.SeqWithoutIsStrInference((d_0_a_)[:d_2_n_:]))), (d_3_j_) + (1)))
                return r
            d_5_r_: EHBP.Option
            d_5_r_ = default__.ParseValue(s, d_3_j_, depth)
            if (d_5_r_).is_None:
                r = EHBP.Option_None()
                return r
            let_tmp_rhs0_ = (d_5_r_).value
            d_6_v_ = let_tmp_rhs0_[0]
            d_7_k_ = let_tmp_rhs0_[1]
            d_8_m_: int
            d_8_m_ = default__.SkipWs(s, d_7_k_)
            if (d_8_m_) == (len(s)):
                r = EHBP.Option_None()
                return r
            if ((s)[d_8_m_]) == (_dafny.CodePoint(']')):
                r = EHBP.Option_Some((Json_JArray(((acc) + (_dafny.SeqWithoutIsStrInference((d_0_a_)[:d_2_n_:]))) + (_dafny.SeqWithoutIsStrInference([d_6_v_]))), (d_8_m_) + (1)))
                return r
            if ((s)[d_8_m_]) != (_dafny.CodePoint(',')):
                r = EHBP.Option_None()
                return r
            out0_: _dafny.Array
            out0_ = default__.Append(d_0_a_, d_2_n_, d_6_v_)
            d_0_a_ = out0_
            rhs3_ = (d_2_n_) + (1)
            rhs4_ = default__.SkipWs(s, (d_8_m_) + (1))
            rhs5_ = False
            d_2_n_ = rhs3_
            d_3_j_ = rhs4_
            d_4_f_ = rhs5_
        return r

    @staticmethod
    def MembersFrom(s, i, depth, acc, first):
        if (i) == (len(s)):
            return EHBP.Option_None()
        elif (first) and (((s)[i]) == (_dafny.CodePoint('}'))):
            return EHBP.Option_Some((Json_JObject(acc), (i) + (1)))
        elif ((s)[i]) != (_dafny.CodePoint('"')):
            return EHBP.Option_None()
        elif True:
            source0_ = default__.ParseString(s, (i) + (1), _dafny.SeqWithoutIsStrInference([]))
            if True:
                if source0_.is_None:
                    return EHBP.Option_None()
            if True:
                value0 = source0_.value
                d_0_name_ = value0[0]
                d_1_k_ = value0[1]
                d_2_c_ = default__.SkipWs(s, d_1_k_)
                if ((d_2_c_) == (len(s))) or (((s)[d_2_c_]) != (_dafny.CodePoint(':'))):
                    return EHBP.Option_None()
                elif True:
                    source1_ = default__.ParseValue(s, default__.SkipWs(s, (d_2_c_) + (1)), depth)
                    if True:
                        if source1_.is_None:
                            return EHBP.Option_None()
                    if True:
                        value1 = source1_.value
                        d_3_v_ = value1[0]
                        d_4_k2_ = value1[1]
                        d_5_m_ = default__.SkipWs(s, d_4_k2_)
                        if (d_5_m_) == (len(s)):
                            return EHBP.Option_None()
                        elif ((s)[d_5_m_]) == (_dafny.CodePoint(',')):
                            return default__.MembersFrom(s, default__.SkipWs(s, (d_5_m_) + (1)), depth, (acc) + (_dafny.SeqWithoutIsStrInference([(d_0_name_, d_3_v_)])), False)
                        elif ((s)[d_5_m_]) == (_dafny.CodePoint('}')):
                            return EHBP.Option_Some((Json_JObject((acc) + (_dafny.SeqWithoutIsStrInference([(d_0_name_, d_3_v_)]))), (d_5_m_) + (1)))
                        elif True:
                            return EHBP.Option_None()

    @staticmethod
    def ParseMembers(s, i, depth, acc, first):
        r: EHBP.Option = EHBP.Option.default()()
        d_0_a_: _dafny.Array
        def lambda0_(d_1___v15_):
            return (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), Json_JNull())

        init0_ = lambda0_
        nw0_ = _dafny.Array(None, 0)
        for i0_0_ in range(nw0_.length(0)):
            nw0_[i0_0_] = init0_(i0_0_)
        d_0_a_ = nw0_
        d_2_n_: int
        d_3_j_: int
        d_4_f_: bool
        rhs0_ = 0
        rhs1_ = i
        rhs2_ = first
        d_2_n_ = rhs0_
        d_3_j_ = rhs1_
        d_4_f_ = rhs2_
        while True:
            if (d_3_j_) == (len(s)):
                r = EHBP.Option_None()
                return r
            if (d_4_f_) and (((s)[d_3_j_]) == (_dafny.CodePoint('}'))):
                r = EHBP.Option_Some((Json_JObject((acc) + (_dafny.SeqWithoutIsStrInference((d_0_a_)[:d_2_n_:]))), (d_3_j_) + (1)))
                return r
            if ((s)[d_3_j_]) != (_dafny.CodePoint('"')):
                r = EHBP.Option_None()
                return r
            d_5_rn_: EHBP.Option
            d_5_rn_ = default__.ParseString(s, (d_3_j_) + (1), _dafny.SeqWithoutIsStrInference([]))
            if (d_5_rn_).is_None:
                r = EHBP.Option_None()
                return r
            let_tmp_rhs0_ = (d_5_rn_).value
            d_6_name_ = let_tmp_rhs0_[0]
            d_7_k_ = let_tmp_rhs0_[1]
            d_8_c_: int
            d_8_c_ = default__.SkipWs(s, d_7_k_)
            if ((d_8_c_) == (len(s))) or (((s)[d_8_c_]) != (_dafny.CodePoint(':'))):
                r = EHBP.Option_None()
                return r
            d_9_r_: EHBP.Option
            d_9_r_ = default__.ParseValue(s, default__.SkipWs(s, (d_8_c_) + (1)), depth)
            if (d_9_r_).is_None:
                r = EHBP.Option_None()
                return r
            let_tmp_rhs1_ = (d_9_r_).value
            d_10_v_ = let_tmp_rhs1_[0]
            d_11_k2_ = let_tmp_rhs1_[1]
            d_12_m_: int
            d_12_m_ = default__.SkipWs(s, d_11_k2_)
            if (d_12_m_) == (len(s)):
                r = EHBP.Option_None()
                return r
            if ((s)[d_12_m_]) == (_dafny.CodePoint('}')):
                r = EHBP.Option_Some((Json_JObject(((acc) + (_dafny.SeqWithoutIsStrInference((d_0_a_)[:d_2_n_:]))) + (_dafny.SeqWithoutIsStrInference([(d_6_name_, d_10_v_)]))), (d_12_m_) + (1)))
                return r
            if ((s)[d_12_m_]) != (_dafny.CodePoint(',')):
                r = EHBP.Option_None()
                return r
            out0_: _dafny.Array
            out0_ = default__.Append(d_0_a_, d_2_n_, (d_6_name_, d_10_v_))
            d_0_a_ = out0_
            rhs3_ = (d_2_n_) + (1)
            rhs4_ = default__.SkipWs(s, (d_12_m_) + (1))
            rhs5_ = False
            d_2_n_ = rhs3_
            d_3_j_ = rhs4_
            d_4_f_ = rhs5_
        return r

    @staticmethod
    def Append(a, n, v):
        b: _dafny.Array = _dafny.Array(None, 0)
        if (n) < ((a).length(0)):
            (a)[(n)] = v
            b = a
            return b
        def lambda0_(d_0_n_, d_1_a_, d_2_v_):
            def lambda1_(d_3_k_):
                return ((d_1_a_)[d_3_k_] if ((0) <= (d_3_k_)) and ((d_3_k_) < (d_0_n_)) else d_2_v_)

            return lambda1_

        init0_ = lambda0_(n, a, v)
        nw0_ = _dafny.Array(None, ((2) * (n)) + (1))
        for i0_0_ in range(nw0_.length(0)):
            nw0_[i0_0_] = init0_(i0_0_)
        b = nw0_
        return b

    @staticmethod
    def ParseJson(s):
        source0_ = default__.ParseValue(s, default__.SkipWs(s, 0), 0)
        if True:
            if source0_.is_None:
                return EHBP.Option_None()
        if True:
            value0 = source0_.value
            d_0_v_ = value0[0]
            d_1_j_ = value0[1]
            if (default__.SkipWs(s, d_1_j_)) == (len(s)):
                return EHBP.Option_Some(d_0_v_)
            elif True:
                return EHBP.Option_None()

    @staticmethod
    def Member(members, name):
        return default__.MemberFrom(members, len(members), name)

    @staticmethod
    def MemberFrom(members, n, name):
        while True:
            with _dafny.label():
                if (n) == (0):
                    return EHBP.Option_None()
                elif (((members)[(n) - (1)])[0]) == (name):
                    return EHBP.Option_Some(((members)[(n) - (1)])[1])
                elif True:
                    in0_ = members
                    in1_ = (n) - (1)
                    in2_ = name
                    members = in0_
                    n = in1_
                    name = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def StringMember(members, name):
        source0_ = default__.Member(members, name)
        if True:
            if source0_.is_Some:
                value0 = source0_.value
                if value0.is_JString:
                    d_0_v_ = value0.s
                    return EHBP.Option_Some(d_0_v_)
        if True:
            return EHBP.Option_None()

    @staticmethod
    def Cont(b):
        return ((128) <= (b)) and ((b) <= (191))

    @staticmethod
    def Utf8From(b, i, acc):
        while True:
            with _dafny.label():
                if (i) == (len(b)):
                    return acc
                elif True:
                    d_0_c_ = (b)[i]
                    if (d_0_c_) < (128):
                        in0_ = b
                        in1_ = (i) + (1)
                        in2_ = (acc) + (_dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(d_0_c_))]))
                        b = in0_
                        i = in1_
                        acc = in2_
                        raise _dafny.TailCall()
                    elif ((((194) <= (d_0_c_)) and ((d_0_c_) <= (223))) and (((i) + (2)) <= (len(b)))) and (default__.Cont((b)[(i) + (1)])):
                        in3_ = b
                        in4_ = (i) + (2)
                        in5_ = (acc) + (_dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr((((d_0_c_) - (192)) * (64)) + (((b)[(i) + (1)]) - (128))))]))
                        b = in3_
                        i = in4_
                        acc = in5_
                        raise _dafny.TailCall()
                    elif (((((224) <= (d_0_c_)) and ((d_0_c_) <= (239))) and (((i) + (3)) <= (len(b)))) and (default__.Cont((b)[(i) + (1)]))) and (default__.Cont((b)[(i) + (2)])):
                        d_1_cp_ = ((((d_0_c_) - (224)) * (4096)) + ((((b)[(i) + (1)]) - (128)) * (64))) + (((b)[(i) + (2)]) - (128))
                        if ((d_1_cp_) < (2048)) or (((55296) <= (d_1_cp_)) and ((d_1_cp_) <= (57343))):
                            in6_ = b
                            in7_ = (i) + (1)
                            in8_ = (acc) + (_dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(65533))]))
                            b = in6_
                            i = in7_
                            acc = in8_
                            raise _dafny.TailCall()
                        elif True:
                            in9_ = b
                            in10_ = (i) + (3)
                            in11_ = (acc) + (_dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(d_1_cp_))]))
                            b = in9_
                            i = in10_
                            acc = in11_
                            raise _dafny.TailCall()
                    elif ((((((240) <= (d_0_c_)) and ((d_0_c_) <= (244))) and (((i) + (4)) <= (len(b)))) and (default__.Cont((b)[(i) + (1)]))) and (default__.Cont((b)[(i) + (2)]))) and (default__.Cont((b)[(i) + (3)])):
                        d_2_cp_ = (((((d_0_c_) - (240)) * (262144)) + ((((b)[(i) + (1)]) - (128)) * (4096))) + ((((b)[(i) + (2)]) - (128)) * (64))) + (((b)[(i) + (3)]) - (128))
                        if ((d_2_cp_) < (65536)) or ((d_2_cp_) > (1114111)):
                            in12_ = b
                            in13_ = (i) + (1)
                            in14_ = (acc) + (_dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(65533))]))
                            b = in12_
                            i = in13_
                            acc = in14_
                            raise _dafny.TailCall()
                        elif True:
                            in15_ = b
                            in16_ = (i) + (4)
                            in17_ = (acc) + (_dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(d_2_cp_))]))
                            b = in15_
                            i = in16_
                            acc = in17_
                            raise _dafny.TailCall()
                    elif True:
                        in18_ = b
                        in19_ = (i) + (1)
                        in20_ = (acc) + (_dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr(65533))]))
                        b = in18_
                        i = in19_
                        acc = in20_
                        raise _dafny.TailCall()
                break

    @staticmethod
    def Utf8(b):
        hresult_: _dafny.Seq = _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, ""))
        d_0_a_: _dafny.Array
        def lambda0_(d_1___v17_):
            return _dafny.CodePoint(' ')

        init0_ = lambda0_
        nw0_ = _dafny.Array(None, len(b))
        for i0_0_ in range(nw0_.length(0)):
            nw0_[i0_0_] = init0_(i0_0_)
        d_0_a_ = nw0_
        d_2_i_: int
        d_3_n_: int
        rhs0_ = 0
        rhs1_ = 0
        d_2_i_ = rhs0_
        d_3_n_ = rhs1_
        while (d_2_i_) < (len(b)):
            d_4_c_: int
            d_4_c_ = (b)[d_2_i_]
            d_5_cp_: int
            d_6_w_: int
            rhs2_ = 65533
            rhs3_ = 1
            d_5_cp_ = rhs2_
            d_6_w_ = rhs3_
            if (d_4_c_) < (128):
                d_5_cp_ = d_4_c_
            elif ((((194) <= (d_4_c_)) and ((d_4_c_) <= (223))) and (((d_2_i_) + (2)) <= (len(b)))) and (default__.Cont((b)[(d_2_i_) + (1)])):
                rhs4_ = (((d_4_c_) - (192)) * (64)) + (((b)[(d_2_i_) + (1)]) - (128))
                rhs5_ = 2
                d_5_cp_ = rhs4_
                d_6_w_ = rhs5_
            elif (((((224) <= (d_4_c_)) and ((d_4_c_) <= (239))) and (((d_2_i_) + (3)) <= (len(b)))) and (default__.Cont((b)[(d_2_i_) + (1)]))) and (default__.Cont((b)[(d_2_i_) + (2)])):
                d_7_v_: int
                d_7_v_ = ((((d_4_c_) - (224)) * (4096)) + ((((b)[(d_2_i_) + (1)]) - (128)) * (64))) + (((b)[(d_2_i_) + (2)]) - (128))
                if not(((d_7_v_) < (2048)) or (((55296) <= (d_7_v_)) and ((d_7_v_) <= (57343)))):
                    rhs6_ = d_7_v_
                    rhs7_ = 3
                    d_5_cp_ = rhs6_
                    d_6_w_ = rhs7_
            elif ((((((240) <= (d_4_c_)) and ((d_4_c_) <= (244))) and (((d_2_i_) + (4)) <= (len(b)))) and (default__.Cont((b)[(d_2_i_) + (1)]))) and (default__.Cont((b)[(d_2_i_) + (2)]))) and (default__.Cont((b)[(d_2_i_) + (3)])):
                d_8_v_: int
                d_8_v_ = (((((d_4_c_) - (240)) * (262144)) + ((((b)[(d_2_i_) + (1)]) - (128)) * (4096))) + ((((b)[(d_2_i_) + (2)]) - (128)) * (64))) + (((b)[(d_2_i_) + (3)]) - (128))
                if not(((d_8_v_) < (65536)) or ((d_8_v_) > (1114111))):
                    rhs8_ = d_8_v_
                    rhs9_ = 4
                    d_5_cp_ = rhs8_
                    d_6_w_ = rhs9_
            (d_0_a_)[(d_3_n_)] = _dafny.CodePoint(chr(d_5_cp_))
            rhs10_ = (d_2_i_) + (d_6_w_)
            rhs11_ = (d_3_n_) + (1)
            d_2_i_ = rhs10_
            d_3_n_ = rhs11_
        hresult_ = _dafny.SeqWithoutIsStrInference((d_0_a_)[:d_3_n_:])
        return hresult_
        return hresult_

    @staticmethod
    def ParseProblem(body):
        source0_ = default__.ParseJson(default__.Utf8(body))
        if True:
            if source0_.is_Some:
                value0 = source0_.value
                if value0.is_JObject:
                    d_0_members_ = value0.members
                    return (True, default__.StringMember(d_0_members_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "type"))), default__.StringMember(d_0_members_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "title"))))
        if True:
            return (False, EHBP.Option_None(), EHBP.Option_None())

    @staticmethod
    def ParseToken(json):
        source0_ = default__.ParseJson(json)
        if True:
            if source0_.is_Some:
                value0 = source0_.value
                if value0.is_JObject:
                    d_0_members_ = value0.members
                    return (default__.StringMember(d_0_members_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "exportedSecret"))), default__.StringMember(d_0_members_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "requestEnc"))))
        if True:
            return (EHBP.Option_None(), EHBP.Option_None())

    @staticmethod
    def Escape(s):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(s)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_1_c_ = (s)[0]
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "\\\"")) if (d_1_c_) == (_dafny.CodePoint('"')) else (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "\\\\")) if (d_1_c_) == (_dafny.CodePoint('\\')) else ((_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "\\u00"))) + (_dafny.SeqWithoutIsStrInference([(EHBP.default__.HexDigits)[_dafny.euclidian_division(ord(d_1_c_), 16)], (EHBP.default__.HexDigits)[_dafny.euclidian_modulus(ord(d_1_c_), 16)]])) if (ord(d_1_c_)) < (32) else _dafny.SeqWithoutIsStrInference([d_1_c_])))))
                    in0_ = _dafny.SeqWithoutIsStrInference((s)[1::])
                    s = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def FormatToken(exportedSecretHex, requestEncHex):
        return ((((_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "{\"exportedSecret\":\""))) + (default__.Escape(exportedSecretHex))) + (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "\",\"requestEnc\":\"")))) + (default__.Escape(requestEncHex))) + (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "\"}")))

    @staticmethod
    def SessionApply(store, action):
        source0_ = action
        if True:
            if source0_.is_Begin:
                return SessionStore_SessionStore((0 if ((store).generation) == (default__.MaxSeq) else ((store).generation) + (1)), EHBP.Option_None())
        if True:
            if source0_.is_Publish:
                d_0_generation_ = source0_.generation
                d_1_token_ = source0_.token
                if (d_0_generation_) == ((store).generation):
                    d_2_dt__update__tmp_h0_ = store
                    d_3_dt__update_htoken_h0_ = EHBP.Option_Some(d_1_token_)
                    return SessionStore_SessionStore((d_2_dt__update__tmp_h0_).generation, d_3_dt__update_htoken_h0_)
                elif True:
                    return store
        if True:
            d_4_generation_ = source0_.generation
            if (d_4_generation_) == ((store).generation):
                d_5_dt__update__tmp_h1_ = store
                d_6_dt__update_htoken_h1_ = EHBP.Option_None()
                return SessionStore_SessionStore((d_5_dt__update__tmp_h1_).generation, d_6_dt__update_htoken_h1_)
            elif True:
                return store

    @staticmethod
    def Frames(d, buf, i, acc):
        while True:
            with _dafny.label():
                pat_let_tv0_ = buf
                pat_let_tv1_ = i
                pat_let_tv2_ = buf
                pat_let_tv3_ = i
                if ((len(buf)) - (i)) < (4):
                    def iife0_(_pat_let25_0):
                        def iife1_(d_0_dt__update__tmp_h0_):
                            def iife2_(_pat_let26_0):
                                def iife3_(d_1_dt__update_hpending_h0_):
                                    return Dec_Dec(d_1_dt__update_hpending_h0_, (d_0_dt__update__tmp_h0_).next_, (d_0_dt__update__tmp_h0_).authenticated, (d_0_dt__update__tmp_h0_).requireFrame)
                                return iife3_(_pat_let26_0)
                            return iife2_(_dafny.SeqWithoutIsStrInference((pat_let_tv0_)[pat_let_tv1_::]))
                        return iife1_(_pat_let25_0)
                    return (acc, iife0_(d), EHBP.Option_None())
                elif True:
                    d_2_length_ = EHBP.default__.U32(buf, i)
                    if (d_2_length_) == (0):
                        in0_ = d
                        in1_ = buf
                        in2_ = (i) + (4)
                        in3_ = acc
                        d = in0_
                        buf = in1_
                        i = in2_
                        acc = in3_
                        raise _dafny.TailCall()
                    elif (d_2_length_) > (EHBP.default__.MaxChunkBytes):
                        return (acc, d, EHBP.Option_Some(EHBP.Code_ChunkTooLarge()))
                    elif ((len(buf)) - (i)) < ((4) + (d_2_length_)):
                        def iife4_(_pat_let27_0):
                            def iife5_(d_3_dt__update__tmp_h1_):
                                def iife6_(_pat_let28_0):
                                    def iife7_(d_4_dt__update_hpending_h1_):
                                        return Dec_Dec(d_4_dt__update_hpending_h1_, (d_3_dt__update__tmp_h1_).next_, (d_3_dt__update__tmp_h1_).authenticated, (d_3_dt__update__tmp_h1_).requireFrame)
                                    return iife7_(_pat_let28_0)
                                return iife6_(_dafny.SeqWithoutIsStrInference((pat_let_tv2_)[pat_let_tv3_::]))
                            return iife5_(_pat_let27_0)
                        return (acc, iife4_(d), EHBP.Option_None())
                    elif ((d).next_) == (default__.MaxSeq):
                        return (acc, d, EHBP.Option_Some(EHBP.Code_SequenceOverflow()))
                    elif True:
                        in4_ = Dec_Dec(_dafny.SeqWithoutIsStrInference([]), ((d).next_) + (1), True, (d).requireFrame)
                        in5_ = buf
                        in6_ = ((i) + (4)) + (d_2_length_)
                        in7_ = (acc) + (_dafny.SeqWithoutIsStrInference([EHBP.Framed_Framed((d).next_, _dafny.SeqWithoutIsStrInference((buf)[(i) + (4):((i) + (4)) + (d_2_length_):]))]))
                        d = in4_
                        buf = in5_
                        i = in6_
                        acc = in7_
                        raise _dafny.TailCall()
                break

    @staticmethod
    def FrameNeed(pending):
        if (len(pending)) < (4):
            return (4) - (len(pending))
        elif True:
            d_0_whole_ = (4) + (EHBP.default__.U32(pending, 0))
            if (d_0_whole_) > (len(pending)):
                return (d_0_whole_) - (len(pending))
            elif True:
                return 1

    @staticmethod
    def Push(d, data):
        return default__.PushFrom(d, data, 0, _dafny.SeqWithoutIsStrInference([]))

    @staticmethod
    def PushFrom(d, data, i, acc):
        while True:
            with _dafny.label():
                if (len((d).pending)) == (0):
                    return default__.Frames(d, data, i, acc)
                elif (i) == (len(data)):
                    return (acc, d, EHBP.Option_None())
                elif True:
                    d_0_take_ = default__.Min((len(data)) - (i), default__.FrameNeed((d).pending))
                    let_tmp_rhs0_ = default__.Frames(d, ((d).pending) + (_dafny.SeqWithoutIsStrInference((data)[i:(i) + (d_0_take_):])), 0, acc)
                    d_1_frames_ = let_tmp_rhs0_[0]
                    d_2_next_ = let_tmp_rhs0_[1]
                    d_3_err_ = let_tmp_rhs0_[2]
                    if (d_3_err_).is_Some:
                        return (d_1_frames_, d_2_next_, d_3_err_)
                    elif True:
                        in0_ = d_2_next_
                        in1_ = data
                        in2_ = (i) + (d_0_take_)
                        in3_ = d_1_frames_
                        d = in0_
                        data = in1_
                        i = in2_
                        acc = in3_
                        raise _dafny.TailCall()
                break

    @staticmethod
    def Finish(d):
        if ((len((d).pending)) != (0)) or (((d).requireFrame) and (not((d).authenticated))):
            return EHBP.Option_Some(EHBP.Code_FramingTruncated())
        elif True:
            return EHBP.Option_None()

    @staticmethod
    def Initial(origin, publicKey):
        return State_State(Phase_Idle(), origin, publicKey, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference([]), 0, False, EHBP.Token_Token(_dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference([])), default__.NoCtx)

    @staticmethod
    def ResponseOnly(origin, token):
        return State_State(Phase_Exchanging(Upload_UpDone(), Response_AwaitHead(True)), origin, _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference([]), 0, False, token, default__.NoCtx)

    @staticmethod
    def DecryptStart(token, status, headers):
        return default__.Step(default__.ResponseOnly(default__.NoOrigin, token), Event_ResponseHead(status, headers, False))

    @staticmethod
    def DeriveStart(token, responseNonce):
        return default__.Step(default__.ResponseOnly(default__.NoOrigin, token), Event_ResponseHead(200, _dafny.SeqWithoutIsStrInference([(EHBP.default__.ResponseNonceHeader, EHBP.default__.EncodeHex(responseNonce))]), False))

    @staticmethod
    def KeysOf(s):
        if (((s).phase).is_Exchanging) and ((((s).phase).response).is_Body):
            return EHBP.Option_Some((((((s).phase).response).keys).key, ((((s).phase).response).keys).baseNonce))
        elif True:
            return EHBP.Option_None()

    @staticmethod
    def Contract(s, e, r):
        return ((not (default__.Ends((r)[1])) or ((not(((r)[0]).published)) and ((default__.ClearsOnce((r)[1], (s).generation) if (s).published else default__.NoClear((r)[1]))))) and (not (not(default__.Ends((r)[1]))) or (default__.NoClear((r)[1])))) and (not (not(default__.NoEmit((r)[1]))) or (((((e).is_AeadOpenResult) and ((e).ok)) and (((s).phase).is_Exchanging)) and ((((s).phase).response).is_Opening)))

    @staticmethod
    def Ending(s, r):
        return (((default__.Ends((r)[1])) and (not(((r)[0]).published))) and ((default__.ClearsOnce((r)[1], (s).generation) if (s).published else default__.NoClear((r)[1])))) and (default__.NoEmit((r)[1]))

    @staticmethod
    def End(s, close, last):
        def lambda0_():
            source0_ = (s).phase
            if True:
                if source0_.is_Exchanging:
                    d_1_up_ = source0_.upload
                    return Phase_Exchanging(d_1_up_, Response_RespEnded())
            if True:
                return Phase_Ended()

        d_0_phase_ = lambda0_()
        d_2_g_ = (s).generation
        d_3_acts_ = (_dafny.SeqWithoutIsStrInference([Action_Close(Stream_ResponseBody()), Action_ClearToken(d_2_g_), last]) if (close) and ((s).published) else (_dafny.SeqWithoutIsStrInference([Action_Close(Stream_ResponseBody()), last]) if close else (_dafny.SeqWithoutIsStrInference([Action_ClearToken(d_2_g_), last]) if (s).published else _dafny.SeqWithoutIsStrInference([last]))))
        def iife0_(_pat_let29_0):
            def iife1_(d_4_dt__update__tmp_h0_):
                def iife2_(_pat_let30_0):
                    def iife3_(d_5_dt__update_hpublished_h0_):
                        def iife4_(_pat_let31_0):
                            def iife5_(d_6_dt__update_hphase_h0_):
                                return State_State(d_6_dt__update_hphase_h0_, (d_4_dt__update__tmp_h0_).origin, (d_4_dt__update__tmp_h0_).publicKey, (d_4_dt__update__tmp_h0_).verb, (d_4_dt__update__tmp_h0_).url, (d_4_dt__update__tmp_h0_).headers, (d_4_dt__update__tmp_h0_).generation, d_5_dt__update_hpublished_h0_, (d_4_dt__update__tmp_h0_).token, (d_4_dt__update__tmp_h0_).ctx)
                            return iife5_(_pat_let31_0)
                        return iife4_(d_0_phase_)
                    return iife3_(_pat_let30_0)
                return iife2_(False)
            return iife1_(_pat_let29_0)
        return (iife0_(s), d_3_acts_)

    @staticmethod
    def Abort(s, close, code, message):
        return default__.End(s, close, Action_Fail(code, message))

    @staticmethod
    def Unexpected(s):
        return default__.Abort(s, False, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "unexpected event")))

    @staticmethod
    def Min(a, b):
        if (a) < (b):
            return a
        elif True:
            return b

    @staticmethod
    def Min32(a, b):
        if (a) < (b):
            return a
        elif True:
            return b

    @staticmethod
    def Piece(chunk, at, n):
        if ((at) == (0)) and ((n) == (len(chunk))):
            return chunk
        elif True:
            return _dafny.SeqWithoutIsStrInference((chunk)[at:(at) + (n):])

    @staticmethod
    def FrameWrites(ciphertext, end):
        return _dafny.SeqWithoutIsStrInference([Action_Write(EHBP.default__.BE32(len(ciphertext)), BodyEnd_More()), Action_Write(ciphertext, end)])

    @staticmethod
    def WithUpload(s, up):
        d_0_dt__update__tmp_h0_ = s
        d_1_dt__update_hphase_h0_ = Phase_Exchanging(up, ((s).phase).response)
        return State_State(d_1_dt__update_hphase_h0_, (d_0_dt__update__tmp_h0_).origin, (d_0_dt__update__tmp_h0_).publicKey, (d_0_dt__update__tmp_h0_).verb, (d_0_dt__update__tmp_h0_).url, (d_0_dt__update__tmp_h0_).headers, (d_0_dt__update__tmp_h0_).generation, (d_0_dt__update__tmp_h0_).published, (d_0_dt__update__tmp_h0_).token, (d_0_dt__update__tmp_h0_).ctx)

    @staticmethod
    def WithResponse(s, rs):
        d_0_dt__update__tmp_h0_ = s
        d_1_dt__update_hphase_h0_ = Phase_Exchanging(((s).phase).upload, rs)
        return State_State(d_1_dt__update_hphase_h0_, (d_0_dt__update__tmp_h0_).origin, (d_0_dt__update__tmp_h0_).publicKey, (d_0_dt__update__tmp_h0_).verb, (d_0_dt__update__tmp_h0_).url, (d_0_dt__update__tmp_h0_).headers, (d_0_dt__update__tmp_h0_).generation, (d_0_dt__update__tmp_h0_).published, (d_0_dt__update__tmp_h0_).token, (d_0_dt__update__tmp_h0_).ctx)

    @staticmethod
    def SendPlain(s):
        def iife0_(_pat_let32_0):
            def iife1_(d_0_dt__update__tmp_h0_):
                def iife2_(_pat_let33_0):
                    def iife3_(d_1_dt__update_hphase_h0_):
                        return State_State(d_1_dt__update_hphase_h0_, (d_0_dt__update__tmp_h0_).origin, (d_0_dt__update__tmp_h0_).publicKey, (d_0_dt__update__tmp_h0_).verb, (d_0_dt__update__tmp_h0_).url, (d_0_dt__update__tmp_h0_).headers, (d_0_dt__update__tmp_h0_).generation, (d_0_dt__update__tmp_h0_).published, (d_0_dt__update__tmp_h0_).token, (d_0_dt__update__tmp_h0_).ctx)
                    return iife3_(_pat_let33_0)
                return iife2_(Phase_Exchanging(Upload_NoUpload(), Response_AwaitHead(False)))
            return iife1_(_pat_let32_0)
        return (iife0_(s), _dafny.SeqWithoutIsStrInference([Action_Send((s).verb, (s).url, (s).headers, False)]))

    @staticmethod
    def ForUpload(e):
        return ((((e).is_Chunk) or ((e).is_StreamFailed)) and (((e).stream).is_RequestBody)) or ((e).is_AeadSealResult)

    @staticmethod
    def AbortUpload(s, code):
        return (default__.WithUpload(s, Upload_UpDone()), _dafny.SeqWithoutIsStrInference([Action_Write(_dafny.SeqWithoutIsStrInference([]), BodyEnd_Aborted(code))]))

    @staticmethod
    def Step(s, e):
        pat_let_tv0_ = e
        if (e).is_CallerClose:
            return default__.End(s, False, Action_Close(Stream_ResponseBody()))
        elif True:
            source0_ = (s).phase
            if True:
                if source0_.is_Idle:
                    if (e).is_Start:
                        return default__.StepStart(s, e)
                    elif (e).is_DiscoverStart:
                        def iife0_(_pat_let34_0):
                            def iife1_(d_0_dt__update__tmp_h0_):
                                def iife2_(_pat_let35_0):
                                    def iife3_(d_1_dt__update_hphase_h0_):
                                        return State_State(d_1_dt__update_hphase_h0_, (d_0_dt__update__tmp_h0_).origin, (d_0_dt__update__tmp_h0_).publicKey, (d_0_dt__update__tmp_h0_).verb, (d_0_dt__update__tmp_h0_).url, (d_0_dt__update__tmp_h0_).headers, (d_0_dt__update__tmp_h0_).generation, (d_0_dt__update__tmp_h0_).published, (d_0_dt__update__tmp_h0_).token, (d_0_dt__update__tmp_h0_).ctx)
                                    return iife3_(_pat_let35_0)
                                return iife2_(Phase_DiscAwaitHead())
                            return iife1_(_pat_let34_0)
                        return (iife0_(s), _dafny.SeqWithoutIsStrInference([Action_Send(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "GET")), (EHBP.default__.OriginUrl((s).origin)) + (EHBP.default__.KeysPath), _dafny.SeqWithoutIsStrInference([]), False)]))
                    elif True:
                        return default__.Unexpected(s)
            if True:
                if source0_.is_AwaitSession:
                    d_2_hasBody_ = source0_.hasBody
                    if not((e).is_SessionBegun):
                        return default__.Unexpected(s)
                    elif True:
                        def iife4_(_pat_let36_0):
                            def iife5_(d_4_dt__update__tmp_h1_):
                                def iife6_(_pat_let37_0):
                                    def iife7_(d_5_dt__update_hgeneration_h0_):
                                        return State_State((d_4_dt__update__tmp_h1_).phase, (d_4_dt__update__tmp_h1_).origin, (d_4_dt__update__tmp_h1_).publicKey, (d_4_dt__update__tmp_h1_).verb, (d_4_dt__update__tmp_h1_).url, (d_4_dt__update__tmp_h1_).headers, d_5_dt__update_hgeneration_h0_, (d_4_dt__update__tmp_h1_).published, (d_4_dt__update__tmp_h1_).token, (d_4_dt__update__tmp_h1_).ctx)
                                    return iife7_(_pat_let37_0)
                                return iife6_((pat_let_tv0_).generation)
                            return iife5_(_pat_let36_0)
                        d_3_begun_ = iife4_(s)
                        if d_2_hasBody_:
                            def iife8_(_pat_let38_0):
                                def iife9_(d_6_dt__update__tmp_h2_):
                                    def iife10_(_pat_let39_0):
                                        def iife11_(d_7_dt__update_hphase_h1_):
                                            return State_State(d_7_dt__update_hphase_h1_, (d_6_dt__update__tmp_h2_).origin, (d_6_dt__update__tmp_h2_).publicKey, (d_6_dt__update__tmp_h2_).verb, (d_6_dt__update__tmp_h2_).url, (d_6_dt__update__tmp_h2_).headers, (d_6_dt__update__tmp_h2_).generation, (d_6_dt__update__tmp_h2_).published, (d_6_dt__update__tmp_h2_).token, (d_6_dt__update__tmp_h2_).ctx)
                                        return iife11_(_pat_let39_0)
                                    return iife10_(Phase_Peeking(0))
                                return iife9_(_pat_let38_0)
                            return (iife8_(d_3_begun_), _dafny.SeqWithoutIsStrInference([Action_Read(Stream_RequestBody())]))
                        elif True:
                            return default__.SendPlain(d_3_begun_)
            if True:
                if source0_.is_Peeking:
                    d_8_empty_ = source0_.empty
                    source1_ = e
                    if True:
                        if source1_.is_StreamFailed:
                            stream0 = source1_.stream
                            if stream0.is_RequestBody:
                                return default__.Abort(s, False, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "failed to read request body")))
                    if True:
                        if source1_.is_Chunk:
                            stream1 = source1_.stream
                            if stream1.is_RequestBody:
                                d_9_data_ = source1_.data
                                d_10_eof_ = source1_.eof
                                if (len(d_9_data_)) > (default__.MaxReadBytes):
                                    return default__.Abort(s, False, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "request body chunk too large")))
                                elif (len(d_9_data_)) > (0):
                                    source2_ = default__.SenderStart((s).publicKey, EHBP.default__.Ascii(EHBP.default__.HpkeRequestInfo))
                                    if True:
                                        if source2_.is_HContinue:
                                            d_11_h_ = source2_.h
                                            d_12_a_ = source2_.action
                                            def iife12_(_pat_let40_0):
                                                def iife13_(d_13_dt__update__tmp_h3_):
                                                    def iife14_(_pat_let41_0):
                                                        def iife15_(d_14_dt__update_hphase_h2_):
                                                            return State_State(d_14_dt__update_hphase_h2_, (d_13_dt__update__tmp_h3_).origin, (d_13_dt__update__tmp_h3_).publicKey, (d_13_dt__update__tmp_h3_).verb, (d_13_dt__update__tmp_h3_).url, (d_13_dt__update__tmp_h3_).headers, (d_13_dt__update__tmp_h3_).generation, (d_13_dt__update__tmp_h3_).published, (d_13_dt__update__tmp_h3_).token, (d_13_dt__update__tmp_h3_).ctx)
                                                        return iife15_(_pat_let41_0)
                                                    return iife14_(Phase_AwaitSetup(d_9_data_, d_10_eof_, d_11_h_))
                                                return iife13_(_pat_let40_0)
                                            return (iife12_(s), _dafny.SeqWithoutIsStrInference([d_12_a_]))
                                    if True:
                                        return default__.Unexpected(s)
                                elif d_10_eof_:
                                    return default__.SendPlain(s)
                                elif ((d_8_empty_) + (1)) == (EHBP.default__.MaxEmptyReads):
                                    return default__.Abort(s, False, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "request body made no progress")))
                                elif True:
                                    def iife16_(_pat_let42_0):
                                        def iife17_(d_15_dt__update__tmp_h4_):
                                            def iife18_(_pat_let43_0):
                                                def iife19_(d_16_dt__update_hphase_h3_):
                                                    return State_State(d_16_dt__update_hphase_h3_, (d_15_dt__update__tmp_h4_).origin, (d_15_dt__update__tmp_h4_).publicKey, (d_15_dt__update__tmp_h4_).verb, (d_15_dt__update__tmp_h4_).url, (d_15_dt__update__tmp_h4_).headers, (d_15_dt__update__tmp_h4_).generation, (d_15_dt__update__tmp_h4_).published, (d_15_dt__update__tmp_h4_).token, (d_15_dt__update__tmp_h4_).ctx)
                                                return iife19_(_pat_let43_0)
                                            return iife18_(Phase_Peeking((d_8_empty_) + (1)))
                                        return iife17_(_pat_let42_0)
                                    return (iife16_(s), _dafny.SeqWithoutIsStrInference([Action_Read(Stream_RequestBody())]))
                    if True:
                        return default__.Unexpected(s)
            if True:
                if source0_.is_AwaitSetup:
                    d_17_first_ = source0_.first
                    d_18_firstEof_ = source0_.firstEof
                    d_19_h_ = source0_.hpke
                    source3_ = default__.HpkeStep(d_19_h_, e)
                    if True:
                        if source3_.is_HFailed:
                            d_20_code_ = source3_.code
                            d_21_message_ = source3_.message
                            return default__.Abort(s, False, d_20_code_, d_21_message_)
                    if True:
                        if source3_.is_HContinue:
                            d_22_next_ = source3_.h
                            d_23_a_ = source3_.action
                            def iife20_(_pat_let44_0):
                                def iife21_(d_24_dt__update__tmp_h5_):
                                    def iife22_(_pat_let45_0):
                                        def iife23_(d_25_dt__update_hphase_h4_):
                                            return State_State(d_25_dt__update_hphase_h4_, (d_24_dt__update__tmp_h5_).origin, (d_24_dt__update__tmp_h5_).publicKey, (d_24_dt__update__tmp_h5_).verb, (d_24_dt__update__tmp_h5_).url, (d_24_dt__update__tmp_h5_).headers, (d_24_dt__update__tmp_h5_).generation, (d_24_dt__update__tmp_h5_).published, (d_24_dt__update__tmp_h5_).token, (d_24_dt__update__tmp_h5_).ctx)
                                        return iife23_(_pat_let45_0)
                                    return iife22_(Phase_AwaitSetup(d_17_first_, d_18_firstEof_, d_22_next_))
                                return iife21_(_pat_let44_0)
                            return (iife20_(s), _dafny.SeqWithoutIsStrInference([d_23_a_]))
                    if True:
                        d_26_ctx_ = source3_.ctx
                        d_27_enc_ = source3_.enc
                        d_28_job_ = default__.ExportJob(d_26_ctx_, EHBP.default__.Ascii(EHBP.default__.ExportLabel), EHBP.default__.ExportLength)
                        def iife24_(_pat_let46_0):
                            def iife25_(d_29_dt__update__tmp_h6_):
                                def iife26_(_pat_let47_0):
                                    def iife27_(d_30_dt__update_hctx_h0_):
                                        def iife28_(_pat_let48_0):
                                            def iife29_(d_31_dt__update_hphase_h5_):
                                                return State_State(d_31_dt__update_hphase_h5_, (d_29_dt__update__tmp_h6_).origin, (d_29_dt__update__tmp_h6_).publicKey, (d_29_dt__update__tmp_h6_).verb, (d_29_dt__update__tmp_h6_).url, (d_29_dt__update__tmp_h6_).headers, (d_29_dt__update__tmp_h6_).generation, (d_29_dt__update__tmp_h6_).published, (d_29_dt__update__tmp_h6_).token, d_30_dt__update_hctx_h0_)
                                            return iife29_(_pat_let48_0)
                                        return iife28_(Phase_AwaitExport(d_17_first_, d_18_firstEof_, d_27_enc_, d_28_job_))
                                    return iife27_(_pat_let47_0)
                                return iife26_(d_26_ctx_)
                            return iife25_(_pat_let46_0)
                        return (iife24_(s), _dafny.SeqWithoutIsStrInference([default__.JobAction(d_28_job_)]))
            if True:
                if source0_.is_AwaitExport:
                    d_32_first_ = source0_.first
                    d_33_firstEof_ = source0_.firstEof
                    d_34_enc_ = source0_.enc
                    d_35_job_ = source0_.job
                    source4_ = default__.JobStep(d_35_job_, e)
                    if True:
                        if source4_.is_JobFailed:
                            d_36_code_ = source4_.code
                            d_37_message_ = source4_.message
                            return default__.Abort(s, False, d_36_code_, d_37_message_)
                    if True:
                        if source4_.is_Pending:
                            d_38_next_ = source4_.job
                            d_39_a_ = source4_.action
                            def iife30_(_pat_let49_0):
                                def iife31_(d_40_dt__update__tmp_h7_):
                                    def iife32_(_pat_let50_0):
                                        def iife33_(d_41_dt__update_hphase_h6_):
                                            return State_State(d_41_dt__update_hphase_h6_, (d_40_dt__update__tmp_h7_).origin, (d_40_dt__update__tmp_h7_).publicKey, (d_40_dt__update__tmp_h7_).verb, (d_40_dt__update__tmp_h7_).url, (d_40_dt__update__tmp_h7_).headers, (d_40_dt__update__tmp_h7_).generation, (d_40_dt__update__tmp_h7_).published, (d_40_dt__update__tmp_h7_).token, (d_40_dt__update__tmp_h7_).ctx)
                                        return iife33_(_pat_let50_0)
                                    return iife32_(Phase_AwaitExport(d_32_first_, d_33_firstEof_, d_34_enc_, d_38_next_))
                                return iife31_(_pat_let49_0)
                            return (iife30_(s), _dafny.SeqWithoutIsStrInference([d_39_a_]))
                    if True:
                        d_42_secret_ = source4_.data
                        if (len(d_34_enc_)) != (EHBP.default__.RequestEncLength):
                            return default__.Abort(s, False, EHBP.Code_HpkeSetupFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "HPKE sender setup failed")))
                        elif (len(d_42_secret_)) != (EHBP.default__.ExportLength):
                            return default__.Abort(s, False, EHBP.Code_HpkeSetupFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "HPKE export failed")))
                        elif True:
                            d_43_token_ = EHBP.Token_Token(d_42_secret_, d_34_enc_)
                            d_44_headers_ = ((s).headers) + (_dafny.SeqWithoutIsStrInference([(EHBP.default__.EncapsulatedKeyHeader, EHBP.default__.EncodeHex(d_34_enc_))]))
                            def iife34_(_pat_let51_0):
                                def iife35_(d_45_dt__update__tmp_h8_):
                                    def iife36_(_pat_let52_0):
                                        def iife37_(d_46_dt__update_htoken_h0_):
                                            def iife38_(_pat_let53_0):
                                                def iife39_(d_47_dt__update_hpublished_h0_):
                                                    def iife40_(_pat_let54_0):
                                                        def iife41_(d_48_dt__update_hphase_h7_):
                                                            return State_State(d_48_dt__update_hphase_h7_, (d_45_dt__update__tmp_h8_).origin, (d_45_dt__update__tmp_h8_).publicKey, (d_45_dt__update__tmp_h8_).verb, (d_45_dt__update__tmp_h8_).url, (d_45_dt__update__tmp_h8_).headers, (d_45_dt__update__tmp_h8_).generation, d_47_dt__update_hpublished_h0_, d_46_dt__update_htoken_h0_, (d_45_dt__update__tmp_h8_).ctx)
                                                        return iife41_(_pat_let54_0)
                                                    return iife40_(Phase_Exchanging(Upload_Sealing(d_32_first_, 0, d_33_firstEof_), Response_AwaitHead(True)))
                                                return iife39_(_pat_let53_0)
                                            return iife38_(True)
                                        return iife37_(_pat_let52_0)
                                    return iife36_(d_43_token_)
                                return iife35_(_pat_let51_0)
                            return (iife34_(s), _dafny.SeqWithoutIsStrInference([Action_PublishToken((s).generation, d_42_secret_, d_34_enc_), Action_Send((s).verb, (s).url, d_44_headers_, True), default__.SealAction((s).ctx, default__.Piece(d_32_first_, 0, default__.Min32(len(d_32_first_), EHBP.default__.RequestFrameBytes)))]))
            if True:
                if source0_.is_Exchanging:
                    d_49_up_ = source0_.upload
                    d_50_rs_ = source0_.response
                    if default__.ForUpload(e):
                        return default__.StepUpload(s, d_49_up_, e)
                    elif True:
                        return default__.StepResponse(s, d_50_rs_, e)
            if True:
                if source0_.is_DiscAwaitHead:
                    source5_ = e
                    if True:
                        if source5_.is_StreamFailed:
                            stream2 = source5_.stream
                            if stream2.is_ResponseBody:
                                return default__.Abort(s, False, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "failed to get server public key")))
                    if True:
                        if source5_.is_ResponseHead:
                            d_51_status_ = source5_.status
                            d_52_headers_ = source5_.headers
                            d_53_redirected_ = source5_.redirected
                            if ((d_51_status_) < (100)) or ((d_51_status_) > (599)):
                                return default__.Abort(s, True, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "failed to get server public key")))
                            elif True:
                                source6_ = EHBP.default__.ClassifyDiscovery(EHBP.Head_Head(d_51_status_, d_52_headers_, d_53_redirected_))
                                if True:
                                    if source6_.is_Err:
                                        d_54_code_ = source6_.code
                                        d_55_message_ = source6_.message
                                        return default__.Abort(s, True, d_54_code_, d_55_message_)
                                if True:
                                    def iife42_(_pat_let55_0):
                                        def iife43_(d_56_dt__update__tmp_h9_):
                                            def iife44_(_pat_let56_0):
                                                def iife45_(d_57_dt__update_hphase_h8_):
                                                    return State_State(d_57_dt__update_hphase_h8_, (d_56_dt__update__tmp_h9_).origin, (d_56_dt__update__tmp_h9_).publicKey, (d_56_dt__update__tmp_h9_).verb, (d_56_dt__update__tmp_h9_).url, (d_56_dt__update__tmp_h9_).headers, (d_56_dt__update__tmp_h9_).generation, (d_56_dt__update__tmp_h9_).published, (d_56_dt__update__tmp_h9_).token, (d_56_dt__update__tmp_h9_).ctx)
                                                return iife45_(_pat_let56_0)
                                            return iife44_(Phase_DiscReading(_dafny.SeqWithoutIsStrInference([])))
                                        return iife43_(_pat_let55_0)
                                    return (iife42_(s), _dafny.SeqWithoutIsStrInference([Action_Read(Stream_ResponseBody())]))
                    if True:
                        return default__.Unexpected(s)
            if True:
                if source0_.is_DiscReading:
                    d_58_data_ = source0_.data
                    source7_ = e
                    if True:
                        if source7_.is_StreamFailed:
                            stream3 = source7_.stream
                            if stream3.is_ResponseBody:
                                return default__.Abort(s, True, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "failed to read key configuration")))
                    if True:
                        if source7_.is_Chunk:
                            stream4 = source7_.stream
                            if stream4.is_ResponseBody:
                                d_59_chunk_ = source7_.data
                                d_60_eof_ = source7_.eof
                                d_61_grown_ = (d_58_data_) + (d_59_chunk_)
                                if ((len(d_61_grown_)) <= (EHBP.default__.MaxKeyConfigBytes)) and (not(d_60_eof_)):
                                    def iife46_(_pat_let57_0):
                                        def iife47_(d_62_dt__update__tmp_h10_):
                                            def iife48_(_pat_let58_0):
                                                def iife49_(d_63_dt__update_hphase_h9_):
                                                    return State_State(d_63_dt__update_hphase_h9_, (d_62_dt__update__tmp_h10_).origin, (d_62_dt__update__tmp_h10_).publicKey, (d_62_dt__update__tmp_h10_).verb, (d_62_dt__update__tmp_h10_).url, (d_62_dt__update__tmp_h10_).headers, (d_62_dt__update__tmp_h10_).generation, (d_62_dt__update__tmp_h10_).published, (d_62_dt__update__tmp_h10_).token, (d_62_dt__update__tmp_h10_).ctx)
                                                return iife49_(_pat_let58_0)
                                            return iife48_(Phase_DiscReading(d_61_grown_))
                                        return iife47_(_pat_let57_0)
                                    return (iife46_(s), _dafny.SeqWithoutIsStrInference([Action_Read(Stream_ResponseBody())]))
                                elif True:
                                    source8_ = EHBP.default__.ParseConfig(d_61_grown_)
                                    if True:
                                        if source8_.is_Ok:
                                            d_64_pk_ = source8_.value
                                            return default__.End(s, True, Action_Discovered(d_64_pk_))
                                    if True:
                                        d_65_code_ = source8_.code
                                        d_66_message_ = source8_.message
                                        return default__.Abort(s, True, d_65_code_, d_66_message_)
                    if True:
                        return default__.Unexpected(s)
            if True:
                return default__.Unexpected(s)

    @staticmethod
    def StepStart(s, e):
        pat_let_tv0_ = e
        pat_let_tv1_ = e
        pat_let_tv2_ = e
        pat_let_tv3_ = e
        d_0_target_ = EHBP.default__.MakeOrigin((e).scheme, (e).host, (EHBP.Option_Some((e).port) if (e).hasPort else EHBP.Option_None()), (e).hasUserinfo)
        source0_ = EHBP.default__.ValidateRequest((s).origin, d_0_target_, (e).headers)
        if True:
            if source0_.is_Err:
                d_1_code_ = source0_.code
                d_2_message_ = source0_.message
                return default__.Abort(s, False, d_1_code_, d_2_message_)
        if True:
            def iife0_(_pat_let59_0):
                def iife1_(d_3_dt__update__tmp_h0_):
                    def iife2_(_pat_let60_0):
                        def iife3_(d_4_dt__update_hheaders_h0_):
                            def iife4_(_pat_let61_0):
                                def iife5_(d_5_dt__update_hurl_h0_):
                                    def iife6_(_pat_let62_0):
                                        def iife7_(d_6_dt__update_hverb_h0_):
                                            def iife8_(_pat_let63_0):
                                                def iife9_(d_7_dt__update_hphase_h0_):
                                                    return State_State(d_7_dt__update_hphase_h0_, (d_3_dt__update__tmp_h0_).origin, (d_3_dt__update__tmp_h0_).publicKey, d_6_dt__update_hverb_h0_, d_5_dt__update_hurl_h0_, d_4_dt__update_hheaders_h0_, (d_3_dt__update__tmp_h0_).generation, (d_3_dt__update__tmp_h0_).published, (d_3_dt__update__tmp_h0_).token, (d_3_dt__update__tmp_h0_).ctx)
                                                return iife9_(_pat_let63_0)
                                            return iife8_(Phase_AwaitSession((pat_let_tv3_).hasBody))
                                        return iife7_(_pat_let62_0)
                                    return iife6_((pat_let_tv2_).verb)
                                return iife5_(_pat_let61_0)
                            return iife4_((pat_let_tv1_).url)
                        return iife3_(_pat_let60_0)
                    return iife2_(EHBP.default__.DropFraming((pat_let_tv0_).headers))
                return iife1_(_pat_let59_0)
            return (iife0_(s), _dafny.SeqWithoutIsStrInference([Action_BeginSession()]))

    @staticmethod
    def StepUpload(s, up, e):
        pat_let_tv0_ = s
        source0_ = up
        if True:
            if source0_.is_Sealing:
                d_0_plaintext_ = source0_.plaintext
                d_1_offset_ = source0_.offset
                d_2_eof_ = source0_.eof
                d_3_size_ = len(d_0_plaintext_)
                d_4_at_ = default__.Min32(d_1_offset_, d_3_size_)
                d_5_n_ = default__.Min32((d_3_size_) - (d_4_at_), EHBP.default__.RequestFrameBytes)
                if not((e).is_AeadSealResult):
                    return default__.AbortUpload(s, EHBP.Code_Transport())
                elif (len((e).ciphertext)) != ((d_5_n_) + (EHBP.default__.AeadTagLength)):
                    return default__.AbortUpload(s, EHBP.Code_HpkeSetupFailed())
                elif (((s).ctx).seqNo) == (default__.MaxSeq):
                    return default__.AbortUpload(s, EHBP.Code_SequenceOverflow())
                elif True:
                    def iife0_(_pat_let64_0):
                        def iife1_(d_7_dt__update__tmp_h0_):
                            def iife2_(_pat_let65_0):
                                def iife3_(d_8_dt__update_hctx_h0_):
                                    return State_State((d_7_dt__update__tmp_h0_).phase, (d_7_dt__update__tmp_h0_).origin, (d_7_dt__update__tmp_h0_).publicKey, (d_7_dt__update__tmp_h0_).verb, (d_7_dt__update__tmp_h0_).url, (d_7_dt__update__tmp_h0_).headers, (d_7_dt__update__tmp_h0_).generation, (d_7_dt__update__tmp_h0_).published, (d_7_dt__update__tmp_h0_).token, d_8_dt__update_hctx_h0_)
                                return iife3_(_pat_let65_0)
                            return iife2_(default__.Bump((pat_let_tv0_).ctx))
                        return iife1_(_pat_let64_0)
                    d_6_bumped_ = iife0_(s)
                    d_9_next_ = (d_4_at_) + (d_5_n_)
                    if (d_9_next_) < (d_3_size_):
                        return (default__.WithUpload(d_6_bumped_, Upload_Sealing(d_0_plaintext_, d_9_next_, d_2_eof_)), (default__.FrameWrites((e).ciphertext, BodyEnd_More())) + (_dafny.SeqWithoutIsStrInference([default__.SealAction((d_6_bumped_).ctx, default__.Piece(d_0_plaintext_, d_9_next_, default__.Min32((d_3_size_) - (d_9_next_), EHBP.default__.RequestFrameBytes)))])))
                    elif d_2_eof_:
                        return (default__.WithUpload(d_6_bumped_, Upload_UpDone()), default__.FrameWrites((e).ciphertext, BodyEnd_Done()))
                    elif True:
                        return (default__.WithUpload(d_6_bumped_, Upload_UpReading(0)), (default__.FrameWrites((e).ciphertext, BodyEnd_More())) + (_dafny.SeqWithoutIsStrInference([Action_Read(Stream_RequestBody())])))
        if True:
            if source0_.is_UpReading:
                d_10_empty_ = source0_.empty
                source1_ = e
                if True:
                    if source1_.is_StreamFailed:
                        stream0 = source1_.stream
                        if stream0.is_RequestBody:
                            return default__.AbortUpload(s, EHBP.Code_Transport())
                if True:
                    if source1_.is_Chunk:
                        stream1 = source1_.stream
                        if stream1.is_RequestBody:
                            d_11_data_ = source1_.data
                            d_12_eof_ = source1_.eof
                            if (len(d_11_data_)) > (default__.MaxReadBytes):
                                return default__.AbortUpload(s, EHBP.Code_Transport())
                            elif (len(d_11_data_)) > (0):
                                return (default__.WithUpload(s, Upload_Sealing(d_11_data_, 0, d_12_eof_)), _dafny.SeqWithoutIsStrInference([default__.SealAction((s).ctx, default__.Piece(d_11_data_, 0, default__.Min32(len(d_11_data_), EHBP.default__.RequestFrameBytes)))]))
                            elif d_12_eof_:
                                return (default__.WithUpload(s, Upload_UpDone()), _dafny.SeqWithoutIsStrInference([Action_Write(_dafny.SeqWithoutIsStrInference([]), BodyEnd_Done())]))
                            elif ((d_10_empty_) + (1)) == (EHBP.default__.MaxEmptyReads):
                                return default__.AbortUpload(s, EHBP.Code_Transport())
                            elif True:
                                return (default__.WithUpload(s, Upload_UpReading((d_10_empty_) + (1))), _dafny.SeqWithoutIsStrInference([Action_Read(Stream_RequestBody())]))
                if True:
                    return default__.AbortUpload(s, EHBP.Code_Transport())
        if True:
            return default__.AbortUpload(s, EHBP.Code_Transport())

    @staticmethod
    def StepResponse(s, rs, e):
        source0_ = rs
        if True:
            if source0_.is_AwaitHead:
                d_0_encrypted_ = source0_.encrypted
                source1_ = e
                if True:
                    if source1_.is_StreamFailed:
                        stream0 = source1_.stream
                        if stream0.is_ResponseBody:
                            return default__.Abort(s, False, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "failed to make request")))
                if True:
                    if source1_.is_ResponseHead:
                        d_1_status_ = source1_.status
                        d_2_headers_ = source1_.headers
                        d_3_redirected_ = source1_.redirected
                        if (not(d_3_redirected_)) and (((d_1_status_) < (100)) or ((d_1_status_) > (599))):
                            return default__.Abort(s, True, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "transport reported an impossible status")))
                        elif True:
                            source2_ = EHBP.default__.Classify(d_0_encrypted_, EHBP.Head_Head(d_1_status_, d_2_headers_, d_3_redirected_))
                            if True:
                                if source2_.is_PassThrough:
                                    return default__.End(s, False, Action_Passthrough(d_1_status_, d_2_headers_, _dafny.SeqWithoutIsStrInference([])))
                            if True:
                                if source2_.is_Refuse:
                                    d_4_code_ = source2_.code
                                    d_5_message_ = source2_.message
                                    return default__.Abort(s, True, d_4_code_, d_5_message_)
                            if True:
                                if source2_.is_NeedProblemBody:
                                    return (default__.WithResponse(s, Response_ProblemReading(d_1_status_, d_2_headers_, _dafny.SeqWithoutIsStrInference([]))), _dafny.SeqWithoutIsStrInference([Action_Read(Stream_ResponseBody())]))
                            if True:
                                d_6_nonce_ = source2_.nonce
                                d_7_requireFrame_ = source2_.requireFrame
                                if not(EHBP.default__.ValidToken((s).token)):
                                    return default__.Abort(s, True, EHBP.Code_InvalidInput(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "token fields must be 32 bytes")))
                                elif (len(d_6_nonce_)) != (EHBP.default__.ResponseNonceLength):
                                    return default__.Abort(s, True, EHBP.Code_InvalidInput(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "response nonce must be 32 bytes")))
                                elif True:
                                    d_8_job_ = default__.Extract((((s).token).requestEnc) + (d_6_nonce_), ((s).token).exportedSecret)
                                    return (default__.WithResponse(s, Response_AwaitKeys(d_1_status_, d_2_headers_, d_7_requireFrame_, 0, d_8_job_, _dafny.SeqWithoutIsStrInference([]), _dafny.SeqWithoutIsStrInference([]))), _dafny.SeqWithoutIsStrInference([default__.JobAction(d_8_job_)]))
                if True:
                    return default__.Unexpected(s)
        if True:
            if source0_.is_ProblemReading:
                d_9_status_ = source0_.status
                d_10_headers_ = source0_.headers
                d_11_data_ = source0_.data
                source3_ = e
                if True:
                    if source3_.is_StreamFailed:
                        stream1 = source3_.stream
                        if stream1.is_ResponseBody:
                            return default__.Abort(s, True, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "failed to read problem response")))
                if True:
                    if source3_.is_Chunk:
                        stream2 = source3_.stream
                        if stream2.is_ResponseBody:
                            d_12_chunk_ = source3_.data
                            d_13_eof_ = source3_.eof
                            d_14_grown_ = (d_11_data_) + (d_12_chunk_)
                            if ((len(d_14_grown_)) <= ((EHBP.default__.MaxProblemBytes) + (1))) and (not(d_13_eof_)):
                                return (default__.WithResponse(s, Response_ProblemReading(d_9_status_, d_10_headers_, d_14_grown_)), _dafny.SeqWithoutIsStrInference([Action_Read(Stream_ResponseBody())]))
                            elif True:
                                d_15_oversized_ = (len(d_14_grown_)) > (EHBP.default__.MaxProblemBytes)
                                let_tmp_rhs0_ = ((False, EHBP.Option_None(), EHBP.Option_None()) if d_15_oversized_ else default__.ParseProblem(d_14_grown_))
                                d_16_isObject_ = let_tmp_rhs0_[0]
                                d_17_typeValue_ = let_tmp_rhs0_[1]
                                d_18_title_ = let_tmp_rhs0_[2]
                                source4_ = EHBP.default__.ClassifyProblem(d_15_oversized_, d_16_isObject_, d_17_typeValue_, d_18_title_)
                                if True:
                                    if source4_.is_Refuse:
                                        d_19_code_ = source4_.code
                                        d_20_message_ = source4_.message
                                        return default__.Abort(s, True, d_19_code_, d_20_message_)
                                if True:
                                    if source4_.is_PassThrough:
                                        return default__.End(s, False, Action_Passthrough(d_9_status_, d_10_headers_, d_14_grown_))
                                if True:
                                    return default__.Abort(s, True, EHBP.Code_Transport(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "unreachable")))
                if True:
                    return default__.Unexpected(s)
        if True:
            if source0_.is_AwaitKeys:
                d_21_status_ = source0_.status
                d_22_headers_ = source0_.headers
                d_23_requireFrame_ = source0_.requireFrame
                d_24_stage_ = source0_.stage
                d_25_job_ = source0_.job
                d_26_prk_ = source0_.prk
                d_27_key_ = source0_.key
                source5_ = default__.JobStep(d_25_job_, e)
                if True:
                    if source5_.is_JobFailed:
                        d_28_code_ = source5_.code
                        d_29_message_ = source5_.message
                        return default__.Abort(s, True, d_28_code_, d_29_message_)
                if True:
                    if source5_.is_Pending:
                        d_30_next_ = source5_.job
                        d_31_a_ = source5_.action
                        return (default__.WithResponse(s, Response_AwaitKeys(d_21_status_, d_22_headers_, d_23_requireFrame_, d_24_stage_, d_30_next_, d_26_prk_, d_27_key_)), _dafny.SeqWithoutIsStrInference([d_31_a_]))
                if True:
                    d_32_out_ = source5_.data
                    if (d_24_stage_) == (0):
                        d_33_next_ = default__.Expand(d_32_out_, EHBP.default__.Ascii(EHBP.default__.ResponseKeyLabel), EHBP.default__.KeyLength)
                        return (default__.WithResponse(s, Response_AwaitKeys(d_21_status_, d_22_headers_, d_23_requireFrame_, 1, d_33_next_, d_32_out_, _dafny.SeqWithoutIsStrInference([]))), _dafny.SeqWithoutIsStrInference([default__.JobAction(d_33_next_)]))
                    elif (d_24_stage_) == (1):
                        d_34_next_ = default__.Expand(d_26_prk_, EHBP.default__.Ascii(EHBP.default__.ResponseNonceLabel), EHBP.default__.NonceLength)
                        return (default__.WithResponse(s, Response_AwaitKeys(d_21_status_, d_22_headers_, d_23_requireFrame_, 2, d_34_next_, d_26_prk_, d_32_out_)), _dafny.SeqWithoutIsStrInference([default__.JobAction(d_34_next_)]))
                    elif ((len(d_27_key_)) == (EHBP.default__.KeyLength)) and ((len(d_32_out_)) == (EHBP.default__.NonceLength)):
                        d_35_k_ = d_27_key_
                        d_36_n_ = d_32_out_
                        return (default__.WithResponse(s, Response_Body(Ctx_Ctx(d_35_k_, d_36_n_, _dafny.SeqWithoutIsStrInference([]), 0), Dec_Dec(_dafny.SeqWithoutIsStrInference([]), 0, False, d_23_requireFrame_), False)), _dafny.SeqWithoutIsStrInference([Action_Done(d_21_status_, EHBP.default__.DropFraming(d_22_headers_))]))
                    elif True:
                        return default__.Abort(s, True, EHBP.Code_HpkeSetupFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "HKDF expand returned the wrong length")))
        if True:
            if source0_.is_Body:
                d_37_keys_ = source0_.keys
                d_38_dec_ = source0_.dec
                d_39_done_ = source0_.done
                if not((e).is_CallerRead):
                    return default__.Unexpected(s)
                elif d_39_done_:
                    return default__.End(s, False, Action_Finished())
                elif True:
                    return (default__.WithResponse(s, Response_BodyReading(d_37_keys_, d_38_dec_)), _dafny.SeqWithoutIsStrInference([Action_Read(Stream_ResponseBody())]))
        if True:
            if source0_.is_BodyReading:
                d_40_keys_ = source0_.keys
                d_41_dec_ = source0_.dec
                source6_ = e
                if True:
                    if source6_.is_StreamFailed:
                        stream3 = source6_.stream
                        if stream3.is_ResponseBody:
                            return default__.Abort(s, False, EHBP.Code_FramingTruncated(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "response body failed")))
                if True:
                    if source6_.is_Chunk:
                        stream4 = source6_.stream
                        if stream4.is_ResponseBody:
                            d_42_data_ = source6_.data
                            d_43_eof_ = source6_.eof
                            let_tmp_rhs1_ = default__.Push(d_41_dec_, d_42_data_)
                            d_44_frames_ = let_tmp_rhs1_[0]
                            d_45_next_ = let_tmp_rhs1_[1]
                            d_46_err_ = let_tmp_rhs1_[2]
                            if (d_46_err_).is_Some:
                                return default__.Abort(s, False, (d_46_err_).value, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
                            elif True:
                                return default__.OpenNext(s, d_40_keys_, d_45_next_, d_44_frames_, _dafny.SeqWithoutIsStrInference([]), d_43_eof_)
                if True:
                    return default__.Unexpected(s)
        if True:
            if source0_.is_Opening:
                d_47_keys_ = source0_.keys
                d_48_dec_ = source0_.dec
                d_49_frames_ = source0_.frames
                d_50_chunks_ = source0_.chunks
                d_51_eof_ = source0_.eof
                if (not((e).is_AeadOpenResult)) or ((len(d_49_frames_)) == (0)):
                    return default__.Unexpected(s)
                elif not((e).ok):
                    return default__.Abort(s, False, EHBP.Code_AeadDecryptFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "frame failed to authenticate")))
                elif ((len((e).plaintext)) + (EHBP.default__.AeadTagLength)) != (len(((d_49_frames_)[0]).ciphertext)):
                    return default__.Abort(s, False, EHBP.Code_AeadDecryptFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "AEAD returned the wrong length")))
                elif True:
                    return default__.OpenNext(s, d_47_keys_, d_48_dec_, _dafny.SeqWithoutIsStrInference((d_49_frames_)[1::]), ((d_50_chunks_) + (_dafny.SeqWithoutIsStrInference([(e).plaintext])) if (len((e).plaintext)) > (0) else d_50_chunks_), d_51_eof_)
        if True:
            return default__.Unexpected(s)

    @staticmethod
    def Emits(chunks):
        return _dafny.SeqWithoutIsStrInference([Action_EmitPlaintext((chunks)[d_0_i_]) for d_0_i_ in range(len(chunks))])

    @staticmethod
    def OpenNext(s, keys, dec, frames, chunks, eof):
        if (len(frames)) > (0):
            if (len(((frames)[0]).ciphertext)) < (EHBP.default__.AeadTagLength):
                return default__.Abort(s, False, EHBP.Code_AeadDecryptFailed(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "frame shorter than the AEAD tag")))
            elif True:
                return (default__.WithResponse(s, Response_Opening(keys, dec, frames, chunks, eof)), _dafny.SeqWithoutIsStrInference([Action_AeadOpen((keys).key, EHBP.default__.ComputeNonce((keys).baseNonce, ((frames)[0]).seqNo), ((frames)[0]).ciphertext)]))
        elif eof:
            source0_ = default__.Finish(dec)
            if True:
                if source0_.is_Some:
                    d_0_code_ = source0_.value
                    return default__.Abort(s, False, d_0_code_, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
            if True:
                if (len(chunks)) > (0):
                    return (default__.WithResponse(s, Response_Body(keys, dec, True)), default__.Emits(chunks))
                elif True:
                    return default__.End(s, False, Action_Finished())
        elif (len(chunks)) > (0):
            return (default__.WithResponse(s, Response_Body(keys, dec, False)), default__.Emits(chunks))
        elif True:
            return (default__.WithResponse(s, Response_BodyReading(keys, dec)), _dafny.SeqWithoutIsStrInference([Action_Read(Stream_ResponseBody())]))

    @staticmethod
    def Hex(s):
        source0_ = EHBP.default__.DecodeHex(s)
        if True:
            if source0_.is_Some:
                d_0_b_ = source0_.value
                return d_0_b_
        if True:
            return _dafny.SeqWithoutIsStrInference([])

    @staticmethod
    def SelfCheckJudge(results):
        if (len(results)) != (len(default__.SelfCheckActions)):
            return _dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "self-check: wrong number of results"))])
        elif True:
            return (((((((((_dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "HmacSha256: RFC 4231 test case 1"))]) if ((results)[0]) != (Event_HmacResult(default__.HmacTag)) else _dafny.SeqWithoutIsStrInference([]))) + ((_dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "X25519: RFC 7748 base point"))]) if ((results)[1]) != (Event_X25519Result(default__.AlicePk)) else _dafny.SeqWithoutIsStrInference([])))) + ((_dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "X25519: RFC 7748 shared secret"))]) if ((results)[2]) != (Event_X25519Result(default__.AliceBobShared)) else _dafny.SeqWithoutIsStrInference([])))) + ((_dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "AeadSeal: known answer"))]) if ((results)[3]) != (Event_AeadSealResult(default__.GcmCt)) else _dafny.SeqWithoutIsStrInference([])))) + ((_dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "AeadOpen: known answer"))]) if ((results)[4]) != (Event_AeadOpenResult(True, EHBP.default__.Ascii(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ehbp"))))) else _dafny.SeqWithoutIsStrInference([])))) + ((_dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "AeadOpen: accepted a tampered tag"))]) if (not(((results)[5]).is_AeadOpenResult)) or (((results)[5]).ok) else _dafny.SeqWithoutIsStrInference([])))) + ((_dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "AeadOpen: accepted a frame shorter than the tag"))]) if (not(((results)[6]).is_AeadOpenResult)) or (((results)[6]).ok) else _dafny.SeqWithoutIsStrInference([])))) + ((_dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "RandomBytes: length"))]) if (((not(((results)[7]).is_RandomResult)) or (not(((results)[8]).is_RandomResult))) or ((len(((results)[7]).data)) != (32))) or ((len(((results)[8]).data)) != (32)) else _dafny.SeqWithoutIsStrInference([])))) + ((_dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "RandomBytes: repeated output"))]) if ((results)[7]) == ((results)[8]) else _dafny.SeqWithoutIsStrInference([])))

    @staticmethod
    def Rotr(x, n):
        return ((x) >> (n)) | (((x) << ((32) - (n))) & ((1 << 32) - 1))

    @staticmethod
    def Word(b, i):
        return EHBP.default__.U32(b, i)

    @staticmethod
    def WordBytes(w):
        return EHBP.default__.BE32(w)

    @staticmethod
    def MessageSchedule(w):
        while True:
            with _dafny.label():
                if (len(w)) == (64):
                    return w
                elif True:
                    d_0_s0_ = ((default__.Rotr((w)[(len(w)) - (15)], 7)) ^ (default__.Rotr((w)[(len(w)) - (15)], 18))) ^ (((w)[(len(w)) - (15)]) >> (3))
                    d_1_s1_ = ((default__.Rotr((w)[(len(w)) - (2)], 17)) ^ (default__.Rotr((w)[(len(w)) - (2)], 19))) ^ (((w)[(len(w)) - (2)]) >> (10))
                    in0_ = (w) + (_dafny.SeqWithoutIsStrInference([(((((((w)[(len(w)) - (16)]) + (d_0_s0_)) & ((1 << 32) - 1)) + ((w)[(len(w)) - (7)])) & ((1 << 32) - 1)) + (d_1_s1_)) & ((1 << 32) - 1)]))
                    w = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def Rounds(w, t, v):
        while True:
            with _dafny.label():
                if (t) == (64):
                    return v
                elif True:
                    d_0_a_ = (v)[0]
                    d_1_b_ = (v)[1]
                    d_2_c_ = (v)[2]
                    d_3_d_ = (v)[3]
                    d_4_e_ = (v)[4]
                    d_5_f_ = (v)[5]
                    d_6_g_ = (v)[6]
                    d_7_h_ = (v)[7]
                    d_8_t1_ = ((((((((d_7_h_) + (((default__.Rotr(d_4_e_, 6)) ^ (default__.Rotr(d_4_e_, 11))) ^ (default__.Rotr(d_4_e_, 25)))) & ((1 << 32) - 1)) + (((d_4_e_) & (d_5_f_)) ^ (((~(d_4_e_)) & ((1 << 32) - 1)) & (d_6_g_)))) & ((1 << 32) - 1)) + ((default__.K256)[t])) & ((1 << 32) - 1)) + ((w)[t])) & ((1 << 32) - 1)
                    d_9_t2_ = ((((default__.Rotr(d_0_a_, 2)) ^ (default__.Rotr(d_0_a_, 13))) ^ (default__.Rotr(d_0_a_, 22))) + ((((d_0_a_) & (d_1_b_)) ^ ((d_0_a_) & (d_2_c_))) ^ ((d_1_b_) & (d_2_c_)))) & ((1 << 32) - 1)
                    in0_ = w
                    in1_ = (t) + (1)
                    in2_ = _dafny.SeqWithoutIsStrInference([((d_8_t1_) + (d_9_t2_)) & ((1 << 32) - 1), d_0_a_, d_1_b_, d_2_c_, ((d_3_d_) + (d_8_t1_)) & ((1 << 32) - 1), d_4_e_, d_5_f_, d_6_g_])
                    w = in0_
                    t = in1_
                    v = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def Blocks(p, i, h):
        while True:
            with _dafny.label():
                if (i) == (len(p)):
                    return h
                elif True:
                    d_0_block_ = _dafny.SeqWithoutIsStrInference((p)[i:(i) + (64):])
                    d_1_w_ = default__.MessageSchedule(_dafny.SeqWithoutIsStrInference([default__.Word(d_0_block_, (4) * (d_2_j_)) for d_2_j_ in range(16)]))
                    d_3_v_ = default__.Rounds(d_1_w_, 0, h)
                    in0_ = p
                    in1_ = (i) + (64)
                    in2_ = _dafny.SeqWithoutIsStrInference([(((h)[d_4_j_]) + ((d_3_v_)[d_4_j_])) & ((1 << 32) - 1) for d_4_j_ in range(8)])
                    p = in0_
                    i = in1_
                    h = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def Sha256(msg):
        d_0_pad_ = _dafny.euclidian_modulus((119) - (_dafny.euclidian_modulus(len(msg), 64)), 64)
        d_1_bits_ = (len(msg)) * (8)
        d_2_padded_ = ((((msg) + (_dafny.SeqWithoutIsStrInference([128]))) + (_dafny.SeqWithoutIsStrInference([0 for d_3_i_ in range(d_0_pad_)]))) + (EHBP.default__.BE32(_dafny.euclidian_modulus(_dafny.euclidian_division(d_1_bits_, 4294967296), 4294967296)))) + (EHBP.default__.BE32(_dafny.euclidian_modulus(d_1_bits_, 4294967296)))
        d_4_h_ = default__.Blocks(d_2_padded_, 0, default__.H256)
        return (((((((default__.WordBytes((d_4_h_)[0])) + (default__.WordBytes((d_4_h_)[1]))) + (default__.WordBytes((d_4_h_)[2]))) + (default__.WordBytes((d_4_h_)[3]))) + (default__.WordBytes((d_4_h_)[4]))) + (default__.WordBytes((d_4_h_)[5]))) + (default__.WordBytes((d_4_h_)[6]))) + (default__.WordBytes((d_4_h_)[7]))

    @staticmethod
    def XorPad(b, p):
        return _dafny.SeqWithoutIsStrInference([((b)[d_0_i_]) ^ (p) for d_0_i_ in range(len(b))])

    @staticmethod
    def HmacRef(key, data):
        d_0_k_ = (default__.Sha256(key) if (len(key)) > (64) else key)
        d_1_kp_ = (d_0_k_) + (_dafny.SeqWithoutIsStrInference([0 for d_2_i_ in range((64) - (len(d_0_k_)))]))
        return default__.Sha256((default__.XorPad(d_1_kp_, 92)) + (default__.Sha256((default__.XorPad(d_1_kp_, 54)) + (data))))

    @staticmethod
    def Pow2(n):
        d_0___accumulator_ = 1
        while True:
            with _dafny.label():
                if (n) == (0):
                    return (1) * (d_0___accumulator_)
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) * (2)
                    in0_ = (n) - (1)
                    n = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def PowMod(b, e):
        if (e) == (0):
            return _dafny.euclidian_modulus(1, default__.P25519)
        elif (_dafny.euclidian_modulus(e, 2)) == (0):
            d_0_h_ = default__.PowMod(b, _dafny.euclidian_division(e, 2))
            return _dafny.euclidian_modulus((d_0_h_) * (d_0_h_), default__.P25519)
        elif True:
            return _dafny.euclidian_modulus((b) * (default__.PowMod(b, (e) - (1))), default__.P25519)

    @staticmethod
    def LE(b):
        if (len(b)) == (0):
            return 0
        elif True:
            return ((b)[0]) + ((256) * (default__.LE(_dafny.SeqWithoutIsStrInference((b)[1::]))))

    @staticmethod
    def LEBytes(n, length):
        return _dafny.SeqWithoutIsStrInference([_dafny.euclidian_modulus(_dafny.euclidian_division(n, default__.Pow2((8) * (d_0_i_))), 256) for d_0_i_ in range(length)])

    @staticmethod
    def Clamp(k):
        return ((_dafny.SeqWithoutIsStrInference([((k)[0]) & (248)])) + (_dafny.SeqWithoutIsStrInference((k)[1:31:]))) + (_dafny.SeqWithoutIsStrInference([(((k)[31]) & (127)) | (64)]))

    @staticmethod
    def Ladder(k, x1, t, x2, z2, x3, z3, swap):
        while True:
            with _dafny.label():
                d_0_kt_ = _dafny.euclidian_modulus(_dafny.euclidian_division(k, default__.Pow2(t)), 2)
                d_1_sw_ = (1 if (swap) != (d_0_kt_) else 0)
                let_tmp_rhs0_ = ((x3, x2) if (d_1_sw_) == (1) else (x2, x3))
                d_2_x2s_ = let_tmp_rhs0_[0]
                d_3_x3s_ = let_tmp_rhs0_[1]
                let_tmp_rhs1_ = ((z3, z2) if (d_1_sw_) == (1) else (z2, z3))
                d_4_z2s_ = let_tmp_rhs1_[0]
                d_5_z3s_ = let_tmp_rhs1_[1]
                d_6_a_ = _dafny.euclidian_modulus((d_2_x2s_) + (d_4_z2s_), default__.P25519)
                d_7_aa_ = _dafny.euclidian_modulus((d_6_a_) * (d_6_a_), default__.P25519)
                d_8_b_ = _dafny.euclidian_modulus((d_2_x2s_) - (d_4_z2s_), default__.P25519)
                d_9_bb_ = _dafny.euclidian_modulus((d_8_b_) * (d_8_b_), default__.P25519)
                d_10_e_ = _dafny.euclidian_modulus((d_7_aa_) - (d_9_bb_), default__.P25519)
                d_11_c_ = _dafny.euclidian_modulus((d_3_x3s_) + (d_5_z3s_), default__.P25519)
                d_12_d_ = _dafny.euclidian_modulus((d_3_x3s_) - (d_5_z3s_), default__.P25519)
                d_13_da_ = _dafny.euclidian_modulus((d_12_d_) * (d_6_a_), default__.P25519)
                d_14_cb_ = _dafny.euclidian_modulus((d_11_c_) * (d_8_b_), default__.P25519)
                d_15_nx3_ = _dafny.euclidian_modulus(((d_13_da_) + (d_14_cb_)) * ((d_13_da_) + (d_14_cb_)), default__.P25519)
                d_16_nz3_ = _dafny.euclidian_modulus((x1) * (_dafny.euclidian_modulus(((d_13_da_) - (d_14_cb_)) * ((d_13_da_) - (d_14_cb_)), default__.P25519)), default__.P25519)
                d_17_nx2_ = _dafny.euclidian_modulus((d_7_aa_) * (d_9_bb_), default__.P25519)
                d_18_nz2_ = _dafny.euclidian_modulus((d_10_e_) * (_dafny.euclidian_modulus((d_7_aa_) + ((121665) * (d_10_e_)), default__.P25519)), default__.P25519)
                if (t) == (0):
                    return (d_17_nx2_, d_18_nz2_, d_15_nx3_, d_16_nz3_, d_0_kt_)
                elif True:
                    in0_ = k
                    in1_ = x1
                    in2_ = (t) - (1)
                    in3_ = d_17_nx2_
                    in4_ = d_18_nz2_
                    in5_ = d_15_nx3_
                    in6_ = d_16_nz3_
                    in7_ = d_0_kt_
                    k = in0_
                    x1 = in1_
                    t = in2_
                    x2 = in3_
                    z2 = in4_
                    x3 = in5_
                    z3 = in6_
                    swap = in7_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def X25519Ref(scalar, point):
        d_0_k_ = default__.LE(default__.Clamp(scalar))
        d_1_u_ = _dafny.euclidian_modulus(default__.LE(point), default__.Pow2(255))
        let_tmp_rhs0_ = default__.Ladder(d_0_k_, d_1_u_, 255, 1, 0, d_1_u_, 1, 0)
        d_2_x2_ = let_tmp_rhs0_[0]
        d_3_z2_ = let_tmp_rhs0_[1]
        d_4_x3_ = let_tmp_rhs0_[2]
        d_5_z3_ = let_tmp_rhs0_[3]
        d_6_swap_ = let_tmp_rhs0_[4]
        let_tmp_rhs1_ = ((d_4_x3_, d_5_z3_) if (d_6_swap_) == (1) else (d_2_x2_, d_3_z2_))
        d_7_x_ = let_tmp_rhs1_[0]
        d_8_z_ = let_tmp_rhs1_[1]
        return default__.LEBytes(_dafny.euclidian_modulus((d_7_x_) * (default__.PowMod(d_8_z_, (default__.P25519) - (2))), default__.P25519), 32)

    @_dafny.classproperty
    def BasePoint(instance):
        return (_dafny.SeqWithoutIsStrInference([9])) + (default__.Repeat(31, 0))
    @_dafny.classproperty
    def HpkeVersion(instance):
        return EHBP.default__.Ascii(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "HPKE-v1")))
    @_dafny.classproperty
    def KemSuiteId(instance):
        return (EHBP.default__.Ascii(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "KEM")))) + (EHBP.default__.BE16(EHBP.default__.KemX25519))
    @_dafny.classproperty
    def HpkeSuiteId(instance):
        return (((EHBP.default__.Ascii(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "HPKE")))) + (EHBP.default__.BE16(EHBP.default__.KemX25519))) + (EHBP.default__.BE16(EHBP.default__.KdfHkdfSha256))) + (EHBP.default__.BE16(EHBP.default__.AeadAes256Gcm))
    @_dafny.classproperty
    def MaxSeq(instance):
        return 18446744073709551615
    @_dafny.classproperty
    def MaxJsonStringChars(instance):
        return 1024
    @_dafny.classproperty
    def MaxJsonDepth(instance):
        return 64
    @_dafny.classproperty
    def NewSession(instance):
        return SessionStore_SessionStore(0, EHBP.Option_None())
    @_dafny.classproperty
    def NoCtx(instance):
        return Ctx_Ctx(default__.Repeat(32, 0), default__.Repeat(12, 0), _dafny.SeqWithoutIsStrInference([]), 0)
    @_dafny.classproperty
    def MaxReadBytes(instance):
        return 4294967295
    @_dafny.classproperty
    def NoOrigin(instance):
        return EHBP.Origin_Origin(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "https")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), 443)
    @_dafny.classproperty
    def GcmKey(instance):
        return default__.Iota(32)
    @_dafny.classproperty
    def GcmNonce(instance):
        return default__.Iota(12)
    @_dafny.classproperty
    def GcmCt(instance):
        return default__.Hex(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "226ab46b72d4be2b87fabbe9dbe0bfc2adbce017")))
    @_dafny.classproperty
    def AliceSk(instance):
        return default__.Hex(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")))
    @_dafny.classproperty
    def AlicePk(instance):
        return default__.Hex(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")))
    @_dafny.classproperty
    def BobPk(instance):
        return default__.Hex(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")))
    @_dafny.classproperty
    def AliceBobShared(instance):
        return default__.Hex(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")))
    @_dafny.classproperty
    def HmacKey(instance):
        return default__.Repeat(20, 11)
    @_dafny.classproperty
    def HmacTag(instance):
        return default__.Hex(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")))
    @_dafny.classproperty
    def SelfCheckActions(instance):
        return _dafny.SeqWithoutIsStrInference([Action_HmacSha256(default__.HmacKey, EHBP.default__.Ascii(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "Hi There")))), Action_X25519(default__.AliceSk, default__.BasePoint), Action_X25519(default__.AliceSk, default__.BobPk), Action_AeadSeal(default__.GcmKey, default__.GcmNonce, EHBP.default__.Ascii(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ehbp")))), Action_AeadOpen(default__.GcmKey, default__.GcmNonce, default__.GcmCt), Action_AeadOpen(default__.GcmKey, default__.GcmNonce, (_dafny.SeqWithoutIsStrInference((default__.GcmCt)[:(len(default__.GcmCt)) - (1):])) + (_dafny.SeqWithoutIsStrInference([((default__.GcmCt)[(len(default__.GcmCt)) - (1)]) ^ (1)]))), Action_AeadOpen(default__.GcmKey, default__.GcmNonce, _dafny.SeqWithoutIsStrInference((default__.GcmCt)[:8:])), Action_RandomBytes(32), Action_RandomBytes(32)])
    @_dafny.classproperty
    def K256(instance):
        return _dafny.SeqWithoutIsStrInference([1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298])
    @_dafny.classproperty
    def H256(instance):
        return _dafny.SeqWithoutIsStrInference([1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225])
    @_dafny.classproperty
    def P25519(instance):
        return 57896044618658097711785492504343953926634992332820282019728792003956564819949

class Stream:
    @_dafny.classproperty
    def AllSingletonConstructors(cls):
        return [Stream_RequestBody(), Stream_ResponseBody()]
    @classmethod
    def default(cls, ):
        return lambda: Stream_RequestBody()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_RequestBody(self) -> bool:
        return isinstance(self, Stream_RequestBody)
    @property
    def is_ResponseBody(self) -> bool:
        return isinstance(self, Stream_ResponseBody)

class Stream_RequestBody(Stream, NamedTuple('RequestBody', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Stream.RequestBody'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Stream_RequestBody)
    def __hash__(self) -> int:
        return super().__hash__()

class Stream_ResponseBody(Stream, NamedTuple('ResponseBody', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Stream.ResponseBody'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Stream_ResponseBody)
    def __hash__(self) -> int:
        return super().__hash__()


class BodyEnd:
    @classmethod
    def default(cls, ):
        return lambda: BodyEnd_More()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_More(self) -> bool:
        return isinstance(self, BodyEnd_More)
    @property
    def is_Done(self) -> bool:
        return isinstance(self, BodyEnd_Done)
    @property
    def is_Aborted(self) -> bool:
        return isinstance(self, BodyEnd_Aborted)

class BodyEnd_More(BodyEnd, NamedTuple('More', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.BodyEnd.More'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, BodyEnd_More)
    def __hash__(self) -> int:
        return super().__hash__()

class BodyEnd_Done(BodyEnd, NamedTuple('Done', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.BodyEnd.Done'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, BodyEnd_Done)
    def __hash__(self) -> int:
        return super().__hash__()

class BodyEnd_Aborted(BodyEnd, NamedTuple('Aborted', [('code', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.BodyEnd.Aborted({_dafny.string_of(self.code)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, BodyEnd_Aborted) and self.code == __o.code
    def __hash__(self) -> int:
        return super().__hash__()


class Event:
    @classmethod
    def default(cls, ):
        return lambda: Event_Start(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), int(0), False, False, _dafny.Seq({}), False)
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Start(self) -> bool:
        return isinstance(self, Event_Start)
    @property
    def is_DiscoverStart(self) -> bool:
        return isinstance(self, Event_DiscoverStart)
    @property
    def is_SessionBegun(self) -> bool:
        return isinstance(self, Event_SessionBegun)
    @property
    def is_RandomResult(self) -> bool:
        return isinstance(self, Event_RandomResult)
    @property
    def is_X25519Result(self) -> bool:
        return isinstance(self, Event_X25519Result)
    @property
    def is_HmacResult(self) -> bool:
        return isinstance(self, Event_HmacResult)
    @property
    def is_AeadSealResult(self) -> bool:
        return isinstance(self, Event_AeadSealResult)
    @property
    def is_AeadOpenResult(self) -> bool:
        return isinstance(self, Event_AeadOpenResult)
    @property
    def is_ResponseHead(self) -> bool:
        return isinstance(self, Event_ResponseHead)
    @property
    def is_Chunk(self) -> bool:
        return isinstance(self, Event_Chunk)
    @property
    def is_StreamFailed(self) -> bool:
        return isinstance(self, Event_StreamFailed)
    @property
    def is_CallerRead(self) -> bool:
        return isinstance(self, Event_CallerRead)
    @property
    def is_CallerClose(self) -> bool:
        return isinstance(self, Event_CallerClose)

class Event_Start(Event, NamedTuple('Start', [('verb', Any), ('url', Any), ('scheme', Any), ('host', Any), ('port', Any), ('hasPort', Any), ('hasUserinfo', Any), ('headers', Any), ('hasBody', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.Start({self.verb.VerbatimString(True)}, {self.url.VerbatimString(True)}, {self.scheme.VerbatimString(True)}, {self.host.VerbatimString(True)}, {_dafny.string_of(self.port)}, {_dafny.string_of(self.hasPort)}, {_dafny.string_of(self.hasUserinfo)}, {_dafny.string_of(self.headers)}, {_dafny.string_of(self.hasBody)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_Start) and self.verb == __o.verb and self.url == __o.url and self.scheme == __o.scheme and self.host == __o.host and self.port == __o.port and self.hasPort == __o.hasPort and self.hasUserinfo == __o.hasUserinfo and self.headers == __o.headers and self.hasBody == __o.hasBody
    def __hash__(self) -> int:
        return super().__hash__()

class Event_DiscoverStart(Event, NamedTuple('DiscoverStart', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.DiscoverStart'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_DiscoverStart)
    def __hash__(self) -> int:
        return super().__hash__()

class Event_SessionBegun(Event, NamedTuple('SessionBegun', [('generation', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.SessionBegun({_dafny.string_of(self.generation)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_SessionBegun) and self.generation == __o.generation
    def __hash__(self) -> int:
        return super().__hash__()

class Event_RandomResult(Event, NamedTuple('RandomResult', [('data', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Event.RandomResult(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_RandomResult) and self.data == __o.data
    def __hash__(self) -> int:
        return super().__hash__()

class Event_X25519Result(Event, NamedTuple('X25519Result', [('point', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Event.X25519Result(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_X25519Result) and self.point == __o.point
    def __hash__(self) -> int:
        return super().__hash__()

class Event_HmacResult(Event, NamedTuple('HmacResult', [('mac', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Event.HmacResult(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_HmacResult) and self.mac == __o.mac
    def __hash__(self) -> int:
        return super().__hash__()

class Event_AeadSealResult(Event, NamedTuple('AeadSealResult', [('ciphertext', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.AeadSealResult({_dafny.string_of(self.ciphertext)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_AeadSealResult) and self.ciphertext == __o.ciphertext
    def __hash__(self) -> int:
        return super().__hash__()

class Event_AeadOpenResult(Event, NamedTuple('AeadOpenResult', [('ok', Any), ('plaintext', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.AeadOpenResult({_dafny.string_of(self.ok)}, {_dafny.string_of(self.plaintext)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_AeadOpenResult) and self.ok == __o.ok and self.plaintext == __o.plaintext
    def __hash__(self) -> int:
        return super().__hash__()

class Event_ResponseHead(Event, NamedTuple('ResponseHead', [('status', Any), ('headers', Any), ('redirected', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.ResponseHead({_dafny.string_of(self.status)}, {_dafny.string_of(self.headers)}, {_dafny.string_of(self.redirected)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_ResponseHead) and self.status == __o.status and self.headers == __o.headers and self.redirected == __o.redirected
    def __hash__(self) -> int:
        return super().__hash__()

class Event_Chunk(Event, NamedTuple('Chunk', [('stream', Any), ('data', Any), ('eof', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.Chunk({_dafny.string_of(self.stream)}, {_dafny.string_of(self.data)}, {_dafny.string_of(self.eof)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_Chunk) and self.stream == __o.stream and self.data == __o.data and self.eof == __o.eof
    def __hash__(self) -> int:
        return super().__hash__()

class Event_StreamFailed(Event, NamedTuple('StreamFailed', [('stream', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.StreamFailed({_dafny.string_of(self.stream)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_StreamFailed) and self.stream == __o.stream
    def __hash__(self) -> int:
        return super().__hash__()

class Event_CallerRead(Event, NamedTuple('CallerRead', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.CallerRead'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_CallerRead)
    def __hash__(self) -> int:
        return super().__hash__()

class Event_CallerClose(Event, NamedTuple('CallerClose', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Event.CallerClose'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Event_CallerClose)
    def __hash__(self) -> int:
        return super().__hash__()


class Action:
    @classmethod
    def default(cls, ):
        return lambda: Action_BeginSession()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_BeginSession(self) -> bool:
        return isinstance(self, Action_BeginSession)
    @property
    def is_PublishToken(self) -> bool:
        return isinstance(self, Action_PublishToken)
    @property
    def is_ClearToken(self) -> bool:
        return isinstance(self, Action_ClearToken)
    @property
    def is_RandomBytes(self) -> bool:
        return isinstance(self, Action_RandomBytes)
    @property
    def is_X25519(self) -> bool:
        return isinstance(self, Action_X25519)
    @property
    def is_HmacSha256(self) -> bool:
        return isinstance(self, Action_HmacSha256)
    @property
    def is_AeadSeal(self) -> bool:
        return isinstance(self, Action_AeadSeal)
    @property
    def is_AeadOpen(self) -> bool:
        return isinstance(self, Action_AeadOpen)
    @property
    def is_Send(self) -> bool:
        return isinstance(self, Action_Send)
    @property
    def is_Write(self) -> bool:
        return isinstance(self, Action_Write)
    @property
    def is_Read(self) -> bool:
        return isinstance(self, Action_Read)
    @property
    def is_Close(self) -> bool:
        return isinstance(self, Action_Close)
    @property
    def is_EmitPlaintext(self) -> bool:
        return isinstance(self, Action_EmitPlaintext)
    @property
    def is_Passthrough(self) -> bool:
        return isinstance(self, Action_Passthrough)
    @property
    def is_Done(self) -> bool:
        return isinstance(self, Action_Done)
    @property
    def is_Finished(self) -> bool:
        return isinstance(self, Action_Finished)
    @property
    def is_Discovered(self) -> bool:
        return isinstance(self, Action_Discovered)
    @property
    def is_Fail(self) -> bool:
        return isinstance(self, Action_Fail)

class Action_BeginSession(Action, NamedTuple('BeginSession', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.BeginSession'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_BeginSession)
    def __hash__(self) -> int:
        return super().__hash__()

class Action_PublishToken(Action, NamedTuple('PublishToken', [('generation', Any), ('exportedSecret', Any), ('requestEnc', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Action.PublishToken(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_PublishToken) and self.generation == __o.generation and self.exportedSecret == __o.exportedSecret and self.requestEnc == __o.requestEnc
    def __hash__(self) -> int:
        return super().__hash__()

class Action_ClearToken(Action, NamedTuple('ClearToken', [('generation', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.ClearToken({_dafny.string_of(self.generation)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_ClearToken) and self.generation == __o.generation
    def __hash__(self) -> int:
        return super().__hash__()

class Action_RandomBytes(Action, NamedTuple('RandomBytes', [('length', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.RandomBytes({_dafny.string_of(self.length)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_RandomBytes) and self.length == __o.length
    def __hash__(self) -> int:
        return super().__hash__()

class Action_X25519(Action, NamedTuple('X25519', [('scalar', Any), ('point', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Action.X25519(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_X25519) and self.scalar == __o.scalar and self.point == __o.point
    def __hash__(self) -> int:
        return super().__hash__()

class Action_HmacSha256(Action, NamedTuple('HmacSha256', [('key', Any), ('data', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Action.HmacSha256(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_HmacSha256) and self.key == __o.key and self.data == __o.data
    def __hash__(self) -> int:
        return super().__hash__()

class Action_AeadSeal(Action, NamedTuple('AeadSeal', [('key', Any), ('nonce', Any), ('plaintext', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Action.AeadSeal(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_AeadSeal) and self.key == __o.key and self.nonce == __o.nonce and self.plaintext == __o.plaintext
    def __hash__(self) -> int:
        return super().__hash__()

class Action_AeadOpen(Action, NamedTuple('AeadOpen', [('key', Any), ('nonce', Any), ('ciphertext', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Action.AeadOpen(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_AeadOpen) and self.key == __o.key and self.nonce == __o.nonce and self.ciphertext == __o.ciphertext
    def __hash__(self) -> int:
        return super().__hash__()

class Action_Send(Action, NamedTuple('Send', [('verb', Any), ('url', Any), ('headers', Any), ('hasBody', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.Send({self.verb.VerbatimString(True)}, {self.url.VerbatimString(True)}, {_dafny.string_of(self.headers)}, {_dafny.string_of(self.hasBody)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_Send) and self.verb == __o.verb and self.url == __o.url and self.headers == __o.headers and self.hasBody == __o.hasBody
    def __hash__(self) -> int:
        return super().__hash__()

class Action_Write(Action, NamedTuple('Write', [('data', Any), ('end', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.Write({_dafny.string_of(self.data)}, {_dafny.string_of(self.end)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_Write) and self.data == __o.data and self.end == __o.end
    def __hash__(self) -> int:
        return super().__hash__()

class Action_Read(Action, NamedTuple('Read', [('stream', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.Read({_dafny.string_of(self.stream)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_Read) and self.stream == __o.stream
    def __hash__(self) -> int:
        return super().__hash__()

class Action_Close(Action, NamedTuple('Close', [('stream', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.Close({_dafny.string_of(self.stream)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_Close) and self.stream == __o.stream
    def __hash__(self) -> int:
        return super().__hash__()

class Action_EmitPlaintext(Action, NamedTuple('EmitPlaintext', [('data', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.EmitPlaintext({_dafny.string_of(self.data)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_EmitPlaintext) and self.data == __o.data
    def __hash__(self) -> int:
        return super().__hash__()

class Action_Passthrough(Action, NamedTuple('Passthrough', [('status', Any), ('headers', Any), ('prefix', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.Passthrough({_dafny.string_of(self.status)}, {_dafny.string_of(self.headers)}, {_dafny.string_of(self.prefix)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_Passthrough) and self.status == __o.status and self.headers == __o.headers and self.prefix == __o.prefix
    def __hash__(self) -> int:
        return super().__hash__()

class Action_Done(Action, NamedTuple('Done', [('status', Any), ('headers', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.Done({_dafny.string_of(self.status)}, {_dafny.string_of(self.headers)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_Done) and self.status == __o.status and self.headers == __o.headers
    def __hash__(self) -> int:
        return super().__hash__()

class Action_Finished(Action, NamedTuple('Finished', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.Finished'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_Finished)
    def __hash__(self) -> int:
        return super().__hash__()

class Action_Discovered(Action, NamedTuple('Discovered', [('publicKey', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.Discovered({_dafny.string_of(self.publicKey)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_Discovered) and self.publicKey == __o.publicKey
    def __hash__(self) -> int:
        return super().__hash__()

class Action_Fail(Action, NamedTuple('Fail', [('code', Any), ('message', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Action.Fail({_dafny.string_of(self.code)}, {self.message.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Action_Fail) and self.code == __o.code and self.message == __o.message
    def __hash__(self) -> int:
        return super().__hash__()


class Performed:
    @classmethod
    def default(cls, ):
        return lambda: Performed_Quiet()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Quiet(self) -> bool:
        return isinstance(self, Performed_Quiet)
    @property
    def is_Got(self) -> bool:
        return isinstance(self, Performed_Got)
    @property
    def is_Stop(self) -> bool:
        return isinstance(self, Performed_Stop)

class Performed_Quiet(Performed, NamedTuple('Quiet', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Performed.Quiet'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Performed_Quiet)
    def __hash__(self) -> int:
        return super().__hash__()

class Performed_Got(Performed, NamedTuple('Got', [('e', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Performed.Got({_dafny.string_of(self.e)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Performed_Got) and self.e == __o.e
    def __hash__(self) -> int:
        return super().__hash__()

class Performed_Stop(Performed, NamedTuple('Stop', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Performed.Stop'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Performed_Stop)
    def __hash__(self) -> int:
        return super().__hash__()


class Performer:
    pass
    def BeginSession(self):
        pass

    def PublishToken(self, generation, exportedSecret, requestEnc):
        pass

    def ClearToken(self, generation):
        pass

    def RandomBytes(self, length):
        pass

    def X25519(self, scalar, point):
        pass

    def HmacSha256(self, key, data):
        pass

    def AeadSeal(self, key, nonce, plaintext):
        pass

    def AeadOpen(self, key, nonce, ciphertext):
        pass

    def Send(self, verb, url, headers, hasBody):
        pass

    def Write(self, data, end):
        pass

    def Read(self, stream):
        pass

    def Close(self, stream):
        pass

    def EmitPlaintext(self, data):
        pass


class Job:
    @classmethod
    def default(cls, ):
        return lambda: Job_JExtract(_dafny.Seq({}), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_JExtract(self) -> bool:
        return isinstance(self, Job_JExtract)
    @property
    def is_JExpand(self) -> bool:
        return isinstance(self, Job_JExpand)

class Job_JExtract(Job, NamedTuple('JExtract', [('salt', Any), ('ikm', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Job.JExtract(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Job_JExtract) and self.salt == __o.salt and self.ikm == __o.ikm
    def __hash__(self) -> int:
        return super().__hash__()

class Job_JExpand(Job, NamedTuple('JExpand', [('prk', Any), ('info', Any), ('length', Any), ('acc', Any), ('prev', Any), ('i', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Job.JExpand(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Job_JExpand) and self.prk == __o.prk and self.info == __o.info and self.length == __o.length and self.acc == __o.acc and self.prev == __o.prev and self.i == __o.i
    def __hash__(self) -> int:
        return super().__hash__()


class JobOut:
    @classmethod
    def default(cls, ):
        return lambda: JobOut_Pending(Job.default()(), Action.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Pending(self) -> bool:
        return isinstance(self, JobOut_Pending)
    @property
    def is_Output(self) -> bool:
        return isinstance(self, JobOut_Output)
    @property
    def is_JobFailed(self) -> bool:
        return isinstance(self, JobOut_JobFailed)

class JobOut_Pending(JobOut, NamedTuple('Pending', [('job', Any), ('action', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.JobOut.Pending({_dafny.string_of(self.job)}, {_dafny.string_of(self.action)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, JobOut_Pending) and self.job == __o.job and self.action == __o.action
    def __hash__(self) -> int:
        return super().__hash__()

class JobOut_Output(JobOut, NamedTuple('Output', [('data', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.JobOut.Output(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, JobOut_Output) and self.data == __o.data
    def __hash__(self) -> int:
        return super().__hash__()

class JobOut_JobFailed(JobOut, NamedTuple('JobFailed', [('code', Any), ('message', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.JobOut.JobFailed({_dafny.string_of(self.code)}, {self.message.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, JobOut_JobFailed) and self.code == __o.code and self.message == __o.message
    def __hash__(self) -> int:
        return super().__hash__()


class Key:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return _dafny.SeqWithoutIsStrInference([0 for d_0_i_ in range(32)])
    def _Is(source__):
        d_1_b_: _dafny.Seq = source__
        return (len(d_1_b_)) == (EHBP.default__.KeyLength)

class NonceBase:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return _dafny.SeqWithoutIsStrInference([0 for d_2_i_ in range(12)])
    def _Is(source__):
        d_3_b_: _dafny.Seq = source__
        return (len(d_3_b_)) == (EHBP.default__.NonceLength)

class Ctx:
    @classmethod
    def default(cls, ):
        return lambda: Ctx_Ctx(Key.default(), NonceBase.default(), _dafny.Seq({}), int(0))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Ctx(self) -> bool:
        return isinstance(self, Ctx_Ctx)

class Ctx_Ctx(Ctx, NamedTuple('Ctx', [('key', Any), ('baseNonce', Any), ('exporterSecret', Any), ('seqNo', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Ctx.Ctx(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Ctx_Ctx) and self.key == __o.key and self.baseNonce == __o.baseNonce and self.exporterSecret == __o.exporterSecret and self.seqNo == __o.seqNo
    def __hash__(self) -> int:
        return super().__hash__()


class Hpke:
    @classmethod
    def default(cls, ):
        return lambda: Hpke_HRandom(_dafny.Seq({}), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_HRandom(self) -> bool:
        return isinstance(self, Hpke_HRandom)
    @property
    def is_HEnc(self) -> bool:
        return isinstance(self, Hpke_HEnc)
    @property
    def is_HDh(self) -> bool:
        return isinstance(self, Hpke_HDh)
    @property
    def is_HSchedule(self) -> bool:
        return isinstance(self, Hpke_HSchedule)

class Hpke_HRandom(Hpke, NamedTuple('HRandom', [('pkR', Any), ('info', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Hpke.HRandom({_dafny.string_of(self.pkR)}, {_dafny.string_of(self.info)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Hpke_HRandom) and self.pkR == __o.pkR and self.info == __o.info
    def __hash__(self) -> int:
        return super().__hash__()

class Hpke_HEnc(Hpke, NamedTuple('HEnc', [('skE', Any), ('pkR', Any), ('info', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Hpke.HEnc(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Hpke_HEnc) and self.skE == __o.skE and self.pkR == __o.pkR and self.info == __o.info
    def __hash__(self) -> int:
        return super().__hash__()

class Hpke_HDh(Hpke, NamedTuple('HDh', [('enc', Any), ('pkR', Any), ('info', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Hpke.HDh({_dafny.string_of(self.enc)}, {_dafny.string_of(self.pkR)}, {_dafny.string_of(self.info)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Hpke_HDh) and self.enc == __o.enc and self.pkR == __o.pkR and self.info == __o.info
    def __hash__(self) -> int:
        return super().__hash__()

class Hpke_HSchedule(Hpke, NamedTuple('HSchedule', [('stage', Any), ('job', Any), ('enc', Any), ('pkR', Any), ('info', Any), ('shared', Any), ('pskIdHash', Any), ('infoHash', Any), ('secret', Any), ('key', Any), ('baseNonce', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Hpke.HSchedule(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Hpke_HSchedule) and self.stage == __o.stage and self.job == __o.job and self.enc == __o.enc and self.pkR == __o.pkR and self.info == __o.info and self.shared == __o.shared and self.pskIdHash == __o.pskIdHash and self.infoHash == __o.infoHash and self.secret == __o.secret and self.key == __o.key and self.baseNonce == __o.baseNonce
    def __hash__(self) -> int:
        return super().__hash__()


class HpkeOut:
    @classmethod
    def default(cls, ):
        return lambda: HpkeOut_HContinue(Hpke.default()(), Action.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_HContinue(self) -> bool:
        return isinstance(self, HpkeOut_HContinue)
    @property
    def is_HReady(self) -> bool:
        return isinstance(self, HpkeOut_HReady)
    @property
    def is_HFailed(self) -> bool:
        return isinstance(self, HpkeOut_HFailed)

class HpkeOut_HContinue(HpkeOut, NamedTuple('HContinue', [('h', Any), ('action', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.HpkeOut.HContinue({_dafny.string_of(self.h)}, {_dafny.string_of(self.action)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, HpkeOut_HContinue) and self.h == __o.h and self.action == __o.action
    def __hash__(self) -> int:
        return super().__hash__()

class HpkeOut_HReady(HpkeOut, NamedTuple('HReady', [('ctx', Any), ('enc', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.HpkeOut.HReady({_dafny.string_of(self.ctx)}, {_dafny.string_of(self.enc)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, HpkeOut_HReady) and self.ctx == __o.ctx and self.enc == __o.enc
    def __hash__(self) -> int:
        return super().__hash__()

class HpkeOut_HFailed(HpkeOut, NamedTuple('HFailed', [('code', Any), ('message', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.HpkeOut.HFailed({_dafny.string_of(self.code)}, {self.message.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, HpkeOut_HFailed) and self.code == __o.code and self.message == __o.message
    def __hash__(self) -> int:
        return super().__hash__()


class Json:
    @classmethod
    def default(cls, ):
        return lambda: Json_JNull()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_JNull(self) -> bool:
        return isinstance(self, Json_JNull)
    @property
    def is_JBool(self) -> bool:
        return isinstance(self, Json_JBool)
    @property
    def is_JNumber(self) -> bool:
        return isinstance(self, Json_JNumber)
    @property
    def is_JString(self) -> bool:
        return isinstance(self, Json_JString)
    @property
    def is_JArray(self) -> bool:
        return isinstance(self, Json_JArray)
    @property
    def is_JObject(self) -> bool:
        return isinstance(self, Json_JObject)

class Json_JNull(Json, NamedTuple('JNull', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Json.JNull'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Json_JNull)
    def __hash__(self) -> int:
        return super().__hash__()

class Json_JBool(Json, NamedTuple('JBool', [('b', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Json.JBool({_dafny.string_of(self.b)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Json_JBool) and self.b == __o.b
    def __hash__(self) -> int:
        return super().__hash__()

class Json_JNumber(Json, NamedTuple('JNumber', [('raw', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Json.JNumber({self.raw.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Json_JNumber) and self.raw == __o.raw
    def __hash__(self) -> int:
        return super().__hash__()

class Json_JString(Json, NamedTuple('JString', [('s', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Json.JString({self.s.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Json_JString) and self.s == __o.s
    def __hash__(self) -> int:
        return super().__hash__()

class Json_JArray(Json, NamedTuple('JArray', [('items', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Json.JArray({_dafny.string_of(self.items)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Json_JArray) and self.items == __o.items
    def __hash__(self) -> int:
        return super().__hash__()

class Json_JObject(Json, NamedTuple('JObject', [('members', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Json.JObject({_dafny.string_of(self.members)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Json_JObject) and self.members == __o.members
    def __hash__(self) -> int:
        return super().__hash__()


class SessionStore:
    @classmethod
    def default(cls, ):
        return lambda: SessionStore_SessionStore(int(0), EHBP.Option.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_SessionStore(self) -> bool:
        return isinstance(self, SessionStore_SessionStore)

class SessionStore_SessionStore(SessionStore, NamedTuple('SessionStore', [('generation', Any), ('token', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.SessionStore.SessionStore({_dafny.string_of(self.generation)}, {_dafny.string_of(self.token)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, SessionStore_SessionStore) and self.generation == __o.generation and self.token == __o.token
    def __hash__(self) -> int:
        return super().__hash__()


class SessionAction:
    @classmethod
    def default(cls, ):
        return lambda: SessionAction_Begin()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Begin(self) -> bool:
        return isinstance(self, SessionAction_Begin)
    @property
    def is_Publish(self) -> bool:
        return isinstance(self, SessionAction_Publish)
    @property
    def is_Clear(self) -> bool:
        return isinstance(self, SessionAction_Clear)

class SessionAction_Begin(SessionAction, NamedTuple('Begin', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.SessionAction.Begin'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, SessionAction_Begin)
    def __hash__(self) -> int:
        return super().__hash__()

class SessionAction_Publish(SessionAction, NamedTuple('Publish', [('generation', Any), ('token', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.SessionAction.Publish({_dafny.string_of(self.generation)}, {_dafny.string_of(self.token)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, SessionAction_Publish) and self.generation == __o.generation and self.token == __o.token
    def __hash__(self) -> int:
        return super().__hash__()

class SessionAction_Clear(SessionAction, NamedTuple('Clear', [('generation', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.SessionAction.Clear({_dafny.string_of(self.generation)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, SessionAction_Clear) and self.generation == __o.generation
    def __hash__(self) -> int:
        return super().__hash__()


class Dec:
    @classmethod
    def default(cls, ):
        return lambda: Dec_Dec(_dafny.Seq({}), int(0), False, False)
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Dec(self) -> bool:
        return isinstance(self, Dec_Dec)

class Dec_Dec(Dec, NamedTuple('Dec', [('pending', Any), ('next_', Any), ('authenticated', Any), ('requireFrame', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Dec.Dec({_dafny.string_of(self.pending)}, {_dafny.string_of(self.next_)}, {_dafny.string_of(self.authenticated)}, {_dafny.string_of(self.requireFrame)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Dec_Dec) and self.pending == __o.pending and self.next_ == __o.next_ and self.authenticated == __o.authenticated and self.requireFrame == __o.requireFrame
    def __hash__(self) -> int:
        return super().__hash__()


class Chunk:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return _dafny.SeqWithoutIsStrInference([])
    def _Is(source__):
        d_4_b_: _dafny.Seq = source__
        return (len(d_4_b_)) < (4294967296)

class Upload:
    @classmethod
    def default(cls, ):
        return lambda: Upload_NoUpload()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_NoUpload(self) -> bool:
        return isinstance(self, Upload_NoUpload)
    @property
    def is_Sealing(self) -> bool:
        return isinstance(self, Upload_Sealing)
    @property
    def is_UpReading(self) -> bool:
        return isinstance(self, Upload_UpReading)
    @property
    def is_UpDone(self) -> bool:
        return isinstance(self, Upload_UpDone)

class Upload_NoUpload(Upload, NamedTuple('NoUpload', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Upload.NoUpload'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Upload_NoUpload)
    def __hash__(self) -> int:
        return super().__hash__()

class Upload_Sealing(Upload, NamedTuple('Sealing', [('plaintext', Any), ('offset', Any), ('eof', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Upload.Sealing({_dafny.string_of(self.plaintext)}, {_dafny.string_of(self.offset)}, {_dafny.string_of(self.eof)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Upload_Sealing) and self.plaintext == __o.plaintext and self.offset == __o.offset and self.eof == __o.eof
    def __hash__(self) -> int:
        return super().__hash__()

class Upload_UpReading(Upload, NamedTuple('UpReading', [('empty', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Upload.UpReading({_dafny.string_of(self.empty)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Upload_UpReading) and self.empty == __o.empty
    def __hash__(self) -> int:
        return super().__hash__()

class Upload_UpDone(Upload, NamedTuple('UpDone', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Upload.UpDone'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Upload_UpDone)
    def __hash__(self) -> int:
        return super().__hash__()


class Response:
    @classmethod
    def default(cls, ):
        return lambda: Response_AwaitHead(False)
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_AwaitHead(self) -> bool:
        return isinstance(self, Response_AwaitHead)
    @property
    def is_ProblemReading(self) -> bool:
        return isinstance(self, Response_ProblemReading)
    @property
    def is_AwaitKeys(self) -> bool:
        return isinstance(self, Response_AwaitKeys)
    @property
    def is_Body(self) -> bool:
        return isinstance(self, Response_Body)
    @property
    def is_BodyReading(self) -> bool:
        return isinstance(self, Response_BodyReading)
    @property
    def is_Opening(self) -> bool:
        return isinstance(self, Response_Opening)
    @property
    def is_RespEnded(self) -> bool:
        return isinstance(self, Response_RespEnded)

class Response_AwaitHead(Response, NamedTuple('AwaitHead', [('encrypted', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Response.AwaitHead({_dafny.string_of(self.encrypted)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Response_AwaitHead) and self.encrypted == __o.encrypted
    def __hash__(self) -> int:
        return super().__hash__()

class Response_ProblemReading(Response, NamedTuple('ProblemReading', [('status', Any), ('headers', Any), ('data', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Response.ProblemReading({_dafny.string_of(self.status)}, {_dafny.string_of(self.headers)}, {_dafny.string_of(self.data)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Response_ProblemReading) and self.status == __o.status and self.headers == __o.headers and self.data == __o.data
    def __hash__(self) -> int:
        return super().__hash__()

class Response_AwaitKeys(Response, NamedTuple('AwaitKeys', [('status', Any), ('headers', Any), ('requireFrame', Any), ('stage', Any), ('job', Any), ('prk', Any), ('key', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBPEvents.Response.AwaitKeys(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Response_AwaitKeys) and self.status == __o.status and self.headers == __o.headers and self.requireFrame == __o.requireFrame and self.stage == __o.stage and self.job == __o.job and self.prk == __o.prk and self.key == __o.key
    def __hash__(self) -> int:
        return super().__hash__()

class Response_Body(Response, NamedTuple('Body', [('keys', Any), ('dec', Any), ('done', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Response.Body({_dafny.string_of(self.keys)}, {_dafny.string_of(self.dec)}, {_dafny.string_of(self.done)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Response_Body) and self.keys == __o.keys and self.dec == __o.dec and self.done == __o.done
    def __hash__(self) -> int:
        return super().__hash__()

class Response_BodyReading(Response, NamedTuple('BodyReading', [('keys', Any), ('dec', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Response.BodyReading({_dafny.string_of(self.keys)}, {_dafny.string_of(self.dec)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Response_BodyReading) and self.keys == __o.keys and self.dec == __o.dec
    def __hash__(self) -> int:
        return super().__hash__()

class Response_Opening(Response, NamedTuple('Opening', [('keys', Any), ('dec', Any), ('frames', Any), ('chunks', Any), ('eof', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Response.Opening({_dafny.string_of(self.keys)}, {_dafny.string_of(self.dec)}, {_dafny.string_of(self.frames)}, {_dafny.string_of(self.chunks)}, {_dafny.string_of(self.eof)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Response_Opening) and self.keys == __o.keys and self.dec == __o.dec and self.frames == __o.frames and self.chunks == __o.chunks and self.eof == __o.eof
    def __hash__(self) -> int:
        return super().__hash__()

class Response_RespEnded(Response, NamedTuple('RespEnded', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Response.RespEnded'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Response_RespEnded)
    def __hash__(self) -> int:
        return super().__hash__()


class Phase:
    @classmethod
    def default(cls, ):
        return lambda: Phase_Idle()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Idle(self) -> bool:
        return isinstance(self, Phase_Idle)
    @property
    def is_AwaitSession(self) -> bool:
        return isinstance(self, Phase_AwaitSession)
    @property
    def is_Peeking(self) -> bool:
        return isinstance(self, Phase_Peeking)
    @property
    def is_AwaitSetup(self) -> bool:
        return isinstance(self, Phase_AwaitSetup)
    @property
    def is_AwaitExport(self) -> bool:
        return isinstance(self, Phase_AwaitExport)
    @property
    def is_Exchanging(self) -> bool:
        return isinstance(self, Phase_Exchanging)
    @property
    def is_DiscAwaitHead(self) -> bool:
        return isinstance(self, Phase_DiscAwaitHead)
    @property
    def is_DiscReading(self) -> bool:
        return isinstance(self, Phase_DiscReading)
    @property
    def is_Ended(self) -> bool:
        return isinstance(self, Phase_Ended)

class Phase_Idle(Phase, NamedTuple('Idle', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Phase.Idle'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Phase_Idle)
    def __hash__(self) -> int:
        return super().__hash__()

class Phase_AwaitSession(Phase, NamedTuple('AwaitSession', [('hasBody', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Phase.AwaitSession({_dafny.string_of(self.hasBody)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Phase_AwaitSession) and self.hasBody == __o.hasBody
    def __hash__(self) -> int:
        return super().__hash__()

class Phase_Peeking(Phase, NamedTuple('Peeking', [('empty', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Phase.Peeking({_dafny.string_of(self.empty)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Phase_Peeking) and self.empty == __o.empty
    def __hash__(self) -> int:
        return super().__hash__()

class Phase_AwaitSetup(Phase, NamedTuple('AwaitSetup', [('first', Any), ('firstEof', Any), ('hpke', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Phase.AwaitSetup({_dafny.string_of(self.first)}, {_dafny.string_of(self.firstEof)}, {_dafny.string_of(self.hpke)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Phase_AwaitSetup) and self.first == __o.first and self.firstEof == __o.firstEof and self.hpke == __o.hpke
    def __hash__(self) -> int:
        return super().__hash__()

class Phase_AwaitExport(Phase, NamedTuple('AwaitExport', [('first', Any), ('firstEof', Any), ('enc', Any), ('job', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Phase.AwaitExport({_dafny.string_of(self.first)}, {_dafny.string_of(self.firstEof)}, {_dafny.string_of(self.enc)}, {_dafny.string_of(self.job)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Phase_AwaitExport) and self.first == __o.first and self.firstEof == __o.firstEof and self.enc == __o.enc and self.job == __o.job
    def __hash__(self) -> int:
        return super().__hash__()

class Phase_Exchanging(Phase, NamedTuple('Exchanging', [('upload', Any), ('response', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Phase.Exchanging({_dafny.string_of(self.upload)}, {_dafny.string_of(self.response)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Phase_Exchanging) and self.upload == __o.upload and self.response == __o.response
    def __hash__(self) -> int:
        return super().__hash__()

class Phase_DiscAwaitHead(Phase, NamedTuple('DiscAwaitHead', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Phase.DiscAwaitHead'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Phase_DiscAwaitHead)
    def __hash__(self) -> int:
        return super().__hash__()

class Phase_DiscReading(Phase, NamedTuple('DiscReading', [('data', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Phase.DiscReading({_dafny.string_of(self.data)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Phase_DiscReading) and self.data == __o.data
    def __hash__(self) -> int:
        return super().__hash__()

class Phase_Ended(Phase, NamedTuple('Ended', [])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.Phase.Ended'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Phase_Ended)
    def __hash__(self) -> int:
        return super().__hash__()


class State:
    @classmethod
    def default(cls, ):
        return lambda: State_State(Phase.default()(), EHBP.Origin.default()(), _dafny.Seq({}), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.Seq({}), int(0), False, EHBP.Token.default()(), Ctx.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_State(self) -> bool:
        return isinstance(self, State_State)

class State_State(State, NamedTuple('State', [('phase', Any), ('origin', Any), ('publicKey', Any), ('verb', Any), ('url', Any), ('headers', Any), ('generation', Any), ('published', Any), ('token', Any), ('ctx', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBPEvents.State.State({_dafny.string_of(self.phase)}, {_dafny.string_of(self.origin)}, {_dafny.string_of(self.publicKey)}, {self.verb.VerbatimString(True)}, {self.url.VerbatimString(True)}, {_dafny.string_of(self.headers)}, {_dafny.string_of(self.generation)}, {_dafny.string_of(self.published)}, {_dafny.string_of(self.token)}, {_dafny.string_of(self.ctx)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, State_State) and self.phase == __o.phase and self.origin == __o.origin and self.publicKey == __o.publicKey and self.verb == __o.verb and self.url == __o.url and self.headers == __o.headers and self.generation == __o.generation and self.published == __o.published and self.token == __o.token and self.ctx == __o.ctx
    def __hash__(self) -> int:
        return super().__hash__()

