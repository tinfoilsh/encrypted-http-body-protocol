import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_

# Module: EHBP

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def CheckPublicKey(b):
        if (len(b)) == (32):
            d_0_key_ = b
            return Result_Ok(d_0_key_)
        elif True:
            return Result_Err(Code_InvalidKeyConfig(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "public key must be 32 bytes")))

    @staticmethod
    def CodeString(c):
        source0_ = c
        if True:
            if source0_.is_InvalidKeyConfig:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "INVALID_KEY_CONFIG"))
        if True:
            if source0_.is_UnsupportedSuite:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNSUPPORTED_SUITE"))
        if True:
            if source0_.is_InvalidEncapsulatedKey:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "INVALID_ENCAPSULATED_KEY"))
        if True:
            if source0_.is_HpkeSetupFailed:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "HPKE_SETUP_FAILED"))
        if True:
            if source0_.is_MissingResponseNonce:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "MISSING_RESPONSE_NONCE"))
        if True:
            if source0_.is_UnexpectedRedirect:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "UNEXPECTED_REDIRECT"))
        if True:
            if source0_.is_InvalidResponseNonce:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "INVALID_RESPONSE_NONCE"))
        if True:
            if source0_.is_DuplicateResponseNonce:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "DUPLICATE_RESPONSE_NONCE"))
        if True:
            if source0_.is_KeyConfigMismatch:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "KEY_CONFIG_MISMATCH"))
        if True:
            if source0_.is_FramingTruncated:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "FRAMING_TRUNCATED"))
        if True:
            if source0_.is_ChunkTooLarge:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "CHUNK_TOO_LARGE"))
        if True:
            if source0_.is_AeadDecryptFailed:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "AEAD_DECRYPT_FAILED"))
        if True:
            if source0_.is_SequenceOverflow:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "SEQUENCE_OVERFLOW"))
        if True:
            if source0_.is_InvalidToken:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "INVALID_TOKEN"))
        if True:
            if source0_.is_InvalidInput:
                return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "INVALID_INPUT"))
        if True:
            return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, ""))

    @staticmethod
    def U16(b, i):
        return (((b)[i]) * (256)) + ((b)[(i) + (1)])

    @staticmethod
    def U32(b, i):
        return ((default__.U16(b, i)) * (65536)) + (default__.U16(b, (i) + (2)))

    @staticmethod
    def BE16(v):
        return _dafny.SeqWithoutIsStrInference([_dafny.euclidian_division(v, 256), _dafny.euclidian_modulus(v, 256)])

    @staticmethod
    def BE32(v):
        return (default__.BE16(_dafny.euclidian_division(v, 65536))) + (default__.BE16(_dafny.euclidian_modulus(v, 65536)))

    @staticmethod
    def IsAscii(s):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(s)))) or ((ord((s)[d_0_i_])) < (128))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(s)), True, lambda0_)

    @staticmethod
    def Ascii(s):
        return _dafny.SeqWithoutIsStrInference([ord((s)[d_0_i_]) for d_0_i_ in range(len(s))])

    @staticmethod
    def LowerChar(c):
        if ((_dafny.CodePoint('A')) <= (c)) and ((c) <= (_dafny.CodePoint('Z'))):
            return _dafny.CodePoint(chr((ord(c)) + (32)))
        elif True:
            return c

    @staticmethod
    def Lower(s):
        return _dafny.SeqWithoutIsStrInference([default__.LowerChar((s)[d_0_i_]) for d_0_i_ in range(len(s))])

    @staticmethod
    def EqualFold(a, b):
        return (default__.Lower(a)) == (default__.Lower(b))

    @staticmethod
    def IsSpace(c):
        return ((c) == (_dafny.CodePoint(' '))) or ((c) == (_dafny.CodePoint('\t')))

    @staticmethod
    def TrimLeft(s):
        while True:
            with _dafny.label():
                if ((len(s)) > (0)) and (default__.IsSpace((s)[0])):
                    in0_ = _dafny.SeqWithoutIsStrInference((s)[1::])
                    s = in0_
                    raise _dafny.TailCall()
                elif True:
                    return s
                break

    @staticmethod
    def TrimRight(s):
        while True:
            with _dafny.label():
                if ((len(s)) > (0)) and (default__.IsSpace((s)[(len(s)) - (1)])):
                    in0_ = _dafny.SeqWithoutIsStrInference((s)[:(len(s)) - (1):])
                    s = in0_
                    raise _dafny.TailCall()
                elif True:
                    return s
                break

    @staticmethod
    def Trim(s):
        return default__.TrimRight(default__.TrimLeft(s))

    @staticmethod
    def Before(s, sep):
        return default__.BeforeFrom(s, sep, 0)

    @staticmethod
    def BeforeFrom(s, sep, i):
        while True:
            with _dafny.label():
                if ((i) == (len(s))) or (((s)[i]) == (sep)):
                    return _dafny.SeqWithoutIsStrInference((s)[:i:])
                elif True:
                    in0_ = s
                    in1_ = sep
                    in2_ = (i) + (1)
                    s = in0_
                    sep = in1_
                    i = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def MediaType(contentType):
        return default__.Lower(default__.Trim(default__.Before(contentType, _dafny.CodePoint(';'))))

    @staticmethod
    def HasMediaType(contentType, want):
        return ((contentType).is_Some) and ((default__.MediaType((contentType).value)) == (default__.Lower(want)))

    @staticmethod
    def HexDigitValue(c):
        if ((_dafny.CodePoint('0')) <= (c)) and ((c) <= (_dafny.CodePoint('9'))):
            return Option_Some((ord(c)) - (ord(_dafny.CodePoint('0'))))
        elif ((_dafny.CodePoint('a')) <= (c)) and ((c) <= (_dafny.CodePoint('f'))):
            return Option_Some(((ord(c)) - (ord(_dafny.CodePoint('a')))) + (10))
        elif ((_dafny.CodePoint('A')) <= (c)) and ((c) <= (_dafny.CodePoint('F'))):
            return Option_Some(((ord(c)) - (ord(_dafny.CodePoint('A')))) + (10))
        elif True:
            return Option_None()

    @staticmethod
    def IsHex(s):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(s)))) or ((default__.HexDigitValue((s)[d_0_i_])).is_Some)

        return ((_dafny.euclidian_modulus(len(s), 2)) == (0)) and (_dafny.quantifier(_dafny.IntegerRange(0, len(s)), True, lambda0_))

    @staticmethod
    def DecodeHex(s):
        if not(default__.IsHex(s)):
            return Option_None()
        elif True:
            return Option_Some(_dafny.SeqWithoutIsStrInference([(((default__.HexDigitValue((s)[(2) * (d_0_i_)])).value) * (16)) + ((default__.HexDigitValue((s)[((2) * (d_0_i_)) + (1)])).value) for d_0_i_ in range(_dafny.euclidian_division(len(s), 2))]))

    @staticmethod
    def EncodeHex(b):
        return _dafny.SeqWithoutIsStrInference([((default__.HexDigits)[_dafny.euclidian_division((b)[_dafny.euclidian_division(d_0_i_, 2)], 16)] if (_dafny.euclidian_modulus(d_0_i_, 2)) == (0) else (default__.HexDigits)[_dafny.euclidian_modulus((b)[_dafny.euclidian_division(d_0_i_, 2)], 16)]) for d_0_i_ in range((2) * (len(b)))])

    @staticmethod
    def ComputeNonce(nonceBase, seqNo):
        pat_let_tv0_ = nonceBase
        pat_let_tv1_ = nonceBase
        pat_let_tv2_ = seqNo
        def iife0_(_pat_let0_0):
            def iife1_(d_1_j_):
                return ((pat_let_tv0_)[d_1_j_] if (d_1_j_) < (4) else ((pat_let_tv1_)[d_1_j_]) ^ (default__.ByteAt(pat_let_tv2_, (11) - (d_1_j_))))
            return iife1_(_pat_let0_0)
        return _dafny.SeqWithoutIsStrInference([iife0_(d_0_i_) for d_0_i_ in range(default__.NonceLength)])

    @staticmethod
    def NonceFor(nonceBase, seqNo):
        if (len(nonceBase)) != (default__.NonceLength):
            return Result_Err(Code_InvalidInput(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "nonce base must be 12 bytes")))
        elif True:
            return Result_Ok(default__.ComputeNonce(nonceBase, seqNo))

    @staticmethod
    def ByteAt(x, k):
        while True:
            with _dafny.label():
                if (k) == (0):
                    return _dafny.euclidian_modulus(x, 256)
                elif True:
                    in0_ = _dafny.euclidian_division(x, 256)
                    in1_ = (k) - (1)
                    x = in0_
                    k = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def KnownKdf(id_):
        return (((id_) == (1)) or ((id_) == (2))) or ((id_) == (3))

    @staticmethod
    def KnownAead(id_):
        return (((id_) == (1)) or ((id_) == (2))) or ((id_) == (3))

    @staticmethod
    def ParseConfig(data):
        if (len(data)) < (3):
            return Result_Err(Code_InvalidKeyConfig(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "invalid config")))
        elif (default__.U16(data, 1)) != (default__.KemX25519):
            return Result_Err(Code_UnsupportedSuite(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "unsupported KEM")))
        elif (len(data)) < (((3) + (default__.PublicKeyLength)) + (2)):
            return Result_Err(Code_InvalidKeyConfig(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "invalid config")))
        elif True:
            d_0_pk_ = _dafny.SeqWithoutIsStrInference((data)[3:(3) + (default__.PublicKeyLength):])
            d_1_suitesLen_ = default__.U16(data, (3) + (default__.PublicKeyLength))
            d_2_start_ = ((3) + (default__.PublicKeyLength)) + (2)
            if (len(data)) < ((d_2_start_) + (d_1_suitesLen_)):
                return Result_Err(Code_InvalidKeyConfig(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "invalid config")))
            elif True:
                source0_ = default__.ParseSuites(_dafny.SeqWithoutIsStrInference((data)[d_2_start_:(d_2_start_) + (d_1_suitesLen_):]))
                if True:
                    if source0_.is_Err:
                        d_3_code_ = source0_.code
                        d_4_message_ = source0_.message
                        return Result_Err(d_3_code_, d_4_message_)
                if True:
                    d_5_suites_ = source0_.value
                    if (len(d_5_suites_)) == (0):
                        return Result_Err(Code_InvalidKeyConfig(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "no cipher suites found in config")))
                    elif (len(d_5_suites_)) != (1):
                        return Result_Err(Code_UnsupportedSuite(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "expected exactly one cipher suite")))
                    elif ((d_5_suites_)[0]) != ((default__.KdfHkdfSha256, default__.AeadAes256Gcm)):
                        return Result_Err(Code_UnsupportedSuite(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "unsupported cipher suite")))
                    elif True:
                        return Result_Ok(d_0_pk_)

    @staticmethod
    def ParseSuites(s):
        return default__.ParseSuitesFrom(s, 0, _dafny.SeqWithoutIsStrInference([]))

    @staticmethod
    def ParseSuitesFrom(s, i, acc):
        while True:
            with _dafny.label():
                if (i) == (len(s)):
                    return Result_Ok(acc)
                elif ((len(s)) - (i)) < (4):
                    return Result_Err(Code_InvalidKeyConfig(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "invalid config")))
                elif True:
                    d_0_kdf_ = default__.U16(s, i)
                    d_1_aead_ = default__.U16(s, (i) + (2))
                    if not(default__.KnownKdf(d_0_kdf_)):
                        return Result_Err(Code_UnsupportedSuite(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "invalid KDF")))
                    elif not(default__.KnownAead(d_1_aead_)):
                        return Result_Err(Code_UnsupportedSuite(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "invalid AEAD")))
                    elif True:
                        in0_ = s
                        in1_ = (i) + (4)
                        in2_ = (acc) + (_dafny.SeqWithoutIsStrInference([(d_0_kdf_, d_1_aead_)]))
                        s = in0_
                        i = in1_
                        acc = in2_
                        raise _dafny.TailCall()
                break

    @staticmethod
    def MarshalConfig(publicKey):
        if (len(publicKey)) != (default__.PublicKeyLength):
            return Result_Err(Code_InvalidKeyConfig(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "invalid public key")))
        elif True:
            return Result_Ok((((((_dafny.SeqWithoutIsStrInference([0])) + (default__.BE16(default__.KemX25519))) + (publicKey)) + (default__.BE16(4))) + (default__.BE16(default__.KdfHkdfSha256))) + (default__.BE16(default__.AeadAes256Gcm)))

    @staticmethod
    def ValidToken(t):
        return ((len((t).exportedSecret)) == (default__.ExportLength)) and ((len((t).requestEnc)) == (default__.RequestEncLength))

    @staticmethod
    def ValidateTokenFields(exportedSecretHex, requestEncHex):
        if ((exportedSecretHex).is_None) or ((requestEncHex).is_None):
            return Result_Err(Code_InvalidToken(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "token field missing")))
        elif True:
            source0_ = (default__.DecodeHex((exportedSecretHex).value), default__.DecodeHex((requestEncHex).value))
            if True:
                d_00_ = source0_[0]
                if d_00_.is_Some:
                    d_0_secret_ = d_00_.value
                    d_10_ = source0_[1]
                    if d_10_.is_Some:
                        d_1_enc_ = d_10_.value
                        if ((len(d_0_secret_)) != (default__.ExportLength)) or ((len(d_1_enc_)) != (default__.RequestEncLength)):
                            return Result_Err(Code_InvalidToken(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "token field has wrong length")))
                        elif True:
                            return Result_Ok(Token_Token(d_0_secret_, d_1_enc_))
            if True:
                return Result_Err(Code_InvalidToken(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "token field is not hex")))

    @staticmethod
    def Frame(ciphertext):
        return (default__.BE32(len(ciphertext))) + (ciphertext)

    @staticmethod
    def HeaderValues(headers, name):
        return default__.HeaderValuesFrom(headers, name, 0, _dafny.SeqWithoutIsStrInference([]))

    @staticmethod
    def HeaderValuesFrom(headers, name, i, acc):
        while True:
            with _dafny.label():
                if (i) == (len(headers)):
                    return acc
                elif True:
                    in0_ = headers
                    in1_ = name
                    in2_ = (i) + (1)
                    in3_ = ((acc) + (_dafny.SeqWithoutIsStrInference([((headers)[i])[1]])) if default__.EqualFold(((headers)[i])[0], name) else acc)
                    headers = in0_
                    name = in1_
                    i = in2_
                    acc = in3_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def FirstHeader(headers, name):
        d_0_values_ = default__.HeaderValues(headers, name)
        if (len(d_0_values_)) == (0):
            return Option_None()
        elif True:
            return Option_Some((d_0_values_)[0])

    @staticmethod
    def BodylessSuccess(status):
        return ((status) == (204)) or ((status) == (205))

    @staticmethod
    def Classify(encrypted, head):
        d_0_nonces_ = default__.HeaderValues((head).headers, default__.ResponseNonceHeader)
        if not(encrypted):
            return Disposition_PassThrough()
        elif ((head).redirected) or (((300) <= ((head).status)) and (((head).status) < (400))):
            return Disposition_Refuse(Code_UnexpectedRedirect(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "redirect in response to an encrypted request")))
        elif (len(d_0_nonces_)) == (0):
            if ((head).status) < (400):
                return Disposition_Refuse(Code_MissingResponseNonce(), ((_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "missing "))) + (default__.ResponseNonceHeader)) + (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, " header"))))
            elif (((head).status) == (422)) and (default__.HasMediaType(default__.FirstHeader((head).headers, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "Content-Type"))), default__.ProblemJsonMediaType)):
                return Disposition_NeedProblemBody()
            elif True:
                return Disposition_PassThrough()
        elif (len(d_0_nonces_)) > (1):
            return Disposition_Refuse(Code_DuplicateResponseNonce(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "duplicate response nonce")))
        elif ((d_0_nonces_)[0]) == (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, ""))):
            return Disposition_Refuse(Code_InvalidResponseNonce(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "empty response nonce")))
        elif True:
            source0_ = default__.DecodeHex((d_0_nonces_)[0])
            if True:
                if source0_.is_None:
                    return Disposition_Refuse(Code_InvalidResponseNonce(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "response nonce is not hex")))
            if True:
                d_1_nonce_ = source0_.value
                if (len(d_1_nonce_)) != (default__.ResponseNonceLength):
                    return Disposition_Refuse(Code_InvalidResponseNonce(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "response nonce has wrong length")))
                elif default__.BodylessSuccess((head).status):
                    return Disposition_Refuse(Code_FramingTruncated(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "status cannot carry an authenticated frame")))
                elif True:
                    return Disposition_Decrypt(d_1_nonce_, ((head).status) < (400))

    @staticmethod
    def ClassifyProblem(oversized, isObject, typeValue, title):
        if ((oversized) or (not(isObject))) or ((typeValue) != (Option_Some(default__.KeyConfigProblemType))):
            return Disposition_PassThrough()
        elif True:
            return Disposition_Refuse(Code_KeyConfigMismatch(), ((title).value if ((title).is_Some) and (((title).value) != (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))) else default__.DefaultKeyConfigTitle))

    @staticmethod
    def ClassifyDiscovery(head):
        if ((head).redirected) or (((head).status) != (200)):
            return Result_Err(Code_InvalidKeyConfig(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "discovery returned a non-200 status")))
        elif not(default__.HasMediaType(default__.FirstHeader((head).headers, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "Content-Type"))), default__.KeysMediaType)):
            return Result_Err(Code_InvalidKeyConfig(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "discovery returned the wrong media type")))
        elif True:
            return Result_Ok(())

    @staticmethod
    def DefaultPort(scheme):
        if (default__.Lower(scheme)) == (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "https"))):
            return 443
        elif True:
            return 80

    @staticmethod
    def MakeOrigin(scheme, host, port, hasUserinfo):
        d_0_s_ = default__.Lower(scheme)
        if ((d_0_s_) != (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "http")))) and ((d_0_s_) != (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "https")))):
            return Result_Err(Code_InvalidInput(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "base URL must include an HTTP origin")))
        elif (host) == (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, ""))):
            return Result_Err(Code_InvalidInput(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "base URL must include an HTTP origin")))
        elif hasUserinfo:
            return Result_Err(Code_InvalidInput(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "base URL must not include credentials")))
        elif True:
            return Result_Ok(Origin_Origin(d_0_s_, default__.Lower(host), ((port).value if (port).is_Some else default__.DefaultPort(d_0_s_))))

    @staticmethod
    def SameOrigin(a, b):
        return ((((a).scheme) == ((b).scheme)) and (((a).host) == ((b).host))) and (((a).port) == ((b).port))

    @staticmethod
    def ReservedHeader(name):
        return ((default__.EqualFold(name, default__.EncapsulatedKeyHeader)) or (default__.EqualFold(name, default__.ResponseNonceHeader))) or (default__.EqualFold(name, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "Host"))))

    @staticmethod
    def FramingHeader(name):
        return (default__.EqualFold(name, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "Content-Length")))) or (default__.EqualFold(name, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "Transfer-Encoding"))))

    @staticmethod
    def ValidateRequest(origin, target, headers):
        if (target).is_Err:
            return Result_Err(Code_InvalidInput(), (target).message)
        elif not(default__.SameOrigin(origin, (target).value)):
            return Result_Err(Code_InvalidInput(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "request URL must use the configured origin")))
        elif True:
            return default__.ValidateHeadersFrom(headers, 0)

    @staticmethod
    def ValidateHeadersFrom(headers, i):
        while True:
            with _dafny.label():
                if (i) == (len(headers)):
                    return Result_Ok(())
                elif default__.ReservedHeader(((headers)[i])[0]):
                    return Result_Err(Code_InvalidInput(), (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "reserved request header cannot be set by callers: "))) + (((headers)[i])[0]))
                elif True:
                    in0_ = headers
                    in1_ = (i) + (1)
                    headers = in0_
                    i = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def DropFraming(headers):
        return default__.DropFramingFrom(headers, 0, _dafny.SeqWithoutIsStrInference([]))

    @staticmethod
    def DropFramingFrom(headers, i, acc):
        while True:
            with _dafny.label():
                if (i) == (len(headers)):
                    return acc
                elif True:
                    in0_ = headers
                    in1_ = (i) + (1)
                    in2_ = (acc if default__.FramingHeader(((headers)[i])[0]) else (acc) + (_dafny.SeqWithoutIsStrInference([(headers)[i]])))
                    headers = in0_
                    i = in1_
                    acc = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def OriginUrl(origin):
        d_0_portPart_ = (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")) if ((origin).port) == (default__.DefaultPort((origin).scheme)) else (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, ":"))) + (default__.IntToString((origin).port)))
        return ((((origin).scheme) + (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "://")))) + ((origin).host)) + (d_0_portPart_)

    @staticmethod
    def IntToString(n):
        if (n) < (0):
            return (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "-"))) + (default__.IntToString((0) - (n)))
        elif (n) < (10):
            return _dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr((ord(_dafny.CodePoint('0'))) + (n)))])
        elif True:
            return (default__.IntToString(_dafny.euclidian_division(n, 10))) + (_dafny.SeqWithoutIsStrInference([_dafny.CodePoint(chr((ord(_dafny.CodePoint('0'))) + (_dafny.euclidian_modulus(n, 10))))]))

    @_dafny.classproperty
    def Codes(instance):
        return _dafny.SeqWithoutIsStrInference([Code_InvalidKeyConfig(), Code_UnsupportedSuite(), Code_InvalidEncapsulatedKey(), Code_HpkeSetupFailed(), Code_MissingResponseNonce(), Code_UnexpectedRedirect(), Code_InvalidResponseNonce(), Code_DuplicateResponseNonce(), Code_KeyConfigMismatch(), Code_FramingTruncated(), Code_ChunkTooLarge(), Code_AeadDecryptFailed(), Code_SequenceOverflow(), Code_InvalidToken(), Code_InvalidInput()])
    @_dafny.classproperty
    def KemX25519(instance):
        return 32
    @_dafny.classproperty
    def KdfHkdfSha256(instance):
        return 1
    @_dafny.classproperty
    def AeadAes256Gcm(instance):
        return 2
    @_dafny.classproperty
    def MaxChunkBytes(instance):
        return ((64) * (1024)) * (1024)
    @_dafny.classproperty
    def RequestFrameBytes(instance):
        return 65536
    @_dafny.classproperty
    def HexDigits(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "0123456789abcdef"))
    @_dafny.classproperty
    def NonceLength(instance):
        return 12
    @_dafny.classproperty
    def PublicKeyLength(instance):
        return 32
    @_dafny.classproperty
    def ExportLength(instance):
        return 32
    @_dafny.classproperty
    def RequestEncLength(instance):
        return 32
    @_dafny.classproperty
    def ResponseNonceHeader(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "Ehbp-Response-Nonce"))
    @_dafny.classproperty
    def ProblemJsonMediaType(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "application/problem+json"))
    @_dafny.classproperty
    def ResponseNonceLength(instance):
        return 32
    @_dafny.classproperty
    def KeyConfigProblemType(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "urn:ietf:params:ehbp:error:key-config"))
    @_dafny.classproperty
    def DefaultKeyConfigTitle(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "key configuration mismatch"))
    @_dafny.classproperty
    def KeysMediaType(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "application/ohttp-keys"))
    @_dafny.classproperty
    def EncapsulatedKeyHeader(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "Ehbp-Encapsulated-Key"))
    @_dafny.classproperty
    def KeyLength(instance):
        return 32
    @_dafny.classproperty
    def HpkeRequestInfo(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ehbp request"))
    @_dafny.classproperty
    def ExportLabel(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ehbp response"))
    @_dafny.classproperty
    def ResponseKeyLabel(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "key"))
    @_dafny.classproperty
    def ResponseNonceLabel(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "nonce"))
    @_dafny.classproperty
    def KeysPath(instance):
        return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "/.well-known/hpke-keys"))
    @_dafny.classproperty
    def MaxProblemBytes(instance):
        return (64) * (1024)
    @_dafny.classproperty
    def MaxKeyConfigBytes(instance):
        return (37) + (65535)
    @_dafny.classproperty
    def MaxEmptyReads(instance):
        return 100
    @_dafny.classproperty
    def AeadTagLength(instance):
        return 16
    @_dafny.classproperty
    def HashLength(instance):
        return 32

class uint8:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return int(0)
    def _Is(source__):
        return True

class uint16:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return int(0)
    def _Is(source__):
        return True

class uint32:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return int(0)
    def _Is(source__):
        return True

class uint64:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return int(0)
    def _Is(source__):
        return True

class PublicKey:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return _dafny.SeqWithoutIsStrInference([0 for d_0_i_ in range(32)])
    def _Is(source__):
        d_1_b_: _dafny.Seq = source__
        return (len(d_1_b_)) == (32)

class Code:
    @_dafny.classproperty
    def AllSingletonConstructors(cls):
        return [Code_InvalidKeyConfig(), Code_UnsupportedSuite(), Code_InvalidEncapsulatedKey(), Code_HpkeSetupFailed(), Code_MissingResponseNonce(), Code_UnexpectedRedirect(), Code_InvalidResponseNonce(), Code_DuplicateResponseNonce(), Code_KeyConfigMismatch(), Code_FramingTruncated(), Code_ChunkTooLarge(), Code_AeadDecryptFailed(), Code_SequenceOverflow(), Code_InvalidToken(), Code_InvalidInput(), Code_Transport()]
    @classmethod
    def default(cls, ):
        return lambda: Code_InvalidKeyConfig()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_InvalidKeyConfig(self) -> bool:
        return isinstance(self, Code_InvalidKeyConfig)
    @property
    def is_UnsupportedSuite(self) -> bool:
        return isinstance(self, Code_UnsupportedSuite)
    @property
    def is_InvalidEncapsulatedKey(self) -> bool:
        return isinstance(self, Code_InvalidEncapsulatedKey)
    @property
    def is_HpkeSetupFailed(self) -> bool:
        return isinstance(self, Code_HpkeSetupFailed)
    @property
    def is_MissingResponseNonce(self) -> bool:
        return isinstance(self, Code_MissingResponseNonce)
    @property
    def is_UnexpectedRedirect(self) -> bool:
        return isinstance(self, Code_UnexpectedRedirect)
    @property
    def is_InvalidResponseNonce(self) -> bool:
        return isinstance(self, Code_InvalidResponseNonce)
    @property
    def is_DuplicateResponseNonce(self) -> bool:
        return isinstance(self, Code_DuplicateResponseNonce)
    @property
    def is_KeyConfigMismatch(self) -> bool:
        return isinstance(self, Code_KeyConfigMismatch)
    @property
    def is_FramingTruncated(self) -> bool:
        return isinstance(self, Code_FramingTruncated)
    @property
    def is_ChunkTooLarge(self) -> bool:
        return isinstance(self, Code_ChunkTooLarge)
    @property
    def is_AeadDecryptFailed(self) -> bool:
        return isinstance(self, Code_AeadDecryptFailed)
    @property
    def is_SequenceOverflow(self) -> bool:
        return isinstance(self, Code_SequenceOverflow)
    @property
    def is_InvalidToken(self) -> bool:
        return isinstance(self, Code_InvalidToken)
    @property
    def is_InvalidInput(self) -> bool:
        return isinstance(self, Code_InvalidInput)
    @property
    def is_Transport(self) -> bool:
        return isinstance(self, Code_Transport)

class Code_InvalidKeyConfig(Code, NamedTuple('InvalidKeyConfig', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.InvalidKeyConfig'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_InvalidKeyConfig)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_UnsupportedSuite(Code, NamedTuple('UnsupportedSuite', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.UnsupportedSuite'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_UnsupportedSuite)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_InvalidEncapsulatedKey(Code, NamedTuple('InvalidEncapsulatedKey', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.InvalidEncapsulatedKey'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_InvalidEncapsulatedKey)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_HpkeSetupFailed(Code, NamedTuple('HpkeSetupFailed', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.HpkeSetupFailed'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_HpkeSetupFailed)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_MissingResponseNonce(Code, NamedTuple('MissingResponseNonce', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.MissingResponseNonce'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_MissingResponseNonce)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_UnexpectedRedirect(Code, NamedTuple('UnexpectedRedirect', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.UnexpectedRedirect'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_UnexpectedRedirect)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_InvalidResponseNonce(Code, NamedTuple('InvalidResponseNonce', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.InvalidResponseNonce'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_InvalidResponseNonce)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_DuplicateResponseNonce(Code, NamedTuple('DuplicateResponseNonce', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.DuplicateResponseNonce'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_DuplicateResponseNonce)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_KeyConfigMismatch(Code, NamedTuple('KeyConfigMismatch', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.KeyConfigMismatch'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_KeyConfigMismatch)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_FramingTruncated(Code, NamedTuple('FramingTruncated', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.FramingTruncated'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_FramingTruncated)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_ChunkTooLarge(Code, NamedTuple('ChunkTooLarge', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.ChunkTooLarge'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_ChunkTooLarge)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_AeadDecryptFailed(Code, NamedTuple('AeadDecryptFailed', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.AeadDecryptFailed'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_AeadDecryptFailed)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_SequenceOverflow(Code, NamedTuple('SequenceOverflow', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.SequenceOverflow'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_SequenceOverflow)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_InvalidToken(Code, NamedTuple('InvalidToken', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.InvalidToken'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_InvalidToken)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_InvalidInput(Code, NamedTuple('InvalidInput', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.InvalidInput'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_InvalidInput)
    def __hash__(self) -> int:
        return super().__hash__()

class Code_Transport(Code, NamedTuple('Transport', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Code.Transport'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Code_Transport)
    def __hash__(self) -> int:
        return super().__hash__()


class Result:
    @classmethod
    def default(cls, ):
        return lambda: Result_Err(Code.default()(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Ok(self) -> bool:
        return isinstance(self, Result_Ok)
    @property
    def is_Err(self) -> bool:
        return isinstance(self, Result_Err)

class Result_Ok(Result, NamedTuple('Ok', [('value', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Result.Ok({_dafny.string_of(self.value)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Result_Ok) and self.value == __o.value
    def __hash__(self) -> int:
        return super().__hash__()

class Result_Err(Result, NamedTuple('Err', [('code', Any), ('message', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Result.Err({_dafny.string_of(self.code)}, {self.message.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Result_Err) and self.code == __o.code and self.message == __o.message
    def __hash__(self) -> int:
        return super().__hash__()


class Option:
    @classmethod
    def default(cls, ):
        return lambda: Option_None()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_None(self) -> bool:
        return isinstance(self, Option_None)
    @property
    def is_Some(self) -> bool:
        return isinstance(self, Option_Some)

class Option_None(Option, NamedTuple('None_', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Option.None'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Option_None)
    def __hash__(self) -> int:
        return super().__hash__()

class Option_Some(Option, NamedTuple('Some', [('value', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Option.Some({_dafny.string_of(self.value)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Option_Some) and self.value == __o.value
    def __hash__(self) -> int:
        return super().__hash__()


class Token:
    @classmethod
    def default(cls, ):
        return lambda: Token_Token(_dafny.Seq({}), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Token(self) -> bool:
        return isinstance(self, Token_Token)

class Token_Token(Token, NamedTuple('Token', [('exportedSecret', Any), ('requestEnc', Any)])):
    def __dafnystr__(self) -> str:
        return 'EHBP.Token.Token(<redacted>)'
    __repr__ = __dafnystr__
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Token_Token) and self.exportedSecret == __o.exportedSecret and self.requestEnc == __o.requestEnc
    def __hash__(self) -> int:
        return super().__hash__()


class Framed:
    @classmethod
    def default(cls, ):
        return lambda: Framed_Framed(int(0), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Framed(self) -> bool:
        return isinstance(self, Framed_Framed)

class Framed_Framed(Framed, NamedTuple('Framed', [('seqNo', Any), ('ciphertext', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Framed.Framed({_dafny.string_of(self.seqNo)}, {_dafny.string_of(self.ciphertext)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Framed_Framed) and self.seqNo == __o.seqNo and self.ciphertext == __o.ciphertext
    def __hash__(self) -> int:
        return super().__hash__()


class Head:
    @classmethod
    def default(cls, ):
        return lambda: Head_Head(int(0), _dafny.Seq({}), False)
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Head(self) -> bool:
        return isinstance(self, Head_Head)

class Head_Head(Head, NamedTuple('Head', [('status', Any), ('headers', Any), ('redirected', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Head.Head({_dafny.string_of(self.status)}, {_dafny.string_of(self.headers)}, {_dafny.string_of(self.redirected)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Head_Head) and self.status == __o.status and self.headers == __o.headers and self.redirected == __o.redirected
    def __hash__(self) -> int:
        return super().__hash__()


class Disposition:
    @classmethod
    def default(cls, ):
        return lambda: Disposition_PassThrough()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_PassThrough(self) -> bool:
        return isinstance(self, Disposition_PassThrough)
    @property
    def is_Decrypt(self) -> bool:
        return isinstance(self, Disposition_Decrypt)
    @property
    def is_NeedProblemBody(self) -> bool:
        return isinstance(self, Disposition_NeedProblemBody)
    @property
    def is_Refuse(self) -> bool:
        return isinstance(self, Disposition_Refuse)

class Disposition_PassThrough(Disposition, NamedTuple('PassThrough', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Disposition.PassThrough'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Disposition_PassThrough)
    def __hash__(self) -> int:
        return super().__hash__()

class Disposition_Decrypt(Disposition, NamedTuple('Decrypt', [('nonce', Any), ('requireFrame', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Disposition.Decrypt({_dafny.string_of(self.nonce)}, {_dafny.string_of(self.requireFrame)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Disposition_Decrypt) and self.nonce == __o.nonce and self.requireFrame == __o.requireFrame
    def __hash__(self) -> int:
        return super().__hash__()

class Disposition_NeedProblemBody(Disposition, NamedTuple('NeedProblemBody', [])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Disposition.NeedProblemBody'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Disposition_NeedProblemBody)
    def __hash__(self) -> int:
        return super().__hash__()

class Disposition_Refuse(Disposition, NamedTuple('Refuse', [('code', Any), ('message', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Disposition.Refuse({_dafny.string_of(self.code)}, {self.message.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Disposition_Refuse) and self.code == __o.code and self.message == __o.message
    def __hash__(self) -> int:
        return super().__hash__()


class Origin:
    @classmethod
    def default(cls, ):
        return lambda: Origin_Origin(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), int(0))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Origin(self) -> bool:
        return isinstance(self, Origin_Origin)

class Origin_Origin(Origin, NamedTuple('Origin', [('scheme', Any), ('host', Any), ('port', Any)])):
    def __dafnystr__(self) -> str:
        return f'EHBP.Origin.Origin({self.scheme.VerbatimString(True)}, {self.host.VerbatimString(True)}, {_dafny.string_of(self.port)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Origin_Origin) and self.scheme == __o.scheme and self.host == __o.host and self.port == __o.port
    def __hash__(self) -> int:
        return super().__hash__()

