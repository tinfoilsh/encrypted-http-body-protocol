// Class __default
// Dafny class __default compiled into Java
package EHBP;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static Result<dafny.DafnySequence<? extends java.lang.Byte>> CheckPublicKey(dafny.DafnySequence<? extends java.lang.Byte> b) {
    if (java.util.Objects.equals(java.math.BigInteger.valueOf((b).length()), java.math.BigInteger.valueOf(32L))) {
      dafny.DafnySequence<? extends java.lang.Byte> _0_key = b;
      return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Ok(PublicKey._typeDescriptor(), _0_key);
    } else {
      return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(PublicKey._typeDescriptor(), Code.create_InvalidKeyConfig(), dafny.DafnySequence.asUnicodeString("public key must be 32 bytes"));
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> CodeString(Code c) {
    Code _source0 = c;
    if (_source0.is_InvalidKeyConfig()) {
      return dafny.DafnySequence.asUnicodeString("INVALID_KEY_CONFIG");
    } else if (_source0.is_UnsupportedSuite()) {
      return dafny.DafnySequence.asUnicodeString("UNSUPPORTED_SUITE");
    } else if (_source0.is_InvalidEncapsulatedKey()) {
      return dafny.DafnySequence.asUnicodeString("INVALID_ENCAPSULATED_KEY");
    } else if (_source0.is_HpkeSetupFailed()) {
      return dafny.DafnySequence.asUnicodeString("HPKE_SETUP_FAILED");
    } else if (_source0.is_MissingResponseNonce()) {
      return dafny.DafnySequence.asUnicodeString("MISSING_RESPONSE_NONCE");
    } else if (_source0.is_UnexpectedRedirect()) {
      return dafny.DafnySequence.asUnicodeString("UNEXPECTED_REDIRECT");
    } else if (_source0.is_InvalidResponseNonce()) {
      return dafny.DafnySequence.asUnicodeString("INVALID_RESPONSE_NONCE");
    } else if (_source0.is_DuplicateResponseNonce()) {
      return dafny.DafnySequence.asUnicodeString("DUPLICATE_RESPONSE_NONCE");
    } else if (_source0.is_KeyConfigMismatch()) {
      return dafny.DafnySequence.asUnicodeString("KEY_CONFIG_MISMATCH");
    } else if (_source0.is_FramingTruncated()) {
      return dafny.DafnySequence.asUnicodeString("FRAMING_TRUNCATED");
    } else if (_source0.is_ChunkTooLarge()) {
      return dafny.DafnySequence.asUnicodeString("CHUNK_TOO_LARGE");
    } else if (_source0.is_AeadDecryptFailed()) {
      return dafny.DafnySequence.asUnicodeString("AEAD_DECRYPT_FAILED");
    } else if (_source0.is_SequenceOverflow()) {
      return dafny.DafnySequence.asUnicodeString("SEQUENCE_OVERFLOW");
    } else if (_source0.is_InvalidToken()) {
      return dafny.DafnySequence.asUnicodeString("INVALID_TOKEN");
    } else if (_source0.is_InvalidInput()) {
      return dafny.DafnySequence.asUnicodeString("INVALID_INPUT");
    } else {
      return dafny.DafnySequence.asUnicodeString("");
    }
  }
  public static short U16(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger i)
  {
    return (short) (short) ((short)(((short) (short) ((short)(((short) java.lang.Byte.toUnsignedInt(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((i))))))) * ((short) 256)))) + ((short) java.lang.Byte.toUnsignedInt(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE))))))))));
  }
  public static int U32(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger i)
  {
    return (int) (((int) ((java.lang.Short.toUnsignedInt(__default.U16(b, i))) * (65536))) + (java.lang.Short.toUnsignedInt(__default.U16(b, (i).add(java.math.BigInteger.valueOf(2L))))));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> BE16(short v) {
    return dafny.DafnySequence.<java.lang.Byte> of(((byte) (dafny.Helpers.divideUnsignedShort(v, (short) 256))), ((byte) (dafny.Helpers.remainderUnsignedShort(v, (short) 256))));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> BE32(int v) {
    return dafny.DafnySequence.<java.lang.Byte>concatenate(__default.BE16(((short) (java.lang.Integer.divideUnsigned(v, 65536)))), __default.BE16(((short) (java.lang.Integer.remainderUnsigned(v, 65536)))));
  }
  public static boolean IsAscii(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return ((java.util.function.Function<dafny.DafnySequence<? extends dafny.CodePoint>, Boolean>)(_0_s) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_s).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _1_i = (java.math.BigInteger)_forall_var_0;
      return !(((_1_i).signum() != -1) && ((_1_i).compareTo(java.math.BigInteger.valueOf((_0_s).length())) < 0)) || ((java.math.BigInteger.valueOf(((dafny.CodePoint)((_0_s).select(dafny.Helpers.toInt((_1_i))))).value())).compareTo(java.math.BigInteger.valueOf(128L)) < 0);
    }));}).apply(s);
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Ascii(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return dafny.DafnySequence.Create(uint8._typeDescriptor(), java.math.BigInteger.valueOf((s).length()), ((java.util.function.Function<dafny.DafnySequence<? extends dafny.CodePoint>, java.util.function.Function<java.math.BigInteger, java.lang.Byte>>)(_0_s) -> {return ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return (java.math.BigInteger.valueOf(((dafny.CodePoint)((_0_s).select(dafny.Helpers.toInt((_1_i))))).value())).byteValue();
    });}).apply(s));
  }
  public static int LowerChar(int c) {
    if ((('A') <= (c)) && ((c) <= ('Z'))) {
      return (int)dafny.Helpers.toInt(((java.math.BigInteger.valueOf(c)).add(java.math.BigInteger.valueOf(32L))));
    } else {
      return c;
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> Lower(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return dafny.DafnySequence.Create(dafny.TypeDescriptor.UNICODE_CHAR, java.math.BigInteger.valueOf((s).length()), ((java.util.function.Function<dafny.DafnySequence<? extends dafny.CodePoint>, java.util.function.Function<java.math.BigInteger, dafny.CodePoint>>)(_0_s) -> {return ((java.util.function.Function<java.math.BigInteger, dafny.CodePoint>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return dafny.CodePoint.valueOf(__default.LowerChar(((dafny.CodePoint)((_0_s).select(dafny.Helpers.toInt((_1_i))))).value()));
    });}).apply(s));
  }
  public static boolean EqualFold(dafny.DafnySequence<? extends dafny.CodePoint> a, dafny.DafnySequence<? extends dafny.CodePoint> b)
  {
    return (__default.Lower(a)).equals(__default.Lower(b));
  }
  public static boolean IsSpace(int c) {
    return ((c) == (' ')) || ((c) == ('\t'));
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> TrimLeft(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    TAIL_CALL_START: while (true) {
      if (((java.math.BigInteger.valueOf((s).length())).signum() == 1) && (__default.IsSpace(((dafny.CodePoint)((s).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))).value()))) {
        dafny.DafnySequence<? extends dafny.CodePoint> _in0 = (s).drop(java.math.BigInteger.ONE);
        s = _in0;
        continue TAIL_CALL_START;
      } else {
        return s;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> TrimRight(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    TAIL_CALL_START: while (true) {
      if (((java.math.BigInteger.valueOf((s).length())).signum() == 1) && (__default.IsSpace(((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((s).length())).subtract(java.math.BigInteger.ONE)))))).value()))) {
        dafny.DafnySequence<? extends dafny.CodePoint> _in0 = (s).take((java.math.BigInteger.valueOf((s).length())).subtract(java.math.BigInteger.ONE));
        s = _in0;
        continue TAIL_CALL_START;
      } else {
        return s;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> Trim(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return __default.TrimRight(__default.TrimLeft(s));
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> Before(dafny.DafnySequence<? extends dafny.CodePoint> s, int sep)
  {
    return __default.BeforeFrom(s, sep, java.math.BigInteger.ZERO);
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> BeforeFrom(dafny.DafnySequence<? extends dafny.CodePoint> s, int sep, java.math.BigInteger i)
  {
    TAIL_CALL_START: while (true) {
      if ((java.util.Objects.equals(i, java.math.BigInteger.valueOf((s).length()))) || ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == (sep))) {
        return (s).take(i);
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _in0 = s;
        int _in1 = sep;
        java.math.BigInteger _in2 = (i).add(java.math.BigInteger.ONE);
        s = _in0;
        sep = _in1;
        i = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> MediaType(dafny.DafnySequence<? extends dafny.CodePoint> contentType) {
    return __default.Lower(__default.Trim(__default.Before(contentType, ';')));
  }
  public static boolean HasMediaType(Option<dafny.DafnySequence<? extends dafny.CodePoint>> contentType, dafny.DafnySequence<? extends dafny.CodePoint> want)
  {
    return ((contentType).is_Some()) && ((__default.MediaType((contentType).dtor_value())).equals(__default.Lower(want)));
  }
  public static Option<java.lang.Byte> HexDigitValue(int c) {
    if ((('0') <= (c)) && ((c) <= ('9'))) {
      return Option.<java.lang.Byte>create_Some(uint8._typeDescriptor(), ((java.math.BigInteger.valueOf(c)).subtract(java.math.BigInteger.valueOf('0'))).byteValue());
    } else if ((('a') <= (c)) && ((c) <= ('f'))) {
      return Option.<java.lang.Byte>create_Some(uint8._typeDescriptor(), (((java.math.BigInteger.valueOf(c)).subtract(java.math.BigInteger.valueOf('a'))).add(java.math.BigInteger.valueOf(10L))).byteValue());
    } else if ((('A') <= (c)) && ((c) <= ('F'))) {
      return Option.<java.lang.Byte>create_Some(uint8._typeDescriptor(), (((java.math.BigInteger.valueOf(c)).subtract(java.math.BigInteger.valueOf('A'))).add(java.math.BigInteger.valueOf(10L))).byteValue());
    } else {
      return Option.<java.lang.Byte>create_None(uint8._typeDescriptor());
    }
  }
  public static boolean IsHex(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return ((dafny.DafnyEuclidean.EuclideanModulus(java.math.BigInteger.valueOf((s).length()), java.math.BigInteger.valueOf(2L))).signum() == 0) && (((java.util.function.Function<dafny.DafnySequence<? extends dafny.CodePoint>, Boolean>)(_0_s) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_s).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _1_i = (java.math.BigInteger)_forall_var_0;
      return !(((_1_i).signum() != -1) && ((_1_i).compareTo(java.math.BigInteger.valueOf((_0_s).length())) < 0)) || ((__default.HexDigitValue(((dafny.CodePoint)((_0_s).select(dafny.Helpers.toInt((_1_i))))).value())).is_Some());
    }));}).apply(s));
  }
  public static Option<dafny.DafnySequence<? extends java.lang.Byte>> DecodeHex(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    if (!(__default.IsHex(s))) {
      return Option.<dafny.DafnySequence<? extends java.lang.Byte>>create_None(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()));
    } else {
      return Option.<dafny.DafnySequence<? extends java.lang.Byte>>create_Some(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), dafny.DafnySequence.Create(uint8._typeDescriptor(), dafny.DafnyEuclidean.EuclideanDivision(java.math.BigInteger.valueOf((s).length()), java.math.BigInteger.valueOf(2L)), ((java.util.function.Function<dafny.DafnySequence<? extends dafny.CodePoint>, java.util.function.Function<java.math.BigInteger, java.lang.Byte>>)(_0_s) -> {return ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_1_i_boxed0) -> {
  java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
  return (byte) (byte) ((byte)(((byte) (byte) ((byte)(((__default.HexDigitValue(((dafny.CodePoint)((_0_s).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf(2L)).multiply(_1_i)))))).value())).dtor_value()) * ((byte) 16)))) + ((__default.HexDigitValue(((dafny.CodePoint)((_0_s).select(dafny.Helpers.toInt((((java.math.BigInteger.valueOf(2L)).multiply(_1_i)).add(java.math.BigInteger.ONE)))))).value())).dtor_value())));
});}).apply(s)));
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> EncodeHex(dafny.DafnySequence<? extends java.lang.Byte> b) {
    return dafny.DafnySequence.Create(dafny.TypeDescriptor.UNICODE_CHAR, (java.math.BigInteger.valueOf(2L)).multiply(java.math.BigInteger.valueOf((b).length())), ((java.util.function.Function<dafny.DafnySequence<? extends java.lang.Byte>, java.util.function.Function<java.math.BigInteger, dafny.CodePoint>>)(_0_b) -> {return ((java.util.function.Function<java.math.BigInteger, dafny.CodePoint>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return dafny.CodePoint.valueOf((((dafny.DafnyEuclidean.EuclideanModulus(_1_i, java.math.BigInteger.valueOf(2L))).signum() == 0) ? (((dafny.CodePoint)((__default.HexDigits()).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanDivision(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((_0_b).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanDivision(_1_i, java.math.BigInteger.valueOf(2L)))))))), java.math.BigInteger.valueOf(16L))))))).value()) : (((dafny.CodePoint)((__default.HexDigits()).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanModulus(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((_0_b).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanDivision(_1_i, java.math.BigInteger.valueOf(2L)))))))), java.math.BigInteger.valueOf(16L))))))).value())));
    });}).apply(b));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> ComputeNonce(dafny.DafnySequence<? extends java.lang.Byte> nonceBase, long seqNo)
  {
    return dafny.DafnySequence.Create(uint8._typeDescriptor(), __default.NonceLength(), ((dafny.Function2<dafny.DafnySequence<? extends java.lang.Byte>, java.lang.Long, java.util.function.Function<java.math.BigInteger, java.lang.Byte>>)(_0_nonceBase, __1_seqNo0) -> {long _1_seqNo = ((long)(java.lang.Object)(__1_seqNo0));
    return ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_2_i_boxed0) -> {
      java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
      return ((byte)(java.lang.Object)(dafny.Helpers.<java.lang.Integer, java.lang.Byte>Let((_2_i).intValue(), boxed0 -> {
        int _pat_let0_0 = ((int)(java.lang.Object)(boxed0));
        return ((byte)(java.lang.Object)(dafny.Helpers.<java.lang.Integer, java.lang.Byte>Let(_pat_let0_0, boxed1 -> {
          int _3_j = ((int)(java.lang.Object)(boxed1));
          return ((java.lang.Integer.compareUnsigned(_3_j, 4) < 0) ? (((byte)(java.lang.Object)((_0_nonceBase).select(_3_j)))) : (((byte) (byte) ((byte)(((((byte)(java.lang.Object)((_0_nonceBase).select(_3_j))))) ^ ((__default.ByteAt(_1_seqNo, (int) ((11) - (_3_j))))))))));
        }
        )));
      }
      )));
    });}).apply(nonceBase, seqNo));
  }
  public static Result<dafny.DafnySequence<? extends java.lang.Byte>> NonceFor(dafny.DafnySequence<? extends java.lang.Byte> nonceBase, long seqNo)
  {
    if (!java.util.Objects.equals(java.math.BigInteger.valueOf((nonceBase).length()), __default.NonceLength())) {
      return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), Code.create_InvalidInput(), dafny.DafnySequence.asUnicodeString("nonce base must be 12 bytes"));
    } else {
      return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Ok(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), __default.ComputeNonce(nonceBase, seqNo));
    }
  }
  public static byte ByteAt(long x, int k)
  {
    TAIL_CALL_START: while (true) {
      if (((k) == 0 ? 0 : 1) == 0) {
        return ((byte) ((long) java.lang.Long.remainderUnsigned(x, (long) 256L)));
      } else {
        long _in0 = (long) java.lang.Long.divideUnsigned(x, (long) 256L);
        int _in1 = (int) ((k) - (1));
        x = _in0;
        k = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static boolean KnownKdf(short id) {
    return (((id) == ((short) 1)) || ((id) == ((short) 2))) || ((id) == ((short) 3));
  }
  public static boolean KnownAead(short id) {
    return (((id) == ((short) 1)) || ((id) == ((short) 2))) || ((id) == ((short) 3));
  }
  public static Result<dafny.DafnySequence<? extends java.lang.Byte>> ParseConfig(dafny.DafnySequence<? extends java.lang.Byte> data) {
    if ((java.math.BigInteger.valueOf((data).length())).compareTo(java.math.BigInteger.valueOf(3L)) < 0) {
      return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), Code.create_InvalidKeyConfig(), dafny.DafnySequence.asUnicodeString("invalid config"));
    } else if ((__default.U16(data, java.math.BigInteger.ONE)) != (__default.KemX25519())) {
      return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), Code.create_UnsupportedSuite(), dafny.DafnySequence.asUnicodeString("unsupported KEM"));
    } else if ((java.math.BigInteger.valueOf((data).length())).compareTo(((java.math.BigInteger.valueOf(3L)).add(__default.PublicKeyLength())).add(java.math.BigInteger.valueOf(2L))) < 0) {
      return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), Code.create_InvalidKeyConfig(), dafny.DafnySequence.asUnicodeString("invalid config"));
    } else {
      dafny.DafnySequence<? extends java.lang.Byte> _0_pk = (data).subsequence(dafny.Helpers.toInt((java.math.BigInteger.valueOf(3L))), dafny.Helpers.toInt(((java.math.BigInteger.valueOf(3L)).add(__default.PublicKeyLength()))));
      java.math.BigInteger _1_suitesLen = dafny.Helpers.unsignedToBigInteger(__default.U16(data, (java.math.BigInteger.valueOf(3L)).add(__default.PublicKeyLength())));
      java.math.BigInteger _2_start = ((java.math.BigInteger.valueOf(3L)).add(__default.PublicKeyLength())).add(java.math.BigInteger.valueOf(2L));
      if ((java.math.BigInteger.valueOf((data).length())).compareTo((_2_start).add(_1_suitesLen)) < 0) {
        return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), Code.create_InvalidKeyConfig(), dafny.DafnySequence.asUnicodeString("invalid config"));
      } else {
        Result<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>> _source0 = __default.ParseSuites((data).subsequence(dafny.Helpers.toInt((_2_start)), dafny.Helpers.toInt(((_2_start).add(_1_suitesLen)))));
        if (_source0.is_Ok()) {
          dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>> _3___mcc_h0 = ((EHBP.Result_Ok<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>>)_source0)._value;
          dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>> _4_suites = _3___mcc_h0;
          if ((java.math.BigInteger.valueOf((_4_suites).length())).signum() == 0) {
            return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), Code.create_InvalidKeyConfig(), dafny.DafnySequence.asUnicodeString("no cipher suites found in config"));
          } else if (!java.util.Objects.equals(java.math.BigInteger.valueOf((_4_suites).length()), java.math.BigInteger.ONE)) {
            return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), Code.create_UnsupportedSuite(), dafny.DafnySequence.asUnicodeString("expected exactly one cipher suite"));
          } else if (!java.util.Objects.equals(((dafny.Tuple2<java.lang.Short, java.lang.Short>)(java.lang.Object)((_4_suites).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), dafny.Tuple2.<java.lang.Short, java.lang.Short>create(__default.KdfHkdfSha256(), __default.AeadAes256Gcm()))) {
            return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), Code.create_UnsupportedSuite(), dafny.DafnySequence.asUnicodeString("unsupported cipher suite"));
          } else {
            return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Ok(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), _0_pk);
          }
        } else {
          Code _5___mcc_h1 = ((EHBP.Result_Err<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>>)_source0)._code;
          dafny.DafnySequence<? extends dafny.CodePoint> _6___mcc_h2 = ((EHBP.Result_Err<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>>)_source0)._message;
          dafny.DafnySequence<? extends dafny.CodePoint> _7_message = _6___mcc_h2;
          Code _8_code = _5___mcc_h1;
          return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), _8_code, _7_message);
        }
      }
    }
  }
  public static Result<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>> ParseSuites(dafny.DafnySequence<? extends java.lang.Byte> s) {
    return __default.ParseSuitesFrom(s, java.math.BigInteger.ZERO, dafny.DafnySequence.<dafny.Tuple2<java.lang.Short, java.lang.Short>> empty(dafny.Tuple2.<java.lang.Short, java.lang.Short>_typeDescriptor(uint16._typeDescriptor(), uint16._typeDescriptor())));
  }
  public static Result<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>> ParseSuitesFrom(dafny.DafnySequence<? extends java.lang.Byte> s, java.math.BigInteger i, dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>> acc)
  {
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((s).length()))) {
        return Result.<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>>create_Ok(dafny.DafnySequence.<dafny.Tuple2<java.lang.Short, java.lang.Short>>_typeDescriptor(dafny.Tuple2.<java.lang.Short, java.lang.Short>_typeDescriptor(uint16._typeDescriptor(), uint16._typeDescriptor())), acc);
      } else if (((java.math.BigInteger.valueOf((s).length())).subtract(i)).compareTo(java.math.BigInteger.valueOf(4L)) < 0) {
        return Result.<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>>create_Err(dafny.DafnySequence.<dafny.Tuple2<java.lang.Short, java.lang.Short>>_typeDescriptor(dafny.Tuple2.<java.lang.Short, java.lang.Short>_typeDescriptor(uint16._typeDescriptor(), uint16._typeDescriptor())), Code.create_InvalidKeyConfig(), dafny.DafnySequence.asUnicodeString("invalid config"));
      } else {
        short _0_kdf = __default.U16(s, i);
        short _1_aead = __default.U16(s, (i).add(java.math.BigInteger.valueOf(2L)));
        if (!(__default.KnownKdf(_0_kdf))) {
          return Result.<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>>create_Err(dafny.DafnySequence.<dafny.Tuple2<java.lang.Short, java.lang.Short>>_typeDescriptor(dafny.Tuple2.<java.lang.Short, java.lang.Short>_typeDescriptor(uint16._typeDescriptor(), uint16._typeDescriptor())), Code.create_UnsupportedSuite(), dafny.DafnySequence.asUnicodeString("invalid KDF"));
        } else if (!(__default.KnownAead(_1_aead))) {
          return Result.<dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>>>create_Err(dafny.DafnySequence.<dafny.Tuple2<java.lang.Short, java.lang.Short>>_typeDescriptor(dafny.Tuple2.<java.lang.Short, java.lang.Short>_typeDescriptor(uint16._typeDescriptor(), uint16._typeDescriptor())), Code.create_UnsupportedSuite(), dafny.DafnySequence.asUnicodeString("invalid AEAD"));
        } else {
          dafny.DafnySequence<? extends java.lang.Byte> _in0 = s;
          java.math.BigInteger _in1 = (i).add(java.math.BigInteger.valueOf(4L));
          dafny.DafnySequence<? extends dafny.Tuple2<java.lang.Short, java.lang.Short>> _in2 = dafny.DafnySequence.<dafny.Tuple2<java.lang.Short, java.lang.Short>>concatenate(acc, dafny.DafnySequence.<dafny.Tuple2<java.lang.Short, java.lang.Short>> of(dafny.Tuple2.<java.lang.Short, java.lang.Short>_typeDescriptor(uint16._typeDescriptor(), uint16._typeDescriptor()), dafny.Tuple2.<java.lang.Short, java.lang.Short>create(_0_kdf, _1_aead)));
          s = _in0;
          i = _in1;
          acc = _in2;
          continue TAIL_CALL_START;
        }
      }
    }
  }
  public static Result<dafny.DafnySequence<? extends java.lang.Byte>> MarshalConfig(dafny.DafnySequence<? extends java.lang.Byte> publicKey) {
    if (!java.util.Objects.equals(java.math.BigInteger.valueOf((publicKey).length()), __default.PublicKeyLength())) {
      return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Err(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), Code.create_InvalidKeyConfig(), dafny.DafnySequence.asUnicodeString("invalid public key"));
    } else {
      return Result.<dafny.DafnySequence<? extends java.lang.Byte>>create_Ok(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte> of((byte) 0), __default.BE16(__default.KemX25519())), publicKey), __default.BE16((short) 4)), __default.BE16(__default.KdfHkdfSha256())), __default.BE16(__default.AeadAes256Gcm())));
    }
  }
  public static boolean ValidToken(Token t) {
    return (java.util.Objects.equals(java.math.BigInteger.valueOf(((t).dtor_exportedSecret()).length()), __default.ExportLength())) && (java.util.Objects.equals(java.math.BigInteger.valueOf(((t).dtor_requestEnc()).length()), __default.RequestEncLength()));
  }
  public static Result<Token> ValidateTokenFields(Option<dafny.DafnySequence<? extends dafny.CodePoint>> exportedSecretHex, Option<dafny.DafnySequence<? extends dafny.CodePoint>> requestEncHex)
  {
    if (((exportedSecretHex).is_None()) || ((requestEncHex).is_None())) {
      return Result.<Token>create_Err(Token._typeDescriptor(), Code.create_InvalidToken(), dafny.DafnySequence.asUnicodeString("token field missing"));
    } else {
      dafny.Tuple2<Option<dafny.DafnySequence<? extends java.lang.Byte>>, Option<dafny.DafnySequence<? extends java.lang.Byte>>> _source0 = dafny.Tuple2.<Option<dafny.DafnySequence<? extends java.lang.Byte>>, Option<dafny.DafnySequence<? extends java.lang.Byte>>>create(__default.DecodeHex((exportedSecretHex).dtor_value()), __default.DecodeHex((requestEncHex).dtor_value()));
      Option<dafny.DafnySequence<? extends java.lang.Byte>> _0___mcc_h0 = ((Option<dafny.DafnySequence<? extends java.lang.Byte>>)(java.lang.Object)(((dafny.Tuple2<Option<dafny.DafnySequence<? extends java.lang.Byte>>, Option<dafny.DafnySequence<? extends java.lang.Byte>>>)_source0).dtor__0()));
      Option<dafny.DafnySequence<? extends java.lang.Byte>> _1___mcc_h1 = ((Option<dafny.DafnySequence<? extends java.lang.Byte>>)(java.lang.Object)(((dafny.Tuple2<Option<dafny.DafnySequence<? extends java.lang.Byte>>, Option<dafny.DafnySequence<? extends java.lang.Byte>>>)_source0).dtor__1()));
      Option<dafny.DafnySequence<? extends java.lang.Byte>> _source1 = _0___mcc_h0;
      if (_source1.is_None()) {
        return Result.<Token>create_Err(Token._typeDescriptor(), Code.create_InvalidToken(), dafny.DafnySequence.asUnicodeString("token field is not hex"));
      } else {
        dafny.DafnySequence<? extends java.lang.Byte> _2___mcc_h4 = ((EHBP.Option_Some<dafny.DafnySequence<? extends java.lang.Byte>>)_source1)._value;
        Option<dafny.DafnySequence<? extends java.lang.Byte>> _source2 = _1___mcc_h1;
        if (_source2.is_None()) {
          return Result.<Token>create_Err(Token._typeDescriptor(), Code.create_InvalidToken(), dafny.DafnySequence.asUnicodeString("token field is not hex"));
        } else {
          dafny.DafnySequence<? extends java.lang.Byte> _3___mcc_h6 = ((EHBP.Option_Some<dafny.DafnySequence<? extends java.lang.Byte>>)_source2)._value;
          dafny.DafnySequence<? extends java.lang.Byte> _4_enc = _3___mcc_h6;
          dafny.DafnySequence<? extends java.lang.Byte> _5_secret = _2___mcc_h4;
          if ((!java.util.Objects.equals(java.math.BigInteger.valueOf((_5_secret).length()), __default.ExportLength())) || (!java.util.Objects.equals(java.math.BigInteger.valueOf((_4_enc).length()), __default.RequestEncLength()))) {
            return Result.<Token>create_Err(Token._typeDescriptor(), Code.create_InvalidToken(), dafny.DafnySequence.asUnicodeString("token field has wrong length"));
          } else {
            return Result.<Token>create_Ok(Token._typeDescriptor(), Token.create(_5_secret, _4_enc));
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Frame(dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    return dafny.DafnySequence.<java.lang.Byte>concatenate(__default.BE32((ciphertext).cardinalityInt()), ciphertext);
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> HeaderValues(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, dafny.DafnySequence<? extends dafny.CodePoint> name)
  {
    return __default.HeaderValuesFrom(headers, name, java.math.BigInteger.ZERO, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> HeaderValuesFrom(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, dafny.DafnySequence<? extends dafny.CodePoint> name, java.math.BigInteger i, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> acc)
  {
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((headers).length()))) {
        return acc;
      } else {
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _in0 = headers;
        dafny.DafnySequence<? extends dafny.CodePoint> _in1 = name;
        java.math.BigInteger _in2 = (i).add(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _in3 = ((__default.EqualFold((((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>)(java.lang.Object)((headers).select(dafny.Helpers.toInt((i)))))).dtor__0(), name)) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(acc, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), (((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>)(java.lang.Object)((headers).select(dafny.Helpers.toInt((i)))))).dtor__1()))) : (acc));
        headers = _in0;
        name = _in1;
        i = _in2;
        acc = _in3;
        continue TAIL_CALL_START;
      }
    }
  }
  public static Option<dafny.DafnySequence<? extends dafny.CodePoint>> FirstHeader(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, dafny.DafnySequence<? extends dafny.CodePoint> name)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0_values = __default.HeaderValues(headers, name);
    if ((java.math.BigInteger.valueOf((_0_values).length())).signum() == 0) {
      return Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    } else {
      return Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_Some(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((_0_values).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))));
    }
  }
  public static boolean BodylessSuccess(java.math.BigInteger status) {
    return (java.util.Objects.equals(status, java.math.BigInteger.valueOf(204L))) || (java.util.Objects.equals(status, java.math.BigInteger.valueOf(205L)));
  }
  public static Disposition Classify(boolean encrypted, Head head)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0_nonces = __default.HeaderValues((head).dtor_headers(), __default.ResponseNonceHeader());
    if (!(encrypted)) {
      return Disposition.create_PassThrough();
    } else if (((head).dtor_redirected()) || (((java.math.BigInteger.valueOf(300L)).compareTo((head).dtor_status()) <= 0) && (((head).dtor_status()).compareTo(java.math.BigInteger.valueOf(400L)) < 0))) {
      return Disposition.create_Refuse(Code.create_UnexpectedRedirect(), dafny.DafnySequence.asUnicodeString("redirect in response to an encrypted request"));
    } else if ((java.math.BigInteger.valueOf((_0_nonces).length())).signum() == 0) {
      if (((head).dtor_status()).compareTo(java.math.BigInteger.valueOf(400L)) < 0) {
        return Disposition.create_Refuse(Code.create_MissingResponseNonce(), dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.asUnicodeString("missing "), __default.ResponseNonceHeader()), dafny.DafnySequence.asUnicodeString(" header")));
      } else if ((java.util.Objects.equals((head).dtor_status(), java.math.BigInteger.valueOf(422L))) && (__default.HasMediaType(__default.FirstHeader((head).dtor_headers(), dafny.DafnySequence.asUnicodeString("Content-Type")), __default.ProblemJsonMediaType()))) {
        return Disposition.create_NeedProblemBody();
      } else {
        return Disposition.create_PassThrough();
      }
    } else if ((java.math.BigInteger.valueOf((_0_nonces).length())).compareTo(java.math.BigInteger.ONE) > 0) {
      return Disposition.create_Refuse(Code.create_DuplicateResponseNonce(), dafny.DafnySequence.asUnicodeString("duplicate response nonce"));
    } else if ((((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((_0_nonces).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).equals(dafny.DafnySequence.asUnicodeString(""))) {
      return Disposition.create_Refuse(Code.create_InvalidResponseNonce(), dafny.DafnySequence.asUnicodeString("empty response nonce"));
    } else {
      Option<dafny.DafnySequence<? extends java.lang.Byte>> _source0 = __default.DecodeHex(((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((_0_nonces).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))));
      if (_source0.is_None()) {
        return Disposition.create_Refuse(Code.create_InvalidResponseNonce(), dafny.DafnySequence.asUnicodeString("response nonce is not hex"));
      } else {
        dafny.DafnySequence<? extends java.lang.Byte> _1___mcc_h0 = ((EHBP.Option_Some<dafny.DafnySequence<? extends java.lang.Byte>>)_source0)._value;
        dafny.DafnySequence<? extends java.lang.Byte> _2_nonce = _1___mcc_h0;
        if (!java.util.Objects.equals(java.math.BigInteger.valueOf((_2_nonce).length()), __default.ResponseNonceLength())) {
          return Disposition.create_Refuse(Code.create_InvalidResponseNonce(), dafny.DafnySequence.asUnicodeString("response nonce has wrong length"));
        } else if (__default.BodylessSuccess((head).dtor_status())) {
          return Disposition.create_Refuse(Code.create_FramingTruncated(), dafny.DafnySequence.asUnicodeString("status cannot carry an authenticated frame"));
        } else {
          return Disposition.create_Decrypt(_2_nonce, ((head).dtor_status()).compareTo(java.math.BigInteger.valueOf(400L)) < 0);
        }
      }
    }
  }
  public static Disposition ClassifyProblem(boolean oversized, boolean isObject, Option<dafny.DafnySequence<? extends dafny.CodePoint>> typeValue, Option<dafny.DafnySequence<? extends dafny.CodePoint>> title)
  {
    if (((oversized) || (!(isObject))) || (!java.util.Objects.equals(typeValue, Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_Some(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), __default.KeyConfigProblemType())))) {
      return Disposition.create_PassThrough();
    } else {
      return Disposition.create_Refuse(Code.create_KeyConfigMismatch(), ((((title).is_Some()) && (!((title).dtor_value()).equals(dafny.DafnySequence.asUnicodeString("")))) ? ((title).dtor_value()) : (__default.DefaultKeyConfigTitle())));
    }
  }
  public static Result<dafny.Tuple0> ClassifyDiscovery(Head head) {
    if (((head).dtor_redirected()) || (!java.util.Objects.equals((head).dtor_status(), java.math.BigInteger.valueOf(200L)))) {
      return Result.<dafny.Tuple0>create_Err(dafny.Tuple0._typeDescriptor(), Code.create_InvalidKeyConfig(), dafny.DafnySequence.asUnicodeString("discovery returned a non-200 status"));
    } else if (!(__default.HasMediaType(__default.FirstHeader((head).dtor_headers(), dafny.DafnySequence.asUnicodeString("Content-Type")), __default.KeysMediaType()))) {
      return Result.<dafny.Tuple0>create_Err(dafny.Tuple0._typeDescriptor(), Code.create_InvalidKeyConfig(), dafny.DafnySequence.asUnicodeString("discovery returned the wrong media type"));
    } else {
      return Result.<dafny.Tuple0>create_Ok(dafny.Tuple0._typeDescriptor(), dafny.Tuple0.create());
    }
  }
  public static java.math.BigInteger DefaultPort(dafny.DafnySequence<? extends dafny.CodePoint> scheme) {
    if ((__default.Lower(scheme)).equals(dafny.DafnySequence.asUnicodeString("https"))) {
      return java.math.BigInteger.valueOf(443L);
    } else {
      return java.math.BigInteger.valueOf(80L);
    }
  }
  public static Result<Origin> MakeOrigin(dafny.DafnySequence<? extends dafny.CodePoint> scheme, dafny.DafnySequence<? extends dafny.CodePoint> host, Option<java.math.BigInteger> port, boolean hasUserinfo)
  {
    dafny.DafnySequence<? extends dafny.CodePoint> _0_s = __default.Lower(scheme);
    if ((!(_0_s).equals(dafny.DafnySequence.asUnicodeString("http"))) && (!(_0_s).equals(dafny.DafnySequence.asUnicodeString("https")))) {
      return Result.<Origin>create_Err(Origin._typeDescriptor(), Code.create_InvalidInput(), dafny.DafnySequence.asUnicodeString("base URL must include an HTTP origin"));
    } else if ((host).equals(dafny.DafnySequence.asUnicodeString(""))) {
      return Result.<Origin>create_Err(Origin._typeDescriptor(), Code.create_InvalidInput(), dafny.DafnySequence.asUnicodeString("base URL must include an HTTP origin"));
    } else if (hasUserinfo) {
      return Result.<Origin>create_Err(Origin._typeDescriptor(), Code.create_InvalidInput(), dafny.DafnySequence.asUnicodeString("base URL must not include credentials"));
    } else {
      return Result.<Origin>create_Ok(Origin._typeDescriptor(), Origin.create(_0_s, __default.Lower(host), (((port).is_Some()) ? ((port).dtor_value()) : (__default.DefaultPort(_0_s)))));
    }
  }
  public static boolean SameOrigin(Origin a, Origin b)
  {
    return ((((a).dtor_scheme()).equals((b).dtor_scheme())) && (((a).dtor_host()).equals((b).dtor_host()))) && (java.util.Objects.equals((a).dtor_port(), (b).dtor_port()));
  }
  public static boolean ReservedHeader(dafny.DafnySequence<? extends dafny.CodePoint> name) {
    return ((__default.EqualFold(name, __default.EncapsulatedKeyHeader())) || (__default.EqualFold(name, __default.ResponseNonceHeader()))) || (__default.EqualFold(name, dafny.DafnySequence.asUnicodeString("Host")));
  }
  public static boolean FramingHeader(dafny.DafnySequence<? extends dafny.CodePoint> name) {
    return (__default.EqualFold(name, dafny.DafnySequence.asUnicodeString("Content-Length"))) || (__default.EqualFold(name, dafny.DafnySequence.asUnicodeString("Transfer-Encoding")));
  }
  public static Result<dafny.Tuple0> ValidateRequest(Origin origin, Result<Origin> target, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers)
  {
    if ((target).is_Err()) {
      return Result.<dafny.Tuple0>create_Err(dafny.Tuple0._typeDescriptor(), Code.create_InvalidInput(), (target).dtor_message());
    } else if (!(__default.SameOrigin(origin, (target).dtor_value()))) {
      return Result.<dafny.Tuple0>create_Err(dafny.Tuple0._typeDescriptor(), Code.create_InvalidInput(), dafny.DafnySequence.asUnicodeString("request URL must use the configured origin"));
    } else {
      return __default.ValidateHeadersFrom(headers, java.math.BigInteger.ZERO);
    }
  }
  public static Result<dafny.Tuple0> ValidateHeadersFrom(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, java.math.BigInteger i)
  {
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((headers).length()))) {
        return Result.<dafny.Tuple0>create_Ok(dafny.Tuple0._typeDescriptor(), dafny.Tuple0.create());
      } else if (__default.ReservedHeader((((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>)(java.lang.Object)((headers).select(dafny.Helpers.toInt((i)))))).dtor__0())) {
        return Result.<dafny.Tuple0>create_Err(dafny.Tuple0._typeDescriptor(), Code.create_InvalidInput(), dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.asUnicodeString("reserved request header cannot be set by callers: "), (((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>)(java.lang.Object)((headers).select(dafny.Helpers.toInt((i)))))).dtor__0()));
      } else {
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _in0 = headers;
        java.math.BigInteger _in1 = (i).add(java.math.BigInteger.ONE);
        headers = _in0;
        i = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> DropFraming(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers) {
    return __default.DropFramingFrom(headers, java.math.BigInteger.ZERO, dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> empty(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))));
  }
  public static dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> DropFramingFrom(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers, java.math.BigInteger i, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> acc)
  {
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((headers).length()))) {
        return acc;
      } else {
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _in0 = headers;
        java.math.BigInteger _in1 = (i).add(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _in2 = ((__default.FramingHeader((((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>)(java.lang.Object)((headers).select(dafny.Helpers.toInt((i)))))).dtor__0())) ? (acc) : (dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>>concatenate(acc, dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> of(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), ((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>)(java.lang.Object)((headers).select(dafny.Helpers.toInt((i)))))))));
        headers = _in0;
        i = _in1;
        acc = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> OriginUrl(Origin origin) {
    dafny.DafnySequence<? extends dafny.CodePoint> _0_portPart = ((java.util.Objects.equals((origin).dtor_port(), __default.DefaultPort((origin).dtor_scheme()))) ? (dafny.DafnySequence.asUnicodeString("")) : (dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.asUnicodeString(":"), __default.IntToString((origin).dtor_port()))));
    return dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.<dafny.CodePoint>concatenate((origin).dtor_scheme(), dafny.DafnySequence.asUnicodeString("://")), (origin).dtor_host()), _0_portPart);
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> IntToString(java.math.BigInteger n) {
    if ((n).signum() == -1) {
      return dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.asUnicodeString("-"), __default.IntToString((java.math.BigInteger.ZERO).subtract(n)));
    } else if ((n).compareTo(java.math.BigInteger.valueOf(10L)) < 0) {
      return dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt(((java.math.BigInteger.valueOf('0')).add(n)))));
    } else {
      return dafny.DafnySequence.<dafny.CodePoint>concatenate(__default.IntToString(dafny.DafnyEuclidean.EuclideanDivision(n, java.math.BigInteger.valueOf(10L))), dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt(((java.math.BigInteger.valueOf('0')).add(dafny.DafnyEuclidean.EuclideanModulus(n, java.math.BigInteger.valueOf(10L))))))));
    }
  }
  public static dafny.DafnySequence<? extends Code> Codes()
  {
    return dafny.DafnySequence.<Code> of(Code._typeDescriptor(), Code.create_InvalidKeyConfig(), Code.create_UnsupportedSuite(), Code.create_InvalidEncapsulatedKey(), Code.create_HpkeSetupFailed(), Code.create_MissingResponseNonce(), Code.create_UnexpectedRedirect(), Code.create_InvalidResponseNonce(), Code.create_DuplicateResponseNonce(), Code.create_KeyConfigMismatch(), Code.create_FramingTruncated(), Code.create_ChunkTooLarge(), Code.create_AeadDecryptFailed(), Code.create_SequenceOverflow(), Code.create_InvalidToken(), Code.create_InvalidInput());
  }
  public static short KemX25519()
  {
    return (short) 32;
  }
  public static short KdfHkdfSha256()
  {
    return (short) 1;
  }
  public static short AeadAes256Gcm()
  {
    return (short) 2;
  }
  public static int MaxChunkBytes()
  {
    return (int) (((int) ((64) * (1024))) * (1024));
  }
  public static int RequestFrameBytes()
  {
    return 65536;
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> HexDigits()
  {
    return dafny.DafnySequence.asUnicodeString("0123456789abcdef");
  }
  public static java.math.BigInteger NonceLength()
  {
    return java.math.BigInteger.valueOf(12L);
  }
  public static java.math.BigInteger PublicKeyLength()
  {
    return java.math.BigInteger.valueOf(32L);
  }
  public static java.math.BigInteger ExportLength()
  {
    return java.math.BigInteger.valueOf(32L);
  }
  public static java.math.BigInteger RequestEncLength()
  {
    return java.math.BigInteger.valueOf(32L);
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> ResponseNonceHeader()
  {
    return dafny.DafnySequence.asUnicodeString("Ehbp-Response-Nonce");
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> ProblemJsonMediaType()
  {
    return dafny.DafnySequence.asUnicodeString("application/problem+json");
  }
  public static java.math.BigInteger ResponseNonceLength()
  {
    return java.math.BigInteger.valueOf(32L);
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> KeyConfigProblemType()
  {
    return dafny.DafnySequence.asUnicodeString("urn:ietf:params:ehbp:error:key-config");
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> DefaultKeyConfigTitle()
  {
    return dafny.DafnySequence.asUnicodeString("key configuration mismatch");
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> KeysMediaType()
  {
    return dafny.DafnySequence.asUnicodeString("application/ohttp-keys");
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> EncapsulatedKeyHeader()
  {
    return dafny.DafnySequence.asUnicodeString("Ehbp-Encapsulated-Key");
  }
  public static java.math.BigInteger KeyLength()
  {
    return java.math.BigInteger.valueOf(32L);
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> HpkeRequestInfo()
  {
    return dafny.DafnySequence.asUnicodeString("ehbp request");
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> ExportLabel()
  {
    return dafny.DafnySequence.asUnicodeString("ehbp response");
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> ResponseKeyLabel()
  {
    return dafny.DafnySequence.asUnicodeString("key");
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> ResponseNonceLabel()
  {
    return dafny.DafnySequence.asUnicodeString("nonce");
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> KeysPath()
  {
    return dafny.DafnySequence.asUnicodeString("/.well-known/hpke-keys");
  }
  public static java.math.BigInteger MaxProblemBytes()
  {
    return (java.math.BigInteger.valueOf(64L)).multiply(java.math.BigInteger.valueOf(1024L));
  }
  public static java.math.BigInteger MaxKeyConfigBytes()
  {
    return (java.math.BigInteger.valueOf(37L)).add(java.math.BigInteger.valueOf(65535L));
  }
  public static java.math.BigInteger MaxEmptyReads()
  {
    return java.math.BigInteger.valueOf(100L);
  }
  public static java.math.BigInteger AeadTagLength()
  {
    return java.math.BigInteger.valueOf(16L);
  }
  public static java.math.BigInteger HashLength()
  {
    return java.math.BigInteger.valueOf(32L);
  }
  @Override
  public java.lang.String toString() {
    return "EHBP._default";
  }
}
