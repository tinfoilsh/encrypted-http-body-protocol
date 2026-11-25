// Class __default
// Dafny class __default compiled into Java
package EHBPEvents;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static boolean Terminal(Action a) {
    return (((((a).is_Fail()) || ((a).is_Finished())) || ((a).is_Passthrough())) || ((a).is_Discovered())) || ((a).is_Close());
  }
  public static boolean Ends(dafny.DafnySequence<? extends Action> acts) {
    return ((java.util.function.Function<dafny.DafnySequence<? extends Action>, Boolean>)(_0_acts) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_acts).length())), false, ((_exists_var_0_boxed0) -> {
      java.math.BigInteger _exists_var_0 = ((java.math.BigInteger)(java.lang.Object)(_exists_var_0_boxed0));
      java.math.BigInteger _1_i = (java.math.BigInteger)_exists_var_0;
      return (((_1_i).signum() != -1) && ((_1_i).compareTo(java.math.BigInteger.valueOf((_0_acts).length())) < 0)) && (__default.Terminal(((Action)(java.lang.Object)((_0_acts).select(dafny.Helpers.toInt((_1_i)))))));
    }));}).apply(acts);
  }
  public static boolean NoClear(dafny.DafnySequence<? extends Action> acts) {
    return ((java.util.function.Function<dafny.DafnySequence<? extends Action>, Boolean>)(_0_acts) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_acts).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _1_i = (java.math.BigInteger)_forall_var_0;
      return !(((_1_i).signum() != -1) && ((_1_i).compareTo(java.math.BigInteger.valueOf((_0_acts).length())) < 0)) || (!((((Action)(java.lang.Object)((_0_acts).select(dafny.Helpers.toInt((_1_i)))))).is_ClearToken()));
    }));}).apply(acts);
  }
  public static boolean ClearsOnce(dafny.DafnySequence<? extends Action> acts, long g)
  {
    return ((dafny.Function2<dafny.DafnySequence<? extends Action>, java.lang.Long, Boolean>)(_0_acts, __1_g0) -> {long _1_g = ((long)(java.lang.Object)(__1_g0));
    return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_acts).length())), false, ((_exists_var_0_boxed0) -> {
      java.math.BigInteger _exists_var_0 = ((java.math.BigInteger)(java.lang.Object)(_exists_var_0_boxed0));
      java.math.BigInteger _2_i = (java.math.BigInteger)_exists_var_0;
      return ((((_2_i).signum() != -1) && ((_2_i).compareTo(java.math.BigInteger.valueOf((_0_acts).length())) < 0)) && (java.util.Objects.equals(((Action)(java.lang.Object)((_0_acts).select(dafny.Helpers.toInt((_2_i))))), Action.create_ClearToken(_1_g)))) && (((dafny.Function2<dafny.DafnySequence<? extends Action>, java.math.BigInteger, Boolean>)(_3_acts, _4_i) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_3_acts).length())), true, ((_forall_var_0_boxed0) -> {
        java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
        java.math.BigInteger _5_j = (java.math.BigInteger)_forall_var_0;
        return !((((_5_j).signum() != -1) && ((_5_j).compareTo(java.math.BigInteger.valueOf((_3_acts).length())) < 0)) && (!java.util.Objects.equals(_5_j, _4_i))) || (!((((Action)(java.lang.Object)((_3_acts).select(dafny.Helpers.toInt((_5_j)))))).is_ClearToken()));
      }));}).apply(_0_acts, _2_i));
    }));}).apply(acts, g);
  }
  public static boolean NoEmit(dafny.DafnySequence<? extends Action> acts) {
    return ((java.util.function.Function<dafny.DafnySequence<? extends Action>, Boolean>)(_0_acts) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_acts).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _1_i = (java.math.BigInteger)_forall_var_0;
      return !(((_1_i).signum() != -1) && ((_1_i).compareTo(java.math.BigInteger.valueOf((_0_acts).length())) < 0)) || (!((((Action)(java.lang.Object)((_0_acts).select(dafny.Helpers.toInt((_1_i)))))).is_EmitPlaintext()));
    }));}).apply(acts);
  }
  public static Performed Perform(Performer p, Action a)
  {
    Performed r = Performed.Default();
    if(true) {
      Action _source0 = a;
      if (_source0.is_BeginSession()) {
        long _0_generation;
        long _out0;
        _out0 = (p).BeginSession();
        _0_generation = _out0;
        r = Performed.create_Got(Event.create_SessionBegun(_0_generation));
        return r;
      } else if (_source0.is_PublishToken()) {
        long _1___mcc_h0 = ((EHBPEvents.Action_PublishToken)_source0)._generation;
        dafny.DafnySequence<? extends java.lang.Byte> _2___mcc_h1 = ((EHBPEvents.Action_PublishToken)_source0)._exportedSecret;
        dafny.DafnySequence<? extends java.lang.Byte> _3___mcc_h2 = ((EHBPEvents.Action_PublishToken)_source0)._requestEnc;
        dafny.DafnySequence<? extends java.lang.Byte> _4_requestEnc = _3___mcc_h2;
        dafny.DafnySequence<? extends java.lang.Byte> _5_exportedSecret = _2___mcc_h1;
        long _6_generation = _1___mcc_h0;
        (p).PublishToken(_6_generation, _5_exportedSecret, _4_requestEnc);
        r = Performed.create_Quiet();
        return r;
      } else if (_source0.is_ClearToken()) {
        long _7___mcc_h3 = ((EHBPEvents.Action_ClearToken)_source0)._generation;
        long _8_generation = _7___mcc_h3;
        (p).ClearToken(_8_generation);
        r = Performed.create_Quiet();
        return r;
      } else if (_source0.is_RandomBytes()) {
        java.math.BigInteger _9___mcc_h4 = ((EHBPEvents.Action_RandomBytes)_source0)._length;
        java.math.BigInteger _10_length = _9___mcc_h4;
        dafny.DafnySequence<? extends java.lang.Byte> _11_data;
        dafny.DafnySequence<? extends java.lang.Byte> _out1;
        _out1 = (p).RandomBytes(_10_length);
        _11_data = _out1;
        r = Performed.create_Got(Event.create_RandomResult(_11_data));
        return r;
      } else if (_source0.is_X25519()) {
        dafny.DafnySequence<? extends java.lang.Byte> _12___mcc_h5 = ((EHBPEvents.Action_X25519)_source0)._scalar;
        dafny.DafnySequence<? extends java.lang.Byte> _13___mcc_h6 = ((EHBPEvents.Action_X25519)_source0)._point;
        dafny.DafnySequence<? extends java.lang.Byte> _14_point = _13___mcc_h6;
        dafny.DafnySequence<? extends java.lang.Byte> _15_scalar = _12___mcc_h5;
        dafny.DafnySequence<? extends java.lang.Byte> _16_shared;
        dafny.DafnySequence<? extends java.lang.Byte> _out2;
        _out2 = (p).X25519(_15_scalar, _14_point);
        _16_shared = _out2;
        r = Performed.create_Got(Event.create_X25519Result(_16_shared));
        return r;
      } else if (_source0.is_HmacSha256()) {
        dafny.DafnySequence<? extends java.lang.Byte> _17___mcc_h7 = ((EHBPEvents.Action_HmacSha256)_source0)._key;
        dafny.DafnySequence<? extends java.lang.Byte> _18___mcc_h8 = ((EHBPEvents.Action_HmacSha256)_source0)._data;
        dafny.DafnySequence<? extends java.lang.Byte> _19_data = _18___mcc_h8;
        dafny.DafnySequence<? extends java.lang.Byte> _20_key = _17___mcc_h7;
        dafny.DafnySequence<? extends java.lang.Byte> _21_mac;
        dafny.DafnySequence<? extends java.lang.Byte> _out3;
        _out3 = (p).HmacSha256(_20_key, _19_data);
        _21_mac = _out3;
        r = Performed.create_Got(Event.create_HmacResult(_21_mac));
        return r;
      } else if (_source0.is_AeadSeal()) {
        dafny.DafnySequence<? extends java.lang.Byte> _22___mcc_h9 = ((EHBPEvents.Action_AeadSeal)_source0)._key;
        dafny.DafnySequence<? extends java.lang.Byte> _23___mcc_h10 = ((EHBPEvents.Action_AeadSeal)_source0)._nonce;
        dafny.DafnySequence<? extends java.lang.Byte> _24___mcc_h11 = ((EHBPEvents.Action_AeadSeal)_source0)._plaintext;
        dafny.DafnySequence<? extends java.lang.Byte> _25_plaintext = _24___mcc_h11;
        dafny.DafnySequence<? extends java.lang.Byte> _26_nonce = _23___mcc_h10;
        dafny.DafnySequence<? extends java.lang.Byte> _27_key = _22___mcc_h9;
        dafny.DafnySequence<? extends java.lang.Byte> _28_ciphertext;
        dafny.DafnySequence<? extends java.lang.Byte> _out4;
        _out4 = (p).AeadSeal(_27_key, _26_nonce, _25_plaintext);
        _28_ciphertext = _out4;
        r = Performed.create_Got(Event.create_AeadSealResult(_28_ciphertext));
        return r;
      } else if (_source0.is_AeadOpen()) {
        dafny.DafnySequence<? extends java.lang.Byte> _29___mcc_h12 = ((EHBPEvents.Action_AeadOpen)_source0)._key;
        dafny.DafnySequence<? extends java.lang.Byte> _30___mcc_h13 = ((EHBPEvents.Action_AeadOpen)_source0)._nonce;
        dafny.DafnySequence<? extends java.lang.Byte> _31___mcc_h14 = ((EHBPEvents.Action_AeadOpen)_source0)._ciphertext;
        dafny.DafnySequence<? extends java.lang.Byte> _32_ciphertext = _31___mcc_h14;
        dafny.DafnySequence<? extends java.lang.Byte> _33_nonce = _30___mcc_h13;
        dafny.DafnySequence<? extends java.lang.Byte> _34_key = _29___mcc_h12;
        boolean _35_ok;
        dafny.DafnySequence<? extends java.lang.Byte> _36_plaintext;
        boolean _out5;
        dafny.DafnySequence<? extends java.lang.Byte> _out6;
        dafny.Tuple2<Boolean, dafny.DafnySequence<? extends java.lang.Byte>> _outcollector0 = (p).AeadOpen(_34_key, _33_nonce, _32_ciphertext);
        _out5 = (boolean) (Object) _outcollector0.dtor__0();
        _out6 = (dafny.DafnySequence<? extends java.lang.Byte>) (Object) _outcollector0.dtor__1();
        _35_ok = _out5;
        _36_plaintext = _out6;
        r = Performed.create_Got(Event.create_AeadOpenResult(_35_ok, _36_plaintext));
        return r;
      } else if (_source0.is_Send()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _37___mcc_h15 = ((EHBPEvents.Action_Send)_source0)._verb;
        dafny.DafnySequence<? extends dafny.CodePoint> _38___mcc_h16 = ((EHBPEvents.Action_Send)_source0)._url;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _39___mcc_h17 = ((EHBPEvents.Action_Send)_source0)._headers;
        boolean _40___mcc_h18 = ((EHBPEvents.Action_Send)_source0)._hasBody;
        boolean _41_hasBody = _40___mcc_h18;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _42_headers = _39___mcc_h17;
        dafny.DafnySequence<? extends dafny.CodePoint> _43_url = _38___mcc_h16;
        dafny.DafnySequence<? extends dafny.CodePoint> _44_verb = _37___mcc_h15;
        boolean _45_ok;
        java.math.BigInteger _46_status = java.math.BigInteger.ZERO;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _47_head;
        boolean _48_redirected;
        boolean _out7;
        java.math.BigInteger _out8 = java.math.BigInteger.ZERO;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _out9;
        boolean _out10;
        dafny.Tuple4<Boolean, java.math.BigInteger, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>>, Boolean> _outcollector1 = (p).Send(_44_verb, _43_url, _42_headers, _41_hasBody);
        _out7 = (boolean) (Object) _outcollector1.dtor__0();
        _out8 = (java.math.BigInteger) (Object) _outcollector1.dtor__1();
        _out9 = (dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>>) (Object) _outcollector1.dtor__2();
        _out10 = (boolean) (Object) _outcollector1.dtor__3();
        _45_ok = _out7;
        _46_status = _out8;
        _47_head = _out9;
        _48_redirected = _out10;
        r = Performed.create_Got(((_45_ok) ? (Event.create_ResponseHead(_46_status, _47_head, _48_redirected)) : (Event.create_StreamFailed(Stream.create_ResponseBody()))));
        return r;
      } else if (_source0.is_Write()) {
        dafny.DafnySequence<? extends java.lang.Byte> _49___mcc_h19 = ((EHBPEvents.Action_Write)_source0)._data;
        BodyEnd _50___mcc_h20 = ((EHBPEvents.Action_Write)_source0)._end;
        BodyEnd _51_end = _50___mcc_h20;
        dafny.DafnySequence<? extends java.lang.Byte> _52_data = _49___mcc_h19;
        boolean _53_ok;
        boolean _out11;
        _out11 = (p).Write(_52_data, _51_end);
        _53_ok = _out11;
        if (_53_ok) {
          r = Performed.create_Quiet();
        } else {
          r = Performed.create_Stop();
        }
        return r;
      } else if (_source0.is_Read()) {
        Stream _54___mcc_h21 = ((EHBPEvents.Action_Read)_source0)._stream;
        Stream _55_stream = _54___mcc_h21;
        boolean _56_ok;
        dafny.DafnySequence<? extends java.lang.Byte> _57_data;
        boolean _58_eof;
        boolean _out12;
        dafny.DafnySequence<? extends java.lang.Byte> _out13;
        boolean _out14;
        dafny.Tuple3<Boolean, dafny.DafnySequence<? extends java.lang.Byte>, Boolean> _outcollector2 = (p).Read(_55_stream);
        _out12 = (boolean) (Object) _outcollector2.dtor__0();
        _out13 = (dafny.DafnySequence<? extends java.lang.Byte>) (Object) _outcollector2.dtor__1();
        _out14 = (boolean) (Object) _outcollector2.dtor__2();
        _56_ok = _out12;
        _57_data = _out13;
        _58_eof = _out14;
        r = Performed.create_Got(((_56_ok) ? (Event.create_Chunk(_55_stream, _57_data, _58_eof)) : (Event.create_StreamFailed(_55_stream))));
        return r;
      } else if (_source0.is_Close()) {
        Stream _59___mcc_h22 = ((EHBPEvents.Action_Close)_source0)._stream;
        Stream _60_stream = _59___mcc_h22;
        (p).Close(_60_stream);
        r = Performed.create_Quiet();
        return r;
      } else if (_source0.is_EmitPlaintext()) {
        dafny.DafnySequence<? extends java.lang.Byte> _61___mcc_h23 = ((EHBPEvents.Action_EmitPlaintext)_source0)._data;
        dafny.DafnySequence<? extends java.lang.Byte> _62_data = _61___mcc_h23;
        (p).EmitPlaintext(_62_data);
        r = Performed.create_Quiet();
        return r;
      } else if (_source0.is_Passthrough()) {
        java.math.BigInteger _63___mcc_h24 = ((EHBPEvents.Action_Passthrough)_source0)._status;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _64___mcc_h25 = ((EHBPEvents.Action_Passthrough)_source0)._headers;
        dafny.DafnySequence<? extends java.lang.Byte> _65___mcc_h26 = ((EHBPEvents.Action_Passthrough)_source0)._prefix;
        r = Performed.create_Quiet();
        return r;
      } else if (_source0.is_Done()) {
        java.math.BigInteger _66___mcc_h27 = ((EHBPEvents.Action_Done)_source0)._status;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _67___mcc_h28 = ((EHBPEvents.Action_Done)_source0)._headers;
        r = Performed.create_Quiet();
        return r;
      } else if (_source0.is_Finished()) {
        r = Performed.create_Quiet();
        return r;
      } else if (_source0.is_Discovered()) {
        dafny.DafnySequence<? extends java.lang.Byte> _68___mcc_h29 = ((EHBPEvents.Action_Discovered)_source0)._publicKey;
        r = Performed.create_Quiet();
        return r;
      } else {
        EHBP.Code _69___mcc_h30 = ((EHBPEvents.Action_Fail)_source0)._code;
        dafny.DafnySequence<? extends dafny.CodePoint> _70___mcc_h31 = ((EHBPEvents.Action_Fail)_source0)._message;
        r = Performed.create_Quiet();
        return r;
      }
    }
    return r;
  }
  public static Job Extract(dafny.DafnySequence<? extends java.lang.Byte> salt, dafny.DafnySequence<? extends java.lang.Byte> ikm)
  {
    return Job.create_JExtract(salt, ikm);
  }
  public static Job Expand(dafny.DafnySequence<? extends java.lang.Byte> prk, dafny.DafnySequence<? extends java.lang.Byte> info, java.math.BigInteger length)
  {
    return Job.create_JExpand(prk, info, length, dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), (byte) 1);
  }
  public static Action JobAction(Job j) {
    Job _source0 = j;
    if (_source0.is_JExtract()) {
      dafny.DafnySequence<? extends java.lang.Byte> _0___mcc_h0 = ((EHBPEvents.Job_JExtract)_source0)._salt;
      dafny.DafnySequence<? extends java.lang.Byte> _1___mcc_h1 = ((EHBPEvents.Job_JExtract)_source0)._ikm;
      dafny.DafnySequence<? extends java.lang.Byte> _2_ikm = _1___mcc_h1;
      dafny.DafnySequence<? extends java.lang.Byte> _3_salt = _0___mcc_h0;
      return Action.create_HmacSha256(_3_salt, _2_ikm);
    } else {
      dafny.DafnySequence<? extends java.lang.Byte> _4___mcc_h2 = ((EHBPEvents.Job_JExpand)_source0)._prk;
      dafny.DafnySequence<? extends java.lang.Byte> _5___mcc_h3 = ((EHBPEvents.Job_JExpand)_source0)._info;
      java.math.BigInteger _6___mcc_h4 = ((EHBPEvents.Job_JExpand)_source0)._length;
      dafny.DafnySequence<? extends java.lang.Byte> _7___mcc_h5 = ((EHBPEvents.Job_JExpand)_source0)._acc;
      dafny.DafnySequence<? extends java.lang.Byte> _8___mcc_h6 = ((EHBPEvents.Job_JExpand)_source0)._prev;
      byte _9___mcc_h7 = ((EHBPEvents.Job_JExpand)_source0)._i;
      byte _10_i = _9___mcc_h7;
      dafny.DafnySequence<? extends java.lang.Byte> _11_prev = _8___mcc_h6;
      dafny.DafnySequence<? extends java.lang.Byte> _12_info = _5___mcc_h3;
      dafny.DafnySequence<? extends java.lang.Byte> _13_prk = _4___mcc_h2;
      return Action.create_HmacSha256(_13_prk, dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(_11_prev, _12_info), dafny.DafnySequence.<java.lang.Byte> of(_10_i)));
    }
  }
  public static JobOut JobStep(Job j, Event e)
  {
    if (!((e).is_HmacResult())) {
      return JobOut.create_JobFailed(EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("unexpected event"));
    } else if (!java.util.Objects.equals(java.math.BigInteger.valueOf(((e).dtor_mac()).length()), EHBP.__default.HashLength())) {
      return JobOut.create_JobFailed(EHBP.Code.create_HpkeSetupFailed(), dafny.DafnySequence.asUnicodeString("HMAC returned the wrong length"));
    } else {
      Job _source0 = j;
      if (_source0.is_JExtract()) {
        dafny.DafnySequence<? extends java.lang.Byte> _0___mcc_h0 = ((EHBPEvents.Job_JExtract)_source0)._salt;
        dafny.DafnySequence<? extends java.lang.Byte> _1___mcc_h1 = ((EHBPEvents.Job_JExtract)_source0)._ikm;
        return JobOut.create_Output((e).dtor_mac());
      } else {
        dafny.DafnySequence<? extends java.lang.Byte> _2___mcc_h2 = ((EHBPEvents.Job_JExpand)_source0)._prk;
        dafny.DafnySequence<? extends java.lang.Byte> _3___mcc_h3 = ((EHBPEvents.Job_JExpand)_source0)._info;
        java.math.BigInteger _4___mcc_h4 = ((EHBPEvents.Job_JExpand)_source0)._length;
        dafny.DafnySequence<? extends java.lang.Byte> _5___mcc_h5 = ((EHBPEvents.Job_JExpand)_source0)._acc;
        dafny.DafnySequence<? extends java.lang.Byte> _6___mcc_h6 = ((EHBPEvents.Job_JExpand)_source0)._prev;
        byte _7___mcc_h7 = ((EHBPEvents.Job_JExpand)_source0)._i;
        byte _8_i = _7___mcc_h7;
        dafny.DafnySequence<? extends java.lang.Byte> _9_acc = _5___mcc_h5;
        java.math.BigInteger _10_length = _4___mcc_h4;
        dafny.DafnySequence<? extends java.lang.Byte> _11_info = _3___mcc_h3;
        dafny.DafnySequence<? extends java.lang.Byte> _12_prk = _2___mcc_h2;
        dafny.DafnySequence<? extends java.lang.Byte> _13_grown = dafny.DafnySequence.<java.lang.Byte>concatenate(_9_acc, (e).dtor_mac());
        if ((java.math.BigInteger.valueOf((_13_grown).length())).compareTo(_10_length) >= 0) {
          return JobOut.create_Output((_13_grown).take(_10_length));
        } else if ((_8_i) == ((byte) 255)) {
          return JobOut.create_JobFailed(EHBP.Code.create_HpkeSetupFailed(), dafny.DafnySequence.asUnicodeString("HKDF expand length too large"));
        } else {
          Job _14_next = Job.create_JExpand(_12_prk, _11_info, _10_length, _13_grown, (e).dtor_mac(), (byte) (byte) ((byte)((_8_i) + ((byte) 1))));
          return JobOut.create_Pending(_14_next, __default.JobAction(_14_next));
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Repeat(java.math.BigInteger n, byte v)
  {
    return dafny.DafnySequence.Create(EHBP.uint8._typeDescriptor(), n, ((java.util.function.Function<java.lang.Byte, java.util.function.Function<java.math.BigInteger, java.lang.Byte>>)(__0_v0) -> {byte _0_v = ((byte)(java.lang.Object)(__0_v0));
    return ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return _0_v;
    });}).apply(v));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Iota(java.math.BigInteger n) {
    return dafny.DafnySequence.Create(EHBP.uint8._typeDescriptor(), n, ((java.util.function.Function<java.math.BigInteger, java.util.function.Function<java.math.BigInteger, java.lang.Byte>>)(_0_n) -> {return ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return (_1_i).byteValue();
    });}).apply(n));
  }
  public static Job LabeledExtract(dafny.DafnySequence<? extends java.lang.Byte> suite, dafny.DafnySequence<? extends java.lang.Byte> salt, dafny.DafnySequence<? extends dafny.CodePoint> tag, dafny.DafnySequence<? extends java.lang.Byte> ikm)
  {
    return __default.Extract(salt, dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(__default.HpkeVersion(), suite), EHBP.__default.Ascii(tag)), ikm));
  }
  public static Job LabeledExpand(dafny.DafnySequence<? extends java.lang.Byte> suite, dafny.DafnySequence<? extends java.lang.Byte> prk, dafny.DafnySequence<? extends dafny.CodePoint> tag, dafny.DafnySequence<? extends java.lang.Byte> info, java.math.BigInteger length)
  {
    return __default.Expand(prk, dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(EHBP.__default.BE16((length).shortValue()), __default.HpkeVersion()), suite), EHBP.__default.Ascii(tag)), info), length);
  }
  public static HpkeOut SenderStart(dafny.DafnySequence<? extends java.lang.Byte> pkR, dafny.DafnySequence<? extends java.lang.Byte> info)
  {
    return HpkeOut.create_HContinue(Hpke.create_HRandom(pkR, info), Action.create_RandomBytes(java.math.BigInteger.valueOf(32L)));
  }
  public static HpkeOut RecipientStart(dafny.DafnySequence<? extends java.lang.Byte> skR, dafny.DafnySequence<? extends java.lang.Byte> pkR, dafny.DafnySequence<? extends java.lang.Byte> enc, dafny.DafnySequence<? extends java.lang.Byte> info)
  {
    return HpkeOut.create_HContinue(Hpke.create_HDh(enc, pkR, info), Action.create_X25519(skR, enc));
  }
  public static HpkeOut Schedule(Hpke h, Job job)
  {
    Job _pat_let_tv0 = job;
    return HpkeOut.create_HContinue(((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(h, boxed2 -> {
  Hpke _pat_let1_0 = ((Hpke)(java.lang.Object)(boxed2));
  return ((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(_pat_let1_0, boxed3 -> {
    Hpke _0_dt__update__tmp_h0 = ((Hpke)(java.lang.Object)(boxed3));
    return ((Hpke)(java.lang.Object)(dafny.Helpers.<Job, Hpke>Let(_pat_let_tv0, boxed4 -> {
      Job _pat_let2_0 = ((Job)(java.lang.Object)(boxed4));
      return ((Hpke)(java.lang.Object)(dafny.Helpers.<Job, Hpke>Let(_pat_let2_0, boxed5 -> {
        Job _1_dt__update_hjob_h0 = ((Job)(java.lang.Object)(boxed5));
        return Hpke.create_HSchedule((_0_dt__update__tmp_h0).dtor_stage(), _1_dt__update_hjob_h0, (_0_dt__update__tmp_h0).dtor_enc(), (_0_dt__update__tmp_h0).dtor_pkR(), (_0_dt__update__tmp_h0).dtor_info(), (_0_dt__update__tmp_h0).dtor_shared(), (_0_dt__update__tmp_h0).dtor_pskIdHash(), (_0_dt__update__tmp_h0).dtor_infoHash(), (_0_dt__update__tmp_h0).dtor_secret(), (_0_dt__update__tmp_h0).dtor_key(), (_0_dt__update__tmp_h0).dtor_baseNonce());
      }
      )));
    }
    )));
  }
  )));
}
))), __default.JobAction(job));
  }
  public static HpkeOut HpkeStep(Hpke h, Event e)
  {
    Hpke _source0 = h;
    if (_source0.is_HRandom()) {
      dafny.DafnySequence<? extends java.lang.Byte> _0___mcc_h0 = ((EHBPEvents.Hpke_HRandom)_source0)._pkR;
      dafny.DafnySequence<? extends java.lang.Byte> _1___mcc_h1 = ((EHBPEvents.Hpke_HRandom)_source0)._info;
      dafny.DafnySequence<? extends java.lang.Byte> _2_info = _1___mcc_h1;
      dafny.DafnySequence<? extends java.lang.Byte> _3_pkR = _0___mcc_h0;
      if (!((e).is_RandomResult())) {
        return HpkeOut.create_HFailed(EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("unexpected event"));
      } else if (!java.util.Objects.equals(java.math.BigInteger.valueOf(((e).dtor_data()).length()), java.math.BigInteger.valueOf(32L))) {
        return HpkeOut.create_HFailed(EHBP.Code.create_HpkeSetupFailed(), dafny.DafnySequence.asUnicodeString("random bytes have the wrong length"));
      } else {
        return HpkeOut.create_HContinue(Hpke.create_HEnc((e).dtor_data(), _3_pkR, _2_info), Action.create_X25519((e).dtor_data(), __default.BasePoint()));
      }
    } else if (_source0.is_HEnc()) {
      dafny.DafnySequence<? extends java.lang.Byte> _4___mcc_h2 = ((EHBPEvents.Hpke_HEnc)_source0)._skE;
      dafny.DafnySequence<? extends java.lang.Byte> _5___mcc_h3 = ((EHBPEvents.Hpke_HEnc)_source0)._pkR;
      dafny.DafnySequence<? extends java.lang.Byte> _6___mcc_h4 = ((EHBPEvents.Hpke_HEnc)_source0)._info;
      dafny.DafnySequence<? extends java.lang.Byte> _7_info = _6___mcc_h4;
      dafny.DafnySequence<? extends java.lang.Byte> _8_pkR = _5___mcc_h3;
      dafny.DafnySequence<? extends java.lang.Byte> _9_skE = _4___mcc_h2;
      if (!((e).is_X25519Result())) {
        return HpkeOut.create_HFailed(EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("unexpected event"));
      } else if (!java.util.Objects.equals(java.math.BigInteger.valueOf(((e).dtor_point()).length()), java.math.BigInteger.valueOf(32L))) {
        return HpkeOut.create_HFailed(EHBP.Code.create_HpkeSetupFailed(), dafny.DafnySequence.asUnicodeString("X25519 failed"));
      } else {
        return HpkeOut.create_HContinue(Hpke.create_HDh((e).dtor_point(), _8_pkR, _7_info), Action.create_X25519(_9_skE, _8_pkR));
      }
    } else if (_source0.is_HDh()) {
      dafny.DafnySequence<? extends java.lang.Byte> _10___mcc_h5 = ((EHBPEvents.Hpke_HDh)_source0)._enc;
      dafny.DafnySequence<? extends java.lang.Byte> _11___mcc_h6 = ((EHBPEvents.Hpke_HDh)_source0)._pkR;
      dafny.DafnySequence<? extends java.lang.Byte> _12___mcc_h7 = ((EHBPEvents.Hpke_HDh)_source0)._info;
      dafny.DafnySequence<? extends java.lang.Byte> _13_info = _12___mcc_h7;
      dafny.DafnySequence<? extends java.lang.Byte> _14_pkR = _11___mcc_h6;
      dafny.DafnySequence<? extends java.lang.Byte> _15_enc = _10___mcc_h5;
      if (!((e).is_X25519Result())) {
        return HpkeOut.create_HFailed(EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("unexpected event"));
      } else if (!java.util.Objects.equals(java.math.BigInteger.valueOf(((e).dtor_point()).length()), java.math.BigInteger.valueOf(32L))) {
        return HpkeOut.create_HFailed(EHBP.Code.create_HpkeSetupFailed(), dafny.DafnySequence.asUnicodeString("X25519 failed"));
      } else {
        return __default.Schedule(Hpke.create_HSchedule(java.math.BigInteger.ZERO, __default.Extract(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor())), _15_enc, _14_pkR, _13_info, dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor())), __default.LabeledExtract(__default.KemSuiteId(), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.asUnicodeString("eae_prk"), (e).dtor_point()));
      }
    } else {
      java.math.BigInteger _16___mcc_h8 = ((EHBPEvents.Hpke_HSchedule)_source0)._stage;
      Job _17___mcc_h9 = ((EHBPEvents.Hpke_HSchedule)_source0)._job;
      dafny.DafnySequence<? extends java.lang.Byte> _18___mcc_h10 = ((EHBPEvents.Hpke_HSchedule)_source0)._enc;
      dafny.DafnySequence<? extends java.lang.Byte> _19___mcc_h11 = ((EHBPEvents.Hpke_HSchedule)_source0)._pkR;
      dafny.DafnySequence<? extends java.lang.Byte> _20___mcc_h12 = ((EHBPEvents.Hpke_HSchedule)_source0)._info;
      dafny.DafnySequence<? extends java.lang.Byte> _21___mcc_h13 = ((EHBPEvents.Hpke_HSchedule)_source0)._shared;
      dafny.DafnySequence<? extends java.lang.Byte> _22___mcc_h14 = ((EHBPEvents.Hpke_HSchedule)_source0)._pskIdHash;
      dafny.DafnySequence<? extends java.lang.Byte> _23___mcc_h15 = ((EHBPEvents.Hpke_HSchedule)_source0)._infoHash;
      dafny.DafnySequence<? extends java.lang.Byte> _24___mcc_h16 = ((EHBPEvents.Hpke_HSchedule)_source0)._secret;
      dafny.DafnySequence<? extends java.lang.Byte> _25___mcc_h17 = ((EHBPEvents.Hpke_HSchedule)_source0)._key;
      dafny.DafnySequence<? extends java.lang.Byte> _26___mcc_h18 = ((EHBPEvents.Hpke_HSchedule)_source0)._baseNonce;
      dafny.DafnySequence<? extends java.lang.Byte> _27_baseNonce = _26___mcc_h18;
      dafny.DafnySequence<? extends java.lang.Byte> _28_key = _25___mcc_h17;
      dafny.DafnySequence<? extends java.lang.Byte> _29_secret = _24___mcc_h16;
      dafny.DafnySequence<? extends java.lang.Byte> _30_infoHash = _23___mcc_h15;
      dafny.DafnySequence<? extends java.lang.Byte> _31_pskIdHash = _22___mcc_h14;
      dafny.DafnySequence<? extends java.lang.Byte> _32_shared = _21___mcc_h13;
      dafny.DafnySequence<? extends java.lang.Byte> _33_info = _20___mcc_h12;
      dafny.DafnySequence<? extends java.lang.Byte> _34_pkR = _19___mcc_h11;
      dafny.DafnySequence<? extends java.lang.Byte> _35_enc = _18___mcc_h10;
      Job _36_job = _17___mcc_h9;
      java.math.BigInteger _37_stage = _16___mcc_h8;
      JobOut _source1 = __default.JobStep(_36_job, e);
      if (_source1.is_Pending()) {
        Job _38___mcc_h19 = ((EHBPEvents.JobOut_Pending)_source1)._job;
        Action _39___mcc_h20 = ((EHBPEvents.JobOut_Pending)_source1)._action;
        Action _40_action = _39___mcc_h20;
        Job _41_next = _38___mcc_h19;
        return HpkeOut.create_HContinue(((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(h, boxed6 -> {
  Hpke _pat_let3_0 = ((Hpke)(java.lang.Object)(boxed6));
  return ((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(_pat_let3_0, boxed7 -> {
    Hpke _42_dt__update__tmp_h0 = ((Hpke)(java.lang.Object)(boxed7));
    return ((Hpke)(java.lang.Object)(dafny.Helpers.<Job, Hpke>Let(_41_next, boxed8 -> {
      Job _pat_let4_0 = ((Job)(java.lang.Object)(boxed8));
      return ((Hpke)(java.lang.Object)(dafny.Helpers.<Job, Hpke>Let(_pat_let4_0, boxed9 -> {
        Job _43_dt__update_hjob_h0 = ((Job)(java.lang.Object)(boxed9));
        return Hpke.create_HSchedule((_42_dt__update__tmp_h0).dtor_stage(), _43_dt__update_hjob_h0, (_42_dt__update__tmp_h0).dtor_enc(), (_42_dt__update__tmp_h0).dtor_pkR(), (_42_dt__update__tmp_h0).dtor_info(), (_42_dt__update__tmp_h0).dtor_shared(), (_42_dt__update__tmp_h0).dtor_pskIdHash(), (_42_dt__update__tmp_h0).dtor_infoHash(), (_42_dt__update__tmp_h0).dtor_secret(), (_42_dt__update__tmp_h0).dtor_key(), (_42_dt__update__tmp_h0).dtor_baseNonce());
      }
      )));
    }
    )));
  }
  )));
}
))), _40_action);
      } else if (_source1.is_Output()) {
        dafny.DafnySequence<? extends java.lang.Byte> _44___mcc_h21 = ((EHBPEvents.JobOut_Output)_source1)._data;
        dafny.DafnySequence<? extends java.lang.Byte> _45_out = _44___mcc_h21;
        dafny.DafnySequence<? extends java.lang.Byte> _46_ksc = dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte> of((byte) 0), _31_pskIdHash), _30_infoHash);
        if ((_37_stage).signum() == 0) {
          return __default.Schedule(((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(h, boxed10 -> {
            Hpke _pat_let5_0 = ((Hpke)(java.lang.Object)(boxed10));
            return ((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(_pat_let5_0, boxed11 -> {
              Hpke _47_dt__update__tmp_h1 = ((Hpke)(java.lang.Object)(boxed11));
              return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(java.math.BigInteger.ONE, boxed12 -> {
                java.math.BigInteger _pat_let6_0 = ((java.math.BigInteger)(java.lang.Object)(boxed12));
                return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(_pat_let6_0, boxed13 -> {
                  java.math.BigInteger _48_dt__update_hstage_h0 = ((java.math.BigInteger)(java.lang.Object)(boxed13));
                  return Hpke.create_HSchedule(_48_dt__update_hstage_h0, (_47_dt__update__tmp_h1).dtor_job(), (_47_dt__update__tmp_h1).dtor_enc(), (_47_dt__update__tmp_h1).dtor_pkR(), (_47_dt__update__tmp_h1).dtor_info(), (_47_dt__update__tmp_h1).dtor_shared(), (_47_dt__update__tmp_h1).dtor_pskIdHash(), (_47_dt__update__tmp_h1).dtor_infoHash(), (_47_dt__update__tmp_h1).dtor_secret(), (_47_dt__update__tmp_h1).dtor_key(), (_47_dt__update__tmp_h1).dtor_baseNonce());
                }
                )));
              }
              )));
            }
            )));
          }
          ))), __default.LabeledExpand(__default.KemSuiteId(), _45_out, dafny.DafnySequence.asUnicodeString("shared_secret"), dafny.DafnySequence.<java.lang.Byte>concatenate(_35_enc, _34_pkR), EHBP.__default.HashLength()));
        } else if (java.util.Objects.equals(_37_stage, java.math.BigInteger.ONE)) {
          return __default.Schedule(((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(h, boxed14 -> {
            Hpke _pat_let7_0 = ((Hpke)(java.lang.Object)(boxed14));
            return ((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(_pat_let7_0, boxed15 -> {
              Hpke _49_dt__update__tmp_h2 = ((Hpke)(java.lang.Object)(boxed15));
              return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_45_out, boxed16 -> {
                dafny.DafnySequence<? extends java.lang.Byte> _pat_let8_0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed16));
                return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_pat_let8_0, boxed17 -> {
                  dafny.DafnySequence<? extends java.lang.Byte> _50_dt__update_hshared_h0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed17));
                  return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(java.math.BigInteger.valueOf(2L), boxed18 -> {
                    java.math.BigInteger _pat_let9_0 = ((java.math.BigInteger)(java.lang.Object)(boxed18));
                    return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(_pat_let9_0, boxed19 -> {
                      java.math.BigInteger _51_dt__update_hstage_h1 = ((java.math.BigInteger)(java.lang.Object)(boxed19));
                      return Hpke.create_HSchedule(_51_dt__update_hstage_h1, (_49_dt__update__tmp_h2).dtor_job(), (_49_dt__update__tmp_h2).dtor_enc(), (_49_dt__update__tmp_h2).dtor_pkR(), (_49_dt__update__tmp_h2).dtor_info(), _50_dt__update_hshared_h0, (_49_dt__update__tmp_h2).dtor_pskIdHash(), (_49_dt__update__tmp_h2).dtor_infoHash(), (_49_dt__update__tmp_h2).dtor_secret(), (_49_dt__update__tmp_h2).dtor_key(), (_49_dt__update__tmp_h2).dtor_baseNonce());
                    }
                    )));
                  }
                  )));
                }
                )));
              }
              )));
            }
            )));
          }
          ))), __default.LabeledExtract(__default.HpkeSuiteId(), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.asUnicodeString("psk_id_hash"), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor())));
        } else if (java.util.Objects.equals(_37_stage, java.math.BigInteger.valueOf(2L))) {
          return __default.Schedule(((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(h, boxed20 -> {
            Hpke _pat_let10_0 = ((Hpke)(java.lang.Object)(boxed20));
            return ((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(_pat_let10_0, boxed21 -> {
              Hpke _52_dt__update__tmp_h3 = ((Hpke)(java.lang.Object)(boxed21));
              return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_45_out, boxed22 -> {
                dafny.DafnySequence<? extends java.lang.Byte> _pat_let11_0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed22));
                return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_pat_let11_0, boxed23 -> {
                  dafny.DafnySequence<? extends java.lang.Byte> _53_dt__update_hpskIdHash_h0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed23));
                  return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(java.math.BigInteger.valueOf(3L), boxed24 -> {
                    java.math.BigInteger _pat_let12_0 = ((java.math.BigInteger)(java.lang.Object)(boxed24));
                    return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(_pat_let12_0, boxed25 -> {
                      java.math.BigInteger _54_dt__update_hstage_h2 = ((java.math.BigInteger)(java.lang.Object)(boxed25));
                      return Hpke.create_HSchedule(_54_dt__update_hstage_h2, (_52_dt__update__tmp_h3).dtor_job(), (_52_dt__update__tmp_h3).dtor_enc(), (_52_dt__update__tmp_h3).dtor_pkR(), (_52_dt__update__tmp_h3).dtor_info(), (_52_dt__update__tmp_h3).dtor_shared(), _53_dt__update_hpskIdHash_h0, (_52_dt__update__tmp_h3).dtor_infoHash(), (_52_dt__update__tmp_h3).dtor_secret(), (_52_dt__update__tmp_h3).dtor_key(), (_52_dt__update__tmp_h3).dtor_baseNonce());
                    }
                    )));
                  }
                  )));
                }
                )));
              }
              )));
            }
            )));
          }
          ))), __default.LabeledExtract(__default.HpkeSuiteId(), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.asUnicodeString("info_hash"), _33_info));
        } else if (java.util.Objects.equals(_37_stage, java.math.BigInteger.valueOf(3L))) {
          return __default.Schedule(((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(h, boxed26 -> {
            Hpke _pat_let13_0 = ((Hpke)(java.lang.Object)(boxed26));
            return ((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(_pat_let13_0, boxed27 -> {
              Hpke _55_dt__update__tmp_h4 = ((Hpke)(java.lang.Object)(boxed27));
              return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_45_out, boxed28 -> {
                dafny.DafnySequence<? extends java.lang.Byte> _pat_let14_0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed28));
                return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_pat_let14_0, boxed29 -> {
                  dafny.DafnySequence<? extends java.lang.Byte> _56_dt__update_hinfoHash_h0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed29));
                  return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(java.math.BigInteger.valueOf(4L), boxed30 -> {
                    java.math.BigInteger _pat_let15_0 = ((java.math.BigInteger)(java.lang.Object)(boxed30));
                    return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(_pat_let15_0, boxed31 -> {
                      java.math.BigInteger _57_dt__update_hstage_h3 = ((java.math.BigInteger)(java.lang.Object)(boxed31));
                      return Hpke.create_HSchedule(_57_dt__update_hstage_h3, (_55_dt__update__tmp_h4).dtor_job(), (_55_dt__update__tmp_h4).dtor_enc(), (_55_dt__update__tmp_h4).dtor_pkR(), (_55_dt__update__tmp_h4).dtor_info(), (_55_dt__update__tmp_h4).dtor_shared(), (_55_dt__update__tmp_h4).dtor_pskIdHash(), _56_dt__update_hinfoHash_h0, (_55_dt__update__tmp_h4).dtor_secret(), (_55_dt__update__tmp_h4).dtor_key(), (_55_dt__update__tmp_h4).dtor_baseNonce());
                    }
                    )));
                  }
                  )));
                }
                )));
              }
              )));
            }
            )));
          }
          ))), __default.LabeledExtract(__default.HpkeSuiteId(), _32_shared, dafny.DafnySequence.asUnicodeString("secret"), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor())));
        } else if (java.util.Objects.equals(_37_stage, java.math.BigInteger.valueOf(4L))) {
          return __default.Schedule(((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(h, boxed32 -> {
            Hpke _pat_let16_0 = ((Hpke)(java.lang.Object)(boxed32));
            return ((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(_pat_let16_0, boxed33 -> {
              Hpke _58_dt__update__tmp_h5 = ((Hpke)(java.lang.Object)(boxed33));
              return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_45_out, boxed34 -> {
                dafny.DafnySequence<? extends java.lang.Byte> _pat_let17_0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed34));
                return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_pat_let17_0, boxed35 -> {
                  dafny.DafnySequence<? extends java.lang.Byte> _59_dt__update_hsecret_h0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed35));
                  return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(java.math.BigInteger.valueOf(5L), boxed36 -> {
                    java.math.BigInteger _pat_let18_0 = ((java.math.BigInteger)(java.lang.Object)(boxed36));
                    return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(_pat_let18_0, boxed37 -> {
                      java.math.BigInteger _60_dt__update_hstage_h4 = ((java.math.BigInteger)(java.lang.Object)(boxed37));
                      return Hpke.create_HSchedule(_60_dt__update_hstage_h4, (_58_dt__update__tmp_h5).dtor_job(), (_58_dt__update__tmp_h5).dtor_enc(), (_58_dt__update__tmp_h5).dtor_pkR(), (_58_dt__update__tmp_h5).dtor_info(), (_58_dt__update__tmp_h5).dtor_shared(), (_58_dt__update__tmp_h5).dtor_pskIdHash(), (_58_dt__update__tmp_h5).dtor_infoHash(), _59_dt__update_hsecret_h0, (_58_dt__update__tmp_h5).dtor_key(), (_58_dt__update__tmp_h5).dtor_baseNonce());
                    }
                    )));
                  }
                  )));
                }
                )));
              }
              )));
            }
            )));
          }
          ))), __default.LabeledExpand(__default.HpkeSuiteId(), _45_out, dafny.DafnySequence.asUnicodeString("key"), _46_ksc, EHBP.__default.KeyLength()));
        } else if (java.util.Objects.equals(_37_stage, java.math.BigInteger.valueOf(5L))) {
          return __default.Schedule(((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(h, boxed38 -> {
            Hpke _pat_let19_0 = ((Hpke)(java.lang.Object)(boxed38));
            return ((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(_pat_let19_0, boxed39 -> {
              Hpke _61_dt__update__tmp_h6 = ((Hpke)(java.lang.Object)(boxed39));
              return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_45_out, boxed40 -> {
                dafny.DafnySequence<? extends java.lang.Byte> _pat_let20_0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed40));
                return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_pat_let20_0, boxed41 -> {
                  dafny.DafnySequence<? extends java.lang.Byte> _62_dt__update_hkey_h0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed41));
                  return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(java.math.BigInteger.valueOf(6L), boxed42 -> {
                    java.math.BigInteger _pat_let21_0 = ((java.math.BigInteger)(java.lang.Object)(boxed42));
                    return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(_pat_let21_0, boxed43 -> {
                      java.math.BigInteger _63_dt__update_hstage_h5 = ((java.math.BigInteger)(java.lang.Object)(boxed43));
                      return Hpke.create_HSchedule(_63_dt__update_hstage_h5, (_61_dt__update__tmp_h6).dtor_job(), (_61_dt__update__tmp_h6).dtor_enc(), (_61_dt__update__tmp_h6).dtor_pkR(), (_61_dt__update__tmp_h6).dtor_info(), (_61_dt__update__tmp_h6).dtor_shared(), (_61_dt__update__tmp_h6).dtor_pskIdHash(), (_61_dt__update__tmp_h6).dtor_infoHash(), (_61_dt__update__tmp_h6).dtor_secret(), _62_dt__update_hkey_h0, (_61_dt__update__tmp_h6).dtor_baseNonce());
                    }
                    )));
                  }
                  )));
                }
                )));
              }
              )));
            }
            )));
          }
          ))), __default.LabeledExpand(__default.HpkeSuiteId(), _29_secret, dafny.DafnySequence.asUnicodeString("base_nonce"), _46_ksc, EHBP.__default.NonceLength()));
        } else if (java.util.Objects.equals(_37_stage, java.math.BigInteger.valueOf(6L))) {
          return __default.Schedule(((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(h, boxed44 -> {
            Hpke _pat_let22_0 = ((Hpke)(java.lang.Object)(boxed44));
            return ((Hpke)(java.lang.Object)(dafny.Helpers.<Hpke, Hpke>Let(_pat_let22_0, boxed45 -> {
              Hpke _64_dt__update__tmp_h7 = ((Hpke)(java.lang.Object)(boxed45));
              return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_45_out, boxed46 -> {
                dafny.DafnySequence<? extends java.lang.Byte> _pat_let23_0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed46));
                return ((Hpke)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Hpke>Let(_pat_let23_0, boxed47 -> {
                  dafny.DafnySequence<? extends java.lang.Byte> _65_dt__update_hbaseNonce_h0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed47));
                  return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(java.math.BigInteger.valueOf(7L), boxed48 -> {
                    java.math.BigInteger _pat_let24_0 = ((java.math.BigInteger)(java.lang.Object)(boxed48));
                    return ((Hpke)(java.lang.Object)(dafny.Helpers.<java.math.BigInteger, Hpke>Let(_pat_let24_0, boxed49 -> {
                      java.math.BigInteger _66_dt__update_hstage_h6 = ((java.math.BigInteger)(java.lang.Object)(boxed49));
                      return Hpke.create_HSchedule(_66_dt__update_hstage_h6, (_64_dt__update__tmp_h7).dtor_job(), (_64_dt__update__tmp_h7).dtor_enc(), (_64_dt__update__tmp_h7).dtor_pkR(), (_64_dt__update__tmp_h7).dtor_info(), (_64_dt__update__tmp_h7).dtor_shared(), (_64_dt__update__tmp_h7).dtor_pskIdHash(), (_64_dt__update__tmp_h7).dtor_infoHash(), (_64_dt__update__tmp_h7).dtor_secret(), (_64_dt__update__tmp_h7).dtor_key(), _65_dt__update_hbaseNonce_h0);
                    }
                    )));
                  }
                  )));
                }
                )));
              }
              )));
            }
            )));
          }
          ))), __default.LabeledExpand(__default.HpkeSuiteId(), _29_secret, dafny.DafnySequence.asUnicodeString("exp"), _46_ksc, EHBP.__default.HashLength()));
        } else if (((java.util.Objects.equals(_37_stage, java.math.BigInteger.valueOf(7L))) && (java.util.Objects.equals(java.math.BigInteger.valueOf((_28_key).length()), EHBP.__default.KeyLength()))) && (java.util.Objects.equals(java.math.BigInteger.valueOf((_27_baseNonce).length()), EHBP.__default.NonceLength()))) {
          dafny.DafnySequence<? extends java.lang.Byte> _67_k = _28_key;
          dafny.DafnySequence<? extends java.lang.Byte> _68_n = _27_baseNonce;
          return HpkeOut.create_HReady(Ctx.create(_67_k, _68_n, _45_out, (long) 0L), _35_enc);
        } else {
          return HpkeOut.create_HFailed(EHBP.Code.create_HpkeSetupFailed(), dafny.DafnySequence.asUnicodeString("key schedule produced the wrong lengths"));
        }
      } else {
        EHBP.Code _69___mcc_h22 = ((EHBPEvents.JobOut_JobFailed)_source1)._code;
        dafny.DafnySequence<? extends dafny.CodePoint> _70___mcc_h23 = ((EHBPEvents.JobOut_JobFailed)_source1)._message;
        dafny.DafnySequence<? extends dafny.CodePoint> _71_message = _70___mcc_h23;
        EHBP.Code _72_code = _69___mcc_h22;
        return HpkeOut.create_HFailed(_72_code, _71_message);
      }
    }
  }
  public static Action SealAction(Ctx ctx, dafny.DafnySequence<? extends java.lang.Byte> plaintext)
  {
    return Action.create_AeadSeal((ctx).dtor_key(), EHBP.__default.ComputeNonce((ctx).dtor_baseNonce(), (ctx).dtor_seqNo()), plaintext);
  }
  public static Action OpenAction(Ctx ctx, dafny.DafnySequence<? extends java.lang.Byte> ciphertext)
  {
    return Action.create_AeadOpen((ctx).dtor_key(), EHBP.__default.ComputeNonce((ctx).dtor_baseNonce(), (ctx).dtor_seqNo()), ciphertext);
  }
  public static Ctx Bump(Ctx ctx) {
    Ctx _0_dt__update__tmp_h0 = ctx;
    long _1_dt__update_hseqNo_h0 = (long) (long) (((ctx).dtor_seqNo()) + ((long) 1L));
    return Ctx.create((_0_dt__update__tmp_h0).dtor_key(), (_0_dt__update__tmp_h0).dtor_baseNonce(), (_0_dt__update__tmp_h0).dtor_exporterSecret(), _1_dt__update_hseqNo_h0);
  }
  public static Job ExportJob(Ctx ctx, dafny.DafnySequence<? extends java.lang.Byte> context, java.math.BigInteger length)
  {
    return __default.LabeledExpand(__default.HpkeSuiteId(), (ctx).dtor_exporterSecret(), dafny.DafnySequence.asUnicodeString("sec"), context, length);
  }
  public static boolean JsonWs(int c) {
    return ((((c) == (' ')) || ((c) == ('\t'))) || ((c) == ('\n'))) || ((c) == ('\r'));
  }
  public static boolean IsDigit(int c) {
    return (('0') <= (c)) && ((c) <= ('9'));
  }
  public static java.math.BigInteger SkipWs(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i)
  {
    TAIL_CALL_START: while (true) {
      if (((i).compareTo(java.math.BigInteger.valueOf((s).length())) < 0) && (__default.JsonWs(((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()))) {
        dafny.DafnySequence<? extends dafny.CodePoint> _in0 = s;
        java.math.BigInteger _in1 = (i).add(java.math.BigInteger.ONE);
        s = _in0;
        i = _in1;
        continue TAIL_CALL_START;
      } else {
        return i;
      }
    }
  }
  public static java.math.BigInteger Digits(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i)
  {
    TAIL_CALL_START: while (true) {
      if (((i).compareTo(java.math.BigInteger.valueOf((s).length())) < 0) && (__default.IsDigit(((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()))) {
        dafny.DafnySequence<? extends dafny.CodePoint> _in0 = s;
        java.math.BigInteger _in1 = (i).add(java.math.BigInteger.ONE);
        s = _in0;
        i = _in1;
        continue TAIL_CALL_START;
      } else {
        return i;
      }
    }
  }
  public static EHBP.Option<java.math.BigInteger> Hex4(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i)
  {
    if (((i).add(java.math.BigInteger.valueOf(4L))).compareTo(java.math.BigInteger.valueOf((s).length())) > 0) {
      return EHBP.Option.<java.math.BigInteger>create_None(dafny.TypeDescriptor.BIG_INTEGER);
    } else {
      dafny.Tuple4<EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>> _source0 = dafny.Tuple4.<EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>>create(EHBP.__default.HexDigitValue(((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()), EHBP.__default.HexDigitValue(((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE)))))).value()), EHBP.__default.HexDigitValue(((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(2L))))))).value()), EHBP.__default.HexDigitValue(((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(3L))))))).value()));
      EHBP.Option<java.lang.Byte> _0___mcc_h0 = ((EHBP.Option<java.lang.Byte>)(java.lang.Object)(((dafny.Tuple4<EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>>)_source0).dtor__0()));
      EHBP.Option<java.lang.Byte> _1___mcc_h1 = ((EHBP.Option<java.lang.Byte>)(java.lang.Object)(((dafny.Tuple4<EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>>)_source0).dtor__1()));
      EHBP.Option<java.lang.Byte> _2___mcc_h2 = ((EHBP.Option<java.lang.Byte>)(java.lang.Object)(((dafny.Tuple4<EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>>)_source0).dtor__2()));
      EHBP.Option<java.lang.Byte> _3___mcc_h3 = ((EHBP.Option<java.lang.Byte>)(java.lang.Object)(((dafny.Tuple4<EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>, EHBP.Option<java.lang.Byte>>)_source0).dtor__3()));
      EHBP.Option<java.lang.Byte> _source1 = _0___mcc_h0;
      if (_source1.is_None()) {
        return EHBP.Option.<java.math.BigInteger>create_None(dafny.TypeDescriptor.BIG_INTEGER);
      } else {
        byte _4___mcc_h8 = ((EHBP.Option_Some<java.lang.Byte>)_source1)._value;
        EHBP.Option<java.lang.Byte> _source2 = _1___mcc_h1;
        if (_source2.is_None()) {
          return EHBP.Option.<java.math.BigInteger>create_None(dafny.TypeDescriptor.BIG_INTEGER);
        } else {
          byte _5___mcc_h10 = ((EHBP.Option_Some<java.lang.Byte>)_source2)._value;
          EHBP.Option<java.lang.Byte> _source3 = _2___mcc_h2;
          if (_source3.is_None()) {
            return EHBP.Option.<java.math.BigInteger>create_None(dafny.TypeDescriptor.BIG_INTEGER);
          } else {
            byte _6___mcc_h12 = ((EHBP.Option_Some<java.lang.Byte>)_source3)._value;
            EHBP.Option<java.lang.Byte> _source4 = _3___mcc_h3;
            if (_source4.is_None()) {
              return EHBP.Option.<java.math.BigInteger>create_None(dafny.TypeDescriptor.BIG_INTEGER);
            } else {
              byte _7___mcc_h14 = ((EHBP.Option_Some<java.lang.Byte>)_source4)._value;
              byte _8_d = _7___mcc_h14;
              byte _9_c = _6___mcc_h12;
              byte _10_b = _5___mcc_h10;
              byte _11_a = _4___mcc_h8;
              return EHBP.Option.<java.math.BigInteger>create_Some(dafny.TypeDescriptor.BIG_INTEGER, ((((dafny.Helpers.unsignedToBigInteger(_11_a)).multiply(java.math.BigInteger.valueOf(4096L))).add((dafny.Helpers.unsignedToBigInteger(_10_b)).multiply(java.math.BigInteger.valueOf(256L)))).add((dafny.Helpers.unsignedToBigInteger(_9_c)).multiply(java.math.BigInteger.valueOf(16L)))).add(dafny.Helpers.unsignedToBigInteger(_8_d)));
            }
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> Keep(dafny.DafnySequence<? extends dafny.CodePoint> acc, dafny.DafnySequence<? extends dafny.CodePoint> add)
  {
    if ((java.math.BigInteger.valueOf((acc).length())).compareTo(__default.MaxJsonStringChars()) >= 0) {
      return acc;
    } else if (((java.math.BigInteger.valueOf((acc).length())).add(java.math.BigInteger.valueOf((add).length()))).compareTo(__default.MaxJsonStringChars()) <= 0) {
      return dafny.DafnySequence.<dafny.CodePoint>concatenate(acc, add);
    } else {
      return dafny.DafnySequence.<dafny.CodePoint>concatenate(acc, (add).take((__default.MaxJsonStringChars()).subtract(java.math.BigInteger.valueOf((acc).length()))));
    }
  }
  public static java.math.BigInteger Max(java.math.BigInteger a, java.math.BigInteger b)
  {
    if ((a).compareTo(b) >= 0) {
      return a;
    } else {
      return b;
    }
  }
  public static java.math.BigInteger LiteralEnd(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i)
  {
    TAIL_CALL_START: while (true) {
      if ((((java.util.Objects.equals(i, java.math.BigInteger.valueOf((s).length()))) || ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('"'))) || ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('\\'))) || ((java.math.BigInteger.valueOf(((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value())).compareTo(java.math.BigInteger.valueOf(32L)) < 0)) {
        return i;
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _in0 = s;
        java.math.BigInteger _in1 = (i).add(java.math.BigInteger.ONE);
        s = _in0;
        i = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static EHBP.Option<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>> ParseString(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i, dafny.DafnySequence<? extends dafny.CodePoint> acc)
  {
    TAIL_CALL_START: while (true) {
      java.math.BigInteger _0_j = __default.LiteralEnd(s, i);
      dafny.DafnySequence<? extends dafny.CodePoint> _1_run = __default.Keep(acc, (s).subsequence(dafny.Helpers.toInt((i)), dafny.Helpers.toInt((_0_j))));
      if (java.util.Objects.equals(_0_j, java.math.BigInteger.valueOf((s).length()))) {
        return EHBP.Option.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>>create_None(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.TypeDescriptor.BIG_INTEGER));
      } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_0_j))))).value()) == ('"')) {
        return EHBP.Option.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>>create_Some(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.TypeDescriptor.BIG_INTEGER), dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>create(_1_run, (_0_j).add(java.math.BigInteger.ONE)));
      } else if ((java.math.BigInteger.valueOf(((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_0_j))))).value())).compareTo(java.math.BigInteger.valueOf(32L)) < 0) {
        return EHBP.Option.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>>create_None(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.TypeDescriptor.BIG_INTEGER));
      } else if (java.util.Objects.equals((_0_j).add(java.math.BigInteger.ONE), java.math.BigInteger.valueOf((s).length()))) {
        return EHBP.Option.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>>create_None(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.TypeDescriptor.BIG_INTEGER));
      } else {
        int _2_c = ((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((_0_j).add(java.math.BigInteger.ONE)))))).value();
        if ((((_2_c) == ('"')) || ((_2_c) == ('\\'))) || ((_2_c) == ('/'))) {
          dafny.DafnySequence<? extends dafny.CodePoint> _in0 = s;
          java.math.BigInteger _in1 = (_0_j).add(java.math.BigInteger.valueOf(2L));
          dafny.DafnySequence<? extends dafny.CodePoint> _in2 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf(_2_c)));
          s = _in0;
          i = _in1;
          acc = _in2;
          continue TAIL_CALL_START;
        } else if ((_2_c) == ('b')) {
          dafny.DafnySequence<? extends dafny.CodePoint> _in3 = s;
          java.math.BigInteger _in4 = (_0_j).add(java.math.BigInteger.valueOf(2L));
          dafny.DafnySequence<? extends dafny.CodePoint> _in5 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((java.math.BigInteger.valueOf(8L))))));
          s = _in3;
          i = _in4;
          acc = _in5;
          continue TAIL_CALL_START;
        } else if ((_2_c) == ('f')) {
          dafny.DafnySequence<? extends dafny.CodePoint> _in6 = s;
          java.math.BigInteger _in7 = (_0_j).add(java.math.BigInteger.valueOf(2L));
          dafny.DafnySequence<? extends dafny.CodePoint> _in8 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((java.math.BigInteger.valueOf(12L))))));
          s = _in6;
          i = _in7;
          acc = _in8;
          continue TAIL_CALL_START;
        } else if ((_2_c) == ('n')) {
          dafny.DafnySequence<? extends dafny.CodePoint> _in9 = s;
          java.math.BigInteger _in10 = (_0_j).add(java.math.BigInteger.valueOf(2L));
          dafny.DafnySequence<? extends dafny.CodePoint> _in11 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf('\n')));
          s = _in9;
          i = _in10;
          acc = _in11;
          continue TAIL_CALL_START;
        } else if ((_2_c) == ('r')) {
          dafny.DafnySequence<? extends dafny.CodePoint> _in12 = s;
          java.math.BigInteger _in13 = (_0_j).add(java.math.BigInteger.valueOf(2L));
          dafny.DafnySequence<? extends dafny.CodePoint> _in14 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf('\r')));
          s = _in12;
          i = _in13;
          acc = _in14;
          continue TAIL_CALL_START;
        } else if ((_2_c) == ('t')) {
          dafny.DafnySequence<? extends dafny.CodePoint> _in15 = s;
          java.math.BigInteger _in16 = (_0_j).add(java.math.BigInteger.valueOf(2L));
          dafny.DafnySequence<? extends dafny.CodePoint> _in17 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf('\t')));
          s = _in15;
          i = _in16;
          acc = _in17;
          continue TAIL_CALL_START;
        } else if ((_2_c) != ('u')) {
          return EHBP.Option.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>>create_None(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), _System.nat._typeDescriptor()));
        } else {
          EHBP.Option<java.math.BigInteger> _source0 = __default.Hex4(s, (_0_j).add(java.math.BigInteger.valueOf(2L)));
          if (_source0.is_None()) {
            return EHBP.Option.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>>create_None(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), _System.nat._typeDescriptor()));
          } else {
            java.math.BigInteger _3___mcc_h0 = ((EHBP.Option_Some<java.math.BigInteger>)_source0)._value;
            java.math.BigInteger _4_cp = _3___mcc_h0;
            if (((java.math.BigInteger.valueOf(55296L)).compareTo(_4_cp) <= 0) && ((_4_cp).compareTo(java.math.BigInteger.valueOf(56319L)) <= 0)) {
              EHBP.Option<java.math.BigInteger> _5_lo = ((((((_0_j).add(java.math.BigInteger.valueOf(8L))).compareTo(java.math.BigInteger.valueOf((s).length())) <= 0) && ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((_0_j).add(java.math.BigInteger.valueOf(6L))))))).value()) == ('\\'))) && ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((_0_j).add(java.math.BigInteger.valueOf(7L))))))).value()) == ('u'))) ? (__default.Hex4(s, (_0_j).add(java.math.BigInteger.valueOf(8L)))) : (EHBP.Option.<java.math.BigInteger>create_None(dafny.TypeDescriptor.BIG_INTEGER)));
              if (((_5_lo).is_Some()) && (((java.math.BigInteger.valueOf(56320L)).compareTo((_5_lo).dtor_value()) <= 0) && (((_5_lo).dtor_value()).compareTo(java.math.BigInteger.valueOf(57343L)) <= 0))) {
                dafny.DafnySequence<? extends dafny.CodePoint> _in18 = s;
                java.math.BigInteger _in19 = (_0_j).add(java.math.BigInteger.valueOf(12L));
                dafny.DafnySequence<? extends dafny.CodePoint> _in20 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((((java.math.BigInteger.valueOf(65536L)).add(((_4_cp).subtract(java.math.BigInteger.valueOf(55296L))).multiply(java.math.BigInteger.valueOf(1024L)))).add(((_5_lo).dtor_value()).subtract(java.math.BigInteger.valueOf(56320L))))))));
                s = _in18;
                i = _in19;
                acc = _in20;
                continue TAIL_CALL_START;
              } else {
                dafny.DafnySequence<? extends dafny.CodePoint> _in21 = s;
                java.math.BigInteger _in22 = (_0_j).add(java.math.BigInteger.valueOf(6L));
                dafny.DafnySequence<? extends dafny.CodePoint> _in23 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((java.math.BigInteger.valueOf(65533L))))));
                s = _in21;
                i = _in22;
                acc = _in23;
                continue TAIL_CALL_START;
              }
            } else if (((java.math.BigInteger.valueOf(56320L)).compareTo(_4_cp) <= 0) && ((_4_cp).compareTo(java.math.BigInteger.valueOf(57343L)) <= 0)) {
              dafny.DafnySequence<? extends dafny.CodePoint> _in24 = s;
              java.math.BigInteger _in25 = (_0_j).add(java.math.BigInteger.valueOf(6L));
              dafny.DafnySequence<? extends dafny.CodePoint> _in26 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((java.math.BigInteger.valueOf(65533L))))));
              s = _in24;
              i = _in25;
              acc = _in26;
              continue TAIL_CALL_START;
            } else {
              dafny.DafnySequence<? extends dafny.CodePoint> _in27 = s;
              java.math.BigInteger _in28 = (_0_j).add(java.math.BigInteger.valueOf(6L));
              dafny.DafnySequence<? extends dafny.CodePoint> _in29 = __default.Keep(_1_run, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((_4_cp)))));
              s = _in27;
              i = _in28;
              acc = _in29;
              continue TAIL_CALL_START;
            }
          }
        }
      }
    }
  }
  public static EHBP.Option<java.math.BigInteger> Frac(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i)
  {
    if (((i).compareTo(java.math.BigInteger.valueOf((s).length())) < 0) && ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('.'))) {
      if ((((i).add(java.math.BigInteger.ONE)).compareTo(java.math.BigInteger.valueOf((s).length())) < 0) && (__default.IsDigit(((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE)))))).value()))) {
        return EHBP.Option.<java.math.BigInteger>create_Some(_System.nat._typeDescriptor(), __default.Digits(s, (i).add(java.math.BigInteger.ONE)));
      } else {
        return EHBP.Option.<java.math.BigInteger>create_None(_System.nat._typeDescriptor());
      }
    } else {
      return EHBP.Option.<java.math.BigInteger>create_Some(_System.nat._typeDescriptor(), i);
    }
  }
  public static EHBP.Option<java.math.BigInteger> Exponent(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i)
  {
    if (((i).compareTo(java.math.BigInteger.valueOf((s).length())) < 0) && (((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('e')) || ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('E')))) {
      java.math.BigInteger _0_j = (((((i).add(java.math.BigInteger.ONE)).compareTo(java.math.BigInteger.valueOf((s).length())) < 0) && (((((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE)))))).value()) == ('+')) || ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE)))))).value()) == ('-')))) ? ((i).add(java.math.BigInteger.valueOf(2L))) : ((i).add(java.math.BigInteger.ONE)));
      if (((_0_j).compareTo(java.math.BigInteger.valueOf((s).length())) < 0) && (__default.IsDigit(((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_0_j))))).value()))) {
        return EHBP.Option.<java.math.BigInteger>create_Some(_System.nat._typeDescriptor(), __default.Digits(s, _0_j));
      } else {
        return EHBP.Option.<java.math.BigInteger>create_None(_System.nat._typeDescriptor());
      }
    } else {
      return EHBP.Option.<java.math.BigInteger>create_Some(_System.nat._typeDescriptor(), i);
    }
  }
  public static EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> ParseNumber(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i)
  {
    java.math.BigInteger _0_j = ((((i).compareTo(java.math.BigInteger.valueOf((s).length())) < 0) && ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('-'))) ? ((i).add(java.math.BigInteger.ONE)) : (i));
    if (java.util.Objects.equals(_0_j, java.math.BigInteger.valueOf((s).length()))) {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
    } else {
      EHBP.Option<java.math.BigInteger> _1_k = (((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_0_j))))).value()) == ('0')) ? (EHBP.Option.<java.math.BigInteger>create_Some(dafny.TypeDescriptor.BIG_INTEGER, (_0_j).add(java.math.BigInteger.ONE))) : (((__default.IsDigit(((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_0_j))))).value())) ? (EHBP.Option.<java.math.BigInteger>create_Some(dafny.TypeDescriptor.BIG_INTEGER, __default.Digits(s, (_0_j).add(java.math.BigInteger.ONE)))) : (EHBP.Option.<java.math.BigInteger>create_None(dafny.TypeDescriptor.BIG_INTEGER)))));
      if ((_1_k).is_None()) {
        return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
      } else {
        EHBP.Option<java.math.BigInteger> _source0 = __default.Frac(s, (_1_k).dtor_value());
        if (_source0.is_None()) {
          return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
        } else {
          java.math.BigInteger _2___mcc_h0 = ((EHBP.Option_Some<java.math.BigInteger>)_source0)._value;
          java.math.BigInteger _3_f = _2___mcc_h0;
          EHBP.Option<java.math.BigInteger> _source1 = __default.Exponent(s, _3_f);
          if (_source1.is_None()) {
            return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          } else {
            java.math.BigInteger _4___mcc_h1 = ((EHBP.Option_Some<java.math.BigInteger>)_source1)._value;
            java.math.BigInteger _5_end = _4___mcc_h1;
            return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JNumber((s).subsequence(dafny.Helpers.toInt((i)), dafny.Helpers.toInt((_5_end)))), _5_end));
          }
        }
      }
    }
  }
  public static EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> Literal(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i, dafny.DafnySequence<? extends dafny.CodePoint> word, Json value)
  {
    if ((((i).add(java.math.BigInteger.valueOf((word).length()))).compareTo(java.math.BigInteger.valueOf((s).length())) <= 0) && (((s).subsequence(dafny.Helpers.toInt((i)), dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf((word).length())))))).equals(word))) {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER), dafny.Tuple2.<Json, java.math.BigInteger>create(value, (i).add(java.math.BigInteger.valueOf((word).length()))));
    } else {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
    }
  }
  public static EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> ParseValue(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i, java.math.BigInteger depth)
  {
    if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((s).length()))) {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
    } else if ((((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('{')) || ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('['))) && ((depth).compareTo(__default.MaxJsonDepth()) >= 0)) {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
    } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('{')) {
      return __default.ParseMembers(s, __default.SkipWs(s, (i).add(java.math.BigInteger.ONE)), (depth).add(java.math.BigInteger.ONE), dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> empty(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), Json._typeDescriptor())), true);
    } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('[')) {
      return __default.ParseItems(s, __default.SkipWs(s, (i).add(java.math.BigInteger.ONE)), (depth).add(java.math.BigInteger.ONE), dafny.DafnySequence.<Json> empty(Json._typeDescriptor()), true);
    } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('"')) {
      EHBP.Option<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>> _source0 = __default.ParseString(s, (i).add(java.math.BigInteger.ONE), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
      if (_source0.is_None()) {
        return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
      } else {
        dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger> _0___mcc_h0 = ((EHBP.Option_Some<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>>)_source0)._value;
        dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger> _source1 = _0___mcc_h0;
        dafny.DafnySequence<? extends dafny.CodePoint> _1___mcc_h1 = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>)_source1).dtor__0()));
        java.math.BigInteger _2___mcc_h2 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>)_source1).dtor__1()));
        java.math.BigInteger _3_j = _2___mcc_h2;
        dafny.DafnySequence<? extends dafny.CodePoint> _4_str = _1___mcc_h1;
        return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JString(_4_str), _3_j));
      }
    } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('t')) {
      return __default.Literal(s, i, dafny.DafnySequence.asUnicodeString("true"), Json.create_JBool(true));
    } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('f')) {
      return __default.Literal(s, i, dafny.DafnySequence.asUnicodeString("false"), Json.create_JBool(false));
    } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('n')) {
      return __default.Literal(s, i, dafny.DafnySequence.asUnicodeString("null"), Json.create_JNull());
    } else {
      return __default.ParseNumber(s, i);
    }
  }
  public static EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> ItemsFrom(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i, java.math.BigInteger depth, dafny.DafnySequence<? extends Json> acc, boolean first)
  {
    if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((s).length()))) {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
    } else if ((first) && ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == (']'))) {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JArray(acc), (i).add(java.math.BigInteger.ONE)));
    } else {
      EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> _source0 = __default.ParseValue(s, i, depth);
      if (_source0.is_None()) {
        return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
      } else {
        dafny.Tuple2<Json, java.math.BigInteger> _0___mcc_h0 = ((EHBP.Option_Some<dafny.Tuple2<Json, java.math.BigInteger>>)_source0)._value;
        dafny.Tuple2<Json, java.math.BigInteger> _source1 = _0___mcc_h0;
        Json _1___mcc_h1 = ((Json)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_source1).dtor__0()));
        java.math.BigInteger _2___mcc_h2 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_source1).dtor__1()));
        java.math.BigInteger _3_k = _2___mcc_h2;
        Json _4_v = _1___mcc_h1;
        java.math.BigInteger _5_m = __default.SkipWs(s, _3_k);
        if (java.util.Objects.equals(_5_m, java.math.BigInteger.valueOf((s).length()))) {
          return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
        } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_5_m))))).value()) == (',')) {
          return __default.ItemsFrom(s, __default.SkipWs(s, (_5_m).add(java.math.BigInteger.ONE)), depth, dafny.DafnySequence.<Json>concatenate(acc, dafny.DafnySequence.<Json> of(Json._typeDescriptor(), _4_v)), false);
        } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_5_m))))).value()) == (']')) {
          return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JArray(dafny.DafnySequence.<Json>concatenate(acc, dafny.DafnySequence.<Json> of(Json._typeDescriptor(), _4_v))), (_5_m).add(java.math.BigInteger.ONE)));
        } else {
          return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
        }
      }
    }
  }
  public static EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> ParseItems(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i, java.math.BigInteger depth, dafny.DafnySequence<? extends Json> acc, boolean first)
  {
    EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>Default(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
    if(true) {
      Json[] _0_a;
      java.util.function.Function<java.math.BigInteger, Json> _init0 = ((java.util.function.Function<java.math.BigInteger, Json>)(_1___v14_boxed0) -> {
        java.math.BigInteger _1___v14 = ((java.math.BigInteger)(java.lang.Object)(_1___v14_boxed0));
        return Json.create_JNull();
      });
      Json[] _nw0 = (Json[]) Json._typeDescriptor().newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.ZERO), "Java arrays may be no larger than the maximum 32-bit signed int"));
      for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw0))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
        _nw0[dafny.Helpers.toInt(_i0_0)] = ((Json)(java.lang.Object)(_init0.apply(_i0_0)));
      }
      _0_a = _nw0;
      java.math.BigInteger _2_n = java.math.BigInteger.ZERO;
      java.math.BigInteger _3_j = java.math.BigInteger.ZERO;
      boolean _4_f;
      java.math.BigInteger _rhs0 = java.math.BigInteger.ZERO;
      java.math.BigInteger _rhs1 = i;
      boolean _rhs2 = first;
      _2_n = _rhs0;
      _3_j = _rhs1;
      _4_f = _rhs2;
      while (true) {
        if (java.util.Objects.equals(_3_j, java.math.BigInteger.valueOf((s).length()))) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        if ((_4_f) && ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_3_j))))).value()) == (']'))) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JArray(dafny.DafnySequence.<Json>concatenate(acc, dafny.DafnySequence.fromRawArrayRange(Json._typeDescriptor(), (_0_a), 0, dafny.Helpers.toInt((_2_n))))), (_3_j).add(java.math.BigInteger.ONE)));
          return r;
        }
        EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> _5_r;
        _5_r = __default.ParseValue(s, _3_j, depth);
        if ((_5_r).is_None()) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        dafny.Tuple2<Json, java.math.BigInteger> _let_tmp_rhs0 = (_5_r).dtor_value();
        Json _6_v = ((Json)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_let_tmp_rhs0).dtor__0()));
        java.math.BigInteger _7_k = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_let_tmp_rhs0).dtor__1()));
        java.math.BigInteger _8_m = java.math.BigInteger.ZERO;
        _8_m = __default.SkipWs(s, _7_k);
        if (java.util.Objects.equals(_8_m, java.math.BigInteger.valueOf((s).length()))) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_8_m))))).value()) == (']')) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JArray(dafny.DafnySequence.<Json>concatenate(dafny.DafnySequence.<Json>concatenate(acc, dafny.DafnySequence.fromRawArrayRange(Json._typeDescriptor(), (_0_a), 0, dafny.Helpers.toInt((_2_n)))), dafny.DafnySequence.<Json> of(Json._typeDescriptor(), _6_v))), (_8_m).add(java.math.BigInteger.ONE)));
          return r;
        }
        if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_8_m))))).value()) != (',')) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        Object _out0;
        _out0 = __default.<Json>Append(Json._typeDescriptor(), _0_a, _2_n, _6_v);
        _0_a = ((Json[])(java.lang.Object)(_out0));
        java.math.BigInteger _rhs3 = (_2_n).add(java.math.BigInteger.ONE);
        java.math.BigInteger _rhs4 = __default.SkipWs(s, (_8_m).add(java.math.BigInteger.ONE));
        boolean _rhs5 = false;
        _2_n = _rhs3;
        _3_j = _rhs4;
        _4_f = _rhs5;
      }
    }
    return r;
  }
  public static EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> MembersFrom(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i, java.math.BigInteger depth, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> acc, boolean first)
  {
    if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((s).length()))) {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
    } else if ((first) && ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) == ('}'))) {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JObject(acc), (i).add(java.math.BigInteger.ONE)));
    } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((i))))).value()) != ('"')) {
      return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
    } else {
      EHBP.Option<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>> _source0 = __default.ParseString(s, (i).add(java.math.BigInteger.ONE), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
      if (_source0.is_None()) {
        return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
      } else {
        dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger> _0___mcc_h0 = ((EHBP.Option_Some<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>>)_source0)._value;
        dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger> _source1 = _0___mcc_h0;
        dafny.DafnySequence<? extends dafny.CodePoint> _1___mcc_h1 = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>)_source1).dtor__0()));
        java.math.BigInteger _2___mcc_h2 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>)_source1).dtor__1()));
        java.math.BigInteger _3_k = _2___mcc_h2;
        dafny.DafnySequence<? extends dafny.CodePoint> _4_name = _1___mcc_h1;
        java.math.BigInteger _5_c = __default.SkipWs(s, _3_k);
        if ((java.util.Objects.equals(_5_c, java.math.BigInteger.valueOf((s).length()))) || ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_5_c))))).value()) != (':'))) {
          return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
        } else {
          EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> _source2 = __default.ParseValue(s, __default.SkipWs(s, (_5_c).add(java.math.BigInteger.ONE)), depth);
          if (_source2.is_None()) {
            return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
          } else {
            dafny.Tuple2<Json, java.math.BigInteger> _6___mcc_h3 = ((EHBP.Option_Some<dafny.Tuple2<Json, java.math.BigInteger>>)_source2)._value;
            dafny.Tuple2<Json, java.math.BigInteger> _source3 = _6___mcc_h3;
            Json _7___mcc_h4 = ((Json)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_source3).dtor__0()));
            java.math.BigInteger _8___mcc_h5 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_source3).dtor__1()));
            java.math.BigInteger _9_k2 = _8___mcc_h5;
            Json _10_v = _7___mcc_h4;
            java.math.BigInteger _11_m = __default.SkipWs(s, _9_k2);
            if (java.util.Objects.equals(_11_m, java.math.BigInteger.valueOf((s).length()))) {
              return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
            } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_11_m))))).value()) == (',')) {
              return __default.MembersFrom(s, __default.SkipWs(s, (_11_m).add(java.math.BigInteger.ONE)), depth, dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>>concatenate(acc, dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> of(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), Json._typeDescriptor()), dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>create(_4_name, _10_v))), false);
            } else if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_11_m))))).value()) == ('}')) {
              return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JObject(dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>>concatenate(acc, dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> of(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), Json._typeDescriptor()), dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>create(_4_name, _10_v)))), (_11_m).add(java.math.BigInteger.ONE)));
            } else {
              return EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER));
            }
          }
        }
      }
    }
  }
  public static EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> ParseMembers(dafny.DafnySequence<? extends dafny.CodePoint> s, java.math.BigInteger i, java.math.BigInteger depth, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> acc, boolean first)
  {
    EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>Default(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
    if(true) {
      dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>[] _0_a;
      java.util.function.Function<java.math.BigInteger, dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> _init0 = ((java.util.function.Function<java.math.BigInteger, dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>>)(_1___v15_boxed0) -> {
        java.math.BigInteger _1___v15 = ((java.math.BigInteger)(java.lang.Object)(_1___v15_boxed0));
        return dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>create(dafny.DafnySequence.asUnicodeString(""), Json.create_JNull());
      });
      dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>[] _nw0 = (dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>[]) dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), Json._typeDescriptor()).newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.ZERO), "Java arrays may be no larger than the maximum 32-bit signed int"));
      for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw0))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
        _nw0[dafny.Helpers.toInt(_i0_0)] = ((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>)(java.lang.Object)(_init0.apply(_i0_0)));
      }
      _0_a = _nw0;
      java.math.BigInteger _2_n = java.math.BigInteger.ZERO;
      java.math.BigInteger _3_j = java.math.BigInteger.ZERO;
      boolean _4_f;
      java.math.BigInteger _rhs0 = java.math.BigInteger.ZERO;
      java.math.BigInteger _rhs1 = i;
      boolean _rhs2 = first;
      _2_n = _rhs0;
      _3_j = _rhs1;
      _4_f = _rhs2;
      while (true) {
        if (java.util.Objects.equals(_3_j, java.math.BigInteger.valueOf((s).length()))) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        if ((_4_f) && ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_3_j))))).value()) == ('}'))) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), dafny.TypeDescriptor.BIG_INTEGER), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JObject(dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>>concatenate(acc, dafny.DafnySequence.fromRawArrayRange(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), Json._typeDescriptor()), (_0_a), 0, dafny.Helpers.toInt((_2_n))))), (_3_j).add(java.math.BigInteger.ONE)));
          return r;
        }
        if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_3_j))))).value()) != ('"')) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        EHBP.Option<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>> _5_rn;
        _5_rn = __default.ParseString(s, (_3_j).add(java.math.BigInteger.ONE), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
        if ((_5_rn).is_None()) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger> _let_tmp_rhs0 = (_5_rn).dtor_value();
        dafny.DafnySequence<? extends dafny.CodePoint> _6_name = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>)_let_tmp_rhs0).dtor__0()));
        java.math.BigInteger _7_k = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, java.math.BigInteger>)_let_tmp_rhs0).dtor__1()));
        java.math.BigInteger _8_c = java.math.BigInteger.ZERO;
        _8_c = __default.SkipWs(s, _7_k);
        if ((java.util.Objects.equals(_8_c, java.math.BigInteger.valueOf((s).length()))) || ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_8_c))))).value()) != (':'))) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> _9_r;
        _9_r = __default.ParseValue(s, __default.SkipWs(s, (_8_c).add(java.math.BigInteger.ONE)), depth);
        if ((_9_r).is_None()) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        dafny.Tuple2<Json, java.math.BigInteger> _let_tmp_rhs1 = (_9_r).dtor_value();
        Json _10_v = ((Json)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_let_tmp_rhs1).dtor__0()));
        java.math.BigInteger _11_k2 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_let_tmp_rhs1).dtor__1()));
        java.math.BigInteger _12_m = java.math.BigInteger.ZERO;
        _12_m = __default.SkipWs(s, _11_k2);
        if (java.util.Objects.equals(_12_m, java.math.BigInteger.valueOf((s).length()))) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_12_m))))).value()) == ('}')) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_Some(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()), dafny.Tuple2.<Json, java.math.BigInteger>create(Json.create_JObject(dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>>concatenate(dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>>concatenate(acc, dafny.DafnySequence.fromRawArrayRange(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), Json._typeDescriptor()), (_0_a), 0, dafny.Helpers.toInt((_2_n)))), dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> of(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), Json._typeDescriptor()), dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>create(_6_name, _10_v)))), (_12_m).add(java.math.BigInteger.ONE)));
          return r;
        }
        if ((((dafny.CodePoint)((s).select(dafny.Helpers.toInt((_12_m))))).value()) != (',')) {
          r = EHBP.Option.<dafny.Tuple2<Json, java.math.BigInteger>>create_None(dafny.Tuple2.<Json, java.math.BigInteger>_typeDescriptor(Json._typeDescriptor(), _System.nat._typeDescriptor()));
          return r;
        }
        Object _out0;
        _out0 = __default.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>>Append(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), Json._typeDescriptor()), _0_a, _2_n, dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, Json>create(_6_name, _10_v));
        _0_a = ((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>[])(java.lang.Object)(_out0));
        java.math.BigInteger _rhs3 = (_2_n).add(java.math.BigInteger.ONE);
        java.math.BigInteger _rhs4 = __default.SkipWs(s, (_12_m).add(java.math.BigInteger.ONE));
        boolean _rhs5 = false;
        _2_n = _rhs3;
        _3_j = _rhs4;
        _4_f = _rhs5;
      }
    }
    return r;
  }
  public static <__T> java.lang.Object Append(dafny.TypeDescriptor<__T> _td___T, java.lang.Object a, java.math.BigInteger n, __T v)
  {
    java.lang.Object b = (java.lang.Object)_td___T.newArray(0);
    if(true) {
      if ((n).compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength((a)))) < 0) {
        _td___T.setArrayElement((a), dafny.Helpers.toInt(((n)).intValue()), v);
        b = a;
        return b;
      }
      java.util.function.Function<java.math.BigInteger, __T> _init0 = ((dafny.Function3<java.math.BigInteger, java.lang.Object, __T, java.util.function.Function<java.math.BigInteger, __T>>)(_0_n, _1_a, _2_v) -> {return ((java.util.function.Function<java.math.BigInteger, __T>)(_3_k_boxed0) -> {
        java.math.BigInteger _3_k = ((java.math.BigInteger)(java.lang.Object)(_3_k_boxed0));
        return ((((_3_k).signum() != -1) && ((_3_k).compareTo(_0_n) < 0)) ? (_td___T.getArrayElement((_1_a), (dafny.Helpers.toInt((_3_k))))) : (_2_v));
      });}).apply(n, a, v);
      java.lang.Object _nw0 = (java.lang.Object) _td___T.newArray(dafny.Helpers.toIntChecked((((java.math.BigInteger.valueOf(2L)).multiply(n)).add(java.math.BigInteger.ONE)), "Java arrays may be no larger than the maximum 32-bit signed int"));
      for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw0))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
        _td___T.setArrayElement(_nw0, dafny.Helpers.toInt(_i0_0), ((__T)(java.lang.Object)(_init0.apply(_i0_0))));
      }
      b = _nw0;
    }
    return b;
  }
  public static EHBP.Option<Json> ParseJson(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    EHBP.Option<dafny.Tuple2<Json, java.math.BigInteger>> _source0 = __default.ParseValue(s, __default.SkipWs(s, java.math.BigInteger.ZERO), java.math.BigInteger.ZERO);
    if (_source0.is_None()) {
      return EHBP.Option.<Json>create_None(Json._typeDescriptor());
    } else {
      dafny.Tuple2<Json, java.math.BigInteger> _0___mcc_h0 = ((EHBP.Option_Some<dafny.Tuple2<Json, java.math.BigInteger>>)_source0)._value;
      dafny.Tuple2<Json, java.math.BigInteger> _source1 = _0___mcc_h0;
      Json _1___mcc_h1 = ((Json)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_source1).dtor__0()));
      java.math.BigInteger _2___mcc_h2 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<Json, java.math.BigInteger>)_source1).dtor__1()));
      java.math.BigInteger _3_j = _2___mcc_h2;
      Json _4_v = _1___mcc_h1;
      if (java.util.Objects.equals(__default.SkipWs(s, _3_j), java.math.BigInteger.valueOf((s).length()))) {
        return EHBP.Option.<Json>create_Some(Json._typeDescriptor(), _4_v);
      } else {
        return EHBP.Option.<Json>create_None(Json._typeDescriptor());
      }
    }
  }
  public static EHBP.Option<Json> Member(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> members, dafny.DafnySequence<? extends dafny.CodePoint> name)
  {
    return __default.MemberFrom(members, java.math.BigInteger.valueOf((members).length()), name);
  }
  public static EHBP.Option<Json> MemberFrom(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> members, java.math.BigInteger n, dafny.DafnySequence<? extends dafny.CodePoint> name)
  {
    TAIL_CALL_START: while (true) {
      if ((n).signum() == 0) {
        return EHBP.Option.<Json>create_None(Json._typeDescriptor());
      } else if (((((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>)(java.lang.Object)((members).select(dafny.Helpers.toInt(((n).subtract(java.math.BigInteger.ONE))))))).dtor__0()).equals(name)) {
        return EHBP.Option.<Json>create_Some(Json._typeDescriptor(), (((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>)(java.lang.Object)((members).select(dafny.Helpers.toInt(((n).subtract(java.math.BigInteger.ONE))))))).dtor__1());
      } else {
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> _in0 = members;
        java.math.BigInteger _in1 = (n).subtract(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends dafny.CodePoint> _in2 = name;
        members = _in0;
        n = _in1;
        name = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>> StringMember(dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> members, dafny.DafnySequence<? extends dafny.CodePoint> name)
  {
    EHBP.Option<Json> _source0 = __default.Member(members, name);
    if (_source0.is_None()) {
      return EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    } else {
      Json _0___mcc_h0 = ((EHBP.Option_Some<Json>)_source0)._value;
      Json _source1 = _0___mcc_h0;
      if (_source1.is_JNull()) {
        return EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
      } else if (_source1.is_JBool()) {
        boolean _1___mcc_h2 = ((EHBPEvents.Json_JBool)_source1)._b;
        return EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
      } else if (_source1.is_JNumber()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h4 = ((EHBPEvents.Json_JNumber)_source1)._raw;
        return EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
      } else if (_source1.is_JString()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _3___mcc_h6 = ((EHBPEvents.Json_JString)_source1)._s;
        dafny.DafnySequence<? extends dafny.CodePoint> _4_v = _3___mcc_h6;
        return EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_Some(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), _4_v);
      } else if (_source1.is_JArray()) {
        dafny.DafnySequence<? extends Json> _5___mcc_h8 = ((EHBPEvents.Json_JArray)_source1)._items;
        return EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
      } else {
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> _6___mcc_h10 = ((EHBPEvents.Json_JObject)_source1)._members;
        return EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
      }
    }
  }
  public static boolean Cont(byte b) {
    return (java.lang.Integer.compareUnsigned((byte) 128, b) <= 0) && (java.lang.Integer.compareUnsigned(b, (byte) 191) <= 0);
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> Utf8From(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger i, dafny.DafnySequence<? extends dafny.CodePoint> acc)
  {
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((b).length()))) {
        return acc;
      } else {
        byte _0_c = ((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((i)))));
        if (java.lang.Integer.compareUnsigned(_0_c, (byte) 128) < 0) {
          dafny.DafnySequence<? extends java.lang.Byte> _in0 = b;
          java.math.BigInteger _in1 = (i).add(java.math.BigInteger.ONE);
          dafny.DafnySequence<? extends dafny.CodePoint> _in2 = dafny.DafnySequence.<dafny.CodePoint>concatenate(acc, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)java.lang.Byte.toUnsignedInt(_0_c))));
          b = _in0;
          i = _in1;
          acc = _in2;
          continue TAIL_CALL_START;
        } else if ((((java.lang.Integer.compareUnsigned((byte) 194, _0_c) <= 0) && (java.lang.Integer.compareUnsigned(_0_c, (byte) 223) <= 0)) && (((i).add(java.math.BigInteger.valueOf(2L))).compareTo(java.math.BigInteger.valueOf((b).length())) <= 0)) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE))))))))) {
          dafny.DafnySequence<? extends java.lang.Byte> _in3 = b;
          java.math.BigInteger _in4 = (i).add(java.math.BigInteger.valueOf(2L));
          dafny.DafnySequence<? extends dafny.CodePoint> _in5 = dafny.DafnySequence.<dafny.CodePoint>concatenate(acc, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt(((((dafny.Helpers.unsignedToBigInteger(_0_c)).subtract(java.math.BigInteger.valueOf(192L))).multiply(java.math.BigInteger.valueOf(64L))).add((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE)))))))).subtract(java.math.BigInteger.valueOf(128L))))))));
          b = _in3;
          i = _in4;
          acc = _in5;
          continue TAIL_CALL_START;
        } else if (((((java.lang.Integer.compareUnsigned((byte) 224, _0_c) <= 0) && (java.lang.Integer.compareUnsigned(_0_c, (byte) 239) <= 0)) && (((i).add(java.math.BigInteger.valueOf(3L))).compareTo(java.math.BigInteger.valueOf((b).length())) <= 0)) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE))))))))) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(2L)))))))))) {
          java.math.BigInteger _1_cp = ((((dafny.Helpers.unsignedToBigInteger(_0_c)).subtract(java.math.BigInteger.valueOf(224L))).multiply(java.math.BigInteger.valueOf(4096L))).add(((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE)))))))).subtract(java.math.BigInteger.valueOf(128L))).multiply(java.math.BigInteger.valueOf(64L)))).add((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(2L))))))))).subtract(java.math.BigInteger.valueOf(128L)));
          if (((_1_cp).compareTo(java.math.BigInteger.valueOf(2048L)) < 0) || (((java.math.BigInteger.valueOf(55296L)).compareTo(_1_cp) <= 0) && ((_1_cp).compareTo(java.math.BigInteger.valueOf(57343L)) <= 0))) {
            dafny.DafnySequence<? extends java.lang.Byte> _in6 = b;
            java.math.BigInteger _in7 = (i).add(java.math.BigInteger.ONE);
            dafny.DafnySequence<? extends dafny.CodePoint> _in8 = dafny.DafnySequence.<dafny.CodePoint>concatenate(acc, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((java.math.BigInteger.valueOf(65533L))))));
            b = _in6;
            i = _in7;
            acc = _in8;
            continue TAIL_CALL_START;
          } else {
            dafny.DafnySequence<? extends java.lang.Byte> _in9 = b;
            java.math.BigInteger _in10 = (i).add(java.math.BigInteger.valueOf(3L));
            dafny.DafnySequence<? extends dafny.CodePoint> _in11 = dafny.DafnySequence.<dafny.CodePoint>concatenate(acc, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((_1_cp)))));
            b = _in9;
            i = _in10;
            acc = _in11;
            continue TAIL_CALL_START;
          }
        } else if ((((((java.lang.Integer.compareUnsigned((byte) 240, _0_c) <= 0) && (java.lang.Integer.compareUnsigned(_0_c, (byte) 244) <= 0)) && (((i).add(java.math.BigInteger.valueOf(4L))).compareTo(java.math.BigInteger.valueOf((b).length())) <= 0)) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE))))))))) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(2L)))))))))) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(3L)))))))))) {
          java.math.BigInteger _2_cp = (((((dafny.Helpers.unsignedToBigInteger(_0_c)).subtract(java.math.BigInteger.valueOf(240L))).multiply(java.math.BigInteger.valueOf(262144L))).add(((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.ONE)))))))).subtract(java.math.BigInteger.valueOf(128L))).multiply(java.math.BigInteger.valueOf(4096L)))).add(((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(2L))))))))).subtract(java.math.BigInteger.valueOf(128L))).multiply(java.math.BigInteger.valueOf(64L)))).add((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(3L))))))))).subtract(java.math.BigInteger.valueOf(128L)));
          if (((_2_cp).compareTo(java.math.BigInteger.valueOf(65536L)) < 0) || ((_2_cp).compareTo(java.math.BigInteger.valueOf(1114111L)) > 0)) {
            dafny.DafnySequence<? extends java.lang.Byte> _in12 = b;
            java.math.BigInteger _in13 = (i).add(java.math.BigInteger.ONE);
            dafny.DafnySequence<? extends dafny.CodePoint> _in14 = dafny.DafnySequence.<dafny.CodePoint>concatenate(acc, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((java.math.BigInteger.valueOf(65533L))))));
            b = _in12;
            i = _in13;
            acc = _in14;
            continue TAIL_CALL_START;
          } else {
            dafny.DafnySequence<? extends java.lang.Byte> _in15 = b;
            java.math.BigInteger _in16 = (i).add(java.math.BigInteger.valueOf(4L));
            dafny.DafnySequence<? extends dafny.CodePoint> _in17 = dafny.DafnySequence.<dafny.CodePoint>concatenate(acc, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((_2_cp)))));
            b = _in15;
            i = _in16;
            acc = _in17;
            continue TAIL_CALL_START;
          }
        } else {
          dafny.DafnySequence<? extends java.lang.Byte> _in18 = b;
          java.math.BigInteger _in19 = (i).add(java.math.BigInteger.ONE);
          dafny.DafnySequence<? extends dafny.CodePoint> _in20 = dafny.DafnySequence.<dafny.CodePoint>concatenate(acc, dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf((int)dafny.Helpers.toInt((java.math.BigInteger.valueOf(65533L))))));
          b = _in18;
          i = _in19;
          acc = _in20;
          continue TAIL_CALL_START;
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> Utf8(dafny.DafnySequence<? extends java.lang.Byte> b)
  {
    dafny.DafnySequence<? extends dafny.CodePoint> _hresult = dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR);
    int[] _0_a;
    java.util.function.Function<java.math.BigInteger, dafny.CodePoint> _init0 = ((java.util.function.Function<java.math.BigInteger, dafny.CodePoint>)(_1___v17_boxed0) -> {
      java.math.BigInteger _1___v17 = ((java.math.BigInteger)(java.lang.Object)(_1___v17_boxed0));
      return dafny.CodePoint.valueOf(' ');
    });
    int[] _nw0 = (int[]) dafny.TypeDescriptor.UNICODE_CHAR.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf((b).length())), "Java arrays may be no larger than the maximum 32-bit signed int"));
    for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw0))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
      _nw0[dafny.Helpers.toInt(_i0_0)] = ((dafny.CodePoint)(_init0.apply(_i0_0))).value();
    }
    _0_a = _nw0;
    java.math.BigInteger _2_i = java.math.BigInteger.ZERO;
    java.math.BigInteger _3_n = java.math.BigInteger.ZERO;
    java.math.BigInteger _rhs0 = java.math.BigInteger.ZERO;
    java.math.BigInteger _rhs1 = java.math.BigInteger.ZERO;
    _2_i = _rhs0;
    _3_n = _rhs1;
    while ((_2_i).compareTo(java.math.BigInteger.valueOf((b).length())) < 0) {
      byte _4_c;
      _4_c = ((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((_2_i)))));
      java.math.BigInteger _5_cp = java.math.BigInteger.ZERO;
      java.math.BigInteger _6_w = java.math.BigInteger.ZERO;
      java.math.BigInteger _rhs2 = java.math.BigInteger.valueOf(65533L);
      java.math.BigInteger _rhs3 = java.math.BigInteger.ONE;
      _5_cp = _rhs2;
      _6_w = _rhs3;
      if (java.lang.Integer.compareUnsigned(_4_c, (byte) 128) < 0) {
        _5_cp = dafny.Helpers.unsignedToBigInteger(_4_c);
      } else if ((((java.lang.Integer.compareUnsigned((byte) 194, _4_c) <= 0) && (java.lang.Integer.compareUnsigned(_4_c, (byte) 223) <= 0)) && (((_2_i).add(java.math.BigInteger.valueOf(2L))).compareTo(java.math.BigInteger.valueOf((b).length())) <= 0)) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.ONE))))))))) {
        java.math.BigInteger _rhs4 = (((dafny.Helpers.unsignedToBigInteger(_4_c)).subtract(java.math.BigInteger.valueOf(192L))).multiply(java.math.BigInteger.valueOf(64L))).add((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.ONE)))))))).subtract(java.math.BigInteger.valueOf(128L)));
        java.math.BigInteger _rhs5 = java.math.BigInteger.valueOf(2L);
        _5_cp = _rhs4;
        _6_w = _rhs5;
      } else if (((((java.lang.Integer.compareUnsigned((byte) 224, _4_c) <= 0) && (java.lang.Integer.compareUnsigned(_4_c, (byte) 239) <= 0)) && (((_2_i).add(java.math.BigInteger.valueOf(3L))).compareTo(java.math.BigInteger.valueOf((b).length())) <= 0)) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.ONE))))))))) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.valueOf(2L)))))))))) {
        java.math.BigInteger _7_v = java.math.BigInteger.ZERO;
        _7_v = ((((dafny.Helpers.unsignedToBigInteger(_4_c)).subtract(java.math.BigInteger.valueOf(224L))).multiply(java.math.BigInteger.valueOf(4096L))).add(((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.ONE)))))))).subtract(java.math.BigInteger.valueOf(128L))).multiply(java.math.BigInteger.valueOf(64L)))).add((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.valueOf(2L))))))))).subtract(java.math.BigInteger.valueOf(128L)));
        if (!(((_7_v).compareTo(java.math.BigInteger.valueOf(2048L)) < 0) || (((java.math.BigInteger.valueOf(55296L)).compareTo(_7_v) <= 0) && ((_7_v).compareTo(java.math.BigInteger.valueOf(57343L)) <= 0)))) {
          java.math.BigInteger _rhs6 = _7_v;
          java.math.BigInteger _rhs7 = java.math.BigInteger.valueOf(3L);
          _5_cp = _rhs6;
          _6_w = _rhs7;
        }
      } else if ((((((java.lang.Integer.compareUnsigned((byte) 240, _4_c) <= 0) && (java.lang.Integer.compareUnsigned(_4_c, (byte) 244) <= 0)) && (((_2_i).add(java.math.BigInteger.valueOf(4L))).compareTo(java.math.BigInteger.valueOf((b).length())) <= 0)) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.ONE))))))))) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.valueOf(2L)))))))))) && (__default.Cont(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.valueOf(3L)))))))))) {
        java.math.BigInteger _8_v = java.math.BigInteger.ZERO;
        _8_v = (((((dafny.Helpers.unsignedToBigInteger(_4_c)).subtract(java.math.BigInteger.valueOf(240L))).multiply(java.math.BigInteger.valueOf(262144L))).add(((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.ONE)))))))).subtract(java.math.BigInteger.valueOf(128L))).multiply(java.math.BigInteger.valueOf(4096L)))).add(((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.valueOf(2L))))))))).subtract(java.math.BigInteger.valueOf(128L))).multiply(java.math.BigInteger.valueOf(64L)))).add((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_2_i).add(java.math.BigInteger.valueOf(3L))))))))).subtract(java.math.BigInteger.valueOf(128L)));
        if (!(((_8_v).compareTo(java.math.BigInteger.valueOf(65536L)) < 0) || ((_8_v).compareTo(java.math.BigInteger.valueOf(1114111L)) > 0))) {
          java.math.BigInteger _rhs8 = _8_v;
          java.math.BigInteger _rhs9 = java.math.BigInteger.valueOf(4L);
          _5_cp = _rhs8;
          _6_w = _rhs9;
        }
      }
      (_0_a)[dafny.Helpers.toInt(((_3_n)).intValue())] = (int)dafny.Helpers.toInt((_5_cp));
      java.math.BigInteger _rhs10 = (_2_i).add(_6_w);
      java.math.BigInteger _rhs11 = (_3_n).add(java.math.BigInteger.ONE);
      _2_i = _rhs10;
      _3_n = _rhs11;
    }
    _hresult = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.UNICODE_CHAR, (_0_a), 0, dafny.Helpers.toInt((_3_n)));
    return _hresult;
  }
  public static dafny.Tuple3<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>> ParseProblem(dafny.DafnySequence<? extends java.lang.Byte> body) {
    EHBP.Option<Json> _source0 = __default.ParseJson(__default.Utf8(body));
    if (_source0.is_None()) {
      return dafny.Tuple3.<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(false, EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
    } else {
      Json _0___mcc_h0 = ((EHBP.Option_Some<Json>)_source0)._value;
      Json _source1 = _0___mcc_h0;
      if (_source1.is_JNull()) {
        return dafny.Tuple3.<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(false, EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else if (_source1.is_JBool()) {
        boolean _1___mcc_h2 = ((EHBPEvents.Json_JBool)_source1)._b;
        return dafny.Tuple3.<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(false, EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else if (_source1.is_JNumber()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h4 = ((EHBPEvents.Json_JNumber)_source1)._raw;
        return dafny.Tuple3.<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(false, EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else if (_source1.is_JString()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _3___mcc_h6 = ((EHBPEvents.Json_JString)_source1)._s;
        return dafny.Tuple3.<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(false, EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else if (_source1.is_JArray()) {
        dafny.DafnySequence<? extends Json> _4___mcc_h8 = ((EHBPEvents.Json_JArray)_source1)._items;
        return dafny.Tuple3.<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(false, EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> _5___mcc_h10 = ((EHBPEvents.Json_JObject)_source1)._members;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> _6_members = _5___mcc_h10;
        return dafny.Tuple3.<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(true, __default.StringMember(_6_members, dafny.DafnySequence.asUnicodeString("type")), __default.StringMember(_6_members, dafny.DafnySequence.asUnicodeString("title")));
      }
    }
  }
  public static dafny.Tuple2<EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>> ParseToken(dafny.DafnySequence<? extends dafny.CodePoint> json) {
    EHBP.Option<Json> _source0 = __default.ParseJson(json);
    if (_source0.is_None()) {
      return dafny.Tuple2.<EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
    } else {
      Json _0___mcc_h0 = ((EHBP.Option_Some<Json>)_source0)._value;
      Json _source1 = _0___mcc_h0;
      if (_source1.is_JNull()) {
        return dafny.Tuple2.<EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else if (_source1.is_JBool()) {
        boolean _1___mcc_h2 = ((EHBPEvents.Json_JBool)_source1)._b;
        return dafny.Tuple2.<EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else if (_source1.is_JNumber()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h4 = ((EHBPEvents.Json_JNumber)_source1)._raw;
        return dafny.Tuple2.<EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else if (_source1.is_JString()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _3___mcc_h6 = ((EHBPEvents.Json_JString)_source1)._s;
        return dafny.Tuple2.<EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else if (_source1.is_JArray()) {
        dafny.DafnySequence<? extends Json> _4___mcc_h8 = ((EHBPEvents.Json_JArray)_source1)._items;
        return dafny.Tuple2.<EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> _5___mcc_h10 = ((EHBPEvents.Json_JObject)_source1)._members;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, Json>> _6_members = _5___mcc_h10;
        return dafny.Tuple2.<EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(__default.StringMember(_6_members, dafny.DafnySequence.asUnicodeString("exportedSecret")), __default.StringMember(_6_members, dafny.DafnySequence.asUnicodeString("requestEnc")));
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> Escape(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    dafny.DafnySequence<? extends dafny.CodePoint> _0___accumulator = dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR);
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((s).length())).signum() == 0) {
        return dafny.DafnySequence.<dafny.CodePoint>concatenate(_0___accumulator, dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
      } else {
        int _1_c = ((dafny.CodePoint)((s).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))).value();
        _0___accumulator = dafny.DafnySequence.<dafny.CodePoint>concatenate(_0___accumulator, (((_1_c) == ('"')) ? (dafny.DafnySequence.asUnicodeString("\\\"")) : ((((_1_c) == ('\\')) ? (dafny.DafnySequence.asUnicodeString("\\\\")) : ((((java.math.BigInteger.valueOf(_1_c)).compareTo(java.math.BigInteger.valueOf(32L)) < 0) ? (dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.asUnicodeString("\\u00"), dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf(((dafny.CodePoint)((EHBP.__default.HexDigits()).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanDivision(java.math.BigInteger.valueOf(_1_c), java.math.BigInteger.valueOf(16L))))))).value()), dafny.CodePoint.valueOf(((dafny.CodePoint)((EHBP.__default.HexDigits()).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanModulus(java.math.BigInteger.valueOf(_1_c), java.math.BigInteger.valueOf(16L))))))).value())))) : (dafny.DafnySequence.<dafny.CodePoint> of(dafny.TypeDescriptor.UNICODE_CHAR, dafny.CodePoint.valueOf(_1_c)))))))));
        dafny.DafnySequence<? extends dafny.CodePoint> _in0 = (s).drop(java.math.BigInteger.ONE);
        s = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> FormatToken(dafny.DafnySequence<? extends dafny.CodePoint> exportedSecretHex, dafny.DafnySequence<? extends dafny.CodePoint> requestEncHex)
  {
    return dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.<dafny.CodePoint>concatenate(dafny.DafnySequence.asUnicodeString("{\"exportedSecret\":\""), __default.Escape(exportedSecretHex)), dafny.DafnySequence.asUnicodeString("\",\"requestEnc\":\"")), __default.Escape(requestEncHex)), dafny.DafnySequence.asUnicodeString("\"}"));
  }
  public static SessionStore SessionApply(SessionStore store, SessionAction action)
  {
    SessionAction _source0 = action;
    if (_source0.is_Begin()) {
      return SessionStore.create(((((store).dtor_generation()) == (__default.MaxSeq())) ? ((long) 0L) : ((long) (long) (((store).dtor_generation()) + ((long) 1L)))), EHBP.Option.<EHBP.Token>create_None(EHBP.Token._typeDescriptor()));
    } else if (_source0.is_Publish()) {
      long _0___mcc_h0 = ((EHBPEvents.SessionAction_Publish)_source0)._generation;
      EHBP.Token _1___mcc_h1 = ((EHBPEvents.SessionAction_Publish)_source0)._token;
      EHBP.Token _2_token = _1___mcc_h1;
      long _3_generation = _0___mcc_h0;
      if ((_3_generation) == ((store).dtor_generation())) {
        SessionStore _4_dt__update__tmp_h0 = store;
        EHBP.Option<EHBP.Token> _5_dt__update_htoken_h0 = EHBP.Option.<EHBP.Token>create_Some(EHBP.Token._typeDescriptor(), _2_token);
        return SessionStore.create((_4_dt__update__tmp_h0).dtor_generation(), _5_dt__update_htoken_h0);
      } else {
        return store;
      }
    } else {
      long _6___mcc_h2 = ((EHBPEvents.SessionAction_Clear)_source0)._generation;
      long _7_generation = _6___mcc_h2;
      if ((_7_generation) == ((store).dtor_generation())) {
        SessionStore _8_dt__update__tmp_h1 = store;
        EHBP.Option<EHBP.Token> _9_dt__update_htoken_h1 = EHBP.Option.<EHBP.Token>create_None(EHBP.Token._typeDescriptor());
        return SessionStore.create((_8_dt__update__tmp_h1).dtor_generation(), _9_dt__update_htoken_h1);
      } else {
        return store;
      }
    }
  }
  public static dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>> Frames(Dec d, dafny.DafnySequence<? extends java.lang.Byte> buf, java.math.BigInteger i, dafny.DafnySequence<? extends EHBP.Framed> acc)
  {
    TAIL_CALL_START: while (true) {
      dafny.DafnySequence<? extends java.lang.Byte> _pat_let_tv0 = buf;
      java.math.BigInteger _pat_let_tv1 = i;
      dafny.DafnySequence<? extends java.lang.Byte> _pat_let_tv2 = buf;
      java.math.BigInteger _pat_let_tv3 = i;
      if (((java.math.BigInteger.valueOf((buf).length())).subtract(i)).compareTo(java.math.BigInteger.valueOf(4L)) < 0) {
        return dafny.Tuple3.<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>create(acc, ((Dec)(java.lang.Object)(dafny.Helpers.<Dec, Dec>Let(d, boxed50 -> {
  Dec _pat_let25_0 = ((Dec)(java.lang.Object)(boxed50));
  return ((Dec)(java.lang.Object)(dafny.Helpers.<Dec, Dec>Let(_pat_let25_0, boxed51 -> {
    Dec _0_dt__update__tmp_h0 = ((Dec)(java.lang.Object)(boxed51));
    return ((Dec)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Dec>Let((_pat_let_tv0).drop(_pat_let_tv1), boxed52 -> {
      dafny.DafnySequence<? extends java.lang.Byte> _pat_let26_0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed52));
      return ((Dec)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Dec>Let(_pat_let26_0, boxed53 -> {
        dafny.DafnySequence<? extends java.lang.Byte> _1_dt__update_hpending_h0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed53));
        return Dec.create(_1_dt__update_hpending_h0, (_0_dt__update__tmp_h0).dtor_next(), (_0_dt__update__tmp_h0).dtor_authenticated(), (_0_dt__update__tmp_h0).dtor_requireFrame());
      }
      )));
    }
    )));
  }
  )));
}
))), EHBP.Option.<EHBP.Code>create_None(EHBP.Code._typeDescriptor()));
      } else {
        int _2_length = EHBP.__default.U32(buf, i);
        if (((_2_length) == 0 ? 0 : 1) == 0) {
          Dec _in0 = d;
          dafny.DafnySequence<? extends java.lang.Byte> _in1 = buf;
          java.math.BigInteger _in2 = (i).add(java.math.BigInteger.valueOf(4L));
          dafny.DafnySequence<? extends EHBP.Framed> _in3 = acc;
          d = _in0;
          buf = _in1;
          i = _in2;
          acc = _in3;
          continue TAIL_CALL_START;
        } else if (java.lang.Integer.compareUnsigned(_2_length, EHBP.__default.MaxChunkBytes()) > 0) {
          return dafny.Tuple3.<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>create(acc, d, EHBP.Option.<EHBP.Code>create_Some(EHBP.Code._typeDescriptor(), EHBP.Code.create_ChunkTooLarge()));
        } else if (((java.math.BigInteger.valueOf((buf).length())).subtract(i)).compareTo((java.math.BigInteger.valueOf(4L)).add(dafny.Helpers.unsignedToBigInteger(_2_length))) < 0) {
          return dafny.Tuple3.<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>create(acc, ((Dec)(java.lang.Object)(dafny.Helpers.<Dec, Dec>Let(d, boxed54 -> {
  Dec _pat_let27_0 = ((Dec)(java.lang.Object)(boxed54));
  return ((Dec)(java.lang.Object)(dafny.Helpers.<Dec, Dec>Let(_pat_let27_0, boxed55 -> {
    Dec _3_dt__update__tmp_h1 = ((Dec)(java.lang.Object)(boxed55));
    return ((Dec)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Dec>Let((_pat_let_tv2).drop(_pat_let_tv3), boxed56 -> {
      dafny.DafnySequence<? extends java.lang.Byte> _pat_let28_0 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed56));
      return ((Dec)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends java.lang.Byte>, Dec>Let(_pat_let28_0, boxed57 -> {
        dafny.DafnySequence<? extends java.lang.Byte> _4_dt__update_hpending_h1 = ((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)(boxed57));
        return Dec.create(_4_dt__update_hpending_h1, (_3_dt__update__tmp_h1).dtor_next(), (_3_dt__update__tmp_h1).dtor_authenticated(), (_3_dt__update__tmp_h1).dtor_requireFrame());
      }
      )));
    }
    )));
  }
  )));
}
))), EHBP.Option.<EHBP.Code>create_None(EHBP.Code._typeDescriptor()));
        } else if (((d).dtor_next()) == (__default.MaxSeq())) {
          return dafny.Tuple3.<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>create(acc, d, EHBP.Option.<EHBP.Code>create_Some(EHBP.Code._typeDescriptor(), EHBP.Code.create_SequenceOverflow()));
        } else {
          Dec _in4 = Dec.create(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), (long) (long) (((d).dtor_next()) + ((long) 1L)), true, (d).dtor_requireFrame());
          dafny.DafnySequence<? extends java.lang.Byte> _in5 = buf;
          java.math.BigInteger _in6 = ((i).add(java.math.BigInteger.valueOf(4L))).add(dafny.Helpers.unsignedToBigInteger(_2_length));
          dafny.DafnySequence<? extends EHBP.Framed> _in7 = dafny.DafnySequence.<EHBP.Framed>concatenate(acc, dafny.DafnySequence.<EHBP.Framed> of(EHBP.Framed._typeDescriptor(), EHBP.Framed.create((d).dtor_next(), (buf).subsequence(dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(4L)))), dafny.Helpers.toInt((((i).add(java.math.BigInteger.valueOf(4L))).add(dafny.Helpers.unsignedToBigInteger(_2_length))))))));
          d = _in4;
          buf = _in5;
          i = _in6;
          acc = _in7;
          continue TAIL_CALL_START;
        }
      }
    }
  }
  public static java.math.BigInteger FrameNeed(dafny.DafnySequence<? extends java.lang.Byte> pending) {
    if ((java.math.BigInteger.valueOf((pending).length())).compareTo(java.math.BigInteger.valueOf(4L)) < 0) {
      return (java.math.BigInteger.valueOf(4L)).subtract(java.math.BigInteger.valueOf((pending).length()));
    } else {
      java.math.BigInteger _0_whole = (java.math.BigInteger.valueOf(4L)).add(dafny.Helpers.unsignedToBigInteger(EHBP.__default.U32(pending, java.math.BigInteger.ZERO)));
      if ((_0_whole).compareTo(java.math.BigInteger.valueOf((pending).length())) > 0) {
        return (_0_whole).subtract(java.math.BigInteger.valueOf((pending).length()));
      } else {
        return java.math.BigInteger.ONE;
      }
    }
  }
  public static dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>> Push(Dec d, dafny.DafnySequence<? extends java.lang.Byte> data)
  {
    return __default.PushFrom(d, data, java.math.BigInteger.ZERO, dafny.DafnySequence.<EHBP.Framed> empty(EHBP.Framed._typeDescriptor()));
  }
  public static dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>> PushFrom(Dec d, dafny.DafnySequence<? extends java.lang.Byte> data, java.math.BigInteger i, dafny.DafnySequence<? extends EHBP.Framed> acc)
  {
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf(((d).dtor_pending()).length())).signum() == 0) {
        return __default.Frames(d, data, i, acc);
      } else if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((data).length()))) {
        return dafny.Tuple3.<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>create(acc, d, EHBP.Option.<EHBP.Code>create_None(EHBP.Code._typeDescriptor()));
      } else {
        java.math.BigInteger _0_take = __default.Min((java.math.BigInteger.valueOf((data).length())).subtract(i), __default.FrameNeed((d).dtor_pending()));
        dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>> _let_tmp_rhs0 = __default.Frames(d, dafny.DafnySequence.<java.lang.Byte>concatenate((d).dtor_pending(), (data).subsequence(dafny.Helpers.toInt((i)), dafny.Helpers.toInt(((i).add(_0_take))))), java.math.BigInteger.ZERO, acc);
        dafny.DafnySequence<? extends EHBP.Framed> _1_frames = ((dafny.DafnySequence<? extends EHBP.Framed>)(java.lang.Object)(((dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>)_let_tmp_rhs0).dtor__0()));
        Dec _2_next = ((Dec)(java.lang.Object)(((dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>)_let_tmp_rhs0).dtor__1()));
        EHBP.Option<EHBP.Code> _3_err = ((EHBP.Option<EHBP.Code>)(java.lang.Object)(((dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>)_let_tmp_rhs0).dtor__2()));
        if ((_3_err).is_Some()) {
          return dafny.Tuple3.<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>create(_1_frames, _2_next, _3_err);
        } else {
          Dec _in0 = _2_next;
          dafny.DafnySequence<? extends java.lang.Byte> _in1 = data;
          java.math.BigInteger _in2 = (i).add(_0_take);
          dafny.DafnySequence<? extends EHBP.Framed> _in3 = _1_frames;
          d = _in0;
          data = _in1;
          i = _in2;
          acc = _in3;
          continue TAIL_CALL_START;
        }
      }
    }
  }
  public static EHBP.Option<EHBP.Code> Finish(Dec d) {
    if (((java.math.BigInteger.valueOf(((d).dtor_pending()).length())).signum() != 0) || (((d).dtor_requireFrame()) && (!((d).dtor_authenticated())))) {
      return EHBP.Option.<EHBP.Code>create_Some(EHBP.Code._typeDescriptor(), EHBP.Code.create_FramingTruncated());
    } else {
      return EHBP.Option.<EHBP.Code>create_None(EHBP.Code._typeDescriptor());
    }
  }
  public static State Initial(EHBP.Origin origin, dafny.DafnySequence<? extends java.lang.Byte> publicKey)
  {
    return State.create(Phase.create_Idle(), origin, publicKey, dafny.DafnySequence.asUnicodeString(""), dafny.DafnySequence.asUnicodeString(""), dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> empty(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))), (long) 0L, false, EHBP.Token.create(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor())), __default.NoCtx());
  }
  public static State ResponseOnly(EHBP.Origin origin, EHBP.Token token)
  {
    return State.create(Phase.create_Exchanging(Upload.create_UpDone(), Response.create_AwaitHead(true)), origin, dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.asUnicodeString(""), dafny.DafnySequence.asUnicodeString(""), dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> empty(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))), (long) 0L, false, token, __default.NoCtx());
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> DecryptStart(EHBP.Token token, java.math.BigInteger status, dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> headers)
  {
    return __default.Step(__default.ResponseOnly(__default.NoOrigin(), token), Event.create_ResponseHead(status, headers, false));
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> DeriveStart(EHBP.Token token, dafny.DafnySequence<? extends java.lang.Byte> responseNonce)
  {
    return __default.Step(__default.ResponseOnly(__default.NoOrigin(), token), Event.create_ResponseHead(java.math.BigInteger.valueOf(200L), dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> of(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>create(EHBP.__default.ResponseNonceHeader(), EHBP.__default.EncodeHex(responseNonce))), false));
  }
  public static EHBP.Option<dafny.Tuple2<dafny.DafnySequence<? extends java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>>> KeysOf(State s) {
    if ((((s).dtor_phase()).is_Exchanging()) && ((((s).dtor_phase()).dtor_response()).is_Body())) {
      return EHBP.Option.<dafny.Tuple2<dafny.DafnySequence<? extends java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>>>create_Some(dafny.Tuple2.<dafny.DafnySequence<? extends java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>>_typeDescriptor(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(EHBP.uint8._typeDescriptor())), dafny.Tuple2.<dafny.DafnySequence<? extends java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>>create(((((s).dtor_phase()).dtor_response()).dtor_keys()).dtor_key(), ((((s).dtor_phase()).dtor_response()).dtor_keys()).dtor_baseNonce()));
    } else {
      return EHBP.Option.<dafny.Tuple2<dafny.DafnySequence<? extends java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>>>create_None(dafny.Tuple2.<dafny.DafnySequence<? extends java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>>_typeDescriptor(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(EHBP.uint8._typeDescriptor())));
    }
  }
  public static boolean Contract(State s, Event e, dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> r)
  {
    return ((!(__default.Ends((r).dtor__1())) || ((!(((r).dtor__0()).dtor_published())) && ((((s).dtor_published()) ? (__default.ClearsOnce((r).dtor__1(), (s).dtor_generation())) : (__default.NoClear((r).dtor__1())))))) && (!(!(__default.Ends((r).dtor__1()))) || (__default.NoClear((r).dtor__1())))) && (!(!(__default.NoEmit((r).dtor__1()))) || (((((e).is_AeadOpenResult()) && ((e).dtor_ok())) && (((s).dtor_phase()).is_Exchanging())) && ((((s).dtor_phase()).dtor_response()).is_Opening())));
  }
  public static boolean Ending(State s, dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> r)
  {
    return (((__default.Ends((r).dtor__1())) && (!(((r).dtor__0()).dtor_published()))) && ((((s).dtor_published()) ? (__default.ClearsOnce((r).dtor__1(), (s).dtor_generation())) : (__default.NoClear((r).dtor__1()))))) && (__default.NoEmit((r).dtor__1()));
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> End(State s, boolean close, Action last)
  {
    Phase _0_phase = ((java.util.function.Function<Phase, Phase>)(_source0_boxed0) -> {
      Phase _source0 = ((Phase)(java.lang.Object)(_source0_boxed0));
      if (_source0.is_Idle()) {
        return Phase.create_Ended();
      } else if (_source0.is_AwaitSession()) {
        boolean _1___mcc_h0 = ((EHBPEvents.Phase_AwaitSession)_source0)._hasBody;
        return Phase.create_Ended();
      } else if (_source0.is_Peeking()) {
        java.math.BigInteger _2___mcc_h2 = ((EHBPEvents.Phase_Peeking)_source0)._empty;
        return Phase.create_Ended();
      } else if (_source0.is_AwaitSetup()) {
        dafny.DafnySequence<? extends java.lang.Byte> _3___mcc_h4 = ((EHBPEvents.Phase_AwaitSetup)_source0)._first;
        boolean _4___mcc_h5 = ((EHBPEvents.Phase_AwaitSetup)_source0)._firstEof;
        Hpke _5___mcc_h6 = ((EHBPEvents.Phase_AwaitSetup)_source0)._hpke;
        return Phase.create_Ended();
      } else if (_source0.is_AwaitExport()) {
        dafny.DafnySequence<? extends java.lang.Byte> _6___mcc_h10 = ((EHBPEvents.Phase_AwaitExport)_source0)._first;
        boolean _7___mcc_h11 = ((EHBPEvents.Phase_AwaitExport)_source0)._firstEof;
        dafny.DafnySequence<? extends java.lang.Byte> _8___mcc_h12 = ((EHBPEvents.Phase_AwaitExport)_source0)._enc;
        Job _9___mcc_h13 = ((EHBPEvents.Phase_AwaitExport)_source0)._job;
        return Phase.create_Ended();
      } else if (_source0.is_Exchanging()) {
        Upload _10___mcc_h18 = ((EHBPEvents.Phase_Exchanging)_source0)._upload;
        Response _11___mcc_h19 = ((EHBPEvents.Phase_Exchanging)_source0)._response;
        Upload _12_up = _10___mcc_h18;
        return Phase.create_Exchanging(_12_up, Response.create_RespEnded());
      } else if (_source0.is_DiscAwaitHead()) {
        return Phase.create_Ended();
      } else if (_source0.is_DiscReading()) {
        dafny.DafnySequence<? extends java.lang.Byte> _13___mcc_h22 = ((EHBPEvents.Phase_DiscReading)_source0)._data;
        return Phase.create_Ended();
      } else {
        return Phase.create_Ended();
      }
    }).apply((s).dtor_phase());
    long _14_g = (s).dtor_generation();
    dafny.DafnySequence<? extends Action> _15_acts = (((close) && ((s).dtor_published())) ? (dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Close(Stream.create_ResponseBody()), Action.create_ClearToken(_14_g), last)) : (((close) ? (dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Close(Stream.create_ResponseBody()), last)) : ((((s).dtor_published()) ? (dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_ClearToken(_14_g), last)) : (dafny.DafnySequence.<Action> of(Action._typeDescriptor(), last)))))));
    return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed58 -> {
  State _pat_let29_0 = ((State)(java.lang.Object)(boxed58));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let29_0, boxed59 -> {
    State _16_dt__update__tmp_h0 = ((State)(java.lang.Object)(boxed59));
    return ((State)(java.lang.Object)(dafny.Helpers.<Boolean, State>Let(false, boxed60 -> {
      boolean _pat_let30_0 = ((boolean)(java.lang.Object)(boxed60));
      return ((State)(java.lang.Object)(dafny.Helpers.<Boolean, State>Let(_pat_let30_0, boxed61 -> {
        boolean _17_dt__update_hpublished_h0 = ((boolean)(java.lang.Object)(boxed61));
        return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_0_phase, boxed62 -> {
          Phase _pat_let31_0 = ((Phase)(java.lang.Object)(boxed62));
          return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let31_0, boxed63 -> {
            Phase _18_dt__update_hphase_h0 = ((Phase)(java.lang.Object)(boxed63));
            return State.create(_18_dt__update_hphase_h0, (_16_dt__update__tmp_h0).dtor_origin(), (_16_dt__update__tmp_h0).dtor_publicKey(), (_16_dt__update__tmp_h0).dtor_verb(), (_16_dt__update__tmp_h0).dtor_url(), (_16_dt__update__tmp_h0).dtor_headers(), (_16_dt__update__tmp_h0).dtor_generation(), _17_dt__update_hpublished_h0, (_16_dt__update__tmp_h0).dtor_token(), (_16_dt__update__tmp_h0).dtor_ctx());
          }
          )));
        }
        )));
      }
      )));
    }
    )));
  }
  )));
}
))), _15_acts);
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> Abort(State s, boolean close, EHBP.Code code, dafny.DafnySequence<? extends dafny.CodePoint> message)
  {
    return __default.End(s, close, Action.create_Fail(code, message));
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> Unexpected(State s) {
    return __default.Abort(s, false, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("unexpected event"));
  }
  public static java.math.BigInteger Min(java.math.BigInteger a, java.math.BigInteger b)
  {
    if ((a).compareTo(b) < 0) {
      return a;
    } else {
      return b;
    }
  }
  public static int Min32(int a, int b)
  {
    if (java.lang.Integer.compareUnsigned(a, b) < 0) {
      return a;
    } else {
      return b;
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Piece(dafny.DafnySequence<? extends java.lang.Byte> chunk, int at, int n)
  {
    if ((((at) == 0 ? 0 : 1) == 0) && (java.util.Objects.equals(dafny.Helpers.unsignedToBigInteger(n), java.math.BigInteger.valueOf((chunk).length())))) {
      return chunk;
    } else {
      return (chunk).subsequence(at, (int) ((at) + (n)));
    }
  }
  public static dafny.DafnySequence<? extends Action> FrameWrites(dafny.DafnySequence<? extends java.lang.Byte> ciphertext, BodyEnd end)
  {
    return dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Write(EHBP.__default.BE32((ciphertext).cardinalityInt()), BodyEnd.create_More()), Action.create_Write(ciphertext, end));
  }
  public static State WithUpload(State s, Upload up)
  {
    State _0_dt__update__tmp_h0 = s;
    Phase _1_dt__update_hphase_h0 = Phase.create_Exchanging(up, ((s).dtor_phase()).dtor_response());
    return State.create(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).dtor_origin(), (_0_dt__update__tmp_h0).dtor_publicKey(), (_0_dt__update__tmp_h0).dtor_verb(), (_0_dt__update__tmp_h0).dtor_url(), (_0_dt__update__tmp_h0).dtor_headers(), (_0_dt__update__tmp_h0).dtor_generation(), (_0_dt__update__tmp_h0).dtor_published(), (_0_dt__update__tmp_h0).dtor_token(), (_0_dt__update__tmp_h0).dtor_ctx());
  }
  public static State WithResponse(State s, Response rs)
  {
    State _0_dt__update__tmp_h0 = s;
    Phase _1_dt__update_hphase_h0 = Phase.create_Exchanging(((s).dtor_phase()).dtor_upload(), rs);
    return State.create(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).dtor_origin(), (_0_dt__update__tmp_h0).dtor_publicKey(), (_0_dt__update__tmp_h0).dtor_verb(), (_0_dt__update__tmp_h0).dtor_url(), (_0_dt__update__tmp_h0).dtor_headers(), (_0_dt__update__tmp_h0).dtor_generation(), (_0_dt__update__tmp_h0).dtor_published(), (_0_dt__update__tmp_h0).dtor_token(), (_0_dt__update__tmp_h0).dtor_ctx());
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> SendPlain(State s) {
    return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed64 -> {
  State _pat_let32_0 = ((State)(java.lang.Object)(boxed64));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let32_0, boxed65 -> {
    State _0_dt__update__tmp_h0 = ((State)(java.lang.Object)(boxed65));
    return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_Exchanging(Upload.create_NoUpload(), Response.create_AwaitHead(false)), boxed66 -> {
      Phase _pat_let33_0 = ((Phase)(java.lang.Object)(boxed66));
      return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let33_0, boxed67 -> {
        Phase _1_dt__update_hphase_h0 = ((Phase)(java.lang.Object)(boxed67));
        return State.create(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).dtor_origin(), (_0_dt__update__tmp_h0).dtor_publicKey(), (_0_dt__update__tmp_h0).dtor_verb(), (_0_dt__update__tmp_h0).dtor_url(), (_0_dt__update__tmp_h0).dtor_headers(), (_0_dt__update__tmp_h0).dtor_generation(), (_0_dt__update__tmp_h0).dtor_published(), (_0_dt__update__tmp_h0).dtor_token(), (_0_dt__update__tmp_h0).dtor_ctx());
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Send((s).dtor_verb(), (s).dtor_url(), (s).dtor_headers(), false)));
  }
  public static boolean ForUpload(Event e) {
    return ((((e).is_Chunk()) || ((e).is_StreamFailed())) && (((e).dtor_stream()).is_RequestBody())) || ((e).is_AeadSealResult());
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> AbortUpload(State s, EHBP.Code code)
  {
    return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithUpload(s, Upload.create_UpDone()), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Write(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), BodyEnd.create_Aborted(code))));
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> Step(State s, Event e)
  {
    Event _pat_let_tv0 = e;
    if ((e).is_CallerClose()) {
      return __default.End(s, false, Action.create_Close(Stream.create_ResponseBody()));
    } else {
      Phase _source0 = (s).dtor_phase();
      if (_source0.is_Idle()) {
        if ((e).is_Start()) {
          return __default.StepStart(s, e);
        } else if ((e).is_DiscoverStart()) {
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed68 -> {
  State _pat_let34_0 = ((State)(java.lang.Object)(boxed68));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let34_0, boxed69 -> {
    State _0_dt__update__tmp_h0 = ((State)(java.lang.Object)(boxed69));
    return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_DiscAwaitHead(), boxed70 -> {
      Phase _pat_let35_0 = ((Phase)(java.lang.Object)(boxed70));
      return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let35_0, boxed71 -> {
        Phase _1_dt__update_hphase_h0 = ((Phase)(java.lang.Object)(boxed71));
        return State.create(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).dtor_origin(), (_0_dt__update__tmp_h0).dtor_publicKey(), (_0_dt__update__tmp_h0).dtor_verb(), (_0_dt__update__tmp_h0).dtor_url(), (_0_dt__update__tmp_h0).dtor_headers(), (_0_dt__update__tmp_h0).dtor_generation(), (_0_dt__update__tmp_h0).dtor_published(), (_0_dt__update__tmp_h0).dtor_token(), (_0_dt__update__tmp_h0).dtor_ctx());
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Send(dafny.DafnySequence.asUnicodeString("GET"), dafny.DafnySequence.<dafny.CodePoint>concatenate(EHBP.__default.OriginUrl((s).dtor_origin()), EHBP.__default.KeysPath()), dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> empty(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))), false)));
        } else {
          return __default.Unexpected(s);
        }
      } else if (_source0.is_AwaitSession()) {
        boolean _2___mcc_h0 = ((EHBPEvents.Phase_AwaitSession)_source0)._hasBody;
        boolean _3_hasBody = _2___mcc_h0;
        if (!((e).is_SessionBegun())) {
          return __default.Unexpected(s);
        } else {
          State _4_begun = ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed72 -> {
            State _pat_let36_0 = ((State)(java.lang.Object)(boxed72));
            return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let36_0, boxed73 -> {
              State _5_dt__update__tmp_h1 = ((State)(java.lang.Object)(boxed73));
              return ((State)(java.lang.Object)(dafny.Helpers.<java.lang.Long, State>Let((_pat_let_tv0).dtor_generation(), boxed74 -> {
                long _pat_let37_0 = ((long)(java.lang.Object)(boxed74));
                return ((State)(java.lang.Object)(dafny.Helpers.<java.lang.Long, State>Let(_pat_let37_0, boxed75 -> {
                  long _6_dt__update_hgeneration_h0 = ((long)(java.lang.Object)(boxed75));
                  return State.create((_5_dt__update__tmp_h1).dtor_phase(), (_5_dt__update__tmp_h1).dtor_origin(), (_5_dt__update__tmp_h1).dtor_publicKey(), (_5_dt__update__tmp_h1).dtor_verb(), (_5_dt__update__tmp_h1).dtor_url(), (_5_dt__update__tmp_h1).dtor_headers(), _6_dt__update_hgeneration_h0, (_5_dt__update__tmp_h1).dtor_published(), (_5_dt__update__tmp_h1).dtor_token(), (_5_dt__update__tmp_h1).dtor_ctx());
                }
                )));
              }
              )));
            }
            )));
          }
          )));
          if (_3_hasBody) {
            return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_4_begun, boxed76 -> {
  State _pat_let38_0 = ((State)(java.lang.Object)(boxed76));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let38_0, boxed77 -> {
    State _7_dt__update__tmp_h2 = ((State)(java.lang.Object)(boxed77));
    return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_Peeking(java.math.BigInteger.ZERO), boxed78 -> {
      Phase _pat_let39_0 = ((Phase)(java.lang.Object)(boxed78));
      return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let39_0, boxed79 -> {
        Phase _8_dt__update_hphase_h1 = ((Phase)(java.lang.Object)(boxed79));
        return State.create(_8_dt__update_hphase_h1, (_7_dt__update__tmp_h2).dtor_origin(), (_7_dt__update__tmp_h2).dtor_publicKey(), (_7_dt__update__tmp_h2).dtor_verb(), (_7_dt__update__tmp_h2).dtor_url(), (_7_dt__update__tmp_h2).dtor_headers(), (_7_dt__update__tmp_h2).dtor_generation(), (_7_dt__update__tmp_h2).dtor_published(), (_7_dt__update__tmp_h2).dtor_token(), (_7_dt__update__tmp_h2).dtor_ctx());
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_RequestBody())));
          } else {
            return __default.SendPlain(_4_begun);
          }
        }
      } else if (_source0.is_Peeking()) {
        java.math.BigInteger _9___mcc_h1 = ((EHBPEvents.Phase_Peeking)_source0)._empty;
        java.math.BigInteger _10_empty = _9___mcc_h1;
        Event _source1 = e;
        if (_source1.is_Start()) {
          dafny.DafnySequence<? extends dafny.CodePoint> _11___mcc_h12 = ((EHBPEvents.Event_Start)_source1)._verb;
          dafny.DafnySequence<? extends dafny.CodePoint> _12___mcc_h13 = ((EHBPEvents.Event_Start)_source1)._url;
          dafny.DafnySequence<? extends dafny.CodePoint> _13___mcc_h14 = ((EHBPEvents.Event_Start)_source1)._scheme;
          dafny.DafnySequence<? extends dafny.CodePoint> _14___mcc_h15 = ((EHBPEvents.Event_Start)_source1)._host;
          java.math.BigInteger _15___mcc_h16 = ((EHBPEvents.Event_Start)_source1)._port;
          boolean _16___mcc_h17 = ((EHBPEvents.Event_Start)_source1)._hasPort;
          boolean _17___mcc_h18 = ((EHBPEvents.Event_Start)_source1)._hasUserinfo;
          dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _18___mcc_h19 = ((EHBPEvents.Event_Start)_source1)._headers;
          boolean _19___mcc_h20 = ((EHBPEvents.Event_Start)_source1)._hasBody;
          return __default.Unexpected(s);
        } else if (_source1.is_DiscoverStart()) {
          return __default.Unexpected(s);
        } else if (_source1.is_SessionBegun()) {
          long _20___mcc_h30 = ((EHBPEvents.Event_SessionBegun)_source1)._generation;
          return __default.Unexpected(s);
        } else if (_source1.is_RandomResult()) {
          dafny.DafnySequence<? extends java.lang.Byte> _21___mcc_h32 = ((EHBPEvents.Event_RandomResult)_source1)._data;
          return __default.Unexpected(s);
        } else if (_source1.is_X25519Result()) {
          dafny.DafnySequence<? extends java.lang.Byte> _22___mcc_h34 = ((EHBPEvents.Event_X25519Result)_source1)._point;
          return __default.Unexpected(s);
        } else if (_source1.is_HmacResult()) {
          dafny.DafnySequence<? extends java.lang.Byte> _23___mcc_h36 = ((EHBPEvents.Event_HmacResult)_source1)._mac;
          return __default.Unexpected(s);
        } else if (_source1.is_AeadSealResult()) {
          dafny.DafnySequence<? extends java.lang.Byte> _24___mcc_h38 = ((EHBPEvents.Event_AeadSealResult)_source1)._ciphertext;
          return __default.Unexpected(s);
        } else if (_source1.is_AeadOpenResult()) {
          boolean _25___mcc_h40 = ((EHBPEvents.Event_AeadOpenResult)_source1)._ok;
          dafny.DafnySequence<? extends java.lang.Byte> _26___mcc_h41 = ((EHBPEvents.Event_AeadOpenResult)_source1)._plaintext;
          return __default.Unexpected(s);
        } else if (_source1.is_ResponseHead()) {
          java.math.BigInteger _27___mcc_h44 = ((EHBPEvents.Event_ResponseHead)_source1)._status;
          dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _28___mcc_h45 = ((EHBPEvents.Event_ResponseHead)_source1)._headers;
          boolean _29___mcc_h46 = ((EHBPEvents.Event_ResponseHead)_source1)._redirected;
          return __default.Unexpected(s);
        } else if (_source1.is_Chunk()) {
          Stream _30___mcc_h50 = ((EHBPEvents.Event_Chunk)_source1)._stream;
          dafny.DafnySequence<? extends java.lang.Byte> _31___mcc_h51 = ((EHBPEvents.Event_Chunk)_source1)._data;
          boolean _32___mcc_h52 = ((EHBPEvents.Event_Chunk)_source1)._eof;
          Stream _source2 = _30___mcc_h50;
          if (_source2.is_RequestBody()) {
            boolean _33_eof = _32___mcc_h52;
            dafny.DafnySequence<? extends java.lang.Byte> _34_data = _31___mcc_h51;
            if ((java.math.BigInteger.valueOf((_34_data).length())).compareTo(__default.MaxReadBytes()) > 0) {
              return __default.Abort(s, false, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("request body chunk too large"));
            } else if ((java.math.BigInteger.valueOf((_34_data).length())).signum() == 1) {
              HpkeOut _source3 = __default.SenderStart((s).dtor_publicKey(), EHBP.__default.Ascii(EHBP.__default.HpkeRequestInfo()));
              if (_source3.is_HContinue()) {
                Hpke _35___mcc_h58 = ((EHBPEvents.HpkeOut_HContinue)_source3)._h;
                Action _36___mcc_h59 = ((EHBPEvents.HpkeOut_HContinue)_source3)._action;
                Action _37_a = _36___mcc_h59;
                Hpke _38_h = _35___mcc_h58;
                return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed80 -> {
  State _pat_let40_0 = ((State)(java.lang.Object)(boxed80));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let40_0, boxed81 -> {
    State _39_dt__update__tmp_h3 = ((State)(java.lang.Object)(boxed81));
    return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_AwaitSetup(_34_data, _33_eof, _38_h), boxed82 -> {
      Phase _pat_let41_0 = ((Phase)(java.lang.Object)(boxed82));
      return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let41_0, boxed83 -> {
        Phase _40_dt__update_hphase_h2 = ((Phase)(java.lang.Object)(boxed83));
        return State.create(_40_dt__update_hphase_h2, (_39_dt__update__tmp_h3).dtor_origin(), (_39_dt__update__tmp_h3).dtor_publicKey(), (_39_dt__update__tmp_h3).dtor_verb(), (_39_dt__update__tmp_h3).dtor_url(), (_39_dt__update__tmp_h3).dtor_headers(), (_39_dt__update__tmp_h3).dtor_generation(), (_39_dt__update__tmp_h3).dtor_published(), (_39_dt__update__tmp_h3).dtor_token(), (_39_dt__update__tmp_h3).dtor_ctx());
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), _37_a));
              } else if (_source3.is_HReady()) {
                Ctx _41___mcc_h62 = ((EHBPEvents.HpkeOut_HReady)_source3)._ctx;
                dafny.DafnySequence<? extends java.lang.Byte> _42___mcc_h63 = ((EHBPEvents.HpkeOut_HReady)_source3)._enc;
                return __default.Unexpected(s);
              } else {
                EHBP.Code _43___mcc_h66 = ((EHBPEvents.HpkeOut_HFailed)_source3)._code;
                dafny.DafnySequence<? extends dafny.CodePoint> _44___mcc_h67 = ((EHBPEvents.HpkeOut_HFailed)_source3)._message;
                return __default.Unexpected(s);
              }
            } else if (_33_eof) {
              return __default.SendPlain(s);
            } else if (java.util.Objects.equals((_10_empty).add(java.math.BigInteger.ONE), EHBP.__default.MaxEmptyReads())) {
              return __default.Abort(s, false, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("request body made no progress"));
            } else {
              return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed84 -> {
  State _pat_let42_0 = ((State)(java.lang.Object)(boxed84));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let42_0, boxed85 -> {
    State _45_dt__update__tmp_h4 = ((State)(java.lang.Object)(boxed85));
    return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_Peeking((_10_empty).add(java.math.BigInteger.ONE)), boxed86 -> {
      Phase _pat_let43_0 = ((Phase)(java.lang.Object)(boxed86));
      return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let43_0, boxed87 -> {
        Phase _46_dt__update_hphase_h3 = ((Phase)(java.lang.Object)(boxed87));
        return State.create(_46_dt__update_hphase_h3, (_45_dt__update__tmp_h4).dtor_origin(), (_45_dt__update__tmp_h4).dtor_publicKey(), (_45_dt__update__tmp_h4).dtor_verb(), (_45_dt__update__tmp_h4).dtor_url(), (_45_dt__update__tmp_h4).dtor_headers(), (_45_dt__update__tmp_h4).dtor_generation(), (_45_dt__update__tmp_h4).dtor_published(), (_45_dt__update__tmp_h4).dtor_token(), (_45_dt__update__tmp_h4).dtor_ctx());
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_RequestBody())));
            }
          } else {
            return __default.Unexpected(s);
          }
        } else if (_source1.is_StreamFailed()) {
          Stream _47___mcc_h56 = ((EHBPEvents.Event_StreamFailed)_source1)._stream;
          Stream _source4 = _47___mcc_h56;
          if (_source4.is_RequestBody()) {
            return __default.Abort(s, false, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("failed to read request body"));
          } else {
            return __default.Unexpected(s);
          }
        } else if (_source1.is_CallerRead()) {
          return __default.Unexpected(s);
        } else {
          return __default.Unexpected(s);
        }
      } else if (_source0.is_AwaitSetup()) {
        dafny.DafnySequence<? extends java.lang.Byte> _48___mcc_h2 = ((EHBPEvents.Phase_AwaitSetup)_source0)._first;
        boolean _49___mcc_h3 = ((EHBPEvents.Phase_AwaitSetup)_source0)._firstEof;
        Hpke _50___mcc_h4 = ((EHBPEvents.Phase_AwaitSetup)_source0)._hpke;
        Hpke _51_h = _50___mcc_h4;
        boolean _52_firstEof = _49___mcc_h3;
        dafny.DafnySequence<? extends java.lang.Byte> _53_first = _48___mcc_h2;
        HpkeOut _source5 = __default.HpkeStep(_51_h, e);
        if (_source5.is_HContinue()) {
          Hpke _54___mcc_h70 = ((EHBPEvents.HpkeOut_HContinue)_source5)._h;
          Action _55___mcc_h71 = ((EHBPEvents.HpkeOut_HContinue)_source5)._action;
          Action _56_a = _55___mcc_h71;
          Hpke _57_next = _54___mcc_h70;
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed88 -> {
  State _pat_let44_0 = ((State)(java.lang.Object)(boxed88));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let44_0, boxed89 -> {
    State _58_dt__update__tmp_h5 = ((State)(java.lang.Object)(boxed89));
    return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_AwaitSetup(_53_first, _52_firstEof, _57_next), boxed90 -> {
      Phase _pat_let45_0 = ((Phase)(java.lang.Object)(boxed90));
      return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let45_0, boxed91 -> {
        Phase _59_dt__update_hphase_h4 = ((Phase)(java.lang.Object)(boxed91));
        return State.create(_59_dt__update_hphase_h4, (_58_dt__update__tmp_h5).dtor_origin(), (_58_dt__update__tmp_h5).dtor_publicKey(), (_58_dt__update__tmp_h5).dtor_verb(), (_58_dt__update__tmp_h5).dtor_url(), (_58_dt__update__tmp_h5).dtor_headers(), (_58_dt__update__tmp_h5).dtor_generation(), (_58_dt__update__tmp_h5).dtor_published(), (_58_dt__update__tmp_h5).dtor_token(), (_58_dt__update__tmp_h5).dtor_ctx());
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), _56_a));
        } else if (_source5.is_HReady()) {
          Ctx _60___mcc_h72 = ((EHBPEvents.HpkeOut_HReady)_source5)._ctx;
          dafny.DafnySequence<? extends java.lang.Byte> _61___mcc_h73 = ((EHBPEvents.HpkeOut_HReady)_source5)._enc;
          dafny.DafnySequence<? extends java.lang.Byte> _62_enc = _61___mcc_h73;
          Ctx _63_ctx = _60___mcc_h72;
          Job _64_job = __default.ExportJob(_63_ctx, EHBP.__default.Ascii(EHBP.__default.ExportLabel()), EHBP.__default.ExportLength());
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed92 -> {
  State _pat_let46_0 = ((State)(java.lang.Object)(boxed92));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let46_0, boxed93 -> {
    State _65_dt__update__tmp_h6 = ((State)(java.lang.Object)(boxed93));
    return ((State)(java.lang.Object)(dafny.Helpers.<Ctx, State>Let(_63_ctx, boxed94 -> {
      Ctx _pat_let47_0 = ((Ctx)(java.lang.Object)(boxed94));
      return ((State)(java.lang.Object)(dafny.Helpers.<Ctx, State>Let(_pat_let47_0, boxed95 -> {
        Ctx _66_dt__update_hctx_h0 = ((Ctx)(java.lang.Object)(boxed95));
        return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_AwaitExport(_53_first, _52_firstEof, _62_enc, _64_job), boxed96 -> {
          Phase _pat_let48_0 = ((Phase)(java.lang.Object)(boxed96));
          return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let48_0, boxed97 -> {
            Phase _67_dt__update_hphase_h5 = ((Phase)(java.lang.Object)(boxed97));
            return State.create(_67_dt__update_hphase_h5, (_65_dt__update__tmp_h6).dtor_origin(), (_65_dt__update__tmp_h6).dtor_publicKey(), (_65_dt__update__tmp_h6).dtor_verb(), (_65_dt__update__tmp_h6).dtor_url(), (_65_dt__update__tmp_h6).dtor_headers(), (_65_dt__update__tmp_h6).dtor_generation(), (_65_dt__update__tmp_h6).dtor_published(), (_65_dt__update__tmp_h6).dtor_token(), _66_dt__update_hctx_h0);
          }
          )));
        }
        )));
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), __default.JobAction(_64_job)));
        } else {
          EHBP.Code _68___mcc_h74 = ((EHBPEvents.HpkeOut_HFailed)_source5)._code;
          dafny.DafnySequence<? extends dafny.CodePoint> _69___mcc_h75 = ((EHBPEvents.HpkeOut_HFailed)_source5)._message;
          dafny.DafnySequence<? extends dafny.CodePoint> _70_message = _69___mcc_h75;
          EHBP.Code _71_code = _68___mcc_h74;
          return __default.Abort(s, false, _71_code, _70_message);
        }
      } else if (_source0.is_AwaitExport()) {
        dafny.DafnySequence<? extends java.lang.Byte> _72___mcc_h5 = ((EHBPEvents.Phase_AwaitExport)_source0)._first;
        boolean _73___mcc_h6 = ((EHBPEvents.Phase_AwaitExport)_source0)._firstEof;
        dafny.DafnySequence<? extends java.lang.Byte> _74___mcc_h7 = ((EHBPEvents.Phase_AwaitExport)_source0)._enc;
        Job _75___mcc_h8 = ((EHBPEvents.Phase_AwaitExport)_source0)._job;
        Job _76_job = _75___mcc_h8;
        dafny.DafnySequence<? extends java.lang.Byte> _77_enc = _74___mcc_h7;
        boolean _78_firstEof = _73___mcc_h6;
        dafny.DafnySequence<? extends java.lang.Byte> _79_first = _72___mcc_h5;
        JobOut _source6 = __default.JobStep(_76_job, e);
        if (_source6.is_Pending()) {
          Job _80___mcc_h76 = ((EHBPEvents.JobOut_Pending)_source6)._job;
          Action _81___mcc_h77 = ((EHBPEvents.JobOut_Pending)_source6)._action;
          Action _82_a = _81___mcc_h77;
          Job _83_next = _80___mcc_h76;
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed98 -> {
  State _pat_let49_0 = ((State)(java.lang.Object)(boxed98));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let49_0, boxed99 -> {
    State _84_dt__update__tmp_h7 = ((State)(java.lang.Object)(boxed99));
    return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_AwaitExport(_79_first, _78_firstEof, _77_enc, _83_next), boxed100 -> {
      Phase _pat_let50_0 = ((Phase)(java.lang.Object)(boxed100));
      return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let50_0, boxed101 -> {
        Phase _85_dt__update_hphase_h6 = ((Phase)(java.lang.Object)(boxed101));
        return State.create(_85_dt__update_hphase_h6, (_84_dt__update__tmp_h7).dtor_origin(), (_84_dt__update__tmp_h7).dtor_publicKey(), (_84_dt__update__tmp_h7).dtor_verb(), (_84_dt__update__tmp_h7).dtor_url(), (_84_dt__update__tmp_h7).dtor_headers(), (_84_dt__update__tmp_h7).dtor_generation(), (_84_dt__update__tmp_h7).dtor_published(), (_84_dt__update__tmp_h7).dtor_token(), (_84_dt__update__tmp_h7).dtor_ctx());
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), _82_a));
        } else if (_source6.is_Output()) {
          dafny.DafnySequence<? extends java.lang.Byte> _86___mcc_h78 = ((EHBPEvents.JobOut_Output)_source6)._data;
          dafny.DafnySequence<? extends java.lang.Byte> _87_secret = _86___mcc_h78;
          if (!java.util.Objects.equals(java.math.BigInteger.valueOf((_77_enc).length()), EHBP.__default.RequestEncLength())) {
            return __default.Abort(s, false, EHBP.Code.create_HpkeSetupFailed(), dafny.DafnySequence.asUnicodeString("HPKE sender setup failed"));
          } else if (!java.util.Objects.equals(java.math.BigInteger.valueOf((_87_secret).length()), EHBP.__default.ExportLength())) {
            return __default.Abort(s, false, EHBP.Code.create_HpkeSetupFailed(), dafny.DafnySequence.asUnicodeString("HPKE export failed"));
          } else {
            EHBP.Token _88_token = EHBP.Token.create(_87_secret, _77_enc);
            dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _89_headers = dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>>concatenate((s).dtor_headers(), dafny.DafnySequence.<dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> of(dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), dafny.Tuple2.<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>create(EHBP.__default.EncapsulatedKeyHeader(), EHBP.__default.EncodeHex(_77_enc))));
            return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed102 -> {
  State _pat_let51_0 = ((State)(java.lang.Object)(boxed102));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let51_0, boxed103 -> {
    State _90_dt__update__tmp_h8 = ((State)(java.lang.Object)(boxed103));
    return ((State)(java.lang.Object)(dafny.Helpers.<EHBP.Token, State>Let(_88_token, boxed104 -> {
      EHBP.Token _pat_let52_0 = ((EHBP.Token)(java.lang.Object)(boxed104));
      return ((State)(java.lang.Object)(dafny.Helpers.<EHBP.Token, State>Let(_pat_let52_0, boxed105 -> {
        EHBP.Token _91_dt__update_htoken_h0 = ((EHBP.Token)(java.lang.Object)(boxed105));
        return ((State)(java.lang.Object)(dafny.Helpers.<Boolean, State>Let(true, boxed106 -> {
          boolean _pat_let53_0 = ((boolean)(java.lang.Object)(boxed106));
          return ((State)(java.lang.Object)(dafny.Helpers.<Boolean, State>Let(_pat_let53_0, boxed107 -> {
            boolean _92_dt__update_hpublished_h0 = ((boolean)(java.lang.Object)(boxed107));
            return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_Exchanging(Upload.create_Sealing(_79_first, 0, _78_firstEof), Response.create_AwaitHead(true)), boxed108 -> {
              Phase _pat_let54_0 = ((Phase)(java.lang.Object)(boxed108));
              return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let54_0, boxed109 -> {
                Phase _93_dt__update_hphase_h7 = ((Phase)(java.lang.Object)(boxed109));
                return State.create(_93_dt__update_hphase_h7, (_90_dt__update__tmp_h8).dtor_origin(), (_90_dt__update__tmp_h8).dtor_publicKey(), (_90_dt__update__tmp_h8).dtor_verb(), (_90_dt__update__tmp_h8).dtor_url(), (_90_dt__update__tmp_h8).dtor_headers(), (_90_dt__update__tmp_h8).dtor_generation(), _92_dt__update_hpublished_h0, _91_dt__update_htoken_h0, (_90_dt__update__tmp_h8).dtor_ctx());
              }
              )));
            }
            )));
          }
          )));
        }
        )));
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_PublishToken((s).dtor_generation(), _87_secret, _77_enc), Action.create_Send((s).dtor_verb(), (s).dtor_url(), _89_headers, true), __default.SealAction((s).dtor_ctx(), __default.Piece(_79_first, 0, __default.Min32((_79_first).cardinalityInt(), EHBP.__default.RequestFrameBytes())))));
          }
        } else {
          EHBP.Code _94___mcc_h79 = ((EHBPEvents.JobOut_JobFailed)_source6)._code;
          dafny.DafnySequence<? extends dafny.CodePoint> _95___mcc_h80 = ((EHBPEvents.JobOut_JobFailed)_source6)._message;
          dafny.DafnySequence<? extends dafny.CodePoint> _96_message = _95___mcc_h80;
          EHBP.Code _97_code = _94___mcc_h79;
          return __default.Abort(s, false, _97_code, _96_message);
        }
      } else if (_source0.is_Exchanging()) {
        Upload _98___mcc_h9 = ((EHBPEvents.Phase_Exchanging)_source0)._upload;
        Response _99___mcc_h10 = ((EHBPEvents.Phase_Exchanging)_source0)._response;
        Response _100_rs = _99___mcc_h10;
        Upload _101_up = _98___mcc_h9;
        if (__default.ForUpload(e)) {
          return __default.StepUpload(s, _101_up, e);
        } else {
          return __default.StepResponse(s, _100_rs, e);
        }
      } else if (_source0.is_DiscAwaitHead()) {
        Event _source7 = e;
        if (_source7.is_Start()) {
          dafny.DafnySequence<? extends dafny.CodePoint> _102___mcc_h81 = ((EHBPEvents.Event_Start)_source7)._verb;
          dafny.DafnySequence<? extends dafny.CodePoint> _103___mcc_h82 = ((EHBPEvents.Event_Start)_source7)._url;
          dafny.DafnySequence<? extends dafny.CodePoint> _104___mcc_h83 = ((EHBPEvents.Event_Start)_source7)._scheme;
          dafny.DafnySequence<? extends dafny.CodePoint> _105___mcc_h84 = ((EHBPEvents.Event_Start)_source7)._host;
          java.math.BigInteger _106___mcc_h85 = ((EHBPEvents.Event_Start)_source7)._port;
          boolean _107___mcc_h86 = ((EHBPEvents.Event_Start)_source7)._hasPort;
          boolean _108___mcc_h87 = ((EHBPEvents.Event_Start)_source7)._hasUserinfo;
          dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _109___mcc_h88 = ((EHBPEvents.Event_Start)_source7)._headers;
          boolean _110___mcc_h89 = ((EHBPEvents.Event_Start)_source7)._hasBody;
          return __default.Unexpected(s);
        } else if (_source7.is_DiscoverStart()) {
          return __default.Unexpected(s);
        } else if (_source7.is_SessionBegun()) {
          long _111___mcc_h99 = ((EHBPEvents.Event_SessionBegun)_source7)._generation;
          return __default.Unexpected(s);
        } else if (_source7.is_RandomResult()) {
          dafny.DafnySequence<? extends java.lang.Byte> _112___mcc_h101 = ((EHBPEvents.Event_RandomResult)_source7)._data;
          return __default.Unexpected(s);
        } else if (_source7.is_X25519Result()) {
          dafny.DafnySequence<? extends java.lang.Byte> _113___mcc_h103 = ((EHBPEvents.Event_X25519Result)_source7)._point;
          return __default.Unexpected(s);
        } else if (_source7.is_HmacResult()) {
          dafny.DafnySequence<? extends java.lang.Byte> _114___mcc_h105 = ((EHBPEvents.Event_HmacResult)_source7)._mac;
          return __default.Unexpected(s);
        } else if (_source7.is_AeadSealResult()) {
          dafny.DafnySequence<? extends java.lang.Byte> _115___mcc_h107 = ((EHBPEvents.Event_AeadSealResult)_source7)._ciphertext;
          return __default.Unexpected(s);
        } else if (_source7.is_AeadOpenResult()) {
          boolean _116___mcc_h109 = ((EHBPEvents.Event_AeadOpenResult)_source7)._ok;
          dafny.DafnySequence<? extends java.lang.Byte> _117___mcc_h110 = ((EHBPEvents.Event_AeadOpenResult)_source7)._plaintext;
          return __default.Unexpected(s);
        } else if (_source7.is_ResponseHead()) {
          java.math.BigInteger _118___mcc_h113 = ((EHBPEvents.Event_ResponseHead)_source7)._status;
          dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _119___mcc_h114 = ((EHBPEvents.Event_ResponseHead)_source7)._headers;
          boolean _120___mcc_h115 = ((EHBPEvents.Event_ResponseHead)_source7)._redirected;
          boolean _121_redirected = _120___mcc_h115;
          dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _122_headers = _119___mcc_h114;
          java.math.BigInteger _123_status = _118___mcc_h113;
          if (((_123_status).compareTo(java.math.BigInteger.valueOf(100L)) < 0) || ((_123_status).compareTo(java.math.BigInteger.valueOf(599L)) > 0)) {
            return __default.Abort(s, true, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("failed to get server public key"));
          } else {
            EHBP.Result<dafny.Tuple0> _source8 = EHBP.__default.ClassifyDiscovery(EHBP.Head.create(_123_status, _122_headers, _121_redirected));
            if (_source8.is_Ok()) {
              dafny.Tuple0 _124___mcc_h127 = ((EHBP.Result_Ok<dafny.Tuple0>)_source8)._value;
              return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed110 -> {
  State _pat_let55_0 = ((State)(java.lang.Object)(boxed110));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let55_0, boxed111 -> {
    State _125_dt__update__tmp_h9 = ((State)(java.lang.Object)(boxed111));
    return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_DiscReading(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor())), boxed112 -> {
      Phase _pat_let56_0 = ((Phase)(java.lang.Object)(boxed112));
      return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let56_0, boxed113 -> {
        Phase _126_dt__update_hphase_h8 = ((Phase)(java.lang.Object)(boxed113));
        return State.create(_126_dt__update_hphase_h8, (_125_dt__update__tmp_h9).dtor_origin(), (_125_dt__update__tmp_h9).dtor_publicKey(), (_125_dt__update__tmp_h9).dtor_verb(), (_125_dt__update__tmp_h9).dtor_url(), (_125_dt__update__tmp_h9).dtor_headers(), (_125_dt__update__tmp_h9).dtor_generation(), (_125_dt__update__tmp_h9).dtor_published(), (_125_dt__update__tmp_h9).dtor_token(), (_125_dt__update__tmp_h9).dtor_ctx());
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_ResponseBody())));
            } else {
              EHBP.Code _127___mcc_h128 = ((EHBP.Result_Err<dafny.Tuple0>)_source8)._code;
              dafny.DafnySequence<? extends dafny.CodePoint> _128___mcc_h129 = ((EHBP.Result_Err<dafny.Tuple0>)_source8)._message;
              dafny.DafnySequence<? extends dafny.CodePoint> _129_message = _128___mcc_h129;
              EHBP.Code _130_code = _127___mcc_h128;
              return __default.Abort(s, true, _130_code, _129_message);
            }
          }
        } else if (_source7.is_Chunk()) {
          Stream _131___mcc_h119 = ((EHBPEvents.Event_Chunk)_source7)._stream;
          dafny.DafnySequence<? extends java.lang.Byte> _132___mcc_h120 = ((EHBPEvents.Event_Chunk)_source7)._data;
          boolean _133___mcc_h121 = ((EHBPEvents.Event_Chunk)_source7)._eof;
          return __default.Unexpected(s);
        } else if (_source7.is_StreamFailed()) {
          Stream _134___mcc_h125 = ((EHBPEvents.Event_StreamFailed)_source7)._stream;
          Stream _source9 = _134___mcc_h125;
          if (_source9.is_RequestBody()) {
            return __default.Unexpected(s);
          } else {
            return __default.Abort(s, false, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("failed to get server public key"));
          }
        } else if (_source7.is_CallerRead()) {
          return __default.Unexpected(s);
        } else {
          return __default.Unexpected(s);
        }
      } else if (_source0.is_DiscReading()) {
        dafny.DafnySequence<? extends java.lang.Byte> _135___mcc_h11 = ((EHBPEvents.Phase_DiscReading)_source0)._data;
        dafny.DafnySequence<? extends java.lang.Byte> _136_data = _135___mcc_h11;
        Event _source10 = e;
        if (_source10.is_Start()) {
          dafny.DafnySequence<? extends dafny.CodePoint> _137___mcc_h130 = ((EHBPEvents.Event_Start)_source10)._verb;
          dafny.DafnySequence<? extends dafny.CodePoint> _138___mcc_h131 = ((EHBPEvents.Event_Start)_source10)._url;
          dafny.DafnySequence<? extends dafny.CodePoint> _139___mcc_h132 = ((EHBPEvents.Event_Start)_source10)._scheme;
          dafny.DafnySequence<? extends dafny.CodePoint> _140___mcc_h133 = ((EHBPEvents.Event_Start)_source10)._host;
          java.math.BigInteger _141___mcc_h134 = ((EHBPEvents.Event_Start)_source10)._port;
          boolean _142___mcc_h135 = ((EHBPEvents.Event_Start)_source10)._hasPort;
          boolean _143___mcc_h136 = ((EHBPEvents.Event_Start)_source10)._hasUserinfo;
          dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _144___mcc_h137 = ((EHBPEvents.Event_Start)_source10)._headers;
          boolean _145___mcc_h138 = ((EHBPEvents.Event_Start)_source10)._hasBody;
          return __default.Unexpected(s);
        } else if (_source10.is_DiscoverStart()) {
          return __default.Unexpected(s);
        } else if (_source10.is_SessionBegun()) {
          long _146___mcc_h148 = ((EHBPEvents.Event_SessionBegun)_source10)._generation;
          return __default.Unexpected(s);
        } else if (_source10.is_RandomResult()) {
          dafny.DafnySequence<? extends java.lang.Byte> _147___mcc_h150 = ((EHBPEvents.Event_RandomResult)_source10)._data;
          return __default.Unexpected(s);
        } else if (_source10.is_X25519Result()) {
          dafny.DafnySequence<? extends java.lang.Byte> _148___mcc_h152 = ((EHBPEvents.Event_X25519Result)_source10)._point;
          return __default.Unexpected(s);
        } else if (_source10.is_HmacResult()) {
          dafny.DafnySequence<? extends java.lang.Byte> _149___mcc_h154 = ((EHBPEvents.Event_HmacResult)_source10)._mac;
          return __default.Unexpected(s);
        } else if (_source10.is_AeadSealResult()) {
          dafny.DafnySequence<? extends java.lang.Byte> _150___mcc_h156 = ((EHBPEvents.Event_AeadSealResult)_source10)._ciphertext;
          return __default.Unexpected(s);
        } else if (_source10.is_AeadOpenResult()) {
          boolean _151___mcc_h158 = ((EHBPEvents.Event_AeadOpenResult)_source10)._ok;
          dafny.DafnySequence<? extends java.lang.Byte> _152___mcc_h159 = ((EHBPEvents.Event_AeadOpenResult)_source10)._plaintext;
          return __default.Unexpected(s);
        } else if (_source10.is_ResponseHead()) {
          java.math.BigInteger _153___mcc_h162 = ((EHBPEvents.Event_ResponseHead)_source10)._status;
          dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _154___mcc_h163 = ((EHBPEvents.Event_ResponseHead)_source10)._headers;
          boolean _155___mcc_h164 = ((EHBPEvents.Event_ResponseHead)_source10)._redirected;
          return __default.Unexpected(s);
        } else if (_source10.is_Chunk()) {
          Stream _156___mcc_h168 = ((EHBPEvents.Event_Chunk)_source10)._stream;
          dafny.DafnySequence<? extends java.lang.Byte> _157___mcc_h169 = ((EHBPEvents.Event_Chunk)_source10)._data;
          boolean _158___mcc_h170 = ((EHBPEvents.Event_Chunk)_source10)._eof;
          Stream _source11 = _156___mcc_h168;
          if (_source11.is_RequestBody()) {
            return __default.Unexpected(s);
          } else {
            boolean _159_eof = _158___mcc_h170;
            dafny.DafnySequence<? extends java.lang.Byte> _160_chunk = _157___mcc_h169;
            dafny.DafnySequence<? extends java.lang.Byte> _161_grown = dafny.DafnySequence.<java.lang.Byte>concatenate(_136_data, _160_chunk);
            if (((java.math.BigInteger.valueOf((_161_grown).length())).compareTo(EHBP.__default.MaxKeyConfigBytes()) <= 0) && (!(_159_eof))) {
              return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed114 -> {
  State _pat_let57_0 = ((State)(java.lang.Object)(boxed114));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let57_0, boxed115 -> {
    State _162_dt__update__tmp_h10 = ((State)(java.lang.Object)(boxed115));
    return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_DiscReading(_161_grown), boxed116 -> {
      Phase _pat_let58_0 = ((Phase)(java.lang.Object)(boxed116));
      return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let58_0, boxed117 -> {
        Phase _163_dt__update_hphase_h9 = ((Phase)(java.lang.Object)(boxed117));
        return State.create(_163_dt__update_hphase_h9, (_162_dt__update__tmp_h10).dtor_origin(), (_162_dt__update__tmp_h10).dtor_publicKey(), (_162_dt__update__tmp_h10).dtor_verb(), (_162_dt__update__tmp_h10).dtor_url(), (_162_dt__update__tmp_h10).dtor_headers(), (_162_dt__update__tmp_h10).dtor_generation(), (_162_dt__update__tmp_h10).dtor_published(), (_162_dt__update__tmp_h10).dtor_token(), (_162_dt__update__tmp_h10).dtor_ctx());
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_ResponseBody())));
            } else {
              EHBP.Result<dafny.DafnySequence<? extends java.lang.Byte>> _source12 = EHBP.__default.ParseConfig(_161_grown);
              if (_source12.is_Ok()) {
                dafny.DafnySequence<? extends java.lang.Byte> _164___mcc_h176 = ((EHBP.Result_Ok<dafny.DafnySequence<? extends java.lang.Byte>>)_source12)._value;
                dafny.DafnySequence<? extends java.lang.Byte> _165_pk = _164___mcc_h176;
                return __default.End(s, true, Action.create_Discovered(_165_pk));
              } else {
                EHBP.Code _166___mcc_h177 = ((EHBP.Result_Err<dafny.DafnySequence<? extends java.lang.Byte>>)_source12)._code;
                dafny.DafnySequence<? extends dafny.CodePoint> _167___mcc_h178 = ((EHBP.Result_Err<dafny.DafnySequence<? extends java.lang.Byte>>)_source12)._message;
                dafny.DafnySequence<? extends dafny.CodePoint> _168_message = _167___mcc_h178;
                EHBP.Code _169_code = _166___mcc_h177;
                return __default.Abort(s, true, _169_code, _168_message);
              }
            }
          }
        } else if (_source10.is_StreamFailed()) {
          Stream _170___mcc_h174 = ((EHBPEvents.Event_StreamFailed)_source10)._stream;
          Stream _source13 = _170___mcc_h174;
          if (_source13.is_RequestBody()) {
            return __default.Unexpected(s);
          } else {
            return __default.Abort(s, true, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("failed to read key configuration"));
          }
        } else if (_source10.is_CallerRead()) {
          return __default.Unexpected(s);
        } else {
          return __default.Unexpected(s);
        }
      } else {
        return __default.Unexpected(s);
      }
    }
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> StepStart(State s, Event e)
  {
    Event _pat_let_tv0 = e;
    Event _pat_let_tv1 = e;
    Event _pat_let_tv2 = e;
    Event _pat_let_tv3 = e;
    EHBP.Result<EHBP.Origin> _0_target = EHBP.__default.MakeOrigin((e).dtor_scheme(), (e).dtor_host(), (((e).dtor_hasPort()) ? (EHBP.Option.<java.math.BigInteger>create_Some(dafny.TypeDescriptor.BIG_INTEGER, (e).dtor_port())) : (EHBP.Option.<java.math.BigInteger>create_None(dafny.TypeDescriptor.BIG_INTEGER))), (e).dtor_hasUserinfo());
    EHBP.Result<dafny.Tuple0> _source0 = EHBP.__default.ValidateRequest((s).dtor_origin(), _0_target, (e).dtor_headers());
    if (_source0.is_Ok()) {
      dafny.Tuple0 _1___mcc_h0 = ((EHBP.Result_Ok<dafny.Tuple0>)_source0)._value;
      return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed118 -> {
  State _pat_let59_0 = ((State)(java.lang.Object)(boxed118));
  return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let59_0, boxed119 -> {
    State _2_dt__update__tmp_h0 = ((State)(java.lang.Object)(boxed119));
    return ((State)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>>, State>Let(EHBP.__default.DropFraming((_pat_let_tv0).dtor_headers()), boxed120 -> {
      dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _pat_let60_0 = ((dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>>)(java.lang.Object)(boxed120));
      return ((State)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>>, State>Let(_pat_let60_0, boxed121 -> {
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _3_dt__update_hheaders_h0 = ((dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>>)(java.lang.Object)(boxed121));
        return ((State)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends dafny.CodePoint>, State>Let((_pat_let_tv1).dtor_url(), boxed122 -> {
          dafny.DafnySequence<? extends dafny.CodePoint> _pat_let61_0 = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(boxed122));
          return ((State)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends dafny.CodePoint>, State>Let(_pat_let61_0, boxed123 -> {
            dafny.DafnySequence<? extends dafny.CodePoint> _4_dt__update_hurl_h0 = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(boxed123));
            return ((State)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends dafny.CodePoint>, State>Let((_pat_let_tv2).dtor_verb(), boxed124 -> {
              dafny.DafnySequence<? extends dafny.CodePoint> _pat_let62_0 = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(boxed124));
              return ((State)(java.lang.Object)(dafny.Helpers.<dafny.DafnySequence<? extends dafny.CodePoint>, State>Let(_pat_let62_0, boxed125 -> {
                dafny.DafnySequence<? extends dafny.CodePoint> _5_dt__update_hverb_h0 = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(boxed125));
                return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(Phase.create_AwaitSession((_pat_let_tv3).dtor_hasBody()), boxed126 -> {
                  Phase _pat_let63_0 = ((Phase)(java.lang.Object)(boxed126));
                  return ((State)(java.lang.Object)(dafny.Helpers.<Phase, State>Let(_pat_let63_0, boxed127 -> {
                    Phase _6_dt__update_hphase_h0 = ((Phase)(java.lang.Object)(boxed127));
                    return State.create(_6_dt__update_hphase_h0, (_2_dt__update__tmp_h0).dtor_origin(), (_2_dt__update__tmp_h0).dtor_publicKey(), _5_dt__update_hverb_h0, _4_dt__update_hurl_h0, _3_dt__update_hheaders_h0, (_2_dt__update__tmp_h0).dtor_generation(), (_2_dt__update__tmp_h0).dtor_published(), (_2_dt__update__tmp_h0).dtor_token(), (_2_dt__update__tmp_h0).dtor_ctx());
                  }
                  )));
                }
                )));
              }
              )));
            }
            )));
          }
          )));
        }
        )));
      }
      )));
    }
    )));
  }
  )));
}
))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_BeginSession()));
    } else {
      EHBP.Code _7___mcc_h1 = ((EHBP.Result_Err<dafny.Tuple0>)_source0)._code;
      dafny.DafnySequence<? extends dafny.CodePoint> _8___mcc_h2 = ((EHBP.Result_Err<dafny.Tuple0>)_source0)._message;
      dafny.DafnySequence<? extends dafny.CodePoint> _9_message = _8___mcc_h2;
      EHBP.Code _10_code = _7___mcc_h1;
      return __default.Abort(s, false, _10_code, _9_message);
    }
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> StepUpload(State s, Upload up, Event e)
  {
    State _pat_let_tv0 = s;
    Upload _source0 = up;
    if (_source0.is_NoUpload()) {
      return __default.AbortUpload(s, EHBP.Code.create_Transport());
    } else if (_source0.is_Sealing()) {
      dafny.DafnySequence<? extends java.lang.Byte> _0___mcc_h0 = ((EHBPEvents.Upload_Sealing)_source0)._plaintext;
      int _1___mcc_h1 = ((EHBPEvents.Upload_Sealing)_source0)._offset;
      boolean _2___mcc_h2 = ((EHBPEvents.Upload_Sealing)_source0)._eof;
      boolean _3_eof = _2___mcc_h2;
      int _4_offset = _1___mcc_h1;
      dafny.DafnySequence<? extends java.lang.Byte> _5_plaintext = _0___mcc_h0;
      int _6_size = (_5_plaintext).cardinalityInt();
      int _7_at = __default.Min32(_4_offset, _6_size);
      int _8_n = __default.Min32((int) ((_6_size) - (_7_at)), EHBP.__default.RequestFrameBytes());
      if (!((e).is_AeadSealResult())) {
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (!java.util.Objects.equals(java.math.BigInteger.valueOf(((e).dtor_ciphertext()).length()), (dafny.Helpers.unsignedToBigInteger(_8_n)).add(EHBP.__default.AeadTagLength()))) {
        return __default.AbortUpload(s, EHBP.Code.create_HpkeSetupFailed());
      } else if ((((s).dtor_ctx()).dtor_seqNo()) == (__default.MaxSeq())) {
        return __default.AbortUpload(s, EHBP.Code.create_SequenceOverflow());
      } else {
        State _9_bumped = ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(s, boxed128 -> {
          State _pat_let64_0 = ((State)(java.lang.Object)(boxed128));
          return ((State)(java.lang.Object)(dafny.Helpers.<State, State>Let(_pat_let64_0, boxed129 -> {
            State _10_dt__update__tmp_h0 = ((State)(java.lang.Object)(boxed129));
            return ((State)(java.lang.Object)(dafny.Helpers.<Ctx, State>Let(__default.Bump((_pat_let_tv0).dtor_ctx()), boxed130 -> {
              Ctx _pat_let65_0 = ((Ctx)(java.lang.Object)(boxed130));
              return ((State)(java.lang.Object)(dafny.Helpers.<Ctx, State>Let(_pat_let65_0, boxed131 -> {
                Ctx _11_dt__update_hctx_h0 = ((Ctx)(java.lang.Object)(boxed131));
                return State.create((_10_dt__update__tmp_h0).dtor_phase(), (_10_dt__update__tmp_h0).dtor_origin(), (_10_dt__update__tmp_h0).dtor_publicKey(), (_10_dt__update__tmp_h0).dtor_verb(), (_10_dt__update__tmp_h0).dtor_url(), (_10_dt__update__tmp_h0).dtor_headers(), (_10_dt__update__tmp_h0).dtor_generation(), (_10_dt__update__tmp_h0).dtor_published(), (_10_dt__update__tmp_h0).dtor_token(), _11_dt__update_hctx_h0);
              }
              )));
            }
            )));
          }
          )));
        }
        )));
        int _12_next = (int) ((_7_at) + (_8_n));
        if (java.lang.Integer.compareUnsigned(_12_next, _6_size) < 0) {
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithUpload(_9_bumped, Upload.create_Sealing(_5_plaintext, _12_next, _3_eof)), dafny.DafnySequence.<Action>concatenate(__default.FrameWrites((e).dtor_ciphertext(), BodyEnd.create_More()), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), __default.SealAction((_9_bumped).dtor_ctx(), __default.Piece(_5_plaintext, _12_next, __default.Min32((int) ((_6_size) - (_12_next)), EHBP.__default.RequestFrameBytes()))))));
        } else if (_3_eof) {
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithUpload(_9_bumped, Upload.create_UpDone()), __default.FrameWrites((e).dtor_ciphertext(), BodyEnd.create_Done()));
        } else {
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithUpload(_9_bumped, Upload.create_UpReading(java.math.BigInteger.ZERO)), dafny.DafnySequence.<Action>concatenate(__default.FrameWrites((e).dtor_ciphertext(), BodyEnd.create_More()), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_RequestBody()))));
        }
      }
    } else if (_source0.is_UpReading()) {
      java.math.BigInteger _13___mcc_h6 = ((EHBPEvents.Upload_UpReading)_source0)._empty;
      java.math.BigInteger _14_empty = _13___mcc_h6;
      Event _source1 = e;
      if (_source1.is_Start()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _15___mcc_h8 = ((EHBPEvents.Event_Start)_source1)._verb;
        dafny.DafnySequence<? extends dafny.CodePoint> _16___mcc_h9 = ((EHBPEvents.Event_Start)_source1)._url;
        dafny.DafnySequence<? extends dafny.CodePoint> _17___mcc_h10 = ((EHBPEvents.Event_Start)_source1)._scheme;
        dafny.DafnySequence<? extends dafny.CodePoint> _18___mcc_h11 = ((EHBPEvents.Event_Start)_source1)._host;
        java.math.BigInteger _19___mcc_h12 = ((EHBPEvents.Event_Start)_source1)._port;
        boolean _20___mcc_h13 = ((EHBPEvents.Event_Start)_source1)._hasPort;
        boolean _21___mcc_h14 = ((EHBPEvents.Event_Start)_source1)._hasUserinfo;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _22___mcc_h15 = ((EHBPEvents.Event_Start)_source1)._headers;
        boolean _23___mcc_h16 = ((EHBPEvents.Event_Start)_source1)._hasBody;
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (_source1.is_DiscoverStart()) {
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (_source1.is_SessionBegun()) {
        long _24___mcc_h26 = ((EHBPEvents.Event_SessionBegun)_source1)._generation;
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (_source1.is_RandomResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _25___mcc_h28 = ((EHBPEvents.Event_RandomResult)_source1)._data;
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (_source1.is_X25519Result()) {
        dafny.DafnySequence<? extends java.lang.Byte> _26___mcc_h30 = ((EHBPEvents.Event_X25519Result)_source1)._point;
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (_source1.is_HmacResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _27___mcc_h32 = ((EHBPEvents.Event_HmacResult)_source1)._mac;
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (_source1.is_AeadSealResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _28___mcc_h34 = ((EHBPEvents.Event_AeadSealResult)_source1)._ciphertext;
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (_source1.is_AeadOpenResult()) {
        boolean _29___mcc_h36 = ((EHBPEvents.Event_AeadOpenResult)_source1)._ok;
        dafny.DafnySequence<? extends java.lang.Byte> _30___mcc_h37 = ((EHBPEvents.Event_AeadOpenResult)_source1)._plaintext;
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (_source1.is_ResponseHead()) {
        java.math.BigInteger _31___mcc_h40 = ((EHBPEvents.Event_ResponseHead)_source1)._status;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _32___mcc_h41 = ((EHBPEvents.Event_ResponseHead)_source1)._headers;
        boolean _33___mcc_h42 = ((EHBPEvents.Event_ResponseHead)_source1)._redirected;
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else if (_source1.is_Chunk()) {
        Stream _34___mcc_h46 = ((EHBPEvents.Event_Chunk)_source1)._stream;
        dafny.DafnySequence<? extends java.lang.Byte> _35___mcc_h47 = ((EHBPEvents.Event_Chunk)_source1)._data;
        boolean _36___mcc_h48 = ((EHBPEvents.Event_Chunk)_source1)._eof;
        Stream _source2 = _34___mcc_h46;
        if (_source2.is_RequestBody()) {
          boolean _37_eof = _36___mcc_h48;
          dafny.DafnySequence<? extends java.lang.Byte> _38_data = _35___mcc_h47;
          if ((java.math.BigInteger.valueOf((_38_data).length())).compareTo(__default.MaxReadBytes()) > 0) {
            return __default.AbortUpload(s, EHBP.Code.create_Transport());
          } else if ((java.math.BigInteger.valueOf((_38_data).length())).signum() == 1) {
            return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithUpload(s, Upload.create_Sealing(_38_data, 0, _37_eof)), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), __default.SealAction((s).dtor_ctx(), __default.Piece(_38_data, 0, __default.Min32((_38_data).cardinalityInt(), EHBP.__default.RequestFrameBytes())))));
          } else if (_37_eof) {
            return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithUpload(s, Upload.create_UpDone()), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Write(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), BodyEnd.create_Done())));
          } else if (java.util.Objects.equals((_14_empty).add(java.math.BigInteger.ONE), EHBP.__default.MaxEmptyReads())) {
            return __default.AbortUpload(s, EHBP.Code.create_Transport());
          } else {
            return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithUpload(s, Upload.create_UpReading((_14_empty).add(java.math.BigInteger.ONE))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_RequestBody())));
          }
        } else {
          return __default.AbortUpload(s, EHBP.Code.create_Transport());
        }
      } else if (_source1.is_StreamFailed()) {
        Stream _39___mcc_h52 = ((EHBPEvents.Event_StreamFailed)_source1)._stream;
        Stream _source3 = _39___mcc_h52;
        if (_source3.is_RequestBody()) {
          return __default.AbortUpload(s, EHBP.Code.create_Transport());
        } else {
          return __default.AbortUpload(s, EHBP.Code.create_Transport());
        }
      } else if (_source1.is_CallerRead()) {
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      } else {
        return __default.AbortUpload(s, EHBP.Code.create_Transport());
      }
    } else {
      return __default.AbortUpload(s, EHBP.Code.create_Transport());
    }
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> StepResponse(State s, Response rs, Event e)
  {
    Response _source0 = rs;
    if (_source0.is_AwaitHead()) {
      boolean _0___mcc_h0 = ((EHBPEvents.Response_AwaitHead)_source0)._encrypted;
      boolean _1_encrypted = _0___mcc_h0;
      Event _source1 = e;
      if (_source1.is_Start()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h21 = ((EHBPEvents.Event_Start)_source1)._verb;
        dafny.DafnySequence<? extends dafny.CodePoint> _3___mcc_h22 = ((EHBPEvents.Event_Start)_source1)._url;
        dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h23 = ((EHBPEvents.Event_Start)_source1)._scheme;
        dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h24 = ((EHBPEvents.Event_Start)_source1)._host;
        java.math.BigInteger _6___mcc_h25 = ((EHBPEvents.Event_Start)_source1)._port;
        boolean _7___mcc_h26 = ((EHBPEvents.Event_Start)_source1)._hasPort;
        boolean _8___mcc_h27 = ((EHBPEvents.Event_Start)_source1)._hasUserinfo;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _9___mcc_h28 = ((EHBPEvents.Event_Start)_source1)._headers;
        boolean _10___mcc_h29 = ((EHBPEvents.Event_Start)_source1)._hasBody;
        return __default.Unexpected(s);
      } else if (_source1.is_DiscoverStart()) {
        return __default.Unexpected(s);
      } else if (_source1.is_SessionBegun()) {
        long _11___mcc_h39 = ((EHBPEvents.Event_SessionBegun)_source1)._generation;
        return __default.Unexpected(s);
      } else if (_source1.is_RandomResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _12___mcc_h41 = ((EHBPEvents.Event_RandomResult)_source1)._data;
        return __default.Unexpected(s);
      } else if (_source1.is_X25519Result()) {
        dafny.DafnySequence<? extends java.lang.Byte> _13___mcc_h43 = ((EHBPEvents.Event_X25519Result)_source1)._point;
        return __default.Unexpected(s);
      } else if (_source1.is_HmacResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _14___mcc_h45 = ((EHBPEvents.Event_HmacResult)_source1)._mac;
        return __default.Unexpected(s);
      } else if (_source1.is_AeadSealResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _15___mcc_h47 = ((EHBPEvents.Event_AeadSealResult)_source1)._ciphertext;
        return __default.Unexpected(s);
      } else if (_source1.is_AeadOpenResult()) {
        boolean _16___mcc_h49 = ((EHBPEvents.Event_AeadOpenResult)_source1)._ok;
        dafny.DafnySequence<? extends java.lang.Byte> _17___mcc_h50 = ((EHBPEvents.Event_AeadOpenResult)_source1)._plaintext;
        return __default.Unexpected(s);
      } else if (_source1.is_ResponseHead()) {
        java.math.BigInteger _18___mcc_h53 = ((EHBPEvents.Event_ResponseHead)_source1)._status;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _19___mcc_h54 = ((EHBPEvents.Event_ResponseHead)_source1)._headers;
        boolean _20___mcc_h55 = ((EHBPEvents.Event_ResponseHead)_source1)._redirected;
        boolean _21_redirected = _20___mcc_h55;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _22_headers = _19___mcc_h54;
        java.math.BigInteger _23_status = _18___mcc_h53;
        if ((!(_21_redirected)) && (((_23_status).compareTo(java.math.BigInteger.valueOf(100L)) < 0) || ((_23_status).compareTo(java.math.BigInteger.valueOf(599L)) > 0))) {
          return __default.Abort(s, true, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("transport reported an impossible status"));
        } else {
          EHBP.Disposition _source2 = EHBP.__default.Classify(_1_encrypted, EHBP.Head.create(_23_status, _22_headers, _21_redirected));
          if (_source2.is_PassThrough()) {
            return __default.End(s, false, Action.create_Passthrough(_23_status, _22_headers, dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor())));
          } else if (_source2.is_Decrypt()) {
            dafny.DafnySequence<? extends java.lang.Byte> _24___mcc_h67 = ((EHBP.Disposition_Decrypt)_source2)._nonce;
            boolean _25___mcc_h68 = ((EHBP.Disposition_Decrypt)_source2)._requireFrame;
            boolean _26_requireFrame = _25___mcc_h68;
            dafny.DafnySequence<? extends java.lang.Byte> _27_nonce = _24___mcc_h67;
            if (!(EHBP.__default.ValidToken((s).dtor_token()))) {
              return __default.Abort(s, true, EHBP.Code.create_InvalidInput(), dafny.DafnySequence.asUnicodeString("token fields must be 32 bytes"));
            } else if (!java.util.Objects.equals(java.math.BigInteger.valueOf((_27_nonce).length()), EHBP.__default.ResponseNonceLength())) {
              return __default.Abort(s, true, EHBP.Code.create_InvalidInput(), dafny.DafnySequence.asUnicodeString("response nonce must be 32 bytes"));
            } else {
              Job _28_job = __default.Extract(dafny.DafnySequence.<java.lang.Byte>concatenate(((s).dtor_token()).dtor_requestEnc(), _27_nonce), ((s).dtor_token()).dtor_exportedSecret());
              return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_AwaitKeys(_23_status, _22_headers, _26_requireFrame, java.math.BigInteger.ZERO, _28_job, dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), __default.JobAction(_28_job)));
            }
          } else if (_source2.is_NeedProblemBody()) {
            return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_ProblemReading(_23_status, _22_headers, dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_ResponseBody())));
          } else {
            EHBP.Code _29___mcc_h69 = ((EHBP.Disposition_Refuse)_source2)._code;
            dafny.DafnySequence<? extends dafny.CodePoint> _30___mcc_h70 = ((EHBP.Disposition_Refuse)_source2)._message;
            dafny.DafnySequence<? extends dafny.CodePoint> _31_message = _30___mcc_h70;
            EHBP.Code _32_code = _29___mcc_h69;
            return __default.Abort(s, true, _32_code, _31_message);
          }
        }
      } else if (_source1.is_Chunk()) {
        Stream _33___mcc_h59 = ((EHBPEvents.Event_Chunk)_source1)._stream;
        dafny.DafnySequence<? extends java.lang.Byte> _34___mcc_h60 = ((EHBPEvents.Event_Chunk)_source1)._data;
        boolean _35___mcc_h61 = ((EHBPEvents.Event_Chunk)_source1)._eof;
        return __default.Unexpected(s);
      } else if (_source1.is_StreamFailed()) {
        Stream _36___mcc_h65 = ((EHBPEvents.Event_StreamFailed)_source1)._stream;
        Stream _source3 = _36___mcc_h65;
        if (_source3.is_RequestBody()) {
          return __default.Unexpected(s);
        } else {
          return __default.Abort(s, false, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("failed to make request"));
        }
      } else if (_source1.is_CallerRead()) {
        return __default.Unexpected(s);
      } else {
        return __default.Unexpected(s);
      }
    } else if (_source0.is_ProblemReading()) {
      java.math.BigInteger _37___mcc_h1 = ((EHBPEvents.Response_ProblemReading)_source0)._status;
      dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _38___mcc_h2 = ((EHBPEvents.Response_ProblemReading)_source0)._headers;
      dafny.DafnySequence<? extends java.lang.Byte> _39___mcc_h3 = ((EHBPEvents.Response_ProblemReading)_source0)._data;
      dafny.DafnySequence<? extends java.lang.Byte> _40_data = _39___mcc_h3;
      dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _41_headers = _38___mcc_h2;
      java.math.BigInteger _42_status = _37___mcc_h1;
      Event _source4 = e;
      if (_source4.is_Start()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _43___mcc_h71 = ((EHBPEvents.Event_Start)_source4)._verb;
        dafny.DafnySequence<? extends dafny.CodePoint> _44___mcc_h72 = ((EHBPEvents.Event_Start)_source4)._url;
        dafny.DafnySequence<? extends dafny.CodePoint> _45___mcc_h73 = ((EHBPEvents.Event_Start)_source4)._scheme;
        dafny.DafnySequence<? extends dafny.CodePoint> _46___mcc_h74 = ((EHBPEvents.Event_Start)_source4)._host;
        java.math.BigInteger _47___mcc_h75 = ((EHBPEvents.Event_Start)_source4)._port;
        boolean _48___mcc_h76 = ((EHBPEvents.Event_Start)_source4)._hasPort;
        boolean _49___mcc_h77 = ((EHBPEvents.Event_Start)_source4)._hasUserinfo;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _50___mcc_h78 = ((EHBPEvents.Event_Start)_source4)._headers;
        boolean _51___mcc_h79 = ((EHBPEvents.Event_Start)_source4)._hasBody;
        return __default.Unexpected(s);
      } else if (_source4.is_DiscoverStart()) {
        return __default.Unexpected(s);
      } else if (_source4.is_SessionBegun()) {
        long _52___mcc_h89 = ((EHBPEvents.Event_SessionBegun)_source4)._generation;
        return __default.Unexpected(s);
      } else if (_source4.is_RandomResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _53___mcc_h91 = ((EHBPEvents.Event_RandomResult)_source4)._data;
        return __default.Unexpected(s);
      } else if (_source4.is_X25519Result()) {
        dafny.DafnySequence<? extends java.lang.Byte> _54___mcc_h93 = ((EHBPEvents.Event_X25519Result)_source4)._point;
        return __default.Unexpected(s);
      } else if (_source4.is_HmacResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _55___mcc_h95 = ((EHBPEvents.Event_HmacResult)_source4)._mac;
        return __default.Unexpected(s);
      } else if (_source4.is_AeadSealResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _56___mcc_h97 = ((EHBPEvents.Event_AeadSealResult)_source4)._ciphertext;
        return __default.Unexpected(s);
      } else if (_source4.is_AeadOpenResult()) {
        boolean _57___mcc_h99 = ((EHBPEvents.Event_AeadOpenResult)_source4)._ok;
        dafny.DafnySequence<? extends java.lang.Byte> _58___mcc_h100 = ((EHBPEvents.Event_AeadOpenResult)_source4)._plaintext;
        return __default.Unexpected(s);
      } else if (_source4.is_ResponseHead()) {
        java.math.BigInteger _59___mcc_h103 = ((EHBPEvents.Event_ResponseHead)_source4)._status;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _60___mcc_h104 = ((EHBPEvents.Event_ResponseHead)_source4)._headers;
        boolean _61___mcc_h105 = ((EHBPEvents.Event_ResponseHead)_source4)._redirected;
        return __default.Unexpected(s);
      } else if (_source4.is_Chunk()) {
        Stream _62___mcc_h109 = ((EHBPEvents.Event_Chunk)_source4)._stream;
        dafny.DafnySequence<? extends java.lang.Byte> _63___mcc_h110 = ((EHBPEvents.Event_Chunk)_source4)._data;
        boolean _64___mcc_h111 = ((EHBPEvents.Event_Chunk)_source4)._eof;
        Stream _source5 = _62___mcc_h109;
        if (_source5.is_RequestBody()) {
          return __default.Unexpected(s);
        } else {
          boolean _65_eof = _64___mcc_h111;
          dafny.DafnySequence<? extends java.lang.Byte> _66_chunk = _63___mcc_h110;
          dafny.DafnySequence<? extends java.lang.Byte> _67_grown = dafny.DafnySequence.<java.lang.Byte>concatenate(_40_data, _66_chunk);
          if (((java.math.BigInteger.valueOf((_67_grown).length())).compareTo((EHBP.__default.MaxProblemBytes()).add(java.math.BigInteger.ONE)) <= 0) && (!(_65_eof))) {
            return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_ProblemReading(_42_status, _41_headers, _67_grown)), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_ResponseBody())));
          } else {
            boolean _68_oversized = (java.math.BigInteger.valueOf((_67_grown).length())).compareTo(EHBP.__default.MaxProblemBytes()) > 0;
            dafny.Tuple3<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>> _let_tmp_rhs0 = ((_68_oversized) ? (dafny.Tuple3.<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>create(false, EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), EHBP.Option.<dafny.DafnySequence<? extends dafny.CodePoint>>create_None(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)))) : (__default.ParseProblem(_67_grown)));
            boolean _69_isObject = ((boolean)(java.lang.Object)(((dafny.Tuple3<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>)_let_tmp_rhs0).dtor__0()));
            EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>> _70_typeValue = ((EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>)(java.lang.Object)(((dafny.Tuple3<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>)_let_tmp_rhs0).dtor__1()));
            EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>> _71_title = ((EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>)(java.lang.Object)(((dafny.Tuple3<Boolean, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>, EHBP.Option<dafny.DafnySequence<? extends dafny.CodePoint>>>)_let_tmp_rhs0).dtor__2()));
            EHBP.Disposition _source6 = EHBP.__default.ClassifyProblem(_68_oversized, _69_isObject, _70_typeValue, _71_title);
            if (_source6.is_PassThrough()) {
              return __default.End(s, false, Action.create_Passthrough(_42_status, _41_headers, _67_grown));
            } else if (_source6.is_Decrypt()) {
              dafny.DafnySequence<? extends java.lang.Byte> _72___mcc_h117 = ((EHBP.Disposition_Decrypt)_source6)._nonce;
              boolean _73___mcc_h118 = ((EHBP.Disposition_Decrypt)_source6)._requireFrame;
              return __default.Abort(s, true, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("unreachable"));
            } else if (_source6.is_NeedProblemBody()) {
              return __default.Abort(s, true, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("unreachable"));
            } else {
              EHBP.Code _74___mcc_h121 = ((EHBP.Disposition_Refuse)_source6)._code;
              dafny.DafnySequence<? extends dafny.CodePoint> _75___mcc_h122 = ((EHBP.Disposition_Refuse)_source6)._message;
              dafny.DafnySequence<? extends dafny.CodePoint> _76_message = _75___mcc_h122;
              EHBP.Code _77_code = _74___mcc_h121;
              return __default.Abort(s, true, _77_code, _76_message);
            }
          }
        }
      } else if (_source4.is_StreamFailed()) {
        Stream _78___mcc_h115 = ((EHBPEvents.Event_StreamFailed)_source4)._stream;
        Stream _source7 = _78___mcc_h115;
        if (_source7.is_RequestBody()) {
          return __default.Unexpected(s);
        } else {
          return __default.Abort(s, true, EHBP.Code.create_Transport(), dafny.DafnySequence.asUnicodeString("failed to read problem response"));
        }
      } else if (_source4.is_CallerRead()) {
        return __default.Unexpected(s);
      } else {
        return __default.Unexpected(s);
      }
    } else if (_source0.is_AwaitKeys()) {
      java.math.BigInteger _79___mcc_h4 = ((EHBPEvents.Response_AwaitKeys)_source0)._status;
      dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _80___mcc_h5 = ((EHBPEvents.Response_AwaitKeys)_source0)._headers;
      boolean _81___mcc_h6 = ((EHBPEvents.Response_AwaitKeys)_source0)._requireFrame;
      java.math.BigInteger _82___mcc_h7 = ((EHBPEvents.Response_AwaitKeys)_source0)._stage;
      Job _83___mcc_h8 = ((EHBPEvents.Response_AwaitKeys)_source0)._job;
      dafny.DafnySequence<? extends java.lang.Byte> _84___mcc_h9 = ((EHBPEvents.Response_AwaitKeys)_source0)._prk;
      dafny.DafnySequence<? extends java.lang.Byte> _85___mcc_h10 = ((EHBPEvents.Response_AwaitKeys)_source0)._key;
      dafny.DafnySequence<? extends java.lang.Byte> _86_key = _85___mcc_h10;
      dafny.DafnySequence<? extends java.lang.Byte> _87_prk = _84___mcc_h9;
      Job _88_job = _83___mcc_h8;
      java.math.BigInteger _89_stage = _82___mcc_h7;
      boolean _90_requireFrame = _81___mcc_h6;
      dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _91_headers = _80___mcc_h5;
      java.math.BigInteger _92_status = _79___mcc_h4;
      JobOut _source8 = __default.JobStep(_88_job, e);
      if (_source8.is_Pending()) {
        Job _93___mcc_h125 = ((EHBPEvents.JobOut_Pending)_source8)._job;
        Action _94___mcc_h126 = ((EHBPEvents.JobOut_Pending)_source8)._action;
        Action _95_a = _94___mcc_h126;
        Job _96_next = _93___mcc_h125;
        return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_AwaitKeys(_92_status, _91_headers, _90_requireFrame, _89_stage, _96_next, _87_prk, _86_key)), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), _95_a));
      } else if (_source8.is_Output()) {
        dafny.DafnySequence<? extends java.lang.Byte> _97___mcc_h127 = ((EHBPEvents.JobOut_Output)_source8)._data;
        dafny.DafnySequence<? extends java.lang.Byte> _98_out = _97___mcc_h127;
        if ((_89_stage).signum() == 0) {
          Job _99_next = __default.Expand(_98_out, EHBP.__default.Ascii(EHBP.__default.ResponseKeyLabel()), EHBP.__default.KeyLength());
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_AwaitKeys(_92_status, _91_headers, _90_requireFrame, java.math.BigInteger.ONE, _99_next, _98_out, dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()))), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), __default.JobAction(_99_next)));
        } else if (java.util.Objects.equals(_89_stage, java.math.BigInteger.ONE)) {
          Job _100_next = __default.Expand(_87_prk, EHBP.__default.Ascii(EHBP.__default.ResponseNonceLabel()), EHBP.__default.NonceLength());
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_AwaitKeys(_92_status, _91_headers, _90_requireFrame, java.math.BigInteger.valueOf(2L), _100_next, _87_prk, _98_out)), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), __default.JobAction(_100_next)));
        } else if ((java.util.Objects.equals(java.math.BigInteger.valueOf((_86_key).length()), EHBP.__default.KeyLength())) && (java.util.Objects.equals(java.math.BigInteger.valueOf((_98_out).length()), EHBP.__default.NonceLength()))) {
          dafny.DafnySequence<? extends java.lang.Byte> _101_k = _86_key;
          dafny.DafnySequence<? extends java.lang.Byte> _102_n = _98_out;
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_Body(Ctx.create(_101_k, _102_n, dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), (long) 0L), Dec.create(dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), (long) 0L, false, _90_requireFrame), false)), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Done(_92_status, EHBP.__default.DropFraming(_91_headers))));
        } else {
          return __default.Abort(s, true, EHBP.Code.create_HpkeSetupFailed(), dafny.DafnySequence.asUnicodeString("HKDF expand returned the wrong length"));
        }
      } else {
        EHBP.Code _103___mcc_h128 = ((EHBPEvents.JobOut_JobFailed)_source8)._code;
        dafny.DafnySequence<? extends dafny.CodePoint> _104___mcc_h129 = ((EHBPEvents.JobOut_JobFailed)_source8)._message;
        dafny.DafnySequence<? extends dafny.CodePoint> _105_message = _104___mcc_h129;
        EHBP.Code _106_code = _103___mcc_h128;
        return __default.Abort(s, true, _106_code, _105_message);
      }
    } else if (_source0.is_Body()) {
      Ctx _107___mcc_h11 = ((EHBPEvents.Response_Body)_source0)._keys;
      Dec _108___mcc_h12 = ((EHBPEvents.Response_Body)_source0)._dec;
      boolean _109___mcc_h13 = ((EHBPEvents.Response_Body)_source0)._done;
      boolean _110_done = _109___mcc_h13;
      Dec _111_dec = _108___mcc_h12;
      Ctx _112_keys = _107___mcc_h11;
      if (!((e).is_CallerRead())) {
        return __default.Unexpected(s);
      } else if (_110_done) {
        return __default.End(s, false, Action.create_Finished());
      } else {
        return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_BodyReading(_112_keys, _111_dec)), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_ResponseBody())));
      }
    } else if (_source0.is_BodyReading()) {
      Ctx _113___mcc_h14 = ((EHBPEvents.Response_BodyReading)_source0)._keys;
      Dec _114___mcc_h15 = ((EHBPEvents.Response_BodyReading)_source0)._dec;
      Dec _115_dec = _114___mcc_h15;
      Ctx _116_keys = _113___mcc_h14;
      Event _source9 = e;
      if (_source9.is_Start()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _117___mcc_h130 = ((EHBPEvents.Event_Start)_source9)._verb;
        dafny.DafnySequence<? extends dafny.CodePoint> _118___mcc_h131 = ((EHBPEvents.Event_Start)_source9)._url;
        dafny.DafnySequence<? extends dafny.CodePoint> _119___mcc_h132 = ((EHBPEvents.Event_Start)_source9)._scheme;
        dafny.DafnySequence<? extends dafny.CodePoint> _120___mcc_h133 = ((EHBPEvents.Event_Start)_source9)._host;
        java.math.BigInteger _121___mcc_h134 = ((EHBPEvents.Event_Start)_source9)._port;
        boolean _122___mcc_h135 = ((EHBPEvents.Event_Start)_source9)._hasPort;
        boolean _123___mcc_h136 = ((EHBPEvents.Event_Start)_source9)._hasUserinfo;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _124___mcc_h137 = ((EHBPEvents.Event_Start)_source9)._headers;
        boolean _125___mcc_h138 = ((EHBPEvents.Event_Start)_source9)._hasBody;
        return __default.Unexpected(s);
      } else if (_source9.is_DiscoverStart()) {
        return __default.Unexpected(s);
      } else if (_source9.is_SessionBegun()) {
        long _126___mcc_h148 = ((EHBPEvents.Event_SessionBegun)_source9)._generation;
        return __default.Unexpected(s);
      } else if (_source9.is_RandomResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _127___mcc_h150 = ((EHBPEvents.Event_RandomResult)_source9)._data;
        return __default.Unexpected(s);
      } else if (_source9.is_X25519Result()) {
        dafny.DafnySequence<? extends java.lang.Byte> _128___mcc_h152 = ((EHBPEvents.Event_X25519Result)_source9)._point;
        return __default.Unexpected(s);
      } else if (_source9.is_HmacResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _129___mcc_h154 = ((EHBPEvents.Event_HmacResult)_source9)._mac;
        return __default.Unexpected(s);
      } else if (_source9.is_AeadSealResult()) {
        dafny.DafnySequence<? extends java.lang.Byte> _130___mcc_h156 = ((EHBPEvents.Event_AeadSealResult)_source9)._ciphertext;
        return __default.Unexpected(s);
      } else if (_source9.is_AeadOpenResult()) {
        boolean _131___mcc_h158 = ((EHBPEvents.Event_AeadOpenResult)_source9)._ok;
        dafny.DafnySequence<? extends java.lang.Byte> _132___mcc_h159 = ((EHBPEvents.Event_AeadOpenResult)_source9)._plaintext;
        return __default.Unexpected(s);
      } else if (_source9.is_ResponseHead()) {
        java.math.BigInteger _133___mcc_h162 = ((EHBPEvents.Event_ResponseHead)_source9)._status;
        dafny.DafnySequence<? extends dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>>> _134___mcc_h163 = ((EHBPEvents.Event_ResponseHead)_source9)._headers;
        boolean _135___mcc_h164 = ((EHBPEvents.Event_ResponseHead)_source9)._redirected;
        return __default.Unexpected(s);
      } else if (_source9.is_Chunk()) {
        Stream _136___mcc_h168 = ((EHBPEvents.Event_Chunk)_source9)._stream;
        dafny.DafnySequence<? extends java.lang.Byte> _137___mcc_h169 = ((EHBPEvents.Event_Chunk)_source9)._data;
        boolean _138___mcc_h170 = ((EHBPEvents.Event_Chunk)_source9)._eof;
        Stream _source10 = _136___mcc_h168;
        if (_source10.is_RequestBody()) {
          return __default.Unexpected(s);
        } else {
          boolean _139_eof = _138___mcc_h170;
          dafny.DafnySequence<? extends java.lang.Byte> _140_data = _137___mcc_h169;
          dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>> _let_tmp_rhs1 = __default.Push(_115_dec, _140_data);
          dafny.DafnySequence<? extends EHBP.Framed> _141_frames = ((dafny.DafnySequence<? extends EHBP.Framed>)(java.lang.Object)(((dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>)_let_tmp_rhs1).dtor__0()));
          Dec _142_next = ((Dec)(java.lang.Object)(((dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>)_let_tmp_rhs1).dtor__1()));
          EHBP.Option<EHBP.Code> _143_err = ((EHBP.Option<EHBP.Code>)(java.lang.Object)(((dafny.Tuple3<dafny.DafnySequence<? extends EHBP.Framed>, Dec, EHBP.Option<EHBP.Code>>)_let_tmp_rhs1).dtor__2()));
          if ((_143_err).is_Some()) {
            return __default.Abort(s, false, (_143_err).dtor_value(), dafny.DafnySequence.asUnicodeString(""));
          } else {
            return __default.OpenNext(s, _116_keys, _142_next, _141_frames, dafny.DafnySequence.<dafny.DafnySequence<? extends java.lang.Byte>> empty(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(EHBP.uint8._typeDescriptor())), _139_eof);
          }
        }
      } else if (_source9.is_StreamFailed()) {
        Stream _144___mcc_h174 = ((EHBPEvents.Event_StreamFailed)_source9)._stream;
        Stream _source11 = _144___mcc_h174;
        if (_source11.is_RequestBody()) {
          return __default.Unexpected(s);
        } else {
          return __default.Abort(s, false, EHBP.Code.create_FramingTruncated(), dafny.DafnySequence.asUnicodeString("response body failed"));
        }
      } else if (_source9.is_CallerRead()) {
        return __default.Unexpected(s);
      } else {
        return __default.Unexpected(s);
      }
    } else if (_source0.is_Opening()) {
      Ctx _145___mcc_h16 = ((EHBPEvents.Response_Opening)_source0)._keys;
      Dec _146___mcc_h17 = ((EHBPEvents.Response_Opening)_source0)._dec;
      dafny.DafnySequence<? extends EHBP.Framed> _147___mcc_h18 = ((EHBPEvents.Response_Opening)_source0)._frames;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.lang.Byte>> _148___mcc_h19 = ((EHBPEvents.Response_Opening)_source0)._chunks;
      boolean _149___mcc_h20 = ((EHBPEvents.Response_Opening)_source0)._eof;
      boolean _150_eof = _149___mcc_h20;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.lang.Byte>> _151_chunks = _148___mcc_h19;
      dafny.DafnySequence<? extends EHBP.Framed> _152_frames = _147___mcc_h18;
      Dec _153_dec = _146___mcc_h17;
      Ctx _154_keys = _145___mcc_h16;
      if ((!((e).is_AeadOpenResult())) || ((java.math.BigInteger.valueOf((_152_frames).length())).signum() == 0)) {
        return __default.Unexpected(s);
      } else if (!((e).dtor_ok())) {
        return __default.Abort(s, false, EHBP.Code.create_AeadDecryptFailed(), dafny.DafnySequence.asUnicodeString("frame failed to authenticate"));
      } else if (!java.util.Objects.equals((java.math.BigInteger.valueOf(((e).dtor_plaintext()).length())).add(EHBP.__default.AeadTagLength()), java.math.BigInteger.valueOf(((((EHBP.Framed)(java.lang.Object)((_152_frames).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_ciphertext()).length()))) {
        return __default.Abort(s, false, EHBP.Code.create_AeadDecryptFailed(), dafny.DafnySequence.asUnicodeString("AEAD returned the wrong length"));
      } else {
        return __default.OpenNext(s, _154_keys, _153_dec, (_152_frames).drop(java.math.BigInteger.ONE), (((java.math.BigInteger.valueOf(((e).dtor_plaintext()).length())).signum() == 1) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends java.lang.Byte>>concatenate(_151_chunks, dafny.DafnySequence.<dafny.DafnySequence<? extends java.lang.Byte>> of(dafny.DafnySequence.<java.lang.Byte>_typeDescriptor(EHBP.uint8._typeDescriptor()), (e).dtor_plaintext()))) : (_151_chunks)), _150_eof);
      }
    } else {
      return __default.Unexpected(s);
    }
  }
  public static dafny.DafnySequence<? extends Action> Emits(dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.lang.Byte>> chunks) {
    return dafny.DafnySequence.Create(Action._typeDescriptor(), java.math.BigInteger.valueOf((chunks).length()), ((java.util.function.Function<dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.lang.Byte>>, java.util.function.Function<java.math.BigInteger, Action>>)(_0_chunks) -> {return ((java.util.function.Function<java.math.BigInteger, Action>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return Action.create_EmitPlaintext(((dafny.DafnySequence<? extends java.lang.Byte>)(java.lang.Object)((_0_chunks).select(dafny.Helpers.toInt((_1_i))))));
    });}).apply(chunks));
  }
  public static dafny.Tuple2<State, dafny.DafnySequence<? extends Action>> OpenNext(State s, Ctx keys, Dec dec, dafny.DafnySequence<? extends EHBP.Framed> frames, dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.lang.Byte>> chunks, boolean eof)
  {
    if ((java.math.BigInteger.valueOf((frames).length())).signum() == 1) {
      if ((java.math.BigInteger.valueOf(((((EHBP.Framed)(java.lang.Object)((frames).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_ciphertext()).length())).compareTo(EHBP.__default.AeadTagLength()) < 0) {
        return __default.Abort(s, false, EHBP.Code.create_AeadDecryptFailed(), dafny.DafnySequence.asUnicodeString("frame shorter than the AEAD tag"));
      } else {
        return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_Opening(keys, dec, frames, chunks, eof)), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_AeadOpen((keys).dtor_key(), EHBP.__default.ComputeNonce((keys).dtor_baseNonce(), (((EHBP.Framed)(java.lang.Object)((frames).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_seqNo()), (((EHBP.Framed)(java.lang.Object)((frames).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_ciphertext())));
      }
    } else if (eof) {
      EHBP.Option<EHBP.Code> _source0 = __default.Finish(dec);
      if (_source0.is_None()) {
        if ((java.math.BigInteger.valueOf((chunks).length())).signum() == 1) {
          return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_Body(keys, dec, true)), __default.Emits(chunks));
        } else {
          return __default.End(s, false, Action.create_Finished());
        }
      } else {
        EHBP.Code _0___mcc_h0 = ((EHBP.Option_Some<EHBP.Code>)_source0)._value;
        EHBP.Code _1_code = _0___mcc_h0;
        return __default.Abort(s, false, _1_code, dafny.DafnySequence.asUnicodeString(""));
      }
    } else if ((java.math.BigInteger.valueOf((chunks).length())).signum() == 1) {
      return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_Body(keys, dec, false)), __default.Emits(chunks));
    } else {
      return dafny.Tuple2.<State, dafny.DafnySequence<? extends Action>>create(__default.WithResponse(s, Response.create_BodyReading(keys, dec)), dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_Read(Stream.create_ResponseBody())));
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Hex(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    EHBP.Option<dafny.DafnySequence<? extends java.lang.Byte>> _source0 = EHBP.__default.DecodeHex(s);
    if (_source0.is_None()) {
      return dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor());
    } else {
      dafny.DafnySequence<? extends java.lang.Byte> _0___mcc_h0 = ((EHBP.Option_Some<dafny.DafnySequence<? extends java.lang.Byte>>)_source0)._value;
      dafny.DafnySequence<? extends java.lang.Byte> _1_b = _0___mcc_h0;
      return _1_b;
    }
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> SelfCheckJudge(dafny.DafnySequence<? extends Event> results) {
    if (!java.util.Objects.equals(java.math.BigInteger.valueOf((results).length()), java.math.BigInteger.valueOf((__default.SelfCheckActions()).length()))) {
      return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("self-check: wrong number of results"));
    } else {
      return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(((!java.util.Objects.equals(((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), Event.create_HmacResult(__default.HmacTag()))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("HmacSha256: RFC 4231 test case 1"))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)))), ((!java.util.Objects.equals(((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.ONE))))), Event.create_X25519Result(__default.AlicePk()))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("X25519: RFC 7748 base point"))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))))), ((!java.util.Objects.equals(((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(2L)))))), Event.create_X25519Result(__default.AliceBobShared()))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("X25519: RFC 7748 shared secret"))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))))), ((!java.util.Objects.equals(((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(3L)))))), Event.create_AeadSealResult(__default.GcmCt()))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("AeadSeal: known answer"))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))))), ((!java.util.Objects.equals(((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(4L)))))), Event.create_AeadOpenResult(true, EHBP.__default.Ascii(dafny.DafnySequence.asUnicodeString("ehbp"))))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("AeadOpen: known answer"))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))))), (((!((((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(5L))))))).is_AeadOpenResult())) || ((((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(5L))))))).dtor_ok())) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("AeadOpen: accepted a tampered tag"))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))))), (((!((((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(6L))))))).is_AeadOpenResult())) || ((((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(6L))))))).dtor_ok())) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("AeadOpen: accepted a frame shorter than the tag"))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))))), (((((!((((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(7L))))))).is_RandomResult())) || (!((((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(8L))))))).is_RandomResult()))) || (!java.util.Objects.equals(java.math.BigInteger.valueOf(((((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(7L))))))).dtor_data()).length()), java.math.BigInteger.valueOf(32L)))) || (!java.util.Objects.equals(java.math.BigInteger.valueOf(((((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(8L))))))).dtor_data()).length()), java.math.BigInteger.valueOf(32L)))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("RandomBytes: length"))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))))), ((java.util.Objects.equals(((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(7L)))))), ((Event)(java.lang.Object)((results).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(8L)))))))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("RandomBytes: repeated output"))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)))));
    }
  }
  public static int Rotr(int x, java.math.BigInteger n)
  {
    return (int) ((dafny.Helpers.bv32ShiftRight(x, (n).byteValue())) | ((int) ((dafny.Helpers.bv32ShiftLeft(x, ((java.math.BigInteger.valueOf(32L)).subtract(n)).byteValue())))));
  }
  public static int Word(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger i)
  {
    return (dafny.Helpers.unsignedToBigInteger(EHBP.__default.U32(b, i))).intValue();
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> WordBytes(int w) {
    return EHBP.__default.BE32((dafny.Helpers.unsignedToBigInteger(w)).intValue());
  }
  public static dafny.DafnySequence<? extends java.lang.Integer> MessageSchedule(dafny.DafnySequence<? extends java.lang.Integer> w) {
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(java.math.BigInteger.valueOf((w).length()), java.math.BigInteger.valueOf(64L))) {
        return w;
      } else {
        int _0_s0 = (int) (((int) ((__default.Rotr(((int)(java.lang.Object)((w).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((w).length())).subtract(java.math.BigInteger.valueOf(15L))))))), java.math.BigInteger.valueOf(7L))) ^ (__default.Rotr(((int)(java.lang.Object)((w).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((w).length())).subtract(java.math.BigInteger.valueOf(15L))))))), java.math.BigInteger.valueOf(18L))))) ^ (dafny.Helpers.bv32ShiftRight(((int)(java.lang.Object)((w).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((w).length())).subtract(java.math.BigInteger.valueOf(15L))))))), (byte) 3)));
        int _1_s1 = (int) (((int) ((__default.Rotr(((int)(java.lang.Object)((w).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((w).length())).subtract(java.math.BigInteger.valueOf(2L))))))), java.math.BigInteger.valueOf(17L))) ^ (__default.Rotr(((int)(java.lang.Object)((w).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((w).length())).subtract(java.math.BigInteger.valueOf(2L))))))), java.math.BigInteger.valueOf(19L))))) ^ (dafny.Helpers.bv32ShiftRight(((int)(java.lang.Object)((w).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((w).length())).subtract(java.math.BigInteger.valueOf(2L))))))), (byte) 10)));
        dafny.DafnySequence<? extends java.lang.Integer> _in0 = dafny.DafnySequence.<java.lang.Integer>concatenate(w, dafny.DafnySequence.<java.lang.Integer> of((int) (((int) (((int) (((int) (((int) (((int) ((((int)(java.lang.Object)((w).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((w).length())).subtract(java.math.BigInteger.valueOf(16L)))))))) + (_0_s0))))) + (((int)(java.lang.Object)((w).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((w).length())).subtract(java.math.BigInteger.valueOf(7L)))))))))))) + (_1_s1))))));
        w = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Integer> Rounds(dafny.DafnySequence<? extends java.lang.Integer> w, java.math.BigInteger t, dafny.DafnySequence<? extends java.lang.Integer> v)
  {
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(t, java.math.BigInteger.valueOf(64L))) {
        return v;
      } else {
        int _0_a = ((int)(java.lang.Object)((v).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))));
        int _1_b = ((int)(java.lang.Object)((v).select(dafny.Helpers.toInt((java.math.BigInteger.ONE)))));
        int _2_c = ((int)(java.lang.Object)((v).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(2L))))));
        int _3_d = ((int)(java.lang.Object)((v).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(3L))))));
        int _4_e = ((int)(java.lang.Object)((v).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(4L))))));
        int _5_f = ((int)(java.lang.Object)((v).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(5L))))));
        int _6_g = ((int)(java.lang.Object)((v).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(6L))))));
        int _7_h = ((int)(java.lang.Object)((v).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(7L))))));
        int _8_t1 = (int) (((int) (((int) (((int) (((int) (((int) (((int) (((int) ((_7_h) + ((int) (((int) ((__default.Rotr(_4_e, java.math.BigInteger.valueOf(6L))) ^ (__default.Rotr(_4_e, java.math.BigInteger.valueOf(11L))))) ^ (__default.Rotr(_4_e, java.math.BigInteger.valueOf(25L))))))))) + ((int) (((int) ((_4_e) & (_5_f))) ^ ((int) (((int) ((~(_4_e)))) & (_6_g))))))))) + (((int)(java.lang.Object)((__default.K256()).select(dafny.Helpers.toInt((t)))))))))) + (((int)(java.lang.Object)((w).select(dafny.Helpers.toInt((t)))))))));
        int _9_t2 = (int) (((int) (((int) (((int) ((__default.Rotr(_0_a, java.math.BigInteger.valueOf(2L))) ^ (__default.Rotr(_0_a, java.math.BigInteger.valueOf(13L))))) ^ (__default.Rotr(_0_a, java.math.BigInteger.valueOf(22L))))) + ((int) (((int) (((int) ((_0_a) & (_1_b))) ^ ((int) ((_0_a) & (_2_c))))) ^ ((int) ((_1_b) & (_2_c))))))));
        dafny.DafnySequence<? extends java.lang.Integer> _in0 = w;
        java.math.BigInteger _in1 = (t).add(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends java.lang.Integer> _in2 = dafny.DafnySequence.<java.lang.Integer> of((int) (((int) ((_8_t1) + (_9_t2)))), _0_a, _1_b, _2_c, (int) (((int) ((_3_d) + (_8_t1)))), _4_e, _5_f, _6_g);
        w = _in0;
        t = _in1;
        v = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Integer> Blocks(dafny.DafnySequence<? extends java.lang.Byte> p, java.math.BigInteger i, dafny.DafnySequence<? extends java.lang.Integer> h)
  {
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(i, java.math.BigInteger.valueOf((p).length()))) {
        return h;
      } else {
        dafny.DafnySequence<? extends java.lang.Byte> _0_block = (p).subsequence(dafny.Helpers.toInt((i)), dafny.Helpers.toInt(((i).add(java.math.BigInteger.valueOf(64L)))));
        dafny.DafnySequence<? extends java.lang.Integer> _1_w = __default.MessageSchedule(dafny.DafnySequence.Create(dafny.TypeDescriptor.INT, java.math.BigInteger.valueOf(16L), ((java.util.function.Function<dafny.DafnySequence<? extends java.lang.Byte>, java.util.function.Function<java.math.BigInteger, java.lang.Integer>>)(_2_block) -> {return ((java.util.function.Function<java.math.BigInteger, java.lang.Integer>)(_3_j_boxed0) -> {
          java.math.BigInteger _3_j = ((java.math.BigInteger)(java.lang.Object)(_3_j_boxed0));
          return __default.Word(_2_block, (java.math.BigInteger.valueOf(4L)).multiply(_3_j));
        });}).apply(_0_block)));
        dafny.DafnySequence<? extends java.lang.Integer> _4_v = __default.Rounds(_1_w, java.math.BigInteger.ZERO, h);
        dafny.DafnySequence<? extends java.lang.Byte> _in0 = p;
        java.math.BigInteger _in1 = (i).add(java.math.BigInteger.valueOf(64L));
        dafny.DafnySequence<? extends java.lang.Integer> _in2 = dafny.DafnySequence.Create(dafny.TypeDescriptor.INT, java.math.BigInteger.valueOf(8L), ((dafny.Function2<dafny.DafnySequence<? extends java.lang.Integer>, dafny.DafnySequence<? extends java.lang.Integer>, java.util.function.Function<java.math.BigInteger, java.lang.Integer>>)(_5_h, _6_v) -> {return ((java.util.function.Function<java.math.BigInteger, java.lang.Integer>)(_7_j_boxed0) -> {
          java.math.BigInteger _7_j = ((java.math.BigInteger)(java.lang.Object)(_7_j_boxed0));
          return (int) (((int) ((((int)(java.lang.Object)((_5_h).select(dafny.Helpers.toInt((_7_j)))))) + (((int)(java.lang.Object)((_6_v).select(dafny.Helpers.toInt((_7_j)))))))));
        });}).apply(h, _4_v));
        p = _in0;
        i = _in1;
        h = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Sha256(dafny.DafnySequence<? extends java.lang.Byte> msg) {
    java.math.BigInteger _0_pad = dafny.DafnyEuclidean.EuclideanModulus((java.math.BigInteger.valueOf(119L)).subtract(dafny.DafnyEuclidean.EuclideanModulus(java.math.BigInteger.valueOf((msg).length()), java.math.BigInteger.valueOf(64L))), java.math.BigInteger.valueOf(64L));
    java.math.BigInteger _1_bits = (java.math.BigInteger.valueOf((msg).length())).multiply(java.math.BigInteger.valueOf(8L));
    dafny.DafnySequence<? extends java.lang.Byte> _2_padded = dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(msg, dafny.DafnySequence.<java.lang.Byte> of((byte) 128)), dafny.DafnySequence.Create(EHBP.uint8._typeDescriptor(), _0_pad, ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_3_i_boxed0) -> {
      java.math.BigInteger _3_i = ((java.math.BigInteger)(java.lang.Object)(_3_i_boxed0));
      return (byte) 0;
    }))), EHBP.__default.BE32((dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(_1_bits, java.math.BigInteger.valueOf(4294967296L)), java.math.BigInteger.valueOf(4294967296L))).intValue())), EHBP.__default.BE32((dafny.DafnyEuclidean.EuclideanModulus(_1_bits, java.math.BigInteger.valueOf(4294967296L))).intValue()));
    dafny.DafnySequence<? extends java.lang.Integer> _4_h = __default.Blocks(_2_padded, java.math.BigInteger.ZERO, __default.H256());
    return dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(__default.WordBytes(((int)(java.lang.Object)((_4_h).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))), __default.WordBytes(((int)(java.lang.Object)((_4_h).select(dafny.Helpers.toInt((java.math.BigInteger.ONE))))))), __default.WordBytes(((int)(java.lang.Object)((_4_h).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(2L)))))))), __default.WordBytes(((int)(java.lang.Object)((_4_h).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(3L)))))))), __default.WordBytes(((int)(java.lang.Object)((_4_h).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(4L)))))))), __default.WordBytes(((int)(java.lang.Object)((_4_h).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(5L)))))))), __default.WordBytes(((int)(java.lang.Object)((_4_h).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(6L)))))))), __default.WordBytes(((int)(java.lang.Object)((_4_h).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(7L))))))));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> XorPad(dafny.DafnySequence<? extends java.lang.Byte> b, byte p)
  {
    return dafny.DafnySequence.Create(EHBP.uint8._typeDescriptor(), java.math.BigInteger.valueOf((b).length()), ((dafny.Function2<dafny.DafnySequence<? extends java.lang.Byte>, java.lang.Byte, java.util.function.Function<java.math.BigInteger, java.lang.Byte>>)(_0_b, __1_p0) -> {byte _1_p = ((byte)(java.lang.Object)(__1_p0));
    return ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_2_i_boxed0) -> {
      java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
      return ((byte) (byte) ((byte)(((((byte)(java.lang.Object)((_0_b).select(dafny.Helpers.toInt((_2_i))))))) ^ ((_1_p)))));
    });}).apply(b, p));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> HmacRef(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> data)
  {
    dafny.DafnySequence<? extends java.lang.Byte> _0_k = (((java.math.BigInteger.valueOf((key).length())).compareTo(java.math.BigInteger.valueOf(64L)) > 0) ? (__default.Sha256(key)) : (key));
    dafny.DafnySequence<? extends java.lang.Byte> _1_kp = dafny.DafnySequence.<java.lang.Byte>concatenate(_0_k, dafny.DafnySequence.Create(EHBP.uint8._typeDescriptor(), (java.math.BigInteger.valueOf(64L)).subtract(java.math.BigInteger.valueOf((_0_k).length())), ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_2_i_boxed0) -> {
      java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
      return (byte) 0;
    })));
    return __default.Sha256(dafny.DafnySequence.<java.lang.Byte>concatenate(__default.XorPad(_1_kp, (byte) 92), __default.Sha256(dafny.DafnySequence.<java.lang.Byte>concatenate(__default.XorPad(_1_kp, (byte) 54), data))));
  }
  public static java.math.BigInteger Pow2(java.math.BigInteger n) {
    java.math.BigInteger _0___accumulator = java.math.BigInteger.ONE;
    TAIL_CALL_START: while (true) {
      if ((n).signum() == 0) {
        return (java.math.BigInteger.ONE).multiply(_0___accumulator);
      } else {
        _0___accumulator = (_0___accumulator).multiply(java.math.BigInteger.valueOf(2L));
        java.math.BigInteger _in0 = (n).subtract(java.math.BigInteger.ONE);
        n = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static java.math.BigInteger PowMod(java.math.BigInteger b, java.math.BigInteger e)
  {
    if ((e).signum() == 0) {
      return dafny.DafnyEuclidean.EuclideanModulus(java.math.BigInteger.ONE, __default.P25519());
    } else if ((dafny.DafnyEuclidean.EuclideanModulus(e, java.math.BigInteger.valueOf(2L))).signum() == 0) {
      java.math.BigInteger _0_h = __default.PowMod(b, dafny.DafnyEuclidean.EuclideanDivision(e, java.math.BigInteger.valueOf(2L)));
      return dafny.DafnyEuclidean.EuclideanModulus((_0_h).multiply(_0_h), __default.P25519());
    } else {
      return dafny.DafnyEuclidean.EuclideanModulus((b).multiply(__default.PowMod(b, (e).subtract(java.math.BigInteger.ONE))), __default.P25519());
    }
  }
  public static java.math.BigInteger LE(dafny.DafnySequence<? extends java.lang.Byte> b) {
    if ((java.math.BigInteger.valueOf((b).length())).signum() == 0) {
      return java.math.BigInteger.ZERO;
    } else {
      return (dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))).add((java.math.BigInteger.valueOf(256L)).multiply(__default.LE((b).drop(java.math.BigInteger.ONE))));
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> LEBytes(java.math.BigInteger n, java.math.BigInteger length)
  {
    return dafny.DafnySequence.Create(EHBP.uint8._typeDescriptor(), length, ((dafny.Function2<java.math.BigInteger, java.math.BigInteger, java.util.function.Function<java.math.BigInteger, java.lang.Byte>>)(_0_n, _1_length) -> {return ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_2_i_boxed0) -> {
      java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
      return (dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(_0_n, __default.Pow2((java.math.BigInteger.valueOf(8L)).multiply(_2_i))), java.math.BigInteger.valueOf(256L))).byteValue();
    });}).apply(n, length));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Clamp(dafny.DafnySequence<? extends java.lang.Byte> k) {
    return dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte> of(((byte) (byte) ((byte)(((((byte)(java.lang.Object)((k).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))) & ((byte) 248))))), (k).subsequence(dafny.Helpers.toInt((java.math.BigInteger.ONE)), dafny.Helpers.toInt((java.math.BigInteger.valueOf(31L))))), dafny.DafnySequence.<java.lang.Byte> of(((byte) (byte) ((byte)(((byte) (byte) ((byte)(((((byte)(java.lang.Object)((k).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(31L)))))))) & ((byte) 127)))) | ((byte) 64))))));
  }
  public static dafny.Tuple5<java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger> Ladder(java.math.BigInteger k, java.math.BigInteger x1, java.math.BigInteger t, java.math.BigInteger x2, java.math.BigInteger z2, java.math.BigInteger x3, java.math.BigInteger z3, java.math.BigInteger swap)
  {
    TAIL_CALL_START: while (true) {
      java.math.BigInteger _0_kt = dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(k, __default.Pow2(t)), java.math.BigInteger.valueOf(2L));
      java.math.BigInteger _1_sw = ((!java.util.Objects.equals(swap, _0_kt)) ? (java.math.BigInteger.ONE) : (java.math.BigInteger.ZERO));
      dafny.Tuple2<java.math.BigInteger, java.math.BigInteger> _let_tmp_rhs0 = ((java.util.Objects.equals(_1_sw, java.math.BigInteger.ONE)) ? (dafny.Tuple2.<java.math.BigInteger, java.math.BigInteger>create(x3, x2)) : (dafny.Tuple2.<java.math.BigInteger, java.math.BigInteger>create(x2, x3)));
      java.math.BigInteger _2_x2s = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs0).dtor__0()));
      java.math.BigInteger _3_x3s = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs0).dtor__1()));
      dafny.Tuple2<java.math.BigInteger, java.math.BigInteger> _let_tmp_rhs1 = ((java.util.Objects.equals(_1_sw, java.math.BigInteger.ONE)) ? (dafny.Tuple2.<java.math.BigInteger, java.math.BigInteger>create(z3, z2)) : (dafny.Tuple2.<java.math.BigInteger, java.math.BigInteger>create(z2, z3)));
      java.math.BigInteger _4_z2s = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs1).dtor__0()));
      java.math.BigInteger _5_z3s = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs1).dtor__1()));
      java.math.BigInteger _6_a = dafny.DafnyEuclidean.EuclideanModulus((_2_x2s).add(_4_z2s), __default.P25519());
      java.math.BigInteger _7_aa = dafny.DafnyEuclidean.EuclideanModulus((_6_a).multiply(_6_a), __default.P25519());
      java.math.BigInteger _8_b = dafny.DafnyEuclidean.EuclideanModulus((_2_x2s).subtract(_4_z2s), __default.P25519());
      java.math.BigInteger _9_bb = dafny.DafnyEuclidean.EuclideanModulus((_8_b).multiply(_8_b), __default.P25519());
      java.math.BigInteger _10_e = dafny.DafnyEuclidean.EuclideanModulus((_7_aa).subtract(_9_bb), __default.P25519());
      java.math.BigInteger _11_c = dafny.DafnyEuclidean.EuclideanModulus((_3_x3s).add(_5_z3s), __default.P25519());
      java.math.BigInteger _12_d = dafny.DafnyEuclidean.EuclideanModulus((_3_x3s).subtract(_5_z3s), __default.P25519());
      java.math.BigInteger _13_da = dafny.DafnyEuclidean.EuclideanModulus((_12_d).multiply(_6_a), __default.P25519());
      java.math.BigInteger _14_cb = dafny.DafnyEuclidean.EuclideanModulus((_11_c).multiply(_8_b), __default.P25519());
      java.math.BigInteger _15_nx3 = dafny.DafnyEuclidean.EuclideanModulus(((_13_da).add(_14_cb)).multiply((_13_da).add(_14_cb)), __default.P25519());
      java.math.BigInteger _16_nz3 = dafny.DafnyEuclidean.EuclideanModulus((x1).multiply(dafny.DafnyEuclidean.EuclideanModulus(((_13_da).subtract(_14_cb)).multiply((_13_da).subtract(_14_cb)), __default.P25519())), __default.P25519());
      java.math.BigInteger _17_nx2 = dafny.DafnyEuclidean.EuclideanModulus((_7_aa).multiply(_9_bb), __default.P25519());
      java.math.BigInteger _18_nz2 = dafny.DafnyEuclidean.EuclideanModulus((_10_e).multiply(dafny.DafnyEuclidean.EuclideanModulus((_7_aa).add((java.math.BigInteger.valueOf(121665L)).multiply(_10_e)), __default.P25519())), __default.P25519());
      if ((t).signum() == 0) {
        return dafny.Tuple5.<java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger>create(_17_nx2, _18_nz2, _15_nx3, _16_nz3, _0_kt);
      } else {
        java.math.BigInteger _in0 = k;
        java.math.BigInteger _in1 = x1;
        java.math.BigInteger _in2 = (t).subtract(java.math.BigInteger.ONE);
        java.math.BigInteger _in3 = _17_nx2;
        java.math.BigInteger _in4 = _18_nz2;
        java.math.BigInteger _in5 = _15_nx3;
        java.math.BigInteger _in6 = _16_nz3;
        java.math.BigInteger _in7 = _0_kt;
        k = _in0;
        x1 = _in1;
        t = _in2;
        x2 = _in3;
        z2 = _in4;
        x3 = _in5;
        z3 = _in6;
        swap = _in7;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> X25519Ref(dafny.DafnySequence<? extends java.lang.Byte> scalar, dafny.DafnySequence<? extends java.lang.Byte> point)
  {
    java.math.BigInteger _0_k = __default.LE(__default.Clamp(scalar));
    java.math.BigInteger _1_u = dafny.DafnyEuclidean.EuclideanModulus(__default.LE(point), __default.Pow2(java.math.BigInteger.valueOf(255L)));
    dafny.Tuple5<java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger> _let_tmp_rhs0 = __default.Ladder(_0_k, _1_u, java.math.BigInteger.valueOf(255L), java.math.BigInteger.ONE, java.math.BigInteger.ZERO, _1_u, java.math.BigInteger.ONE, java.math.BigInteger.ZERO);
    java.math.BigInteger _2_x2 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple5<java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs0).dtor__0()));
    java.math.BigInteger _3_z2 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple5<java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs0).dtor__1()));
    java.math.BigInteger _4_x3 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple5<java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs0).dtor__2()));
    java.math.BigInteger _5_z3 = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple5<java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs0).dtor__3()));
    java.math.BigInteger _6_swap = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple5<java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs0).dtor__4()));
    dafny.Tuple2<java.math.BigInteger, java.math.BigInteger> _let_tmp_rhs1 = ((java.util.Objects.equals(_6_swap, java.math.BigInteger.ONE)) ? (dafny.Tuple2.<java.math.BigInteger, java.math.BigInteger>create(_4_x3, _5_z3)) : (dafny.Tuple2.<java.math.BigInteger, java.math.BigInteger>create(_2_x2, _3_z2)));
    java.math.BigInteger _7_x = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs1).dtor__0()));
    java.math.BigInteger _8_z = ((java.math.BigInteger)(java.lang.Object)(((dafny.Tuple2<java.math.BigInteger, java.math.BigInteger>)_let_tmp_rhs1).dtor__1()));
    return __default.LEBytes(dafny.DafnyEuclidean.EuclideanModulus((_7_x).multiply(__default.PowMod(_8_z, (__default.P25519()).subtract(java.math.BigInteger.valueOf(2L)))), __default.P25519()), java.math.BigInteger.valueOf(32L));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> BasePoint()
  {
    return dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte> of((byte) 9), __default.Repeat(java.math.BigInteger.valueOf(31L), (byte) 0));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> HpkeVersion()
  {
    return EHBP.__default.Ascii(dafny.DafnySequence.asUnicodeString("HPKE-v1"));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> KemSuiteId()
  {
    return dafny.DafnySequence.<java.lang.Byte>concatenate(EHBP.__default.Ascii(dafny.DafnySequence.asUnicodeString("KEM")), EHBP.__default.BE16(EHBP.__default.KemX25519()));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> HpkeSuiteId()
  {
    return dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(EHBP.__default.Ascii(dafny.DafnySequence.asUnicodeString("HPKE")), EHBP.__default.BE16(EHBP.__default.KemX25519())), EHBP.__default.BE16(EHBP.__default.KdfHkdfSha256())), EHBP.__default.BE16(EHBP.__default.AeadAes256Gcm()));
  }
  public static long MaxSeq()
  {
    return (long) -1L;
  }
  public static java.math.BigInteger MaxJsonStringChars()
  {
    return java.math.BigInteger.valueOf(1024L);
  }
  public static java.math.BigInteger MaxJsonDepth()
  {
    return java.math.BigInteger.valueOf(64L);
  }
  public static SessionStore NewSession()
  {
    return SessionStore.create((long) 0L, EHBP.Option.<EHBP.Token>create_None(EHBP.Token._typeDescriptor()));
  }
  public static Ctx NoCtx()
  {
    return Ctx.create(__default.Repeat(java.math.BigInteger.valueOf(32L), (byte) 0), __default.Repeat(java.math.BigInteger.valueOf(12L), (byte) 0), dafny.DafnySequence.<java.lang.Byte> empty(EHBP.uint8._typeDescriptor()), (long) 0L);
  }
  public static java.math.BigInteger MaxReadBytes()
  {
    return java.math.BigInteger.valueOf(4294967295L);
  }
  public static EHBP.Origin NoOrigin()
  {
    return EHBP.Origin.create(dafny.DafnySequence.asUnicodeString("https"), dafny.DafnySequence.asUnicodeString(""), java.math.BigInteger.valueOf(443L));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> GcmKey()
  {
    return __default.Iota(java.math.BigInteger.valueOf(32L));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> GcmNonce()
  {
    return __default.Iota(java.math.BigInteger.valueOf(12L));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> GcmCt()
  {
    return __default.Hex(dafny.DafnySequence.asUnicodeString("226ab46b72d4be2b87fabbe9dbe0bfc2adbce017"));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> AliceSk()
  {
    return __default.Hex(dafny.DafnySequence.asUnicodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> AlicePk()
  {
    return __default.Hex(dafny.DafnySequence.asUnicodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> BobPk()
  {
    return __default.Hex(dafny.DafnySequence.asUnicodeString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> AliceBobShared()
  {
    return __default.Hex(dafny.DafnySequence.asUnicodeString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> HmacKey()
  {
    return __default.Repeat(java.math.BigInteger.valueOf(20L), (byte) 11);
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> HmacTag()
  {
    return __default.Hex(dafny.DafnySequence.asUnicodeString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
  }
  public static dafny.DafnySequence<? extends Action> SelfCheckActions()
  {
    return dafny.DafnySequence.<Action> of(Action._typeDescriptor(), Action.create_HmacSha256(__default.HmacKey(), EHBP.__default.Ascii(dafny.DafnySequence.asUnicodeString("Hi There"))), Action.create_X25519(__default.AliceSk(), __default.BasePoint()), Action.create_X25519(__default.AliceSk(), __default.BobPk()), Action.create_AeadSeal(__default.GcmKey(), __default.GcmNonce(), EHBP.__default.Ascii(dafny.DafnySequence.asUnicodeString("ehbp"))), Action.create_AeadOpen(__default.GcmKey(), __default.GcmNonce(), __default.GcmCt()), Action.create_AeadOpen(__default.GcmKey(), __default.GcmNonce(), dafny.DafnySequence.<java.lang.Byte>concatenate((__default.GcmCt()).take((java.math.BigInteger.valueOf((__default.GcmCt()).length())).subtract(java.math.BigInteger.ONE)), dafny.DafnySequence.<java.lang.Byte> of(((byte) (byte) ((byte)(((((byte)(java.lang.Object)((__default.GcmCt()).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf((__default.GcmCt()).length())).subtract(java.math.BigInteger.ONE)))))))) ^ ((byte) 1))))))), Action.create_AeadOpen(__default.GcmKey(), __default.GcmNonce(), (__default.GcmCt()).take(java.math.BigInteger.valueOf(8L))), Action.create_RandomBytes(java.math.BigInteger.valueOf(32L)), Action.create_RandomBytes(java.math.BigInteger.valueOf(32L)));
  }
  public static dafny.DafnySequence<? extends java.lang.Integer> K256()
  {
    return dafny.DafnySequence.<java.lang.Integer> of(1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987, 1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872, -1866530822, -1538233109, -1090935817, -965641998);
  }
  public static dafny.DafnySequence<? extends java.lang.Integer> H256()
  {
    return dafny.DafnySequence.<java.lang.Integer> of(1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372, 528734635, 1541459225);
  }
  public static java.math.BigInteger P25519()
  {
    return new java.math.BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949");
  }
  @Override
  public java.lang.String toString() {
    return "EHBPEvents._default";
  }
}
