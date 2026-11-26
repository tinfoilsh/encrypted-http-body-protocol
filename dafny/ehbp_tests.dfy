// The tests of the core (dafny test ehbp_tests.dfy). Nothing here is translated:
// the bundles are built from ehbp_events.dfy and ehbp_server.dfy, so the
// scripted handlers and the test vectors below stay out of every SDK.
include "ehbp_server.dfy"

module EHBPTests {
  import opened EHBP
  import opened EHBPEvents

  method {:test} ConfigRoundTrip() {
    var pk: bytes := seq(32, i => 7);
    var cfg := MarshalConfig(pk);
    expect cfg.Ok? && ParseConfig(cfg.value) == Ok(pk);
    expect ParseConfig(cfg.value[..10]).Err? && ParseConfig(cfg.value[..10]).code == InvalidKeyConfig;
    expect ParseConfig(cfg.value + cfg.value) == Ok(pk);
    expect ParseConfig([0, 0, 0x10] + cfg.value[3..]).code == UnsupportedSuite;
    expect ComputeNonce(seq(12, i => 0), 0x0102) == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2];
  }

  method {:test} HexAndMediaType() {
    expect DecodeHex("0aFF") == Some([10, 255]);
    expect DecodeHex("0x0a") == None && DecodeHex("abc") == None && DecodeHex("0 a") == None;
    expect EncodeHex([10, 255]) == "0aff";
    expect MediaType(" Application/OHTTP-Keys ; charset=x") == "application/ohttp-keys";
    expect OriginUrl(Origin("https", "example.com", 443)) == "https://example.com";
    expect OriginUrl(Origin("http", "127.0.0.1", 8080)) == "http://127.0.0.1:8080";
  }

  predicate RefusedWith(d: Disposition, code: Code) { d.Refuse? && d.code == code }

  method {:test} ClassifierPinsTheSpec() {
    var nonce := EncodeHex(seq(32, i => 1));
    var enc := true;
    expect Classify(false, Head(422, [("Content-Type", ProblemJsonMediaType)], false)).PassThrough?;
    expect RefusedWith(Classify(enc, Head(200, [], false)), MissingResponseNonce);
    expect Classify(enc, Head(502, [], false)).PassThrough?;
    expect Classify(enc, Head(422, [("content-type", "application/problem+json; charset=utf-8")], false)).NeedProblemBody?;
    expect RefusedWith(Classify(enc, Head(303, [(ResponseNonceHeader, nonce)], false)), UnexpectedRedirect);
    expect RefusedWith(Classify(enc, Head(200, [(ResponseNonceHeader, nonce)], true)), UnexpectedRedirect);
    expect RefusedWith(Classify(enc, Head(204, [(ResponseNonceHeader, "abcd")], false)), InvalidResponseNonce);
    expect RefusedWith(Classify(enc, Head(204, [(ResponseNonceHeader, nonce)], false)), FramingTruncated);
    expect RefusedWith(Classify(enc, Head(502, [(ResponseNonceHeader, "")], false)), InvalidResponseNonce);
    expect RefusedWith(Classify(enc, Head(200, [(ResponseNonceHeader, nonce), (ResponseNonceHeader, nonce)], false)), DuplicateResponseNonce);
    expect Classify(enc, Head(500, [(ResponseNonceHeader, nonce)], false)) == Decrypt(seq(32, i => 1), false);
    expect Classify(enc, Head(200, [(ResponseNonceHeader, nonce)], false)) == Decrypt(seq(32, i => 1), true);
    expect ClassifyProblem(false, true, Some(KeyConfigProblemType), None) == Refuse(KeyConfigMismatch, DefaultKeyConfigTitle);
    expect ClassifyProblem(true, true, Some(KeyConfigProblemType), None).PassThrough?;
    expect ClassifyDiscovery(Head(200, [("Content-Type", "APPLICATION/ohttp-keys;v=1")], false)).Ok?;
    expect ClassifyDiscovery(Head(203, [("Content-Type", KeysMediaType)], false)).Err?;
    var origin := Origin("https", "server.test", 443);
    expect ValidateRequest(origin, MakeOrigin("https", "SERVER.test", None, false), [("X-Custom", "1")]).Ok?;
    expect ValidateRequest(origin, MakeOrigin("https", "server.test", Some(8443), false), []).Err?;
    expect ValidateRequest(origin, MakeOrigin("https", "server.test", None, true), []).Err?;
    expect ValidateRequest(origin, Ok(origin), [("host", "evil")]).Err?;
    expect DropFraming([("content-length", "1"), ("X", "y"), ("Transfer-Encoding", "chunked")]) == [("X", "y")];
  }

  // Ascii without the IsAscii obligation, for test literals.
  function A(s: string): bytes { seq(|s|, i requires 0 <= i < |s| => if s[i] as int < 0x80 then s[i] as int as uint8 else 0x3f) }

  method {:test} DeriveAndDecryptEntries() {
    var token := Token(Repeat(32, 1), Repeat(32, 2));
    var (s, acts) := DeriveStart(token, Repeat(32, 3));
    expect |acts| == 1 && acts[0].HmacSha256?;
    expect KeysOf(s).None?;
    var (s2, acts2) := DecryptStart(token, 303, []);
    expect |acts2| >= 1 && acts2[|acts2| - 1].Fail? && acts2[|acts2| - 1].code == UnexpectedRedirect;
  }

  method {:test} JsonStringsAreBoundedAndLinear() {
    // A 4,000-character member is kept to MaxJsonStringChars; the document still parses.
    var long := seq(4000, i => 'a');
    var doc := "{\"exportedSecret\":\"" + long + "\",\"requestEnc\":\"bb\"}";
    var t := ParseToken(doc);
    expect t.0.Some? && |t.0.value| == MaxJsonStringChars && t.1 == Some("bb");
    // Escapes inside a long run decode in place.
    var u := ParseToken("{\"exportedSecret\":\"x\\ny\",\"requestEnc\":\"\\u00e9\"}");
    expect u.0 == Some("x\ny") && u.1 == Some([0xe9 as char]);
  }

  method {:test} ReferencePrimitivesMatchKnownAnswers() {
    expect EncodeHex(Sha256(A("abc"))) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    expect HmacRef(HmacKey, A("Hi There")) == HmacTag;
    expect |AliceSk| == 32 && |BobPk| == 32;
    expect X25519Ref(AliceSk, BasePoint) == AlicePk;
    expect X25519Ref(AliceSk, BobPk) == AliceBobShared;
    // RFC 5869 test case 1 through the HKDF job machine.
    var ikm: bytes := Repeat(22, 0x0b);
    var salt: bytes := Iota(13);
    var info: bytes := Hex("f0f1f2f3f4f5f6f7f8f9");
    var prk := RunJob(Extract(salt, ikm));
    expect EncodeHex(prk) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    var okm := RunJob(Expand(prk, info, 42));
    expect EncodeHex(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    // The judge accepts the reference answers and names a wrong one.
    var results := [HmacResult(HmacTag), X25519Result(AlicePk), X25519Result(AliceBobShared), AeadSealResult(GcmCt),
      AeadOpenResult(true, A("ehbp")), AeadOpenResult(false, []), AeadOpenResult(false, []), RandomResult(Repeat(32, 1)), RandomResult(Repeat(32, 2))];
    expect SelfCheckJudge(results) == [];
    expect SelfCheckJudge(results[8 := results[7]]) == ["RandomBytes: repeated output"];
  }

  // Drives a job with the reference HMAC until it outputs.
  method RunJob(job: Job) returns (out: bytes)
  {
    var j := job;
    out := [];
    for fuel := 0 to 256 {
      var a := JobAction(j);
      expect a.HmacSha256?;
      match JobStep(j, HmacResult(HmacRef(a.key, a.data))) {
        case Output(data) => return data;
        case Pending(next, _) => j := next;
        case JobFailed(_, _) => expect false;
      }
    }
  }

  // Performs crypto actions with the reference primitives; the AEAD is faked
  // as plaintext plus a 16-byte tag, since AES-GCM is native only.
  method RunHpke(start: HpkeOut, scalar: bytes) returns (ctx: Ctx, enc: bytes, shared: bytes)
  {
    var o := start;
    ctx, enc, shared := NoCtx, [], [];
    for fuel := 0 to 64 {
      match o {
        case HReady(c, e) => return c, e, shared;
        case HFailed(_, _) => expect false;
        case HContinue(h, a) =>
          if h.HSchedule? && h.stage == 2 { shared := h.shared; }
          var e: Event;
          if a.RandomBytes? { e := RandomResult(scalar); }
          else if a.X25519? { expect |a.scalar| == 32 && |a.point| == 32; e := X25519Result(X25519Ref(a.scalar, a.point)); }
          else { expect a.HmacSha256?; e := HmacResult(HmacRef(a.key, a.data)); }
          o := HpkeStep(h, e);
      }
    }
  }

  // RFC 9180 test vector: base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
  method {:test} HpkeMatchesRfc9180Vector() {
    var info := Hex("4f6465206f6e2061204772656369616e2055726e");
    var skEm := Hex("179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11");
    var pkRm := Hex("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c");
    var skRm := Hex("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d");
    var ctx, enc, shared := RunHpke(SenderStart(pkRm, info), skEm);
    expect EncodeHex(enc) == "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256";
    expect EncodeHex(shared) == "3101c54c3a4f87439eaac080699ed9bbcc726ffe44e860c0424ccb7e3e2ead7b";
    expect EncodeHex(ctx.key) == "f50b0609186798729ed0564b36ef2ef8044f1f9d05636874d1f46c819c7a669f";
    expect EncodeHex(ctx.baseNonce) == "151d9929e2449747889bc923";
    expect EncodeHex(ctx.exporterSecret) == "86017151bbff6a1940e8abae2ac9e0e7032e33df1eaaecc02ca6259b130d62df";
    // The first two seals use base_nonce XOR 0 and XOR 1 (the vector's nonces).
    var pt := Hex("4265617574792069732074727574682c20747275746820626561757479");
    var s0 := SealAction(ctx, pt);
    expect s0.AeadSeal? && s0.key == ctx.key && EncodeHex(s0.nonce) == "151d9929e2449747889bc923" && s0.plaintext == pt;
    expect ctx.seqNo == 0;
    var s1 := SealAction(Bump(ctx), pt);
    expect s1.AeadSeal? && EncodeHex(s1.nonce) == "151d9929e2449747889bc922";
    var e0 := RunJob(ExportJob(ctx, [], 32));
    expect EncodeHex(e0) == "ded6cffafaea6b812cbf3e241e88332adbc077aca81512914213810ee291770a";
    var e1 := RunJob(ExportJob(ctx, Hex("54657374436f6e74657874"), 32));
    expect EncodeHex(e1) == "7c5ded445732c14fe09727d29b4251c0fd38455fe8440571e687f0886aac94d2";
    // The recipient derives the same context from its private key and enc.
    var rctx, renc, rshared := RunHpke(RecipientStart(skRm, pkRm, enc, info), []);
    expect rctx == ctx && renc == enc && rshared == shared;
    var o0 := OpenAction(rctx, Hex("e5d8"));
    expect o0.AeadOpen? && o0.key == ctx.key && EncodeHex(o0.nonce) == "151d9929e2449747889bc923";
    // A wrong-length primitive result fails the setup with HpkeSetupFailed.
    expect HpkeStep(HRandom(pkRm, info), RandomResult([1, 2, 3])) == HFailed(HpkeSetupFailed, "random bytes have the wrong length");
    expect HpkeStep(HRandom(pkRm, info), HmacResult([])) == HFailed(Transport, "unexpected event");
  }

  method {:test} JsonParsesTheProtocolDocuments() {
    var (isObject, typeValue, title) := ParseProblem(A("{\"type\":\"x\",\"title\":5,\"TYPE\":\"y\"}"));
    expect isObject && typeValue == Some("x") && title == None;
    var (dup, typeDup, _) := ParseProblem(A(" {\"type\":\"first\", \"type\" : \"last\"} "));
    expect dup && typeDup == Some("last");
    var (arr, _, _) := ParseProblem(A("[1]"));
    expect !arr;
    var (bad, _, _) := ParseProblem(A("{bad"));
    expect !bad;
    var (nul, _, _) := ParseProblem(A("null"));
    expect !nul;
    var (trailing, _, _) := ParseProblem(A("{} x"));
    expect !trailing;
    var (nested, _, titleNested) := ParseProblem(A("{\"a\":[1,-2.5e+3,true,false,null,{\"b\":[]}],\"title\":\"t\"}"));
    expect nested && titleNested == Some("t");
    var (badNumber, _, _) := ParseProblem(A("{\"a\":01}"));
    expect !badNumber;
    var (trailingComma, _, _) := ParseProblem(A("{\"a\":1,}"));
    expect !trailingComma;
    var (esc, _, titleEsc) := ParseProblem(A("{\"title\":\"a\\\"b\\\\c\\n\\u0041\\ud83d\\ude00\\udc00\"}"));
    expect esc && titleEsc == Some("a\"b\\c\nA" + [0x1F600 as char, 0xFFFD as char]);
    var (utf8, _, titleUtf8) := ParseProblem(A("{\"title\":\"") + [0xC3, 0xA9, 0xFF] + A("\"}"));
    expect utf8 && titleUtf8 == Some([0xE9 as char, 0xFFFD as char]);
    var (control, _, _) := ParseProblem(A("{\"title\":\"a") + [0x01] + A("\"}"));
    expect !control;
    var deep := seq(65, i => '[') + seq(65, i => ']');
    expect ParseJson(deep) == None;
    expect ParseJson(seq(64, i => '[') + seq(64, i => ']')).Some?;
    var (over, _, _) := ParseProblem(A("{\"a\":") + A(deep) + A("}"));
    expect !over;
    expect FormatToken("aa", "b\"c") == "{\"exportedSecret\":\"aa\",\"requestEnc\":\"b\\\"c\"}";
    expect ParseToken(FormatToken("aa", "bb")) == (Some("aa"), Some("bb"));
    expect ParseToken("{\"exportedSecret\":1}") == (None, None);
    expect ParseToken("{\"exportedSecret\":\"a\",\"requestEnc\":[\"b\"]}") == (Some("a"), None);
  }

  // A scripted handler for the driver tests: crypto results come from fixed
  // bytes (the driver only checks lengths), the AEAD appends or strips a
  // 16-byte tag, BeginSession yields generation 1. I/O actions are logged for
  // the test to answer.
  method Pump(start: State, first: Event) returns (s: State, log: seq<Action>)
  {
    s := start;
    log := [];
    var e := first;
    for fuel := 0 to 64 {
      var (next, acts) := Step(s, e);
      s := next;
      log := log + acts;
      var pending: Option<Event> := None;
      for i := 0 to |acts| {
        var a := acts[i];
        if a.BeginSession? { pending := Some(SessionBegun(1)); }
        else if a.RandomBytes? { pending := Some(RandomResult(Repeat(a.length, 7))); }
        else if a.X25519? { pending := Some(X25519Result(Repeat(32, 8))); }
        else if a.HmacSha256? { pending := Some(HmacResult(Repeat(32, 9))); }
        else if a.AeadSeal? { pending := Some(AeadSealResult(a.plaintext + Repeat(16, 0))); }
        else if a.AeadOpen? { pending := Some(AeadOpenResult(true, a.ciphertext[.. |a.ciphertext| - AeadTagLength])); }
      }
      if pending.None? { return; }
      e := pending.value;
    }
  }

  function Last(log: seq<Action>): Action requires |log| > 0 { log[|log| - 1] }

  const TestOrigin: Origin := Origin("https", "server.test", 443)
  const TestKey: bytes := Repeat(32, 3)
  const NonceHeader: (string, string) := (ResponseNonceHeader, EncodeHex(Repeat(32, 1)))

  function TestStart(headers: Headers, hasBody: bool): Event
  {
    Start("POST", "https://server.test/v1", "https", "server.test", 0, false, false, headers, hasBody)
  }

  method {:test} DecoderSplitsAtAnyBoundary() {
    // A frame, a zero-length frame, a frame: every split point yields the same frames.
    var wire: bytes := [0, 0, 0, 2, 0xAA, 0xBB, 0, 0, 0, 0, 0, 0, 0, 1, 0xCC];
    var want := [Framed(0, [0xAA, 0xBB]), Framed(1, [0xCC])];
    for k := 0 to |wire| + 1 {
      var (f1, d1, e1) := Push(Dec([], 0, false, true), wire[.. k]);
      expect e1.None?;
      var (f2, d2, e2) := Push(d1, wire[k ..]);
      expect e2.None? && f1 + f2 == want && Finish(d2).None?;
    }
    var (_, d3, _) := Push(Dec([], 0, false, true), wire[.. 5]);
    expect Finish(d3) == Some(FramingTruncated);
    var (_, _, e4) := Push(Dec([0x04, 0], 0, false, true), [0, 1]);
    expect e4 == Some(ChunkTooLarge);
  }

  method {:test} DriverHappyPath() {
    var s, log := Pump(Initial(TestOrigin, TestKey), TestStart([("Content-Length", "2"), ("X-A", "1")], true));
    expect log == [BeginSession, Read(RequestBody)];
    s, log := Pump(s, Chunk(RequestBody, A("hi"), true));
    expect |log| >= 5;
    // RandomBytes, X25519 x2, the key schedule, the export, then publish, send, seal, write.
    expect log[0] == RandomBytes(32) && log[1] == X25519(Repeat(32, 7), BasePoint) && log[2] == X25519(Repeat(32, 7), TestKey);
    var secret := Repeat(32, 9);
    var enc := Repeat(32, 8);
    expect log[|log| - 5] == PublishToken(1, secret, enc);
    expect log[|log| - 4] == Send("POST", "https://server.test/v1", [("X-A", "1"), (EncapsulatedKeyHeader, EncodeHex(enc))], true);
    expect log[|log| - 3].AeadSeal? && log[|log| - 3].plaintext == A("hi") && log[|log| - 3].nonce == ComputeNonce(Repeat(12, 9), 0);
    expect log[|log| - 2 ..] == FrameWrites(A("hi") + Repeat(16, 0), BodyEnd.Done);
    expect s.ctx.seqNo == 1 && s.published;
    // A 200 with a nonce: three HKDF steps then Done with framing headers dropped.
    s, log := Pump(s, ResponseHead(200, [NonceHeader, ("Content-Length", "99")], false));
    expect |log| == 4 && log[0] == HmacSha256(enc + Repeat(32, 1), secret);
    expect Last(log) == Action.Done(200, [NonceHeader]);
    // The caller reads: two frames in one chunk are released together, the token after.
    s, log := Pump(s, CallerRead);
    expect log == [Read(ResponseBody)];
    var frame1 := Frame(A("ab") + Repeat(16, 0));
    var frame2 := Frame(A("cd") + Repeat(16, 0));
    s, log := Pump(s, Chunk(ResponseBody, frame1 + frame2, true));
    expect |log| == 4 && log[0].AeadOpen? && log[0].nonce == ComputeNonce(Repeat(12, 9), 0);
    expect log[1].AeadOpen? && log[1].nonce == ComputeNonce(Repeat(12, 9), 1);
    expect log[2..] == [EmitPlaintext(A("ab")), EmitPlaintext(A("cd"))];
    expect s.published;
    s, log := Pump(s, CallerRead);
    expect log == [ClearToken(1), Finished] && !s.published;
    s, log := Pump(s, CallerClose);
    expect log == [Close(ResponseBody)];
  }

  method {:test} DriverBodylessAndGuards() {
    // A reserved header is refused before any session work.
    var s, log := Pump(Initial(TestOrigin, TestKey), TestStart([("Host", "evil")], true));
    expect log == [Fail(InvalidInput, "reserved request header cannot be set by callers: Host")];
    // A cross-origin URL likewise.
    s, log := Pump(Initial(TestOrigin, TestKey), Start("GET", "https://other.test/", "https", "other.test", 0, false, false, [], false));
    expect |log| == 1 && log[0].Fail? && log[0].code == InvalidInput;
    // No body: a plaintext exchange and no token to clear.
    s, log := Pump(Initial(TestOrigin, TestKey), TestStart([], false));
    expect log == [BeginSession, Send("POST", "https://server.test/v1", [], false)];
    s, log := Pump(s, ResponseHead(201, [("X", "y")], false));
    expect log == [Passthrough(201, [("X", "y")], [])];
    // An empty body is a plaintext exchange too, after the peek.
    s, log := Pump(Initial(TestOrigin, TestKey), TestStart([], true));
    s, log := Pump(s, Chunk(RequestBody, [], false));
    expect log == [Read(RequestBody)];
    s, log := Pump(s, Chunk(RequestBody, [], true));
    expect log == [Send("POST", "https://server.test/v1", [], false)];
    // A body that never progresses is reported after MaxEmptyReads reads.
    s, log := Pump(Initial(TestOrigin, TestKey), TestStart([], true));
    var i := 0;
    while i < MaxEmptyReads - 1 {
      s, log := Pump(s, Chunk(RequestBody, [], false));
      i := i + 1;
      expect log == [Read(RequestBody)] && s.phase == Peeking(i);
    }
    s, log := Pump(s, Chunk(RequestBody, [], false));
    expect log == [Fail(Transport, "request body made no progress")];
  }

  method {:test} SessionRulesPinTheSpec() {
    var t := Token(Repeat(32, 1), Repeat(32, 2));
    var st := SessionApply(NewSession, Begin);
    expect st == SessionStore(1, None);
    expect SessionApply(st, Publish(0, t)) == st;
    st := SessionApply(st, Publish(1, t));
    expect st.token == Some(t);
    expect SessionApply(st, Clear(2)) == st;
    expect SessionApply(st, Clear(1)) == SessionStore(1, None);
    expect SessionApply(st, Begin) == SessionStore(2, None);
  }

  method EncryptedExchange() returns (s: State)
  {
    var log;
    s, log := Pump(Initial(TestOrigin, TestKey), TestStart([], true));
    s, log := Pump(s, Chunk(RequestBody, A("hi"), true));
    expect |log| > 0 && Last(log).Write? && Last(log).end.Done?;
  }

  method {:test} DriverFailurePaths() {
    // Redirect: refused, closed, token cleared.
    var s := EncryptedExchange();
    var log;
    s, log := Pump(s, ResponseHead(302, [("Location", "/x")], false));
    expect log == [Close(ResponseBody), ClearToken(1), Fail(UnexpectedRedirect, "redirect in response to an encrypted request")];
    // fetch's `redirect: 'manual'` in a browser reports an opaque redirect as status 0.
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(0, [], true));
    expect log == [Close(ResponseBody), ClearToken(1), Fail(UnexpectedRedirect, "redirect in response to an encrypted request")];
    // 502 without a nonce: pass-through consumes the token.
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(502, [], false));
    expect log == [ClearToken(1), Passthrough(502, [], [])];
    // 422 problem document: read, parsed here, refused as a key-config mismatch.
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(422, [("Content-Type", "application/problem+json; charset=utf-8")], false));
    expect log == [Read(ResponseBody)];
    s, log := Pump(s, Chunk(ResponseBody, A("{\"type\":\"urn:ietf:params:ehbp:error:key-config\",\"title\":\"rotated\"}"), true));
    expect log == [Close(ResponseBody), ClearToken(1), Fail(KeyConfigMismatch, "rotated")];
    // A different problem passes through with the bytes already read as prefix.
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(422, [("Content-Type", "application/problem+json")], false));
    s, log := Pump(s, Chunk(ResponseBody, A("{\"type\":\"other\"}"), false));
    expect log == [Read(ResponseBody)];
    s, log := Pump(s, Chunk(ResponseBody, [], true));
    expect log == [ClearToken(1), Passthrough(422, [("Content-Type", "application/problem+json")], A("{\"type\":\"other\"}"))];
    // A transport failure on the head.
    s := EncryptedExchange();
    s, log := Pump(s, StreamFailed(ResponseBody));
    expect log == [ClearToken(1), Fail(Transport, "failed to make request")];
    // Inside the body: a tampered frame releases nothing and clears the token.
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(200, [NonceHeader], false));
    s, log := Pump(s, CallerRead);
    var r1 := Step(s, Chunk(ResponseBody, Frame(Repeat(20, 5)), false));
    expect |r1.1| == 1 && r1.1[0].AeadOpen?;
    var r2 := Step(r1.0, AeadOpenResult(false, []));
    expect r2.1 == [ClearToken(1), Fail(AeadDecryptFailed, "frame failed to authenticate")];
    // A partial length prefix at EOF is truncated framing; so is a transport failure.
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(200, [NonceHeader], false));
    s, log := Pump(s, CallerRead);
    s, log := Pump(s, Chunk(ResponseBody, [0, 0, 0], true));
    expect log == [ClearToken(1), Fail(FramingTruncated, "")];
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(200, [NonceHeader], false));
    s, log := Pump(s, CallerRead);
    s, log := Pump(s, StreamFailed(ResponseBody));
    expect log == [ClearToken(1), Fail(FramingTruncated, "response body failed")];
    // A 200 with no frame at all is truncated; a 500 with none is fine.
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(200, [NonceHeader], false));
    s, log := Pump(s, CallerRead);
    s, log := Pump(s, Chunk(ResponseBody, [], true));
    expect log == [ClearToken(1), Fail(FramingTruncated, "")];
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(500, [NonceHeader], false));
    s, log := Pump(s, CallerRead);
    s, log := Pump(s, Chunk(ResponseBody, [], true));
    expect log == [ClearToken(1), Finished];
    // A frame shorter than the tag is an authentication failure before any AEAD call.
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(200, [NonceHeader], false));
    s, log := Pump(s, CallerRead);
    s, log := Pump(s, Chunk(ResponseBody, Frame([1, 2, 3]), true));
    expect log == [ClearToken(1), Fail(AeadDecryptFailed, "frame shorter than the AEAD tag")];
    // Closing early clears the token; the upload lane keeps going independently.
    s := EncryptedExchange();
    s, log := Pump(s, ResponseHead(200, [NonceHeader], false));
    s, log := Pump(s, CallerClose);
    expect log == [ClearToken(1), Close(ResponseBody)] && !s.published;
    s, log := Pump(s, CallerClose);
    expect log == [Close(ResponseBody)];
    // An unexpected event is a Transport failure, never an unhandled case.
    s, log := Pump(Initial(TestOrigin, TestKey), StreamFailed(ResponseBody));
    expect log == [Fail(Transport, "unexpected event")];
    s := EncryptedExchange();
    s, log := Pump(s, HmacResult([]));
    expect log == [ClearToken(1), Fail(Transport, "unexpected event")];
  }

  method {:test} DriverUploadLaneAndDiscovery() {
    var s, log := Pump(Initial(TestOrigin, TestKey), TestStart([], true));
    // A first chunk larger than a frame is sealed in RequestFrameBytes pieces, then the body is read on.
    var big := Repeat(RequestFrameBytes as nat + 1, 4);
    s, log := Pump(s, Chunk(RequestBody, big, false));
    expect |log| >= 7 && log[|log| - 7].AeadSeal? && |log[|log| - 7].plaintext| == RequestFrameBytes as nat;
    expect log[|log| - 6 .. |log| - 4] == FrameWrites(big[.. RequestFrameBytes as nat] + Repeat(16, 0), More);
    expect log[|log| - 4].AeadSeal? && log[|log| - 4].plaintext == [4];
    expect log[|log| - 3 .. |log| - 1] == FrameWrites([4] + Repeat(16, 0), More);
    expect Last(log) == Read(RequestBody) && s.ctx.seqNo == 2;
    // The response head may arrive while the upload continues.
    s, log := Pump(s, ResponseHead(502, [], false));
    expect log == [ClearToken(1), Passthrough(502, [], [])];
    s, log := Pump(s, Chunk(RequestBody, [], true));
    expect log == [Write([], BodyEnd.Done)];
    // A body failure after commitment aborts the upload only.
    s, log := Pump(Initial(TestOrigin, TestKey), TestStart([], true));
    s, log := Pump(s, Chunk(RequestBody, A("x"), false));
    s, log := Pump(s, StreamFailed(RequestBody));
    expect log == [Write([], Aborted(Transport))] && s.published;
    // Discovery: GET the keys path, accept 200 + media type, parse the first config.
    var cfg := MarshalConfig(TestKey).value;
    s, log := Pump(Initial(TestOrigin, []), DiscoverStart);
    expect log == [Send("GET", "https://server.test/.well-known/hpke-keys", [], false)];
    s, log := Pump(s, ResponseHead(200, [("Content-Type", "application/ohttp-keys")], false));
    expect log == [Read(ResponseBody)];
    s, log := Pump(s, Chunk(ResponseBody, cfg[.. 10], false));
    expect log == [Read(ResponseBody)];
    s, log := Pump(s, Chunk(ResponseBody, cfg[10 ..] + cfg, true));
    expect log == [Close(ResponseBody), Discovered(TestKey)];
    s, log := Pump(Initial(TestOrigin, []), DiscoverStart);
    s, log := Pump(s, ResponseHead(203, [("Content-Type", "application/ohttp-keys")], false));
    expect log == [Close(ResponseBody), Fail(InvalidKeyConfig, "discovery returned a non-200 status")];
    s, log := Pump(Initial(TestOrigin, []), DiscoverStart);
    s, log := Pump(s, ResponseHead(200, [("Content-Type", "text/plain")], false));
    expect log == [Close(ResponseBody), Fail(InvalidKeyConfig, "discovery returned the wrong media type")];
  }
}

// A scripted handler as EHBPTests.Pump, for the server driver.
module EHBPServerTests {
  import opened EHBP
  import EV = EHBPEvents
  import opened EHBPServer
  import T = EHBPTests

  method SPump(start: SState, first: SEvent) returns (s: SState, log: seq<SAction>)
    requires Inv(start)
    ensures Inv(s)
  {
    s := start;
    log := [];
    var e := first;
    for fuel := 0 to 64
      invariant Inv(s)
    {
      var (next, acts) := ServerStep(s, e);
      s := next;
      log := log + acts;
      var pending: Option<SEvent> := None;
      for i := 0 to |acts| {
        var a := acts[i];
        if a.RandomBytes? { pending := Some(RandomResult(EV.Repeat(a.length, 7))); }
        else if a.X25519? { pending := Some(X25519Result(EV.Repeat(32, 8))); }
        else if a.HmacSha256? { pending := Some(HmacResult(EV.Repeat(32, 9))); }
        else if a.AeadSeal? { pending := Some(AeadSealResult(a.plaintext + EV.Repeat(16, 0))); }
        else if a.AeadOpen? && |a.ciphertext| >= AeadTagLength { pending := Some(AeadOpenResult(true, a.ciphertext[.. |a.ciphertext| - AeadTagLength])); }
      }
      if pending.None? { return; }
      e := pending.value;
    }
  }

  function Last(log: seq<SAction>): SAction requires |log| > 0 { log[|log| - 1] }

  const Sk: bytes := EV.Repeat(32, 3)
  const Pk: bytes := EV.Repeat(32, 4)
  const Enc: bytes := EV.Repeat(32, 2)
  const KeyHeader: Headers := [(EncapsulatedKeyHeader, EncodeHex(Enc))]
  const TestNonce: bytes := EV.Repeat(32, 7)
  const TestKeys: Headers := [(ResponseNonceHeader, EncodeHex(TestNonce)), ("Transfer-Encoding", "chunked")]
  const Tag: bytes := EV.Repeat(16, 0)

  // Decapsulated and waiting for the first chunk.
  method Decapped() returns (s: SState)
    ensures Inv(s)
  {
    var log;
    s, log := SPump(ServerInitial(Sk, Pk), RequestStart(KeyHeader, true));
    expect |log| > 0 && log[0] == X25519(Sk, Enc) && Last(log) == Read(EV.RequestBody) && s.phase == Peek(Reading(0));
  }

  // Through to Dispatch, with "hi" released and the body not yet at eof.
  method Dispatched() returns (s: SState)
    ensures Inv(s)
  {
    s := Decapped();
    var log;
    s, log := SPump(s, Chunk(Frame(T.A("hi") + Tag), false));
    expect |log| > 3 && log[0] == AeadOpen(EV.Repeat(32, 9), ComputeNonce(EV.Repeat(12, 9), 0), T.A("hi") + Tag);
    expect log[1] == EmitPlaintext(T.A("hi")) && log[2].HmacSha256? && Last(log) == Dispatch;
    expect s.phase.Running? && s.phase.req == Waiting && !s.phase.resp.started && s.payload;
  }

  method {:test} ServerHappyPath() {
    var s := Dispatched();
    var log;
    s, log := SPump(s, HandlerRead);
    expect log == [Read(EV.RequestBody)];
    // Two frames in one chunk are released one by one, then the body ends.
    s, log := SPump(s, Chunk(Frame(T.A("ab") + Tag) + Frame(T.A("cd") + Tag), true));
    expect |log| == 5 && log[1] == EmitPlaintext(T.A("ab")) && log[3] == EmitPlaintext(T.A("cd")) && log[4] == Close(EV.RequestBody);
    expect log[2].AeadOpen? && log[2].nonce == ComputeNonce(EV.Repeat(12, 9), 2);
    s, log := SPump(s, HandlerRead);
    expect log == [Close(EV.RequestBody)];
    // The first write starts the response with the nonce and seals one frame.
    s, log := SPump(s, HandlerChunk(T.A("ok")));
    expect log == [StartResponse(200, TestKeys), AeadSeal(EV.Repeat(32, 9), ComputeNonce(EV.Repeat(12, 9), 0), T.A("ok")), Write(Frame(T.A("ok") + Tag), EV.More)];
    s, log := SPump(s, HandlerChunk([]));
    expect log == [];
    s, log := SPump(s, HandlerDone);
    expect log == [Close(EV.ResponseBody)] && s.phase.Ended?;
    // A write larger than a frame is sealed in RequestFrameBytes pieces.
    s := Dispatched();
    var big := EV.Repeat(RequestFrameBytes as nat + 1, 4);
    s, log := SPump(s, HandlerChunk(big));
    expect |log| == 5 && log[1].AeadSeal? && |log[1].plaintext| == RequestFrameBytes as nat && log[3].AeadSeal? && log[3].plaintext == [4];
    expect log[3].nonce == ComputeNonce(EV.Repeat(12, 9), 1) && log[4] == Write(Frame([4] + Tag), EV.More);
  }

  method {:test} ServerRefusesBadKeys() {
    var s, log := SPump(ServerInitial(Sk, Pk), RequestStart([("X-A", "1")], true));
    expect log == [PassRequest];
    s, log := SPump(ServerInitial(Sk, Pk), RequestStart([("X-A", "1")], false));
    expect log == [PassRequest];
    var bad := [[("ehbp-encapsulated-key", "zz")], [(EncapsulatedKeyHeader, "abcd")], [(EncapsulatedKeyHeader, "")], KeyHeader + KeyHeader];
    for i := 0 to |bad| {
      s, log := SPump(ServerInitial(Sk, Pk), RequestStart(bad[i], true));
      expect |log| == 1 && log[0].Respond? && log[0].status == 400 && log[0].code == InvalidEncapsulatedKey;
      expect log[0].headers == TextHeaders && log[0].body == Text("failed to decrypt request\n");
    }
    s, log := SPump(ServerInitial(Sk, Pk), RequestStart(KeyHeader, false));
    expect |log| == 1 && log[0].Respond? && log[0].status == 400 && log[0].code == FramingTruncated;
  }

  method {:test} {:isolate_assertions} ServerDecapsulationFailureIs422() {
    var (s, acts) := ServerStep(ServerInitial(Sk, Pk), RequestStart(KeyHeader, true));
    expect acts == [X25519(Sk, Enc)];
    var (s2, acts2) := ServerStep(s, X25519Result([]));
    expect |acts2| == 1 && acts2[0].Respond? && acts2[0].status == 422 && acts2[0].code == HpkeSetupFailed;
    expect acts2[0].headers == [("Content-Type", ProblemJsonMediaType)];
    expect acts2[0].body == Text("{\"type\":\"urn:ietf:params:ehbp:error:key-config\",\"title\":\"failed to decrypt request\"}\n");
    // The first frame failing to authenticate is the same recovery; a later one is a 400.
    s := Decapped();
    var (s3, acts3) := ServerStep(s, Chunk(Frame(EV.Repeat(20, 5)), false));
    expect |acts3| == 1 && acts3[0].AeadOpen?;
    var (_, acts4) := ServerStep(s3, AeadOpenResult(false, []));
    expect |acts4| == 1 && acts4[0].Respond? && acts4[0].status == 422 && acts4[0].code == AeadDecryptFailed && acts4[0].body == Text("{\"type\":\"urn:ietf:params:ehbp:error:key-config\",\"title\":\"failed to decrypt request\"}\n");
    s := Decapped();
    var (s5, acts5) := ServerStep(s, Chunk(Frame(T.A("hi") + Tag) + Frame(EV.Repeat(20, 5)), false));
    var (s6, acts6) := ServerStep(s5, AeadOpenResult(true, T.A("hi")));
    expect |acts6| == 2 && acts6[0] == EmitPlaintext(T.A("hi")) && acts6[1].AeadOpen?;
    var (s7, acts7) := ServerStep(s6, AeadOpenResult(false, []));
    // The plaintext before the bad frame reaches the handler; its next read fails; the answer is a 400.
    expect |acts7| == 1 && acts7[0].HmacSha256? && s7.phase.Deriving?;
    var log;
    s, log := SPump(s7, HmacResult(EV.Repeat(32, 9)));
    expect |log| > 0 && Last(log) == Dispatch;
    s, log := SPump(s, HandlerRead);
    expect log == [Fail(AeadDecryptFailed, "frame failed to authenticate")];
    s, log := SPump(s, HandlerDone);
    expect |log| == 1 && log[0].Respond? && log[0].status == 400 && log[0].code == AeadDecryptFailed && log[0].body == Text("failed to read decrypted request body\n");
  }

  method {:test} ServerTruncatedRequests() {
    // A partial length prefix at eof, before any plaintext.
    var s := Decapped();
    var log;
    s, log := SPump(s, Chunk([0, 0, 0], true));
    expect |log| == 1 && log[0].Respond? && log[0].status == 400 && log[0].code == FramingTruncated;
    // Zero-length frames only.
    s := Decapped();
    s, log := SPump(s, Chunk([0, 0, 0, 0, 0, 0, 0, 0], true));
    expect |log| == 1 && log[0].Respond? && log[0].status == 400 && log[0].code == FramingTruncated && log[0].message == "encrypted request ended before any plaintext";
    // An empty frame that authenticates is not a payload either.
    s := Decapped();
    s, log := SPump(s, Chunk(Frame(Tag), true));
    expect |log| == 2 && log[0].AeadOpen? && log[1].Respond? && log[1].code == FramingTruncated;
    // A chunk without a complete frame is read on; a failed read is a truncation.
    s := Decapped();
    s, log := SPump(s, Chunk([0, 0], false));
    expect log == [Read(EV.RequestBody)];
    s, log := SPump(s, StreamFailed);
    expect |log| == 1 && log[0].Respond? && log[0].status == 400 && log[0].code == FramingTruncated;
    // An oversized length prefix is refused before any read of the frame.
    s := Decapped();
    s, log := SPump(s, Chunk([0xff, 0xff, 0xff, 0xff], false));
    expect |log| == 1 && log[0].Respond? && log[0].status == 400 && log[0].code == ChunkTooLarge;
    // After dispatch a truncation fails the handler's read; the started response is aborted.
    s := Dispatched();
    s, log := SPump(s, HandlerHead(201));
    expect log == [StartResponse(201, TestKeys)];
    s, log := SPump(s, HandlerRead);
    s, log := SPump(s, Chunk([0, 0, 0, 9], true));
    expect log == [Fail(FramingTruncated, "truncated request frame")];
    s, log := SPump(s, HandlerDone);
    expect log == [Write([], EV.Aborted(FramingTruncated))] && s.phase.Ended?;
    s, log := SPump(s, HandlerRead);
    expect log == [Close(EV.RequestBody)];
  }

  method {:test} ServerEmptyResponseCarriesAFrame() {
    var s := Dispatched();
    var log;
    s, log := SPump(s, HandlerDone);
    expect log == [StartResponse(200, TestKeys), AeadSeal(EV.Repeat(32, 9), ComputeNonce(EV.Repeat(12, 9), 0), []), Write(Frame(Tag), EV.More), Close(EV.ResponseBody)];
    // 204 is sent as 200; an informational status is forwarded and does not start the response.
    s := Dispatched();
    s, log := SPump(s, HandlerHead(103));
    expect log == [StartResponse(103, [])];
    s, log := SPump(s, HandlerHead(204));
    expect log == [StartResponse(200, TestKeys)];
    s, log := SPump(s, HandlerHead(500));
    expect log == [];
    s, log := SPump(s, HandlerDone);
    expect |log| == 3 && log[0].AeadSeal? && log[0].plaintext == [] && log[2] == Close(EV.ResponseBody);
    // 304 cannot carry a body: no frame.
    s := Dispatched();
    s, log := SPump(s, HandlerHead(304));
    s, log := SPump(s, HandlerDone);
    expect log == [Close(EV.ResponseBody)];
  }
}
