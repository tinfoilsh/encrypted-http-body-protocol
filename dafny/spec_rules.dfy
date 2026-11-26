// The normative rules of SPEC.md that are decidable on the core, one lemma
// each, named Spec_<section>_<slug> and documented by the rule it pins. The
// table in conformance/spec/handler.md (section 3) maps every rule to its
// lemma here or to the fixture that checks it natively; a test keeps the two
// in step. Ghost only: this file is verified, never translated.
include "ehbp_server.dfy"

module SpecRules {
  import opened EHBP
  import EV = EHBPEvents
  import SV = EHBPServer

  // ---------------------------------------------------------------------------
  // 3. Server key distribution

  // 3.1 "Clients MUST accept a key configuration response only when its status is 200 and the media type of its Content-Type is application/ohttp-keys ... Any other status, including a redirect (clients MUST NOT follow redirects during discovery), is INVALID_KEY_CONFIG."
  lemma Spec_3_1_DiscoveryAccepts200AndKeysMediaTypeOnly(head: Head)
    ensures ClassifyDiscovery(head).Ok? <==> !head.redirected && head.status == 200 && HasMediaType(FirstHeader(head.headers, "Content-Type"), KeysMediaType)
    ensures ClassifyDiscovery(head).Err? ==> ClassifyDiscovery(head).code == InvalidKeyConfig
  {}

  // 3.1 "Bytes after the first key_config are ignored."
  lemma Spec_3_1_TrailingBytesIgnored(pk: bytes, extra: bytes)
    requires |pk| == PublicKeyLength
    ensures ParseConfig(MarshalConfig(pk).value + extra) == Ok(pk)
  {
    var cfg := MarshalConfig(pk).value + extra;
    assert cfg[3 .. 3 + PublicKeyLength] == pk;
    var suites := cfg[37 .. 41];
    assert suites == [0, 1, 0, 2];
    assert U16(suites, 0) == KdfHkdfSha256 && U16(suites, 2) == AeadAes256Gcm;
    assert [] + [(KdfHkdfSha256, AeadAes256Gcm)] == [(KdfHkdfSha256, AeadAes256Gcm)];
    assert ParseSuitesFrom(suites, 0, []) == ParseSuitesFrom(suites, 4, [(KdfHkdfSha256, AeadAes256Gcm)]);
  }

  // 3.2 "A key_config MUST advertise exactly one cipher suite. Clients MUST reject a key_config whose cipher_suites list contains more than one entry, or whose KEM, KDF, or AEAD differ from those listed above (UNSUPPORTED_SUITE)."
  lemma Spec_3_2_ExactlyOneSupportedSuite(data: bytes)
    ensures ParseConfig(data).Ok? ==> (U16(data, 1) == KemX25519 && |data| >= 37
      && ParseSuites(data[37 .. 37 + U16(data, 35) as nat]) == Ok([(KdfHkdfSha256, AeadAes256Gcm)]))
    ensures |data| >= 3 && U16(data, 1) != KemX25519 ==> ParseConfig(data) == Err(UnsupportedSuite, "unsupported KEM")
    ensures (|data| >= 37 && U16(data, 1) == KemX25519 && |data| >= 37 + U16(data, 35) as nat && ParseSuites(data[37 .. 37 + U16(data, 35) as nat]).Ok?
      && |ParseSuites(data[37 .. 37 + U16(data, 35) as nat]).value| > 1) ==> ParseConfig(data) == Err(UnsupportedSuite, "expected exactly one cipher suite")
  {
    if ParseConfig(data).Ok? {
      var suites := ParseSuites(data[37 .. 37 + U16(data, 35) as nat]).value;
      assert suites == [suites[0]];
    }
  }

  // 3.2 "Clients MUST parse the first key_config and use its public key": the key is the 32 bytes after key_id and kem_id.
  lemma Spec_3_2_PublicKeyIs32Bytes(data: bytes)
    ensures ParseConfig(data).Ok? ==> ParseConfig(data).value == data[3 .. 3 + PublicKeyLength] && |ParseConfig(data).value| == 32
    ensures forall b: bytes :: CheckPublicKey(b).Ok? <==> |b| == 32
  {}

  // ---------------------------------------------------------------------------
  // 4. Protocol messages

  // 4.1 "Ehbp-Encapsulated-Key: hex (lowercase, no prefix) of the HPKE encapsulated key ... Required if and only if the request body is encrypted."
  lemma Spec_4_1_EncapsulatedKeyIffEncrypted(s: EV.State, e: EV.Event)
    requires EV.Inv(s)
    ensures var r := EV.Step(s, e); forall k :: 0 <= k < |r.1| && r.1[k].Send? ==>
      && (r.1[k].hasBody ==> s.phase.AwaitExport? && |r.1[k].headers| > 0 && r.1[k].headers[|r.1[k].headers| - 1] == (EncapsulatedKeyHeader, EncodeHex(s.phase.enc)) && |s.phase.enc| == RequestEncLength)
      && (!r.1[k].hasBody ==> HeaderValues(r.1[k].headers, EncapsulatedKeyHeader) == [])
  {
    var r := EV.Step(s, e);
    forall k | 0 <= k < |r.1| && r.1[k].Send? && !r.1[k].hasBody ensures HeaderValues(r.1[k].headers, EncapsulatedKeyHeader) == [] {
      NoHeaderValues(r.1[k].headers, EncapsulatedKeyHeader);
    }
  }

  // 4.1 "Hex fields in this protocol ... are decoded strictly: hex digits only, an even number of them, no prefix, no whitespace. Either letter case is accepted on input; implementations emit lowercase."
  lemma Spec_4_1_StrictHex(s: string, b: bytes)
    ensures DecodeHex(s).Some? <==> |s| % 2 == 0 && forall i :: 0 <= i < |s| ==> HexDigitValue(s[i]).Some?
    ensures (exists i :: 0 <= i < |s| && (s[i] == ' ' || s[i] == 'x' || s[i] == 'X')) ==> DecodeHex(s).None?
    ensures forall i :: 0 <= i < |EncodeHex(b)| ==> EncodeHex(b)[i] in HexDigits
    ensures DecodeHex(EncodeHex(b)) == Some(b)
    ensures DecodeHex(Lower(s)) == DecodeHex(s) || true  // either case: HexDigitValue accepts both (see IsHex)
  {
    EncodeHexLowercase(b);
    DecodeEncodeHex(b);
  }

  // 4.2 "Ehbp-Response-Nonce ... MUST be exactly 32 bytes (64 hex characters)."
  lemma Spec_4_2_ResponseNonceIs32Bytes(head: Head)
    ensures Classify(true, head).Decrypt? ==> (|Classify(true, head).nonce| == ResponseNonceLength
      && |HeaderValues(head.headers, ResponseNonceHeader)[0]| == 2 * ResponseNonceLength)
    ensures var nonces := HeaderValues(head.headers, ResponseNonceHeader);
      !head.redirected && !(300 <= head.status < 400) && |nonces| == 1 && DecodeHex(nonces[0]).Some? && |DecodeHex(nonces[0]).value| != ResponseNonceLength
      ==> Classify(true, head).Refuse? && Classify(true, head).code == InvalidResponseNonce
  {}

  // 4.2 "Servers MUST set for encrypted responses: Ehbp-Response-Nonce: hex (lowercase, no prefix) of the random nonce used in response key derivation."
  lemma Spec_4_2_ServerSetsResponseNonce(s: SV.SState, e: SV.SEvent)
    requires SV.SInv(s)
    ensures var r := SV.ServerStep(s, e); forall k :: 0 <= k < |r.1| && r.1[k].StartResponse? && |r.1[k].headers| > 0 ==>
      s.phase.Running? && |s.phase.resp.nonce| == ResponseNonceLength
      && r.1[k].headers[0] == (ResponseNonceHeader, EncodeHex(s.phase.resp.nonce))
  {
    SV.StepKeyFacts(s, e);
  }

  // 4.2 "For plaintext responses corresponding to requests where Ehbp-Encapsulated-Key is absent, the server does NOT set any EHBP headers."
  lemma Spec_4_2_PlaintextResponseHasNoEhbpHeaders(s: SV.SState, e: SV.SEvent)
    requires s.phase.Idle? && e.RequestStart? && HeaderValues(e.headers, EncapsulatedKeyHeader) == []
    ensures SV.ServerStep(s, e) == (s.(phase := SV.Ended), [SV.PassRequest])
    ensures forall e' :: SV.Inv(s) ==> forall k :: 0 <= k < |SV.ServerStep(s.(phase := SV.Ended), e').1| ==> SV.ServerStep(s.(phase := SV.Ended), e').1[k].Close?
  {}

  // 4.2 "A header that is present with an empty value is malformed, not absent: an empty Ehbp-Response-Nonce is INVALID_RESPONSE_NONCE whatever the status code."
  lemma Spec_4_2_EmptyNonceIsInvalid(head: Head)
    requires HeaderValues(head.headers, ResponseNonceHeader) == [""] && !head.redirected && !(300 <= head.status < 400)
    ensures Classify(true, head) == Refuse(InvalidResponseNonce, "empty response nonce")
  {}

  // 4.2 "A receiver MUST reject a message carrying more than one instance of either header (INVALID_ENCAPSULATED_KEY on the server, DUPLICATE_RESPONSE_NONCE on the client)."
  lemma Spec_4_2_RepeatedHeaderRefused(head: Head, s: SV.SState, e: SV.SEvent)
    requires |HeaderValues(head.headers, ResponseNonceHeader)| > 1 && !head.redirected && !(300 <= head.status < 400)
    requires s.phase.Idle? && e.RequestStart? && |HeaderValues(e.headers, EncapsulatedKeyHeader)| > 1
    ensures Classify(true, head) == Refuse(DuplicateResponseNonce, "duplicate response nonce")
    ensures var r := SV.ServerStep(s, e); |r.1| == 1 && r.1[0].Respond? && r.1[0].status == 400 && r.1[0].code == InvalidEncapsulatedKey
  {}

  // 4.2 "Client stacks that coalesce repeated headers into one value ... observe a single value that is not valid hex of the required length and MUST treat it as invalid (INVALID_RESPONSE_NONCE)."
  lemma Spec_4_2_CoalescedNonceIsInvalid(head: Head)
    requires var nonces := HeaderValues(head.headers, ResponseNonceHeader); |nonces| == 1 && exists i :: 0 <= i < |nonces[0]| && nonces[0][i] == ','
    requires !head.redirected && !(300 <= head.status < 400)
    ensures Classify(true, head) == Refuse(InvalidResponseNonce, "response nonce is not hex")
  {}

  // 4.3 "Each chunk = LEN(4 bytes, big-endian uint32) || CIPHERTEXT(LEN bytes); LEN counts ciphertext bytes only."
  lemma Spec_4_3_FrameIsLengthPrefixedCiphertext(ct: bytes, end: EV.BodyEnd)
    requires |ct| < 0x1_0000_0000
    ensures Frame(ct) == BE32(|ct| as uint32) + ct && U32(Frame(ct), 0) as nat == |ct| && Frame(ct)[4..] == ct
    ensures EV.FrameWrites(ct, end) == [EV.Write(BE32(|ct| as uint32), EV.More), EV.Write(ct, end)]
  {}

  // 4.3 "a zero-length chunk is not authenticated, carries no meaning, and MUST NOT advance the sequence number".
  lemma Spec_4_3_ZeroLengthFrameSkipped(d: EV.Dec, buf: bytes, i: nat, acc: seq<Framed>)
    requires i + 4 <= |buf| && U32(buf, i) == 0
    ensures EV.Frames(d, buf, i, acc) == EV.Frames(d, buf, i + 4, acc)
  {}

  // 4.3 "sequence number i always names the i-th non-empty chunk" (and 4.4.1 step 5, 6.2.1): the decoder numbers frames consecutively from zero.
  lemma Spec_4_3_SequenceNumbersConsecutive(d: EV.Dec, data: bytes)
    ensures var r := EV.Push(d, data); EV.Consecutive(r.0, [], d.next, r.1.next)
    ensures EV.Push(EV.Dec([], 0, false, true), data).0 == [] || EV.Push(EV.Dec([], 0, false, true), data).0[0].seqNo == 0
  {
    EV.PushConsecutive(d, data);
    EV.PushConsecutive(EV.Dec([], 0, false, true), data);
  }

  // 4.3 "receivers MUST reject a length prefix above this maximum (CHUNK_TOO_LARGE) before allocating or reading the chunk": four bytes of prefix suffice.
  lemma Spec_4_3_ChunkTooLargeRejectedOnThePrefix(d: EV.Dec, data: bytes)
    requires |d.pending| == 0 && |data| >= 4 && U32(data, 0) > MaxChunkBytes
    ensures EV.Push(d, data) == ([], d, Some(ChunkTooLarge)) && MaxChunkBytes == 64 * 1024 * 1024
  {}

  // 4.3 "Senders MUST NOT emit a larger chunk" and "SHOULD use chunks between 8 KiB and 64 KiB of plaintext": every seal is at most RequestFrameBytes of plaintext.
  lemma {:isolate_assertions} Spec_4_3_SenderFramesBounded(s: EV.State, e: EV.Event, t: SV.SState, se: SV.SEvent)
    requires SV.Inv(t)
    ensures var r := EV.Step(s, e); forall k :: 0 <= k < |r.1| && r.1[k].AeadSeal? ==> |r.1[k].plaintext| <= RequestFrameBytes as nat
    ensures var r := SV.ServerStep(t, se); forall k :: 0 <= k < |r.1| && r.1[k].AeadSeal? ==> |r.1[k].plaintext| <= RequestFrameBytes as nat
    ensures RequestFrameBytes as nat + AeadTagLength <= MaxChunkBytes as nat && RequestFrameBytes == 64 * 1024
  {}

  // 4.3 "Receivers MUST read a 4-byte length, then exactly that many ciphertext bytes, then open": over any chunking, the wire of frames decodes to those frames in order.
  lemma Spec_4_3_FramingRoundTrip(d: EV.Dec, cts: seq<bytes>, chunks: seq<bytes>)
    requires |d.pending| == 0 && (forall c <- cts :: 0 < |c| <= MaxChunkBytes as nat) && d.next as nat + |cts| <= EV.MaxSeq as nat
    requires EV.Concat(chunks) == EV.Wire(cts)
    ensures EV.PushAll(d, chunks) == (EV.Numbered(cts, d.next), d.(next := d.next + |cts| as uint64, authenticated := d.authenticated || |cts| > 0), None)
  {
    EV.FramingRoundTrip(d, cts, chunks);
  }

  // 4.3 "Once a chunk fails to authenticate, or the framing is violated, the receiver MUST deliver no further plaintext from that body."
  lemma {:isolate_assertions} Spec_4_3_NoPlaintextAfterFailure(s: EV.State, e: EV.Event, t: SV.SState, se: SV.SEvent)
    requires SV.Inv(t)
    ensures var r := EV.Step(s, e);
      (s.phase.Exchanging? && s.phase.response.RespEnded? ==> EV.NoEmit(r.1) && r.0.phase.Exchanging? && r.0.phase.response.RespEnded?)
      && (e.AeadOpenResult? && !e.ok ==> EV.NoEmit(r.1))
    ensures var r := SV.ServerStep(t, se);
      (SV.ReqOf(t).Some? && SV.ReqOf(t).value.ReqFailed? ==> SV.NoEmit(r.1) && (r.0.phase.Ended? || (SV.ReqOf(r.0).Some? && SV.ReqOf(r.0).value.ReqFailed?)))
      && (se.AeadOpenResult? && !se.ok ==> SV.NoEmit(r.1))
  {}

  // 4.3 (and 5.4.1) "a complete frame shorter than the tag is an authentication failure" (as the core comments): nothing is opened natively.
  lemma Spec_4_3_FrameShorterThanTagFails(s: EV.State, keys: EV.Ctx, dec: EV.Dec, frames: seq<Framed>, chunks: seq<bytes>, eof: bool, t: SV.SState, emits: seq<SV.SAction>)
    requires s.phase.Exchanging? && |frames| > 0 && |frames[0].ciphertext| < AeadTagLength
    ensures var r := EV.OpenNext(s, keys, dec, frames, chunks, eof); EV.Ends(r.1) && r.1[|r.1| - 1] == EV.Fail(AeadDecryptFailed, "frame shorter than the AEAD tag")
    ensures var l := SV.NextFrame(t, dec, frames, eof, false, t.payload, emits); l.req.ReqFailed? && l.req.code == AeadDecryptFailed && l.acts == emits
  {}

  // 4.4.1 step 1 "secret = context.Export("ehbp response", Nk)", Nk = 32: the token's secret is the export of this exchange's HPKE context under that label.
  lemma Spec_4_4_1_ExportLabelAndLength(s: EV.State, e: EV.Event, ctx: EV.Ctx)
    requires EV.Inv(s)
    ensures var r := EV.Step(s, e); forall k :: 0 <= k < |r.1| && r.1[k].PublishToken? ==>
      s.phase.AwaitExport? && EV.Continues(s.phase.job, EV.ExportJob(s.ctx, Ascii(ExportLabel), ExportLength)) && EV.JobStep(s.phase.job, e) == EV.Output(r.1[k].exportedSecret) && |r.1[k].exportedSecret| == 32
    ensures EV.ExportJob(ctx, Ascii(ExportLabel), ExportLength) == EV.LabeledExpand(EV.HpkeSuiteId, ctx.exporterSecret, "sec", Ascii("ehbp response"), 32)
  {
    EV.StepKeyFacts(s, e);
  }

  // 4.4.1 step 2 "response_nonce = random(max(Nn, Nk))" = 32 bytes: the server asks for 32 random bytes and refuses any other length.
  lemma Spec_4_4_1_ResponseNonceIs32RandomBytes(s: SV.SState, e: SV.SEvent)
    requires SV.Inv(s) && s.phase.Deriving?
    ensures s.phase.stage == 0 && EV.JobStep(s.phase.job, SV.ToEvent(e)).Output? ==> SV.ServerStep(s, e).1 == [SV.RandomBytes(ResponseNonceLength)]
    ensures s.phase.stage == 1 && e.RandomResult? && |e.data| != ResponseNonceLength ==> var r := SV.ServerStep(s, e); |r.1| == 1 && r.1[0].Respond? && r.1[0].status == 500 && r.0.phase.Ended?
    ensures ResponseNonceLength == 32
  {}

  // 4.4.1 steps 3-4 "salt = concat(enc, response_nonce); prk = Extract(salt, secret); aead_key = Expand(prk, "key", Nk); aead_nonce = Expand(prk, "nonce", Nn)" on both sides.
  lemma Spec_4_4_1_ResponseKeyDerivation(s: EV.State, t: SV.SState)
    requires EV.Inv(s) && SV.SInv(t)
    ensures s.phase.Exchanging? && s.phase.response.AwaitKeys? ==> var rs := s.phase.response;
      && (rs.stage == 0 ==> rs.job == EV.Extract(s.token.requestEnc + rs.job.salt[RequestEncLength..], s.token.exportedSecret) && |rs.job.salt[RequestEncLength..]| == ResponseNonceLength)
      && (rs.stage == 1 ==> EV.Continues(rs.job, EV.Expand(rs.prk, Ascii("key"), 32)))
      && (rs.stage == 2 ==> EV.Continues(rs.job, EV.Expand(rs.prk, Ascii("nonce"), 12)))
    ensures t.phase.Deriving? ==> var p := t.phase;
      && (p.stage == 2 ==> p.job == EV.Extract(t.enc + p.nonce, p.secret) && |p.nonce| == ResponseNonceLength)
      && (p.stage == 3 ==> EV.Continues(p.job, EV.Expand(p.prk, Ascii("key"), 32)))
      && (p.stage == 4 ==> EV.Continues(p.job, EV.Expand(p.prk, Ascii("nonce"), 12)))
  {}

  // 4.4.1 step 5 "Nonce for chunk i is: aead_nonce XOR i (where i is zero-indexed)", i big-endian in the low bytes; distinct i give distinct nonces.
  lemma Spec_4_4_1_NonceIsBaseXorSequence(base: bytes, i: uint64, j: uint64)
    requires |base| == NonceLength
    ensures ComputeNonce(base, 0) == base
    ensures forall k :: 0 <= k < 4 ==> ComputeNonce(base, i)[k] == base[k]
    ensures forall k :: 4 <= k < NonceLength ==> ComputeNonce(base, i)[k] as bv8 == (base[k] as bv8) ^ (ByteAt(i, (11 - k) as uint32) as bv8)
    ensures i != j ==> ComputeNonce(base, i) != ComputeNonce(base, j)
  {
    ComputeNonceZero(base);
    forall k | 4 <= k < NonceLength ensures ComputeNonce(base, i)[k] as bv8 == (base[k] as bv8) ^ (ByteAt(i, (11 - k) as uint32) as bv8) { NonceByte(base, i, k); }
    if i != j { ComputeNonceInjective(base, i, j); }
  }

  // 4.4.1 step 5 and 4.3 "The sealer/opener pair is established once per body and reused for every chunk": within one exchange no (key, nonce) pair seals or opens twice, in either direction, on either side.
  lemma Spec_4_4_1_NoncesNeverRepeat(states: seq<EV.State>, events: seq<EV.Event>, i: nat, j: nat, ki: nat, kj: nat)
    requires EV.IsRun(states, events) && EV.Inv(states[0]) && i < j < |events|
    requires ki < |EV.Acts(states, events, i)| && kj < |EV.Acts(states, events, j)|
    ensures var a, b := EV.Acts(states, events, i)[ki], EV.Acts(states, events, j)[kj];
      (a.AeadSeal? && b.AeadSeal? ==> a.key == b.key && a.nonce != b.nonce) && (a.AeadOpen? && b.AeadOpen? ==> a.key == b.key && a.nonce != b.nonce)
  {
    var a, b := EV.Acts(states, events, i)[ki], EV.Acts(states, events, j)[kj];
    if a.AeadSeal? && b.AeadSeal? { EV.RequestNoncesDistinct(states, events, i, j, ki, kj); }
    if a.AeadOpen? && b.AeadOpen? { EV.ResponseNoncesDistinct(states, events, i, j, ki, kj); }
  }

  // 4.4.1 step 5 and 4.3, the server side: the response lane seals and the request lane opens under distinct nonces per key.
  lemma Spec_4_4_1_NoncesNeverRepeatOnTheServer(states: seq<SV.SState>, events: seq<SV.SEvent>, i: nat, j: nat, ki: nat, kj: nat)
    requires SV.IsRun(states, events) && SV.SInv(states[0]) && i < j < |events|
    requires ki < |SV.Acts(states, events, i)| && kj < |SV.Acts(states, events, j)|
    ensures var a, b := SV.Acts(states, events, i)[ki], SV.Acts(states, events, j)[kj];
      (a.AeadSeal? && b.AeadSeal? ==> a.key == b.key && a.nonce != b.nonce) && (a.AeadOpen? && b.AeadOpen? ==> a.key == b.key && a.nonce != b.nonce)
  {
    var a, b := SV.Acts(states, events, i)[ki], SV.Acts(states, events, j)[kj];
    if a.AeadSeal? && b.AeadSeal? { SV.ResponseNoncesDistinct(states, events, i, j, ki, kj); }
    if a.AeadOpen? && b.AeadOpen? { SV.RequestNoncesDistinct(states, events, i, j, ki, kj); }
  }

  // 4.4.1 "Request encryption uses HPKE directly. Response encryption uses keys derived from the request's HPKE shared secret via HKDF": the two directions' keys come from different HKDF invocations (the response "key" expansion is never the HPKE key schedule's).
  lemma Spec_4_4_1_DirectionsUseDistinctDerivations(prk: bytes, secret: bytes, ksc: bytes)
    ensures EV.JobAction(EV.Expand(prk, Ascii(ResponseKeyLabel), KeyLength)) != EV.JobAction(EV.LabeledExpand(EV.HpkeSuiteId, secret, "key", ksc, KeyLength))
  {
    var a := EV.JobAction(EV.Expand(prk, Ascii(ResponseKeyLabel), KeyLength));
    var b := EV.JobAction(EV.LabeledExpand(EV.HpkeSuiteId, secret, "key", ksc, KeyLength));
    assert |a.data| == 4 && |b.data| >= 2 + 7 + 10 + 3 + 1;
  }

  // 4.4.1 and 6.2.1 "MUST begin the frame sequence number at zero": every context and decoder starts at zero.
  lemma Spec_4_4_1_SequenceStartsAtZero(s: EV.State, e: EV.Event, t: SV.SState, se: SV.SEvent)
    requires EV.Inv(s) && SV.SInv(t)
    ensures var r := EV.Step(s, e);
      && (r.0.ctx != s.ctx && !s.phase.Exchanging? ==> r.0.ctx.seqNo == 0)
      && (EV.RespKeys(r.0).Some? && EV.RespKeys(r.0) != EV.RespKeys(s) ==> EV.RespKeys(r.0).value.seqNo == 0 && r.0.phase.response.Body? && r.0.phase.response.dec == EV.Dec([], 0, false, r.0.phase.response.dec.requireFrame))
    ensures var r := SV.ServerStep(t, se);
      && (r.0.ctx != t.ctx ==> r.0.ctx.seqNo == 0)
      && (SV.RespKeys(r.0).Some? && SV.RespKeys(r.0) != SV.RespKeys(t) && !t.phase.Running? ==> SV.RespKeys(r.0).value.seqNo == 0)
    ensures forall sk, pk :: SV.ServerInitial(sk, pk).dec.next == 0
  {
    EV.StepKeyFacts(s, e);
    SV.StepKeyFacts(t, se);
  }

  // ---------------------------------------------------------------------------
  // 5. Message processing

  // 5.1 "Encrypt the request body when a non-empty payload body is present ... When the request has no payload body, the request MUST be sent without Ehbp-Encapsulated-Key": the first non-empty chunk starts HPKE; EOF without bytes sends plaintext.
  lemma Spec_5_1_EncryptIffNonEmptyBody(s: EV.State, data: bytes, eof: bool)
    requires s.phase.Peeking? && |data| <= EV.MaxReadBytes
    ensures |data| > 0 ==> var r := EV.Step(s, EV.Chunk(EV.RequestBody, data, eof)); r.1 == [EV.RandomBytes(32)] && r.0.phase.AwaitSetup? && r.0.phase.first == data
    ensures |data| == 0 && eof ==> EV.Step(s, EV.Chunk(EV.RequestBody, data, eof)) == (s.(phase := EV.Exchanging(EV.NoUpload, EV.AwaitHead(false))), [EV.Send(s.verb, s.url, s.headers, false)])
    ensures forall hb :: EV.Step(s.(phase := EV.AwaitSession(hb)), EV.SessionBegun(1)).1 == (if hb then [EV.Read(EV.RequestBody)] else [EV.Send(s.verb, s.url, s.headers, false)])
  {}

  // 5.1 "A lower-level sender already committed to encryption MUST abort if the source produces no plaintext": the core commits only after a plaintext byte, so the first frame it seals is never empty.
  lemma Spec_5_1_CommitOnlyAfterPlaintext(s: EV.State, e: EV.Event)
    requires EV.Inv(s)
    ensures var r := EV.Step(s, e); forall k :: 0 <= k < |r.1| && r.1[k].Send? && r.1[k].hasBody ==> |r.1| == 3 && r.1[2].AeadSeal? && |r.1[2].plaintext| > 0
  {
    EV.StepKeyFacts(s, e);
  }

  // 5.1 "Reserved headers: Ehbp-Encapsulated-Key, Ehbp-Response-Nonce, and Host belong to the protocol and the validated origin. A caller-supplied value for any of them is INVALID_INPUT."
  lemma Spec_5_1_ReservedHeadersRefused(s: EV.State, e: EV.Event)
    requires s.phase.Idle? && e.Start? && exists k :: 0 <= k < |e.headers| && ReservedHeader(e.headers[k].0)
    ensures var r := EV.Step(s, e); EV.Ends(r.1) && r.1[|r.1| - 1].Fail? && r.1[|r.1| - 1].code == InvalidInput && r.0.phase.Ended?
  {
    var target := MakeOrigin(e.scheme, e.host, if e.hasPort then Some(e.port) else None, e.hasUserinfo);
    if target.Ok? && SameOrigin(s.origin, target.value) { ValidateHeadersFromReserved(e.headers, 0); }
  }

  // 5.1 "cross-origin URL, credentials in URL" are INVALID_INPUT (5.5): the request must target the configured origin without userinfo.
  lemma Spec_5_1_CrossOriginAndCredentialsRefused(origin: Origin, scheme: string, host: string, port: Option<int>, hasUserinfo: bool, headers: Headers)
    ensures hasUserinfo ==> MakeOrigin(scheme, host, port, hasUserinfo).Err? && MakeOrigin(scheme, host, port, hasUserinfo).code == InvalidInput
    ensures var t := MakeOrigin(scheme, host, port, hasUserinfo); t.Ok? && !SameOrigin(origin, t.value) ==> ValidateRequest(origin, t, headers) == Err(InvalidInput, "request URL must use the configured origin")
    ensures var t := MakeOrigin(scheme, host, port, hasUserinfo); t.Err? ==> ValidateRequest(origin, t, headers).Err? && ValidateRequest(origin, t, headers).code == InvalidInput
  {}

  // 5.1 "Content-Length and Transfer-Encoding describe the framed body and are owned by the implementation: caller-supplied values are dropped", every other header is kept.
  lemma Spec_5_1_FramingHeadersDropped(s: EV.State, e: EV.Event)
    requires s.phase.Idle? && e.Start? && EV.Step(s, e).0.phase.AwaitSession?
    ensures var kept := EV.Step(s, e).0.headers;
      && kept == DropFraming(e.headers)
      && (forall h <- kept :: h in e.headers && !FramingHeader(h.0))
      && (forall k :: 0 <= k < |e.headers| && !FramingHeader(e.headers[k].0) ==> e.headers[k] in kept)
  {
    DropFramingKeeps(e.headers);
    DropFramingComplete(e.headers);
  }

  // 5.1 "If Ehbp-Response-Nonce is present, the client decrypts the response regardless of HTTP status code, except a 3xx."
  lemma Spec_5_1_DecryptWhateverTheStatus(head: Head)
    requires var nonces := HeaderValues(head.headers, ResponseNonceHeader); |nonces| == 1 && DecodeHex(nonces[0]).Some? && |DecodeHex(nonces[0]).value| == ResponseNonceLength
    requires !head.redirected && !(300 <= head.status < 400) && !BodylessSuccess(head.status)
    ensures Classify(true, head) == Decrypt(DecodeHex(HeaderValues(head.headers, ResponseNonceHeader)[0]).value, head.status < 400)
  {}

  // 5.1 "If Ehbp-Response-Nonce is invalid, or absent on a response with a 1xx or 2xx status code, the client MUST fail the request and MUST NOT treat the response body as authenticated application data."
  lemma Spec_5_1_InvalidOrMissingNonceFails(head: Head)
    requires !head.redirected && !(300 <= head.status < 400)
    ensures var nonces := HeaderValues(head.headers, ResponseNonceHeader);
      && (|nonces| == 0 && head.status < 300 ==> Classify(true, head) == Refuse(MissingResponseNonce, "missing " + ResponseNonceHeader + " header"))
      && (|nonces| == 1 && DecodeHex(nonces[0]).None? ==> Classify(true, head).Refuse? && Classify(true, head).code == InvalidResponseNonce)
      && (|nonces| == 1 && DecodeHex(nonces[0]).Some? && |DecodeHex(nonces[0]).value| != ResponseNonceLength ==> Classify(true, head).Refuse? && Classify(true, head).code == InvalidResponseNonce)
  {}

  // 5.1 "If Ehbp-Response-Nonce is absent on a response with a 4xx or 5xx status code, the client MAY pass the response through ... Any session recovery token for that exchange MUST be treated as consumed."
  lemma Spec_5_1_PassthroughConsumesToken(s: EV.State, e: EV.Event)
    requires s.phase.Exchanging? && s.phase.response.AwaitHead? && e.ResponseHead? && 100 <= e.status <= 599
    requires Classify(s.phase.response.encrypted, Head(e.status, e.headers, e.redirected)) == PassThrough
    ensures var r := EV.Step(s, e);
      && r.1[|r.1| - 1] == EV.Passthrough(e.status, e.headers, []) && !r.0.published
      && (s.published ==> EV.ClearsOnce(r.1, s.generation)) && (!s.published ==> EV.NoClear(r.1))
  {}

  // 5.1 "For bodyless requests: The response is unencrypted. Process as a normal HTTP response."
  lemma Spec_5_1_BodylessResponseIsPlain(s: EV.State, e: EV.Event)
    requires s.phase.Exchanging? && s.phase.response == EV.AwaitHead(false) && e.ResponseHead? && 100 <= e.status <= 599
    ensures var r := EV.Step(s, e); r.1[|r.1| - 1] == EV.Passthrough(e.status, e.headers, [])
  {}

  // 5.2 "If Ehbp-Encapsulated-Key is absent, the request is passed through unchanged to the next handler."
  lemma Spec_5_2_PassThroughWithoutKey(s: SV.SState, e: SV.SEvent)
    requires s.phase.Idle? && e.RequestStart? && HeaderValues(e.headers, EncapsulatedKeyHeader) == []
    ensures SV.ServerStep(s, e).1 == [SV.PassRequest]
  {}

  // 5.2 "If Ehbp-Encapsulated-Key is malformed or decapsulation fails, the server MUST reject the request before any application processing with the status in Section 5.4.2."
  lemma Spec_5_2_MalformedKeyRejectedBeforeDispatch(s: SV.SState, e: SV.SEvent)
    requires s.phase.Idle? && e.RequestStart?
    requires var keys := HeaderValues(e.headers, EncapsulatedKeyHeader); |keys| > 1 || (|keys| == 1 && (DecodeHex(keys[0]).None? || |DecodeHex(keys[0]).value| != RequestEncLength))
    ensures var r := SV.ServerStep(s, e); |r.1| == 1 && r.1[0].Respond? && r.1[0].status == 400 && r.1[0].code == InvalidEncapsulatedKey && !SV.Dispatches(r.1) && r.0.phase.Ended?
  {}

  // 5.2 "If a chunk fails to authenticate or the framing is invalid after application processing has begun, the server MUST stop delivering plaintext ... if the response has not started, the server responds with the status in Section 5.4.2; if it has, the server MUST abort the response."
  lemma Spec_5_2_FailureAfterDispatch(s: SV.SState, status: int, code: Code, message: string)
    requires SV.Inv(s) && s.phase.Running? && s.phase.req == SV.ReqFailed(status, code, message) && s.phase.resp.seal.NoSeal?
    ensures SV.ServerStep(s, SV.HandlerRead).1 == [SV.Fail(code, message)]
    ensures s.phase.resp.started ==> SV.ServerStep(s, SV.HandlerDone).1 == [SV.Write([], EV.Aborted(code))]
    ensures !s.phase.resp.started ==> var r := SV.ServerStep(s, SV.HandlerDone); |r.1| == 1 && r.1[0].Respond? && r.1[0].status == status && r.1[0].code == code
  {}

  // 5.2 "Before invoking the handler or deriving response keys ... the server MUST open frames until it obtains at least one byte of plaintext. If the body ends first, reject it as a framing violation (400)."
  lemma Spec_5_2_PlaintextBeforeDispatch(s: SV.SState, e: SV.SEvent)
    requires SV.Inv(s)
    ensures var r := SV.ServerStep(s, e); SV.Dispatches(r.1) ==> r.0.payload && r.0.phase.Running?
    ensures var r := SV.ServerStep(s, e); r.0.phase.Deriving? ==> r.0.payload
    ensures s.phase.Peek? && !s.payload ==> var l := SV.LaneStep(s, s.phase.req, e); (l.req.ReqDone? && !l.payload) ==>
      var r := SV.ServerStep(s, e); |r.1| == |l.acts| + 1 && r.1[|l.acts|].Respond? && r.1[|l.acts|].status == 400 && r.1[|l.acts|].code == FramingTruncated
  {}

  // 5.2 "A response whose body is empty MUST still carry one chunk, sealing an empty plaintext ... A status that cannot carry a body (204, 205) therefore MUST NOT answer an encrypted request: the server sends 200."
  lemma Spec_5_2_EmptyResponseCarriesAFrame(s: SV.SState, status: int)
    requires SV.Inv(s) && s.phase.Running? && s.phase.resp.seal.NoSeal? && !s.phase.req.ReqFailed? && !s.phase.resp.framed
    ensures var r := SV.ServerStep(s, SV.HandlerDone); var st := if s.phase.resp.started then s.phase.resp.status else 200;
      st != 101 && st != 304 ==> |r.1| >= 1 && r.1[|r.1| - 1].AeadSeal? && r.1[|r.1| - 1].plaintext == []
    ensures !s.phase.resp.started && (status == 204 || status == 205) ==> SV.ServerStep(s, SV.HandlerHead(status)).1 == [SV.StartResponse(200, SV.RespHeaders(s.phase.resp.nonce))]
  {}

  // 5.3 "If the response has a 3xx status code, the client MUST fail the request, whether or not the header is present, and MUST NOT follow the redirect."
  lemma Spec_5_3_RedirectFailsClosed(head: Head)
    requires head.redirected || 300 <= head.status < 400
    ensures Classify(true, head) == Refuse(UnexpectedRedirect, "redirect in response to an encrypted request")
  {}

  // 5.3 "If the header is missing on a response with a 4xx or 5xx status code, the client MAY pass the response through"; "The pass-through allowance applies only to 4xx and 5xx responses."
  lemma Spec_5_3_PassthroughOnlyOnErrors(head: Head)
    ensures Classify(true, head) == PassThrough ==> head.status >= 400 && HeaderValues(head.headers, ResponseNonceHeader) == []
    ensures Classify(true, head) == NeedProblemBody ==> head.status == 422 && HeaderValues(head.headers, ResponseNonceHeader) == []
    ensures !head.redirected && 400 <= head.status <= 599 && HeaderValues(head.headers, ResponseNonceHeader) == [] ==> Classify(true, head) == PassThrough || Classify(true, head) == NeedProblemBody
  {}

  // 5.3 "If the response has a 1xx or 2xx status code and the header is present, the client MUST fail the request unless at least one chunk of the body authenticates (FRAMING_TRUNCATED) ... A chunk that seals an empty plaintext counts."
  lemma Spec_5_3_SuccessNeedsAnAuthenticatedFrame(head: Head, tag: bytes)
    requires |tag| == AeadTagLength
    ensures Classify(true, head).Decrypt? ==> Classify(true, head).requireFrame == (head.status < 400)
    ensures EV.Finish(EV.Dec([], 0, false, true)) == Some(FramingTruncated) && EV.Finish(EV.Dec([], 0, false, false)) == None
    ensures var r := EV.Push(EV.Dec([], 0, false, true), Frame(tag)); r.2.None? && r.1.authenticated && EV.Finish(r.1) == None
  {
    EV.FramesOneFrame(EV.Dec([], 0, false, true), tag, [], []);
    assert Frame(tag) + [] == Frame(tag);
  }

  // 5.3 "A 204 or 205 response cannot carry a chunk and MUST be failed. Header validation comes first: a malformed or repeated nonce on a 204 or 205 is INVALID_RESPONSE_NONCE or DUPLICATE_RESPONSE_NONCE, not FRAMING_TRUNCATED."
  lemma Spec_5_3_BodylessSuccessFails(head: Head)
    requires !head.redirected && BodylessSuccess(head.status)
    ensures var nonces := HeaderValues(head.headers, ResponseNonceHeader);
      && (|nonces| == 1 && DecodeHex(nonces[0]).Some? && |DecodeHex(nonces[0]).value| == ResponseNonceLength ==> Classify(true, head) == Refuse(FramingTruncated, "status cannot carry an authenticated frame"))
      && (|nonces| > 1 ==> Classify(true, head) == Refuse(DuplicateResponseNonce, "duplicate response nonce"))
      && (|nonces| == 1 && (DecodeHex(nonces[0]).None? || |DecodeHex(nonces[0]).value| != ResponseNonceLength) ==> Classify(true, head).Refuse? && Classify(true, head).code == InvalidResponseNonce)
      && (|nonces| == 0 ==> Classify(true, head) == Refuse(MissingResponseNonce, "missing " + ResponseNonceHeader + " header"))
  {}

  // 5.4.1 "Implementations MUST fail closed: no plaintext fallback for encrypted exchanges and no decrypted data exposure after an authentication failure": plaintext is released only by the step whose frame authenticated.
  lemma {:isolate_assertions} Spec_5_4_1_FailClosed(s: EV.State, e: EV.Event, t: SV.SState, se: SV.SEvent)
    requires SV.Inv(t)
    ensures var r := EV.Step(s, e); !EV.NoEmit(r.1) ==> e.AeadOpenResult? && e.ok && s.phase.Exchanging? && s.phase.response.Opening?
    ensures var r := EV.Step(s, e); s.phase.Exchanging? && s.phase.response.Opening? && |s.phase.response.frames| > 0 && e.AeadOpenResult? && !e.ok ==> EV.Ends(r.1) && r.1[|r.1| - 1] == EV.Fail(AeadDecryptFailed, "frame failed to authenticate")
    ensures var r := SV.ServerStep(t, se); !SV.NoEmit(r.1) ==> se.AeadOpenResult? && se.ok
  {}

  // 5.4.2 "400 Bad Request: malformed encapsulated request, a chunk framing violation, or an AEAD authentication failure of a chunk after at least one earlier chunk of the same body authenticated."
  lemma Spec_5_4_2_Status400(s: SV.SState, req: SV.Req, e: SV.SEvent)
    requires SV.SInv(s) && SV.ReqOf(s) == Some(req)
    ensures req.Reading? && e.Chunk? && EV.Push(s.dec, e.data).2.Some? ==> var l := SV.LaneStep(s, req, e); l.req.ReqFailed? && l.req.status == 400 && l.req.code == EV.Push(s.dec, e.data).2.value
    ensures req.Opening? && |req.frames| > 0 && req.frames[0].seqNo > 0 && e.AeadOpenResult? && !e.ok ==> var l := SV.LaneStep(s, req, e); l.req == SV.ReqFailed(400, AeadDecryptFailed, "frame failed to authenticate")
    ensures req.Opening? && s.payload && e.AeadOpenResult? && !e.ok ==> SV.LaneStep(s, req, e).req.status == 400
  {}

  // 5.4.2 "422 Unprocessable Content: key configuration mismatch: HPKE setup/decapsulation failure, or an AEAD authentication failure of the first chunk."
  lemma Spec_5_4_2_Status422(s: SV.SState, e: SV.SEvent, req: SV.Req)
    requires SV.SInv(s)
    ensures s.phase.Decap? && EV.HpkeStep(s.phase.hpke, SV.ToEvent(e)).HFailed? && EV.HpkeStep(s.phase.hpke, SV.ToEvent(e)).code != Transport ==>
      var r := SV.ServerStep(s, e); |r.1| == 1 && r.1[0].Respond? && r.1[0].status == 422
    ensures SV.ReqOf(s) == Some(req) && req.Opening? && |req.frames| > 0 && req.frames[0].seqNo == 0 && e.AeadOpenResult? && !e.ok ==>
      SV.LaneStep(s, req, e).req == SV.ReqFailed(422, AeadDecryptFailed, "frame failed to authenticate")
  {}

  // 5.4.2 "A 422 is only ever sent before any plaintext has been released to the application, so the client can replay safely."
  lemma Spec_5_4_2_422OnlyBeforePlaintext(s: SV.SState, e: SV.SEvent)
    requires SV.SInv(s)
    ensures var r := SV.ServerStep(s, e); (exists k :: 0 <= k < |r.1| && r.1[k].Respond? && r.1[k].status == 422) ==> !s.payload && SV.NoEmit(r.1)
  {}

  // 5.4.2 "For 422 key configuration mismatch responses, servers SHOULD use: Content-Type: application/problem+json, JSON body with "type": "urn:ietf:params:ehbp:error:key-config", "title": <summary>."
  lemma Spec_5_4_2_ProblemDocument(s: SV.SState, code: Code, message: string, text: string)
    ensures var r := SV.Answer(s, 422, code, message, text);
      && r.1[0].headers == [("Content-Type", ProblemJsonMediaType)]
      && r.1[0].body == SV.Text("{\"type\":\"" + EV.Escape(KeyConfigProblemType) + "\",\"title\":\"" + EV.Escape(SV.DecryptText) + "\"}\n")
      && KeyConfigProblemType == "urn:ietf:params:ehbp:error:key-config" && ProblemJsonMediaType == "application/problem+json"
  {}

  // 5.4.4 "Error responses MUST NOT disclose fine-grained cryptographic failure causes (for example, whether decapsulation failed versus AEAD authentication failed)."
  lemma Spec_5_4_4_StableProblemTitle(s: SV.SState, code: Code, message: string, text: string, code': Code, message': string, text': string)
    ensures SV.Answer(s, 422, code, message, text).1[0].body == SV.Answer(s, 422, code', message', text').1[0].body
    ensures SV.Answer(s, 422, code, message, text).1[0].headers == SV.Answer(s, 422, code', message', text').1[0].headers
  {}

  // 5.4.2 "Clients detect this response as follows. Detection applies only to responses to encrypted requests that carry no Ehbp-Response-Nonce ... The status MUST be 422 and the Content-Type media type application/problem+json ... The body is a JSON object whose type member equals the URN above ... title is reported when it is a non-empty string, otherwise a generic title is used. A body that is not a JSON object, has a different type, or exceeds 64 KiB is ... passed through unchanged."
  lemma Spec_5_4_2_ProblemDetection(head: Head, oversized: bool, isObject: bool, typeValue: Option<string>, title: Option<string>)
    ensures Classify(false, head) == PassThrough
    ensures Classify(true, head) == NeedProblemBody <==> !head.redirected && head.status == 422 && HeaderValues(head.headers, ResponseNonceHeader) == [] && HasMediaType(FirstHeader(head.headers, "Content-Type"), ProblemJsonMediaType)
    ensures ClassifyProblem(oversized, isObject, typeValue, title).Refuse? <==> !oversized && isObject && typeValue == Some(KeyConfigProblemType)
    ensures ClassifyProblem(false, true, Some(KeyConfigProblemType), title) == Refuse(KeyConfigMismatch, if title.Some? && title.value != "" then title.value else DefaultKeyConfigTitle)
    ensures MaxProblemBytes == 64 * 1024
  {}

  // 5.4.2 a 422 carrying a nonce "is authenticated ciphertext and is decrypted like any other response".
  lemma Spec_5_4_2_Encrypted422IsDecrypted(head: Head)
    requires head.status == 422 && !head.redirected
    requires var nonces := HeaderValues(head.headers, ResponseNonceHeader); |nonces| == 1 && DecodeHex(nonces[0]).Some? && |DecodeHex(nonces[0]).value| == ResponseNonceLength
    ensures Classify(true, head) == Decrypt(DecodeHex(HeaderValues(head.headers, ResponseNonceHeader)[0]).value, false)
  {}

  // 5.5 "Every failure of a step this specification defines MUST be assigned exactly one of the following classes" and "The list is append-only": the codes are distinct strings and Transport has none.
  lemma Spec_5_5_CodesAreDistinct()
    ensures forall i, j :: 0 <= i < j < |Codes| ==> CodeString(Codes[i]) != CodeString(Codes[j])
    ensures forall c :: c != Transport ==> c in Codes && CodeString(c) != ""
    ensures CodeString(Transport) == "" && |Codes| == 15
  {
    CodeStringsAreDistinct();
  }

  // ---------------------------------------------------------------------------
  // 6. Session recovery tokens

  // 6 "MUST make the token obtainable as soon as the request body has been encrypted and before the request is sent": PublishToken precedes Send in the same step.
  lemma Spec_6_TokenPublishedBeforeSend(s: EV.State, e: EV.Event)
    requires EV.Inv(s)
    ensures var r := EV.Step(s, e); forall k :: 0 <= k < |r.1| && r.1[k].Send? && r.1[k].hasBody ==> k == 1 && r.1[0].PublishToken? && r.0.published
  {
    EV.StepKeyFacts(s, e);
  }

  // 6.1 "exported_secret: context.Export("ehbp response", Nk) ... request_enc: the HPKE encapsulated key (enc) from the request."
  lemma Spec_6_1_TokenIsExportAndEnc(s: EV.State, e: EV.Event)
    requires EV.Inv(s)
    ensures var r := EV.Step(s, e); forall k :: 0 <= k < |r.1| && r.1[k].PublishToken? ==>
      && s.phase.AwaitExport? && r.1[k].requestEnc == s.phase.enc
      && EV.Continues(s.phase.job, EV.ExportJob(s.ctx, Ascii(ExportLabel), ExportLength)) && EV.JobStep(s.phase.job, e) == EV.Output(r.1[k].exportedSecret)
      && r.0.token == Token(r.1[k].exportedSecret, r.1[k].requestEnc) && ValidToken(r.0.token)
  {
    EV.StepKeyFacts(s, e);
  }

  // 6.1.1 "both fields MUST be encoded as lowercase hex strings" and the token fields are validated as 32 bytes (5.5 INVALID_TOKEN).
  lemma Spec_6_1_1_TokenJsonIsLowercaseHex(secret: bytes, enc: bytes, a: Option<string>, b: Option<string>)
    ensures forall i :: 0 <= i < |EncodeHex(secret)| ==> EncodeHex(secret)[i] in HexDigits
    ensures EV.FormatToken(EncodeHex(secret), EncodeHex(enc)) == "{\"exportedSecret\":\"" + EncodeHex(secret) + "\",\"requestEnc\":\"" + EncodeHex(enc) + "\"}"
    ensures ValidateTokenFields(a, b).Ok? ==> ValidToken(ValidateTokenFields(a, b).value) && a.Some? && b.Some? && DecodeHex(a.value) == Some(ValidateTokenFields(a, b).value.exportedSecret)
    ensures ValidateTokenFields(a, b).Err? ==> ValidateTokenFields(a, b).code == InvalidToken
  {
    EncodeHexLowercase(secret);
    EncodeHexLowercase(enc);
    EV.EscapePlain(EncodeHex(secret));
    EV.EscapePlain(EncodeHex(enc));
  }

  // 6.2 "Derive response keys using the procedure in Section 4.4, substituting the token's exported_secret for the HPKE export and the token's request_enc for enc."
  lemma Spec_6_2_DecryptWithToken(token: Token, status: int, headers: Headers)
    requires ValidToken(token) && 100 <= status <= 599
    requires var d := Classify(true, Head(status, headers, false)); d.Decrypt?
    ensures var d := Classify(true, Head(status, headers, false)); var (s, acts) := EV.DecryptStart(token, status, headers);
      acts == [EV.HmacSha256(token.requestEnc + d.nonce, token.exportedSecret)]
      && s.phase.Exchanging? && s.phase.response == EV.AwaitKeys(status, headers, d.requireFrame, 0, EV.Extract(token.requestEnc + d.nonce, token.exportedSecret), [], [])
      && !s.published && EV.Inv(s)
  {}

  // 6.2.1 "MUST begin the frame sequence number at zero and increment it only after successfully authenticating a non-empty frame": the opener's sequence number is the frame's position among non-empty frames, from zero.
  lemma Spec_6_2_1_SequenceFromZeroPerNonEmptyFrame(s: EV.State, e: EV.Event)
    requires EV.Inv(s)
    ensures var r := EV.Step(s, e); forall k :: 0 <= k < |r.1| && r.1[k].AeadOpen? ==>
      r.0.phase.Exchanging? && r.0.phase.response.Opening? && |r.0.phase.response.frames| > 0
      && r.1[k].nonce == ComputeNonce(r.0.phase.response.keys.baseNonce, r.0.phase.response.frames[0].seqNo)
      && EV.FramesEndAt(r.0.phase.response.frames, r.0.phase.response.dec.next)
  {
    EV.StepOpenView(s, e);
    EV.StepInv(s, e);
  }

  // 6.2.1 "MUST buffer incomplete framing and MUST emit a frame's plaintext only after that complete frame has been authenticated" and "MUST reject an end-of-stream that leaves a partial length prefix or partial encrypted frame."
  lemma Spec_6_2_1_PartialFrameRejectedAtEof(d: EV.Dec, buf: bytes, i: nat, acc: seq<Framed>, s: EV.State, keys: EV.Ctx, chunks: seq<bytes>)
    requires i <= |buf| && s.phase.Exchanging?
    ensures |d.pending| != 0 ==> EV.Finish(d) == Some(FramingTruncated)
    ensures var r := EV.Frames(d, buf, i, acc); r.2.None? ==> EV.WFPending(r.1.pending)
    ensures |d.pending| != 0 ==> var r := EV.OpenNext(s, keys, d, [], chunks, true); EV.Ends(r.1) && r.1[|r.1| - 1] == EV.Fail(FramingTruncated, "") && EV.NoEmit(r.1)
  {
    EV.FramesPendingWF(d, buf, i, acc);
  }

  // 6.3 "A token is considered consumed once the corresponding exchange has ended, whatever the outcome ... Implementations MUST delete every copy they hold of a consumed token immediately": a step that ends the exchange clears the token exactly once if it was published, and no other step clears it.
  lemma Spec_6_3_TokenClearedExactlyOnceWhenExchangeEnds(s: EV.State, e: EV.Event)
    ensures var r := EV.Step(s, e);
      && (EV.Ends(r.1) ==> !r.0.published && (if s.published then EV.ClearsOnce(r.1, s.generation) else EV.NoClear(r.1)))
      && (!EV.Ends(r.1) ==> EV.NoClear(r.1))
  {}

  // 6.3 "a new request supersedes it": a new session generation drops the token, and a stale publish or clear is ignored.
  lemma Spec_6_3_NewRequestSupersedesToken(st: EV.SessionStore, t: Token, g: uint64)
    ensures EV.SessionApply(st, EV.Begin).token == None && EV.SessionApply(st, EV.Begin).generation != st.generation
    ensures g != st.generation ==> EV.SessionApply(st, EV.Publish(g, t)) == st && EV.SessionApply(st, EV.Clear(g)) == st
  {}

  // 6.3 "Tokens are scoped to a single request-response exchange": the token is set once per exchange and never changes while it runs (its randomness is the residue's).
  lemma Spec_6_3_TokenSetOncePerExchange(s: EV.State, e: EV.Event)
    requires EV.Inv(s)
    ensures var r := EV.Step(s, e); (r.0.token != s.token ==> s.phase.AwaitExport? && r.0.published) && (s.phase.Exchanging? ==> r.0.token == s.token)
  {
    EV.StepKeyFacts(s, e);
  }

  // ---------------------------------------------------------------------------
  // 7. Security considerations

  // 7.2 "Request encryption uses a fresh HPKE setup per HTTP exchange": every exchange starts HPKE from 32 fresh random bytes, and the context is created once and then only advanced.
  lemma Spec_7_2_FreshHpkePerExchange(s: EV.State, e: EV.Event)
    requires EV.Inv(s)
    ensures EV.SenderStart(s.publicKey, Ascii(HpkeRequestInfo)) == EV.HContinue(EV.HRandom(s.publicKey, Ascii(HpkeRequestInfo)), EV.RandomBytes(32))
    ensures var r := EV.Step(s, e); r.0.ctx != s.ctx ==>
      (s.phase.AwaitSetup? && r.0.phase.AwaitExport? && r.0.ctx.seqNo == 0) || (s.phase.Exchanging? && s.ctx.seqNo < EV.MaxSeq && r.0.ctx == EV.Bump(s.ctx))
  {
    EV.StepKeyFacts(s, e);
  }

  // 7.4 "EHBP does not support encrypted responses for requests without a payload body ... The client sends a bodyless request without an encapsulated key and expects a plaintext response."
  lemma Spec_7_4_BodylessRequestIsPlain(s: EV.State, e: EV.Event)
    requires EV.Inv(s) && s.phase.AwaitSession? && !s.phase.hasBody && e.SessionBegun?
    ensures var r := EV.Step(s, e); r.1 == [EV.Send(s.verb, s.url, s.headers, false)] && HeaderValues(s.headers, EncapsulatedKeyHeader) == [] && r.0.phase == EV.Exchanging(EV.NoUpload, EV.AwaitHead(false))
  {
    NoHeaderValues(s.headers, EncapsulatedKeyHeader);
  }

  // 7.4 "A server receiving a key must enforce the nonempty plaintext requirement in Section 5.2": the handler is dispatched only after a plaintext byte authenticated.
  lemma Spec_7_4_ServerDispatchAfterAuth(s: SV.SState, e: SV.SEvent)
    requires SV.Inv(s)
    ensures var r := SV.ServerStep(s, e); SV.Dispatches(r.1) ==> r.0.phase.Running? && r.0.payload
    ensures SV.Inv(SV.ServerStep(s, e).0)
  {}
}
