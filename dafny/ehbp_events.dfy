// EHBP event-driven (sans-I/O) exchange driver.
//
// The exchange as a pure state machine over the rules of ehbp.dfy: the
// residue feeds an Event, Step returns the next State and the Actions to
// perform, and every native result comes back as another Event. Nothing here
// blocks: the residue is a pump loop plus one native binding per action
// (conformance/spec/handler.md, pump.md). HPKE (RFC 9180 base mode), HKDF and JSON live here as well; the
// native surface is five primitives (RandomBytes, X25519, HmacSha256,
// AeadSeal, AeadOpen), one HTTP transaction and the session lock.
//
// Every Event and Action is flat: tags, integers, booleans, byte and string
// sequences (headers are a sequence of string pairs), so the same Step can be
// driven over a C interface (conformance/spec/swift-ffi.md).
include "ehbp.dfy"

module EHBPEvents {
  import opened EHBP

  // ---------------------------------------------------------------------------
  // Events: what the handler tells the driver.

  // The two native byte streams the driver reads: the caller's request body
  // and the server's response body.
  datatype Stream = RequestBody | ResponseBody

  // How a Write leaves the request body: open, ended cleanly, or aborted.
  datatype BodyEnd = More | Done | Aborted(code: Code)

  datatype Event =
    // The caller's request: URL parts for MakeOrigin, headers, whether a body exists.
    | Start(verb: string, url: string, scheme: string, host: string, port: int, hasPort: bool, hasUserinfo: bool, headers: Headers, hasBody: bool)
    | DiscoverStart
    | SessionBegun(generation: uint64)
    | RandomResult(data: bytes)
    | X25519Result(point: bytes)
    | HmacResult(mac: bytes)
    | AeadSealResult(ciphertext: bytes)
    | AeadOpenResult(ok: bool, plaintext: bytes)
    // The result of Send: the head, or StreamFailed(ResponseBody) when the
    // transaction failed before one.
    | ResponseHead(status: int, headers: Headers, redirected: bool)
    // The result of Read(stream): the next bytes, or the stream failed.
    | Chunk(stream: Stream, data: bytes, eof: bool)
    | StreamFailed(stream: Stream)
    // The caller pulls the decrypted body, or releases it.
    | CallerRead
    | CallerClose

  // Actions: what the handler performs, in order. The result of a crypto or
  // I/O action is the Event of the same name; the rest produce no event.
  datatype Action =
    | BeginSession
    | PublishToken(generation: uint64, exportedSecret: bytes, requestEnc: bytes)
    | ClearToken(generation: uint64)
    | RandomBytes(length: nat)
    | X25519(scalar: bytes, point: bytes)
    | HmacSha256(key: bytes, data: bytes)
    | AeadSeal(key: bytes, nonce: bytes, plaintext: bytes)
    | AeadOpen(key: bytes, nonce: bytes, ciphertext: bytes)
    // Start the HTTP transaction. With a body, the actions that follow in the
    // same list belong to the upload: Write feeds it and, by `end`, ends it.
    | Send(verb: string, url: string, headers: Headers, hasBody: bool)
    | Write(data: bytes, end: BodyEnd)
    | Read(stream: Stream)
    | Close(stream: Stream)
    | EmitPlaintext(data: bytes)
    // The native response is handed through as-is after prefix.
    | Passthrough(status: int, headers: Headers, prefix: bytes)
    // A decrypted response begins; plaintext arrives through EmitPlaintext.
    | Done(status: int, headers: Headers)
    | Finished
    | Discovered(publicKey: bytes)
    | Fail(code: Code, message: string)

  predicate Terminal(a: Action) { a.Fail? || a.Finished? || a.Passthrough? || a.Discovered? || a.Close? }
  predicate Ends(acts: seq<Action>) { exists i :: 0 <= i < |acts| && Terminal(acts[i]) }
  predicate NoClear(acts: seq<Action>) { forall i :: 0 <= i < |acts| ==> !acts[i].ClearToken? }
  predicate ClearsOnce(acts: seq<Action>, g: uint64)
  {
    exists i :: 0 <= i < |acts| && acts[i] == ClearToken(g) && forall j :: 0 <= j < |acts| && j != i ==> !acts[j].ClearToken?
  }
  predicate NoEmit(acts: seq<Action>) { forall i :: 0 <= i < |acts| ==> !acts[i].EmitPlaintext? }

  // ---------------------------------------------------------------------------
  // Performing actions. A residue implements Performer with its native
  // bindings (handler.md section 4) and runs the loop of section 5 over
  // Perform, which matches every constructor: a new action fails to compile
  // here instead of being silently ignored by a port.

  // What performing one action yields: an event to feed back, nothing, or
  // the end of this lane (the upload sink is gone).
  datatype Performed = Quiet | Got(e: Event) | Stop

  trait Performer extends object {
    method BeginSession() returns (generation: uint64)
    method PublishToken(generation: uint64, exportedSecret: bytes, requestEnc: bytes)
    method ClearToken(generation: uint64)
    method RandomBytes(length: nat) returns (data: bytes)
    method X25519(scalar: bytes, point: bytes) returns (shared: bytes)
    method HmacSha256(key: bytes, data: bytes) returns (mac: bytes)
    method AeadSeal(key: bytes, nonce: bytes, plaintext: bytes) returns (ciphertext: bytes)
    method AeadOpen(key: bytes, nonce: bytes, ciphertext: bytes) returns (ok: bool, plaintext: bytes)
    // The response head; ok false when the transaction failed before one.
    method Send(verb: string, url: string, headers: Headers, hasBody: bool) returns (ok: bool, status: int, head: Headers, redirected: bool)
    // ok false: the upload sink is gone and this lane ends.
    method Write(data: bytes, end: BodyEnd) returns (ok: bool)
    method Read(stream: Stream) returns (ok: bool, data: bytes, eof: bool)
    method Close(stream: Stream)
    // Plaintext for the caller.
    method EmitPlaintext(data: bytes)
  }

  method Perform(p: Performer, a: Action) returns (r: Performed)
  {
    match a
    case BeginSession =>
      var generation := p.BeginSession();
      return Got(SessionBegun(generation));
    case PublishToken(generation, exportedSecret, requestEnc) =>
      p.PublishToken(generation, exportedSecret, requestEnc);
      return Quiet;
    case ClearToken(generation) =>
      p.ClearToken(generation);
      return Quiet;
    case RandomBytes(length) =>
      var data := p.RandomBytes(length);
      return Got(RandomResult(data));
    case X25519(scalar, point) =>
      var shared := p.X25519(scalar, point);
      return Got(X25519Result(shared));
    case HmacSha256(key, data) =>
      var mac := p.HmacSha256(key, data);
      return Got(HmacResult(mac));
    case AeadSeal(key, nonce, plaintext) =>
      var ciphertext := p.AeadSeal(key, nonce, plaintext);
      return Got(AeadSealResult(ciphertext));
    case AeadOpen(key, nonce, ciphertext) =>
      var ok, plaintext := p.AeadOpen(key, nonce, ciphertext);
      return Got(AeadOpenResult(ok, plaintext));
    case Send(verb, url, headers, hasBody) =>
      var ok, status, head, redirected := p.Send(verb, url, headers, hasBody);
      return Got(if ok then ResponseHead(status, head, redirected) else StreamFailed(ResponseBody));
    case Write(data, end) =>
      var ok := p.Write(data, end);
      return if ok then Quiet else Stop;
    case Read(stream) =>
      var ok, data, eof := p.Read(stream);
      return Got(if ok then Chunk(stream, data, eof) else StreamFailed(stream));
    case Close(stream) =>
      p.Close(stream);
      return Quiet;
    case EmitPlaintext(data) =>
      p.EmitPlaintext(data);
      return Quiet;
    // The terminal actions are the loop's: they settle the exchange's outcome.
    case Passthrough(_, _, _) => return Quiet;
    case Done(_, _) => return Quiet;
    case Finished => return Quiet;
    case Discovered(_) => return Quiet;
    case Fail(_, _) => return Quiet;
  }

  // ---------------------------------------------------------------------------
  // HKDF-SHA256 (RFC 5869) as a job driven by HmacSha256 results.

  datatype Job =
    | JExtract(salt: bytes, ikm: bytes)
    | JExpand(prk: bytes, info: bytes, length: nat, acc: bytes, prev: bytes, i: uint8)

  function Extract(salt: bytes, ikm: bytes): Job { JExtract(salt, ikm) }
  function Expand(prk: bytes, info: bytes, length: nat): Job { JExpand(prk, info, length, [], [], 1) }

  function JobAction(j: Job): Action
  {
    match j
    case JExtract(salt, ikm) => HmacSha256(salt, ikm)
    case JExpand(prk, info, _, _, prev, i) => HmacSha256(prk, prev + info + [i])
  }

  datatype JobOut = Pending(job: Job, action: Action) | Output(data: bytes) | JobFailed(code: Code, message: string)

  function JobStep(j: Job, e: Event): (o: JobOut)
    ensures o.Output? && j.JExpand? ==> |o.data| == j.length
    ensures o.Output? && j.JExtract? ==> |o.data| == HashLength
  {
    if !e.HmacResult? then JobFailed(Transport, "unexpected event")
    else if |e.mac| != HashLength then JobFailed(HpkeSetupFailed, "HMAC returned the wrong length")
    else match j {
      case JExtract(_, _) => Output(e.mac)
      case JExpand(prk, info, length, acc, _, i) =>
        var grown := acc + e.mac;
        if |grown| >= length then Output(grown[..length])
        else if i == 255 then JobFailed(HpkeSetupFailed, "HKDF expand length too large")
        else var next := JExpand(prk, info, length, grown, e.mac, i + 1); Pending(next, JobAction(next))
    }
  }

  // ---------------------------------------------------------------------------
  // HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
  // AES-256-GCM, as a state machine over RandomBytes, X25519 and HmacSha256.

  const HpkeVersion: bytes := Ascii("HPKE-v1")
  const KemSuiteId: bytes := Ascii("KEM") + BE16(KemX25519)
  const HpkeSuiteId: bytes := Ascii("HPKE") + BE16(KemX25519) + BE16(KdfHkdfSha256) + BE16(AeadAes256Gcm)
  // A lambda inside a const crashes Dafny 4.11's verifier, so these go through functions.
  function Repeat(n: nat, v: uint8): bytes { seq(n, i => v) }
  function Iota(n: nat): bytes requires n <= 256 { seq(n, i requires 0 <= i < n => i as uint8) }
  const BasePoint: bytes := [9] + Repeat(31, 0)
  const MaxSeq: uint64 := 0xFFFF_FFFF_FFFF_FFFF

  function LabeledExtract(suite: bytes, salt: bytes, tag: string, ikm: bytes): Job
    requires IsAscii(tag)
  {
    Extract(salt, HpkeVersion + suite + Ascii(tag) + ikm)
  }

  function LabeledExpand(suite: bytes, prk: bytes, tag: string, info: bytes, length: nat): Job
    requires IsAscii(tag) && length < 0x1_0000
  {
    Expand(prk, BE16(length as uint16) + HpkeVersion + suite + Ascii(tag) + info, length)
  }

  type Key = b: bytes | |b| == KeyLength witness seq(32, i => 0)
  type NonceBase = b: bytes | |b| == NonceLength witness seq(12, i => 0)

  // A sender or recipient context: seal/open nonce = baseNonce XOR seq.
  datatype Ctx = Ctx(key: Key, baseNonce: NonceBase, exporterSecret: bytes, seqNo: uint64)

  datatype Hpke =
    | HRandom(pkR: bytes, info: bytes)
    | HEnc(skE: bytes, pkR: bytes, info: bytes)
    | HDh(enc: bytes, pkR: bytes, info: bytes)
    | HSchedule(stage: nat, job: Job, enc: bytes, pkR: bytes, info: bytes, shared: bytes, pskIdHash: bytes, infoHash: bytes, secret: bytes, key: bytes, baseNonce: bytes)

  datatype HpkeOut = HContinue(h: Hpke, action: Action) | HReady(ctx: Ctx, enc: bytes) | HFailed(code: Code, message: string)

  function SenderStart(pkR: bytes, info: bytes): HpkeOut { HContinue(HRandom(pkR, info), RandomBytes(32)) }

  function RecipientStart(skR: bytes, pkR: bytes, enc: bytes, info: bytes): HpkeOut { HContinue(HDh(enc, pkR, info), X25519(skR, enc)) }

  function Schedule(h: Hpke, job: Job): HpkeOut
    requires h.HSchedule?
  {
    HContinue(h.(job := job), JobAction(job))
  }

  function HpkeStep(h: Hpke, e: Event): HpkeOut
  {
    match h {
      case HRandom(pkR, info) =>
        if !e.RandomResult? then HFailed(Transport, "unexpected event")
        else if |e.data| != 32 then HFailed(HpkeSetupFailed, "random bytes have the wrong length")
        else HContinue(HEnc(e.data, pkR, info), X25519(e.data, BasePoint))
      case HEnc(skE, pkR, info) =>
        if !e.X25519Result? then HFailed(Transport, "unexpected event")
        else if |e.point| != 32 then HFailed(HpkeSetupFailed, "X25519 failed")
        else HContinue(HDh(e.point, pkR, info), X25519(skE, pkR))
      case HDh(enc, pkR, info) =>
        if !e.X25519Result? then HFailed(Transport, "unexpected event")
        else if |e.point| != 32 then HFailed(HpkeSetupFailed, "X25519 failed")
        else Schedule(HSchedule(0, Extract([], []), enc, pkR, info, [], [], [], [], [], []), LabeledExtract(KemSuiteId, [], "eae_prk", e.point))
      case HSchedule(stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce) =>
        match JobStep(job, e) {
          case JobFailed(code, message) => HFailed(code, message)
          case Pending(next, action) => HContinue(h.(job := next), action)
          case Output(out) =>
            var ksc := [0] + pskIdHash + infoHash;
            if stage == 0 then Schedule(h.(stage := 1), LabeledExpand(KemSuiteId, out, "shared_secret", enc + pkR, HashLength))
            else if stage == 1 then Schedule(h.(stage := 2, shared := out), LabeledExtract(HpkeSuiteId, [], "psk_id_hash", []))
            else if stage == 2 then Schedule(h.(stage := 3, pskIdHash := out), LabeledExtract(HpkeSuiteId, [], "info_hash", info))
            else if stage == 3 then Schedule(h.(stage := 4, infoHash := out), LabeledExtract(HpkeSuiteId, shared, "secret", []))
            else if stage == 4 then Schedule(h.(stage := 5, secret := out), LabeledExpand(HpkeSuiteId, out, "key", ksc, KeyLength))
            else if stage == 5 then Schedule(h.(stage := 6, key := out), LabeledExpand(HpkeSuiteId, secret, "base_nonce", ksc, NonceLength))
            else if stage == 6 then Schedule(h.(stage := 7, baseNonce := out), LabeledExpand(HpkeSuiteId, secret, "exp", ksc, HashLength))
            else if stage == 7 && |key| == KeyLength && |baseNonce| == NonceLength then
              var k: Key := key;
              var n: NonceBase := baseNonce;
              HReady(Ctx(k, n, out, 0), enc)
            else HFailed(HpkeSetupFailed, "key schedule produced the wrong lengths")
        }
    }
  }

  function SealAction(ctx: Ctx, plaintext: bytes): Action { AeadSeal(ctx.key, ComputeNonce(ctx.baseNonce, ctx.seqNo), plaintext) }
  function OpenAction(ctx: Ctx, ciphertext: bytes): Action { AeadOpen(ctx.key, ComputeNonce(ctx.baseNonce, ctx.seqNo), ciphertext) }
  function Bump(ctx: Ctx): Ctx requires ctx.seqNo < MaxSeq { ctx.(seqNo := ctx.seqNo + 1) }

  function ExportJob(ctx: Ctx, context: bytes, length: nat): Job
    requires length < 0x1_0000
  {
    LabeledExpand(HpkeSuiteId, ctx.exporterSecret, "sec", context, length)
  }

  // ---------------------------------------------------------------------------
  // JSON (RFC 8259): a minimal parser for the two documents the protocol
  // carries. A duplicate member is resolved to its last occurrence, as Go's
  // encoding/json does. Invalid UTF-8 and invalid surrogate escapes decode to
  // U+FFFD, also as Go does. Nesting deeper than MaxJsonDepth is rejected.

  datatype Json = JNull | JBool(b: bool) | JNumber(raw: string) | JString(s: string) | JArray(items: seq<Json>) | JObject(members: seq<(string, Json)>)

  const MaxJsonDepth: nat := 64

  predicate JsonWs(c: char) { c == ' ' || c == '\t' || c == '\n' || c == '\r' }
  predicate IsDigit(c: char) { '0' <= c <= '9' }

  function SkipWs(s: string, i: nat): (j: nat)
    requires i <= |s|
    ensures i <= j <= |s|
    decreases |s| - i
  {
    if i < |s| && JsonWs(s[i]) then SkipWs(s, i + 1) else i
  }

  function Digits(s: string, i: nat): (j: nat)
    requires i <= |s|
    ensures i <= j <= |s|
    decreases |s| - i
  {
    if i < |s| && IsDigit(s[i]) then Digits(s, i + 1) else i
  }

  function Hex4(s: string, i: nat): Option<int>
    requires i <= |s|
    ensures Hex4(s, i).Some? ==> 0 <= Hex4(s, i).value < 0x1_0000
  {
    if i + 4 > |s| then None
    else match (HexDigitValue(s[i]), HexDigitValue(s[i + 1]), HexDigitValue(s[i + 2]), HexDigitValue(s[i + 3])) {
      case (Some(a), Some(b), Some(c), Some(d)) => Some(a as int * 0x1000 + b as int * 0x100 + c as int * 0x10 + d as int)
      case _ => None
    }
  }

  // i is just after the opening quote; returns the string and the index after the closing quote.
  // Decoded characters kept per string. The protocol reads only short strings
  // (a URN, a title, two hex fields); longer ones are truncated so a hostile
  // document cannot make the parser copy quadratically in any runtime.
  const MaxJsonStringChars: nat := 1024

  function Keep(acc: string, add: string): string
    ensures |Keep(acc, add)| <= Max(|acc|, MaxJsonStringChars)
  {
    if |acc| >= MaxJsonStringChars then acc
    else if |acc| + |add| <= MaxJsonStringChars then acc + add
    else acc + add[.. MaxJsonStringChars - |acc|]
  }

  function Max(a: nat, b: nat): nat { if a >= b then a else b }

  // The end of a run of unescaped characters: the index of the next quote,
  // backslash, control character, or the end of input.
  function LiteralEnd(s: string, i: nat): (j: nat)
    requires i <= |s|
    ensures i <= j <= |s|
    decreases |s| - i
  {
    if i == |s| || s[i] == '"' || s[i] == '\\' || s[i] as int < 0x20 then i else LiteralEnd(s, i + 1)
  }

  function ParseString(s: string, i: nat, acc: string): (r: Option<(string, nat)>)
    requires i <= |s|
    ensures r.Some? ==> i < r.value.1 <= |s|
    decreases |s| - i
  {
    var j := LiteralEnd(s, i);
    var run := Keep(acc, s[i .. j]);
    if j == |s| then None
    else if s[j] == '"' then Some((run, j + 1))
    else if s[j] as int < 0x20 then None
    else if j + 1 == |s| then None
    else
      var c := s[j + 1];
      if c == '"' || c == '\\' || c == '/' then ParseString(s, j + 2, Keep(run, [c]))
      else if c == 'b' then ParseString(s, j + 2, Keep(run, [8 as char]))
      else if c == 'f' then ParseString(s, j + 2, Keep(run, [12 as char]))
      else if c == 'n' then ParseString(s, j + 2, Keep(run, ['\n']))
      else if c == 'r' then ParseString(s, j + 2, Keep(run, ['\r']))
      else if c == 't' then ParseString(s, j + 2, Keep(run, ['\t']))
      else if c != 'u' then None
      else match Hex4(s, j + 2) {
        case None => None
        case Some(cp) =>
          if 0xD800 <= cp <= 0xDBFF then
            var lo := if j + 8 <= |s| && s[j + 6] == '\\' && s[j + 7] == 'u' then Hex4(s, j + 8) else None;
            if lo.Some? && 0xDC00 <= lo.value <= 0xDFFF then
              ParseString(s, j + 12, Keep(run, [(0x10000 + (cp - 0xD800) * 0x400 + (lo.value - 0xDC00)) as char]))
            else ParseString(s, j + 6, Keep(run, [0xFFFD as char]))
          else if 0xDC00 <= cp <= 0xDFFF then ParseString(s, j + 6, Keep(run, [0xFFFD as char]))
          else ParseString(s, j + 6, Keep(run, [cp as char]))
      }
  }

  function Frac(s: string, i: nat): (r: Option<nat>)
    requires i <= |s|
    ensures r.Some? ==> i <= r.value <= |s|
  {
    if i < |s| && s[i] == '.' then (if i + 1 < |s| && IsDigit(s[i + 1]) then Some(Digits(s, i + 1)) else None)
    else Some(i)
  }

  function Exponent(s: string, i: nat): (r: Option<nat>)
    requires i <= |s|
    ensures r.Some? ==> i <= r.value <= |s|
  {
    if i < |s| && (s[i] == 'e' || s[i] == 'E') then
      var j := if i + 1 < |s| && (s[i + 1] == '+' || s[i + 1] == '-') then i + 2 else i + 1;
      if j < |s| && IsDigit(s[j]) then Some(Digits(s, j)) else None
    else Some(i)
  }

  function ParseNumber(s: string, i: nat): (r: Option<(Json, nat)>)
    requires i <= |s|
    ensures r.Some? ==> i < r.value.1 <= |s|
  {
    var j := if i < |s| && s[i] == '-' then i + 1 else i;
    if j == |s| then None
    else
      var k := if s[j] == '0' then Some(j + 1) else if IsDigit(s[j]) then Some(Digits(s, j + 1)) else None;
      if k.None? then None
      else match Frac(s, k.value) {
        case None => None
        case Some(f) =>
          match Exponent(s, f) {
            case None => None
            case Some(end) => Some((JNumber(s[i .. end]), end))
          }
      }
  }

  function Literal(s: string, i: nat, word: string, value: Json): (r: Option<(Json, nat)>)
    requires i <= |s| && |word| > 0
    ensures r.Some? ==> i < r.value.1 <= |s|
  {
    if i + |word| <= |s| && s[i .. i + |word|] == word then Some((value, i + |word|)) else None
  }

  // The value at i (no leading whitespace) and the index after it.
  function ParseValue(s: string, i: nat, depth: nat): (r: Option<(Json, nat)>)
    requires i <= |s|
    ensures r.Some? ==> i < r.value.1 <= |s|
    decreases |s| - i, 0
  {
    if i == |s| then None
    else if (s[i] == '{' || s[i] == '[') && depth >= MaxJsonDepth then None
    else if s[i] == '{' then ParseMembers(s, SkipWs(s, i + 1), depth + 1, [], true)
    else if s[i] == '[' then ParseItems(s, SkipWs(s, i + 1), depth + 1, [], true)
    else if s[i] == '"' then
      match ParseString(s, i + 1, []) { case None => None case Some((str, j)) => Some((JString(str), j)) }
    else if s[i] == 't' then Literal(s, i, "true", JBool(true))
    else if s[i] == 'f' then Literal(s, i, "false", JBool(false))
    else if s[i] == 'n' then Literal(s, i, "null", JNull)
    else ParseNumber(s, i)
  }

  function ItemsFrom(s: string, i: nat, depth: nat, acc: seq<Json>, first: bool): (r: Option<(Json, nat)>)
    requires i <= |s|
    ensures r.Some? ==> i < r.value.1 <= |s|
    decreases |s| - i, 1
  {
    if i == |s| then None
    else if first && s[i] == ']' then Some((JArray(acc), i + 1))
    else match ParseValue(s, i, depth) {
      case None => None
      case Some((v, k)) =>
        var m := SkipWs(s, k);
        if m == |s| then None
        else if s[m] == ',' then ItemsFrom(s, SkipWs(s, m + 1), depth, acc + [v], false)
        else if s[m] == ']' then Some((JArray(acc + [v]), m + 1))
        else None
    }
  }

  // Compiled as a loop over the items (the recursion above is the spec): one
  // frame per item or per byte overflowed small stacks on a 64 KiB body.
  function ParseItems(s: string, i: nat, depth: nat, acc: seq<Json>, first: bool): (r: Option<(Json, nat)>)
    requires i <= |s|
    ensures r.Some? ==> i < r.value.1 <= |s|
    decreases |s| - i, 2
  {
    ItemsFrom(s, i, depth, acc, first)
  }
  by method {
    var a := new Json[0](_ => JNull);
    var n, j, f := 0, i, first;
    assert acc + a[..0] == acc;
    while true
      invariant fresh(a) && i <= j <= |s| && n <= a.Length
      invariant ItemsFrom(s, i, depth, acc, first) == ItemsFrom(s, j, depth, acc + a[..n], f)
      decreases |s| - j
    {
      if j == |s| { return None; }
      if f && s[j] == ']' { return Some((JArray(acc + a[..n]), j + 1)); }
      var r := ParseValue(s, j, depth);
      if r.None? { return None; }
      var (v, k) := r.value;
      var m := SkipWs(s, k);
      if m == |s| { return None; }
      if s[m] == ']' { return Some((JArray(acc + a[..n] + [v]), m + 1)); }
      if s[m] != ',' { return None; }
      ghost var pre := acc + a[..n];
      a := Append(a, n, v);
      assert acc + a[..n + 1] == pre + [v];
      n, j, f := n + 1, SkipWs(s, m + 1), false;
    }
  }

  function MembersFrom(s: string, i: nat, depth: nat, acc: seq<(string, Json)>, first: bool): (r: Option<(Json, nat)>)
    requires i <= |s|
    ensures r.Some? ==> i < r.value.1 <= |s|
    decreases |s| - i, 1
  {
    if i == |s| then None
    else if first && s[i] == '}' then Some((JObject(acc), i + 1))
    else if s[i] != '"' then None
    else match ParseString(s, i + 1, []) {
      case None => None
      case Some((name, k)) =>
        var c := SkipWs(s, k);
        if c == |s| || s[c] != ':' then None
        else match ParseValue(s, SkipWs(s, c + 1), depth) {
          case None => None
          case Some((v, k2)) =>
            var m := SkipWs(s, k2);
            if m == |s| then None
            else if s[m] == ',' then MembersFrom(s, SkipWs(s, m + 1), depth, acc + [(name, v)], false)
            else if s[m] == '}' then Some((JObject(acc + [(name, v)]), m + 1))
            else None
        }
    }
  }

  function ParseMembers(s: string, i: nat, depth: nat, acc: seq<(string, Json)>, first: bool): (r: Option<(Json, nat)>)
    requires i <= |s|
    ensures r.Some? ==> i < r.value.1 <= |s|
    decreases |s| - i, 2
  {
    MembersFrom(s, i, depth, acc, first)
  }
  by method {
    var a := new (string, Json)[0](_ => ("", JNull));
    var n, j, f := 0, i, first;
    assert acc + a[..0] == acc;
    while true
      invariant fresh(a) && i <= j <= |s| && n <= a.Length
      invariant MembersFrom(s, i, depth, acc, first) == MembersFrom(s, j, depth, acc + a[..n], f)
      decreases |s| - j
    {
      if j == |s| { return None; }
      if f && s[j] == '}' { return Some((JObject(acc + a[..n]), j + 1)); }
      if s[j] != '"' { return None; }
      var rn := ParseString(s, j + 1, []);
      if rn.None? { return None; }
      var (name, k) := rn.value;
      var c := SkipWs(s, k);
      if c == |s| || s[c] != ':' { return None; }
      var r := ParseValue(s, SkipWs(s, c + 1), depth);
      if r.None? { return None; }
      var (v, k2) := r.value;
      var m := SkipWs(s, k2);
      if m == |s| { return None; }
      if s[m] == '}' { return Some((JObject(acc + a[..n] + [(name, v)]), m + 1)); }
      if s[m] != ',' { return None; }
      ghost var pre := acc + a[..n];
      a := Append(a, n, (name, v));
      assert acc + a[..n + 1] == pre + [(name, v)];
      n, j, f := n + 1, SkipWs(s, m + 1), false;
    }
  }

  // Appends v at a[n], growing into a fresh array when full. The parser fills
  // arrays this way (and the UTF-8 decoder below) because `acc + [v]` once per
  // item builds a chain of lazy concatenations in some runtimes, which are
  // flattened and freed by recursion per link: a 64 KiB body overflowed a 4 MiB stack.
  method Append<T>(a: array<T>, n: nat, v: T) returns (b: array<T>)
    requires n <= a.Length
    modifies a
    ensures n < b.Length && b[..n + 1] == old(a[..n]) + [v]
    ensures b == a || fresh(b)
  {
    if n < a.Length {
      a[n] := v;
      return a;
    }
    b := new T[2 * n + 1](k reads a => if 0 <= k < n then a[k] else v);
  }

  // The whole text must be one value surrounded by whitespace only.
  function ParseJson(s: string): Option<Json>
  {
    match ParseValue(s, SkipWs(s, 0), 0) {
      case None => None
      case Some((v, j)) => if SkipWs(s, j) == |s| then Some(v) else None
    }
  }

  // The last member with this name wins.
  function Member(members: seq<(string, Json)>, name: string): Option<Json> { MemberFrom(members, |members|, name) }

  function MemberFrom(members: seq<(string, Json)>, n: nat, name: string): Option<Json>
    requires n <= |members|
  {
    if n == 0 then None
    else if members[n - 1].0 == name then Some(members[n - 1].1)
    else MemberFrom(members, n - 1, name)
  }

  function StringMember(members: seq<(string, Json)>, name: string): Option<string>
  {
    match Member(members, name) { case Some(JString(v)) => Some(v) case _ => None }
  }

  // Lenient UTF-8: an invalid byte decodes to U+FFFD and is skipped.
  predicate Cont(b: uint8) { 0x80 <= b <= 0xBF }

  function Utf8From(b: bytes, i: nat, acc: string): string
    requires i <= |b|
    decreases |b| - i
  {
    if i == |b| then acc
    else
      var c := b[i];
      if c < 0x80 then Utf8From(b, i + 1, acc + [c as char])
      else if 0xC2 <= c <= 0xDF && i + 2 <= |b| && Cont(b[i + 1]) then
        Utf8From(b, i + 2, acc + [((c as int - 0xC0) * 0x40 + (b[i + 1] as int - 0x80)) as char])
      else if 0xE0 <= c <= 0xEF && i + 3 <= |b| && Cont(b[i + 1]) && Cont(b[i + 2]) then
        var cp := (c as int - 0xE0) * 0x1000 + (b[i + 1] as int - 0x80) * 0x40 + (b[i + 2] as int - 0x80);
        if cp < 0x800 || (0xD800 <= cp <= 0xDFFF) then Utf8From(b, i + 1, acc + [0xFFFD as char])
        else Utf8From(b, i + 3, acc + [cp as char])
      else if 0xF0 <= c <= 0xF4 && i + 4 <= |b| && Cont(b[i + 1]) && Cont(b[i + 2]) && Cont(b[i + 3]) then
        var cp := (c as int - 0xF0) * 0x40000 + (b[i + 1] as int - 0x80) * 0x1000 + (b[i + 2] as int - 0x80) * 0x40 + (b[i + 3] as int - 0x80);
        if cp < 0x10000 || cp > 0x10FFFF then Utf8From(b, i + 1, acc + [0xFFFD as char])
        else Utf8From(b, i + 4, acc + [cp as char])
      else Utf8From(b, i + 1, acc + [0xFFFD as char])
  }

  function Utf8(b: bytes): string { Utf8From(b, 0, []) }
  by method {
    var a := new char[|b|](_ => ' ');
    var i, n := 0, 0;
    while i < |b|
      invariant i <= |b| && n <= i
      invariant Utf8From(b, 0, []) == Utf8From(b, i, a[..n])
    {
      var c := b[i];
      var cp, w := 0xFFFD, 1;
      if c < 0x80 {
        cp := c as int;
      } else if 0xC2 <= c <= 0xDF && i + 2 <= |b| && Cont(b[i + 1]) {
        cp, w := (c as int - 0xC0) * 0x40 + (b[i + 1] as int - 0x80), 2;
      } else if 0xE0 <= c <= 0xEF && i + 3 <= |b| && Cont(b[i + 1]) && Cont(b[i + 2]) {
        var v := (c as int - 0xE0) * 0x1000 + (b[i + 1] as int - 0x80) * 0x40 + (b[i + 2] as int - 0x80);
        if !(v < 0x800 || (0xD800 <= v <= 0xDFFF)) { cp, w := v, 3; }
      } else if 0xF0 <= c <= 0xF4 && i + 4 <= |b| && Cont(b[i + 1]) && Cont(b[i + 2]) && Cont(b[i + 3]) {
        var v := (c as int - 0xF0) * 0x40000 + (b[i + 1] as int - 0x80) * 0x1000 + (b[i + 2] as int - 0x80) * 0x40 + (b[i + 3] as int - 0x80);
        if !(v < 0x10000 || v > 0x10FFFF) { cp, w := v, 4; }
      }
      ghost var pre := a[..n];
      a[n] := cp as char;
      assert a[..n + 1] == pre + [cp as char];
      i, n := i + w, n + 1;
    }
    return a[..n];
  }

  // SPEC 5.4.2: the problem document; isObject is false for anything that is
  // not a JSON object (including null, arrays and malformed text).
  function ParseProblem(body: bytes): (bool, Option<string>, Option<string>)
  {
    match ParseJson(Utf8(body)) {
      case Some(JObject(members)) => (true, StringMember(members, "type"), StringMember(members, "title"))
      case _ => (false, None, None)
    }
  }

  // SPEC 6.1.1: the two string members of a token document.
  function ParseToken(json: string): (Option<string>, Option<string>)
  {
    match ParseJson(json) {
      case Some(JObject(members)) => (StringMember(members, "exportedSecret"), StringMember(members, "requestEnc"))
      case _ => (None, None)
    }
  }

  function Escape(s: string): string
  {
    if |s| == 0 then []
    else
      var c := s[0];
      (if c == '"' then "\\\"" else if c == '\\' then "\\\\"
       else if c as int < 0x20 then "\\u00" + [HexDigits[c as int / 16], HexDigits[c as int % 16]]
       else [c]) + Escape(s[1..])
  }

  function FormatToken(exportedSecretHex: string, requestEncHex: string): string
  {
    "{\"exportedSecret\":\"" + Escape(exportedSecretHex) + "\",\"requestEnc\":\"" + Escape(requestEncHex) + "\"}"
  }

  // ---------------------------------------------------------------------------
  // Session recovery token rules (SPEC 6): the native Session is a mutex
  // around one SessionStore value and applies these transitions verbatim.

  datatype SessionStore = SessionStore(generation: uint64, token: Option<Token>)

  datatype SessionAction = Begin | Publish(generation: uint64, token: Token) | Clear(generation: uint64)

  const NewSession: SessionStore := SessionStore(0, None)

  function SessionApply(store: SessionStore, action: SessionAction): SessionStore
  {
    match action
    case Begin => SessionStore(if store.generation == MaxSeq then 0 else store.generation + 1, None)
    case Publish(generation, token) => if generation == store.generation then store.(token := Some(token)) else store
    case Clear(generation) => if generation == store.generation then store.(token := None) else store
  }

  // ---------------------------------------------------------------------------
  // Pure frame decoder (the value form of EHBP.Decoder). `pending` is the
  // incomplete frame carried from earlier chunks: a chunk is scanned once by
  // offset, and only the frame straddling two chunks is ever concatenated, so
  // the work and the copies are linear in the chunk whatever its size.

  datatype Dec = Dec(pending: bytes, next: uint64, authenticated: bool, requireFrame: bool)

  // The frames complete in buf from i on; what is left becomes pending.
  function Frames(d: Dec, buf: bytes, i: nat, acc: seq<Framed>): (seq<Framed>, Dec, Option<Code>)
    requires i <= |buf|
    decreases |buf| - i
  {
    if |buf| - i < 4 then (acc, d.(pending := buf[i..]), None)
    else
      var length := U32(buf, i);
      if length == 0 then Frames(d, buf, i + 4, acc)
      else if length > MaxChunkBytes then (acc, d, Some(ChunkTooLarge))
      else if |buf| - i < 4 + length as nat then (acc, d.(pending := buf[i..]), None)
      else if d.next == MaxSeq then (acc, d, Some(SequenceOverflow))
      else Frames(Dec([], d.next + 1, true, d.requireFrame), buf, i + 4 + length as nat, acc + [Framed(d.next, buf[i + 4 .. i + 4 + length as nat])])
  }

  // How many more bytes an incomplete frame needs: the rest of its length
  // prefix, then the rest of its body. Never zero, so Push makes progress.
  function FrameNeed(pending: bytes): (n: nat)
    ensures n >= 1
  {
    if |pending| < 4 then 4 - |pending|
    else var whole := 4 + U32(pending, 0) as nat; if whole > |pending| then whole - |pending| else 1
  }

  function Push(d: Dec, data: bytes): (seq<Framed>, Dec, Option<Code>) { PushFrom(d, data, 0, []) }

  function PushFrom(d: Dec, data: bytes, i: nat, acc: seq<Framed>): (seq<Framed>, Dec, Option<Code>)
    requires i <= |data|
    decreases |data| - i
  {
    if |d.pending| == 0 then Frames(d, data, i, acc)
    else if i == |data| then (acc, d, None)
    else
      var take := Min(|data| - i, FrameNeed(d.pending));
      var (frames, next, err) := Frames(d, d.pending + data[i .. i + take], 0, acc);
      if err.Some? then (frames, next, err) else PushFrom(next, data, i + take, frames)
  }

  function Finish(d: Dec): Option<Code>
  {
    if |d.pending| != 0 || (d.requireFrame && !d.authenticated) then Some(FramingTruncated) else None
  }

  // ---------------------------------------------------------------------------
  // Driver state. After Send with a body, the upload and the response are two
  // independent lanes: the response may arrive while the body is still going out.

  // A chunk the residue read. The compiled runtimes index sequences with 32
  // bits, so a longer one is refused on arrival; this keeps the per-frame
  // offsets fixed-width.
  type Chunk = b: bytes | |b| < 0x1_0000_0000 witness []
  const MaxReadBytes: nat := 0xFFFF_FFFF

  datatype Upload =
    | NoUpload
    // One caller chunk being sealed frame by frame from `offset`; each frame is
    // written as it is sealed, so memory is one chunk plus one frame and the
    // work is linear in the chunk whatever size the residue reads.
    | Sealing(plaintext: Chunk, offset: uint32, eof: bool)
    | UpReading(empty: nat)
    | UpDone

  datatype Response =
    | AwaitHead(encrypted: bool)
    | ProblemReading(status: int, headers: Headers, data: bytes)
    | AwaitKeys(status: int, headers: Headers, requireFrame: bool, stage: nat, job: Job, prk: bytes, key: bytes)
    | Body(keys: Ctx, dec: Dec, done: bool)
    | BodyReading(keys: Ctx, dec: Dec)
    // `chunks`: the plaintext of the frames opened so far, released together.
    | Opening(keys: Ctx, dec: Dec, frames: seq<Framed>, chunks: seq<bytes>, eof: bool)
    | RespEnded

  datatype Phase =
    | Idle
    | AwaitSession(hasBody: bool)
    | Peeking(empty: nat)
    | AwaitSetup(first: Chunk, firstEof: bool, hpke: Hpke)
    | AwaitExport(first: Chunk, firstEof: bool, enc: bytes, job: Job)
    | Exchanging(upload: Upload, response: Response)
    | DiscAwaitHead
    | DiscReading(data: bytes)
    | Ended

  datatype State = State(phase: Phase, origin: Origin, publicKey: bytes, verb: string, url: string, headers: Headers,
    generation: uint64, published: bool, token: Token, ctx: Ctx)

  const NoCtx: Ctx := Ctx(Repeat(32, 0), Repeat(12, 0), [], 0)

  function Initial(origin: Origin, publicKey: bytes): State
  {
    State(Idle, origin, publicKey, "", "", [], 0, false, Token([], []), NoCtx)
  }

  // SPEC 6.2: decrypt a response from a token alone. Feed ResponseHead, then
  // Chunk(ResponseBody) and CallerRead events as for a normal exchange. Nothing is
  // published, so no ClearToken is emitted.
  function ResponseOnly(origin: Origin, token: Token): State
  {
    State(Exchanging(UpDone, AwaitHead(true)), origin, [], "", "", [], 0, false, token, NoCtx)
  }

  const NoOrigin: Origin := Origin("https", "", 443)

  // The two token-based helpers every SDK exposes, as event sequences the pump
  // runs like any exchange: DecryptStart feeds the real response head;
  // DeriveStart feeds a synthetic 200 carrying the nonce and stops at Done,
  // where KeysOf reads the material. Neither publishes a token.
  function DecryptStart(token: Token, status: int, headers: Headers): (State, seq<Action>)
  {
    Step(ResponseOnly(NoOrigin, token), ResponseHead(status, headers, false))
  }

  function DeriveStart(token: Token, responseNonce: bytes): (State, seq<Action>)
  {
    Step(ResponseOnly(NoOrigin, token), ResponseHead(200, [(ResponseNonceHeader, EncodeHex(responseNonce))], false))
  }

  // The derived AES key and nonce base once the driver has emitted Done.
  function KeysOf(s: State): Option<(bytes, bytes)>
  {
    if s.phase.Exchanging? && s.phase.response.Body? then Some((s.phase.response.keys.key, s.phase.response.keys.baseNonce)) else None
  }

  // What every Step guarantees: a terminal action list clears the token
  // exactly once when one was published, and plaintext is released only by
  // the step that authenticated the frame.
  predicate Contract(s: State, e: Event, r: (State, seq<Action>))
  {
    && (Ends(r.1) ==> !r.0.published && (if s.published then ClearsOnce(r.1, s.generation) else NoClear(r.1)))
    && (!Ends(r.1) ==> NoClear(r.1))
    && (!NoEmit(r.1) ==> e.AeadOpenResult? && e.ok && s.phase.Exchanging? && s.phase.response.Opening?)
  }

  predicate Ending(s: State, r: (State, seq<Action>))
  {
    Ends(r.1) && !r.0.published && (if s.published then ClearsOnce(r.1, s.generation) else NoClear(r.1)) && NoEmit(r.1)
  }

  // The response lane ends: optionally close the native body, clear the
  // token if one is published, then the terminal action.
  function End(s: State, close: bool, last: Action): (r: (State, seq<Action>))
    requires Terminal(last)
    ensures Ending(s, r)
  {
    var phase := match s.phase case Exchanging(up, _) => Exchanging(up, RespEnded) case _ => Ended;
    var g := s.generation;
    var acts :=
      if close && s.published then [Close(ResponseBody), ClearToken(g), last]
      else if close then [Close(ResponseBody), last]
      else if s.published then [ClearToken(g), last]
      else [last];
    assert acts[|acts| - 1] == last;
    assert s.published ==> acts[|acts| - 2] == ClearToken(g);
    (s.(phase := phase, published := false), acts)
  }

  function Abort(s: State, close: bool, code: Code, message: string): (r: (State, seq<Action>))
    ensures Ending(s, r)
  {
    End(s, close, Fail(code, message))
  }

  function Unexpected(s: State): (r: (State, seq<Action>))
    ensures Ending(s, r)
  {
    Abort(s, false, Transport, "unexpected event")
  }

  function Min(a: nat, b: nat): nat { if a < b then a else b }
  function Min32(a: uint32, b: uint32): uint32 { if a < b then a else b }

  // The next frame's plaintext: n bytes of the chunk from `at`. A chunk no
  // longer than a frame is sealed as it is, without the copy a slice costs in
  // most runtimes.
  function Piece(chunk: Chunk, at: uint32, n: uint32): bytes
    requires at as nat + n as nat <= |chunk|
    ensures Piece(chunk, at, n) == chunk[at .. at + n]
  {
    if at == 0 && n as nat == |chunk| then chunk else chunk[at .. at + n]
  }

  // One frame on the wire (SPEC 4.3): the length prefix and the ciphertext
  // as two writes, so no runtime concatenates them; `end` rides on the last.
  function FrameWrites(ciphertext: bytes, end: BodyEnd): seq<Action>
    requires |ciphertext| < 0x1_0000_0000
  {
    [Write(BE32(|ciphertext| as uint32), More), Write(ciphertext, end)]
  }

  function WithUpload(s: State, up: Upload): State
    requires s.phase.Exchanging?
  {
    s.(phase := Exchanging(up, s.phase.response))
  }

  function WithResponse(s: State, rs: Response): State
    requires s.phase.Exchanging?
  {
    s.(phase := Exchanging(s.phase.upload, rs))
  }

  function SendPlain(s: State): (State, seq<Action>)
  {
    (s.(phase := Exchanging(NoUpload, AwaitHead(false))), [Send(s.verb, s.url, s.headers, false)])
  }

  // The events the upload lane consumes once the exchange is under way.
  predicate ForUpload(e: Event) { ((e.Chunk? || e.StreamFailed?) && e.stream.RequestBody?) || e.AeadSealResult? }

  // Abort the upload only: the response lane goes on.
  function AbortUpload(s: State, code: Code): (State, seq<Action>)
    requires s.phase.Exchanging?
  {
    (WithUpload(s, UpDone), [Write([], Aborted(code))])
  }

  // ---------------------------------------------------------------------------
  // The step function.

  function Step(s: State, e: Event): (r: (State, seq<Action>))
    ensures Contract(s, e, r)
  {
    if e.CallerClose? then End(s, false, Close(ResponseBody))
    else match s.phase {
      case Idle =>
        if e.Start? then StepStart(s, e)
        else if e.DiscoverStart? then (s.(phase := DiscAwaitHead), [Send("GET", OriginUrl(s.origin) + KeysPath, [], false)])
        else Unexpected(s)
      case AwaitSession(hasBody) =>
        if !e.SessionBegun? then Unexpected(s)
        else
          var begun := s.(generation := e.generation);
          if hasBody then (begun.(phase := Peeking(0)), [Read(RequestBody)]) else SendPlain(begun)
      case Peeking(empty) =>
        match e {
          case StreamFailed(RequestBody) => Abort(s, false, Transport, "failed to read request body")
          case Chunk(RequestBody, data, eof) =>
            if |data| > MaxReadBytes then Abort(s, false, Transport, "request body chunk too large")
            else if |data| > 0 then
              match SenderStart(s.publicKey, Ascii(HpkeRequestInfo)) {
                case HContinue(h, a) => (s.(phase := AwaitSetup(data, eof, h)), [a])
                case _ => Unexpected(s)
              }
            else if eof then SendPlain(s)
            else if empty + 1 == MaxEmptyReads then Abort(s, false, Transport, "request body made no progress")
            else (s.(phase := Peeking(empty + 1)), [Read(RequestBody)])
          case _ => Unexpected(s)
        }
      case AwaitSetup(first, firstEof, h) =>
        match HpkeStep(h, e) {
          case HFailed(code, message) => Abort(s, false, code, message)
          case HContinue(next, a) => (s.(phase := AwaitSetup(first, firstEof, next)), [a])
          case HReady(ctx, enc) =>
            var job := ExportJob(ctx, Ascii(ExportLabel), ExportLength);
            (s.(phase := AwaitExport(first, firstEof, enc, job), ctx := ctx), [JobAction(job)])
        }
      case AwaitExport(first, firstEof, enc, job) =>
        match JobStep(job, e) {
          case JobFailed(code, message) => Abort(s, false, code, message)
          case Pending(next, a) => (s.(phase := AwaitExport(first, firstEof, enc, next)), [a])
          case Output(secret) =>
            if |enc| != RequestEncLength then Abort(s, false, HpkeSetupFailed, "HPKE sender setup failed")
            else if |secret| != ExportLength then Abort(s, false, HpkeSetupFailed, "HPKE export failed")
            else
              var token := Token(secret, enc);
              var headers := s.headers + [(EncapsulatedKeyHeader, EncodeHex(enc))];
              (s.(phase := Exchanging(Sealing(first, 0, firstEof), AwaitHead(true)), published := true, token := token),
               [PublishToken(s.generation, secret, enc), Send(s.verb, s.url, headers, true), SealAction(s.ctx, Piece(first, 0, Min32(|first| as uint32, RequestFrameBytes)))])
        }
      case Exchanging(up, rs) =>
        if ForUpload(e) then StepUpload(s, up, e) else StepResponse(s, rs, e)
      case DiscAwaitHead =>
        match e {
          case StreamFailed(ResponseBody) => Abort(s, false, Transport, "failed to get server public key")
          case ResponseHead(status, headers, redirected) =>
            if status < 100 || status > 599 then Abort(s, true, Transport, "failed to get server public key")
            else match ClassifyDiscovery(Head(status, headers, redirected)) {
              case Err(code, message) => Abort(s, true, code, message)
              case Ok(_) => (s.(phase := DiscReading([])), [Read(ResponseBody)])
            }
          case _ => Unexpected(s)
        }
      case DiscReading(data) =>
        match e {
          case StreamFailed(ResponseBody) => Abort(s, true, Transport, "failed to read key configuration")
          case Chunk(ResponseBody, chunk, eof) =>
            var grown := data + chunk;
            if |grown| <= MaxKeyConfigBytes && !eof then (s.(phase := DiscReading(grown)), [Read(ResponseBody)])
            else match ParseConfig(grown) {
              case Ok(pk) => End(s, true, Discovered(pk))
              case Err(code, message) => Abort(s, true, code, message)
            }
          case _ => Unexpected(s)
        }
      case Ended => Unexpected(s)
    }
  }

  // SPEC 5.1 request guards, then a fresh session generation.
  function StepStart(s: State, e: Event): (r: (State, seq<Action>))
    requires e.Start?
    ensures Contract(s, e, r)
  {
    var target := MakeOrigin(e.scheme, e.host, if e.hasPort then Some(e.port) else None, e.hasUserinfo);
    match ValidateRequest(s.origin, target, e.headers) {
      case Err(code, message) => Abort(s, false, code, message)
      case Ok(_) =>
        (s.(phase := AwaitSession(e.hasBody), verb := e.verb, url := e.url, headers := DropFraming(e.headers)), [BeginSession])
    }
  }

  // The upload lane: EncryptingSource.Read, one frame per RequestFrameBytes.
  // An unexpected event here aborts the body, not the exchange.
  function StepUpload(s: State, up: Upload, e: Event): (r: (State, seq<Action>))
    requires s.phase.Exchanging? && up == s.phase.upload
    ensures Contract(s, e, r)
  {
    match up {
      case Sealing(plaintext, offset, eof) =>
        var size := |plaintext| as uint32;
        var at := Min32(offset, size);
        var n := Min32(size - at, RequestFrameBytes);
        if !e.AeadSealResult? then AbortUpload(s, Transport)
        else if |e.ciphertext| != n as nat + AeadTagLength then AbortUpload(s, HpkeSetupFailed)
        else if s.ctx.seqNo == MaxSeq then AbortUpload(s, SequenceOverflow)
        else
          var bumped := s.(ctx := Bump(s.ctx));
          var next := at + n;
          if next < size then
            (WithUpload(bumped, Sealing(plaintext, next, eof)),
             FrameWrites(e.ciphertext, More) + [SealAction(bumped.ctx, Piece(plaintext, next, Min32(size - next, RequestFrameBytes)))])
          else if eof then (WithUpload(bumped, UpDone), FrameWrites(e.ciphertext, BodyEnd.Done))
          else (WithUpload(bumped, UpReading(0)), FrameWrites(e.ciphertext, More) + [Read(RequestBody)])
      case UpReading(empty) =>
        match e {
          case StreamFailed(RequestBody) => AbortUpload(s, Transport)
          case Chunk(RequestBody, data, eof) =>
            if |data| > MaxReadBytes then AbortUpload(s, Transport)
            else if |data| > 0 then (WithUpload(s, Sealing(data, 0, eof)), [SealAction(s.ctx, Piece(data, 0, Min32(|data| as uint32, RequestFrameBytes)))])
            else if eof then (WithUpload(s, UpDone), [Write([], BodyEnd.Done)])
            else if empty + 1 == MaxEmptyReads then AbortUpload(s, Transport)
            else (WithUpload(s, UpReading(empty + 1)), [Read(RequestBody)])
          case _ => AbortUpload(s, Transport)
        }
      case _ => AbortUpload(s, Transport)
    }
  }

  // The response lane: Client.Open, DeriveResponseKeys and DecryptingSource.
  function StepResponse(s: State, rs: Response, e: Event): (r: (State, seq<Action>))
    requires s.phase.Exchanging? && rs == s.phase.response
    ensures Contract(s, e, r)
  {
    match rs {
      case AwaitHead(encrypted) =>
        match e {
          case StreamFailed(ResponseBody) => Abort(s, false, Transport, "failed to make request")
          case ResponseHead(status, headers, redirected) =>
            // A browser's opaque redirect carries status 0: the redirect is the finding, not the status.
            if !redirected && (status < 100 || status > 599) then Abort(s, true, Transport, "transport reported an impossible status")
            else match Classify(encrypted, Head(status, headers, redirected)) {
              case PassThrough => End(s, false, Passthrough(status, headers, []))
              case Refuse(code, message) => Abort(s, true, code, message)
              case NeedProblemBody => (WithResponse(s, ProblemReading(status, headers, [])), [Read(ResponseBody)])
              case Decrypt(nonce, requireFrame) =>
                if !ValidToken(s.token) then Abort(s, true, InvalidInput, "token fields must be 32 bytes")
                else if |nonce| != ResponseNonceLength then Abort(s, true, InvalidInput, "response nonce must be 32 bytes")
                else
                  var job := Extract(s.token.requestEnc + nonce, s.token.exportedSecret);
                  (WithResponse(s, AwaitKeys(status, headers, requireFrame, 0, job, [], [])), [JobAction(job)])
            }
          case _ => Unexpected(s)
        }
      case ProblemReading(status, headers, data) =>
        match e {
          case StreamFailed(ResponseBody) => Abort(s, true, Transport, "failed to read problem response")
          case Chunk(ResponseBody, chunk, eof) =>
            var grown := data + chunk;
            if |grown| <= MaxProblemBytes + 1 && !eof then (WithResponse(s, ProblemReading(status, headers, grown)), [Read(ResponseBody)])
            else
              var oversized := |grown| > MaxProblemBytes;
              var (isObject, typeValue, title) := if oversized then (false, None, None) else ParseProblem(grown);
              match ClassifyProblem(oversized, isObject, typeValue, title) {
                case Refuse(code, message) => Abort(s, true, code, message)
                case PassThrough => End(s, false, Passthrough(status, headers, grown))
                case _ => Abort(s, true, Transport, "unreachable")
              }
          case _ => Unexpected(s)
        }
      case AwaitKeys(status, headers, requireFrame, stage, job, prk, key) =>
        match JobStep(job, e) {
          case JobFailed(code, message) => Abort(s, true, code, message)
          case Pending(next, a) => (WithResponse(s, AwaitKeys(status, headers, requireFrame, stage, next, prk, key)), [a])
          case Output(out) =>
            if stage == 0 then
              var next := Expand(out, Ascii(ResponseKeyLabel), KeyLength);
              (WithResponse(s, AwaitKeys(status, headers, requireFrame, 1, next, out, [])), [JobAction(next)])
            else if stage == 1 then
              var next := Expand(prk, Ascii(ResponseNonceLabel), NonceLength);
              (WithResponse(s, AwaitKeys(status, headers, requireFrame, 2, next, prk, out)), [JobAction(next)])
            else if |key| == KeyLength && |out| == NonceLength then
              var k: Key := key;
              var n: NonceBase := out;
              (WithResponse(s, Body(Ctx(k, n, [], 0), Dec([], 0, false, requireFrame), false)), [Action.Done(status, DropFraming(headers))])
            else Abort(s, true, HpkeSetupFailed, "HKDF expand returned the wrong length")
        }
      case Body(keys, dec, done) =>
        if !e.CallerRead? then Unexpected(s)
        else if done then End(s, false, Finished)
        else (WithResponse(s, BodyReading(keys, dec)), [Read(ResponseBody)])
      case BodyReading(keys, dec) =>
        match e {
          // SPEC 5.5: a transport failure inside the body is a truncation.
          case StreamFailed(ResponseBody) => Abort(s, false, FramingTruncated, "response body failed")
          case Chunk(ResponseBody, data, eof) =>
            var (frames, next, err) := Push(dec, data);
            if err.Some? then Abort(s, false, err.value, "")
            else OpenNext(s, keys, next, frames, [], eof)
          case _ => Unexpected(s)
        }
      case Opening(keys, dec, frames, chunks, eof) =>
        if !e.AeadOpenResult? || |frames| == 0 then Unexpected(s)
        else if !e.ok then Abort(s, false, AeadDecryptFailed, "frame failed to authenticate")
        else if |e.plaintext| + AeadTagLength != |frames[0].ciphertext| then Abort(s, false, AeadDecryptFailed, "AEAD returned the wrong length")
        else OpenNext(s, keys, dec, frames[1..], if |e.plaintext| > 0 then chunks + [e.plaintext] else chunks, eof)
      case RespEnded => Unexpected(s)
    }
  }

  // One EmitPlaintext per opened frame, in order; no concatenation.
  function Emits(chunks: seq<bytes>): (acts: seq<Action>)
    ensures |acts| == |chunks| && forall i :: 0 <= i < |acts| ==> acts[i] == EmitPlaintext(chunks[i])
  {
    seq(|chunks|, i requires 0 <= i < |chunks| => EmitPlaintext(chunks[i]))
  }

  // Open the next frame of the chunk, or release what authenticated. Plaintext
  // is released only once every frame of the chunk has authenticated, as
  // DecryptingSource.Read does; the token is cleared on the read after the last.
  function OpenNext(s: State, keys: Ctx, dec: Dec, frames: seq<Framed>, chunks: seq<bytes>, eof: bool): (r: (State, seq<Action>))
    requires s.phase.Exchanging?
    ensures Ends(r.1) ==> Ending(s, r)
    ensures !Ends(r.1) ==> NoClear(r.1)
    ensures |chunks| == 0 ==> NoEmit(r.1)
  {
    if |frames| > 0 then
      // SPEC 4.3: a complete frame shorter than the tag is an authentication failure.
      if |frames[0].ciphertext| < AeadTagLength then Abort(s, false, AeadDecryptFailed, "frame shorter than the AEAD tag")
      else (WithResponse(s, Opening(keys, dec, frames, chunks, eof)), [AeadOpen(keys.key, ComputeNonce(keys.baseNonce, frames[0].seqNo), frames[0].ciphertext)])
    else if eof then
      match Finish(dec) {
        case Some(code) => Abort(s, false, code, "")
        case None => if |chunks| > 0 then (WithResponse(s, Body(keys, dec, true)), Emits(chunks)) else End(s, false, Finished)
      }
    else if |chunks| > 0 then (WithResponse(s, Body(keys, dec, false)), Emits(chunks))
    else (WithResponse(s, BodyReading(keys, dec)), [Read(ResponseBody)])
  }

  // ---------------------------------------------------------------------------
  // Residue self-check: the five primitives through known-answer vectors. The
  // handler performs SelfCheckActions in order and hands the result events to
  // SelfCheckJudge, which names every failed check.

  function Hex(s: string): bytes { match DecodeHex(s) case Some(b) => b case None => [] }

  const GcmKey: bytes := Iota(32)
  const GcmNonce: bytes := Iota(12)
  const GcmCt: bytes := Hex("226ab46b72d4be2b87fabbe9dbe0bfc2adbce017")
  // RFC 7748 section 6.1.
  const AliceSk: bytes := Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
  const AlicePk: bytes := Hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
  const BobPk: bytes := Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
  const AliceBobShared: bytes := Hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
  // RFC 4231 test case 1.
  const HmacKey: bytes := Repeat(20, 0x0b)
  const HmacTag: bytes := Hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

  const SelfCheckActions: seq<Action> := [
    HmacSha256(HmacKey, Ascii("Hi There")),
    X25519(AliceSk, BasePoint),
    X25519(AliceSk, BobPk),
    AeadSeal(GcmKey, GcmNonce, Ascii("ehbp")),
    AeadOpen(GcmKey, GcmNonce, GcmCt),
    AeadOpen(GcmKey, GcmNonce, GcmCt[.. |GcmCt| - 1] + [((GcmCt[|GcmCt| - 1] as bv8) ^ 1) as uint8]),
    AeadOpen(GcmKey, GcmNonce, GcmCt[.. 8]),
    RandomBytes(32),
    RandomBytes(32)]

  function SelfCheckJudge(results: seq<Event>): seq<string>
  {
    if |results| != |SelfCheckActions| then ["self-check: wrong number of results"]
    else
      (if results[0] != HmacResult(HmacTag) then ["HmacSha256: RFC 4231 test case 1"] else []) +
      (if results[1] != X25519Result(AlicePk) then ["X25519: RFC 7748 base point"] else []) +
      (if results[2] != X25519Result(AliceBobShared) then ["X25519: RFC 7748 shared secret"] else []) +
      (if results[3] != AeadSealResult(GcmCt) then ["AeadSeal: known answer"] else []) +
      (if results[4] != AeadOpenResult(true, Ascii("ehbp")) then ["AeadOpen: known answer"] else []) +
      (if !results[5].AeadOpenResult? || results[5].ok then ["AeadOpen: accepted a tampered tag"] else []) +
      (if !results[6].AeadOpenResult? || results[6].ok then ["AeadOpen: accepted a frame shorter than the tag"] else []) +
      (if !results[7].RandomResult? || !results[8].RandomResult? || |results[7].data| != 32 || |results[8].data| != 32 then ["RandomBytes: length"] else []) +
      (if results[7] == results[8] then ["RandomBytes: repeated output"] else [])
  }

  // ---------------------------------------------------------------------------
  // Reference primitives for the tests only: SHA-256, HMAC and X25519 in
  // Dafny so the RFC 9180 vector can be driven through HpkeStep here. The
  // driver never uses them; the residue's native primitives are the real ones.

  const K256: seq<bv32> := [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
  const H256: seq<bv32> := [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

  function Rotr(x: bv32, n: nat): bv32 requires 0 < n < 32 { (x >> n) | (x << (32 - n)) }
  function Word(b: bytes, i: nat): bv32 requires i + 4 <= |b| { (U32(b, i) as int) as bv32 }
  function WordBytes(w: bv32): bytes { BE32((w as int) as uint32) }

  function MessageSchedule(w: seq<bv32>): seq<bv32>
    requires 16 <= |w| <= 64
    ensures |MessageSchedule(w)| == 64
    decreases 64 - |w|
  {
    if |w| == 64 then w
    else
      var s0 := Rotr(w[|w| - 15], 7) ^ Rotr(w[|w| - 15], 18) ^ (w[|w| - 15] >> 3);
      var s1 := Rotr(w[|w| - 2], 17) ^ Rotr(w[|w| - 2], 19) ^ (w[|w| - 2] >> 10);
      MessageSchedule(w + [w[|w| - 16] + s0 + w[|w| - 7] + s1])
  }

  opaque function Rounds(w: seq<bv32>, t: nat, v: seq<bv32>): seq<bv32>
    requires |w| == 64 && t <= 64 && |v| == 8
    ensures |Rounds(w, t, v)| == 8
    decreases 64 - t
  {
    if t == 64 then v
    else
      var a, b, c, d, e, f, g, h := v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7];
      var t1 := h + (Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25)) + ((e & f) ^ (!e & g)) + K256[t] + w[t];
      var t2 := (Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
      Rounds(w, t + 1, [t1 + t2, a, b, c, d + t1, e, f, g])
  }

  opaque function {:isolate_assertions} Blocks(p: bytes, i: nat, h: seq<bv32>): seq<bv32>
    requires i <= |p| && (|p| - i) % 64 == 0 && |h| == 8
    ensures |Blocks(p, i, h)| == 8
    decreases |p| - i
  {
    if i == |p| then h
    else
      var block := p[i .. i + 64];
      assert |block| == 64;
      var w := MessageSchedule(seq(16, j requires 0 <= j < 16 => Word(block, 4 * j)));
      var v := Rounds(w, 0, h);
      Blocks(p, i + 64, seq(8, j requires 0 <= j < 8 => h[j] + v[j]))
  }

  opaque function Sha256(msg: bytes): (digest: bytes)
    ensures |digest| == 32
  {
    var pad := (119 - |msg| % 64) % 64;
    var bits := |msg| * 8;
    var padded := msg + [0x80] + seq(pad, i => 0 as uint8) + BE32((bits / 0x1_0000_0000 % 0x1_0000_0000) as uint32) + BE32((bits % 0x1_0000_0000) as uint32);
    assert |padded| % 64 == 0;
    var h := Blocks(padded, 0, H256);
    WordBytes(h[0]) + WordBytes(h[1]) + WordBytes(h[2]) + WordBytes(h[3]) + WordBytes(h[4]) + WordBytes(h[5]) + WordBytes(h[6]) + WordBytes(h[7])
  }

  function XorPad(b: bytes, p: uint8): bytes { seq(|b|, i requires 0 <= i < |b| => ((b[i] as bv8) ^ (p as bv8)) as uint8) }

  opaque function HmacRef(key: bytes, data: bytes): bytes
  {
    var k := if |key| > 64 then Sha256(key) else key;
    var kp := k + seq(64 - |k|, i => 0 as uint8);
    Sha256(XorPad(kp, 0x5c) + Sha256(XorPad(kp, 0x36) + data))
  }

  const P25519: int := 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed

  function Pow2(n: nat): int
    ensures Pow2(n) > 0
  {
    if n == 0 then 1 else 2 * Pow2(n - 1)
  }

  opaque function PowMod(b: int, e: nat): int
    decreases e
  {
    if e == 0 then 1 % P25519
    else if e % 2 == 0 then var h := PowMod(b, e / 2); (h * h) % P25519
    else (b * PowMod(b, e - 1)) % P25519
  }

  function LE(b: bytes): int
    ensures LE(b) >= 0
  {
    if |b| == 0 then 0 else b[0] as int + 256 * LE(b[1..])
  }

  function LEBytes(n: int, length: nat): bytes
    requires n >= 0
    ensures |LEBytes(n, length)| == length
  {
    seq(length, i requires 0 <= i < length => ((n / Pow2(8 * i)) % 256) as uint8)
  }

  function Clamp(k: bytes): bytes
    requires |k| == 32
  {
    [((k[0] as bv8) & 248) as uint8] + k[1 .. 31] + [(((k[31] as bv8) & 127) | 64) as uint8]
  }

  // RFC 7748 section 5, the Montgomery ladder from bit t down to bit 0.
  opaque function Ladder(k: int, x1: int, t: nat, x2: int, z2: int, x3: int, z3: int, swap: int): (int, int, int, int, int)
    requires k >= 0
    decreases t
  {
    var kt := (k / Pow2(t)) % 2;
    var sw := if swap != kt then 1 else 0;
    var (x2s, x3s) := if sw == 1 then (x3, x2) else (x2, x3);
    var (z2s, z3s) := if sw == 1 then (z3, z2) else (z2, z3);
    var a := (x2s + z2s) % P25519;
    var aa := (a * a) % P25519;
    var b := (x2s - z2s) % P25519;
    var bb := (b * b) % P25519;
    var e := (aa - bb) % P25519;
    var c := (x3s + z3s) % P25519;
    var d := (x3s - z3s) % P25519;
    var da := (d * a) % P25519;
    var cb := (c * b) % P25519;
    var nx3 := ((da + cb) * (da + cb)) % P25519;
    var nz3 := (x1 * (((da - cb) * (da - cb)) % P25519)) % P25519;
    var nx2 := (aa * bb) % P25519;
    var nz2 := (e * ((aa + 121665 * e) % P25519)) % P25519;
    if t == 0 then (nx2, nz2, nx3, nz3, kt) else Ladder(k, x1, t - 1, nx2, nz2, nx3, nz3, kt)
  }

  opaque function X25519Ref(scalar: bytes, point: bytes): bytes
    requires |scalar| == 32 && |point| == 32
  {
    var k := LE(Clamp(scalar));
    var u := LE(point) % Pow2(255);
    var (x2, z2, x3, z3, swap) := Ladder(k, u, 255, 1, 0, u, 1, 0);
    var (x, z) := if swap == 1 then (x3, z3) else (x2, z2);
    LEBytes((x * PowMod(z, P25519 - 2)) % P25519, 32)
  }

  // ---------------------------------------------------------------------------
  // Proofs (ghost only; nothing below is compiled): the frame decoder as a
  // stream, the ghost invariant over State, nonce uniqueness per lane, result
  // validation and key binding. spec_rules.dfy states the SPEC rules on top.

  // ---- The decoder numbers frames consecutively from d.next (SPEC 4.3, 6.2.1).

  // fs extends acc by frames numbered from..upto-1 in order.
  ghost predicate Consecutive(fs: seq<Framed>, acc: seq<Framed>, from: uint64, upto: uint64)
  {
    && |fs| >= |acc| && fs[..|acc|] == acc && upto as nat == from as nat + |fs| - |acc|
    && forall k :: |acc| <= k < |fs| ==> fs[k].seqNo as nat == from as nat + k - |acc|
  }

  lemma ConsecutiveTrans(fs: seq<Framed>, mid: seq<Framed>, acc: seq<Framed>, a: uint64, b: uint64, c: uint64)
    requires Consecutive(mid, acc, a, b) && Consecutive(fs, mid, b, c)
    ensures Consecutive(fs, acc, a, c)
  {
    assert fs[..|acc|] == fs[..|mid|][..|acc|];
  }

  lemma FramesConsecutive(d: Dec, buf: bytes, i: nat, acc: seq<Framed>)
    requires i <= |buf|
    ensures var r := Frames(d, buf, i, acc); Consecutive(r.0, acc, d.next, r.1.next)
    decreases |buf| - i
  {
    if |buf| - i >= 4 {
      var length := U32(buf, i);
      if length == 0 { FramesConsecutive(d, buf, i + 4, acc); }
      else if length <= MaxChunkBytes && |buf| - i >= 4 + length as nat && d.next != MaxSeq {
        var acc' := acc + [Framed(d.next, buf[i + 4 .. i + 4 + length as nat])];
        var d2 := Dec([], d.next + 1, true, d.requireFrame);
        FramesConsecutive(d2, buf, i + 4 + length as nat, acc');
        var r := Frames(d2, buf, i + 4 + length as nat, acc');
        assert Consecutive(acc', acc, d.next, d2.next);
        ConsecutiveTrans(r.0, acc', acc, d.next, d2.next, r.1.next);
      }
    }
  }

  lemma PushFromConsecutive(d: Dec, data: bytes, i: nat, acc: seq<Framed>)
    requires i <= |data|
    ensures var r := PushFrom(d, data, i, acc); Consecutive(r.0, acc, d.next, r.1.next)
    decreases |data| - i
  {
    if |d.pending| == 0 { FramesConsecutive(d, data, i, acc); }
    else if i == |data| {}
    else {
      var take := Min(|data| - i, FrameNeed(d.pending));
      FramesConsecutive(d, d.pending + data[i .. i + take], 0, acc);
      var fr := Frames(d, d.pending + data[i .. i + take], 0, acc);
      if fr.2.None? {
        PushFromConsecutive(fr.1, data, i + take, fr.0);
        var r := PushFrom(fr.1, data, i + take, fr.0);
        ConsecutiveTrans(r.0, fr.0, acc, d.next, fr.1.next, r.1.next);
      }
    }
  }

  lemma PushConsecutive(d: Dec, data: bytes)
    ensures var r := Push(d, data); Consecutive(r.0, [], d.next, r.1.next)
  { PushFromConsecutive(d, data, 0, []); }

  // ---- The decoder is a stream: any chunking yields the one-shot result.

  // What Frames leaves pending: never a complete, oversized or empty frame.
  ghost predicate WFPending(p: bytes)
  {
    |p| < 4 || (var n := U32(p, 0); n != 0 && n <= MaxChunkBytes && |p| < 4 + n as nat)
  }

  lemma U32Slice(buf: bytes, i: nat)
    requires i + 4 <= |buf|
    ensures U32(buf[i..], 0) == U32(buf, i)
  {}

  lemma FramesShift(d: Dec, buf: bytes, i: nat, acc: seq<Framed>)
    requires i <= |buf|
    ensures Frames(d, buf, i, acc) == Frames(d, buf[i..], 0, acc)
    decreases |buf| - i
  {
    if |buf| - i >= 4 {
      U32Slice(buf, i);
      var length := U32(buf, i);
      if length == 0 {
        FramesShift(d, buf, i + 4, acc);
        FramesShift(d, buf[i..], 4, acc);
        assert buf[i..][4..] == buf[i + 4..];
      } else if length <= MaxChunkBytes && |buf| - i >= 4 + length as nat && d.next != MaxSeq {
        var n := 4 + length as nat;
        assert buf[i..][4 .. n] == buf[i + 4 .. i + n];
        var acc' := acc + [Framed(d.next, buf[i + 4 .. i + n])];
        var d2 := Dec([], d.next + 1, true, d.requireFrame);
        FramesShift(d2, buf, i + n, acc');
        FramesShift(d2, buf[i..], n, acc');
        assert buf[i..][n..] == buf[i + n..];
      }
    }
  }

  lemma FramesPendingWF(d: Dec, buf: bytes, i: nat, acc: seq<Framed>)
    requires i <= |buf|
    ensures var r := Frames(d, buf, i, acc); r.2.None? ==> WFPending(r.1.pending)
    decreases |buf| - i
  {
    if |buf| - i >= 4 {
      U32Slice(buf, i);
      var length := U32(buf, i);
      if length == 0 { FramesPendingWF(d, buf, i + 4, acc); }
      else if length <= MaxChunkBytes && |buf| - i >= 4 + length as nat && d.next != MaxSeq {
        FramesPendingWF(Dec([], d.next + 1, true, d.requireFrame), buf, i + 4 + length as nat, acc + [Framed(d.next, buf[i + 4 .. i + 4 + length as nat])]);
      }
    }
  }

  // An incomplete frame alone yields nothing and stays pending.
  lemma WFPendingNoFrame(d: Dec, p: bytes, acc: seq<Framed>)
    requires WFPending(p)
    ensures Frames(d, p, 0, acc) == (acc, d.(pending := p), None)
  {}

  // The input's pending bytes only show in what an error returns.
  lemma FramesPendingIrrelevant(d: Dec, p: bytes, buf: bytes, i: nat, acc: seq<Framed>)
    requires i <= |buf|
    ensures var a := Frames(d, buf, i, acc); var b := Frames(d.(pending := p), buf, i, acc);
      a.0 == b.0 && a.2 == b.2 && (a.2.None? ==> a.1 == b.1)
    decreases |buf| - i
  {
    if |buf| - i >= 4 {
      var length := U32(buf, i);
      if length == 0 { FramesPendingIrrelevant(d, p, buf, i + 4, acc); }
    }
  }

  // Frames over buf1 then buf2 equals Frames over buf1 + buf2.
  lemma FramesAppend(d: Dec, buf1: bytes, buf2: bytes, i: nat, acc: seq<Framed>)
    requires i <= |buf1| && |d.pending| == 0
    ensures var L := Frames(d, buf1, i, acc); var R := Frames(d, buf1 + buf2, i, acc);
      && (L.2.Some? ==> R == L)
      && (L.2.None? ==> R == Frames(L.1.(pending := []), L.1.pending + buf2, 0, L.0))
    decreases |buf1| - i
  {
    var whole := buf1 + buf2;
    if |buf1| - i < 4 {
      FramesShift(d, whole, i, acc);
      assert whole[i..] == buf1[i..] + buf2;
    } else {
      assert U32(whole, i) == U32(buf1, i);
      var length := U32(buf1, i);
      if length == 0 { FramesAppend(d, buf1, buf2, i + 4, acc); }
      else if length > MaxChunkBytes {}
      else if |buf1| - i < 4 + length as nat {
        FramesShift(d, whole, i, acc);
        assert whole[i..] == buf1[i..] + buf2;
      } else if d.next == MaxSeq {}
      else {
        var n := 4 + length as nat;
        assert whole[i + 4 .. i + n] == buf1[i + 4 .. i + n];
        FramesAppend(Dec([], d.next + 1, true, d.requireFrame), buf1, buf2, i + n, acc + [Framed(d.next, buf1[i + 4 .. i + n])]);
      }
    }
  }

  lemma PushIsOneShot(d: Dec, data: bytes, i: nat, acc: seq<Framed>)
    requires i <= |data| && WFPending(d.pending)
    ensures var P := PushFrom(d, data, i, acc); var One := Frames(d.(pending := []), d.pending + data[i..], 0, acc);
      P.0 == One.0 && P.2 == One.2 && (One.2.None? ==> P.1 == One.1)
    decreases |data| - i
  {
    hide *;
    reveal PushFrom;
    var d0 := d.(pending := []);
    if |d.pending| == 0 {
      FramesShift(d, data, i, acc);
      assert d0 == d && d.pending + data[i..] == data[i..];
    } else if i == |data| {
      assert d.pending + data[i..] == d.pending;
      WFPendingNoFrame(d0, d.pending, acc);
    } else {
      reveal Min;
      var take := Min(|data| - i, FrameNeed(d.pending));
      var buf1 := d.pending + data[i .. i + take];
      var rest := data[i + take ..];
      assert buf1 + rest == d.pending + data[i..];
      FramesPendingIrrelevant(d, [], buf1, 0, acc);
      var fr := Frames(d, buf1, 0, acc);
      assert PushFrom(d, data, i, acc) == (if fr.2.Some? then fr else PushFrom(fr.1, data, i + take, fr.0));
      FramesAppend(d0, buf1, rest, 0, acc);
      if fr.2.None? {
        FramesPendingWF(d, buf1, 0, acc);
        PushIsOneShot(fr.1, data, i + take, fr.0);
      }
    }
  }

  // Frames with an accumulator is the accumulator plus Frames without one.
  lemma FramesAcc(d: Dec, buf: bytes, i: nat, acc: seq<Framed>)
    requires i <= |buf|
    ensures var a := Frames(d, buf, i, acc); var b := Frames(d, buf, i, []); a == (acc + b.0, b.1, b.2)
    decreases |buf| - i
  {
    if |buf| - i >= 4 {
      var length := U32(buf, i);
      if length == 0 { FramesAcc(d, buf, i + 4, acc); }
      else if length <= MaxChunkBytes && |buf| - i >= 4 + length as nat && d.next != MaxSeq {
        var f := Framed(d.next, buf[i + 4 .. i + 4 + length as nat]);
        var d2 := Dec([], d.next + 1, true, d.requireFrame);
        var j := i + 4 + length as nat;
        FramesAcc(d2, buf, j, acc + [f]);
        FramesAcc(d2, buf, j, [f]);
        var b := Frames(d2, buf, j, []);
        assert Frames(d, buf, i, acc) == Frames(d2, buf, j, acc + [f]) == (acc + [f] + b.0, b.1, b.2);
        assert [] + [f] == [f];
        assert Frames(d, buf, i, []) == Frames(d2, buf, j, [f]) == ([f] + b.0, b.1, b.2);
        assert acc + [f] + b.0 == acc + ([f] + b.0);
        var c := Frames(d, buf, i, []);
        assert Frames(d, buf, i, acc) == (acc + c.0, c.1, c.2);
      } else { assert acc + [] == acc; }
    } else { assert acc + [] == acc; }
  }

  ghost function Concat(chunks: seq<bytes>): bytes
  {
    if |chunks| == 0 then [] else chunks[0] + Concat(chunks[1..])
  }

  // Push over the chunks in turn, stopping at the first error.
  ghost function PushAll(d: Dec, chunks: seq<bytes>): (seq<Framed>, Dec, Option<Code>)
    decreases |chunks|
  {
    if |chunks| == 0 then ([], d, None)
    else
      var p := Push(d, chunks[0]);
      if p.2.Some? then p
      else var q := PushAll(p.1, chunks[1..]); (p.0 + q.0, q.1, q.2)
  }

  lemma PushAllIsOneShot(d: Dec, chunks: seq<bytes>)
    requires WFPending(d.pending)
    ensures var All := PushAll(d, chunks); var One := Frames(d.(pending := []), d.pending + Concat(chunks), 0, []);
      All.0 == One.0 && All.2 == One.2 && (One.2.None? ==> All.1 == One.1)
    decreases |chunks|
  {
    var d0 := d.(pending := []);
    if |chunks| == 0 {
      assert d.pending + Concat(chunks) == d.pending;
      WFPendingNoFrame(d0, d.pending, []);
    } else {
      var c0 := chunks[0];
      var rest := Concat(chunks[1..]);
      assert d.pending + Concat(chunks) == (d.pending + c0) + rest;
      PushIsOneShot(d, c0, 0, []);
      var p := Push(d, c0);
      FramesAppend(d0, d.pending + c0, rest, 0, []);
      if p.2.None? {
        FramesPendingWF(d0, d.pending + c0, 0, []);
        PushAllIsOneShot(p.1, chunks[1..]);
        FramesAcc(p.1.(pending := []), p.1.pending + rest, 0, p.0);
      }
    }
  }

  // ---- The wire: Frame(ct_0) + ... + Frame(ct_m-1) decodes to those frames numbered from d.next.

  ghost function Wire(cts: seq<bytes>): bytes
    requires forall c <- cts :: |c| < 0x1_0000_0000
  {
    if |cts| == 0 then [] else Frame(cts[0]) + Wire(cts[1..])
  }

  ghost function Numbered(cts: seq<bytes>, from: uint64): seq<Framed>
    requires from as nat + |cts| <= MaxSeq as nat
  {
    seq(|cts|, k requires 0 <= k < |cts| => Framed(from + k as uint64, cts[k]))
  }

  lemma U16BE16(v: uint16, tail: bytes)
    ensures U16(BE16(v) + tail, 0) == v
  {}

  lemma U32BE32(v: uint32, tail: bytes)
    ensures U32(BE32(v) + tail, 0) == v
  {
    var hi, lo := (v / 0x1_0000) as uint16, (v % 0x1_0000) as uint16;
    assert BE32(v) + tail == BE16(hi) + (BE16(lo) + tail);
    U16BE16(hi, BE16(lo) + tail);
    assert (BE32(v) + tail)[2] == BE16(lo)[0] && (BE32(v) + tail)[3] == BE16(lo)[1];
    assert U16(BE32(v) + tail, 2) == lo;
  }

  // One complete frame at the front of the buffer is taken and numbered d.next.
  lemma FramesOneFrame(d: Dec, c0: bytes, rest: bytes, acc: seq<Framed>)
    requires |d.pending| == 0 && 0 < |c0| <= MaxChunkBytes as nat && d.next != MaxSeq
    ensures Frames(d, Frame(c0) + rest, 0, acc) == Frames(Dec([], d.next + 1, true, d.requireFrame), rest, 0, acc + [Framed(d.next, c0)])
  {
    var buf := Frame(c0) + rest;
    var n := 4 + |c0|;
    U32BE32(|c0| as uint32, c0 + rest);
    assert buf == BE32(|c0| as uint32) + (c0 + rest);
    assert U32(buf, 0) == |c0| as uint32;
    assert buf[4 .. n] == c0;
    var d2 := Dec([], d.next + 1, true, d.requireFrame);
    assert Frames(d, buf, 0, acc) == Frames(d2, buf, n, acc + [Framed(d.next, c0)]);
    FramesShift(d2, buf, n, acc + [Framed(d.next, c0)]);
    assert buf[n..] == rest;
  }

  lemma NumberedCons(cts: seq<bytes>, from: uint64)
    requires |cts| > 0 && from as nat + |cts| <= MaxSeq as nat
    ensures Numbered(cts, from) == [Framed(from, cts[0])] + Numbered(cts[1..], from + 1)
  {
    var l, r := Numbered(cts, from), [Framed(from, cts[0])] + Numbered(cts[1..], from + 1);
    assert |l| == |r|;
    assert forall k :: 0 <= k < |l| ==> l[k] == r[k];
  }

  lemma WireFrames(d: Dec, cts: seq<bytes>, acc: seq<Framed>)
    requires |d.pending| == 0
    requires forall c <- cts :: 0 < |c| <= MaxChunkBytes as nat
    requires d.next as nat + |cts| <= MaxSeq as nat
    ensures Frames(d, Wire(cts), 0, acc) == (acc + Numbered(cts, d.next), d.(next := d.next + |cts| as uint64, authenticated := d.authenticated || |cts| > 0), None)
    decreases |cts|
  {
    hide *;
    reveal Wire;
    if |cts| == 0 {
      reveal Frames, Numbered;
      assert acc + Numbered(cts, d.next) == acc;
    } else {
      var c0 := cts[0];
      var d2 := Dec([], d.next + 1, true, d.requireFrame);
      var acc' := acc + [Framed(d.next, c0)];
      FramesOneFrame(d, c0, Wire(cts[1..]), acc);
      WireFrames(d2, cts[1..], acc');
      NumberedCons(cts, d.next);
      assert acc' + Numbered(cts[1..], d2.next) == acc + Numbered(cts, d.next);
    }
  }

  lemma FramingRoundTrip(d: Dec, cts: seq<bytes>, chunks: seq<bytes>)
    requires |d.pending| == 0
    requires forall c <- cts :: 0 < |c| <= MaxChunkBytes as nat
    requires d.next as nat + |cts| <= MaxSeq as nat
    requires Concat(chunks) == Wire(cts)
    ensures PushAll(d, chunks) == (Numbered(cts, d.next), d.(next := d.next + |cts| as uint64, authenticated := d.authenticated || |cts| > 0), None)
  {
    hide *;
    PushAllIsOneShot(d, chunks);
    assert d.pending + Concat(chunks) == Wire(cts);
    assert d.(pending := []) == d;
    WireFrames(d, cts, []);
    assert [] + Numbered(cts, d.next) == Numbered(cts, d.next);
  }

  // ---- The ghost invariant over the client state.

  ghost predicate Continues(job: Job, start: Job)
  {
    job.JExpand? && start.JExpand? && job.prk == start.prk && job.info == start.info && job.length == start.length
  }

  lemma JobStepContinues(job: Job, e: Event, start: Job)
    requires Continues(job, start) && JobStep(job, e).Pending?
    ensures Continues(JobStep(job, e).job, start)
  {}

  // frames carry the consecutive sequence numbers just before next.
  ghost predicate FramesEndAt(frames: seq<Framed>, next: uint64)
  {
    |frames| <= next as nat && forall k :: 0 <= k < |frames| ==> frames[k].seqNo as nat == next as nat - |frames| + k
  }

  // The response key derivation is HKDF over this exchange's token and the head's nonce (SPEC 4.4.1, 6.2).
  ghost predicate AwaitKeysInv(rs: Response, token: Token)
    requires rs.AwaitKeys?
  {
    && rs.stage <= 2
    && (rs.stage == 0 ==> rs.job.JExtract? && rs.job.ikm == token.exportedSecret && |rs.job.salt| == RequestEncLength + ResponseNonceLength && rs.job.salt[..RequestEncLength] == token.requestEnc)
    && (rs.stage == 1 ==> Continues(rs.job, Expand(rs.prk, Ascii(ResponseKeyLabel), KeyLength)))
    && (rs.stage == 2 ==> Continues(rs.job, Expand(rs.prk, Ascii(ResponseNonceLabel), NonceLength)) && |rs.key| == KeyLength)
  }

  ghost predicate Inv(s: State)
  {
    // encryption is committed to only once a plaintext byte was read (SPEC 5.1, 7.4)
    && (s.phase.AwaitSetup? ==> |s.phase.first| > 0)
    && (s.phase.AwaitExport? ==> |s.phase.first| > 0 && Continues(s.phase.job, ExportJob(s.ctx, Ascii(ExportLabel), ExportLength)))
    && (s.phase.Exchanging? && s.phase.response.AwaitKeys? ==> AwaitKeysInv(s.phase.response, s.token))
    && (s.phase.Exchanging? && s.phase.response.Opening? ==> |s.phase.response.frames| > 0 && FramesEndAt(s.phase.response.frames, s.phase.response.dec.next))
    && (forall i :: 0 <= i < |s.headers| ==> !ReservedHeader(s.headers[i].0))
  }

  lemma InitialInv(origin: Origin, publicKey: bytes, token: Token)
    ensures Inv(Initial(origin, publicKey)) && Inv(ResponseOnly(origin, token))
  {}

  lemma OpenNextInv(s: State, keys: Ctx, dec: Dec, frames: seq<Framed>, chunks: seq<bytes>, eof: bool)
    requires s.phase.Exchanging? && Inv(s) && FramesEndAt(frames, dec.next)
    ensures Inv(OpenNext(s, keys, dec, frames, chunks, eof).0)
  {}

  lemma {:isolate_assertions} StepInv(s: State, e: Event)
    requires Inv(s)
    ensures Inv(Step(s, e).0)
  {
    if e.CallerClose? { return; }
    if s.phase.Idle? && e.Start? {
      var target := MakeOrigin(e.scheme, e.host, if e.hasPort then Some(e.port) else None, e.hasUserinfo);
      if ValidateRequest(s.origin, target, e.headers).Ok? {
        ValidateHeadersOk(e.headers, 0);
        DropFramingKeeps(e.headers);
      }
    } else if s.phase.AwaitExport? {
      if JobStep(s.phase.job, e).Pending? { JobStepContinues(s.phase.job, e, ExportJob(s.ctx, Ascii(ExportLabel), ExportLength)); }
    } else if s.phase.Exchanging? && !ForUpload(e) {
      var rs := s.phase.response;
      if rs.AwaitKeys? && JobStep(rs.job, e).Pending? {
        if rs.stage == 1 { JobStepContinues(rs.job, e, Expand(rs.prk, Ascii(ResponseKeyLabel), KeyLength)); }
        else if rs.stage == 2 { JobStepContinues(rs.job, e, Expand(rs.prk, Ascii(ResponseNonceLabel), NonceLength)); }
      } else if rs.BodyReading? && e.Chunk? && e.stream.ResponseBody? {
        PushConsecutive(rs.dec, e.data);
        var p := Push(rs.dec, e.data);
        if p.2.None? { OpenNextInv(s, rs.keys, p.1, p.0, [], e.eof); }
      } else if rs.Opening? && e.AeadOpenResult? && |rs.frames| > 0 && e.ok && |e.plaintext| + AeadTagLength == |rs.frames[0].ciphertext| {
        OpenNextInv(s, rs.keys, rs.dec, rs.frames[1..], if |e.plaintext| > 0 then rs.chunks + [e.plaintext] else rs.chunks, rs.eof);
      }
    }
  }

  // ---- Nonce uniqueness: one lane of AEAD calls, seen as a view of the state.
  //
  // A lane is live once its context exists, dead once it can issue no more
  // calls, and has a call outstanding (`out`) between issuing one and seeing
  // its result. `mark` is the sequence number the next call uses; the lane's
  // nonces are ComputeNonce(base, mark).

  // (live, dead, out, mark, key, base); a synonym, so nothing is compiled.
  type View = (bool, bool, bool, nat, bytes, bytes)
  ghost function Live(v: View): bool { v.0 }
  ghost function Dead(v: View): bool { v.1 }
  ghost function Out(v: View): bool { v.2 }
  ghost function Mark(v: View): nat { v.3 }
  ghost function VKey(v: View): bytes { v.4 }
  ghost function Base(v: View): bytes { v.5 }
  ghost function MkView(live: bool, dead: bool, out: bool, mark: nat, key: bytes, base: bytes): View { (live, dead, out, mark, key, base) }

  // What one step does to a lane's view; `issued` is whether the step issued a call.
  ghost predicate ViewStep(v: View, w: View, issued: bool)
  {
    && (issued ==> Live(w) && Out(w) && !Dead(w))
    && (Live(v) ==> Live(w) && (Dead(w) || (Mark(w) >= Mark(v) && VKey(w) == VKey(v) && Base(w) == Base(v))))
    && (Live(v) && Out(v) && !Dead(w) && Mark(w) == Mark(v) ==> !issued && Out(w))
    && (Dead(v) ==> Dead(w) && !issued)
  }

  // Along any run of views, the marks of the steps that issue a call strictly increase under one key and base.
  lemma MarksIncrease(views: seq<View>, issued: seq<bool>, i: nat, j: nat)
    requires |views| == |issued| + 1
    requires forall k :: 0 <= k < |issued| ==> ViewStep(views[k], views[k + 1], issued[k])
    requires i < j < |issued| && issued[i] && issued[j]
    ensures Mark(views[i + 1]) < Mark(views[j + 1]) && VKey(views[i + 1]) == VKey(views[j + 1]) && Base(views[i + 1]) == Base(views[j + 1])
  {
    var m, key, base := Mark(views[i + 1]), VKey(views[i + 1]), Base(views[i + 1]);
    var k := i + 1;
    while k < j
      invariant i + 1 <= k <= j
      invariant Live(views[k]) && (Dead(views[k]) || (Mark(views[k]) >= m && VKey(views[k]) == key && Base(views[k]) == base && (Mark(views[k]) == m ==> Out(views[k]))))
    {
      assert ViewStep(views[k], views[k + 1], issued[k]);
      k := k + 1;
    }
    assert ViewStep(views[j], views[j + 1], issued[j]);
  }

  ghost predicate HasSeal(acts: seq<Action>) { exists k :: 0 <= k < |acts| && acts[k].AeadSeal? }
  ghost predicate OneSeal(acts: seq<Action>) { forall k, l :: 0 <= k < |acts| && 0 <= l < |acts| && acts[k].AeadSeal? && acts[l].AeadSeal? ==> k == l }
  ghost predicate HasOpen(acts: seq<Action>) { exists k :: 0 <= k < |acts| && acts[k].AeadOpen? }
  ghost predicate OneOpen(acts: seq<Action>) { forall k, l :: 0 <= k < |acts| && 0 <= l < |acts| && acts[k].AeadOpen? && acts[l].AeadOpen? ==> k == l }

  // The request lane: the HPKE sender context seals frames in sequence.
  ghost function SealView(s: State): View
  {
    var ex := s.phase.Exchanging?;
    MkView(ex, ex && !s.phase.upload.Sealing? && !s.phase.upload.UpReading?, ex && s.phase.upload.Sealing?, s.ctx.seqNo as nat, s.ctx.key, s.ctx.baseNonce)
  }

  ghost predicate SealFacts(s: State, e: Event)
  {
    var r := Step(s, e);
    && ViewStep(SealView(s), SealView(r.0), HasSeal(r.1)) && OneSeal(r.1)
    && forall k :: 0 <= k < |r.1| && r.1[k].AeadSeal? ==> r.1[k].key == r.0.ctx.key && r.1[k].nonce == ComputeNonce(r.0.ctx.baseNonce, r.0.ctx.seqNo)
  }

  // One lemma per place a seal can be issued keeps each proof small.
  lemma SealFactsExport(s: State, e: Event)
    requires s.phase.AwaitExport?
    ensures SealFacts(s, e)
  {}

  lemma SealFactsUpload(s: State, e: Event)
    requires s.phase.Exchanging? && ForUpload(e)
    ensures SealFacts(s, e)
  {}

  lemma SealFactsElsewhere(s: State, e: Event)
    requires !s.phase.AwaitExport? && !(s.phase.Exchanging? && ForUpload(e))
    ensures SealFacts(s, e)
  {}

  lemma StepSealView(s: State, e: Event)
    ensures SealFacts(s, e)
  {
    if s.phase.AwaitExport? { SealFactsExport(s, e); }
    else if s.phase.Exchanging? && ForUpload(e) { SealFactsUpload(s, e); }
    else { SealFactsElsewhere(s, e); }
  }

  // The response lane: the derived context opens the frames the decoder numbered.
  ghost function OpenView(s: State): View
  {
    if !s.phase.Exchanging? then MkView(false, false, false, 0, [], [])
    else
      var rs := s.phase.response;
      if rs.Opening? then MkView(true, false, true, if |rs.frames| > 0 then rs.frames[0].seqNo as nat else rs.dec.next as nat, rs.keys.key, rs.keys.baseNonce)
      else if rs.Body? || rs.BodyReading? then MkView(true, false, false, rs.dec.next as nat, rs.keys.key, rs.keys.baseNonce)
      else if rs.RespEnded? then MkView(true, true, false, 0, [], [])
      else MkView(false, false, false, 0, [], [])
  }

  lemma {:isolate_assertions} StepOpenView(s: State, e: Event)
    requires Inv(s)
    ensures var r := Step(s, e); var w := OpenView(r.0);
      && ViewStep(OpenView(s), w, HasOpen(r.1)) && OneOpen(r.1)
      && forall k :: 0 <= k < |r.1| && r.1[k].AeadOpen? ==> r.1[k].key == VKey(w) && r.1[k].nonce == ComputeNonce(Base(w), Mark(w) as uint64)
  {
    if e.Chunk? && s.phase.Exchanging? && s.phase.response.BodyReading? { PushConsecutive(s.phase.response.dec, e.data); }
  }

  // ---- A run of the client: states[k+1] is Step(states[k], events[k]).0.

  ghost predicate IsRun(states: seq<State>, events: seq<Event>)
  {
    |states| == |events| + 1 && forall k :: 0 <= k < |events| ==> states[k + 1] == Step(states[k], events[k]).0
  }

  ghost function Acts(states: seq<State>, events: seq<Event>, k: nat): seq<Action>
    requires IsRun(states, events) && k < |events|
  {
    Step(states[k], events[k]).1
  }

  lemma RunInv(states: seq<State>, events: seq<Event>, k: nat)
    requires IsRun(states, events) && Inv(states[0]) && k < |states|
    ensures Inv(states[k])
  { if k > 0 { RunInv(states, events, k - 1); StepInv(states[k - 1], events[k - 1]); } }

  // Two request frames of one exchange are sealed under the same key with different nonces.
  lemma RequestNoncesDistinct(states: seq<State>, events: seq<Event>, i: nat, j: nat, ki: nat, kj: nat)
    requires IsRun(states, events) && i < j < |events|
    requires ki < |Acts(states, events, i)| && Acts(states, events, i)[ki].AeadSeal?
    requires kj < |Acts(states, events, j)| && Acts(states, events, j)[kj].AeadSeal?
    ensures var a, b := Acts(states, events, i)[ki], Acts(states, events, j)[kj]; a.key == b.key && a.nonce != b.nonce
  {
    var views := seq(|states|, k requires 0 <= k < |states| => SealView(states[k]));
    var issued := seq(|events|, k requires 0 <= k < |events| => HasSeal(Acts(states, events, k)));
    forall k | 0 <= k < |events| ensures ViewStep(views[k], views[k + 1], issued[k]) { StepSealView(states[k], events[k]); }
    MarksIncrease(views, issued, i, j);
    StepSealView(states[i], events[i]);
    StepSealView(states[j], events[j]);
    ComputeNonceInjective(states[i + 1].ctx.baseNonce, states[i + 1].ctx.seqNo, states[j + 1].ctx.seqNo);
  }

  // Two response frames of one exchange are opened under the same key with different nonces.
  lemma ResponseNoncesDistinct(states: seq<State>, events: seq<Event>, i: nat, j: nat, ki: nat, kj: nat)
    requires IsRun(states, events) && Inv(states[0]) && i < j < |events|
    requires ki < |Acts(states, events, i)| && Acts(states, events, i)[ki].AeadOpen?
    requires kj < |Acts(states, events, j)| && Acts(states, events, j)[kj].AeadOpen?
    ensures var a, b := Acts(states, events, i)[ki], Acts(states, events, j)[kj]; a.key == b.key && a.nonce != b.nonce
  {
    var views := seq(|states|, k requires 0 <= k < |states| => OpenView(states[k]));
    var issued := seq(|events|, k requires 0 <= k < |events| => HasOpen(Acts(states, events, k)));
    forall k | 0 <= k < |events| ensures ViewStep(views[k], views[k + 1], issued[k]) { RunInv(states, events, k); StepOpenView(states[k], events[k]); }
    MarksIncrease(views, issued, i, j);
    RunInv(states, events, i); StepOpenView(states[i], events[i]);
    RunInv(states, events, j); StepOpenView(states[j], events[j]);
    var vi, vj := views[i + 1], views[j + 1];
    ComputeNonceInjective(Base(vi), Mark(vi) as uint64, Mark(vj) as uint64);
  }

  // Escape leaves a string without quotes, backslashes or control characters as it is (SPEC 6.1.1: hex needs no escaping).
  lemma EscapePlain(s: string)
    requires forall i :: 0 <= i < |s| ==> s[i] != '"' && s[i] != '\\' && s[i] as int >= 0x20
    ensures Escape(s) == s
  { if |s| > 0 { EscapePlain(s[1..]); } }

  // ---- Result validation: a native result of the wrong shape is refused before any use.

  ghost predicate IsResult(e: Event) { e.RandomResult? || e.X25519Result? || e.HmacResult? || e.AeadSealResult? || e.AeadOpenResult? }

  // The plaintext length of the seal outstanding in `up`.
  ghost function SealLen(up: Upload): nat
    requires up.Sealing?
  {
    var size := |up.plaintext| as uint32;
    var at := Min32(up.offset, size);
    Min32(size - at, RequestFrameBytes) as nat
  }

  // The shape every native result must have to be used: the requested length, or the AEAD's input length plus or minus the tag.
  ghost predicate WellFormed(s: State, e: Event)
  {
    if e.RandomResult? then |e.data| == 32
    else if e.X25519Result? then |e.point| == 32
    else if e.HmacResult? then |e.mac| == HashLength
    else if e.AeadSealResult? then s.phase.Exchanging? && s.phase.upload.Sealing? && |e.ciphertext| == SealLen(s.phase.upload) + AeadTagLength
    else if e.AeadOpenResult? then e.ok && s.phase.Exchanging? && s.phase.response.Opening? && |s.phase.response.frames| > 0 && |e.plaintext| + AeadTagLength == |s.phase.response.frames[0].ciphertext|
    else true
  }

  ghost predicate NoCrypto(acts: seq<Action>)
  {
    forall k :: 0 <= k < |acts| ==> !(acts[k].AeadSeal? || acts[k].AeadOpen? || acts[k].HmacSha256? || acts[k].X25519? || acts[k].RandomBytes?)
  }

  // The step ended the exchange, or aborted the upload lane.
  ghost predicate Refused(acts: seq<Action>) { Ends(acts) || (|acts| == 1 && acts[0].Write? && acts[0].end.Aborted?) }

  ghost function RespKeys(s: State): Option<Ctx>
  {
    if s.phase.Exchanging? && (s.phase.response.Body? || s.phase.response.BodyReading? || s.phase.response.Opening?) then Some(s.phase.response.keys) else None
  }

  // A malformed result is refused: nothing is sealed, opened, derived or emitted, and no context is created or changed.
  lemma {:isolate_assertions} MalformedResultRefused(s: State, e: Event)
    requires IsResult(e) && !WellFormed(s, e)
    ensures var r := Step(s, e);
      Refused(r.1) && NoCrypto(r.1) && NoEmit(r.1) && r.0.ctx == s.ctx && (RespKeys(r.0).Some? ==> RespKeys(r.0) == RespKeys(s))
  {}

  // ---- Key binding: the contexts and the token of an exchange come from that exchange only.

  lemma {:isolate_assertions} StepKeyFacts(s: State, e: Event)
    requires Inv(s)
    ensures var r := Step(s, e);
      // the request context is created once, by the HPKE setup, and afterwards only advanced
      && (r.0.ctx != s.ctx ==>
            || (s.phase.AwaitSetup? && r.0.phase.AwaitExport? && HpkeStep(s.phase.hpke, e).HReady? && r.0.ctx == HpkeStep(s.phase.hpke, e).ctx && r.0.ctx.seqNo == 0)
            || (s.phase.Exchanging? && s.ctx.seqNo < MaxSeq && r.0.ctx == Bump(s.ctx)))
      // the token is set once, when it is published, and never changes during the exchange
      && (r.0.token != s.token ==> s.phase.AwaitExport? && r.0.published && r.0.phase.Exchanging?)
      && (s.phase.Exchanging? ==> r.0.token == s.token)
      // what is published is this exchange's export and encapsulated key, before the request is sent, under the current generation
      && (forall k :: 0 <= k < |r.1| && r.1[k].PublishToken? ==>
            && s.phase.AwaitExport? && k == 0 && |r.1| == 3 && r.1[1].Send? && r.1[1].hasBody && r.1[2].AeadSeal?
            && r.1[0].generation == s.generation && r.1[0].requestEnc == s.phase.enc
            && JobStep(s.phase.job, e) == Output(r.1[0].exportedSecret)
            && Continues(s.phase.job, ExportJob(s.ctx, Ascii(ExportLabel), ExportLength))
            && r.0.token == Token(r.1[0].exportedSecret, r.1[0].requestEnc) && ValidToken(r.0.token) && r.0.published
            && r.1[1].headers == s.headers + [(EncapsulatedKeyHeader, EncodeHex(r.1[0].requestEnc))])
      // the response derivation starts from the token in flight and the nonce of this head
      && (r.0.phase.Exchanging? && r.0.phase.response.AwaitKeys? && r.0.phase.response.stage == 0 && !(s.phase.Exchanging? && s.phase.response.AwaitKeys?) ==>
            && s.phase.Exchanging? && s.phase.response.AwaitHead? && e.ResponseHead?
            && var d := Classify(s.phase.response.encrypted, Head(e.status, e.headers, e.redirected));
              d.Decrypt? && |d.nonce| == ResponseNonceLength && ValidToken(s.token)
              && r.0.phase.response.job == Extract(s.token.requestEnc + d.nonce, s.token.exportedSecret))
      // the response context is created once, from the two expansions of that derivation
      && (RespKeys(r.0).Some? && RespKeys(r.0) != RespKeys(s) ==>
            && s.phase.Exchanging? && s.phase.response.AwaitKeys? && s.phase.response.stage == 2
            && JobStep(s.phase.response.job, e).Output?
            && RespKeys(r.0) == Some(Ctx(s.phase.response.key, JobStep(s.phase.response.job, e).data, [], 0)))
  {}
}
