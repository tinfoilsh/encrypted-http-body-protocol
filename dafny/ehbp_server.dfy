// The server side (SPEC 5.2) as the same kind of pure machine as the client
// of ehbp_events.dfy. The native middleware feeds the request head, the body
// chunks it reads, the crypto results and what the application handler reads
// and writes; ServerStep answers with the actions. The HPKE recipient, HKDF,
// the frame decoder and the response key derivation are the client's.
// Translated for Go only (the middleware): the client bundles of every other
// language are built from ehbp_events.dfy and never contain this module.
include "ehbp_events.dfy"

module EHBPServer {
  import opened EHBP
  import EV = EHBPEvents

  datatype SEvent =
    | RequestStart(headers: Headers, hasBody: bool)
    | RandomResult(data: bytes)
    | X25519Result(point: bytes)
    | HmacResult(mac: bytes)
    | AeadSealResult(ciphertext: bytes)
    | AeadOpenResult(ok: bool, plaintext: bytes)
    // The result of Read: the next request body bytes, or the read failed.
    | Chunk(data: bytes, eof: bool)
    | StreamFailed
    // The handler pulls plaintext, writes its status, writes bytes, returns.
    | HandlerRead
    | HandlerHead(status: int)
    | HandlerChunk(data: bytes)
    | HandlerDone

  datatype SAction =
    | RandomBytes(length: nat)
    | X25519(scalar: bytes, point: bytes)
    | HmacSha256(key: bytes, data: bytes)
    | AeadSeal(key: bytes, nonce: bytes, plaintext: bytes)
    | AeadOpen(key: bytes, nonce: bytes, ciphertext: bytes)
    // No encapsulated key: the request reaches the handler unchanged.
    | PassRequest
    // A plaintext answer (400, 422 or 500); code and message name the API error.
    | Respond(status: int, code: Code, message: string, headers: Headers, body: bytes)
    | Read(stream: EV.Stream)
    | EmitPlaintext(data: bytes)
    // RequestBody: the decrypted body ended; ResponseBody: the response is complete.
    | Close(stream: EV.Stream)
    // Run the handler; its reads and writes arrive as Handler* events.
    | Dispatch
    // The response head, with the headers the protocol owns.
    | StartResponse(status: int, headers: Headers)
    // One encrypted frame (More), or abort the response (Aborted).
    | Write(data: bytes, end: EV.BodyEnd)
    // The handler's next read fails with this error; the exchange cannot complete.
    | Fail(code: Code, message: string)

  // The crypto machines are the client's: their events and actions map one to one.
  function ToEvent(e: SEvent): EV.Event
  {
    match e
    case RandomResult(d) => EV.RandomResult(d)
    case X25519Result(p) => EV.X25519Result(p)
    case HmacResult(m) => EV.HmacResult(m)
    case AeadSealResult(c) => EV.AeadSealResult(c)
    case AeadOpenResult(ok, p) => EV.AeadOpenResult(ok, p)
    case _ => EV.CallerClose // never a crypto result: the machines report it as unexpected
  }

  function ToAction(a: EV.Action): SAction
  {
    match a
    case RandomBytes(n) => RandomBytes(n)
    case X25519(s, p) => X25519(s, p)
    case HmacSha256(k, d) => HmacSha256(k, d)
    case AeadSeal(k, n, p) => AeadSeal(k, n, p)
    case AeadOpen(k, n, c) => AeadOpen(k, n, c)
    case _ => Fail(Transport, "unexpected action")
  }

  // ---------------------------------------------------------------------------
  // State. Before Dispatch one lane runs: decapsulate, then read until the
  // first plaintext byte (SPEC 5.2), then derive the response keys. After it
  // the request lane (what the handler reads) and the response lane (what it
  // writes) are independent.

  datatype Req =
    | Waiting
    | Reading(empty: nat)
    | Opening(frames: seq<Framed>, eof: bool, emitted: bool)
    | ReqDone
    // status: 422 only when no frame had authenticated (SPEC 5.4.2).
    | ReqFailed(status: int, code: Code, message: string)

  datatype Sealing = NoSeal | Sealing(plaintext: EV.Chunk, offset: uint32, final: bool)

  datatype Resp = Resp(keys: EV.Ctx, nonce: bytes, started: bool, status: int, framed: bool, seal: Sealing)

  datatype Phase =
    | Idle
    | Decap(hpke: EV.Hpke)
    | Peek(req: Req)
    | Deriving(stage: nat, job: EV.Job, req: Req, nonce: bytes, secret: bytes, prk: bytes, key: bytes)
    | Running(req: Req, resp: Resp)
    | Ended

  datatype SState = SState(phase: Phase, sk: bytes, pk: bytes, enc: bytes, ctx: EV.Ctx, dec: EV.Dec, payload: bool)

  function ServerInitial(sk: bytes, pk: bytes): (s: SState)
    ensures Inv(s)
  {
    SState(Idle, sk, pk, [], EV.NoCtx, EV.Dec([], 0, false, false), false)
  }

  // Keys are derived and the handler runs only once a plaintext byte authenticated.
  predicate Inv(s: SState) { s.phase.Deriving? || s.phase.Running? ==> s.payload }

  predicate NoEmit(acts: seq<SAction>) { forall i :: 0 <= i < |acts| ==> !acts[i].EmitPlaintext? }
  predicate Dispatches(acts: seq<SAction>) { exists i :: 0 <= i < |acts| && acts[i].Dispatch? }
  // The actions after which the native side stops performing the list.
  predicate Terminal(a: SAction) { a.PassRequest? || a.Respond? || a.Dispatch? || (a.Close? && a.stream.ResponseBody?) || (a.Write? && a.end.Aborted?) }
  predicate TerminalLast(acts: seq<SAction>) { forall i :: 0 <= i < |acts| && Terminal(acts[i]) ==> i == |acts| - 1 }

  // The server's native bindings (internal/eventresidue/server.go) and the
  // dispatch over them, as Performer and Perform are for the client.
  trait SPerformer extends object {
    method RandomBytes(length: nat) returns (data: bytes)
    method X25519(scalar: bytes, point: bytes) returns (shared: bytes)
    method HmacSha256(key: bytes, data: bytes) returns (mac: bytes)
    method AeadSeal(key: bytes, nonce: bytes, plaintext: bytes) returns (ciphertext: bytes)
    method AeadOpen(key: bytes, nonce: bytes, ciphertext: bytes) returns (ok: bool, plaintext: bytes)
    method PassRequest()
    method Respond(status: int, code: Code, message: string, headers: Headers, body: bytes)
    method Read(stream: EV.Stream) returns (ok: bool, data: bytes, eof: bool)
    method EmitPlaintext(data: bytes)
    method Close(stream: EV.Stream)
    // ran: the handler ran to completion (HandlerDone); false when only recorded.
    method Dispatch() returns (ran: bool)
    method StartResponse(status: int, headers: Headers)
    method Write(data: bytes, end: EV.BodyEnd)
    method Fail(code: Code, message: string)
  }

  method SPerform(p: SPerformer, a: SAction) returns (r: Option<SEvent>)
  {
    match a
    case RandomBytes(length) =>
      var data := p.RandomBytes(length);
      return Some(RandomResult(data));
    case X25519(scalar, point) =>
      var shared := p.X25519(scalar, point);
      return Some(X25519Result(shared));
    case HmacSha256(key, data) =>
      var mac := p.HmacSha256(key, data);
      return Some(HmacResult(mac));
    case AeadSeal(key, nonce, plaintext) =>
      var ciphertext := p.AeadSeal(key, nonce, plaintext);
      return Some(AeadSealResult(ciphertext));
    case AeadOpen(key, nonce, ciphertext) =>
      var ok, plaintext := p.AeadOpen(key, nonce, ciphertext);
      return Some(AeadOpenResult(ok, plaintext));
    case PassRequest =>
      p.PassRequest();
      return None;
    case Respond(status, code, message, headers, body) =>
      p.Respond(status, code, message, headers, body);
      return None;
    case Read(stream) =>
      var ok, data, eof := p.Read(stream);
      return Some(if ok then Chunk(data, eof) else StreamFailed);
    case EmitPlaintext(data) =>
      p.EmitPlaintext(data);
      return None;
    case Close(stream) =>
      p.Close(stream);
      return None;
    case Dispatch =>
      var ran := p.Dispatch();
      return if ran then Some(HandlerDone) else None;
    case StartResponse(status, headers) =>
      p.StartResponse(status, headers);
      return None;
    case Write(data, end) =>
      p.Write(data, end);
      return None;
    case Fail(code, message) =>
      p.Fail(code, message);
      return None;
  }

  // What every ServerStep guarantees: plaintext is released only by the step
  // that authenticated the frame, the handler runs only after a plaintext byte
  // authenticated, and a terminal action ends its list.
  predicate Contract(s: SState, e: SEvent, r: (SState, seq<SAction>))
  {
    && (!NoEmit(r.1) ==> e.AeadOpenResult? && e.ok)
    && (Dispatches(r.1) ==> r.0.phase.Running? && r.0.payload)
    && TerminalLast(r.1)
    && Inv(r.0)
  }

  // ---------------------------------------------------------------------------
  // Plaintext answers, as net/http's Error and the SPEC 5.4.2 problem document.

  function Text(s: string): bytes { seq(|s|, i requires 0 <= i < |s| => if s[i] as int < 0x80 then s[i] as int as uint8 else 0x3f) }
  const TextHeaders: Headers := [("Content-Type", "text/plain; charset=utf-8"), ("X-Content-Type-Options", "nosniff")]
  const DecryptText: string := "failed to decrypt request"
  const ReadText: string := "failed to read decrypted request body"
  const SetupText: string := "failed to setup response encryption"

  function Answer(s: SState, status: int, code: Code, message: string, text: string): (r: (SState, seq<SAction>))
    ensures r.0.phase.Ended? && |r.1| == 1 && r.1[0].Respond? && r.1[0].status == status && r.1[0].code == code
  {
    var ended := s.(phase := Ended);
    // SPEC 5.4.4: every 422 carries the same title, whatever failed.
    if status == 422 then
      (ended, [Respond(status, code, message, [("Content-Type", ProblemJsonMediaType)],
        Text("{\"type\":\"" + EV.Escape(KeyConfigProblemType) + "\",\"title\":\"" + EV.Escape(DecryptText) + "\"}\n"))])
    else (ended, [Respond(status, code, message, TextHeaders, Text(text + "\n"))])
  }

  function Refuse(s: SState, code: Code, message: string): (r: (SState, seq<SAction>))
    ensures r.0.phase.Ended? && |r.1| == 1 && r.1[0].Respond? && r.1[0].status == 400 && r.1[0].code == code
  {
    Answer(s, 400, code, message, DecryptText)
  }

  function AbortResponse(s: SState, code: Code): (r: (SState, seq<SAction>))
    ensures r.0.phase.Ended? && r.1 == [Write([], EV.Aborted(code))]
  {
    (s.(phase := Ended), [Write([], EV.Aborted(code))])
  }

  // ---------------------------------------------------------------------------
  // The request lane: the frame decoder and the HPKE opener. One frame is
  // opened at a time and its plaintext released as soon as it authenticates.

  datatype Lane = Lane(req: Req, dec: EV.Dec, payload: bool, acts: seq<SAction>)

  function OpenFrame(keys: EV.Ctx, f: Framed): SAction { AeadOpen(keys.key, ComputeNonce(keys.baseNonce, f.seqNo), f.ciphertext) }

  // Open the next frame of the chunk, or the chunk is done: at eof the body
  // ends, cleanly or truncated; otherwise plaintext was handed over or the
  // body is read on.
  function NextFrame(s: SState, dec: EV.Dec, frames: seq<Framed>, eof: bool, emitted: bool, payload: bool, emits: seq<SAction>): (l: Lane)
    ensures l.payload == payload && |l.acts| >= |emits| && l.acts[.. |emits|] == emits && (forall i :: |emits| <= i < |l.acts| ==> !l.acts[i].EmitPlaintext? && !Terminal(l.acts[i]))
  {
    if |frames| > 0 then
      // SPEC 4.3: a complete frame shorter than the tag is an authentication failure.
      if |frames[0].ciphertext| < AeadTagLength then Lane(ReqFailed(if frames[0].seqNo == 0 then 422 else 400, AeadDecryptFailed, "frame shorter than the AEAD tag"), dec, payload, emits)
      else Lane(Opening(frames, eof, emitted), dec, payload, emits + [OpenFrame(s.ctx, frames[0])])
    else if eof then
      Lane(if EV.Finish(dec).Some? then ReqFailed(400, FramingTruncated, "truncated request frame") else ReqDone, dec, payload, emits)
    else if emitted then Lane(Waiting, dec, payload, emits)
    else Lane(Reading(0), dec, payload, emits + [Read(EV.RequestBody)])
  }

  // The lane on one of its events: Chunk, StreamFailed or AeadOpenResult.
  function LaneStep(s: SState, req: Req, e: SEvent): (l: Lane)
    ensures !NoEmit(l.acts) ==> e.AeadOpenResult? && e.ok
    ensures s.payload ==> l.payload
    ensures forall i :: 0 <= i < |l.acts| ==> !Terminal(l.acts[i])
  {
    var unexpected := Lane(ReqFailed(500, Transport, "unexpected event"), s.dec, s.payload, []);
    match req {
      case Reading(empty) =>
        match e {
          case StreamFailed => Lane(ReqFailed(400, FramingTruncated, "failed to read request body"), s.dec, s.payload, [])
          case Chunk(data, eof) =>
            var (frames, dec, err) := EV.Push(s.dec, data);
            if err.Some? then Lane(ReqFailed(400, err.value, "invalid request framing"), dec, s.payload, [])
            else if |frames| == 0 && |data| == 0 && !eof then
              if empty + 1 == MaxEmptyReads then Lane(ReqFailed(400, FramingTruncated, "request body made no progress"), dec, s.payload, [])
              else Lane(Reading(empty + 1), dec, s.payload, [Read(EV.RequestBody)])
            else NextFrame(s, dec, frames, eof, false, s.payload, [])
          case _ => unexpected
        }
      case Opening(frames, eof, emitted) =>
        if !e.AeadOpenResult? || |frames| == 0 then unexpected
        else if !e.ok || |e.plaintext| + AeadTagLength != |frames[0].ciphertext| then
          Lane(ReqFailed(if frames[0].seqNo == 0 then 422 else 400, AeadDecryptFailed, "frame failed to authenticate"), s.dec, s.payload, [])
        else
          var got := |e.plaintext| > 0;
          NextFrame(s, s.dec, frames[1..], eof, emitted || got, s.payload || got, if got then [EmitPlaintext(e.plaintext)] else [])
      case _ => unexpected
    }
  }

  // ---------------------------------------------------------------------------
  // The response lane: the response head and the derived-key sealer, one
  // frame of at most RequestFrameBytes per handler write.

  function RespHeaders(nonce: bytes): Headers { [(ResponseNonceHeader, EncodeHex(nonce)), ("Transfer-Encoding", "chunked")] }

  // The handler's status: an informational one is forwarded and does not
  // start the response; 204 and 205 cannot carry the frame a client needs
  // to authenticate a success (SPEC 5.2), so they are sent as 200.
  function Head(resp: Resp, status: int): (r: (Resp, seq<SAction>))
    ensures forall i :: 0 <= i < |r.1| ==> r.1[i].StartResponse?
    ensures r.0.framed == resp.framed && r.0.seal == resp.seal && r.0.keys == resp.keys
  {
    if resp.started then (resp, [])
    else if 100 <= status < 200 && status != 101 then (resp, [StartResponse(status, [])])
    else
      var final := if status == 204 || status == 205 then 200 else status;
      (resp.(started := true, status := final), [StartResponse(final, RespHeaders(resp.nonce))])
  }

  function SealNext(resp: Resp, plaintext: EV.Chunk, at: uint32, final: bool): (r: (Resp, seq<SAction>))
    requires at as nat <= |plaintext|
    ensures |r.1| == 1 && r.1[0].AeadSeal?
  {
    var n := EV.Min32(|plaintext| as uint32 - at, RequestFrameBytes);
    (resp.(seal := Sealing(plaintext, at, final)), [AeadSeal(resp.keys.key, ComputeNonce(resp.keys.baseNonce, resp.keys.seqNo), EV.Piece(plaintext, at, n))])
  }

  predicate ForRequest(e: SEvent) { e.HandlerRead? || e.Chunk? || e.StreamFailed? || e.AeadOpenResult? }

  // ---------------------------------------------------------------------------
  // The step function.

  function ServerStep(s: SState, e: SEvent): (r: (SState, seq<SAction>))
    requires Inv(s)
    ensures Contract(s, e, r)
  {
    match s.phase {
      case Idle => if e.RequestStart? then StepStart(s, e) else Answer(s, 500, Transport, "unexpected event", DecryptText)
      case Decap(h) =>
        match EV.HpkeStep(h, ToEvent(e)) {
          // A failed decapsulation recovers like a stale client key: 422 (SPEC 5.4.2).
          case HFailed(code, message) => Answer(s, if code == Transport then 500 else 422, code, message, DecryptText)
          case HContinue(next, a) => (s.(phase := Decap(next)), [ToAction(a)])
          case HReady(ctx, _) => (s.(phase := Peek(Reading(0)), ctx := ctx), [Read(EV.RequestBody)])
        }
      case Peek(req) =>
        var l := LaneStep(s, req, e);
        var s' := s.(dec := l.dec, payload := l.payload);
        match l.req {
          case ReqFailed(status, code, message) =>
            if l.payload then Derive(s', l.req, l.acts) else Answer(s', status, code, message, ReadText)
          case ReqDone =>
            if l.payload then Derive(s', ReqDone, l.acts) else Answer(s', 400, FramingTruncated, "encrypted request ended before any plaintext", ReadText)
          case Waiting =>
            if l.payload then Derive(s', Waiting, l.acts) else (s'.(phase := Peek(Reading(0))), l.acts + [Read(EV.RequestBody)])
          case _ => (s'.(phase := Peek(l.req)), l.acts)
        }
      case Deriving(stage, job, req, nonce, secret, prk, key) =>
        if stage == 1 then
          if !e.RandomResult? then Answer(s, 500, Transport, "unexpected event", SetupText)
          else if |e.data| != ResponseNonceLength then Answer(s, 500, HpkeSetupFailed, "random bytes have the wrong length", SetupText)
          else
            // SPEC 4.4: salt = enc || nonce, then "key" and "nonce" expansions.
            var next := EV.Extract(s.enc + e.data, secret);
            (s.(phase := Deriving(2, next, req, e.data, secret, [], [])), [ToAction(EV.JobAction(next))])
        else match EV.JobStep(job, ToEvent(e)) {
          case JobFailed(code, message) => Answer(s, 500, code, message, SetupText)
          case Pending(next, a) => (s.(phase := Deriving(stage, next, req, nonce, secret, prk, key)), [ToAction(a)])
          case Output(out) =>
            if stage == 0 then (s.(phase := Deriving(1, job, req, nonce, out, [], [])), [RandomBytes(ResponseNonceLength)])
            else if stage == 2 then
              var next := EV.Expand(out, Ascii(ResponseKeyLabel), KeyLength);
              (s.(phase := Deriving(3, next, req, nonce, secret, out, [])), [ToAction(EV.JobAction(next))])
            else if stage == 3 then
              var next := EV.Expand(prk, Ascii(ResponseNonceLabel), NonceLength);
              (s.(phase := Deriving(4, next, req, nonce, secret, prk, out)), [ToAction(EV.JobAction(next))])
            else if |key| == KeyLength && |out| == NonceLength then
              var k: EV.Key := key;
              var n: EV.NonceBase := out;
              (s.(phase := Running(req, Resp(EV.Ctx(k, n, [], 0), nonce, false, 0, false, NoSeal))), [Dispatch])
            else Answer(s, 500, HpkeSetupFailed, "HKDF expand returned the wrong length", SetupText)
        }
      case Running(req, resp) => if ForRequest(e) then StepRequest(s, req, resp, e) else StepResponse(s, req, resp, e)
      case Ended => (s, if e.HandlerRead? then [Close(EV.RequestBody)] else [])
    }
  }

  // SPEC 4.1, 5.2: the encapsulated key is single-valued, strict hex of the
  // KEM's length; an absent key passes the request through.
  function StepStart(s: SState, e: SEvent): (r: (SState, seq<SAction>))
    requires e.RequestStart?
    ensures Contract(s, e, r)
  {
    var keys := HeaderValues(e.headers, EncapsulatedKeyHeader);
    if |keys| == 0 then (s.(phase := Ended), [PassRequest])
    else if |keys| > 1 then Refuse(s, InvalidEncapsulatedKey, "duplicate " + EncapsulatedKeyHeader + " header")
    else if keys[0] == "" then Refuse(s, InvalidEncapsulatedKey, "missing " + EncapsulatedKeyHeader + " header")
    else match DecodeHex(keys[0]) {
      case None => Refuse(s, InvalidEncapsulatedKey, "invalid encapsulated key")
      case Some(enc) =>
        if |enc| != RequestEncLength then Refuse(s, InvalidEncapsulatedKey, "encapsulated key has the wrong length")
        else if !e.hasBody then Refuse(s, FramingTruncated, "encrypted request has no frame")
        else match EV.RecipientStart(s.sk, s.pk, enc, Ascii(HpkeRequestInfo)) {
          case HContinue(h, a) => (s.(phase := Decap(h), enc := enc), [ToAction(a)])
          case _ => Answer(s, 500, Transport, "unexpected event", DecryptText)
        }
    }
  }

  // The first plaintext byte authenticated: export, then the response keys.
  function Derive(s: SState, req: Req, emits: seq<SAction>): (r: (SState, seq<SAction>))
    requires s.payload
    ensures r.0.phase.Deriving? && r.0.payload && |r.1| == |emits| + 1 && r.1[.. |emits|] == emits && r.1[|emits|].HmacSha256?
  {
    var job := EV.ExportJob(s.ctx, Ascii(ExportLabel), ExportLength);
    (s.(phase := Deriving(0, job, req, [], [], [], [])), emits + [ToAction(EV.JobAction(job))])
  }

  function StepRequest(s: SState, req: Req, resp: Resp, e: SEvent): (r: (SState, seq<SAction>))
    requires s.phase == Running(req, resp) && s.payload
    ensures Contract(s, e, r)
  {
    if e.HandlerRead? then
      match req {
        case Waiting => (s.(phase := Running(Reading(0), resp)), [Read(EV.RequestBody)])
        case ReqDone => (s, [Close(EV.RequestBody)])
        case ReqFailed(_, code, message) => (s, [Fail(code, message)])
        case _ => (s.(phase := Running(ReqFailed(400, Transport, "unexpected event"), resp)), [Fail(Transport, "unexpected event")])
      }
    else
      var l := LaneStep(s, req, e);
      var s' := s.(dec := l.dec, payload := l.payload, phase := Running(l.req, resp));
      match l.req {
        case ReqFailed(_, code, message) => (s', l.acts + [Fail(code, message)])
        case ReqDone => (s', l.acts + [Close(EV.RequestBody)])
        case _ => (s', l.acts)
      }
  }

  function StepResponse(s: SState, req: Req, resp: Resp, e: SEvent): (r: (SState, seq<SAction>))
    requires s.phase == Running(req, resp) && s.payload && !ForRequest(e)
    ensures Contract(s, e, r)
  {
    match e {
      case HandlerHead(status) =>
        var (r, acts) := Head(resp, status);
        (s.(phase := Running(req, r)), acts)
      case HandlerChunk(data) =>
        if !resp.seal.NoSeal? || |data| > EV.MaxReadBytes then AbortResponse(s, Transport)
        else
          var (r, acts) := Head(resp, 200);
          if |data| == 0 then (s.(phase := Running(req, r)), acts)
          else
            var (r2, acts2) := SealNext(r, data, 0, false);
            (s.(phase := Running(req, r2)), acts + acts2)
      case AeadSealResult(ct) =>
        match resp.seal {
          case Sealing(plaintext, offset, final) =>
            var size := |plaintext| as uint32;
            var at := EV.Min32(offset, size);
            var n := EV.Min32(size - at, RequestFrameBytes);
            if |ct| != n as nat + AeadTagLength then AbortResponse(s, HpkeSetupFailed)
            else if resp.keys.seqNo == EV.MaxSeq then AbortResponse(s, SequenceOverflow)
            else
              var bumped := resp.(keys := EV.Bump(resp.keys), framed := true, seal := NoSeal);
              var frame := Write(Frame(ct), EV.More);
              if at + n < size then
                var (r, acts) := SealNext(bumped, plaintext, at + n, final);
                (s.(phase := Running(req, r)), [frame] + acts)
              else if final then (s.(phase := Ended), [frame, Close(EV.ResponseBody)])
              else (s.(phase := Running(req, bumped)), [frame])
          case NoSeal => AbortResponse(s, Transport)
        }
      case HandlerDone =>
        if !resp.seal.NoSeal? then AbortResponse(s, Transport)
        else match req {
          // SPEC 5.2: a frame that failed after the handler started. Nothing
          // sent yet: the protocol status; otherwise abort the response.
          case ReqFailed(status, code, message) =>
            if resp.started then AbortResponse(s, code) else Answer(s, status, code, message, ReadText)
          case _ =>
            // SPEC 5.3: a response with no frame gets one sealing empty
            // plaintext, unless its status cannot carry a body at all.
            var (r, acts) := Head(resp, 200);
            if r.framed || r.status == 101 || r.status == 304 then (s.(phase := Ended), acts + [Close(EV.ResponseBody)])
            else
              var (r2, acts2) := SealNext(r, [], 0, true);
              (s.(phase := Running(req, r2)), acts + acts2)
        }
      case _ => AbortResponse(s, Transport)
    }
  }

  // ---------------------------------------------------------------------------
  // Proofs (ghost only): the server's invariant, lanes, result validation and
  // key binding, as EHBPEvents does for the client.

  ghost function ReqOf(s: SState): Option<Req>
  {
    match s.phase
    case Peek(req) => Some(req)
    case Deriving(_, _, req, _, _, _, _) => Some(req)
    case Running(req, _) => Some(req)
    case _ => None
  }

  // The response key derivation is HKDF over this request's export, enc and a fresh 32-byte nonce (SPEC 4.4.1).
  ghost predicate DerivingInv(s: SState)
    requires s.phase.Deriving?
  {
    var p := s.phase;
    && p.stage <= 4
    && (p.stage == 0 ==> EV.Continues(p.job, EV.ExportJob(s.ctx, Ascii(ExportLabel), ExportLength)))
    && (p.stage == 2 ==> p.job.JExtract? && p.job.salt == s.enc + p.nonce && |p.nonce| == ResponseNonceLength && p.job.ikm == p.secret)
    && (p.stage == 3 ==> EV.Continues(p.job, EV.Expand(p.prk, Ascii(ResponseKeyLabel), KeyLength)) && |p.nonce| == ResponseNonceLength)
    && (p.stage == 4 ==> EV.Continues(p.job, EV.Expand(p.prk, Ascii(ResponseNonceLabel), NonceLength)) && |p.key| == KeyLength && |p.nonce| == ResponseNonceLength)
  }

  ghost predicate SInv(s: SState)
  {
    && Inv(s)
    && (ReqOf(s).Some? && ReqOf(s).value.Opening? ==> var fr := ReqOf(s).value.frames; |fr| > 0 && EV.FramesEndAt(fr, s.dec.next) && (s.payload ==> fr[0].seqNo >= 1))
    && (s.payload ==> s.dec.next >= 1)
    && (s.phase.Idle? || s.phase.Decap? ==> !s.payload)
    // a 422 names a failure before any plaintext (SPEC 5.4.2)
    && (ReqOf(s).Some? && ReqOf(s).value.ReqFailed? && ReqOf(s).value.status == 422 ==> !s.payload)
    && (s.phase.Deriving? ==> DerivingInv(s))
    && (s.phase.Running? ==> |s.phase.resp.nonce| == ResponseNonceLength)
  }

  lemma ServerInitialInv(sk: bytes, pk: bytes)
    ensures SInv(ServerInitial(sk, pk))
  {}

  lemma LaneStepInv(s: SState, req: Req, e: SEvent)
    requires SInv(s) && ReqOf(s) == Some(req)
    ensures var l := LaneStep(s, req, e);
      && (l.req.Opening? ==> |l.req.frames| > 0 && EV.FramesEndAt(l.req.frames, l.dec.next) && (l.payload ==> l.req.frames[0].seqNo >= 1))
      && (l.req.ReqFailed? && l.req.status == 422 ==> !l.payload)
      && (l.payload ==> l.dec.next >= 1)
      && l.dec.next >= s.dec.next
  {
    match req {
      case Reading(empty) =>
        match e {
          case Chunk(data, eof) => EV.PushConsecutive(s.dec, data);
          case _ =>
        }
      case _ =>
    }
  }

  lemma {:isolate_assertions} ServerStepInv(s: SState, e: SEvent)
    requires SInv(s)
    ensures SInv(ServerStep(s, e).0)
  {
    match s.phase {
      case Peek(req) => LaneStepInv(s, req, e);
      case Deriving(stage, job, req, nonce, secret, prk, key) =>
        if stage != 1 {
          match EV.JobStep(job, ToEvent(e)) {
            case Pending(next, a) =>
              if stage == 0 { EV.JobStepContinues(job, ToEvent(e), EV.ExportJob(s.ctx, Ascii(ExportLabel), ExportLength)); }
              else if stage == 3 { EV.JobStepContinues(job, ToEvent(e), EV.Expand(prk, Ascii(ResponseKeyLabel), KeyLength)); }
              else if stage == 4 { EV.JobStepContinues(job, ToEvent(e), EV.Expand(prk, Ascii(ResponseNonceLabel), NonceLength)); }
            case _ =>
          }
        }
      case Running(req, resp) => if ForRequest(e) && !e.HandlerRead? { LaneStepInv(s, req, e); }
      case _ =>
    }
  }

  // ---- Nonce uniqueness on the server: the response lane seals, the request lane opens.

  ghost predicate HasSeal(acts: seq<SAction>) { exists k :: 0 <= k < |acts| && acts[k].AeadSeal? }
  ghost predicate OneSeal(acts: seq<SAction>) { forall k, l :: 0 <= k < |acts| && 0 <= l < |acts| && acts[k].AeadSeal? && acts[l].AeadSeal? ==> k == l }
  ghost predicate HasOpen(acts: seq<SAction>) { exists k :: 0 <= k < |acts| && acts[k].AeadOpen? }
  ghost predicate OneOpen(acts: seq<SAction>) { forall k, l :: 0 <= k < |acts| && 0 <= l < |acts| && acts[k].AeadOpen? && acts[l].AeadOpen? ==> k == l }

  ghost function SealView(s: SState): EV.View
  {
    match s.phase
    case Running(_, resp) => EV.MkView(true, false, resp.seal.Sealing?, resp.keys.seqNo as nat, resp.keys.key, resp.keys.baseNonce)
    case Ended => EV.MkView(true, true, false, 0, [], [])
    case _ => EV.MkView(false, false, false, 0, [], [])
  }

  lemma {:isolate_assertions} StepSealView(s: SState, e: SEvent)
    requires SInv(s)
    ensures var r := ServerStep(s, e); var w := SealView(r.0);
      && EV.ViewStep(SealView(s), w, HasSeal(r.1)) && OneSeal(r.1)
      && forall k :: 0 <= k < |r.1| && r.1[k].AeadSeal? ==> r.1[k].key == EV.VKey(w) && r.1[k].nonce == ComputeNonce(EV.Base(w), EV.Mark(w) as uint64)
  {}

  ghost function OpenView(s: SState): EV.View
  {
    var req := ReqOf(s);
    var out := req.Some? && req.value.Opening?;
    EV.MkView(s.phase.Peek? || s.phase.Deriving? || s.phase.Running? || s.phase.Ended?,
      s.phase.Ended? || (req.Some? && (req.value.ReqDone? || req.value.ReqFailed?)),
      out,
      if out && |req.value.frames| > 0 then req.value.frames[0].seqNo as nat else s.dec.next as nat,
      s.ctx.key, s.ctx.baseNonce)
  }

  lemma {:isolate_assertions} StepOpenView(s: SState, e: SEvent)
    requires SInv(s)
    ensures var r := ServerStep(s, e); var w := OpenView(r.0);
      && EV.ViewStep(OpenView(s), w, HasOpen(r.1)) && OneOpen(r.1)
      && forall k :: 0 <= k < |r.1| && r.1[k].AeadOpen? ==> r.1[k].key == EV.VKey(w) && r.1[k].nonce == ComputeNonce(EV.Base(w), EV.Mark(w) as uint64)
  {
    if e.Chunk? { EV.PushConsecutive(s.dec, e.data); }
    match s.phase {
      case Peek(req) => LaneStepInv(s, req, e);
      case Running(req, resp) => if ForRequest(e) && !e.HandlerRead? { LaneStepInv(s, req, e); }
      case _ =>
    }
  }

  ghost predicate IsRun(states: seq<SState>, events: seq<SEvent>)
  {
    |states| == |events| + 1 && forall k :: 0 <= k < |events| ==> Inv(states[k]) && states[k + 1] == ServerStep(states[k], events[k]).0
  }

  ghost function Acts(states: seq<SState>, events: seq<SEvent>, k: nat): seq<SAction>
    requires IsRun(states, events) && k < |events|
  {
    ServerStep(states[k], events[k]).1
  }

  lemma RunInv(states: seq<SState>, events: seq<SEvent>, k: nat)
    requires IsRun(states, events) && SInv(states[0]) && k < |states|
    ensures SInv(states[k])
  { if k > 0 { RunInv(states, events, k - 1); ServerStepInv(states[k - 1], events[k - 1]); } }

  // Two response frames of one exchange are sealed under the same key with different nonces.
  lemma ResponseNoncesDistinct(states: seq<SState>, events: seq<SEvent>, i: nat, j: nat, ki: nat, kj: nat)
    requires IsRun(states, events) && SInv(states[0]) && i < j < |events|
    requires ki < |Acts(states, events, i)| && Acts(states, events, i)[ki].AeadSeal?
    requires kj < |Acts(states, events, j)| && Acts(states, events, j)[kj].AeadSeal?
    ensures var a, b := Acts(states, events, i)[ki], Acts(states, events, j)[kj]; a.key == b.key && a.nonce != b.nonce
  {
    var views := seq(|states|, k requires 0 <= k < |states| => SealView(states[k]));
    var issued := seq(|events|, k requires 0 <= k < |events| => HasSeal(Acts(states, events, k)));
    forall k | 0 <= k < |events| ensures EV.ViewStep(views[k], views[k + 1], issued[k]) { RunInv(states, events, k); StepSealView(states[k], events[k]); }
    EV.MarksIncrease(views, issued, i, j);
    RunInv(states, events, i); StepSealView(states[i], events[i]);
    RunInv(states, events, j); StepSealView(states[j], events[j]);
    var vi, vj := views[i + 1], views[j + 1];
    ComputeNonceInjective(EV.Base(vi), EV.Mark(vi) as uint64, EV.Mark(vj) as uint64);
  }

  // Two request frames of one exchange are opened under the same key with different nonces.
  lemma RequestNoncesDistinct(states: seq<SState>, events: seq<SEvent>, i: nat, j: nat, ki: nat, kj: nat)
    requires IsRun(states, events) && SInv(states[0]) && i < j < |events|
    requires ki < |Acts(states, events, i)| && Acts(states, events, i)[ki].AeadOpen?
    requires kj < |Acts(states, events, j)| && Acts(states, events, j)[kj].AeadOpen?
    ensures var a, b := Acts(states, events, i)[ki], Acts(states, events, j)[kj]; a.key == b.key && a.nonce != b.nonce
  {
    var views := seq(|states|, k requires 0 <= k < |states| => OpenView(states[k]));
    var issued := seq(|events|, k requires 0 <= k < |events| => HasOpen(Acts(states, events, k)));
    forall k | 0 <= k < |events| ensures EV.ViewStep(views[k], views[k + 1], issued[k]) { RunInv(states, events, k); StepOpenView(states[k], events[k]); }
    EV.MarksIncrease(views, issued, i, j);
    RunInv(states, events, i); StepOpenView(states[i], events[i]);
    RunInv(states, events, j); StepOpenView(states[j], events[j]);
    var vi, vj := views[i + 1], views[j + 1];
    ComputeNonceInjective(EV.Base(vi), EV.Mark(vi) as uint64, EV.Mark(vj) as uint64);
  }

  // ---- Result validation on the server.

  ghost predicate IsResult(e: SEvent) { e.RandomResult? || e.X25519Result? || e.HmacResult? || e.AeadSealResult? || e.AeadOpenResult? }

  ghost function SealLen(seal: Sealing): nat
    requires seal.Sealing?
  {
    var size := |seal.plaintext| as uint32;
    var at := EV.Min32(seal.offset, size);
    EV.Min32(size - at, RequestFrameBytes) as nat
  }

  ghost predicate WellFormed(s: SState, e: SEvent)
  {
    match e
    case RandomResult(data) => |data| == ResponseNonceLength
    case X25519Result(point) => |point| == 32
    case HmacResult(mac) => |mac| == HashLength
    case AeadSealResult(ct) => s.phase.Running? && s.phase.resp.seal.Sealing? && |ct| == SealLen(s.phase.resp.seal) + AeadTagLength
    case AeadOpenResult(ok, pt) => ok && ReqOf(s).Some? && ReqOf(s).value.Opening? && |ReqOf(s).value.frames| > 0 && |pt| + AeadTagLength == |ReqOf(s).value.frames[0].ciphertext|
    case _ => true
  }

  ghost predicate NoCrypto(acts: seq<SAction>)
  {
    forall k :: 0 <= k < |acts| ==> !(acts[k].AeadSeal? || acts[k].AeadOpen? || acts[k].X25519? || acts[k].RandomBytes?)
  }

  ghost function RespKeys(s: SState): Option<EV.Ctx> { if s.phase.Running? then Some(s.phase.resp.keys) else None }

  // A malformed result ends the exchange, or fails the request lane for good: nothing is opened, sealed or emitted
  // with it, and no context is created or changed. (A failed request lane still derives the response keys so the
  // handler's next read can fail, SPEC 5.2; that is HMAC only.)
  lemma {:isolate_assertions} MalformedResultRefused(s: SState, e: SEvent)
    requires SInv(s) && IsResult(e) && !WellFormed(s, e)
    ensures var r := ServerStep(s, e);
      && (r.0.phase.Ended? || (ReqOf(r.0).Some? && ReqOf(r.0).value.ReqFailed?))
      && NoCrypto(r.1) && NoEmit(r.1) && !Dispatches(r.1)
      && r.0.ctx == s.ctx && (RespKeys(r.0).Some? ==> RespKeys(r.0) == RespKeys(s))
  {}

  // ---- Key binding on the server.

  lemma {:isolate_assertions} StepKeyFacts(s: SState, e: SEvent)
    requires SInv(s)
    ensures var r := ServerStep(s, e);
      // the recipient context is created once, by decapsulating this request's enc
      && (r.0.ctx != s.ctx ==> s.phase.Decap? && r.0.phase.Peek? && EV.HpkeStep(s.phase.hpke, ToEvent(e)).HReady? && r.0.ctx == EV.HpkeStep(s.phase.hpke, ToEvent(e)).ctx && r.0.ctx.seqNo == 0)
      && (r.0.enc != s.enc ==> s.phase.Idle? && r.0.phase.Decap? && |r.0.enc| == RequestEncLength && r.0.phase.hpke == EV.HDh(r.0.enc, s.pk, Ascii(HpkeRequestInfo)))
      // the response context is created once, from the last expansion of the derivation over this request's export,
      // enc and nonce, and afterwards only advanced
      && (RespKeys(r.0).Some? && RespKeys(r.0) != RespKeys(s) ==>
            || (&& s.phase.Deriving? && s.phase.stage == 4 && EV.JobStep(s.phase.job, ToEvent(e)).Output?
                && RespKeys(r.0) == Some(EV.Ctx(s.phase.key, EV.JobStep(s.phase.job, ToEvent(e)).data, [], 0))
                && r.0.phase.Running? && r.0.phase.resp.nonce == s.phase.nonce && DerivingInv(s))
            || (s.phase.Running? && s.phase.resp.keys.seqNo < EV.MaxSeq && RespKeys(r.0) == Some(EV.Bump(s.phase.resp.keys))))
      && (s.phase.Running? && r.0.phase.Running? ==> r.0.phase.resp.nonce == s.phase.resp.nonce && r.0.phase.resp.keys.key == s.phase.resp.keys.key && r.0.phase.resp.keys.baseNonce == s.phase.resp.keys.baseNonce)
      // the response head carries the nonce the keys were derived from
      && (forall k :: 0 <= k < |r.1| && r.1[k].StartResponse? && |r.1[k].headers| > 0 ==>
            s.phase.Running? && r.1[k].headers == RespHeaders(s.phase.resp.nonce))
  {}
}
