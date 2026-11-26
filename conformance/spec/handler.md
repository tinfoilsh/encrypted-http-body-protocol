# The core and the residue

Everything the protocol decides is Dafny: `dafny/ehbp.dfy` (module `EHBP`),
`dafny/ehbp_events.dfy` (module `EHBPEvents`) and `dafny/ehbp_server.dfy`
(module `EHBPServer`, Go only); `dafny/ehbp_tests.dfy` holds their tests and
is never translated. Each
SDK keeps a *residue*: native bindings the core drives through events and
actions, a pump loop, and an API shim. What is derived from a machine-readable
source (the error codes and constants, the `core` accessor, the FFI coders) is
rendered by `conformance/tools/gen.py`; everything else is committed code that
`conformance/tools/check.py` holds to the shape described here. Every sentence
below names the file it can be checked against.

## 1. Purpose and trust boundary

Verified (`dafny verify`, run by the `check-generated` job of
`.github/workflows/test.yml`):

- `dafny/ehbp.dfy`: the error codes (`Code`, `CodeString`, `Codes`), the
  protocol constants (`KemX25519` .. `MaxEmptyReads`), hex
  (`DecodeHex`, `EncodeHex`), the nonce (`ComputeNonce`, `NonceFor`), the
  key configuration (`ParseConfig`, `MarshalConfig`, `CheckPublicKey`), the
  token (`Token`, `ValidateTokenFields`), the response classifier
  (`Classify`, `ClassifyProblem`, `ClassifyDiscovery`), the origin and
  request guards (`MakeOrigin`, `ValidateRequest`, `DropFraming`).
- `dafny/ehbp_events.dfy`, module `EHBPEvents`: the client exchange as a
  pure step function (`Step`), HKDF as a job over `HmacSha256` results
  (`Job`, `JobStep`), HPKE base mode over `RandomBytes`, `X25519` and
  `HmacSha256` (`Hpke`, `HpkeStep`), the frame decoder (`Dec`, `Push`,
  `Finish`), the JSON parser (`ParseJson`), the session rules
  (`SessionStore`, `SessionApply`) and the self-check vectors
  (`SelfCheckActions`, `SelfCheckJudge`).
- `dafny/ehbp_server.dfy`, module `EHBPServer`: the server exchange
  (`ServerInitial`, `ServerStep`), used by the Go middleware only
  (`internal/eventresidue/server.go`, `identity/middleware.go`).
- `dafny/spec_rules.dfy`, module `SpecRules`: the normative rules of
  `SPEC.md` as lemmas over the two machines and the pure functions (section
  3); verified, never translated.

Native and trusted, per language:

- Five crypto primitives, one per `Action` constructor: `RandomBytes`,
  `X25519`, `HmacSha256`, `AeadSeal` (AES-256-GCM, empty AAD), `AeadOpen`.
- One HTTP transaction: `send`, `write`, `read`, `close` (section 4).
- A mutex around one `SessionStore` value.
- The Dafny backends and their runtimes (`dafny/gen/go`,
  `dafny/gen-events/{go,js,py,rs,java}`) and the runtime patches of
  `dafny/patch-runtime.py` (section 8).
- For Swift, the Rust bundle behind the C ABI of `rust/ffi` and the coders
  on both sides of it (section 10).

Nothing in a residue inspects a status code, a header value, a nonce, a
frame length or a JSON member: it hands them to the core as events.

Every backend generates a string rendering for each datatype (Go `String`,
JS `toString`, Python `__dafnystr__` and `__repr__`, Rust `Debug` and
`DafnyPrint`, Java `toString`). The patch step (`SECRET_TYPES` in
`dafny/patch-runtime.py`) rewrites the generated printer of every constructor
that holds key material to `<Module>.<Datatype>.<Ctor>(<redacted>)`:
`EHBP.Token`; in `EHBPEvents` the `Event` results `RandomResult`,
`X25519Result`, `HmacResult`, the `Action`s `PublishToken`, `X25519`,
`HmacSha256`, `AeadSeal`, `AeadOpen`, both `Job` constructors, `JobOut.Output`,
`Ctx`, `Hpke.HEnc`, `Hpke.HSchedule` and `Response.AwaitKeys`; in
`EHBPServer` the same crypto events and actions, `Phase.Deriving` and `SState`.
Containers (`State`, `SessionStore`, `HpkeOut`, the `Response` body phases)
print those fields through the constructor's own printer, so logging any core
value cannot expose a secret. Equality and hashing are unchanged.

## 2. The event model

The declarations of `dafny/ehbp_events.dfy`, verbatim in constructor order
(the order is the wire tag of the C ABI, `swift-ffi.md`):

```
datatype Stream  = RequestBody | ResponseBody
datatype BodyEnd = More | Done | Aborted(code: Code)

datatype Event =
  | Start(verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody)
  | DiscoverStart
  | SessionBegun(generation)
  | RandomResult(data) | X25519Result(point) | HmacResult(mac)
  | AeadSealResult(ciphertext) | AeadOpenResult(ok, plaintext)
  | ResponseHead(status, headers, redirected)
  | Chunk(stream, data, eof) | StreamFailed(stream)
  | CallerRead | CallerClose

datatype Action =
  | BeginSession | PublishToken(generation, exportedSecret, requestEnc) | ClearToken(generation)
  | RandomBytes(length) | X25519(scalar, point) | HmacSha256(key, data)
  | AeadSeal(key, nonce, plaintext) | AeadOpen(key, nonce, ciphertext)
  | Send(verb, url, headers, hasBody) | Write(data, end) | Read(stream) | Close(stream)
  | EmitPlaintext(data)
  | Passthrough(status, headers, prefix) | Done(status, headers) | Finished
  | Discovered(publicKey) | Fail(code, message)
```

Every field is a tag, integer, boolean, byte sequence, string or
`Headers` (`seq<(string, string)>`), so the same `Step` is driven over a C
interface. The result of a crypto or I/O action is the event of the same
name; `Send` answers with `ResponseHead` or `StreamFailed(ResponseBody)`,
`Read(stream)` with `Chunk(stream, ..)` or `StreamFailed(stream)`;
`BeginSession` answers with `SessionBegun`; `PublishToken`, `ClearToken`,
`Write` and `Close` produce no event. `Write`'s `end` is `More`, `Done`
(the upload ends after this data) or `Aborted(code)` (the upload fails with
that code). The caller's reads of a decrypted body are `CallerRead` events
and its close is `CallerClose`.

Entry points: `Initial(origin, publicKey)` is the state of a client; a
request starts with `Start(..)` and discovery with `DiscoverStart`.
`ResponseOnly(origin, token)` is a state that only decrypts: `DecryptStart`
and `DeriveStart` step it with a `ResponseHead`, and `KeysOf` reads the
derived key and nonce base once `Done` was emitted (the two token helpers
every SDK exposes, section 7). The server has its own `SEvent` and
`SAction` (`RequestStart`, `HandlerRead`, `HandlerHead`, `HandlerChunk`,
`HandlerDone`; `PassRequest`, `Respond`, `Dispatch`, `StartResponse`, ..)
with the crypto events and actions mapped one to one (`ToEvent`,
`ToAction`).

## 3. Proven properties

Predicates of `dafny/ehbp_events.dfy`, each stated in one sentence:

- `Terminal(a)`: `Fail`, `Finished`, `Passthrough`, `Discovered` and
  `Close` are the actions that end a step's list.
- `Ends(acts)`: the list contains a terminal action. `NoClear(acts)`: no
  `ClearToken`. `ClearsOnce(acts, g)`: exactly one `ClearToken`, and it
  carries generation `g`. `NoEmit(acts)`: no `EmitPlaintext`.
- `Contract(s, e, r)`, which `Step` ensures: a list that ends leaves the
  token unpublished and clears it exactly once if it was published and
  never otherwise; a list that does not end never clears it; and plaintext
  is emitted only by the step whose event is a successful `AeadOpenResult`
  in the `Opening` response state.
- `Ending(s, r)`, which `End`, `Abort` and `Unexpected` ensure: the list
  ends, the token is unpublished, cleared as `Contract` says, and nothing
  is emitted.
- `JobStep` ensures an `Output` has the requested length (`HashLength`
  for extract); `Piece` ensures it is the slice it stands for.
- Server (`EHBPServer`): `Inv(s)`, a `Deriving` or `Running` phase has seen
  an authenticated plaintext byte; `TerminalLast(acts)`, a terminal server
  action (`PassRequest`, `Respond`, `Dispatch`, `Close(ResponseBody)`,
  `Write(_, Aborted)`) is the last of its list; `Contract(s, e, r)`, which
  `ServerStep` ensures: plaintext only on a successful `AeadOpenResult`,
  `Dispatch` only in `Running` with a payload, `TerminalLast`, and `Inv`.

Lemmas of `dafny/ehbp.dfy`: `CodeStringsAreDistinct`,
`MarshalParseRoundTrip`, `ClassifyIsTotal`; and, ghost only, after the
tests: `ComputeNonceInjective` (`ComputeNonce(base, a) != ComputeNonce(base,
b)` for `a != b`, through `ByteAtDetermines`: the eight low bytes determine
a `uint64`), `ComputeNonceZero` (`ComputeNonce(base, 0) == base`),
`NonceByte` (byte `j >= 4` of the nonce is `base[j] XOR` byte `11 - j` of the
sequence number), `DecodeEncodeHex` (`DecodeHex(EncodeHex(b)) == Some(b)`),
`EncodeHexLowercase`, `ValidateHeadersOk` / `ValidateHeadersFromReserved` (a
request validates iff no header is reserved), `DropFramingKeeps` /
`DropFramingComplete` (`DropFraming` removes exactly the framing headers),
`NoHeaderValues`.

Ghost proofs at the end of `EHBPEvents` (nothing compiled; the bundles are
unchanged apart from `expect` positions):

- The decoder as a stream: `Consecutive(fs, acc, from, upto)` (`fs` extends
  `acc` by frames numbered `from .. upto-1`); `FramesConsecutive`,
  `PushConsecutive` (`Push` numbers the frames it yields consecutively from
  `d.next`); `WFPending` (what is left pending is never a complete, empty
  or oversized frame), `FramesPendingWF`; `FramesShift`, `FramesAppend`,
  `FramesPendingIrrelevant`, `FramesAcc`, `PushIsOneShot`, `PushAllIsOneShot`
  (`Push` over any chunking yields the frames, decoder and error of
  `Frames` over the concatenation); `Wire`, `Numbered`, `FramesOneFrame`,
  `WireFrames`, `FramingRoundTrip` (the concatenation of `Frame(ct_i)`,
  split however, decodes to `Framed(d.next + i, ct_i)` in order with no
  error). The sequence number is not on the wire (SPEC 4.3): the decoder
  assigns it, so a replayed or reordered frame is caught by the AEAD nonce,
  not the framing (`decrypt-response-replayed-frame`,
  `decrypt-response-reordered-frames`).
- `Inv(s)`, preserved by `Step` (`StepInv`) and true of `Initial` and
  `ResponseOnly`: encryption is committed to only with a plaintext byte in
  hand; `AwaitExport` runs the export job of this exchange's context
  (`Continues(job, ExportJob(s.ctx, "ehbp response", 32))`); `AwaitKeys`
  runs `Extract(token.requestEnc + nonce, token.exportedSecret)` then
  `Expand(prk, "key", 32)` then `Expand(prk, "nonce", 12)`
  (`AwaitKeysInv`); the frames of `Opening` are consecutive and end just
  before `dec.next` (`FramesEndAt`); the kept request headers are never
  reserved.
- Nonce uniqueness. A lane (`View`: live, dead, outstanding call, mark,
  key, base) is what one direction's AEAD calls look like from the state:
  `SealView` (the request lane: mark `ctx.seqNo`, outstanding while
  `Sealing`) and `OpenView` (the response lane: mark the frame being
  opened, else `dec.next`). `ViewStep(v, w, issued)` is what one step may
  do to a lane; `StepSealView` (`SealFacts`, proved per phase by
  `SealFactsExport`, `SealFactsUpload`, `SealFactsElsewhere`) and
  `StepOpenView` prove `Step` does only that, and that every `AeadSeal` / `AeadOpen` it issues uses the lane's key
  and `ComputeNonce(base, mark)`. `MarksIncrease`: along any run of views
  the marks of the issuing steps strictly increase under one key and base.
  `IsRun(states, events)`, `Acts`, `RunInv`; `RequestNoncesDistinct` and
  `ResponseNoncesDistinct`: two seals (two opens) of one run use the same
  key and different nonces.
- Result validation: `WellFormed(s, e)` (a `RandomResult` / `X25519Result`
  of 32 bytes, an `HmacResult` of 32, an `AeadSealResult` of the
  outstanding plaintext plus the tag, an `AeadOpenResult` that is `ok` and
  the outstanding ciphertext minus the tag); `MalformedResultRefused`: any
  other result ends the exchange or aborts the upload (`Refused`), issues no
  crypto (`NoCrypto`), emits nothing, and leaves `ctx` and the response
  keys (`RespKeys`) unchanged. No check had to be added: every result event
  was already length-checked where it is consumed.
- Key binding (`StepKeyFacts`): `ctx` is set once, by `HReady` of this
  exchange's HPKE setup with `seqNo` 0, and afterwards only `Bump`ed; the
  token is set once, when published, and is constant while `Exchanging`;
  `PublishToken(g, secret, enc)` is action 0 of the step that completes the
  export job, with `g` the current generation, `enc` the setup's `enc`,
  `secret` the job's output, and `Send` (carrying
  `Ehbp-Encapsulated-Key: hex(enc)`) action 1; the response derivation
  starts from the token in flight and the nonce `Classify` returned for this
  head; the response context is created once, from the two expansions.

Ghost proofs at the end of `EHBPServer`, the same shape: `ReqOf`, `SInv`
(`Inv` plus: `Opening` frames consecutive before `dec.next` and, once a
payload byte authenticated, all at sequence number 1 or more; a
`ReqFailed(422)` lane and `Idle` / `Decap` have no payload; `DerivingInv`:
stage 0 runs the export job of `s.ctx`, stage 2 `Extract(s.enc + nonce,
secret)` with a 32-byte nonce, stages 3 and 4 the `"key"` and `"nonce"`
expansions; `Running` carries a 32-byte nonce), `LaneStepInv`,
`ServerStepInv`; `SealView` (the response lane), `OpenView` (the request
lane), `StepSealView`, `StepOpenView`, `IsRun`, `Acts`, `RunInv`,
`ResponseNoncesDistinct`, `RequestNoncesDistinct`; `WellFormed`,
`MalformedResultRefused` (a malformed result ends the exchange or fails the
request lane for good, issues no AEAD, emits nothing, never dispatches, and
leaves `ctx` and the response keys unchanged); `StepKeyFacts` (`ctx` is set
once by decapsulating this request's `enc`; the response context is created
once from the last expansion and carries the nonce `StartResponse` sends,
then is only `Bump`ed).

### SPEC rule to lemma or fixture

Every normative rule of `SPEC.md` that the core decides is a lemma of
`dafny/spec_rules.dfy`, named `Spec_<section>_<slug>` and documented by the
sentence it pins; a rule about the residue or the HTTP stack names the
fixture of `test-vectors/conformance` or the Dafny test that checks it.
`conformance/tools/tests/test_spec_rules.py` checks that every lemma, fixture
and test named here exists and that every `Spec_*` lemma is listed.

| SPEC | Rule | Proof |
| --- | --- | --- |
| 3.1 | discovery accepts only a 200 with the keys media type; no redirect is followed | `Spec_3_1_DiscoveryAccepts200AndKeysMediaTypeOnly` |
| 3.1 | media type compared case-insensitively, parameters ignored | test: `ClassifierPinsTheSpec`; native: `discover-content-type-params` |
| 3.1 | bytes after the first `key_config` are ignored | `Spec_3_1_TrailingBytesIgnored` |
| 3.2 | exactly one suite, `UNSUPPORTED_SUITE` otherwise | `Spec_3_2_ExactlyOneSupportedSuite` |
| 3.2 | the first config's 32-byte public key is used | `Spec_3_2_PublicKeyIs32Bytes` |
| 4.1 | `Ehbp-Encapsulated-Key` iff the body is encrypted | `Spec_4_1_EncapsulatedKeyIffEncrypted` |
| 4.1 | strict hex in, lowercase hex out | `Spec_4_1_StrictHex` |
| 4.1 | wire framing: chunked or `Content-Length`, never both | native: `e2e-caller-framing-headers`, `e2e-echo-large` |
| 4.2 | `Ehbp-Response-Nonce` is exactly 32 bytes | `Spec_4_2_ResponseNonceIs32Bytes` |
| 4.2 | servers set the nonce on encrypted responses | `Spec_4_2_ServerSetsResponseNonce` |
| 4.2 | receivers accept chunked or `Content-Length` | native: `e2e-echo-roundtrip`, `e2e-empty-response` |
| 4.2 | a plaintext response carries no EHBP header | `Spec_4_2_PlaintextResponseHasNoEhbpHeaders` |
| 4.2 | an empty nonce is `INVALID_RESPONSE_NONCE` whatever the status | `Spec_4_2_EmptyNonceIsInvalid` |
| 4.2 | a repeated header is refused on either side | `Spec_4_2_RepeatedHeaderRefused` |
| 4.2 | a coalesced nonce value is `INVALID_RESPONSE_NONCE` | `Spec_4_2_CoalescedNonceIsInvalid`; native: `e2e-duplicate-nonce-coalesced` |
| 4.3 | chunk = big-endian length of the ciphertext, then the ciphertext | `Spec_4_3_FrameIsLengthPrefixedCiphertext` |
| 4.3 | one sealer/opener per direction, reused for every chunk | `Spec_4_4_1_NoncesNeverRepeat`, `Spec_4_4_1_NoncesNeverRepeatOnTheServer` |
| 4.3 | a zero-length chunk is skipped and does not advance the sequence | `Spec_4_3_ZeroLengthFrameSkipped` |
| 4.3 | sequence number `i` names the i-th non-empty chunk | `Spec_4_3_SequenceNumbersConsecutive` |
| 4.3 | end of message is the end of the body, no sentinel | `Spec_4_3_FramingRoundTrip` |
| 4.3 | a length above 64 MiB is `CHUNK_TOO_LARGE` before allocation | `Spec_4_3_ChunkTooLargeRejectedOnThePrefix` |
| 4.3 | senders stream, frames of at most 64 KiB plaintext | `Spec_4_3_SenderFramesBounded`; native (memory): `e2e-large-body-3gib` |
| 4.3 | receivers read a length, that many bytes, open in order | `Spec_4_3_FramingRoundTrip` |
| 4.3 | no plaintext after a failed chunk or framing violation | `Spec_4_3_NoPlaintextAfterFailure` |
| 4.3 | a complete frame shorter than the tag fails authentication | `Spec_4_3_FrameShorterThanTagFails` |
| 4.4.1 | step 1: `Export("ehbp response", 32)` | `Spec_4_4_1_ExportLabelAndLength` |
| 4.4.1 | step 2: a random 32-byte response nonce | `Spec_4_4_1_ResponseNonceIs32RandomBytes` |
| 4.4.1 | steps 3-4: `Extract(concat(enc, nonce), secret)`, `Expand "key"` 32, `Expand "nonce"` 12 | `Spec_4_4_1_ResponseKeyDerivation` |
| 4.4.1 | step 5: nonce for chunk `i` is `aead_nonce XOR i` | `Spec_4_4_1_NonceIsBaseXorSequence` |
| 4.4.1 | step 5: AES-256-GCM with empty AAD | native: `residue-selfcheck` |
| 4.4.1 | the sequence starts at zero | `Spec_4_4_1_SequenceStartsAtZero` |
| 4.4.1 | request and response keys come from different derivations | `Spec_4_4_1_DirectionsUseDistinctDerivations` |
| 4.4.2 | response keys bound to `enc`, the secret and the nonce | native: `decrypt-response-wrong-request-enc`, `decrypt-response-wrong-exported-secret`, `decrypt-response-wrong-nonce` |
| 5.1 | encrypt iff a non-empty body; otherwise no key header | `Spec_5_1_EncryptIffNonEmptyBody` |
| 5.1 | a committed sender aborts without plaintext | `Spec_5_1_CommitOnlyAfterPlaintext` |
| 5.1 | reserved headers are `INVALID_INPUT` | `Spec_5_1_ReservedHeadersRefused` |
| 5.1 | cross-origin URL or credentials are `INVALID_INPUT` | `Spec_5_1_CrossOriginAndCredentialsRefused` |
| 5.1 | `Content-Length` and `Transfer-Encoding` are dropped, others kept | `Spec_5_1_FramingHeadersDropped` |
| 5.1 | caller transport parameters are preserved | native: `e2e-request-meta-encrypted`, `e2e-request-meta-bodyless` |
| 5.1 | with a nonce, decrypt whatever the status except 3xx | `Spec_5_1_DecryptWhateverTheStatus` |
| 5.1 | an invalid nonce, or none on 1xx/2xx, fails | `Spec_5_1_InvalidOrMissingNonceFails` |
| 5.1 | a 4xx/5xx without a nonce passes through and consumes the token | `Spec_5_1_PassthroughConsumesToken` |
| 5.1 | the response to a bodyless request is plain | `Spec_5_1_BodylessResponseIsPlain` |
| 5.2 | no key header: the request passes through | `Spec_5_2_PassThroughWithoutKey` |
| 5.2 | a malformed key or failed decapsulation is rejected before the handler | `Spec_5_2_MalformedKeyRejectedBeforeDispatch`, `Spec_5_4_2_Status422` |
| 5.2 | plaintext is delivered as it authenticates, never whole-body buffered | native: `e2e-large-body-256mib` |
| 5.2 | a failure after dispatch stops delivery; status if not started, abort if started | `Spec_5_2_FailureAfterDispatch` |
| 5.2 | open frames until a plaintext byte; 400 if the body ends first | `Spec_5_2_PlaintextBeforeDispatch` |
| 5.2 | an empty response carries one frame; 204/205 become 200 | `Spec_5_2_EmptyResponseCarriesAFrame` |
| 5.2 | an aborted response is a transport failure on the wire | native: `server-middleware-trailing-tamper` |
| 5.3 | a 3xx fails closed, nonce or not, never followed | `Spec_5_3_RedirectFailsClosed` |
| 5.3 | pass-through only for 4xx/5xx without a nonce | `Spec_5_3_PassthroughOnlyOnErrors` |
| 5.3 | a 1xx/2xx with a nonce needs an authenticated frame; an empty one counts | `Spec_5_3_SuccessNeedsAnAuthenticatedFrame` |
| 5.3 | 204/205 fail; header validation comes first | `Spec_5_3_BodylessSuccessFails` |
| 5.4.1 | fail closed: nothing released after an authentication failure | `Spec_5_4_1_FailClosed` |
| 5.4.2 | 400: malformed key, framing violation, later-frame failure | `Spec_5_4_2_Status400` |
| 5.4.2 | 422: decapsulation or first-frame failure | `Spec_5_4_2_Status422` |
| 5.4.2 | a 422 only before any plaintext was released | `Spec_5_4_2_422OnlyBeforePlaintext` |
| 5.4.2 | the 422 problem document: media type, `type`, `title` | `Spec_5_4_2_ProblemDocument` |
| 5.4.2 | client detection: 422, media type, no nonce, `type`, size cap | `Spec_5_4_2_ProblemDetection` |
| 5.4.2 | a 422 with a nonce is decrypted like any response | `Spec_5_4_2_Encrypted422IsDecrypted` |
| 5.4.3 | recovery: refresh the config, recreate, resend | native: `e2e-keyconfig-422` |
| 5.4.4 | no fine-grained cryptographic cause in error responses | `Spec_5_4_4_StableProblemTitle` |
| 5.5 | one class per failure; distinct, append-only codes | `Spec_5_5_CodesAreDistinct` |
| 5.5 | typed classes and the `<CODE>: <detail>` message | native: the error field of every fixture (`conformance/spec/errors.md`), `residue-selfcheck` |
| 6 | the token is obtainable before the request is sent | `Spec_6_TokenPublishedBeforeSend` |
| 6.1 | token = (export secret, `enc`) | `Spec_6_1_TokenIsExportAndEnc` |
| 6.1.1 | lowercase hex JSON fields, validated as 32 bytes | `Spec_6_1_1_TokenJsonIsLowercaseHex`; native: `token-roundtrip-vector` |
| 6.2 | decrypt from a token: the same derivation with the token's fields | `Spec_6_2_DecryptWithToken` |
| 6.2.1 | the original nonce; sequence from zero per non-empty frame | `Spec_6_2_1_SequenceFromZeroPerNonEmptyFrame` |
| 6.2.1 | buffer partial frames, emit after authentication, reject a partial frame at EOF | `Spec_6_2_1_PartialFrameRejectedAtEof` |
| 6.2.1 | a replayed response restarts at sequence zero | native: `decrypt-response-replayed-frame`, `decrypt-response-reordered-frames` |
| 6.3 | a token is consumed when the exchange ends, whatever the outcome | `Spec_6_3_TokenClearedExactlyOnceWhenExchangeEnds` |
| 6.3 | a new request supersedes the token | `Spec_6_3_NewRequestSupersedesToken` |
| 6.3 | tokens are scoped to one exchange | `Spec_6_3_TokenSetOncePerExchange` |
| 7.2 | a fresh HPKE setup per exchange | `Spec_7_2_FreshHpkePerExchange` |
| 7.3 | private keys protected, keys rotated, labels distinct across protocols | deployment: not checked |
| 7.4 | a bodyless request is sent plain and answered plain | `Spec_7_4_BodylessRequestIsPlain` |
| 7.4 | a server holding a key dispatches only after a plaintext byte | `Spec_7_4_ServerDispatchAfterAuth` |

Finding (5.4.4), fixed on this branch: the Go reference titled a 422 after a
failed decapsulation `failed to decrypt request` and after a first-frame
authentication failure `failed to read decrypted request body`, which
disclosed the cause. `EHBPServer.Answer` now uses one title for every 422;
`Spec_5_4_4_StableProblemTitle` proves the body and headers do not depend
on the failure.

Tests (`dafny test ehbp_tests.dfy`, same CI job; all in `ehbp_tests.dfy`,
so no bundle carries test code): `ConfigRoundTrip`,
`HexAndMediaType`, `ClassifierPinsTheSpec` (over `ehbp.dfy`);
`DeriveAndDecryptEntries`, `JsonStringsAreBoundedAndLinear`,
`ReferencePrimitivesMatchKnownAnswers`, `HpkeMatchesRfc9180Vector`,
`JsonParsesTheProtocolDocuments`, `DecoderSplitsAtAnyBoundary`,
`DriverHappyPath`, `DriverBodylessAndGuards`, `SessionRulesPinTheSpec`,
`DriverFailurePaths`, `DriverUploadLaneAndDiscovery`, `ServerHappyPath`,
`ServerRefusesBadKeys`, `ServerDecapsulationFailureIs422`,
`ServerTruncatedRequests`, `ServerEmptyResponseCarriesAFrame`. The RFC
9180 vector is driven through `HpkeStep` with reference SHA-256, HMAC and
X25519 written in Dafny for the tests only.

## 4. The residue layout

One file per language (`RESIDUES` in `conformance/tools/check.py`), the same
declarations in the same order (`CANONICAL`; names compared with case and
underscores removed), each section under a `<section>:` header comment, in
this order:

| Section | Bindings, in order | What it is |
| --- | --- | --- |
| crypto | `x25519`, `hmacSha256`, `aeadSeal`, `aeadOpen`, `randomBytes` | one native call each, bytes in, bytes out |
| http | `send`, `write`, `read`, `close` | the only block holding native state (an `Exchange` per request or discovery, its outcome, the body readers); `read` and `close` dispatch on the `Stream` tag, `write` on the `BodyEnd` tag |
| session | `beginSession`, `publishToken`, `clearToken`, `token` | a mutex around one `SessionStore`; every decision is `SessionApply` |
| pump | `run`, with the `Performer` methods (Go, Python, Kotlin) or `perform` (JavaScript, Rust, Swift) | section 5 |
| conversions | `seq`, `bytes`, `str`, `string`, `headerSeq`, `headerPairs` | the runtime boundary only |
| mapping | `code`, `error` | from the core's `CodeString`; no table of strings |

Nothing in a residue is rendered. Python's `Performer` methods sit inside
`Exchange`, after its `http` methods (a class cannot be split); the other
ports keep them in the `pump` section.

Files and line budgets (`RESIDUES` in `check.py`):
`internal/eventresidue/residue.go` 510, `python/src/ehbp/_residue.py` 370,
`kotlin/src/main/kotlin/sh/tinfoil/ehbp/residue/Residue.kt` 390,
`rust/src/residue.rs` 500, `js/src/residue.ts` 410,
`swift/Sources/EHBP/Residue.swift` 400. Swift has no `seq`, `bytes`, `str`,
`string`: bytes and strings cross the FFI as they are.

`check.py` fails on a section header missing or out of order (`layout`), a
missing or misordered binding (`bindings`), a file over budget (`budgets`),
or an action tag that no `Performer` method or `perform` case handles
(`actions`). Everything the core does not emit as an action is not in the
residue.

`read` hands the core one native chunk at a time: Go 128 KiB (`readChunk`
in `residue.go`), Python 64 KiB (`bounded` in `_residue.py`, re-slicing
larger caller chunks since the runtime holds a chunk as a list of ints), JS
64 KiB (`ReadChunkBytes` in `residue.ts`), Kotlin 64 KiB (`readChunk` in
`Residue.kt`), Rust and Swift the transport's own chunks (`read` in
`residue.rs`, `Residue.swift`). The core seals at most `RequestFrameBytes`
(64 KiB, `ehbp.dfy`) per frame and refuses a chunk of 2^32 bytes or more
(`MaxReadBytes`, `ehbp_events.dfy`).

## 5. The pump

Every residue writes this loop once, by hand:

```
run(first):
    events = [first]
    loop:
        if events is empty: return                   # a step may produce no event
        actions = Step(state, events.pop())          # the core decides
        for action in actions:
            if action is terminal (Passthrough, Done, Finished, Discovered, Fail):
                record the outcome; return
            if action is Send with a body:
                lane = run on the remaining actions  # the upload: performed concurrently
            match Perform(self, action):             # the core dispatches
                Got(event) -> events.push(event)
                Quiet      -> nothing
                Stop       -> return                 # the upload sink is gone; this lane ends
            if action is Send with a body: break     # the lane owns the rest of this list
```

`Perform(p: Performer, a: Action): Performed` in `dafny/ehbp_events.dfy` is
the dispatch: it matches every `Action` constructor, calls the `Performer`
method of the same name and wraps the result in the event of the same name:

```
BeginSession      -> Got(SessionBegun(p.BeginSession()))
PublishToken      -> p.PublishToken(generation, secret, enc); Quiet
ClearToken        -> p.ClearToken(generation); Quiet
RandomBytes(n)    -> Got(RandomResult(p.RandomBytes(n)))
X25519(s, q)      -> Got(X25519Result(p.X25519(s, q)))
HmacSha256(k, d)  -> Got(HmacResult(p.HmacSha256(k, d)))
AeadSeal(k, n, m) -> Got(AeadSealResult(p.AeadSeal(k, n, m)))
AeadOpen(k, n, c) -> Got(AeadOpenResult(p.AeadOpen(k, n, c)))
Send(...)         -> Got(ResponseHead(..)) or Got(StreamFailed(ResponseBody)), by p.Send's ok
Write(d, end)     -> Quiet, or Stop when p.Write returns false
Read(stream)      -> Got(Chunk(stream, ..)) or Got(StreamFailed(stream)), by p.Read's ok
Close(stream)     -> p.Close(stream); Quiet
EmitPlaintext(d)  -> p.EmitPlaintext(d); Quiet                  # bytes for the caller
terminal actions  -> Quiet                                      # the loop's
```

`Performer` is a trait with one method per non-terminal action, so a port on
`Perform` (Go, Python, Kotlin: `Exchange` implements it, each method one
conversion at the runtime boundary and one binding call) cannot miss an
action: a new constructor fails to compile in `Perform`, and a missing method
fails the port's build. JavaScript, Rust and Swift await inside their HTTP
bindings, which a Dafny trait method cannot (and Swift drives the core over a
C ABI that carries `Step` only), so they keep a hand-written `perform` with
the same cases; `check.py actions` holds all six to the tag list. The server
driver (`SPerformer`, `SPerform` in `EHBPServer`, Go only) has the same shape
with `Option<SEvent>` as its result.

`stream` is `RequestBody` (the caller's body) or `ResponseBody` (the native
response); `end` is `More`, `Done` (the upload ends after `d`) or
`Aborted(code)` (the upload fails with that code). The caller's reads of a
decrypted body feed `CallerRead` events and its close feeds `CallerClose`;
`Done` hands the caller a body whose read runs the same loop. The actions
after a `Send` with a body are the upload: the residue performs them on a
concurrent lane (a goroutine, thread, generator, task or unawaited promise,
per language) because `send` only returns once the response head arrives,
which for a streamed request happens after the body was written.

## 6. JSON in the core

The core parses the two JSON documents itself (`ParseJson` in
`ehbp_events.dfy`, RFC 8259, nesting depth `MaxJsonDepth` = 64; bodies are
decoded by `Utf8`, an invalid byte becoming U+FFFD). Member names are exact
and case-sensitive; the last duplicate wins (`MemberFrom` searches from the
end); an invalid `\u` escape fails the document, a lone surrogate decodes to
U+FFFD (`ParseString`). Decoded strings are kept to `MaxJsonStringChars` =
1,024 characters (`Keep`): the protocol reads only a URN, a title and two
hex fields, and the bound keeps parsing linear whatever a server sends
(`JsonStringsAreBoundedAndLinear`). `ParseProblem`, `ParseToken` and
`FormatToken` are the three functions over it. A residue does no JSON work
and keeps no JSON dependency.

## 7. The API surface

Every SDK exposes the same five entry points and nothing else at the top
level; idiomatic types differ, names follow the language's casing. The
shim is committed code; `check.py api` checks that every name spelled in the
table below appears in the port's files (the column's).

| Entry point | Contract |
| --- | --- |
| constructor `Client(server, keys)` | `server` is an http(s) origin; `keys` is one of: `discover` (fetch `/.well-known/hpke-keys`), a key configuration (RFC 9458 bytes), or a public key (32 bytes). Native transport options (client, timeouts, pinning) are one optional argument. |
| `request(method, path, headers, body)` | one entry point; `body` absent, bytes, or a native stream. Returns the native response whose body is the decrypted stream or the pass-through. Convenience verbs, if any, are one-line wrappers. |
| `discover(server)` | the same discovery the constructor runs; returns the 32-byte public key the core's `Discovered` action carries, which callers cache and pass back as the public-key source. |
| `sessionRecoveryToken()` | the token of the exchange in flight, or none: a value with the two 32-byte fields `exportedSecret` and `requestEnc` and a JSON form (SPEC 6.1.1), never the JSON alone. |
| `selfCheck()` | `SelfCheckActions` performed through this language's bindings, judged by `SelfCheckJudge`: the failed checks, empty on pass. |

Helpers over the pure core live behind a single `core` accessor each SDK
exports for the conformance adapter and the tests only. Its generated
members (section 8) are the ABI ops that take and return bytes and
strings; each SDK adds hand-written helpers that run an exchange from a
token. Error classes and protocol constants are generated from the core's
code list and constants.

The spelling of each member per port. A KeySource is always three forms
spelled `Discover`, `Config`, `PublicKey` in the language's casing; the
discover *function* keeps the verb, so Go, where both are package-level,
spells the KeySource form `Discovered()`:

| Member | Go (`client/client.go`, `core.go`) | Python (`python/src/ehbp/client.py`, `identity.py`) | JavaScript (`js/src/client.ts`, `identity.ts`) | Rust (`rust/src/client.rs`, `identity.rs`, `lib.rs`) | Kotlin (`kotlin/.../client/Client.kt`, `Core.kt`) | Swift (`swift/Sources/EHBP/Client.swift`, `Identity.swift`) |
| --- | --- | --- | --- | --- | --- | --- |
| constructor | `client.New(server, keys, opts...)` | `Client(server, keys, http_client=)` | `await Transport.create(server, keys, options?)`; `new Transport(server, resolvedKeys, options?)` | `Client::new(server, keys, http_client).await` | `Transport(server, keys, httpClient)` | `try await EHBPClient(server:keys:session:)` |
| KeySource: discover | `client.Discovered()` | `Discover` | `{ discover: true }` | `KeySource::Discover` | `KeySource.Discover` | `.discover` |
| KeySource: config | `client.Config(bytes)` | `Config(bytes)` | `{ config }` | `KeySource::Config(vec)` | `KeySource.Config(bytes)` | `.config(data)` |
| KeySource: public key | `client.PublicKey(key)` | `PublicKey(bytes)` | `{ publicKey }` | `KeySource::PublicKey([u8; 32])` | `KeySource.PublicKey(bytes)` | `.publicKey(data)` |
| transport options | `client.WithHTTPClient(c)` | `http_client=httpx.Client` | `{ fetch, discoverInit }` | `Option<reqwest::Client>` | `OkHttpClient` | `URLSession` |
| request | `tr.RoundTrip(*http.Request)` (an `http.Client` `Transport`) | `client.request(method, path, headers=, body=)` | `transport.request(input, init?)`; `get`/`post`/`put`/`delete` | `client.request(method, path, headers, body).await` | `transport.roundTrip(request)` | `client.request(method:path:headers:body:)` or `(..., bodySource:)`; `requestStream(...)` likewise |
| discover | `client.Discover(ctx, server, opts...)` → `[]byte` | `discover(server, http_client=)` → `bytes` | `await discover(server, options?)` → `Uint8Array` | `Client::discover(server, http_client).await` → `[u8; 32]` | `discover(server, httpClient)` → `ByteArray` | `try await EHBPClient.discover(server, session:)` → `Data` |
| sessionRecoveryToken | `tr.SessionRecoveryToken()` → `*SessionRecoveryToken` | `client.session_recovery_token()` → `SessionRecoveryToken \| None` | `transport.sessionRecoveryToken()` → `SessionRecoveryToken \| undefined` | `client.session_recovery_token()` → `Option<SessionRecoveryToken>` | `transport.sessionRecoveryToken()` → `SessionRecoveryToken?` | `client.sessionRecoveryToken()` → `SessionRecoveryToken?` |
| token fields; JSON | `ExportedSecret`, `RequestEnc`; `json.Marshal`/`json.Unmarshal` | `exported_secret`, `request_enc`; `.json`, `core.parse_token` | `exportedSecret`, `requestEnc`; `core.formatToken`/`core.parseToken` | `exported_secret`, `request_enc`; `to_json()`, `core::parse_token` | `exportedSecret`, `requestEnc`; `Core.formatToken`/`Core.parseToken` | `exportedSecret`, `requestEnc`; `.json`, `init(json:)` |
| selfCheck | `client.SelfCheck()` → `[]string` | `self_check()` → `list[str]` | `await selfCheck()` → `string[]` | `tinfoil_ehbp::self_check().await` → `Vec<String>` | `selfCheck()` → `List<String>` | `await EHBPClient.selfCheck()` → `[String]` |
| `core` accessor | `client.Core()` (`CoreAPI`) | `ehbp.core` (the `identity` module) | `core` | `tinfoil_ehbp::core` (module) | `sh.tinfoil.ehbp.Core` | `EHBPClient.core` (`CoreHelpers`, over the internal `Core` enum) |
| generated members | `ParseConfig`, `MarshalConfig`, `CheckPublicKey`, `NonceFor`, `EncodeHex`, `DecodeHex`, `FormatToken`, `ParseToken` | `parse_config`, `marshal_config`, `check_public_key`, `nonce_for`, `encode_hex`, `decode_hex`, `format_token`, `parse_token` | `parseConfig`, `marshalConfig`, `checkPublicKey`, `nonceFor`, `encodeHex`, `decodeHex`, `formatToken`, `parseToken` | `parse_config`, `marshal_config`, `check_public_key`, `nonce_for`, `encode_hex`, `decode_hex`, `format_token`, `parse_token` | `parseConfig`, `marshalConfig`, `checkPublicKey`, `nonceFor`, `encodeHex`, `decodeHex`, `formatToken`, `parseToken` | the internal `Core` enum: every op of `OPS` (`parseConfig` .. `selfCheckJudge`) |
| hand-written members | `DeriveKeys`, `DecryptResponse`, `EncryptRequest` | `derive_keys`, `decrypt`, `decrypted_body` | `deriveKeys`, `decryptWithToken` | `derive_response_keys`, `ResponseDecryptor`, `SessionRecoveryToken::new`/`response_decryptor` | `deriveKeys`, `decryptWithToken` | `CoreHelpers`: `parseConfig`, `marshalConfig`, `computeNonce`, `deriveResponseKeys`, `decryptWithToken` |

## 8. What is generated

The rule: derived from a machine-readable source, generated; otherwise
committed code with a check. One entry point, `python3
conformance/tools/gen.py [--check] [target ...]` (`all` is the default; exit
1 on drift with `--check`, 2 on an unknown target), one package,
`conformance/tools/gen/`, with a module per target. The
`conformance/tools/gen_<target>.py` scripts forward to it. Nothing
per-language lives in a target module: a language is one profile,
`gen/profiles/<lang>.py` (short spellings with `$name` holes), plus one
Jinja template per target, `gen/templates/<lang>/<target>.<ext>.j2`,
rendered with `trim_blocks`, `lstrip_blocks` and `keep_trailing_newline`
(`gen/__init__.py`). A region inside a hand-written file is
`<comment> <name>:begin (<note>)` .. `<comment> <name>:end` and is
replaced whole (`gen/markers.py`); a whole file carries a "do not edit"
header.

| Target | Source | Output | Languages (`LANGS`) | Profile keys (`PROFILE_KEYS`) |
| --- | --- | --- | --- | --- |
| `errors` | `CodeString` and the typed `const` block of `ehbp.dfy` (`gen/dafny_decls.py`) | the whole `errors` and `protocol` files (templates `errors`, `protocol`; Rust through `rustfmt`) | go, python, kotlin, rust, js | `files`, `error_native` |
| `core` | `ACCESSOR` in `gen/core.py`: the ops of `OPS` (`gen/ffi.py`) that take and return bytes and strings (`ParseConfig`, `MarshalConfig`, `CheckPublicKey`, `NonceFor`, `EncodeHex`, `DecodeHex`, `FormatToken`) plus `ParseToken` (parse and `ValidateTokenFields` in one call, returning the native token type); the profile's `core` section | the `core` region of the accessor file; Swift's is every op of `OPS` over the ABI | all six | `files`, `comment`, `end_gap`, `region_indent`, `casing`, `types`, `core` |
| `ffi` | `ROOTS` and `OPS` in `gen/ffi.py` over the datatypes of both Dafny files (`SOURCES`) | the `ffi` region of `rust/ffi/src/lib.rs` and `swift/Sources/EHBP/Core.swift` | rust, swift | `files`, `ffi_ty`, `ffi_name`, `ffi_enc`, `ffi_dec`, `ffi_coder` |

The parsers: `gen/dafny_decls.py` reads declaration lines only (datatypes
with constructor and field order, aliases, newtypes, function signatures,
typed consts, the `CodeString` table) and checks every `OPS` entry exists
in the core with the listed module and arity; `gen/operations_md.py` reads
the first two columns of the operations table (`same as X` inherits) for
`check.py operations`.

Committed code, checked: the residues (section 4; the pump is `Perform` in
the core, section 5), the shims (section 7), the adapters (section 9), the
accessor file's exchange helpers and native token type, the ABI's primitive
coders and six entry points, Go's server operations and RSS probe.

Gates: `python3 conformance/tools/check.py [section ...]` runs `layout`,
`bindings`, `budgets`, `actions`, `operations`, `api`, `generated` (the
`--check` of `errors`, `core` and `ffi`), `docs` and `rules`;
`conformance/.venv/bin/python -m pytest conformance/tools/tests -q`
(`test_cli.py`, `test_dafny_decls.py`, `test_golden.py`, `test_markers.py`,
`test_operations_md.py`, `test_profiles.py`, `test_docs.py`,
`test_spec_rules.py`) renders every target into a temporary tree and compares
it with the committed one, checks rendering is idempotent, names a profile
key or template a target lacks, and runs the `docs` and `rules` sections.

The Dafny bundles: `dafny/generate.sh` translates `ehbp.dfy` to Go with
its runtime into `dafny/gen/go` (`EHBP`, `dafny`, `System_`);
`dafny/generate-events.sh` translates `ehbp_server.dfy` to Go
(`gen-events/go/EHBPEvents`, `EHBPServer`, rewritten to import `gen/go`)
and `ehbp_events.dfy` (client only: `EHBP` and `EHBPEvents`, no server, no
tests) to JavaScript (`gen-events/js/ehbp.js`), Python (`gen-events/py`),
Rust (`gen-events/rs`, crate `ehbp-events-core`) and Java
(`gen-events/java`).
Both run `dafny/patch-runtime.py`, which rewrites one verbatim anchor per
patch and fails when an anchor is in neither its original nor its patched
form: `gen-events/js/ehbp.js` (`Seq.Concat`, `Seq.UnicodeFromString`,
`Seq#slice` loop instead of spreading), `gen-events/py/_dafny/__init__.py`
(a `seq<uint8>` built from `bytes` stays `bytes`), `gen/go/dafny/dafny.go`
and `dafnyFromDafny.go` (a `[]byte`-backed `GoByteArray`). The SDKs import
the bundles as-is.

## 9. The adapters

`conformance/adapters/<lang>` for go, python, js, rust, kotlin and swift are
committed code (`ADAPTERS` in `check.py`): the same program per language,
one dispatch over the operation name. Every operation of `operations.md` is
one of seven shapes: pure (one core call, bytes out), decrypt (whole or
streaming), exchange (body bytes, stream or pattern; the token read 500 ms
after sending, one byte then close, the token once ended, the RSS probe),
discover, hardening (reserved header, cross-origin, credentials), selfcheck
and server (Go only: `decrypt_request`, `middleware_request`, `SERVER_OPS`).
`check.py operations` fails when an adapter's dispatch does not name an
operation of the table; an operation missing from the harness side fails the
run. What every adapter agrees on: the nonce header, the reported header
subset (`ehbp-response-nonce`, `content-length`, `transfer-encoding`,
`content-type`), the probe path and cross-origin target, the hold delay
(500 ms), the reserved-header and `Host` values and the pattern block shift.
Go adds `server.go` and `rss_*.go`.

`conformance/harness/run.py` builds the adapters it is asked for
(`build_adapters`: `go build` for Go, the conformance venv for Python,
`js/dist` for Node, `cargo build --release` for Rust,
`swift/build-core.sh` then `swift build -c release` for Swift,
`./gradlew -PnoAndroid :adapter:installDist` for Kotlin, Playwright for
`js-chromium` and `js-firefox`), starts the oracle (`conformance/server`)
and runs the fixtures; flags `--adapter <name>` (repeatable) and `--heavy`.
`conformance/tools/bench.py` times built adapters against the oracle.

## 10. Swift runs the core through a C ABI

Swift has no Dafny backend: it links the Rust bundle behind the six
functions of `rust/ffi/src/lib.rs` (`ehbp_state_new`, `ehbp_state_free`,
`ehbp_step`, `ehbp_keys_of`, `ehbp_call`, `ehbp_free_buf`), packaged as
`swift/EHBPCore.xcframework` by `swift/build-core.sh`. Its residue keeps
the section 4 layout and the section 7 shim and is checked like the others; `swift/Sources/EHBP/Core.swift` holds the `ffi` region
(types and coders) and the `core` region (the `Core` enum, one wrapper per
op) with the hand-written `CoreState` between them. The ABI, the encoding
and the build are in `swift-ffi.md`.

## 11. Fixtures

The fixture families that need no crypto (`config`, `e2e`, `shape`,
`client-api`, `server-security`) are one Dafny program over the core,
`dafny/fixtures.dfy`, printed through the core's `Escape`.
`dafny/gen-fixtures.sh` writes `test-vectors/conformance/<family>.json`
from it and `crypto.json` from `conformance/tools/gen_fixtures.py`, which
seals frames natively. `conformance/tools/fixture_check.py` runs the
program on the Go and Python backends and fails when their output differs
or the committed files drift; it is not part of `check.py`.

## 12. CI

`.github/workflows/test.yml`: `test-go` (`go test -race ./...`),
`check-generated` (`dafny verify ehbp.dfy ehbp_events.dfy ehbp_server.dfy ehbp_tests.dfy fixtures.dfy spec_rules.dfy`,
`dafny test ehbp_tests.dfy`, `generate.sh --no-verify`,
`generate-events.sh --no-verify`, the generator tests, `check.py`,
`fixture_check.py`, then fails on any diff), `test-js`, `test-swift`
(`swift/build-core.sh`, `swift build`, `swift test`) and `test-kotlin`.
`.github/workflows/conformance.yml` runs `gen_fixtures.py` against the
committed vectors and the full adapter matrix through `harness/run.py`.
