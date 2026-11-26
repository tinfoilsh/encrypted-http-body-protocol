// EHBP protocol core: the verified logic every SDK shares.
//
// No crypto and no I/O live here: the codes, constants, hex, key
// configuration, token, response classifier and origin rules every SDK
// shares. The exchange itself is the event-driven driver of ehbp_events.dfy;
// what a language keeps by hand is conformance/spec/handler.md. Error codes
// mirror conformance/spec/errors.md.
module EHBP {
  newtype uint8 = x: int | 0 <= x < 0x100
  newtype uint16 = x: int | 0 <= x < 0x1_0000
  newtype uint32 = x: int | 0 <= x < 0x1_0000_0000
  newtype uint64 = x: int | 0 <= x < 0x1_0000_0000_0000_0000

  type bytes = seq<uint8>
  type PublicKey = b: bytes | |b| == 32 witness seq(32, i => 0)

  // The checked entry point for callers outside the core (SPEC 3.2).
  function CheckPublicKey(b: bytes): Result<PublicKey>
  {
    if |b| == 32 then var key: PublicKey := b; Ok(key) else Err(InvalidKeyConfig, "public key must be 32 bytes")
  }

  datatype Code =
    | InvalidKeyConfig
    | UnsupportedSuite
    | InvalidEncapsulatedKey
    | HpkeSetupFailed
    | MissingResponseNonce
    | UnexpectedRedirect
    | InvalidResponseNonce
    | DuplicateResponseNonce
    | KeyConfigMismatch
    | FramingTruncated
    | ChunkTooLarge
    | AeadDecryptFailed
    | SequenceOverflow
    | InvalidToken
    | InvalidInput
    // A native I/O failure with no protocol meaning; the shim keeps the cause.
    | Transport

  // SPEC 5.5: the canonical string every SDK exposes for a code. Transport has
  // none; it is the native cause.
  function CodeString(c: Code): string
  {
    match c
    case InvalidKeyConfig => "INVALID_KEY_CONFIG"
    case UnsupportedSuite => "UNSUPPORTED_SUITE"
    case InvalidEncapsulatedKey => "INVALID_ENCAPSULATED_KEY"
    case HpkeSetupFailed => "HPKE_SETUP_FAILED"
    case MissingResponseNonce => "MISSING_RESPONSE_NONCE"
    case UnexpectedRedirect => "UNEXPECTED_REDIRECT"
    case InvalidResponseNonce => "INVALID_RESPONSE_NONCE"
    case DuplicateResponseNonce => "DUPLICATE_RESPONSE_NONCE"
    case KeyConfigMismatch => "KEY_CONFIG_MISMATCH"
    case FramingTruncated => "FRAMING_TRUNCATED"
    case ChunkTooLarge => "CHUNK_TOO_LARGE"
    case AeadDecryptFailed => "AEAD_DECRYPT_FAILED"
    case SequenceOverflow => "SEQUENCE_OVERFLOW"
    case InvalidToken => "INVALID_TOKEN"
    case InvalidInput => "INVALID_INPUT"
    case Transport => ""
  }

  // Every code the SDKs expose, in the order of conformance/spec/errors.md.
  const Codes: seq<Code> := [InvalidKeyConfig, UnsupportedSuite, InvalidEncapsulatedKey, HpkeSetupFailed,
    MissingResponseNonce, UnexpectedRedirect, InvalidResponseNonce, DuplicateResponseNonce, KeyConfigMismatch,
    FramingTruncated, ChunkTooLarge, AeadDecryptFailed, SequenceOverflow, InvalidToken, InvalidInput]

  lemma CodeStringsAreDistinct()
    ensures forall i, j :: 0 <= i < j < |Codes| ==> CodeString(Codes[i]) != CodeString(Codes[j])
  {}

  datatype Result<T> = Ok(value: T) | Err(code: Code, message: string)

  datatype Option<T> = None | Some(value: T)

  // ---------------------------------------------------------------------------
  // Constants (SPEC 3.2, 4.1, 4.3, 4.4).

  const KemX25519: uint16 := 0x0020
  const KdfHkdfSha256: uint16 := 0x0001
  const AeadAes256Gcm: uint16 := 0x0002
  const PublicKeyLength: nat := 32
  const RequestEncLength: nat := 32
  const ExportLength: nat := 32
  const ResponseNonceLength: nat := 32
  const KeyLength: nat := 32
  const NonceLength: nat := 12
  const HpkeRequestInfo: string := "ehbp request"
  const ExportLabel: string := "ehbp response"
  const ResponseKeyLabel: string := "key"
  const ResponseNonceLabel: string := "nonce"
  const EncapsulatedKeyHeader: string := "Ehbp-Encapsulated-Key"
  const ResponseNonceHeader: string := "Ehbp-Response-Nonce"
  const KeysPath: string := "/.well-known/hpke-keys"
  const KeysMediaType: string := "application/ohttp-keys"
  const ProblemJsonMediaType: string := "application/problem+json"
  const KeyConfigProblemType: string := "urn:ietf:params:ehbp:error:key-config"
  const DefaultKeyConfigTitle: string := "key configuration mismatch"
  // SPEC 4.3: a length prefix above this is rejected before any allocation.
  const MaxChunkBytes: uint32 := 64 * 1024 * 1024
  // Plaintext sealed per request frame.
  const RequestFrameBytes: uint32 := 65536
  // SPEC 5.4.2: a larger problem document is not a key-config problem.
  const MaxProblemBytes: nat := 64 * 1024
  // SPEC 3.1: one config is 37 bytes plus at most a uint16 of suites.
  const MaxKeyConfigBytes: nat := 37 + 65535
  // A source that keeps returning no bytes and no end is reported, not waited on.
  const MaxEmptyReads: nat := 100

  // ---------------------------------------------------------------------------
  // Byte and string helpers.

  function U16(b: bytes, i: nat): uint16
    requires i + 2 <= |b|
  {
    (b[i] as uint16) * 0x100 + (b[i + 1] as uint16)
  }

  function U32(b: bytes, i: nat): uint32
    requires i + 4 <= |b|
  {
    (U16(b, i) as uint32) * 0x1_0000 + (U16(b, i + 2) as uint32)
  }

  function BE16(v: uint16): bytes
    ensures |BE16(v)| == 2
  {
    [(v / 0x100) as uint8, (v % 0x100) as uint8]
  }

  function BE32(v: uint32): bytes
    ensures |BE32(v)| == 4
  {
    BE16((v / 0x1_0000) as uint16) + BE16((v % 0x1_0000) as uint16)
  }

  predicate IsAscii(s: string) { forall i :: 0 <= i < |s| ==> s[i] as int < 0x80 }

  function Ascii(s: string): bytes
    requires IsAscii(s)
    ensures |Ascii(s)| == |s|
  {
    seq(|s|, i requires 0 <= i < |s| => s[i] as int as uint8)
  }

  function LowerChar(c: char): char
  {
    if 'A' <= c <= 'Z' then (c as int + 32) as char else c
  }

  function Lower(s: string): string
    ensures |Lower(s)| == |s|
  {
    seq(|s|, i requires 0 <= i < |s| => LowerChar(s[i]))
  }

  predicate EqualFold(a: string, b: string) { Lower(a) == Lower(b) }

  predicate IsSpace(c: char) { c == ' ' || c == '\t' }

  function TrimLeft(s: string): string
    decreases |s|
  {
    if |s| > 0 && IsSpace(s[0]) then TrimLeft(s[1..]) else s
  }

  function TrimRight(s: string): string
    decreases |s|
  {
    if |s| > 0 && IsSpace(s[|s| - 1]) then TrimRight(s[..|s| - 1]) else s
  }

  function Trim(s: string): string { TrimRight(TrimLeft(s)) }

  function Before(s: string, sep: char): string
  {
    BeforeFrom(s, sep, 0)
  }

  function BeforeFrom(s: string, sep: char, i: nat): string
    requires i <= |s|
    decreases |s| - i
  {
    if i == |s| || s[i] == sep then s[..i] else BeforeFrom(s, sep, i + 1)
  }

  // SPEC 3.1, 5.4.2: media type compared case-insensitively, parameters ignored.
  function MediaType(contentType: string): string { Lower(Trim(Before(contentType, ';'))) }

  predicate HasMediaType(contentType: Option<string>, want: string)
  {
    contentType.Some? && MediaType(contentType.value) == Lower(want)
  }

  function HexDigitValue(c: char): Option<uint8>
    ensures HexDigitValue(c).Some? ==> HexDigitValue(c).value < 16
  {
    if '0' <= c <= '9' then Some((c as int - '0' as int) as uint8)
    else if 'a' <= c <= 'f' then Some((c as int - 'a' as int + 10) as uint8)
    else if 'A' <= c <= 'F' then Some((c as int - 'A' as int + 10) as uint8)
    else None
  }

  // SPEC 4.1: strict hex, even length, no prefix, no whitespace, either case.
  predicate IsHex(s: string) { |s| % 2 == 0 && forall i :: 0 <= i < |s| ==> HexDigitValue(s[i]).Some? }

  function DecodeHex(s: string): Option<bytes>
    ensures DecodeHex(s).Some? ==> |DecodeHex(s).value| * 2 == |s|
  {
    if !IsHex(s) then None
    else Some(seq(|s| / 2, i requires 0 <= i < |s| / 2 =>
      HexDigitValue(s[2 * i]).value * 16 + HexDigitValue(s[2 * i + 1]).value))
  }

  const HexDigits: string := "0123456789abcdef"

  function EncodeHex(b: bytes): string
    ensures |EncodeHex(b)| == 2 * |b|
  {
    seq(2 * |b|, i requires 0 <= i < 2 * |b| =>
      if i % 2 == 0 then HexDigits[b[i / 2] as int / 16] else HexDigits[b[i / 2] as int % 16])
  }

  // ---------------------------------------------------------------------------
  // Nonce: nonce = nonceBase XOR seq, seq big-endian in the last 8 bytes.

  // Fixed-width indices: a comprehension over `nat` costs a big integer per
  // element in the compiled runtimes, and this runs once per frame.
  function ComputeNonce(nonceBase: bytes, seqNo: uint64): bytes
    requires |nonceBase| == NonceLength
    ensures |ComputeNonce(nonceBase, seqNo)| == NonceLength
  {
    seq(NonceLength, i requires 0 <= i < NonceLength =>
      var j := i as uint32;
      if j < 4 then nonceBase[j] else ((nonceBase[j] as bv8) ^ (ByteAt(seqNo, 11 - j) as bv8)) as uint8)
  }

  // The checked entry point for callers outside the core.
  function NonceFor(nonceBase: bytes, seqNo: uint64): Result<bytes>
  {
    if |nonceBase| != NonceLength then Err(InvalidInput, "nonce base must be 12 bytes")
    else Ok(ComputeNonce(nonceBase, seqNo))
  }

  // Byte k of x, k = 0 being the least significant.
  function ByteAt(x: uint64, k: uint32): uint8
    requires k < 8
  {
    if k == 0 then (x % 0x100) as uint8 else ByteAt(x / 0x100, k - 1)
  }

  // ---------------------------------------------------------------------------
  // Key config (RFC 9458 application/ohttp-keys), SPEC 3.2.
  //
  // Layout: key_id(1) kem_id(2) public_key(32) suites_len(2) {kdf_id(2) aead_id(2)}*
  // Bytes after the first config are ignored (SPEC 3.1).

  // The identifiers Go's crypto/hpke knows. A suite with an unknown identifier
  // is rejected as soon as it is read; a known-but-wrong one is rejected after
  // the whole list has parsed. The order only shows when a later suite is
  // incomplete, and the reference (Go) behaves this way.
  predicate KnownKdf(id: uint16) { id == 0x0001 || id == 0x0002 || id == 0x0003 }
  predicate KnownAead(id: uint16) { id == 0x0001 || id == 0x0002 || id == 0x0003 }

  function ParseConfig(data: bytes): Result<bytes>
    ensures ParseConfig(data).Ok? ==> |ParseConfig(data).value| == PublicKeyLength
  {
    if |data| < 3 then Err(InvalidKeyConfig, "invalid config")
    else if U16(data, 1) != KemX25519 then Err(UnsupportedSuite, "unsupported KEM")
    else if |data| < 3 + PublicKeyLength + 2 then Err(InvalidKeyConfig, "invalid config")
    else
      var pk := data[3 .. 3 + PublicKeyLength];
      var suitesLen := U16(data, 3 + PublicKeyLength) as nat;
      var start := 3 + PublicKeyLength + 2;
      if |data| < start + suitesLen then Err(InvalidKeyConfig, "invalid config")
      else
        match ParseSuites(data[start .. start + suitesLen])
        case Err(code, message) => Err(code, message)
        case Ok(suites) =>
          if |suites| == 0 then Err(InvalidKeyConfig, "no cipher suites found in config")
          else if |suites| != 1 then Err(UnsupportedSuite, "expected exactly one cipher suite")
          else if suites[0] != (KdfHkdfSha256, AeadAes256Gcm) then Err(UnsupportedSuite, "unsupported cipher suite")
          else Ok(pk)
  }

  function ParseSuites(s: bytes): Result<seq<(uint16, uint16)>>
  {
    ParseSuitesFrom(s, 0, [])
  }

  function ParseSuitesFrom(s: bytes, i: nat, acc: seq<(uint16, uint16)>): Result<seq<(uint16, uint16)>>
    requires i <= |s|
    decreases |s| - i
  {
    if i == |s| then Ok(acc)
    else if |s| - i < 4 then Err(InvalidKeyConfig, "invalid config")
    else
      var kdf := U16(s, i);
      var aead := U16(s, i + 2);
      if !KnownKdf(kdf) then Err(UnsupportedSuite, "invalid KDF")
      else if !KnownAead(aead) then Err(UnsupportedSuite, "invalid AEAD")
      else ParseSuitesFrom(s, i + 4, acc + [(kdf, aead)])
  }

  function MarshalConfig(publicKey: bytes): Result<bytes>
  {
    if |publicKey| != PublicKeyLength then Err(InvalidKeyConfig, "invalid public key")
    else Ok([0] + BE16(KemX25519) + publicKey + BE16(4) + BE16(KdfHkdfSha256) + BE16(AeadAes256Gcm))
  }

  lemma MarshalParseRoundTrip(pk: bytes)
    requires |pk| == PublicKeyLength
    ensures ParseConfig(MarshalConfig(pk).value) == Ok(pk)
  {
    var cfg := MarshalConfig(pk).value;
    assert cfg[3 .. 3 + PublicKeyLength] == pk;
    var suites := cfg[37 .. 41];
    assert suites == [0, 1, 0, 2];
    assert U16(suites, 0) == KdfHkdfSha256 && U16(suites, 2) == AeadAes256Gcm;
    assert KnownKdf(KdfHkdfSha256) && KnownAead(AeadAes256Gcm);
    assert [] + [(KdfHkdfSha256, AeadAes256Gcm)] == [(KdfHkdfSha256, AeadAes256Gcm)];
    assert ParseSuitesFrom(suites, 0, []) == ParseSuitesFrom(suites, 4, [(KdfHkdfSha256, AeadAes256Gcm)]);
    assert ParseSuitesFrom(suites, 4, [(KdfHkdfSha256, AeadAes256Gcm)]) == Ok([(KdfHkdfSha256, AeadAes256Gcm)]);
  }

  // ---------------------------------------------------------------------------
  // Session recovery token (SPEC 6.1.1). JSON parsing is native; the fields
  // are validated here.

  datatype Token = Token(exportedSecret: bytes, requestEnc: bytes)

  predicate ValidToken(t: Token) { |t.exportedSecret| == ExportLength && |t.requestEnc| == RequestEncLength }

  function ValidateTokenFields(exportedSecretHex: Option<string>, requestEncHex: Option<string>): Result<Token>
    ensures ValidateTokenFields(exportedSecretHex, requestEncHex).Ok? ==> ValidToken(ValidateTokenFields(exportedSecretHex, requestEncHex).value)
  {
    if exportedSecretHex.None? || requestEncHex.None? then Err(InvalidToken, "token field missing")
    else
      match (DecodeHex(exportedSecretHex.value), DecodeHex(requestEncHex.value))
      case (Some(secret), Some(enc)) =>
        if |secret| != ExportLength || |enc| != RequestEncLength then Err(InvalidToken, "token field has wrong length")
        else Ok(Token(secret, enc))
      case _ => Err(InvalidToken, "token field is not hex")
  }

  // ---------------------------------------------------------------------------
  // Body framing (SPEC 4.3): frames of uint32 big-endian length then ciphertext.

  function Frame(ciphertext: bytes): bytes
    requires |ciphertext| < 0x1_0000_0000
  {
    BE32(|ciphertext| as uint32) + ciphertext
  }

  datatype Framed = Framed(seqNo: uint64, ciphertext: bytes)

  // ---------------------------------------------------------------------------
  // Classification (SPEC 3.1, 5.1, 5.3, 5.4.2). Pure functions over what the
  // transport observed; the residue never decides anything here.

  // Every header as the stack presents it. A coalescing stack presents one
  // joined value for a repeated header (SPEC 4.2).
  type Headers = seq<(string, string)>

  function HeaderValues(headers: Headers, name: string): seq<string>
  {
    HeaderValuesFrom(headers, name, 0, [])
  }

  function HeaderValuesFrom(headers: Headers, name: string, i: nat, acc: seq<string>): seq<string>
    requires i <= |headers|
    decreases |headers| - i
  {
    if i == |headers| then acc
    else HeaderValuesFrom(headers, name, i + 1, if EqualFold(headers[i].0, name) then acc + [headers[i].1] else acc)
  }

  function FirstHeader(headers: Headers, name: string): Option<string>
  {
    var values := HeaderValues(headers, name);
    if |values| == 0 then None else Some(values[0])
  }

  // What the transport observed about a response. `redirected` is true when
  // the stack followed a redirect on its own before the core saw the result.
  datatype Head = Head(status: int, headers: Headers, redirected: bool)

  datatype Disposition =
    | PassThrough
    | Decrypt(nonce: bytes, requireFrame: bool)
    // A 422 problem document must be read (bounded) before deciding.
    | NeedProblemBody
    | Refuse(code: Code, message: string)

  predicate BodylessSuccess(status: int) { status == 204 || status == 205 }

  function Classify(encrypted: bool, head: Head): Disposition
  {
    var nonces := HeaderValues(head.headers, ResponseNonceHeader);
    if !encrypted then PassThrough
    // SPEC 5.3: a redirect is refused with or without a nonce and never followed.
    else if head.redirected || (300 <= head.status < 400) then Refuse(UnexpectedRedirect, "redirect in response to an encrypted request")
    else if |nonces| == 0 then
      if head.status < 400 then Refuse(MissingResponseNonce, "missing " + ResponseNonceHeader + " header")
      else if head.status == 422 && HasMediaType(FirstHeader(head.headers, "Content-Type"), ProblemJsonMediaType) then NeedProblemBody
      else PassThrough
    else if |nonces| > 1 then Refuse(DuplicateResponseNonce, "duplicate response nonce")
    else if nonces[0] == "" then Refuse(InvalidResponseNonce, "empty response nonce")
    else
      match DecodeHex(nonces[0])
      case None => Refuse(InvalidResponseNonce, "response nonce is not hex")
      case Some(nonce) =>
        if |nonce| != ResponseNonceLength then Refuse(InvalidResponseNonce, "response nonce has wrong length")
        // SPEC 5.1: header validation first, then the bodyless-status rule.
        else if BodylessSuccess(head.status) then Refuse(FramingTruncated, "status cannot carry an authenticated frame")
        else Decrypt(nonce, head.status < 400)
  }

  lemma ClassifyIsTotal(encrypted: bool, head: Head)
    ensures var d := Classify(encrypted, head);
      d.PassThrough? || d.Decrypt? || d.NeedProblemBody? || d.Refuse?
  {}

  // SPEC 5.4.2: the parsed problem document. `isObject` false covers a body
  // that is not JSON or not an object.
  function ClassifyProblem(oversized: bool, isObject: bool, typeValue: Option<string>, title: Option<string>): Disposition
  {
    if oversized || !isObject || typeValue != Some(KeyConfigProblemType) then PassThrough
    else Refuse(KeyConfigMismatch, if title.Some? && title.value != "" then title.value else DefaultKeyConfigTitle)
  }

  // SPEC 3.1: discovery accepts only a 200 with the keys media type.
  function ClassifyDiscovery(head: Head): Result<()>
  {
    if head.redirected || head.status != 200 then Err(InvalidKeyConfig, "discovery returned a non-200 status")
    else if !HasMediaType(FirstHeader(head.headers, "Content-Type"), KeysMediaType) then Err(InvalidKeyConfig, "discovery returned the wrong media type")
    else Ok(())
  }

  // The validated origin requests must target. The shim parses URLs natively
  // and hands over the parts; the decisions are here.
  datatype Origin = Origin(scheme: string, host: string, port: int)

  function DefaultPort(scheme: string): int { if Lower(scheme) == "https" then 443 else 80 }

  function MakeOrigin(scheme: string, host: string, port: Option<int>, hasUserinfo: bool): Result<Origin>
  {
    var s := Lower(scheme);
    if s != "http" && s != "https" then Err(InvalidInput, "base URL must include an HTTP origin")
    else if host == "" then Err(InvalidInput, "base URL must include an HTTP origin")
    else if hasUserinfo then Err(InvalidInput, "base URL must not include credentials")
    else Ok(Origin(s, Lower(host), if port.Some? then port.value else DefaultPort(s)))
  }

  predicate SameOrigin(a: Origin, b: Origin) { a.scheme == b.scheme && a.host == b.host && a.port == b.port }

  predicate ReservedHeader(name: string)
  {
    EqualFold(name, EncapsulatedKeyHeader) || EqualFold(name, ResponseNonceHeader) || EqualFold(name, "Host")
  }

  predicate FramingHeader(name: string) { EqualFold(name, "Content-Length") || EqualFold(name, "Transfer-Encoding") }

  // SPEC 5.1 request guards.
  function ValidateRequest(origin: Origin, target: Result<Origin>, headers: Headers): Result<()>
  {
    if target.Err? then Err(InvalidInput, target.message)
    else if !SameOrigin(origin, target.value) then Err(InvalidInput, "request URL must use the configured origin")
    else ValidateHeadersFrom(headers, 0)
  }

  function ValidateHeadersFrom(headers: Headers, i: nat): Result<()>
    requires i <= |headers|
    decreases |headers| - i
  {
    if i == |headers| then Ok(())
    else if ReservedHeader(headers[i].0) then Err(InvalidInput, "reserved request header cannot be set by callers: " + headers[i].0)
    else ValidateHeadersFrom(headers, i + 1)
  }

  // SPEC 5.1: framing headers belong to the implementation.
  function DropFraming(headers: Headers): Headers
  {
    DropFramingFrom(headers, 0, [])
  }

  function DropFramingFrom(headers: Headers, i: nat, acc: Headers): Headers
    requires i <= |headers|
    decreases |headers| - i
  {
    if i == |headers| then acc
    else DropFramingFrom(headers, i + 1, if FramingHeader(headers[i].0) then acc else acc + [headers[i]])
  }

  function OriginUrl(origin: Origin): string
  {
    var portPart := if origin.port == DefaultPort(origin.scheme) then "" else ":" + IntToString(origin.port);
    origin.scheme + "://" + origin.host + portPart
  }

  function IntToString(n: int): string
    decreases if n < 0 then 1 - n else n
  {
    if n < 0 then "-" + IntToString(-n)
    else if n < 10 then [('0' as int + n) as char]
    else IntToString(n / 10) + [('0' as int + n % 10) as char]
  }

  // ---------------------------------------------------------------------------
  // Lengths the event-driven driver (ehbp_events.dfy) checks on native results.
  const AeadTagLength: nat := 16
  const HashLength: nat := 32

  // ---------------------------------------------------------------------------
  // Proofs (ghost only; nothing below is compiled). The nonce (SPEC 4.4.1),
  // hex (SPEC 4.1) and request-header (SPEC 5.1) facts the event driver's
  // theorems and spec_rules.dfy build on.

  // ComputeNonce is injective in the sequence number: nonce = base XOR seq, and the eight low bytes determine seq.
  ghost function Shift(x: uint64, k: nat): uint64 { if k == 0 then x else Shift(x / 0x100, k - 1) }

  lemma ByteAtIsShift(x: uint64, k: uint32)
    requires k < 8
    ensures ByteAt(x, k) == (Shift(x, k as nat) % 0x100) as uint8
  { if k > 0 { ByteAtIsShift(x / 0x100, k - 1); } }

  lemma ShiftDiv(x: uint64, k: nat)
    ensures Shift(x, k + 1) == Shift(x, k) / 0x100
  { if k > 0 { ShiftDiv(x / 0x100, k - 1); } }

  lemma ShiftEight(x: uint64)
    ensures Shift(x, 8) == 0
  {
    ShiftDiv(x, 0); ShiftDiv(x, 1); ShiftDiv(x, 2); ShiftDiv(x, 3); ShiftDiv(x, 4); ShiftDiv(x, 5); ShiftDiv(x, 6); ShiftDiv(x, 7);
  }

  lemma ByteAtDetermines(a: uint64, b: uint64)
    requires forall k: uint32 :: k < 8 ==> ByteAt(a, k) == ByteAt(b, k)
    ensures a == b
  {
    ShiftEight(a); ShiftEight(b);
    var k := 8;
    while k > 0
      invariant k <= 8 && Shift(a, k) == Shift(b, k)
    {
      ShiftDiv(a, k - 1); ShiftDiv(b, k - 1);
      ByteAtIsShift(a, (k - 1) as uint32); ByteAtIsShift(b, (k - 1) as uint32);
      k := k - 1;
    }
  }

  lemma BvRoundTrip(p: bv8) ensures (p as uint8) as bv8 == p {}
  lemma IntRoundTrip(n: uint8) ensures (n as bv8) as uint8 == n {}
  lemma BvXorCancels(p: bv8, q: bv8, r: bv8) requires p ^ q == p ^ r ensures q == r {}

  // Byte j of the nonce, seen as a bit vector: the base byte XOR byte 11-j of the sequence number.
  lemma NonceByte(base: bytes, x: uint64, j: nat)
    requires |base| == NonceLength && 4 <= j < NonceLength
    ensures ComputeNonce(base, x)[j] as bv8 == (base[j] as bv8) ^ (ByteAt(x, (11 - j) as uint32) as bv8)
  {
    hide *; reveal ComputeNonce, NonceLength;
    BvRoundTrip((base[j] as bv8) ^ (ByteAt(x, (11 - j) as uint32) as bv8));
  }

  lemma {:isolate_assertions} SameNonceSameByte(base: bytes, a: uint64, b: uint64, k: uint32)
    requires |base| == NonceLength && k < 8
    requires ComputeNonce(base, a) == ComputeNonce(base, b)
    ensures ByteAt(a, k) == ByteAt(b, k)
  {
    hide *; reveal NonceLength;
    var j := 11 - k as nat;
    var na, nb := ComputeNonce(base, a)[j], ComputeNonce(base, b)[j];
    assert na == nb;
    var p, qa, qb := base[j] as bv8, ByteAt(a, k) as bv8, ByteAt(b, k) as bv8;
    NonceByte(base, a, j); NonceByte(base, b, j);
    assert na as bv8 == p ^ qa;
    assert nb as bv8 == p ^ qb;
    assert p ^ qa == p ^ qb;
    BvXorCancels(p, qa, qb);
    assert qa == qb;
    IntRoundTrip(ByteAt(a, k)); IntRoundTrip(ByteAt(b, k));
    assert ByteAt(a, k) == qa as uint8;
  }

  lemma ComputeNonceInjective(base: bytes, a: uint64, b: uint64)
    requires |base| == NonceLength && a != b
    ensures ComputeNonce(base, a) != ComputeNonce(base, b)
  {
    hide *; reveal NonceLength;
    if ComputeNonce(base, a) == ComputeNonce(base, b) {
      forall k: uint32 | k < 8 ensures ByteAt(a, k) == ByteAt(b, k) { SameNonceSameByte(base, a, b, k); }
      ByteAtDetermines(a, b);
    }
  }

  lemma ByteAtZero(k: uint32) requires k < 8 ensures ByteAt(0, k) == 0 { if k > 0 { ByteAtZero(k - 1); } }

  lemma ComputeNonceZero(base: bytes)
    requires |base| == NonceLength
    ensures ComputeNonce(base, 0) == base
  {
    forall k: uint32 | k < 8 ensures ByteAt(0, k) == 0 { ByteAtZero(k); }
  }

  // ---- Hex (SPEC 4.1): EncodeHex is lowercase and DecodeHex inverts it.

  lemma HexDigitRoundTrip(v: uint8)
    requires v < 16
    ensures HexDigitValue(HexDigits[v]) == Some(v)
  {}

  lemma EncodeHexLowercase(b: bytes)
    ensures forall i :: 0 <= i < |EncodeHex(b)| ==> EncodeHex(b)[i] in HexDigits
  {}

  lemma DecodeEncodeHex(b: bytes)
    ensures DecodeHex(EncodeHex(b)) == Some(b)
  {
    var s := EncodeHex(b);
    forall i | 0 <= i < |s| ensures HexDigitValue(s[i]).Some? {
      if i % 2 == 0 { HexDigitRoundTrip(b[i / 2] / 16); } else { HexDigitRoundTrip(b[i / 2] % 16); }
    }
    assert IsHex(s);
    var d := DecodeHex(s).value;
    forall i | 0 <= i < |b| ensures d[i] == b[i] {
      HexDigitRoundTrip(b[i] / 16); HexDigitRoundTrip(b[i] % 16);
    }
    assert d == b;
  }

  // ---- Request headers (SPEC 5.1).

  lemma ValidateHeadersOk(headers: Headers, i: nat)
    requires i <= |headers| && ValidateHeadersFrom(headers, i).Ok?
    ensures forall k :: i <= k < |headers| ==> !ReservedHeader(headers[k].0)
    decreases |headers| - i
  { if i < |headers| { ValidateHeadersOk(headers, i + 1); } }

  lemma DropFramingFromKeeps(headers: Headers, i: nat, acc: Headers)
    requires i <= |headers|
    ensures forall h <- DropFramingFrom(headers, i, acc) :: h in acc || (h in headers && !FramingHeader(h.0))
    decreases |headers| - i
  { if i < |headers| { DropFramingFromKeeps(headers, i + 1, if FramingHeader(headers[i].0) then acc else acc + [headers[i]]); } }

  lemma DropFramingKeeps(headers: Headers)
    ensures forall h <- DropFraming(headers) :: h in headers && !FramingHeader(h.0)
  { DropFramingFromKeeps(headers, 0, []); }



  lemma ValidateHeadersFromReserved(headers: Headers, i: nat)
    requires i <= |headers| && exists k :: i <= k < |headers| && ReservedHeader(headers[k].0)
    ensures ValidateHeadersFrom(headers, i) == Err(InvalidInput, "reserved request header cannot be set by callers: " + headers[FirstReserved(headers, i)].0)
    decreases |headers| - i
  { if !ReservedHeader(headers[i].0) { ValidateHeadersFromReserved(headers, i + 1); } }

  ghost function FirstReserved(headers: Headers, i: nat): nat
    requires i <= |headers| && exists k :: i <= k < |headers| && ReservedHeader(headers[k].0)
    ensures i <= FirstReserved(headers, i) < |headers| && ReservedHeader(headers[FirstReserved(headers, i)].0)
    decreases |headers| - i
  { if ReservedHeader(headers[i].0) then i else FirstReserved(headers, i + 1) }

  lemma DropFramingFromComplete(headers: Headers, i: nat, acc: Headers)
    requires i <= |headers|
    ensures forall k :: i <= k < |headers| && !FramingHeader(headers[k].0) ==> headers[k] in DropFramingFrom(headers, i, acc)
    ensures forall h <- acc :: h in DropFramingFrom(headers, i, acc)
    decreases |headers| - i
  { if i < |headers| { DropFramingFromComplete(headers, i + 1, if FramingHeader(headers[i].0) then acc else acc + [headers[i]]); } }

  lemma DropFramingComplete(headers: Headers)
    ensures forall k :: 0 <= k < |headers| && !FramingHeader(headers[k].0) ==> headers[k] in DropFraming(headers)
  { DropFramingFromComplete(headers, 0, []); }

  lemma NoHeaderValuesFrom(headers: Headers, name: string, i: nat, acc: seq<string>)
    requires i <= |headers| && forall k :: i <= k < |headers| ==> !EqualFold(headers[k].0, name)
    ensures HeaderValuesFrom(headers, name, i, acc) == acc
    decreases |headers| - i
  { if i < |headers| { NoHeaderValuesFrom(headers, name, i + 1, acc); } }

  lemma NoHeaderValues(headers: Headers, name: string)
    requires forall k :: 0 <= k < |headers| ==> !EqualFold(headers[k].0, name)
    ensures HeaderValues(headers, name) == []
  { NoHeaderValuesFrom(headers, name, 0, []); }
}
