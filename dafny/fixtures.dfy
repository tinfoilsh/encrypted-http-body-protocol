// The conformance fixtures that need no crypto, as one program over the core:
// config, e2e, shape, client-api and server-security. Main prints each family
// as the JSON test-vectors/conformance/<family>.json holds, after a
// `=== <family>` line; dafny/gen-fixtures.sh splits the output into the files
// and conformance/tools/fixture_check.py diffs the Go and Python backends'
// output byte for byte and against the committed files. The crypto family
// seals frames natively and stays in conformance/tools/gen_fixtures.py.
include "ehbp_events.dfy"

module Fixtures {
  import opened EHBP
  import EV = EHBPEvents

  // ---------------------------------------------------------------------------
  // JSON, printed as Python's json.dumps(indent=2): members in insertion order,
  // empty containers on one line, strings escaped as the core escapes them.

  datatype J = Str(s: string) | Int(n: int) | Bool(b: bool) | Null | Arr(items: seq<J>) | Obj(members: seq<(string, J)>)
  type Members = seq<(string, J)>

  function Indent(depth: nat): string { if depth == 0 then "" else "  " + Indent(depth - 1) }

  method Print(v: J, depth: nat)
    decreases v
  {
    match v {
      case Str(s) => print "\"", EV.Escape(s), "\"";
      case Int(n) => print IntToString(n);
      case Bool(b) => print if b then "true" else "false";
      case Null => print "null";
      case Arr(items) =>
        if |items| == 0 { print "[]"; return; }
        print "[\n";
        for i := 0 to |items| {
          if i > 0 { print ",\n"; }
          print Indent(depth + 1);
          Print(items[i], depth + 1);
        }
        print "\n", Indent(depth), "]";
      case Obj(members) =>
        if |members| == 0 { print "{}"; return; }
        print "{\n";
        for i := 0 to |members| {
          if i > 0 { print ",\n"; }
          print Indent(depth + 1), "\"", EV.Escape(members[i].0), "\": ";
          Print(members[i].1, depth + 1);
        }
        print "\n", Indent(depth), "}";
    }
  }

  method Family(name: string, fixtures: seq<J>)
  {
    print "=== ", name, "\n";
    Print(Arr(fixtures), 0);
    print "\n";
  }

  // ---------------------------------------------------------------------------
  // Value helpers.

  function S(s: string): J { Str(s) }
  function Strs(items: seq<string>): J { Arr(seq(|items|, i requires 0 <= i < |items| => Str(items[i]))) }
  // Hex of a string's bytes; the fixtures only hold ASCII text.
  function Hex(s: string): string
  {
    EncodeHex(seq(|s|, i requires 0 <= i < |s| => if s[i] as int < 0x100 then s[i] as int as uint8 else 0))
  }
  function Bytes(n: nat, v: uint8): string { EncodeHex(seq(n, i => v)) }
  const Hello := Hex("hello")
  // A function: dafny 4.11 crashes on a const whose initializer holds a seq comprehension.
  function Large(): string { Hex(seq(20000, i => 'a')) }

  function Fx(id: string, desc: string, category: string, op: string, rest: Members): J
  {
    Obj([("id", S(id)), ("description", S(desc)), ("category", S(category)), ("operation", S(op))] + rest)
  }
  function Ok(bodyHex: string): J { Obj([("outcome", S("ok")), ("body_hex", S(bodyHex))]) }
  function OkStatus(status: int, bodyHex: string): J { Obj([("outcome", S("ok")), ("status", Int(status)), ("body_hex", S(bodyHex))]) }
  function Pass(status: int): J { Obj([("outcome", S("ok")), ("status", Int(status)), ("passthrough", Bool(true))]) }
  function PassBody(status: int, bodyHex: string): J { Obj(Pass(status).members + [("body_hex", S(bodyHex))]) }
  function Err(code: string): J { Obj([("outcome", S("error")), ("error_code", S(code))]) }
  // Fails before any plaintext is released.
  function ErrClosed(code: string): J
  {
    Obj(Err(code).members + [("plaintext_emitted_before_error", Bool(false)), ("bytes_emitted_before_error", Int(0))])
  }
  function With(e: J, more: Members): J requires e.Obj? { Obj(e.members + more) }
  function NoBrowser(reason: string): J { Obj([("runnable", Bool(false)), ("skip_reason", S(reason))]) }

  // ---------------------------------------------------------------------------
  // Config (SPEC 3.2): key_id kem_id public_key suites_len {kdf_id aead_id}*.

  const Kem := "0020"
  const Kdf := "0001"
  const Aead := "0002"
  const Suite := Kdf + Aead
  const Pk07 := Bytes(32, 7)
  // A valid uncompressed P-256 point (the curve's generator, 65 bytes), so the
  // KEM id alone is what every parser must reject.
  const P256Generator := "04"
    + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
  const SwiftConfigSkip: (string, J) := ("allowed_skips", Obj([("swift", S("swift-client-has-no-public-key-accessor-or-config-marshal"))]))

  function Cfg(keyId: string, kem: string, pk: string, suites: string): string
    requires |suites| / 2 < 0x1_0000
  {
    keyId + kem + pk + EncodeHex(BE16((|suites| / 2) as uint16)) + suites
  }
  function Config(pk: string): string { Cfg("00", Kem, pk, Suite) }

  // Swift intentionally has no public config parse/marshal accessor; the skip
  // is explicit per fixture so an adapter cannot conceal another failure.
  function Parse(id: string, desc: string, config: string, want: J): J
  {
    Fx(id, desc, "config", "parse_config", [("inputs", Obj([("config", S(config))])), ("expect", want), SwiftConfigSkip])
  }

  function ConfigFixtures(): seq<J>
  {
    [
      Parse("parse-config-valid", "Parse a well-formed single key config.", Config(Pk07), Ok(Pk07)),
      Fx("marshal-config", "Marshal a config and compare bytes.", "config", "marshal_config",
         [("inputs", Obj([("publicKey", S(Pk07)), ("keyId", Int(0))])), ("expect", Ok(Config(Pk07))), SwiftConfigSkip]),
      Parse("parse-config-multiple-takes-first", "Two configs concatenated; the first public key wins.",
            Config(Pk07) + Config(Bytes(32, 8)), Ok(Pk07)),
      Parse("parse-config-truncated-pubkey", "Public key cut to 16 bytes.", "00" + Kem + Bytes(16, 7), Err("INVALID_KEY_CONFIG")),
      Parse("parse-config-empty", "An empty discovery body is not a key configuration.", "", Err("INVALID_KEY_CONFIG")),
      Parse("parse-config-truncated-kem-id", "Only the key id and first KEM-id byte are present.", "0000", Err("INVALID_KEY_CONFIG")),
      Parse("parse-config-truncated-suites-length", "The public key is complete but the suites-length field has one byte.",
            "00" + Kem + Pk07 + "00", Err("INVALID_KEY_CONFIG")),
      Parse("parse-config-declared-suites-truncated", "The suites length declares eight bytes but only one suite follows.",
            "00" + Kem + Pk07 + "0008" + Suite, Err("INVALID_KEY_CONFIG")),
      Parse("parse-config-no-suites", "Cipher suites length is zero.", "00" + Kem + Pk07 + "0000", Err("INVALID_KEY_CONFIG")),
      Parse("parse-config-suites-len-not-multiple-of-4", "Cipher suites length is 3.",
            "00" + Kem + Pk07 + "0003" + "000100", Err("INVALID_KEY_CONFIG")),
      Parse("parse-config-key-id-nonzero", "key_id is opaque to the client; a non-zero value is accepted (SPEC 3.2 pins nothing about it).",
            Cfg("07", Kem, Pk07, Suite), Ok(Pk07)),
      Parse("parse-config-short-unsupported-kem", "Only the key id and a foreign KEM id are present: the KEM is checked as soon as it is readable, so this is UNSUPPORTED_SUITE rather than a truncation.",
            "00" + "0010", Err("UNSUPPORTED_SUITE")),
      Parse("parse-config-suites-len-5-complete", "Cipher suites length is 5 and five bytes follow: a structural error (not a multiple of 4), INVALID_KEY_CONFIG rather than a suite count problem.",
            "00" + Kem + Pk07 + "0005" + Suite + "00", Err("INVALID_KEY_CONFIG")),
      Parse("parse-config-unsupported-kem", "KEM id is P-256, not X25519.", Cfg("00", "0010", P256Generator, Suite), Err("UNSUPPORTED_SUITE")),
      Parse("parse-config-unsupported-aead", "AEAD id is ChaCha20-Poly1305, not AES-256-GCM.", Cfg("00", Kem, Pk07, Kdf + "0003"), Err("UNSUPPORTED_SUITE")),
      Parse("parse-config-unsupported-kdf", "KDF id is HKDF-SHA384, not HKDF-SHA256.", Cfg("00", Kem, Pk07, "0002" + Aead), Err("UNSUPPORTED_SUITE")),
      Parse("parse-config-two-suites", "The suites list declares two entries, both the pinned pair. SPEC 3.2 requires exactly one suite.",
            Cfg("00", Kem, Pk07, Suite + Suite), Err("UNSUPPORTED_SUITE"))
    ]
  }

  // ---------------------------------------------------------------------------
  // End to end, against the oracle server's scenarios.

  function Req(verb: string, path: string, body: J, headers: J): J
  {
    Obj([("method", S(verb)), ("path", S(path)), ("body_hex", body), ("headers", headers)])
  }
  function E2e(id: string, desc: string, scenario: string, want: J, body: J, verb: string, headers: J, op: string, rest: Members): J
  {
    Fx(id, desc, "e2e", op, [("server_scenario", S(scenario)), ("request", Req(verb, "/s/" + scenario, body, headers)), ("expect", want)] + rest)
  }
  // A POST of "hello".
  function Post(id: string, scenario: string, want: J, desc: string): J
  {
    E2e(id, desc, scenario, want, S(Hello), "POST", Obj([]), "request", [])
  }
  // A GET without a body.
  function Get(id: string, scenario: string, want: J, desc: string, headers: J): J
  {
    E2e(id, desc, scenario, want, Null, "GET", headers, "request", [])
  }
  const DuplicateNonceBrowser := NoBrowser("browser-coalesces-duplicate-headers")
  const BodylessText := Hex("plaintext for bodyless request")
  const FramingHeaders := Obj([("Content-Length", S("1")), ("Transfer-Encoding", S("chunked"))])
  const CallerHeader := Obj([("X-Caller", S("v1"))])

  // Request-side wire assertions (SPEC 4.1, 5.1, 7.4): the oracle reports what
  // it received as a fixed-format line, encrypted when the request was.
  function Meta(id: string, desc: string, body: J, verb: string, line: string): J
  {
    E2e(id, desc, "request_meta", OkStatus(200, Hex(line)), body, verb, CallerHeader, "request", [])
  }

  // Token lifecycle (SPEC 6.3): after the exchange ends, whatever the outcome,
  // the token is gone.
  function Tok(id: string, scenario: string, want: J, desc: string): J
    requires want.Obj?
  {
    E2e(id, desc, scenario, With(want, [("token_after_exchange", Bool(false))]), S(Hello), "POST", Obj([]), "token_after_exchange",
        [("browser", NoBrowser("token-lifecycle-tested-in-native-adapters"))])
  }

  // SHA-256 of the large-body pattern (a 1 MiB block with block[i] = (i + seed) & 0xff,
  // repeated to the size), what every adapter streams; recompute with hashlib
  // if the pattern changes.
  function LargeBody(id: string, desc: string, size: int, digest: string): J
  {
    Fx(id, desc, "e2e", "large_body",
       [("heavy", Bool(true)), ("inputs", Obj([("size_bytes", Int(size)), ("block_seed", Int(42))])), ("server_scenario", S("digest")),
        ("request", Obj([("method", S("POST")), ("path", S("/s/digest")), ("headers", Obj([]))])),
        ("browser", Obj([("runnable", Bool(true))])), ("expect", OkStatus(200, digest)),
        ("allowed_skips", Obj([("js-chromium", S("opfs-quota-below-body-size")), ("js-firefox", S("opfs-quota-below-body-size"))]))])
  }

  function E2eFixtures(): seq<J>
  {
    [
      Post("e2e-echo-roundtrip", "echo",
           With(OkStatus(200, Hello), [("response_headers_absent", Strs(["content-length", "transfer-encoding"]))]),
           "Encrypted round trip; framing headers stripped from the decrypted response."),
      E2e("e2e-echo-large", "20 KB round trip; exercises multi-frame request encryption end to end.", "echo",
          OkStatus(200, Large()), S(Large()), "POST", Obj([]), "request", []),
      Post("e2e-missing-nonce-200", "drop_nonce_200", ErrClosed("MISSING_RESPONSE_NONCE"), "2xx with no nonce MUST fail closed, not read plaintext."),
      Post("e2e-invalid-nonce-len", "invalid_nonce_len", Err("INVALID_RESPONSE_NONCE"), "Nonce present but 16 bytes."),
      Post("e2e-invalid-nonce-hex", "invalid_nonce_hex", Err("INVALID_RESPONSE_NONCE"), "Nonce has the correct encoded length but contains non-hex characters."),
      Post("e2e-invalid-nonce-odd-hex", "invalid_nonce_odd_hex", Err("INVALID_RESPONSE_NONCE"), "Nonce contains an odd number of hex characters."),
      Post("e2e-invalid-nonce-too-long", "invalid_nonce_too_long", Err("INVALID_RESPONSE_NONCE"), "Nonce is valid hex but 33 bytes rather than 32."),
      E2e("e2e-duplicate-nonce", "Two nonce headers MUST fail closed.", "duplicate_nonce", Err("DUPLICATE_RESPONSE_NONCE"), S(Hello), "POST", Obj([]), "request",
          [("browser", DuplicateNonceBrowser), ("runners", Strs(["go", "python", "rust", "kotlin"]))]),
      E2e("e2e-duplicate-nonce-coalesced",
          "fetch and URLSession coalesce repeated headers; the merged value is not valid hex of the required length and is rejected as malformed (SPEC 4.2).",
          "duplicate_nonce", Err("INVALID_RESPONSE_NONCE"), S(Hello), "POST", Obj([]), "request",
          [("browser", DuplicateNonceBrowser), ("runners", Strs(["js", "swift"]))]),
      Post("e2e-tampered-tag", "tamper_tag", ErrClosed("AEAD_DECRYPT_FAILED"), "Flipped tag byte."),
      Post("e2e-wrong-valid-length-nonce", "wrong_nonce", ErrClosed("AEAD_DECRYPT_FAILED"), "A valid-length nonce other than the sealing nonce must fail authentication."),
      Post("e2e-partial-length-prefix-1", "partial_prefix_1", ErrClosed("FRAMING_TRUNCATED"), "Response ends after one byte of a frame-length prefix."),
      Post("e2e-partial-length-prefix-2", "partial_prefix_2", ErrClosed("FRAMING_TRUNCATED"), "Response ends after two bytes of a frame-length prefix."),
      Post("e2e-partial-length-prefix-3", "partial_prefix_3", ErrClosed("FRAMING_TRUNCATED"), "Response ends after three bytes of a frame-length prefix."),
      Post("e2e-truncated-frame", "truncate_final_frame", ErrClosed("FRAMING_TRUNCATED"), "Response ends mid-frame."),
      Post("e2e-ciphertext-shorter-than-tag", "ciphertext_shorter_than_tag", ErrClosed("AEAD_DECRYPT_FAILED"), "A complete 15-byte frame is too short to contain an AES-GCM tag."),
      Post("e2e-zero-frame-flood", "zero_frame_flood", OkStatus(200, Hello), "4096 legal empty frames must not hang or crash the response parser."),
      Post("e2e-oversized-chunk", "oversized_chunk", ErrClosed("CHUNK_TOO_LARGE"), "Length prefix exceeds the cap."),
      Post("e2e-keyconfig-422", "key_config_mismatch_422", Err("KEY_CONFIG_MISMATCH"), "422 problem+json key-config mismatch is a typed recoverable error."),
      Post("e2e-passthrough-502", "plaintext_error_502", PassBody(502, Hex("upstream unavailable")), "Non-2xx with no nonce MAY pass through as an unauthenticated body."),
      Post("e2e-encrypted-error-500", "encrypted_error_500", OkStatus(500, Hello), "A non-2xx response carrying a nonce is authenticated ciphertext and must decrypt."),
      Post("e2e-redirect-failclosed", "redirect_303", ErrClosed("UNEXPECTED_REDIRECT"), "A redirect answering an encrypted request MUST fail and MUST NOT be followed."),
      Post("e2e-redirect-with-nonce-failclosed", "redirect_303_nonce", ErrClosed("UNEXPECTED_REDIRECT"), "A nonce does not make a redirect acceptable: any 32 bytes pass as one."),
      Post("e2e-plaintext-200-failclosed", "plaintext_success_200", ErrClosed("MISSING_RESPONSE_NONCE"), "2xx plaintext MUST fail closed."),
      Post("e2e-empty-response", "empty_frame", OkStatus(200, ""), "An empty response carries one frame sealing an empty plaintext and decrypts to an empty body."),
      Post("e2e-no-frames-failclosed", "empty_encrypted", ErrClosed("FRAMING_TRUNCATED"), "A 2xx with a nonce but zero frames MUST fail closed: nothing authenticates it."),
      Get("e2e-bodyless-passthrough", "bodyless_plaintext", OkStatus(200, BodylessText),
          "Bodyless request is unencrypted; its plaintext response is returned as-is (SPEC 7.4).", Obj([])),
      E2e("e2e-empty-body-post", "A POST with a known zero-length body has no payload body: sent without the key header, plaintext response (SPEC 5.1, 7.4).",
          "bodyless_plaintext", OkStatus(200, BodylessText), S(""), "POST", Obj([]), "request", []),
      Post("e2e-missing-nonce-204", "drop_nonce_204", ErrClosed("MISSING_RESPONSE_NONCE"),
           "A 204 with no nonce is still a 2xx to an encrypted request: fail closed, even with nothing to decrypt."),
      Post("e2e-invalid-nonce-204", "invalid_nonce_204", Err("INVALID_RESPONSE_NONCE"),
           "A 204 with a 16-byte nonce: the header is validated before the bodyless-status rule (SPEC 5.1)."),
      // The oracle encodes a Go map, so keys are sorted.
      Get("e2e-bodyless-keyconfig-422", "key_config_mismatch_422",
          PassBody(422, Hex("{\"title\":\"stale client key configuration\",\"type\":\"urn:ietf:params:ehbp:error:key-config\"}\n")),
          "A key-config problem answering a bodyless request is plaintext like any other response to it (SPEC 5.4.2, 7.4): returned unchanged, never KEY_CONFIG_MISMATCH.", Obj([])),
      E2e("e2e-caller-framing-headers", "Caller-supplied Content-Length and Transfer-Encoding are dropped on an encrypted request; the implementation frames the body itself (SPEC 5.1).",
          "echo", OkStatus(200, Hello), S(Hello), "POST", FramingHeaders, "request", []),
      Get("e2e-caller-framing-headers-bodyless", "bodyless_plaintext", OkStatus(200, BodylessText),
          "Caller-supplied framing headers are dropped on a bodyless request too (SPEC 5.1).",
          Obj([("Content-Length", S("5")), ("Transfer-Encoding", S("chunked"))])),
      Post("e2e-empty-nonce-200", "empty_nonce_200", Err("INVALID_RESPONSE_NONCE"), "A nonce header present with an empty value is malformed, not absent (SPEC 4.2)."),
      Post("e2e-empty-nonce-502", "empty_nonce_502", Err("INVALID_RESPONSE_NONCE"), "An empty nonce value on a non-2xx is not a pass-through: the header is present and malformed (SPEC 4.2)."),
      Post("e2e-invalid-nonce-huge", "invalid_nonce_huge", Err("INVALID_RESPONSE_NONCE"), "A 64 KiB hex nonce is rejected for its length without exhausting the stack or reading plaintext."),
      Post("e2e-invalid-nonce-0x-prefix", "invalid_nonce_0x", Err("INVALID_RESPONSE_NONCE"), "64 characters starting with 0x: strict hex has no prefix (SPEC 4.1)."),
      Post("e2e-invalid-nonce-whitespace", "invalid_nonce_space", Err("INVALID_RESPONSE_NONCE"), "64 characters with an embedded space: strict hex has no whitespace (SPEC 4.1)."),
      Post("e2e-problem-422-other-type", "problem_422_other_type", PassBody(422, Hex("{\"type\":\"urn:example:validation\",\"title\":\"bad field\"}")),
           "A 422 problem document with another type is an application error: pass through, not KEY_CONFIG_MISMATCH (SPEC 5.4.2)."),
      Post("e2e-problem-422-text-plain", "problem_422_text_plain", Pass(422), "The key-config type under text/plain is not a problem document (SPEC 5.4.2)."),
      Post("e2e-problem-422-numeric-title", "problem_422_numeric_title", Err("KEY_CONFIG_MISMATCH"), "type decides; a non-string title only loses its text (SPEC 5.4.2)."),
      Post("e2e-problem-422-case-keys", "problem_422_case_keys", Pass(422), "JSON member names are case-sensitive: \"Type\" is not the type member (SPEC 5.4.2)."),
      Post("e2e-problem-422-oversized", "problem_422_oversized", Pass(422), "A key-config type inside a document above 64 KiB is not parsed: pass through (SPEC 5.4.2)."),
      Post("e2e-problem-422-deep-array", "problem_422_deep_array", Pass(422), "50 000 nested arrays in a 422 body must not crash the client's JSON parser: not a problem document, pass through."),
      Post("e2e-encrypted-422", "encrypted_422_problem", OkStatus(422, Hex("{\"type\":\"urn:ietf:params:ehbp:error:key-config\",\"title\":\"encrypted\"}")),
           "A 422 that carries a nonce is ciphertext like any other response (SPEC 5.1): decrypted, never KEY_CONFIG_MISMATCH."),
      Meta("e2e-request-meta-encrypted", "An encrypted request carries exactly one lowercase 64-hex key header and the caller's own headers.",
           S(Hello), "POST", "enc=1:64:lower x-caller=v1"),
      Meta("e2e-request-meta-bodyless", "A bodyless request carries no key header and keeps the caller's own headers (SPEC 7.4).",
           Null, "GET", "enc=0:0:none x-caller=v1"),
      Tok("e2e-token-consumed-after-decrypt", "echo", OkStatus(200, Hello), "The token is cleared once the response has been fully decrypted."),
      Tok("e2e-token-consumed-on-passthrough", "plaintext_error_502", PassBody(502, Hex("upstream unavailable")), "An unauthenticated pass-through consumes the token (SPEC 5.1)."),
      Tok("e2e-token-consumed-on-keyconfig-422", "key_config_mismatch_422", Err("KEY_CONFIG_MISMATCH"), "A key-configuration problem consumes the token (SPEC 5.4.2)."),
      Tok("e2e-token-consumed-on-tamper", "tamper_tag", ErrClosed("AEAD_DECRYPT_FAILED"), "A body that stops authenticating consumes the token."),
      Tok("e2e-token-consumed-on-missing-nonce", "drop_nonce_200", ErrClosed("MISSING_RESPONSE_NONCE"), "A protocol failure before any plaintext consumes the token."),
      E2e("e2e-unknown-length-empty", "Select the exchange mode from the plaintext produced by an unknown-length stream.", "bodyless_plaintext",
          With(OkStatus(200, BodylessText), [("response_headers_absent", Strs(["ehbp-response-nonce"]))]), S(""), "POST", Obj([]), "request_stream", []),
      E2e("e2e-unknown-length-payload", "Select the exchange mode from the plaintext produced by an unknown-length stream.", "echo",
          With(OkStatus(200, Hex("streamed")), [("response_headers_present", Strs(["ehbp-response-nonce"]))]), S(Hex("streamed")), "POST", Obj([]), "request_stream", []),
      E2e("e2e-token-consumed-on-early-close", "Read one response byte and close the body. Closing consumes the live recovery token.", "echo",
          With(OkStatus(200, Hex("h")), [("token_before_close", Bool(true)), ("token_after_close", Bool(false))]), S(Hello), "POST", Obj([]), "close_response_early", []),
      // Timing and heavy streaming cases.
      E2e("e2e-token-before-response",
          "SPEC 6: the session recovery token is obtainable once the body is sealed and before the request is sent. Timing-based with a 10x margin: the oracle holds its reply for 5 s; the adapter reads the token 500 ms after sending, while the response is pending, then completes the exchange.",
          "hold", With(OkStatus(200, Hello), [("token_before_response", Bool(true))]), S(Hello), "POST", Obj([]), "token_before_response", []),
      LargeBody("e2e-large-body-3gib",
                "A 3 GiB request body streams through encryption and the server's streaming decryptor; the client must not buffer it. Body bytes: 1 MiB block with block[i] = (i + seed) & 0xff, repeated. The oracle replies with the raw SHA-256 of the plaintext. Browsers spool the frames to the Origin Private File System and upload the file; a browser whose storage quota cannot hold the body skips with the declared reason.",
                3221225472, "5bb8a0daf79ae7af2f38f80ac1ce890a741392362bfb96b37c5fe03261ab9a22"),
      LargeBody("e2e-large-body-256mib",
                "A 256 MiB request body streams through encryption on every runner, including browsers via the OPFS spool, so the bounded-memory upload path is exercised even where quota blocks the 3 GiB body. Same pattern and oracle route as e2e-large-body-3gib.",
                268435456, "f9a891ea18e0514540299aa52cc585ff94b199c11e0f1bc9cae12542893eb327")
    ]
  }

  // ---------------------------------------------------------------------------
  // Shape: observational only; the harness records the received wire shape.

  function ShapeFixtures(): seq<J>
  {
    [
      ShapeFx("shape-small-body", Hello, "Small body: compares transfer-encoding and framing."),
      ShapeFx("shape-large-body", Large(), "20 KB body: reveals clients that split the request into frames.")
    ]
  }

  function ShapeFx(id: string, bodyHex: string, desc: string): J
  {
    Fx(id, desc, "shape", "request",
       [("server_scenario", S("shape")), ("request", Req("POST", "/s/shape", S(bodyHex), Obj([]))), ("expect", Obj([("outcome", S("ok"))]))])
  }

  // ---------------------------------------------------------------------------
  // Client API: discovery (capability-gated for Swift) and request guards.

  function Capi(id: string, op: string, want: J, desc: string, inputs: Members): J
  {
    Fx(id, desc, "client-api", op,
       [("inputs", Obj(inputs)), ("browser", NoBrowser("client-api-ops-tested-in-native-adapters")), ("expect", want)]
       + (if op == "discover" then [("allowed_skips", Obj([("swift", S("swift-client-has-no-discovery-or-request-guards"))]))] else []))
  }
  function Discover(id: string, target: string, want: J, desc: string): J { Capi(id, "discover", want, desc, [("target", S(target))]) }
  function ReservedHeader(id: string, header: string, desc: string): J
  {
    Capi(id, "reject_reserved_header", Err("INVALID_INPUT"), desc, [("header", S(header))])
  }

  function ClientApiFixtures(): seq<J>
  {
    [
      Discover("discover-bad-content-type", "bad_ct", Err("INVALID_KEY_CONFIG"), "Discovery rejects a key config served under the wrong content type."),
      Discover("discover-non-200", "non200", Err("INVALID_KEY_CONFIG"), "Discovery rejects a non-200 key-config response."),
      Discover("discover-content-type-params", "ct_params", Obj([("outcome", S("ok"))]), "Discovery accepts the media type case-insensitively and with parameters (SPEC 3.1)."),
      Discover("discover-status-203", "status203", Err("INVALID_KEY_CONFIG"), "Discovery accepts status 200 only; a 203 (proxy-modified) config is rejected (SPEC 3.1)."),
      Discover("discover-redirect", "redirect", Err("INVALID_KEY_CONFIG"), "Discovery never follows a redirect, even to the valid config (SPEC 3.1)."),
      Discover("discover-trailing-bytes", "trailing", Obj([("outcome", S("ok"))]), "Bytes after the first key_config are ignored (SPEC 3.1)."),
      ReservedHeader("harden-reserved-header", "Ehbp-Response-Nonce", "Client rejects a caller setting Ehbp-Response-Nonce."),
      ReservedHeader("harden-reserved-header-encapsulated-key", "Ehbp-Encapsulated-Key", "Client rejects a caller setting Ehbp-Encapsulated-Key."),
      ReservedHeader("harden-reserved-header-host", "Host", "Client rejects a caller-supplied Host header: the authority follows the validated URL (SPEC 5.1)."),
      Capi("harden-cross-origin", "reject_cross_origin", Err("INVALID_INPUT"), "Client rejects a request to a different origin.", []),
      Capi("harden-url-credentials", "reject_url_credentials", Err("INVALID_INPUT"), "Client rejects credentials embedded in the URL.", []),
      Capi("residue-selfcheck", "residue_selfcheck", Ok(""),
           "The core's SelfCheckActions run through this language's crypto bindings and are judged by SelfCheckJudge (handler.md section 7); body_hex is the hex of the failed checks, so empty means pass.", [])
    ]
  }

  // ---------------------------------------------------------------------------
  // Server security: the one server implementation (Go), through its public
  // identity/middleware APIs in an isolated adapter process.

  function Server(id: string, op: string, mutation: string, want: J, desc: string, inputs: Members): J
  {
    Fx(id, desc, "server", op, [("runners", Strs(["go"])), ("inputs", Obj([("mutation", S(mutation))] + inputs)), ("expect", want)])
  }

  function ServerFixtures(): seq<J>
  {
    [
      Server("server-request-duplicate-encapsulated-key", "decrypt_request", "duplicate_encapsulated_key", Err("INVALID_ENCAPSULATED_KEY"),
             "Two encapsulated-key headers are ambiguous and must be rejected.", []),
      Server("server-request-oversized-frame", "decrypt_request", "oversized_frame", Err("CHUNK_TOO_LARGE"),
             "A request frame above 64 MiB must be rejected before allocation.", []),
      Server("server-request-partial-prefix", "decrypt_request", "partial_prefix", Err("FRAMING_TRUNCATED"),
             "A request ending midway through its length prefix is truncated.", []),
      Server("server-request-zero-frame-burst", "decrypt_request", "zero_frame_burst", Ok(Hex("after-zero-frames")),
             "Ten thousand legal empty frames must not recurse, hang, or crash.", [("zeroFrameCount", Int(10000))]),
      Server("server-middleware-trailing-tamper", "middleware_request", "trailing_tamper",
             With(Err("AEAD_DECRYPT_FAILED"), [("plaintext_emitted_before_error", Bool(true)), ("bytes_emitted_before_error", Int(2 * 65536))]),
             "Request frames authenticate and are released one at a time (SPEC 4.3). A tampered trailing frame fails in the handler's read: the authenticated prefix (two 64 KiB frames) was delivered, nothing from the bad frame is.", [])
    ]
  }

  method Main()
  {
    Family("config", ConfigFixtures());
    Family("e2e", E2eFixtures());
    Family("shape", ShapeFixtures());
    Family("client-api", ClientApiFixtures());
    Family("server-security", ServerFixtures());
  }
}
