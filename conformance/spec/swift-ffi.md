# The Swift SDK over the C ABI

Swift has no Dafny backend. Its core is the Rust bundle of
`dafny/ehbp_events.dfy` (`dafny/gen-events/rs`, the same crate the Rust SDK
links) behind a six-function C ABI in `rust/ffi` (`ehbp-ffi`, cdylib and
staticlib), packaged as `swift/EHBPCore.xcframework` by `swift/build-core.sh`.
The Swift residue (`swift/Sources/EHBP/Residue.swift`, pump included) has the
layout of handler.md section 4 and drives the core through `Core.swift`:
the generated types and coders (`ffi` region), the generated `Core` enum of
op wrappers (`core` region) and the hand-written `CoreState`.

## Functions

| Function | Contract |
| --- | --- |
| `EhbpState *ehbp_state_new(in, len)` | A core `State` from an encoded constructor (table below); NULL on malformed input. Opaque. |
| `void ehbp_state_free(state)` | Releases it. |
| `int32_t ehbp_step(state, event, len, out, out_len)` | `Step(state, event)`: replaces the state in place and returns the encoded `seq<Action>`. |
| `int32_t ehbp_keys_of(state, out, out_len)` | `KeysOf(state)`: encoded `Option<(bytes, bytes)>`, the derived key and nonce base after `Done`. |
| `int32_t ehbp_call(op, in, len, out, out_len)` | One pure core function by op number (`OPS` in `conformance/tools/gen/ffi.py`), encoded arguments in, encoded result out. |
| `void ehbp_free_buf(buf, len)` | Releases a buffer the core handed out. |

Status: `0` ok, `1` malformed input, `2` unknown op, `-1` the core panicked
(never unwound into the caller). Every buffer written to `out` is allocated by
Rust and released once with `ehbp_free_buf`; inputs are borrowed for the call.

Every entry point runs on the caller's thread under `catch_unwind`
(`guarded` in `lib.rs`). The core parses JSON without deep recursion, so a
512 KiB Swift cooperative thread is enough: the test
`deep_problem_body_steps_from_a_small_stack` steps a 50 000-deep problem body
from one.

## Encoding

Big-endian, length-prefixed, no alignment. Both sides' coders are rendered
from the Dafny datatype declarations of `dafny/ehbp.dfy` and
`dafny/ehbp_events.dfy` by `python3 conformance/tools/gen.py ffi` into the
`ffi:begin`..`ffi:end` region of `rust/ffi/src/lib.rs` and
`swift/Sources/EHBP/Core.swift`; `gen.py --check ffi` is the drift gate
(`check.py generated` runs it). Nothing about a type's wire form is typed by
hand, so adding a constructor or a field to a datatype regenerates both sides
in lockstep. The rules the generator applies:

| Dafny type | Bytes |
| --- | --- |
| `bool` | 1: `0` or `1` |
| `int`, `nat` | 8, two's-complement big-endian |
| `uint64` | 8, big-endian |
| `bytes` (`seq<uint8>`) | u32 length, then the bytes |
| `string` | u32 byte length, then UTF-8 |
| `seq<T>` | u32 count, then each `T` |
| `(A, B)` | `A` then `B` |
| datatype, several constructors | 1: the constructor's index in declaration order, then its fields in declaration order (`Code`, `Stream`, `BodyEnd`, `Event`, `Action`, `SessionAction`, and `Option<T>`: `None` 0, `Some` 1 then `T`; `Result<T>`: `Ok` 0 then `T`, `Err` 1 then `Code` and the message `string`) |
| datatype, one constructor | no tag, the fields in declaration order (`Token`, `Origin`, `SessionStore`) |
| type alias (`Headers`) | its target (`seq<(string, string)>`) |

What crosses the ABI is `ROOTS` and the op signatures `OPS` in `gen/ffi.py`;
the closure over their field types is what gets a coder, so a Dafny type the
renderer cannot encode (a newtype other than `uint64`, a type in a position
the Swift side has no value for) fails the generation loudly rather than
silently. On the Swift side a multi-constructor datatype is an `enum` whose
cases carry the Dafny field names as labels, a one-constructor datatype a
`struct`, `Option<T>` is `T?`, and `Result<T>` decodes to `T` or throws the
core's error (Swift never encodes one).

### State constructors (`ehbp_state_new`)

| Tag | Core | Fields |
| --- | --- | --- |
| 0 | `Initial(origin, publicKey)` | Origin, publicKey bytes |
| 1 | `ResponseOnly(NoOrigin, token)` | Token |

The token-only helpers are the core's own `DeriveStart` and `DecryptStart`,
run by the pump: a `ResponseOnly` state stepped with `ResponseHead(200,
[(Ehbp-Response-Nonce, hex(nonce))], false)`, then `KeysOf` after `Done`
(derivation), or `Chunk(ResponseBody, ..)` and `CallerRead` events over the
framed body (decryption).

### Pure helpers (`ehbp_call`)

The op number is the index into `OPS` in `gen/ffi.py`, which names the core
function, its module, its argument types and its result type; the Rust `call`
table is rendered from it (arguments decoded in order, the result encoded).
The Swift `Core` wrappers in `Core.swift` are rendered by `gen.py core`
(one per op of `OPS`) over the generated coders.

The generated Rust test round-trips every constructor of every type the ABI
crosses (its sample list is rendered from the same parse, so a new constructor
cannot be missed) and checks that the tag is the declaration index; the
hand-written tests drive the step function through the C entry points and
step the 50 000-deep problem body from a 512 KiB thread.

## Build and release

`swift/build-core.sh` runs `cargo build --release` in `rust/ffi` for every
Apple target rustup has installed (macOS always; arm64 and x86_64 are lipo'd
when both are present; iOS device and simulator slices only if their targets
are installed; it never installs one), assembles the xcframework by hand (no
Xcode needed: an `Info.plist` and one `libehbp_ffi.a` plus `Headers/ehbp.h`
and a module map per slice) and writes it to `swift/EHBPCore.xcframework`,
which `swift/.gitignore` keeps out of the tree. `Package.swift` declares it as the
`EHBPCore` binary target the `EHBP` target depends on, by local path; the
conformance harness runs the script before building the Swift adapter.

Release: CI builds the xcframework on a macOS runner with the macOS, iOS and
iOS-simulator targets installed, zips it, attaches it to the GitHub release
of the tag, and `Package.swift` switches the binary target to
`url: .../v<version>/EHBPCore.xcframework.zip` with its `checksum` (from
`swift package compute-checksum`), so consumers of the package never need
Rust. That workflow does not exist yet.
