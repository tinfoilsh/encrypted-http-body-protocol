// Typed view of the Dafny-generated event core (dafny/gen-events/js/ehbp.js,
// copied to ./gen by the build, runtime patches included): the pure module
// `core` (EHBP) and the event-driven module `ev` (EHBPEvents). Every protocol
// decision is made there; the conversions between JS and Dafny values live in
// residue.ts.
import type BigNumber from 'bignumber.js';
// @ts-expect-error the generated CommonJS module has no declarations; the parts used are typed below.
import gen from './gen/ehbp.cjs';

export type Seq<T> = T[] & { toVerbatimString(asLiteral: boolean): string };
export type Bytes = Seq<number>;
export type Str = Seq<unknown>;
export type HeadersSeq = Seq<[Str, Str]>;
export interface Code { $tag: number }
export interface Option<T> { is_Some: boolean; is_None: boolean; dtor_value: T }
export interface Result<T> { is_Ok: boolean; is_Err: boolean; dtor_value: T; dtor_code: Code; dtor_message: Str }
export interface Origin { dtor_scheme: Str; dtor_host: Str; dtor_port: BigNumber }
export interface Token { dtor_exportedSecret: Bytes; dtor_requestEnc: Bytes }
/** A generated datatype value: `is_<Ctor>` tests and `dtor_<field>` accessors. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface Datatype { readonly [k: `is_${string}`]: boolean; readonly [k: `dtor_${string}`]: any }
export type Event = Datatype;
export type Action = Datatype;
export type State = Datatype;
export type Job = Datatype;
export interface SessionStore { dtor_generation: BigNumber; dtor_token: Option<Token> }

interface Core {
  Ascii(s: Str): Bytes;
  DecodeHex(s: Str): Option<Bytes>;
  EncodeHex(b: Bytes): Str;
  ComputeNonce(nonceBase: Bytes, seqNo: BigNumber): Bytes;
  NonceFor(nonceBase: Bytes, seqNo: BigNumber): Result<Bytes>;
  CheckPublicKey(b: Bytes): Result<Bytes>;
  ParseConfig(data: Bytes): Result<Bytes>;
  MarshalConfig(publicKey: Bytes): Result<Bytes>;
  ValidToken(t: Token): boolean;
  ValidateTokenFields(exportedSecretHex: Option<Str>, requestEncHex: Option<Str>): Result<Token>;
  MakeOrigin(scheme: Str, host: Str, port: Option<BigNumber>, hasUserinfo: boolean): Result<Origin>;
  ValidateRequest(origin: Origin, target: Result<Origin>, headers: HeadersSeq): Result<unknown>;
  OriginUrl(origin: Origin): Str;
  /** The canonical spelling of a code ("" for Transport) and every code that has one. */
  CodeString(c: Code): Str;
  Codes: Seq<Code>;
  KemX25519: number; KdfHkdfSha256: number; AeadAes256Gcm: number;
  PublicKeyLength: BigNumber; RequestEncLength: BigNumber; ExportLength: BigNumber; ResponseNonceLength: BigNumber;
  KeyLength: BigNumber; NonceLength: BigNumber; RequestFrameBytes: number;
  HpkeRequestInfo: Str; ExportLabel: Str; ResponseKeyLabel: Str; ResponseNonceLabel: Str;
  EncapsulatedKeyHeader: Str; ResponseNonceHeader: Str; KeysPath: Str;
  KeysMediaType: Str; ProblemJsonMediaType: Str; KeyConfigProblemType: Str;
}
interface Events {
  Initial(origin: Origin, publicKey: Bytes): State;
  Step(s: State, e: Event): [State, Seq<Action>];
  NewSession: SessionStore;
  SessionApply(store: SessionStore, action: Datatype): SessionStore;
  SelfCheckActions: Seq<Action>;
  SelfCheckJudge(results: Seq<Event>): Seq<Str>;
  Extract(salt: Bytes, ikm: Bytes): Job;
  Expand(prk: Bytes, info: Bytes, length: BigNumber): Job;
  JobAction(j: Job): Action;
  JobStep(j: Job, e: Event): Datatype;
  ParseToken(json: Str): [Option<Str>, Option<Str>];
  FormatToken(exportedSecretHex: Str, requestEncHex: Str): Str;
  BasePoint: Bytes;
  NoCtx: Datatype;
}
interface SeqClass {
  new <T>(length?: number): Seq<T>;
  of<T>(...items: T[]): Seq<T>;
  UnicodeFromString(s: string): Str;
  Concat<T>(a: Seq<T>, b: Seq<T>): Seq<T>;
  prototype: { slice(start?: unknown, end?: unknown): unknown };
}
type Ctors = Record<string, (...args: unknown[]) => Datatype>;
export const { EHBP, EHBPEvents, _dafny } = gen as {
  EHBP: {
    __default: Core;
    Result: { create_Err(code: Code, message: Str): Result<never> };
    Option: { create_Some<T>(v: T): Option<T>; create_None<T>(): Option<T> };
    Token: { create_Token(exportedSecret: Bytes, requestEnc: Bytes): Token };
    Code: { create_InvalidInput(): Code };
  };
  EHBPEvents: {
    __default: Events;
    Event: {
      create_Start(verb: Str, url: Str, scheme: Str, host: Str, port: BigNumber, hasPort: boolean, hasUserinfo: boolean, headers: HeadersSeq, hasBody: boolean): Event;
      create_DiscoverStart(): Event;
      create_SessionBegun(generation: BigNumber): Event;
      create_RandomResult(data: Bytes): Event;
      create_X25519Result(point: Bytes): Event;
      create_HmacResult(mac: Bytes): Event;
      create_AeadSealResult(ciphertext: Bytes): Event;
      create_AeadOpenResult(ok: boolean, plaintext: Bytes): Event;
      create_ResponseHead(status: BigNumber, headers: HeadersSeq, redirected: boolean): Event;
      create_Chunk(stream: Datatype, data: Bytes, eof: boolean): Event;
      create_StreamFailed(stream: Datatype): Event;
      create_CallerRead(): Event;
      create_CallerClose(): Event;
    };
    Stream: { create_RequestBody(): Datatype; create_ResponseBody(): Datatype };
    SessionAction: { create_Begin(): Datatype; create_Publish(generation: BigNumber, token: Token): Datatype; create_Clear(generation: BigNumber): Datatype };
    State: { create_State(phase: Datatype, origin: Origin, publicKey: Bytes, verb: Str, url: Str, headers: HeadersSeq, generation: BigNumber, published: boolean, token: Token, ctx: Datatype): State };
    Phase: Ctors; Upload: Ctors; Response: Ctors;
  };
  _dafny: { Seq: SeqClass; Tuple: { of<T>(...items: T[]): T[] }; CodePoint: new (value: number) => unknown };
};
export const core = EHBP.__default;
export const ev = EHBPEvents.__default;
export const { Option, Token } = EHBP;
export const { Event, SessionAction, Stream } = EHBPEvents;
export const { Seq, Tuple } = _dafny;
// The same BigNumber copy the generated module loaded, whatever this module's loader resolves.
const Big = (core.NonceLength as BigNumber).constructor as new (v: number | string) => BigNumber;

export const EMPTY: Uint8Array = new Uint8Array(0);
export const int = (n: number | bigint): BigNumber => new Big(n.toString());
export const num = (n: BigNumber): number => n.toNumber();
