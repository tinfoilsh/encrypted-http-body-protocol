// Test support: the server side of an exchange, simulated with the `hpke`
// library (an independent HPKE implementation) and the core's own key
// derivation through `core`, so the tests see what a real server would send.
import assert from 'node:assert';
import { CipherSuite, KDF_HKDF_SHA256, AEAD_AES_256_GCM, type Key } from 'hpke';
import { KEM_DHKEM_X25519_HKDF_SHA256 } from '@panva/hpke-noble';
import { PROTOCOL, core } from '../index.js';
import { core as pure } from '../core.js';
import { string } from '../residue.js';

const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
const ascii = (s: string) => new TextEncoder().encode(s);
const INFO = ascii(string(pure.HpkeRequestInfo));
const EXPORT_LABEL = ascii(string(pure.ExportLabel));
export const NONCE_LENGTH = pure.ResponseNonceLength.toNumber();

export const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
/** The DOM typings want ArrayBuffer-backed views; every array here is one. */
export const buf = (b: Uint8Array): BufferSource => b as unknown as BufferSource;
export const unhex = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, 'hex'));

/** A server key pair: the public key for the Transport, the private key for SetupRecipient. */
export async function serverKeys(): Promise<{ publicKey: Uint8Array; privateKey: Key }> {
  const { publicKey, privateKey } = await suite.GenerateKeyPair(true);
  return { publicKey: new Uint8Array(await suite.SerializePublicKey(publicKey)), privateKey };
}

/** Opens every request frame (4-byte length prefix + ciphertext) with the recipient context. */
export async function openFrames(privateKey: Key, request: Request): Promise<{ plain: Buffer; frames: number; recipient: Awaited<ReturnType<CipherSuite['SetupRecipient']>> }> {
  const encHex = request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER);
  assert(encHex, `missing ${PROTOCOL.ENCAPSULATED_KEY_HEADER}`);
  const recipient = await suite.SetupRecipient(privateKey, unhex(encHex), { info: INFO });
  const body = new Uint8Array(await request.arrayBuffer());
  const plain: Uint8Array[] = [];
  for (let offset = 0; offset < body.byteLength;) {
    const len = new DataView(body.buffer, body.byteOffset + offset).getUint32(0, false);
    plain.push(new Uint8Array(await recipient.Open(body.slice(offset + 4, offset + 4 + len))));
    offset += 4 + len;
  }
  return { plain: Buffer.concat(plain), frames: plain.length, recipient };
}

/** The server's reply to a sealed request: `processed:<request text>` as one frame under the request's exported secret. */
export async function encryptedResponse(privateKey: Key, request: Request): Promise<Response> {
  const requestEnc = unhex(request.headers.get(PROTOCOL.ENCAPSULATED_KEY_HEADER)!);
  const { plain, recipient } = await openFrames(privateKey, request);
  const responseNonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const { key, nonceBase } = await core.deriveKeys(await recipient.Export(EXPORT_LABEL, 32), requestEnc, responseNonce);
  const aes = await crypto.subtle.importKey('raw', buf(key), 'AES-GCM', false, ['encrypt']);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: buf(core.nonceFor(nonceBase, 0)) }, aes, buf(ascii(`processed:${plain.toString()}`))));
  const frame = new Uint8Array(4 + sealed.byteLength);
  new DataView(frame.buffer).setUint32(0, sealed.byteLength, false);
  frame.set(sealed, 4);
  return new Response(frame, { headers: { [PROTOCOL.RESPONSE_NONCE_HEADER]: hex(responseNonce) } });
}
