// Native upload policy for browsers, used by residue.ts `send`: where fetch
// cannot stream a request body, the sealed frames are spooled to memory or to
// the Origin Private File System before the one transaction. Nothing here
// touches the protocol.
import { core, num } from './core.js';

/** @internal true where fetch streams a ReadableStream body (Node). */
export function canStreamUpload(): boolean {
  const proc = (globalThis as { process?: { versions?: { node?: string } } }).process;
  return typeof proc?.versions?.node === 'string';
}

/**
 * Browser sink for the sealed frames. Bodies up to spoolThresholdBytes stay
 * in memory as one Blob of frames; a body that grows past the threshold spills
 * to an Origin Private File System file, which both engines stream from disk.
 * A known-size source above the threshold spills from the first frame.
 * shortcut: Safari exposes OPFS only through sync access handles in a worker, so it stays in memory; add a worker spool if Safari uploads must be bounded.
 */
export async function spool(frames: ReadableStream<Uint8Array>, knownSize?: number): Promise<{ body: BodyInit; cleanup?: () => Promise<void> }> {
  const threshold = spoolThreshold();
  const parts: Uint8Array[] = [];
  let buffered = 0;
  let file: { writer: FileSystemWritableFileStream; handle: FileSystemFileHandle; cleanup: () => Promise<void> } | undefined;
  const reader = frames.getReader();

  // Opens the spool file, writes what is buffered so far in order, and drops
  // the buffer. Returns false (and keeps buffering) when OPFS cannot take it.
  const spill = async (remaining: number | undefined): Promise<boolean> => {
    const opened = await openSpoolFile(remaining);
    if (!opened) return false;
    try {
      for (const part of parts) await opened.writer.write(part as unknown as BufferSource);
    } catch (err) {
      await opened.writer.abort(err).catch(() => {});
      await opened.cleanup().catch(() => {});
      throw err;
    }
    parts.length = 0;
    file = opened;
    return true;
  };

  try {
    let spillRefused = false;
    if (knownSize !== undefined && framedSize(knownSize) > threshold) {
      spillRefused = !(await spill(framedSize(knownSize)));
    }
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (file) {
        await file.writer.write(value as unknown as BufferSource); // awaited per chunk: backpressure bounds memory
        continue;
      }
      parts.push(value);
      buffered += value.byteLength;
      if (buffered > threshold && !spillRefused) spillRefused = !(await spill(undefined));
    }
  } catch (err) {
    // Release the source (the frame stream forwards the cancel) and abort any
    // writable so the original error (quota, I/O) is what surfaces.
    await reader.cancel(err).catch(() => {});
    if (file) {
      await file.writer.abort(err).catch(() => {});
      await file.cleanup().catch(() => {});
    }
    throw err;
  }

  if (!file) return { body: new Blob(parts as BlobPart[]) };
  try {
    await file.writer.close();
    return { body: await file.handle.getFile(), cleanup: file.cleanup };
  } catch (err) {
    await file.writer.abort(err).catch(() => {});
    await file.cleanup().catch(() => {});
    throw err;
  }
}

/**
 * Creates the OPFS spool file, or returns undefined when OPFS is unavailable
 * or its quota cannot hold `expectedBytes` (twice that, since Chromium's
 * quota tracks free disk and shrinks while the spool is written).
 */
async function openSpoolFile(expectedBytes: number | undefined): Promise<{ writer: FileSystemWritableFileStream; handle: FileSystemFileHandle; cleanup: () => Promise<void> } | undefined> {
  const storage = (globalThis as { navigator?: { storage?: StorageManager } }).navigator?.storage;
  const canSpool =
    typeof storage?.getDirectory === 'function' &&
    typeof (globalThis as { FileSystemFileHandle?: { prototype: { createWritable?: unknown } } }).FileSystemFileHandle?.prototype?.createWritable === 'function';
  if (!canSpool) return undefined;
  const root = await storage.getDirectory();
  // Sweep first: a stale spool from a dead page could otherwise hold the quota this upload needs.
  await sweepOrphanedSpools(root);
  if (typeof storage.estimate === 'function') {
    const { quota = 0, usage = 0 } = await storage.estimate();
    const need = expectedBytes ?? spoolThreshold();
    if (quota - usage < need * 2) return undefined;
  }
  const name = `${spoolPrefix}${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const cleanup = () => root.removeEntry(name);
  const handle = await root.getFileHandle(name, { create: true });
  try {
    return { writer: await handle.createWritable(), handle, cleanup };
  } catch (err) {
    await cleanup().catch(() => {});
    throw err;
  }
}

/** Framed bytes a body may reach in memory before it spills to OPFS. */
const spoolThresholdBytes = 64 * 1024 * 1024;
/** @internal test hook: lower the threshold so the spill path runs on small bodies. */
let spoolThresholdOverride: number | undefined;
export function setSpoolThresholdForTests(bytes: number | undefined): void { spoolThresholdOverride = bytes; }
function spoolThreshold(): number { return spoolThresholdOverride ?? spoolThresholdBytes; }

const spoolPrefix = 'ehbp-spool-';
const spoolOrphanAgeMs = 60 * 60 * 1000;

/** Encrypted size estimate of a body of `size` plaintext bytes: 4-byte length and 16-byte tag per frame. */
function framedSize(size: number): number {
  return size + Math.max(1, Math.ceil(size / core.RequestFrameBytes)) * 20;
}

/** Removes our spool files older than an hour (younger ones may belong to a concurrent upload in another tab). */
async function sweepOrphanedSpools(root: FileSystemDirectoryHandle): Promise<void> {
  const entries = (root as unknown as { keys?: () => AsyncIterable<string> }).keys?.();
  if (!entries) return;
  const cutoff = Date.now() - spoolOrphanAgeMs;
  for await (const name of entries) {
    if (!name.startsWith(spoolPrefix)) continue;
    const born = Number(name.slice(spoolPrefix.length).split('-')[0]);
    if (Number.isFinite(born) && born < cutoff) await root.removeEntry(name).catch(() => {});
  }
}

// One copy at most: the frames become Blob parts, not a second body-sized buffer.
export async function collect(stream: ReadableStream<Uint8Array>): Promise<Blob> {
  const parts: Uint8Array[] = [];
  for (const reader = stream.getReader(); ;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return new Blob(parts as BlobPart[]);
}
