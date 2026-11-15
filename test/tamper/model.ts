// SPDX-License-Identifier: AGPL-3.0-or-later
// Tamper model (Blueprint §7, adversary mechanics): an in-memory copy of the
// exported log and of the copied namespace, with the exact operations the
// matrix uses. Nothing here touches the frozen fixture files or a database.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { anchorPackageBytes } from '../../src/anchor/package.js';
import type { Block } from '../../src/chain/schema.js';
import { entryHashOf, sha256Hex } from '../../src/crypto/digests.js';
import { canonicalize } from '../../src/json/jcs.js';
import { parseStrictJson } from '../../src/json/strict-json.js';
import type { JsonObject, JsonValue } from '../../src/json/strict-json.js';
import { parseReceipt } from '../../src/tsa/receipt.js';
import { buildTimeStampReq } from '../../src/tsa/request.js';
import { verifyOffline } from '../../src/verify/verify.js';
import type { VerifyResult } from '../../src/verify/verify.js';
import { FIXTURE_DIR } from '../fixture-tools/fixture-files.js';

export const BUNDLE_PATH = path.resolve('certs/tsa_roots.pem');

export interface Row {
  block: JsonObject;
  entry_hash: string;
}

interface FixtureManifest {
  chain_id: string;
}

export const FIXTURE_CHAIN_ID = (JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.json'), 'utf8')) as FixtureManifest).chain_id;
export const FIXTURE_LOG = fs.readFileSync(path.join(FIXTURE_DIR, 'events.jsonl'));

/** A mutable copy of the frozen fixture: rows, namespace files and bundle bytes. */
export class Evidence {
  rows: Row[];
  files: Map<string, Uint8Array>;
  bundle: Uint8Array;

  constructor() {
    this.rows = FIXTURE_LOG.toString('utf8')
      .trimEnd()
      .split('\n')
      .map((l) => {
        const v = parseStrictJson(l) as JsonObject;
        return { block: v['block'] as JsonObject, entry_hash: v['entry_hash'] as string };
      });
    const ns = path.join(FIXTURE_DIR, FIXTURE_CHAIN_ID);
    this.files = new Map(fs.readdirSync(ns).sort().map((n) => [n, new Uint8Array(fs.readFileSync(path.join(ns, n)))]));
    this.bundle = new Uint8Array(fs.readFileSync(BUNDLE_PATH));
  }

  /** The exported log bytes: one canonical row per line, final LF (§5.3). */
  logBytes(): Buffer {
    return Buffer.from(this.rows.map((r) => `{"block":${canonicalize(r.block)},"entry_hash":"${r.entry_hash}"}\n`).join(''), 'utf8');
  }

  payload(seq: number): JsonObject {
    return this.rows[seq]!.block['payload'] as JsonObject;
  }

  // ---------- A2a / A2b primitives ----------

  /** A2b: recompute prev_hash and entry_hash from row `from` through the tail. */
  recompute(from: number): void {
    for (let i = from; i < this.rows.length; i++) {
      const r = this.rows[i]!;
      if (i > 0) r.block['prev_hash'] = this.rows[i - 1]!.entry_hash;
      r.entry_hash = entryHashOf(r.block);
    }
  }

  /** Renumber block.seq to the row index from `from` on (after a deletion or an insertion). */
  renumber(from: number): void {
    for (let i = from; i < this.rows.length; i++) this.rows[i]!.block['seq'] = i;
  }

  setPayloadField(seq: number, key: string, value: JsonValue): void {
    this.payload(seq)[key] = value;
  }

  deleteRows(from: number, toInclusive: number): void {
    this.rows.splice(from, toInclusive - from + 1);
  }

  deletePackage(k: number): void {
    this.files.delete(`${String(k)}.tsr`);
    this.files.delete(`${String(k)}.anchor.json`);
  }

  /**
   * Replaces package k with a receipt over the current row k: <k>.tsr, and an
   * <k>.anchor.json rebuilt from the current row (§4.5).
   */
  replacePackage(k: number, tsr: Uint8Array, nonceHex: string): void {
    const row = this.rows[k]!;
    this.files.set(`${String(k)}.tsr`, tsr);
    this.files.set(
      `${String(k)}.anchor.json`,
      anchorPackageBytes({
        chainId: row.block['chain_id'] as string,
        anchoredSeq: k,
        entryHash: row.entry_hash,
        block: row.block as Block,
        nonceHex,
        tsqSha256: sha256Hex(buildTimeStampReq(row.entry_hash, nonceHex)),
      }),
    );
  }

  /** In control row k+1, set only tsr_sha256 and tsa_gen_time to those of the receipt for k. */
  setControlMetadata(k: number, tsr: Uint8Array): void {
    const parsed = parseReceipt(tsr);
    if (!parsed.ok) throw new Error(`receipt for ${String(k)} does not parse`);
    this.setPayloadField(k + 1, 'tsr_sha256', sha256Hex(tsr));
    this.setPayloadField(k + 1, 'tsa_gen_time', parsed.receipt.tstInfo.genTime);
  }

  /** Writes the copy to a fresh directory and runs the offline verifier on it. */
  verify(): VerifyResult {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-tamper-'));
    const ns = path.join(dir, FIXTURE_CHAIN_ID);
    fs.mkdirSync(ns);
    for (const [n, b] of this.files) fs.writeFileSync(path.join(ns, n), b);
    const logPath = path.join(dir, 'events.jsonl');
    fs.writeFileSync(logPath, this.logBytes());
    const bundlePath = path.join(dir, 'tsa_roots.pem');
    fs.writeFileSync(bundlePath, this.bundle);
    try {
      return verifyOffline({ logPath, checkpointsPath: ns, bundlePath });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
}

/** The ANCHOR_TIME line of a receipt, derived from its bytes (§6b group 7). */
export function anchorTimeLine(k: number, tsr: Uint8Array): string {
  const parsed = parseReceipt(tsr);
  if (!parsed.ok) throw new Error(`receipt ${String(k)} does not parse`);
  const t = parsed.receipt.tstInfo;
  if (t.accuracy === null) return `ANCHOR_TIME ${String(k)} ${t.genTime} ACCURACY_NS unspecified LATEST_BOUND_NS unspecified`;
  const a = t.accuracy;
  const ns = (a.seconds ?? 0n) * 1_000_000_000n + (a.millis ?? 0n) * 1_000_000n + (a.micros ?? 0n) * 1_000n;
  return `ANCHOR_TIME ${String(k)} ${t.genTime} ACCURACY_NS ${ns.toString()} LATEST_BOUND_NS ${(parsed.genTimeNs + ns).toString()}`;
}

/** Full §6b exit-0 output for the given coverage and the receipts of the remaining packages. */
export function successStdout(e: Evidence, lines: string[], anchored: number[]): string {
  const times = anchored.map((k) => anchorTimeLine(k, e.files.get(`${String(k)}.tsr`)!));
  return [...lines, ...times].map((l) => `${l}\n`).join('');
}

/** True when two logs differ in some block or entry_hash, not only in envelope whitespace. */
export function differsInBlockOrHash(a: Buffer, b: Buffer): boolean {
  const norm = (x: Buffer): string =>
    x
      .toString('utf8')
      .trimEnd()
      .split('\n')
      .map((l) => canonicalize(parseStrictJson(l)))
      .join('\n');
  return norm(a) !== norm(b);
}
