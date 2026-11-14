// SPDX-License-Identifier: AGPL-3.0-or-later
// Builds anchored verifier inputs with the test PKI: a log, packages
// (<k>.tsr + <k>.anchor.json) and a bundle file whose digest the genesis row
// carries. Each package can be replaced or mutated by the test.

import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { anchorPackageBytes } from '../../src/anchor/package.js';
import { ZERO_HASH } from '../../src/chain/ids.js';
import type { Block } from '../../src/chain/schema.js';
import { bundleSha256, entryHashOf, sha256Hex } from '../../src/crypto/digests.js';
import type { JsonObject } from '../../src/json/strict-json.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { parseReceipt } from '../../src/tsa/receipt.js';
import { buildTimeStampReq } from '../../src/tsa/request.js';
import { verifyOffline } from '../../src/verify/verify.js';
import type { VerifyInputs, VerifyResult } from '../../src/verify/verify.js';
import { genesisPayload, obj, pausePayload } from './chain-builder.js';
import type { BuiltRow } from './chain-builder.js';
import { serialize } from './verify-files.js';
import { genTimeOf, issuerAndSerial, testPki, timeStampResp, tstInfo } from './pki.js';
import type { TestPki, TokenSpec, TstSpec } from './pki.js';

export const START_MS = Date.UTC(2026, 10, 13, 12, 0, 0);

export interface PackageFiles {
  tsr: Uint8Array;
  json: Uint8Array;
  genTime: string;
  nonceHex: string;
}

export interface Scenario {
  readonly chainId: string;
  readonly rows: BuiltRow[];
  readonly pki: TestPki;
  readonly bundle: Uint8Array;
  readonly packages: Map<number, PackageFiles>;
}

export interface TokenContext {
  readonly k: number;
  readonly entryHash: string;
  readonly nonce: bigint;
  readonly genTime: string;
  readonly pki: TestPki;
}

/** The default receipt for anchor k, before any test override. */
export function baseTokenSpec(c: TokenContext, tst: Partial<TstSpec> = {}): TokenSpec {
  const { issuer, serial } = issuerAndSerial(c.pki.signer);
  return {
    tst: tstInfo({ hashedMessage: Buffer.from(c.entryHash, 'hex'), genTime: c.genTime, nonce: c.nonce, ...tst }),
    signerCert: c.pki.signer,
    signerKey: c.pki.signerKey,
    signerIssuer: issuer,
    signerSerial: serial,
  };
}

export interface ScenarioOptions {
  /** Highest seq (default 50). */
  readonly last?: number;
  /** Anchored k values; a checkpoint_anchored control follows each at k+1 (default [10, 20]). */
  readonly anchors?: number[];
  /** Positions of checkpoint_failed controls (target = seq - 1). */
  readonly failedAt?: number[];
  readonly pki?: TestPki;
  /** Bundle bytes (default: the PKI bundle). */
  readonly bundle?: Uint8Array;
  /** Receipt bytes for anchor k; default builds a valid one. */
  readonly token?: (c: TokenContext) => Uint8Array;
  /** Seconds between row k ts and genTime (default 1). */
  readonly genTimeOffsetS?: number;
  readonly stepMs?: number;
}

const NONCE = 0x4123456789abcdefn;

export function buildScenario(o: ScenarioOptions = {}): Scenario {
  const pki = o.pki ?? testPki();
  const bundle = o.bundle ?? pki.bundle;
  const chainId = randomUUID();
  const last = o.last ?? 50;
  const anchors = o.anchors ?? [10, 20];
  const failedAt = new Set(o.failedAt ?? []);
  const rows: BuiltRow[] = [];
  const packages = new Map<number, PackageFiles>();
  let prev = ZERO_HASH;
  for (let seq = 0; seq <= last; seq++) {
    const ts = formatTimestamp(START_MS + seq * (o.stepMs ?? 200));
    let payload: JsonObject;
    if (seq === 0) payload = genesisPayload(bundleSha256(bundle));
    else if (anchors.includes(seq - 1)) {
      const p = packages.get(seq - 1)!;
      payload = obj({
        event_type: 'checkpoint_anchored',
        operation: 'tear.checkpoint',
        anchored_seq: seq - 1,
        tsr_sha256: sha256Hex(p.tsr),
        tsa_gen_time: p.genTime,
      });
    } else if (failedAt.has(seq)) {
      payload = obj({ event_type: 'checkpoint_failed', operation: 'tear.checkpoint', target_seq: seq - 1, error_type: 'tsa_unreachable' });
    } else payload = pausePayload(seq);
    const block = obj({ chain_id: chainId, seq, ts, prev_hash: prev, payload });
    const entry = entryHashOf(block);
    rows.push({ block, entry_hash: entry });
    prev = entry;
    if (anchors.includes(seq)) {
      const genTime = genTimeOf(new Date(START_MS + seq * (o.stepMs ?? 200) + (o.genTimeOffsetS ?? 1) * 1000));
      const ctx: TokenContext = { k: seq, entryHash: entry, nonce: NONCE, genTime, pki };
      const tsr = o.token?.(ctx) ?? timeStampResp(baseTokenSpec(ctx));
      const nonceHex = NONCE.toString(16);
      const json = anchorPackageBytes({
        chainId,
        anchoredSeq: seq,
        entryHash: entry,
        block: block as Block,
        nonceHex,
        tsqSha256: sha256Hex(buildTimeStampReq(entry, nonceHex)),
      });
      // The control row carries the genTime the receipt really holds, when it decodes.
      const parsed = parseReceipt(tsr);
      packages.set(seq, { tsr, json, genTime: parsed.ok ? parsed.receipt.tstInfo.genTime : genTime, nonceHex });
    }
  }
  return { chainId, rows, pki, bundle, packages };
}

/** Writes the scenario to a fresh directory; returns the verifier inputs. */
export function writeScenario(s: Scenario, log: Uint8Array = serialize(s.rows)): VerifyInputs {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-anchor-'));
  const ns = path.join(dir, s.chainId);
  fs.mkdirSync(ns);
  for (const [k, p] of s.packages) {
    fs.writeFileSync(path.join(ns, `${String(k)}.tsr`), p.tsr);
    fs.writeFileSync(path.join(ns, `${String(k)}.anchor.json`), p.json);
  }
  const logPath = path.join(dir, 'events.jsonl');
  fs.writeFileSync(logPath, log);
  const bundlePath = path.join(dir, 'tsa_roots.pem');
  fs.writeFileSync(bundlePath, s.bundle);
  return { logPath, checkpointsPath: `${ns}/`, bundlePath };
}

export function verifyScenario(s: Scenario): VerifyResult {
  return verifyOffline(writeScenario(s));
}

/** First stdout line of a verification. */
export function firstLine(r: VerifyResult): string {
  return r.stdout.split('\n')[0] ?? '';
}
