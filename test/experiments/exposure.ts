// SPDX-License-Identifier: AGPL-3.0-or-later
// Experiment B analysis: the exposure window of each epistemic pause in a
// verified evidence package (an exported log and its copied namespace).
//   exposure in events: application events after the pause up to and including the first verified anchor
//                       k >= s that covers it (anchor k commits records 0..k)
//   exposure in time:   signed genTime of that anchor minus ts[s] (seconds)
// Pauses after the highest verified anchor are uncovered.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { isApplicationEventType } from '../../src/chain/schema.js';
import { parseGeneralizedTimeNs, parseTimestampNs } from '../../src/time/timestamps.js';
import { verifyOffline } from '../../src/verify/verify.js';
import type { VerifyResult } from '../../src/verify/verify.js';

export interface LogRow {
  readonly seq: number;
  readonly ts: string;
  readonly payload: Record<string, unknown>;
}

export function readLog(logPath: string): LogRow[] {
  return fs
    .readFileSync(logPath, 'utf8')
    .trimEnd()
    .split('\n')
    .map((l) => {
      const b = (JSON.parse(l) as { block: { seq: number; ts: string; payload: Record<string, unknown> } }).block;
      return { seq: b.seq, ts: b.ts, payload: b.payload };
    });
}

export interface Exposure {
  readonly verify: VerifyResult;
  readonly maxK: number;
  readonly pauses: number;
  readonly covered: { seq: number; events: number; seconds: number | null }[];
  readonly uncovered: number[];
}

/** Verifies the evidence package, then measures every pause against the verified anchors. */
export function measureExposure(logPath: string, checkpointsPath: string, bundlePath: string, withTime: boolean): Exposure {
  const v = verifyOffline({ logPath, checkpointsPath, bundlePath });
  if (v.exitCode !== 0) throw new Error(`evidence does not verify: ${v.stdout}`);
  const m = /^VERIFIED_ANCHORED 0\.\.(\d+)$/m.exec(v.stdout);
  const maxK = m === null ? -1 : Number(m[1]);
  const rows = readLog(logPath);
  const presented = new Set(
    fs
      .readdirSync(checkpointsPath)
      .map((n) => /^(\d+)\.tsr$/.exec(n)?.[1])
      .filter((x): x is string => x !== undefined)
      .map(Number),
  );
  const genTimeNs = new Map<number, bigint>();
  for (const r of rows) {
    if (r.payload['event_type'] === 'checkpoint_anchored' && presented.has(r.payload['anchored_seq'] as number)) {
      genTimeNs.set(r.payload['anchored_seq'] as number, parseGeneralizedTimeNs(r.payload['tsa_gen_time'] as string)!);
    }
  }
  const anchors = [...presented].filter((k) => k <= maxK).sort((a, b) => a - b);
  const app = rows.filter((r) => isApplicationEventType(r.payload['event_type']));
  const covered: Exposure['covered'] = [];
  const uncovered: number[] = [];
  const pauses = rows.filter((r) => r.payload['event_type'] === 'epistemic_pause');
  for (const p of pauses) {
    const k = anchors.find((a) => a >= p.seq);
    if (k === undefined) {
      uncovered.push(p.seq);
      continue;
    }
    const events = app.filter((r) => r.seq > p.seq && r.seq <= k).length;
    const g = genTimeNs.get(k);
    const seconds = withTime && g !== undefined ? Number(g - parseTimestampNs(p.ts)!) / 1e9 : null;
    covered.push({ seq: p.seq, events, seconds });
  }
  return { verify: v, maxK, pauses: pauses.length, covered, uncovered };
}

/**
 * Truncation demonstration: a copy of the pre-close export without the rows after the highest verified anchor
 * (the VALID_UNANCHORED tail). Returns the verifier result and the number of pauses that disappeared.
 */
export function truncateTail(logPath: string, checkpointsPath: string, bundlePath: string, maxK: number, outDir: string): { verify: VerifyResult; removedPauses: number; removedRows: number } {
  const lines = fs.readFileSync(logPath, 'utf8').trimEnd().split('\n');
  const rows = readLog(logPath);
  const keep = lines.filter((_l, i) => rows[i]!.seq <= maxK);
  const removed = rows.filter((r) => r.seq > maxK);
  fs.mkdirSync(outDir, { recursive: true });
  const truncated = path.join(outDir, 'events.truncated.jsonl');
  fs.writeFileSync(truncated, keep.map((l) => `${l}\n`).join(''));
  return {
    verify: verifyOffline({ logPath: truncated, checkpointsPath, bundlePath }),
    removedPauses: removed.filter((r) => r.payload['event_type'] === 'epistemic_pause').length,
    removedRows: removed.length,
  };
}

export function stats(xs: readonly number[]): { min: number; median: number; max: number } | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return { min: s[0]!, median: s.length % 2 === 1 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2, max: s[s.length - 1]! };
}

export function fmtStats(xs: readonly number[], unit: string, digits = 0): string {
  const st = stats(xs);
  if (st === null) return 'none';
  const f = (x: number): string => x.toFixed(digits);
  return `min ${f(st.min)} · median ${f(st.median)} · max ${f(st.max)} ${unit}`;
}
