// SPDX-License-Identifier: AGPL-3.0-or-later
// E1–E10 classification of Blueprint §5.6, steps 3–5. It only reads: the view
// (validated rows, state row, namespace entries without recognized .tmp files)
// and the package files it names. Committed packages are validated with the
// verifier's own Step 2 checks (src/verify/anchors.ts), so the recoverer
// accepts a receipt only under the same TEAR-TSA-01 rules (§6a).

import type { ChainView, Classification, RecoveryClassifier, RecoveryState } from '../chain/interfaces.js';
import type { AcceptedRow } from '../chain/step1.js';
import type { NamespaceEntry } from '../fs/inventory.js';
import { parseTimestampNs } from '../time/timestamps.js';
import { checkPackage } from '../verify/anchors.js';
import type { ValidPackage } from '../verify/anchors.js';

export const ANCHOR_WINDOW_NS = 60_000_000_000n;

interface Files {
  tsq: boolean;
  tsr: boolean;
  json: boolean;
}

function controlOf(row: AcceptedRow | undefined): { type: 'anchored' | 'failed'; target: unknown; p: Record<string, unknown> } | null {
  if (row === undefined) return null;
  const p = row.block.payload as Record<string, unknown>;
  if (p['event_type'] === 'checkpoint_anchored') return { type: 'anchored', target: p['anchored_seq'], p };
  if (p['event_type'] === 'checkpoint_failed') return { type: 'failed', target: p['target_seq'], p };
  return null;
}

/** The package for k is complete and passes Step 2 (2.1–2.7) against the committed log, or null. */
export function validPackage(view: ChainView, k: bigint): ValidPackage | null {
  const r = checkPackage(view.nsPath, k, view.chainId, view.rows, view.bundle);
  return 'code' in r ? null : r;
}

/** The control at k+1 carries exactly the receipt digest and lexical genTime of package k. */
function controlMatches(row: AcceptedRow | undefined, k: number, pkg: ValidPackage): boolean {
  const c = controlOf(row);
  return c !== null && c.type === 'anchored' && c.target === k && c.p['tsr_sha256'] === pkg.tsrSha256 && c.p['tsa_gen_time'] === pkg.genTime;
}

const inconsistent = (reason: string): Classification => ({ kind: 'inconsistent', reason });
const state = (s: RecoveryState): Classification => ({ kind: 'state', state: s });

export function classifyView(view: ChainView): Classification {
  const rows = view.rows;
  const h = rows.length - 1;
  const pending = view.state.pending === null ? null : BigInt(view.state.pending.anchorSeq);

  const byM = new Map<bigint, Files>();
  for (const e of view.entries as readonly NamespaceEntry[]) {
    if (e.temporary) return inconsistent(`temporary file ${e.name} in the classified view`);
    const f = byM.get(e.seq) ?? { tsq: false, tsr: false, json: false };
    if (e.kind === 'tsq') f.tsq = true;
    else if (e.kind === 'tsr') f.tsr = true;
    else f.json = true;
    byM.set(e.seq, f);
  }

  // Step 2b relations of every committed control (§5.3a step 2): target = seq - 1, present and >= 1.
  for (const row of rows) {
    const c = controlOf(row);
    if (c === null) continue;
    if (typeof c.target !== 'number' || c.target !== row.block.seq - 1 || c.target < 1) {
      return inconsistent(`control at ${String(row.block.seq)} does not target the previous row`);
    }
  }

  // Step 3: every package outside the pending one is a confirmed, valid, committed package.
  const confirmed = new Set<number>();
  for (const [m, f] of byM) {
    if (m === pending || (!f.tsr && !f.json)) continue;
    if (!f.tsr || !f.json) return inconsistent(`package ${m.toString()} is incomplete`);
    const pkg = validPackage(view, m);
    if (pkg === null) return inconsistent(`package ${m.toString()} fails Step 2`);
    if (!controlMatches(rows[pkg.k + 1], pkg.k, pkg)) return inconsistent(`package ${m.toString()} has no matching checkpoint_anchored`);
    confirmed.add(pkg.k);
  }
  // Conversely: every committed checkpoint_anchored outside the pending transition has its package.
  for (const row of rows) {
    const c = controlOf(row);
    if (c === null || c.type !== 'anchored') continue;
    const t = c.target as number;
    if (pending !== null && BigInt(t) === pending && row.block.seq === t + 1) continue;
    if (!confirmed.has(t)) return inconsistent(`committed anchor ${String(t)} has no valid package (missing confirmed evidence)`);
  }

  const tsqs = [...byM.entries()].filter(([, f]) => f.tsq).map(([m]) => m);

  // Step 5, no pending anchor.
  if (pending === null) {
    if (tsqs.length === 0) return state('E1');
    if (tsqs.length === 1) {
      const m = tsqs[0]!;
      const next = m <= BigInt(h) ? rows[Number(m) + 1] : undefined;
      const c = controlOf(next);
      if (c !== null && BigInt(c.target as number) === m) {
        if (c.type === 'failed') return state('E2');
        if (confirmed.has(Number(m))) return state('E2');
      }
    }
    return state('E3');
  }

  // Step 4: foreign residue for the pending k.
  const k = pending;
  let foreign = false;
  for (const [m, f] of byM) {
    if (m === k) continue;
    if (f.tsq) foreign = true; // A .tsq for m != k is foreign residue even if its control is committed.
    if ((f.tsr || f.json) && !confirmed.has(Number(m))) foreign = true;
  }
  const kf = byM.get(k) ?? { tsq: false, tsr: false, json: false };
  const kn = Number(k);

  if (BigInt(h) === k + 1n) {
    if (foreign) return state('E6');
    const c = controlOf(rows[kn + 1]);
    if (c !== null && c.type === 'anchored' && c.target === kn) {
      const pkg = kf.tsr && kf.json ? validPackage(view, k) : null;
      return pkg !== null && controlMatches(rows[kn + 1], kn, pkg) ? state('E4') : state('E6');
    }
    if (c !== null && c.type === 'failed' && c.target === kn) return state('E5');
    return state('E6');
  }
  if (BigInt(h) === k) {
    if (foreign) return state('E10');
    if (kf.tsr && kf.json && validPackage(view, k) !== null) return state('E7');
    const pendingTs = parseTimestampNs(view.state.pending!.ts);
    if (pendingTs === null) return state('E10');
    return view.nowNs - pendingTs <= ANCHOR_WINDOW_NS ? state('E8') : state('E9');
  }
  return state('E10');
}

/** The §5.6 classifier behind the interface spec 001 defined. */
export const stateClassifier: RecoveryClassifier = {
  classify: async (view) => classifyView(view),
};
