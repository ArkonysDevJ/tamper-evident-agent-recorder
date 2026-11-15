// SPDX-License-Identifier: AGPL-3.0-or-later
// Experiment A — layer ladder. The 17 cases of spec 004 (15 primary, X1, X2),
// unchanged, seen through four layers of evidence. Expected outcomes were
// predeclared in test/experiments/expected.ts before this file existed; a
// mismatch is reported as "not matching", never adjusted.
//
//   L0  plain log: each row is readable JSON (a minimal reader: no chain, no anchors)
//   L1  tear-verify with an empty namespace (local chain only)
//   L2  tear-verify with the presented namespace (as in M1)
//   L3  L2 plus an auditor procedure outside tear-verify: the bundle SHA-256 and every presented receipt are
//       compared with a retained manifest. SIMULATION of the external custodian: the retained manifest is
//       built by this test from the original frozen fixture.
//
// Writes test-results/layer-ladder.md.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { after, test } from 'node:test';
import { bundleSha256, sha256Hex } from '../../src/crypto/digests.js';
import type { VerifyResult } from '../../src/verify/verify.js';
import { EXPECTED_LADDER, EXPECTED_LADDER_TOTALS } from '../experiments/expected.js';
import type { Layer, LayerOutcome } from '../experiments/expected.js';
import { CASES } from './cases.js';
import { Evidence } from './model.js';
import { StoredReceipts } from './receipts.js';

const OUT = path.resolve('test-results/layer-ladder.md');
const LAYERS: readonly Layer[] = ['L0', 'L1', 'L2', 'L3'];

/** Highest VERIFIED_ANCHORED bound of an exit-0 output, or -1. */
function anchoredBound(r: VerifyResult): number {
  const m = /^VERIFIED_ANCHORED 0\.\.(\d+)$/m.exec(r.stdout);
  return m === null ? -1 : Number(m[1]);
}

function classify(r: VerifyResult, baselineBound: number): LayerOutcome {
  if (r.exitCode !== 0) return 'detected';
  return anchoredBound(r) < baselineBound ? 'reduced coverage' : 'accepted';
}

/** L0: a minimal reader that only checks that each row is readable JSON. */
function l0(e: Evidence): LayerOutcome {
  for (const line of e.logBytes().toString('utf8').trimEnd().split('\n')) {
    try {
      JSON.parse(line);
    } catch {
      return 'detected';
    }
  }
  return 'accepted';
}

function withoutPackages(e: Evidence): Evidence {
  const copy = Object.assign(Object.create(Object.getPrototypeOf(e) as object) as Evidence, e);
  copy.files = new Map();
  return copy;
}

/** The retained manifest (simulated external custodian): the published bundle fingerprint and the original receipts. */
interface Retained {
  readonly bundleSha256: string;
  readonly receipts: ReadonlyMap<string, string>;
}

function retainedFromFixture(): Retained {
  const e = new Evidence();
  const receipts = new Map<string, string>();
  for (const [name, bytes] of e.files) if (name.endsWith('.tsr')) receipts.set(name, sha256Hex(bytes));
  return { bundleSha256: bundleSha256(e.bundle), receipts };
}

/** The auditor comparison: true when the presented bundle and receipts all match the retained copies. */
function auditorMatches(e: Evidence, retained: Retained): boolean {
  if (bundleSha256(e.bundle) !== retained.bundleSha256) return false;
  for (const [name, bytes] of e.files) {
    if (!name.endsWith('.tsr')) continue;
    const kept = retained.receipts.get(name);
    if (kept === undefined || kept !== sha256Hex(bytes)) return false;
  }
  return true;
}

const measured = new Map<string, Record<Layer, LayerOutcome>>();
const source = new StoredReceipts();
const retained = retainedFromFixture();
const baseline = new Evidence();
const bound = { L1: anchoredBound(withoutPackages(baseline).verify()), L2: anchoredBound(baseline.verify()) };

for (const c of CASES) {
  test(`009 layer ladder ${c.id}`, async () => {
    const e = await c.build(source);
    const r2 = e.verify();
    const L2 = classify(r2, bound.L2);
    const row: Record<Layer, LayerOutcome> = {
      L0: l0(e),
      L1: classify(withoutPackages(e).verify(), bound.L1),
      L2,
      L3: L2 === 'detected' || !auditorMatches(e, retained) ? 'detected' : L2,
    };
    measured.set(c.id, row);
    assert.deepEqual(row, EXPECTED_LADDER[c.id], `predeclared for ${c.id}`);
  });
}

test('009 layer ladder totals', () => {
  for (const layer of LAYERS) {
    const totals = { detected: 0, accepted: 0, 'reduced coverage': 0 };
    for (const row of measured.values()) totals[row[layer]]++;
    assert.deepEqual(totals, EXPECTED_LADDER_TOTALS[layer], layer);
  }
});

after(() => {
  const header = '| Case | L0 · plain log | L1 · local chain | L2 · chain and presented anchors | L3 · plus retained references (simulated custodian) |';
  const rows = CASES.map((c) => {
    const m = measured.get(c.id);
    const cell = (l: Layer): string => {
      if (m === undefined) return 'not run';
      const exp = EXPECTED_LADDER[c.id]![l];
      return m[l] === exp ? m[l] : `${m[l]} (expected ${exp}: NOT MATCHING)`;
    };
    return `| ${c.id} | ${cell('L0')} | ${cell('L1')} | ${cell('L2')} | ${cell('L3')} |`;
  });
  const total = (l: Layer): string => {
    const t = { detected: 0, accepted: 0, 'reduced coverage': 0 };
    for (const row of measured.values()) t[row[l]]++;
    return `${String(t.detected)} detected · ${String(t.accepted)} accepted · ${String(t['reduced coverage'])} reduced`;
  };
  const text = [
    '# Layer ladder (experiment A)',
    '',
    'The 17 cases of the tamper battery (15 primary, X1, X2) on copies of the frozen fixture, unchanged.',
    'L3 is a SIMULATION of the external custodian: the retained manifest (bundle fingerprint and original',
    'receipts) is built by the test from the original fixture, and compared with SHA-256 outside tear-verify.',
    'Expected outcomes were predeclared before measurement (test/experiments/expected.ts).',
    '',
    header,
    '| --- | --- | --- | --- | --- |',
    ...rows,
    `| **Totals** | ${total('L0')} | ${total('L1')} | ${total('L2')} | ${total('L3')} |`,
    '',
  ].join('\n');
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, text);
});
