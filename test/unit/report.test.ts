// SPDX-License-Identifier: AGPL-3.0-or-later
// Spec 007: docs/REPORT.md contains each item §9 requires, and it is exactly what scripts/render-report.ts
// renders from the generated files (no number is written by hand). Skipped until the final run exists.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { test } from 'node:test';
import { README_PATH, REPORT_PATH, readmeWithResults, renderReport } from '../../scripts/render-report.js';

const ready = fs.existsSync('docs/results/final-run.json') && fs.existsSync(REPORT_PATH);
const report = ready ? fs.readFileSync(REPORT_PATH, 'utf8') : '';
const opts = { skip: ready ? false : 'no final run yet (docs/results/final-run.json)' };

test('007 report is generated, never edited by hand', opts, () => assert.equal(report, renderReport()));
test('007 README results block is generated', opts, () => assert.equal(fs.readFileSync(README_PATH, 'utf8'), readmeWithResults()));

const items: [string, RegExp[]][] = [
  ['007 AC-1 m1-table', [/## 1\. Tamper-detection matrix/, /\| T3b \| A2a \| not detected: anchored 0\.\.40, tail 41\.\.44 \|/, /\| T7 \| A2b \| degraded coverage/, /\| X1 \|/, /\| X2 \|/]],
  ['007 AC-2 anchored-meaning', [/## 2\. What VERIFIED_ANCHORED means/, /accuracy unspecified/]],
  ['007 AC-3 evidence-loss', [/ANCHOR_EVIDENCE_MISSING <k>/, /hard failure/]],
  ['007 AC-4 custody', [/simulates an external custodian/, /T6b and T7 depend on that custody/, /no revocation check/]],
  ['007 AC-5 host-and-durability', [/All tests ran on one host/, /full_page_writes on,/, /virtual disk/, /§5\.4 deployment invariants/]],
  ['007 AC-6 bundle-custody', [/10335e1e5d816b98665e5f4cb21ed92dd0637d2957658e0c34d55c365240ccfd/, /2026-11-14 at 15:13 UTC/, /Root and signer checks/]],
  ['007 AC-7 cut-profiles', [/Active profile: \*\*Base\*\*/]],
  ['007 AC-8 not-tested', [/### Not tested/, /### Known debt \(Blueprint §10\)/, /### Failed/]],
  ['007 AC-9 m3', [/## 8\. Overhead \(M3\), as measured/]],
  ['007 AC-10 known-debt-entries', [/ESSCertIDv2/, /pathLenConstraint/, /10\.0/]],
  ['007 AC-11 implementation-choices', [/## 10\. Implementation choices \(not normative\)/, /### Spec 008/]],
  ['007 AC-12 partly-tested-data-core', [/\*\*001 AC-9\*\*/, /\*\*001 AC-12\*\*/, /\*\*001 AC-15\*\*/]],
  ['007 AC-13 partly-tested-verifier', [/\*\*002 AC-1\*\*/]],
  ['007 AC-14 envelope-whitespace', [/whitespace in the row envelope/]],
  ['007 AC-15 partly-tested-file-primitives', [/real power loss and the device flush order/]],
  ['007 AC-16 der-reader-trust-surface', [/ASN\.1 DER reader is written in this repository/]],
  ['007 AC-17 partly-tested-anchoring', [/real TSA failures \(timeouts, HTTP errors, rejections\)/]],
  ['007 AC-18 certificate-set-order', [/certificate set is not enforced/]],
  ['007 AC-19 accuracy-unspecified', [/"accuracy unspecified"/]],
  ['007 AC-20 recorded-call-not-run', [/a `tool_call` can be recorded whose tool never ran/]],
  ['007 AC-21 m3-conditions', [/measured on WSL2 over a virtual disk/]],
  ['007 AC-22 partly-tested-recovery', [/real power loss during recovery/]],
  ['007 AC-23 evidence-before-recovery', [/an evidence package taken between a crash and the next recovery/]],
];
test('009 experiments in the report and the README: B1 and B2 apart, no time values as a result', opts, () => {
  assert.match(report, /### B1 · full dataset \(1000 steps\), offline test TSA/);
  assert.match(report, /### B2 · first 150 application events, real TSAs/);
  assert.match(report, /Exposure in time \(B2\) is not reported as a result\. FreeTSA signs `genTime` in whole seconds/);
  assert.doesNotMatch(report, /Exposure in time \(covered pauses\)/);
  assert.doesNotMatch(report, /\| B2 exposure in time/);
  assert.match(report, /The undetected deletion of pauses is shown on the frozen fixture by T3b/);
  assert.match(report, /\| Case \| L0 · plain log \|/);
  const readme = fs.readFileSync(README_PATH, 'utf8');
  assert.match(readme, /\| Pause exposure, B1 \(1000 synthetic steps, offline test TSA\) \|/);
  assert.match(readme, /\| Pause exposure, B2 \(first 150 application events, real time stamps: freetsa \d+\) \|/);
  assert.match(readme, /synthetic, produced by a script with a fixed seed/);
  assert.match(readme, /npm run dataset:generate/);
});

for (const [name, patterns] of items) {
  test(name, opts, () => {
    for (const p of patterns) assert.match(report, p);
  });
}
