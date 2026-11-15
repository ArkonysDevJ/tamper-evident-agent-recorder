// SPDX-License-Identifier: AGPL-3.0-or-later
// Experiment B — exposure window of an epistemic pause. Needs PostgreSQL
// (npm run test:experiments; also in CI with a PostgreSQL service).
//   B1: the full synthetic dataset (1000 steps) through the real interceptor, anchored by the in-process test
//       TSA; deterministic in events. Measures exposure in events before and after closeChain, the truncation
//       demonstration, and record size and latency by argument size.
//   B2: the stored artifacts of the one-time real-TSA run (experiments/b2/, written by npm run experiments:b2)
//       are analyzed offline for exposure in time, when present.
// Expected outcomes were predeclared in test/experiments/expected.ts. Writes test-results/pause-exposure.md.
// The dataset is synthetic; the exposure window is a property of the design (automatic anchors on application
// events at physical sequence numbers divisible by 10) measured on this workload, not a finding about agents.

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { after, test } from 'node:test';
import { autoAnchorHook } from '../../src/anchor/trigger.js';
import { buildEvidencePackage } from '../../src/chain/evidence.js';
import { provisionNamespace } from '../../src/fs/namespace.js';
import { Interceptor } from '../../src/interceptor/interceptor.js';
import { PEPPER_ENV } from '../../src/interceptor/pepper.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { ensureSchema, pgConfig } from '../helpers/pg.js';
import { testPki } from '../helpers/pki.js';
import { testTsa } from '../helpers/test-tsa.js';
import { EXPECTED_EXPOSURE } from './expected.js';
import { fmtStats, measureExposure, readLog, stats, truncateTail } from './exposure.js';
import type { Exposure } from './exposure.js';
import { readDataset } from './replay.js';
import type { ArgClass, ReplayRecord } from './replay.js';
import { replay } from './replay.js';

const OUT = path.resolve('test-results/pause-exposure.md');
const B2_DIR = path.resolve('experiments/b2');
const checks: { what: string; expected: string; measured: string; match: boolean }[] = [];
const sections: string[] = [];

function check(what: string, expected: string, measured: string, match: boolean): void {
  checks.push({ what, expected, measured, match });
}

function exposureLines(label: string, e: Exposure, withTime: boolean): string[] {
  const lines = [
    `- ${label}: ${String(e.pauses)} pauses; highest verified anchor ${String(e.maxK)}; ${String(e.covered.length)} covered, ${String(e.uncovered.length)} uncovered.`,
    `  - Exposure in events (covered pauses): ${fmtStats(e.covered.map((c) => c.events), 'events')}.`,
  ];
  if (withTime) lines.push(`  - Exposure in time (covered pauses): ${fmtStats(e.covered.map((c) => c.seconds!).filter((x) => x !== null), 's', 3)}.`);
  return lines;
}

test('009 B1 pause exposure (full dataset, test TSA)', async () => {
  await ensureSchema();
  const pki = testPki(9);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-b1-'));
  const chainId = randomUUID();
  provisionNamespace(root, chainId);
  const { interceptor, writer } = await Interceptor.start(
    {
      checkpointsRoot: root,
      chainId,
      genesisTs: formatTimestamp(Date.now() - 1000),
      pepperId: 'b1-pepper',
      bundleBytes: pki.bundle,
      pg: pgConfig,
      profile: 'base',
      anchorHook: autoAnchorHook(),
      tsas: [testTsa('test-tsa', pki)],
    },
    { [PEPPER_ENV]: randomBytes(32).toString('hex') },
  );
  const records: ReplayRecord[] = await replay(interceptor, readDataset());
  const bundlePath = path.join(root, 'bundle.pem');
  fs.writeFileSync(bundlePath, pki.bundle);

  // Before close.
  const pre = await buildEvidencePackage({ checkpointsRoot: root, chainId, pg: pgConfig, bundleBytes: pki.bundle, outDir: path.join(root, 'pre-close') });
  const before = measureExposure(pre.logPath, pre.checkpointsPath, bundlePath, false);
  const demo = truncateTail(pre.logPath, pre.checkpointsPath, bundlePath, before.maxK, path.join(root, 'demo'));

  // After closeChain.
  const closed = await writer.closeChain();
  await writer.close();
  const post = await buildEvidencePackage({ checkpointsRoot: root, chainId, pg: pgConfig, bundleBytes: pki.bundle, outDir: path.join(root, 'post-close') });
  const afterClose = measureExposure(post.logPath, post.checkpointsPath, bundlePath, false);

  // Record size and latency by argument size (tool_call records).
  const lineBytes = new Map<number, number>();
  for (const line of fs.readFileSync(pre.logPath, 'utf8').trimEnd().split('\n')) {
    lineBytes.set((JSON.parse(line) as { block: { seq: number } }).block.seq, Buffer.byteLength(line, 'utf8') + 1);
  }
  const byClass = (cls: ArgClass): { bytes: number[]; ms: number[] } => {
    const calls = records.filter((r) => r.kind === 'tool_call' && r.argClass === cls);
    return { bytes: calls.map((r) => lineBytes.get(r.seq)!), ms: calls.map((r) => r.ms) };
  };
  const classes: ArgClass[] = ['small', 'medium', 'large'];
  const perClass = new Map(classes.map((c) => [c, byClass(c)]));
  const meanBytes = (c: ArgClass): number => {
    const b = perClass.get(c)!.bytes;
    return b.reduce((x, y) => x + y, 0) / b.length;
  };

  // Non-vacuity (review finding 5): the analyzer enumerates every pause the replay recorded, and the uncovered
  // list is exactly the pauses after the last verified anchor, counted independently from the exported rows.
  const recordedPauses = records.filter((r) => r.kind === 'epistemic_pause').length;
  assert.equal(recordedPauses, readDataset().filter((s) => s.kind === 'epistemic_pause').length);
  assert.equal(before.pauses, recordedPauses);
  assert.equal(afterClose.pauses, recordedPauses);
  const tailPauses = readLog(pre.logPath).filter((r) => r.payload['event_type'] === 'epistemic_pause' && r.seq > before.maxK).length;
  assert.equal(before.uncovered.length, tailPauses);
  assert.equal(before.covered.length + before.uncovered.length, recordedPauses);

  // Checks against the predeclared expectations.
  const ev = before.covered.map((c) => c.events);
  const afterFirst = before.covered.filter((c) => c.seq > 10).map((c) => c.events);
  check('B1 exposure in events before close: min', String(EXPECTED_EXPOSURE.eventsBeforeClose.min), String(stats(ev)?.min), stats(ev)?.min === EXPECTED_EXPOSURE.eventsBeforeClose.min);
  check('B1 exposure in events before close: max', `≤ ${String(EXPECTED_EXPOSURE.eventsBeforeClose.max)}`, String(stats(ev)?.max), (stats(ev)?.max ?? 99) <= EXPECTED_EXPOSURE.eventsBeforeClose.max);
  check('B1 exposure after the first anchor: max', `≤ ${String(EXPECTED_EXPOSURE.eventsBeforeClose.maxAfterFirstAnchor)}`, String(stats(afterFirst)?.max), (stats(afterFirst)?.max ?? 99) <= EXPECTED_EXPOSURE.eventsBeforeClose.maxAfterFirstAnchor);
  check('B1 tail pauses uncovered before close', 'pauses after the last anchor are uncovered', `${String(before.uncovered.length)} uncovered, all after ${String(before.maxK)}`, before.uncovered.every((s) => s > before.maxK));
  check('B1 all pauses covered after closeChain', 'all covered', `${String(afterClose.covered.length)}/${String(afterClose.pauses)} covered (${closed.result})`, afterClose.uncovered.length === 0);
  check('B1 truncation: exit code', String(EXPECTED_EXPOSURE.truncation.exitCode), String(demo.verify.exitCode), demo.verify.exitCode === 0);
  check('B1 truncation: pauses removed = pauses after the last anchor', String(before.uncovered.length), String(demo.removedPauses), demo.removedPauses === before.uncovered.length);
  const sizes = classes.map(meanBytes);
  const spread = Math.max(...sizes) - Math.min(...sizes);
  check('B1 tool_call record size spread across argument classes', `≤ ${String(EXPECTED_EXPOSURE.recordSizeMaxSpreadBytes)} bytes`, `${spread.toFixed(1)} bytes`, spread <= EXPECTED_EXPOSURE.recordSizeMaxSpreadBytes);
  const latSmall = stats(perClass.get('small')!.ms)!.median;
  const latLarge = stats(perClass.get('large')!.ms)!.median;
  check('B1 tool_call median latency, ~20 KB minus ~100 B', `< ${String(EXPECTED_EXPOSURE.latencyMaxSpreadMs)} ms`, `${(latLarge - latSmall).toFixed(3)} ms`, latLarge - latSmall < EXPECTED_EXPOSURE.latencyMaxSpreadMs);

  sections.push(
    '## B1 · full dataset (1000 steps), offline test TSA',
    '',
    `Application events recorded: ${String(records.length)}. Close: ${closed.result} (${closed.branch}).`,
    '',
    ...exposureLines('Before close', before, false),
    ...exposureLines('After closeChain', afterClose, false),
    '',
    `Truncation demonstration (copy of the pre-close export without rows after ${String(before.maxK)}): tear-verify exit ${String(demo.verify.exitCode)}; ${String(demo.removedRows)} rows and ${String(demo.removedPauses)} pauses disappeared; output \`${demo.verify.stdout.split('\n')[0] ?? ''}\`.`,
    '',
    '| Argument class | tool_call records | Mean exported row size | Median latency per tool_call event |',
    '| --- | --- | --- | --- |',
    ...classes.map((c) => `| ${c} | ${String(perClass.get(c)!.bytes.length)} | ${meanBytes(c).toFixed(1)} bytes | ${stats(perClass.get(c)!.ms)!.median.toFixed(3)} ms |`),
    '',
  );
  assert.deepEqual(checks.filter((c) => !c.match).map((c) => c.what), []);
});

test('009 B2 pause exposure (stored real-TSA artifacts, offline analysis)', (t) => {
  if (!fs.existsSync(path.join(B2_DIR, 'meta.json'))) {
    sections.push('## B2 · first 150 application events, real TSAs', '', 'Not run: no artifacts in experiments/b2/.', '');
    t.skip('no B2 artifacts');
    return;
  }
  const meta = JSON.parse(fs.readFileSync(path.join(B2_DIR, 'meta.json'), 'utf8')) as { events: number; stamps: Record<string, number>; close: string };
  const bundlePath = path.resolve('certs/tsa_roots.pem');
  const ns = (d: string): string => path.join(B2_DIR, d, fs.readdirSync(path.join(B2_DIR, d)).find((n) => n !== 'events.jsonl')!);
  const before = measureExposure(path.join(B2_DIR, 'pre-close', 'events.jsonl'), ns('pre-close'), bundlePath, true);
  const afterClose = measureExposure(path.join(B2_DIR, 'post-close', 'events.jsonl'), ns('post-close'), bundlePath, true);
  // Non-vacuity (review finding 5): the stored B2 log holds 11 pauses, and every covered pause has a time value.
  const storedPauses = readLog(path.join(B2_DIR, 'pre-close', 'events.jsonl')).filter((r) => r.payload['event_type'] === 'epistemic_pause').length;
  assert.equal(storedPauses, 11);
  assert.equal(before.pauses, storedPauses);
  assert.equal(afterClose.pauses, storedPauses);
  assert.ok([...before.covered, ...afterClose.covered].every((c) => c.seconds !== null));
  const secs = [...before.covered, ...afterClose.covered].map((c) => c.seconds!).filter((x) => x !== null);
  assert.equal(secs.length, before.covered.length + afterClose.covered.length);
  check('B2 exposure in time: lower bound', `≥ ${String(EXPECTED_EXPOSURE.timeLowerBoundSeconds)} s`, `${String(stats(secs)?.min.toFixed(3))} s`, (stats(secs)?.min ?? 0) >= EXPECTED_EXPOSURE.timeLowerBoundSeconds);
  check('B2 all pauses covered after closeChain', 'all covered', `${String(afterClose.covered.length)}/${String(afterClose.pauses)}`, afterClose.uncovered.length === 0);
  const rows = readLog(path.join(B2_DIR, 'post-close', 'events.jsonl'));
  sections.push(
    '## B2 · first 150 application events, real TSAs (retained order: FreeTSA, then DigiCert on failure)',
    '',
    `Application events: ${String(meta.events)}; rows after close: ${String(rows.length)}. Close: ${meta.close}. Time-stamp requests: ${Object.entries(meta.stamps).map(([k, v]) => `${k} ${String(v)}`).join(', ')}${meta.stamps['digicert'] === undefined ? '; DigiCert was not used (no primary failure)' : ''}.`,
    'Exposure in time can be negative: FreeTSA signs genTime in whole seconds, so a token issued within the same second as the pause carries an earlier genTime (the §5.7 predicate allows down to -5 s).',
    '',
    ...exposureLines('Before close', before, true),
    ...exposureLines('After closeChain', afterClose, true),
    '',
  );
  assert.deepEqual(checks.filter((c) => c.what.startsWith('B2') && !c.match).map((c) => c.what), []);
});

after(() => {
  const text = [
    '# Pause exposure window (experiment B)',
    '',
    'The dataset is synthetic (experiments/dataset/). The exposure window is a property of the design (automatic',
    'anchors on application events at physical sequence numbers divisible by 10) measured on this workload; it is not',
    'a finding about agents or models.',
    'Expected outcomes were predeclared before measurement (test/experiments/expected.ts).',
    '',
    ...sections,
    '## Predeclared expectations',
    '',
    '| Check | Expected | Measured | Result |',
    '| --- | --- | --- | --- |',
    ...checks.map((c) => `| ${c.what} | ${c.expected} | ${c.measured} | ${c.match ? 'matching' : 'NOT MATCHING'} |`),
    '',
  ].join('\n');
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, text);
});
