// SPDX-License-Identifier: AGPL-3.0-or-later
// npm run test:tamper — the §7 M1 matrix (15 primary results), X1 and X2 on
// copies of the frozen fixture, offline and deterministic. Every expected
// result was copied from Blueprint §7 before the run; a mismatch is reported
// as failed, never adjusted. The run writes test-results/tamper-results.md.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { after, test } from 'node:test';
import { bundleSha256, sha256Hex } from '../../src/crypto/digests.js';
import { loadBundle } from '../../src/pki/bundle.js';
import { checkReceipt, parseReceipt, timePredicate } from '../../src/tsa/receipt.js';
import { parseTimestampNs } from '../../src/time/timestamps.js';
import { FIXTURE_DIR } from '../fixture-tools/fixture-files.js';
import { CASES } from './cases.js';
import type { Expected, TamperCase } from './cases.js';
import { BUNDLE_PATH, Evidence, FIXTURE_CHAIN_ID, FIXTURE_LOG, differsInBlockOrHash, successStdout } from './model.js';
import { StoredReceipts, TAMPER_RECEIPTS_DIR, readManifest } from './receipts.js';

export const RESULTS_PATH = path.resolve('test-results/tamper-results.md');

interface Measured {
  readonly c: TamperCase;
  readonly expected: Expected;
  readonly exitCode: number;
  readonly stdout: string;
  readonly match: boolean;
}

const measured: Measured[] = [];
const extras: { id: string; specified: string; measured: string; match: boolean }[] = [];

function summary(exitCode: number, stdout: string): string {
  const lines = stdout.trimEnd().split('\n');
  if (exitCode === 1) return lines[0] ?? '';
  if (exitCode !== 0) return `exit ${String(exitCode)}: ${lines[0] ?? ''}`;
  const keep = lines.filter((l) => /^(VERIFIED_ANCHORED|VALID_UNANCHORED|ANCHOR_EVIDENCE_MISSING|INCOMPLETE_EXECUTION) /.test(l));
  return `exit 0; ${keep.join('; ')}`;
}

function fixtureDigests(): string {
  const m = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.json'), 'utf8')) as { files: Record<string, string> };
  return Object.keys(m.files)
    .sort()
    .map((f) => `${f}=${sha256Hex(fs.readFileSync(path.join(FIXTURE_DIR, f)))}`)
    .join('\n');
}

const frozenBefore = fixtureDigests();
const source = new StoredReceipts();

test('004 baseline: an unchanged copy reproduces the frozen bytes and verifies as frozen', () => {
  const e = new Evidence();
  assert.ok(e.logBytes().equals(FIXTURE_LOG), 'the copy serializes to the exact exported bytes');
  const r = e.verify();
  assert.equal(r.exitCode, 0);
  assert.equal(r.stdout, successStdout(e, ['VERIFIED_ANCHORED 0..40', 'VALID_UNANCHORED 41..50', 'MAX_ANCHOR_GAP 10', 'ANCHORED_CHECKPOINT_FAILURES 0'], [10, 20, 30, 40]));
});

CASES.forEach((c, i) => {
  test(`004 AC-${String(i + 1)} ${c.id}`, async () => {
    const e = await c.build(source);
    if (c.id !== 'X1') {
      assert.ok(differsInBlockOrHash(e.logBytes(), FIXTURE_LOG), 'the mutation changes block or entry_hash bytes');
    } else {
      assert.ok(e.logBytes().equals(FIXTURE_LOG), 'X1 leaves events.jsonl unchanged');
    }
    const expected = c.expected(e);
    const r = e.verify();
    const match = r.exitCode === expected.exitCode && r.stdout === expected.stdout && r.stderr === '';
    measured.push({ c, expected, exitCode: r.exitCode, stdout: r.stdout, match });
    assert.equal(r.stderr, '');
    assert.equal(r.exitCode, expected.exitCode, `specified: ${c.specified}`);
    assert.equal(r.stdout, expected.stdout, `specified: ${c.specified}`);
  });
});

test('004 AC-18 matrix-15-of-15', () => {
  const primary = measured.filter((m) => m.c.primary);
  assert.equal(primary.length, 15);
  assert.equal(primary.filter((m) => m.c.adversary === 'A2a').length, 6);
  assert.equal(primary.filter((m) => m.c.adversary === 'A2b').length, 9);
  assert.deepEqual(primary.filter((m) => !m.match).map((m) => m.c.id), []);
  for (const id of ['T3b-A2a', 'T3b-A2b', 'T6b-A2b', 'T7-A2b', 'X1']) {
    const m = measured.find((x) => x.c.id === id)!;
    assert.ok(!m.stdout.includes('INCOMPLETE_EXECUTION'), id);
  }
});

// ---------- additional §7 vectors executable with specs 001–003 ----------

function extra(id: string, specified: string, run: () => { measured: string; match: boolean }): void {
  test(`004 additional ${id}`, () => {
    const r = run();
    extras.push({ id, specified, ...r });
    assert.ok(r.match, `${specified} → ${r.measured}`);
  });
}

extra('control-metadata: final control altered, tail recomputed', 'CHECKPOINT_METADATA_MISMATCH at that control (41)', () => {
  const e = new Evidence();
  e.setPayloadField(41, 'tsr_sha256', 'f'.repeat(64));
  e.recompute(41);
  const r = e.verify();
  return { measured: summary(r.exitCode, r.stdout), match: r.exitCode === 1 && r.stdout === 'CHECKPOINT_METADATA_MISMATCH 41\n' && r.stderr === '' };
});

extra('control-metadata: impossible target at the final control', 'CONTROL_EVENT_INVALID only after packages pass (41)', () => {
  const e = new Evidence();
  e.setPayloadField(41, 'anchored_seq', 39);
  e.recompute(41);
  const r = e.verify();
  return { measured: summary(r.exitCode, r.stdout), match: r.exitCode === 1 && r.stdout === 'CONTROL_EVENT_INVALID 41\n' && r.stderr === '' };
});

extra('control-metadata: renumbered T2 still fails divergence first', 'CHECKPOINT_DIVERGENCE 30', () => {
  const m = measured.find((x) => x.c.id === 'T2-A2b');
  assert.ok(m !== undefined);
  return { measured: summary(m.exitCode, m.stdout), match: m.stdout === 'CHECKPOINT_DIVERGENCE 30\n' };
});

extra('receipt revalidation: frozen and replacement receipts under the profile', 'every receipt passes TEAR-TSA-01 Steps 2.2–2.4', () => {
  const bundle = loadBundle(fs.readFileSync(BUNDLE_PATH));
  const results: string[] = [];
  const e = new Evidence();
  for (const k of [10, 20, 30, 40]) {
    const pkg = JSON.parse(Buffer.from(e.files.get(`${String(k)}.anchor.json`)!).toString('utf8')) as Record<string, string>;
    const c = checkReceipt(e.files.get(`${String(k)}.tsr`)!, bundle, pkg['entry_hash']!, pkg['request_nonce_hex']!);
    results.push(`frozen ${String(k)}: ${c.ok ? 'ok' : c.code}`);
  }
  const m = readManifest();
  for (const [name, r] of Object.entries(m.receipts)) {
    const tsr = fs.readFileSync(path.join(TAMPER_RECEIPTS_DIR, r.file));
    const c = checkReceipt(tsr, bundle, r.entry_hash, r.nonce_hex);
    results.push(`${name}: ${c.ok ? 'ok' : c.code}`);
  }
  return { measured: results.join('; '), match: results.every((x) => x.endsWith(': ok')) };
});

extra('T6a precondition: original timestamps more than 10 minutes old when the fresh receipts were issued', 'genTime - ts > 10 min for 30 and 40', () => {
  const m = readManifest();
  const e = new Evidence();
  const out: string[] = [];
  let ok = true;
  for (const k of [30, 40]) {
    const r = m.receipts[`T6a-${String(k)}`]!;
    const parsed = parseReceipt(fs.readFileSync(path.join(TAMPER_RECEIPTS_DIR, r.file)));
    assert.ok(parsed.ok);
    const delta = parsed.genTimeNs - parseTimestampNs(e.rows[k]!.block['ts'] as string)!;
    out.push(`${String(k)}: +${(delta / 1_000_000_000n).toString()} s`);
    ok &&= delta > 600_000_000_000n && !timePredicate(parsed.genTimeNs, parseTimestampNs(e.rows[k]!.block['ts'] as string)!);
  }
  return { measured: out.join('; '), match: ok };
});

extra('bundle custody (auditor procedure, outside tear-verify)', 'only the bundle matching the published fingerprint passes', () => {
  const PUBLISHED = '10335e1e5d816b98665e5f4cb21ed92dd0637d2957658e0c34d55c365240ccfd';
  const pinned = fs.readFileSync(BUNDLE_PATH);
  // Same roots, different pinned signers: the FreeTSA signer is dropped. Both bundles load.
  const blocks = pinned.toString('ascii').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\n/g)!;
  const variant = Buffer.from([blocks[0], blocks[2], blocks[3], blocks[4]].join(''), 'ascii');
  loadBundle(pinned);
  loadBundle(variant);
  const passes = (b: Uint8Array): boolean => bundleSha256(b) === PUBLISHED;
  return { measured: `pinned: ${passes(pinned) ? 'pass' : 'fail'}; variant: ${passes(variant) ? 'pass' : 'fail'}`, match: passes(pinned) && !passes(variant) };
});

after(() => {
  assert.equal(fixtureDigests(), frozenBefore, 'the frozen fixture was not modified');
  const rows = measured.map(
    (m) =>
      `| ${m.c.id.replace(/-A2[ab]$/, '')} | ${m.c.adversary} | ${m.c.specified} | ${summary(m.exitCode, m.stdout)} | ${m.match ? 'match' : 'FAILED'} |`,
  );
  const primary = measured.filter((m) => m.c.primary);
  const count = (adv: string): string => {
    const set = primary.filter((m) => m.c.adversary === adv);
    return `${String(set.filter((m) => m.match).length)}/${String(set.length)}`;
  };
  const extraRows = extras.map((x) => `| ${x.id} | ${x.specified} | ${x.measured} | ${x.match ? 'match' : 'FAILED'} |`);
  const text = [
    '# Tamper battery results (Blueprint §7)',
    '',
    `Frozen fixture chain: \`${FIXTURE_CHAIN_ID}\`. Bundle: \`${bundleSha256(fs.readFileSync(BUNDLE_PATH))}\`.`,
    '',
    '| Case | Adversary | Specified (§7) | Measured | Result |',
    '| --- | --- | --- | --- | --- |',
    ...rows,
    '',
    `Primary M1 results matched: ${String(primary.filter((m) => m.match).length)}/${String(primary.length)} (A2a ${count('A2a')}, A2b ${count('A2b')}). ` +
      `X1: ${measured.find((m) => m.c.id === 'X1')?.match === true ? 'match' : 'FAILED'}. X2: ${measured.find((m) => m.c.id === 'X2')?.match === true ? 'match' : 'FAILED'}.`,
    '',
    '## Additional §7 vectors run on the frozen fixture',
    '',
    '| Vector | Specified | Measured | Result |',
    '| --- | --- | --- | --- |',
    ...extraRows,
    '',
  ].join('\n');
  fs.mkdirSync(path.dirname(RESULTS_PATH), { recursive: true });
  fs.writeFileSync(RESULTS_PATH, text);
});
