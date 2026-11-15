// SPDX-License-Identifier: AGPL-3.0-or-later
// The frozen M1 fixture (Blueprint §7) verified without network, against the
// pinned bundle. The receipts are real and are never regenerated.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { bundleSha256, sha256Hex } from '../../src/crypto/digests.js';
import { parseStrictJson } from '../../src/json/strict-json.js';
import type { JsonObject } from '../../src/json/strict-json.js';
import { loadBundle } from '../../src/pki/bundle.js';
import { bytesEqual, parseCertificate } from '../../src/pki/certificate.js';
import { checkReceipt, parseReceipt } from '../../src/tsa/receipt.js';
import { verifyOffline } from '../../src/verify/verify.js';
import { FIXTURE_DIR, describeReceipt } from '../fixture-tools/fixture-files.js';

interface Manifest {
  chain_id: string;
  tsa_ca_bundle_sha256: string;
  files: Record<string, string>;
  receipts: (Record<string, unknown> & { k: number; tsa: string })[];
  expected_stdout: string;
  expected_exit_code: number;
}

const BUNDLE = path.resolve('certs/tsa_roots.pem');
const manifest = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.json'), 'utf8')) as Manifest;
const ns = path.join(FIXTURE_DIR, manifest.chain_id);
const rows = fs
  .readFileSync(path.join(FIXTURE_DIR, 'events.jsonl'), 'utf8')
  .trimEnd()
  .split('\n')
  .map((l) => parseStrictJson(l) as JsonObject);
const block = (i: number): JsonObject => rows[i]!['block'] as JsonObject;
const payload = (i: number): JsonObject => block(i)['payload'] as JsonObject;

function hashAll(): string {
  return Object.keys(manifest.files)
    .sort()
    .map((f) => `${f}:${sha256Hex(fs.readFileSync(path.join(FIXTURE_DIR, f)))}`)
    .join('\n');
}

test('003 AC-23 frozen-fixture', async (t) => {
  await t.test('every file matches the digest recorded in the manifest', () => {
    for (const [f, digest] of Object.entries(manifest.files)) assert.equal(sha256Hex(fs.readFileSync(path.join(FIXTURE_DIR, f))), digest, f);
    assert.deepEqual(
      fs.readdirSync(ns).sort(),
      ['10.anchor.json', '10.tsr', '20.anchor.json', '20.tsr', '30.anchor.json', '30.tsr', '40.anchor.json', '40.tsr'],
    );
    assert.equal(manifest.tsa_ca_bundle_sha256, bundleSha256(fs.readFileSync(BUNDLE)));
  });
  await t.test('verifies offline to VERIFIED_ANCHORED 0..40, VALID_UNANCHORED 41..50, exactly as frozen', () => {
    const before = hashAll();
    const r = verifyOffline({ logPath: path.join(FIXTURE_DIR, 'events.jsonl'), checkpointsPath: ns, bundlePath: BUNDLE });
    assert.equal(r.exitCode, 0);
    assert.equal(r.stderr, '');
    assert.equal(r.stdout, manifest.expected_stdout);
    assert.ok(r.stdout.startsWith('VERIFIED_ANCHORED 0..40\nVALID_UNANCHORED 41..50\nMAX_ANCHOR_GAP 10\nANCHORED_CHECKPOINT_FAILURES 0\n'));
    assert.ok(!r.stdout.includes('INCOMPLETE_EXECUTION'));
    assert.equal(hashAll(), before, 'verification never rewrites the receipts');
  });
  await t.test('§7 fixture bullets: genesis, 51 rows, controls at 11/21/31/41, pause-only application events', () => {
    assert.equal(rows.length, 51);
    assert.equal(payload(0)['event_type'], 'chain_genesis');
    for (let i = 1; i <= 50; i++) {
      const p = payload(i);
      if ([11, 21, 31, 41].includes(i)) {
        assert.equal(p['event_type'], 'checkpoint_anchored', `row ${String(i)}`);
        assert.equal(p['anchored_seq'], i - 1);
        continue;
      }
      assert.equal(p['event_type'], 'epistemic_pause', `row ${String(i)}`);
      assert.ok(typeof p['task_id'] === 'string' && p['task_id'] !== '');
      assert.ok(typeof p['reason'] === 'string' && p['reason'] !== '');
      assert.deepEqual(p['missing_sources'], []);
    }
    assert.equal(payload(25)['reason'], 'baseline');
    const tasks = [22, 23, 24, 25, 26].map((i) => payload(i)['task_id']);
    assert.equal(new Set(tasks).size, 5, 'distinct task_id values at 22..26');
    assert.ok(!rows.some((_r, i) => ['tool_call', 'tool_result'].includes(String(payload(i)['event_type']))));
  });
  await t.test('timestamps strictly increase with at least 100 ms between rows (ts[22] < ts[23])', () => {
    for (let i = 1; i < rows.length; i++) {
      assert.ok(Date.parse(String(block(i)['ts'])) - Date.parse(String(block(i - 1)['ts'])) >= 100, `rows ${String(i - 1)}..${String(i)}`);
    }
  });
  await t.test('automatic anchors at 10, 20, 30, 40 only; 50 is not anchored (max_auto_anchor_seq = 40)', () => {
    assert.deepEqual(manifest.receipts.map((r) => r.k), [10, 20, 30, 40]);
    assert.ok(!fs.existsSync(path.join(ns, '50.tsr')));
  });
  await t.test('real receipts from both retained TSAs, each pinned and passing TEAR-TSA-01', () => {
    const bundle = loadBundle(fs.readFileSync(BUNDLE));
    const pinnedSigners = bundle.certificates.filter((c) => c.role === 'signer').map((c) => c.cert);
    const usedSigners = new Set<number>();
    for (const rec of manifest.receipts) {
      const tsr = fs.readFileSync(path.join(ns, `${String(rec.k)}.tsr`));
      const pkg = JSON.parse(fs.readFileSync(path.join(ns, `${String(rec.k)}.anchor.json`), 'utf8')) as Record<string, string>;
      const c = checkReceipt(tsr, bundle, pkg['entry_hash']!, pkg['request_nonce_hex']!);
      assert.ok(c.ok, `receipt ${String(rec.k)}`);
      const parsed = parseReceipt(tsr);
      assert.ok(parsed.ok);
      // The manifest records exact bytes, serial, genTime and accuracy.
      const { attempts: _a, k: _k, tsa: _t, ...recorded } = rec;
      assert.deepEqual(describeReceipt(tsr, parsed.receipt), recorded);
      const signerIndex = pinnedSigners.findIndex((s) => parsed.receipt.certificates.some((e) => bytesEqual(e, s.der)));
      assert.ok(signerIndex >= 0);
      usedSigners.add(signerIndex);
    }
    assert.equal(usedSigners.size, 2, 'both pinned signers appear');
    assert.deepEqual([...new Set(manifest.receipts.map((r) => r.tsa))].sort(), ['digicert', 'freetsa']);
    const subjects = pinnedSigners.map((s) => Buffer.from(parseCertificate(s.der).subject).toString('latin1'));
    assert.ok(subjects.some((s) => s.includes('freetsa')) && subjects.some((s) => s.includes('DigiCert')));
  });
  await t.test('the build tool refuses to regenerate an existing fixture', () => {
    assert.ok(fs.existsSync(FIXTURE_DIR));
    const r = spawnSync(process.execPath, ['dist/test/fixture-tools/build-frozen-fixture.js'], { encoding: 'utf8' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /exists: frozen receipts are never regenerated/);
    assert.equal(hashAll(), Object.keys(manifest.files).sort().map((f) => `${f}:${manifest.files[f]!}`).join('\n'));
  });
});
