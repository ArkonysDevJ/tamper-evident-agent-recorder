// SPDX-License-Identifier: AGPL-3.0-or-later
// Requires local PostgreSQL (npm run test:pg). Anchoring in the writer
// (Blueprint §5.7) with in-process test TSAs; no network.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { before, test } from 'node:test';
import { autoAnchorHook, triggersAutoAnchor } from '../../src/anchor/trigger.js';
import { exportChain } from '../../src/chain/export.js';
import { initializeChain } from '../../src/chain/initialize.js';
import type { AnchorHook } from '../../src/chain/interfaces.js';
import { ChainWriter } from '../../src/chain/writer.js';
import type { WriterOptions } from '../../src/chain/writer.js';
import { sha256Hex } from '../../src/crypto/digests.js';
import { verifyOffline } from '../../src/verify/verify.js';
import { pausePayload } from '../helpers/chain-builder.js';
import { RecordingFs } from '../helpers/fs-double.js';
import { ext, nullValue, testPki } from '../helpers/pki.js';
import { admin, codeOf, ensureSchema, initOptions, newChain, pgConfig, rowCount, waitFor, writerOptions } from '../helpers/pg.js';
import type { TestChain } from '../helpers/pg.js';
import { testTsa } from '../helpers/test-tsa.js';
import type { TestTsa } from '../helpers/test-tsa.js';

before(ensureSchema);

const pki = testPki(1);

interface Harness {
  chain: TestChain;
  writer: ChainWriter;
  primary: TestTsa;
  secondary: TestTsa;
  exits: unknown[];
  fsd: RecordingFs;
  hookSeqs: number[];
}

async function harness(extra: Partial<WriterOptions> & { maxAuto?: number; single?: boolean } = {}): Promise<Harness> {
  const chain = newChain();
  await initializeChain(initOptions(chain, { bundleBytes: pki.bundle }));
  const primary = testTsa('primary', pki);
  const secondary = testTsa('secondary', pki);
  const exits: unknown[] = [];
  const fsd = new RecordingFs(chain.nsPath);
  const hookSeqs: number[] = [];
  const inner = autoAnchorHook(extra.maxAuto ?? Number.POSITIVE_INFINITY);
  const spy: AnchorHook = {
    onApplicationCommit: async (ctx) => {
      hookSeqs.push(ctx.seq);
      return inner.onApplicationCommit(ctx);
    },
  };
  const writer = await ChainWriter.open(
    writerOptions(chain, {
      bundleBytes: pki.bundle,
      anchorHook: spy,
      tsas: extra.single === true ? [primary] : [primary, secondary],
      fsOps: fsd,
      exit: (cause) => exits.push(cause),
      ...extra,
    }),
  );
  return { chain, writer, primary, secondary, exits, fsd, hookSeqs };
}

async function appendN(w: ChainWriter, n: number): Promise<Awaited<ReturnType<ChainWriter['append']>>[]> {
  const out = [];
  for (let i = 0; i < n; i++) out.push(await w.append(pausePayload(i + 1)));
  return out;
}

async function stateOf(chainId: string): Promise<Record<string, unknown>> {
  const [s] = await admin('SELECT * FROM tear_chain_state WHERE chain_id = $1', [chainId]);
  return s!;
}

async function eventTypes(chainId: string): Promise<string[]> {
  const rows = await admin<{ t: string }>("SELECT payload->>'event_type' AS t FROM tear_events WHERE chain_id = $1 ORDER BY seq", [chainId]);
  return rows.map((r) => r.t);
}

function names(ns: string): string[] {
  return fs.readdirSync(ns).filter((n) => n !== '.writer.lock').sort();
}

async function exportAndVerify(h: Harness): Promise<ReturnType<typeof verifyOffline>> {
  const dir = path.dirname(h.chain.nsPath);
  const log = path.join(dir, `${h.chain.chainId}.events.jsonl`);
  await exportChain({ pg: pgConfig, chainId: h.chain.chainId, bundleBytes: pki.bundle, outPath: log });
  const bundlePath = path.join(dir, 'bundle.pem');
  fs.writeFileSync(bundlePath, pki.bundle);
  return verifyOffline({ logPath: log, checkpointsPath: h.chain.nsPath, bundlePath });
}

test('003 AC-3 auto-trigger', async (t) => {
  await t.test('trigger rule: k > 0, k % 10 == 0, k <= max_auto_anchor_seq', () => {
    assert.deepEqual([0, 1, 9, 10, 11, 20, 30, 40, 50].filter((k) => triggersAutoAnchor(k, 40)), [10, 20, 30, 40]);
    assert.ok(triggersAutoAnchor(1_000_000, Number.POSITIVE_INFINITY));
  });
  await t.test('pending is set in the transaction of record k; control rows never trigger', async () => {
    const h = await harness();
    h.primary.behaviors = [
      {
        kind: 'custom',
        run: async (req) => {
          // When the TSA is asked, row k and the pending fields are both committed.
          const s = await stateOf(h.chain.chainId);
          assert.equal(String(s['pending_anchor_seq']), '10');
          assert.equal(s['pending_mode'], 'auto');
          assert.equal(await rowCount(h.chain.chainId), 11);
          return testTsa('inner', pki).request(req.der);
        },
      },
      { kind: 'ok' },
    ];
    const results = await appendN(h.writer, 21);
    assert.deepEqual(results.filter((r) => r.anchor !== undefined).map((r) => r.seq), [10, 20]);
    const types = await eventTypes(h.chain.chainId);
    assert.equal(types[11], 'checkpoint_anchored');
    assert.equal(types[21], 'checkpoint_anchored');
    assert.ok(!h.hookSeqs.includes(11) && !h.hookSeqs.includes(21), 'the hook never sees control rows');
    assert.equal(h.hookSeqs.length, 21);
    assert.equal((await stateOf(h.chain.chainId))['pending_anchor_seq'], null);
    await h.writer.close();
  });
  await t.test('k above max_auto_anchor_seq is not anchored', async () => {
    const h = await harness({ maxAuto: 10 });
    const results = await appendN(h.writer, 21);
    assert.deepEqual(results.filter((r) => r.anchor !== undefined).map((r) => r.seq), [10]);
    assert.equal(h.primary.requests.length, 1);
    await h.writer.close();
  });
});

test('003 AC-4 pending-blocks-queue', async (t) => {
  await t.test('while anchor 10 is pending, the next append does not start', async () => {
    const h = await harness();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    h.primary.behaviors = [{ kind: 'custom', run: async (req) => { await gate; return testTsa('inner', pki).request(req.der); } }];
    await appendN(h.writer, 9);
    const tenth = h.writer.append(pausePayload(10));
    await waitFor(() => h.primary.requests.length === 1);
    const next = h.writer.append(pausePayload(11));
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(await rowCount(h.chain.chainId), 11, 'only rows 0..10 exist while pending');
    release();
    const r10 = await tenth;
    const r12 = await next;
    assert.equal(r10.anchor?.kind, 'anchored');
    assert.equal(r12.seq, 12, 'the next append follows the control row at 11');
    await h.writer.close();
  });
});

test('003 AC-5 fallback', async (t) => {
  const failures: [string, TestTsa['behaviors'][number]][] = [
    ['timeout', { kind: 'transport', result: { kind: 'failure', reason: 'timeout', detail: 't' } }],
    ['network error', { kind: 'transport', result: { kind: 'failure', reason: 'network', detail: 'n' } }],
    ['HTTP status not 200', { kind: 'transport', result: { kind: 'failure', reason: 'http_status', detail: '500' } }],
    ['a body that is not a TimeStampResp', { kind: 'body', body: Buffer.from('<html>') }],
    ['PKIStatus rejection', { kind: 'ok', token: { status: 2n } }],
    ['a step 3 failure: bad signature', { kind: 'ok', token: { badSignature: true } }],
    ['a step 3 failure: nonce mismatch', { kind: 'ok', tst: { nonce: 5n } }],
    ['a step 3 failure: TSA_TIME_INCONSISTENT', { kind: 'ok', genTimeOffsetMs: 120_000 }],
  ];
  for (const [label, behavior] of failures) {
    await t.test(`primary fails (${label}): the same .tsq goes to the secondary`, async () => {
      const h = await harness();
      h.primary.behaviors = [behavior];
      const r = (await appendN(h.writer, 10))[9]!;
      assert.equal(r.anchor?.kind, 'anchored');
      assert.equal(r.anchor?.kind === 'anchored' && r.anchor.tsa, 'secondary');
      assert.deepEqual(h.secondary.requests[0]!.der, h.primary.requests[0]!.der);
      assert.equal(sha256Hex(h.primary.requests[0]!.der), JSON.parse(fs.readFileSync(path.join(h.chain.nsPath, '10.anchor.json'), 'utf8')).tsq_der_sha256);
      await h.writer.close();
    });
  }
  await t.test('with one retained TSA there is no fallback', async () => {
    const h = await harness({ single: true });
    h.primary.behaviors = [{ kind: 'transport', result: { kind: 'failure', reason: 'timeout', detail: 't' } }];
    const r = (await appendN(h.writer, 10))[9]!;
    assert.equal(r.anchor?.kind, 'failed');
    assert.equal(h.secondary.requests.length, 0);
    await h.writer.close();
  });
  await t.test('writer invalidation during the request never triggers fallback', async () => {
    const h = await harness();
    h.primary.behaviors = [{ kind: 'custom', run: async (req) => { h.writer.connForTests.invalidate(); return testTsa('inner', pki).request(req.der); } }];
    await appendN(h.writer, 9);
    assert.equal(await codeOf(h.writer.append(pausePayload(10))), 'WRITER_INVALIDATED');
    assert.equal(h.secondary.requests.length, 0);
    await waitFor(() => h.exits.length === 1);
    assert.equal(String((await stateOf(h.chain.chainId))['pending_anchor_seq']), '10', 'no SQL resolution');
    assert.deepEqual(names(h.chain.nsPath), ['10.tsq'], 'no cleanup');
  });
  await t.test('a filesystem error after an accepted receipt never triggers fallback', async () => {
    const h = await harness();
    h.fsd.failOn = { op: 'rename', nth: 2, code: 'EIO' }; // 1: 10.tsq, 2: 10.tsr
    await appendN(h.writer, 9);
    assert.equal(await codeOf(h.writer.append(pausePayload(10))), 'NAMESPACE_MUTATION_FAILED');
    assert.equal(h.secondary.requests.length, 0);
    await waitFor(() => h.exits.length === 1);
    assert.deepEqual(await eventTypes(h.chain.chainId).then((t2) => t2.length), 11, 'no checkpoint row');
  });
});

test('003 AC-6 success-path', async (t) => {
  await t.test('publish .tsr, publish .anchor.json, commit control + clear, then delete .tsq — in that order', async () => {
    const h = await harness();
    const seen: string[] = [];
    h.fsd.before = async (op) => {
      if (op === 'unlink') {
        const s = await stateOf(h.chain.chainId);
        seen.push(`unlink after commit: pending=${String(s['pending_anchor_seq'])} rows=${String(await rowCount(h.chain.chainId))}`);
      }
      if (op === 'open' && h.fsd.calls.at(-1) === 'open 10.anchor.json.tmp') {
        seen.push(`anchor.json while rows=${String(await rowCount(h.chain.chainId))}`);
      }
    };
    await appendN(h.writer, 10);
    const order = h.fsd.calls.filter((c) => c.startsWith('rename') || c.startsWith('unlink'));
    assert.deepEqual(order, ['rename 10.tsq.tmp -> 10.tsq', 'rename 10.tsr.tmp -> 10.tsr', 'rename 10.anchor.json.tmp -> 10.anchor.json', 'unlink 10.tsq']);
    assert.deepEqual(seen, ['anchor.json while rows=11', 'unlink after commit: pending=null rows=12']);
    assert.deepEqual(names(h.chain.nsPath), ['10.anchor.json', '10.tsr']);
    const [control] = await admin<{ p: Record<string, unknown> }>('SELECT payload AS p FROM tear_events WHERE chain_id = $1 AND seq = 11', [h.chain.chainId]);
    assert.equal(control!.p['tsr_sha256'], sha256Hex(fs.readFileSync(path.join(h.chain.nsPath, '10.tsr'))));
    assert.equal(control!.p['operation'], 'tear.checkpoint');
    await appendN(h.writer, 3);
    await h.writer.close();
    const r = await exportAndVerify(h);
    assert.equal(r.exitCode, 0, r.stdout);
    assert.match(r.stdout, /^VERIFIED_ANCHORED 0..10\nVALID_UNANCHORED 11..14\n/);
  });
});

test('003 AC-7 failure-path', async (t) => {
  await t.test('both TSAs fail: checkpoint_failed and the pending clear commit together, then .tsq is deleted', async () => {
    const h = await harness();
    h.primary.behaviors = [{ kind: 'transport', result: { kind: 'failure', reason: 'timeout', detail: 't' } }];
    h.secondary.behaviors = [{ kind: 'ok', token: { badSignature: true } }];
    const r = (await appendN(h.writer, 10))[9]!;
    assert.deepEqual(r.anchor?.kind === 'failed' && r.anchor.errorType, 'tsa_validation_failed');
    const [control] = await admin<{ p: Record<string, unknown> }>('SELECT payload AS p FROM tear_events WHERE chain_id = $1 AND seq = 11', [h.chain.chainId]);
    assert.deepEqual(control!.p, { event_type: 'checkpoint_failed', operation: 'tear.checkpoint', target_seq: 10, error_type: 'tsa_validation_failed' });
    assert.equal((await stateOf(h.chain.chainId))['pending_anchor_seq'], null);
    assert.deepEqual(names(h.chain.nsPath), []);
    await appendN(h.writer, 2);
    await h.writer.close();
    const v = await exportAndVerify(h);
    assert.equal(v.exitCode, 0);
    assert.equal(v.stdout, 'VALID_UNANCHORED 0..13\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
  await t.test('error_type names the last TSA failure: unreachable, rejected', async () => {
    for (const [b, expected] of [
      [{ kind: 'transport', result: { kind: 'failure', reason: 'timeout', detail: 't' } }, 'tsa_unreachable'],
      [{ kind: 'transport', result: { kind: 'failure', reason: 'http_status', detail: '503' } }, 'tsa_rejected'],
      [{ kind: 'ok', token: { status: 2n } }, 'tsa_rejected'],
    ] as const) {
      const h = await harness({ single: true });
      h.primary.behaviors = [b];
      const r = (await appendN(h.writer, 10))[9]!;
      assert.equal(r.anchor?.kind === 'failed' && r.anchor.errorType, expected);
      await h.writer.close();
    }
  });
});

test('003 AC-8 publication-failure', async (t) => {
  const points: [string, RecordingFs['failOn'], string[], string | null][] = [
    ['.tsq write', { op: 'write', nth: 1, code: 'EIO' }, ['10.tsq.tmp'], '10'],
    ['.tsr rename', { op: 'rename', nth: 2, code: 'EIO' }, ['10.tsq', '10.tsr.tmp'], '10'],
    ['.anchor.json directory fsync', { op: 'fsync', nth: 6, code: 'EIO' }, ['10.anchor.json', '10.tsq', '10.tsr'], '10'],
    ['.tsq unlink after the confirmed transition', { op: 'unlink', nth: 1, code: 'EIO' }, ['10.anchor.json', '10.tsq', '10.tsr'], null],
  ];
  for (const [label, failOn, left, pending] of points) {
    await t.test(`${label}: invalidate, drain and exit; no new resolution, no cleanup, no TSA failure`, async () => {
      const h = await harness();
      h.fsd.failOn = failOn;
      await appendN(h.writer, 9);
      assert.equal(await codeOf(h.writer.append(pausePayload(10))), 'NAMESPACE_MUTATION_FAILED');
      await waitFor(() => h.exits.length === 1);
      assert.ok(h.writer.invalidated);
      assert.deepEqual(names(h.chain.nsPath), left);
      const s = await stateOf(h.chain.chainId);
      assert.equal(s['pending_anchor_seq'] === null ? null : String(s['pending_anchor_seq']), pending);
      const types = await eventTypes(h.chain.chainId);
      assert.ok(!types.includes('checkpoint_failed'), 'never reclassified as a TSA failure');
      assert.equal(await codeOf(h.writer.append(pausePayload(11))), 'WRITER_INVALIDATED');
      assert.equal(h.exits.length, 1);
    });
  }
  await t.test('an SQL failure of the checkpoint transition: invalidate and exit, package kept, pending kept', async () => {
    const h = await harness();
    h.fsd.before = async (op) => {
      if (op === 'rename' && h.fsd.calls.at(-1) === 'rename 10.anchor.json.tmp -> 10.anchor.json') {
        await admin('SELECT pg_terminate_backend($1)', [h.writer.backendPid]);
      }
    };
    await appendN(h.writer, 9);
    const code = await codeOf(h.writer.append(pausePayload(10)));
    assert.ok(['WRITER_INVALIDATED', 'COMMIT_OUTCOME_UNKNOWN', 'NAMESPACE_MUTATION_FAILED'].includes(code), code);
    await waitFor(() => h.exits.length === 1);
    assert.deepEqual(names(h.chain.nsPath), ['10.anchor.json', '10.tsq', '10.tsr']);
    assert.equal(String((await stateOf(h.chain.chainId))['pending_anchor_seq']), '10');
    assert.equal(await rowCount(h.chain.chainId), 11);
  });
});

test('003 AC-22 writer-profile', async (t) => {
  const rejected: [string, TestTsa['behaviors'][number]][] = [
    ['a critical TSTInfo extension', { kind: 'ok', tst: { extensions: [ext.raw('1.2.3.4.9', nullValue(), true)] } }],
    ['a token that does not embed its signer', { kind: 'ok', token: { certificates: [] } }],
    ['a signer outside the bundle', { kind: 'ok', token: { signerCert: testPki(2).signer, signerKey: testPki(2).signerKey, certificates: [testPki(2).signer] } }],
    ['an ESS binding to another certificate', { kind: 'ok', token: { ess: [{ version: 2, cert: pki.intermediate }], certificates: [pki.signer, pki.intermediate] } }],
    ['an empty CMS digest set', { kind: 'ok', token: { digestSet: [] } }],
  ];
  for (const [label, b] of rejected) {
    await t.test(`the writer rejects what the verifier rejects: ${label}`, async () => {
      const h = await harness({ single: true });
      h.primary.behaviors = [b];
      const r = (await appendN(h.writer, 10))[9]!;
      assert.equal(r.anchor?.kind === 'failed' && r.anchor.errorType, 'tsa_validation_failed');
      assert.deepEqual(names(h.chain.nsPath), []);
      await h.writer.close();
    });
  }
});
