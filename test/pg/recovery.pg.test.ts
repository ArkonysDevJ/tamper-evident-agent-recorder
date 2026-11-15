// SPDX-License-Identifier: AGPL-3.0-or-later
// Requires local PostgreSQL (npm run test:pg). Spec 006: §5.6 reconciliation
// (E1–E10), initializeChain inspection, closeChain B0–B3, the evidence package
// and fault injection. Fault injection simulates crashes (a failed mutation
// that drains and exits, or SIGKILL in a child process); it does not prove
// behavior under real power loss.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { before, test } from 'node:test';
import { autoAnchorHook } from '../../src/anchor/trigger.js';
import { buildEvidencePackage } from '../../src/chain/evidence.js';
import { initializeChain } from '../../src/chain/initialize.js';
import type { CutProfile } from '../../src/chain/profile.js';
import { ChainWriter } from '../../src/chain/writer.js';
import type { WriterOptions } from '../../src/chain/writer.js';
import { provisionNamespace } from '../../src/fs/namespace.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { verifyOffline } from '../../src/verify/verify.js';
import { pausePayload } from '../helpers/chain-builder.js';
import { RecordingFs } from '../helpers/fs-double.js';
import { loadPki } from '../helpers/pki-files.js';
import { testPki } from '../helpers/pki.js';
import type { TestPki } from '../helpers/pki.js';
import { admin, codeOf, ensureSchema, pgConfig, rowCount, waitFor } from '../helpers/pg.js';
import { testTsa } from '../helpers/test-tsa.js';
import type { TestTsa } from '../helpers/test-tsa.js';

before(ensureSchema);

const PKI = testPki(5);

interface Chain {
  root: string;
  chainId: string;
  nsPath: string;
  pki: TestPki;
  genesisTs: string;
}

function newAnchoredChain(pki: TestPki = PKI): Chain {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-rec-'));
  const chainId = randomUUID();
  const nsPath = provisionNamespace(root, chainId);
  return { root, chainId, nsPath, pki, genesisTs: formatTimestamp(Date.now() - 1000) };
}

function initOpts(c: Chain, profile: CutProfile = 'base') {
  return { checkpointsRoot: c.root, chainId: c.chainId, genesisTs: c.genesisTs, pepperId: 'rec-pepper', bundleBytes: c.pki.bundle, pg: pgConfig, profile };
}

interface Opened {
  writer: ChainWriter | null;
  code: string;
  fsd: RecordingFs;
  tsa: TestTsa;
  exits: unknown[];
}

/** Starts a writer on the chain (§5.6 reconciliation included); records file calls and exits. */
async function open(c: Chain, extra: Partial<WriterOptions> & { failOn?: RecordingFs['failOn']; before?: RecordingFs['before'] } = {}): Promise<Opened> {
  const fsd = new RecordingFs(c.nsPath);
  fsd.failOn = extra.failOn ?? null;
  fsd.before = extra.before ?? null;
  const tsa = testTsa('test-tsa', c.pki);
  const exits: unknown[] = [];
  try {
    const writer = await ChainWriter.open({
      checkpointsRoot: c.root,
      chainId: c.chainId,
      bundleBytes: c.pki.bundle,
      pg: pgConfig,
      profile: 'base',
      anchorHook: autoAnchorHook(),
      tsas: [tsa],
      fsOps: fsd,
      exit: (cause) => exits.push(cause),
      ...extra,
    });
    return { writer, code: 'OK', fsd, tsa, exits };
  } catch (err) {
    return { writer: null, code: (err as { code?: string }).code ?? String(err), fsd, tsa, exits };
  }
}

async function create(c: Chain, profile: CutProfile = 'base'): Promise<void> {
  assert.equal(await initializeChain(initOpts(c, profile)), 'INITIALIZED');
}

async function appendN(w: ChainWriter, n: number): Promise<void> {
  for (let i = 0; i < n; i++) await w.append(pausePayload(i + 1));
}

const names = (c: Chain): string[] => fs.readdirSync(c.nsPath).filter((n) => n !== '.writer.lock').sort();

async function pendingOf(c: Chain): Promise<string | null> {
  const [s] = await admin<{ p: string | null }>('SELECT pending_anchor_seq::text AS p FROM tear_chain_state WHERE chain_id = $1', [c.chainId]);
  return s!.p;
}

async function payloadAt(c: Chain, seq: number): Promise<Record<string, unknown> | undefined> {
  const [r] = await admin<{ p: Record<string, unknown> }>('SELECT payload AS p FROM tear_events WHERE chain_id = $1 AND seq = $2', [c.chainId, seq]);
  return r?.p;
}

/** Sets the pending fields to row k directly (a legacy or non-conforming state for the defensive cases). */
async function setPending(c: Chain, k: number, mode = 'auto'): Promise<void> {
  await admin(
    `UPDATE tear_chain_state SET pending_anchor_seq = $2, pending_entry_hash = e.entry_hash, pending_ts = e.ts, pending_mode = $3
     FROM tear_events e WHERE tear_chain_state.chain_id = $1 AND e.chain_id = $1 AND e.seq = $2`,
    [c.chainId, k, mode],
  );
}

/** Everything inspection must leave untouched: rows, state and namespace bytes (lock file excluded). */
async function snapshot(c: Chain): Promise<string> {
  const ev = await admin('SELECT * FROM tear_events WHERE chain_id = $1 ORDER BY seq', [c.chainId]);
  const st = await admin('SELECT * FROM tear_chain_state WHERE chain_id = $1', [c.chainId]);
  const files = names(c).map((n) => {
    const p = path.join(c.nsPath, n);
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) return `${n}:link:${fs.readlinkSync(p)}`;
    if (!st.isFile()) return `${n}:${st.isDirectory() ? 'dir' : 'other'}`;
    return `${n}:${fs.readFileSync(p).toString('base64')}`;
  });
  return JSON.stringify({ ev, st, files });
}

async function verifyChain(c: Chain): Promise<ReturnType<typeof verifyOffline>> {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-rec-out-'));
  const ev = await buildEvidencePackage({ checkpointsRoot: c.root, chainId: c.chainId, pg: pgConfig, bundleBytes: c.pki.bundle, outDir: path.join(out, 'e') });
  const bundlePath = path.join(out, 'bundle.pem');
  fs.writeFileSync(bundlePath, c.pki.bundle);
  return verifyOffline({ logPath: ev.logPath, checkpointsPath: ev.checkpointsPath, bundlePath });
}

// ---------- state builders (crashes simulated by an injected failure: drain and exit) ----------

/** A writer that anchors at 10 with an injected file failure; returns after it drained and exited. */
async function crashDuringAnchor(c: Chain, failOn: RecordingFs['failOn'], tsaOk = true): Promise<void> {
  await create(c);
  const o = await open(c, { failOn });
  if (!tsaOk) o.tsa.behaviors = [{ kind: 'transport', result: { kind: 'failure', reason: 'timeout', detail: 't' } }];
  await appendN(o.writer!, 9);
  await o.writer!.append(pausePayload(10)).catch(() => undefined);
  await waitFor(() => o.exits.length === 1);
}

// File-call numbering in a fresh writer: fsync 1 is the start-up directory barrier; the anchor at 10 then
// does .tsq (fsync 2, 3), .tsr (4, 5), .anchor.json (6, 7); renames: 1 .tsq, 2 .tsr, 3 .anchor.json.
const E2_STATE = { op: 'unlink', nth: 1, code: 'EIO' } as const; // control committed, .tsq left
const E7_STATE = { op: 'fsync', nth: 7, code: 'EIO' } as const; // package complete, pending kept
const E8_STATE = { op: 'rename', nth: 2, code: 'EIO' } as const; // .tsq + 10.tsr.tmp, pending kept

async function stateE1(c: Chain): Promise<void> {
  await create(c);
  const o = await open(c);
  await appendN(o.writer!, 12);
  await o.writer!.close();
}

async function stateE4(c: Chain, withTsq: boolean): Promise<void> {
  await stateE1(c);
  await setPending(c, 10);
  if (withTsq) fs.writeFileSync(path.join(c.nsPath, '10.tsq'), 'request');
  await admin('DELETE FROM tear_events WHERE chain_id = $1 AND seq > 11', [c.chainId]);
}

async function stateE5(c: Chain): Promise<void> {
  await crashDuringAnchor(c, { op: 'unlink', nth: 1, code: 'EIO' }, false); // checkpoint_failed committed, .tsq left
  await setPending(c, 10);
}

test('006 AC-1 inventory-and-cleanup', async (t) => {
  await t.test('recognized .tmp files are durably deleted before state selection (base)', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    fs.writeFileSync(path.join(c.nsPath, '20.tsr.tmp'), 'partial');
    fs.writeFileSync(path.join(c.nsPath, '20.anchor.json.tmp'), 'partial');
    const o = await open(c);
    assert.equal(o.code, 'OK');
    assert.equal(o.writer!.startedFrom, 'E1');
    assert.deepEqual(names(c), ['10.anchor.json', '10.tsr']);
    assert.deepEqual(o.fsd.calls.slice(0, 2), ['unlink 20.anchor.json.tmp', 'unlink 20.tsr.tmp']);
    await o.writer!.close();
  });
  for (const [label, make] of [
    ['an unknown name', (ns: string) => fs.writeFileSync(path.join(ns, 'notes.txt'), 'x')],
    ['a directory', (ns: string) => fs.mkdirSync(path.join(ns, '30.tsr'))],
    ['a symlink', (ns: string) => fs.symlinkSync('/etc/hostname', path.join(ns, '30.tsr'))],
    ['an unknown temporary name', (ns: string) => fs.writeFileSync(path.join(ns, '30.tsr.tmp2'), 'x')],
  ] as const) {
    await t.test(`${label} fails closed, nothing is touched`, async () => {
      const c = newAnchoredChain();
      await stateE1(c);
      make(c.nsPath);
      const before0 = await snapshot(c);
      const o = await open(c);
      assert.equal(o.code, 'RECONCILIATION_STATE_INCONSISTENT');
      assert.equal(await snapshot(c), before0);
    });
  }
  await t.test('an invalid stored row fails Step 1 validation before any cleanup', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    fs.writeFileSync(path.join(c.nsPath, '20.tsr.tmp'), 'partial');
    await admin("UPDATE tear_events SET ts = '2001-01-01T00:00:00.000Z' WHERE chain_id = $1 AND seq = 5", [c.chainId]);
    const o = await open(c);
    assert.equal(o.code, 'RECONCILIATION_STATE_INCONSISTENT');
    assert.ok(names(c).includes('20.tsr.tmp'), 'no cleanup after a failed validation');
  });
});

test('006 AC-2 committed-packages', async (t) => {
  for (const profile of ['base', 'cut1-3'] as const) {
    await t.test(`${profile}: a committed checkpoint_anchored without its package fails closed`, async () => {
      const c = newAnchoredChain();
      await stateE1(c);
      fs.rmSync(path.join(c.nsPath, '10.tsr'));
      const before0 = await snapshot(c);
      assert.equal((await open(c, { profile })).code, 'RECONCILIATION_STATE_INCONSISTENT');
      assert.equal(await snapshot(c), before0);
    });
  }
  await t.test('a package without its committed control fails closed', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    fs.copyFileSync(path.join(c.nsPath, '10.tsr'), path.join(c.nsPath, '12.tsr'));
    fs.copyFileSync(path.join(c.nsPath, '10.anchor.json'), path.join(c.nsPath, '12.anchor.json'));
    assert.equal((await open(c)).code, 'RECONCILIATION_STATE_INCONSISTENT');
  });
  await t.test('a committed package that fails Step 2 fails closed', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    const p = path.join(c.nsPath, '10.tsr');
    const b = fs.readFileSync(p);
    b[b.length - 10]! ^= 1;
    fs.writeFileSync(p, b);
    assert.equal((await open(c)).code, 'RECONCILIATION_STATE_INCONSISTENT');
  });
  await t.test('the copied offline export still verifies with reduced coverage (X1 policy)', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    fs.rmSync(path.join(c.nsPath, '10.tsr'));
    const v = await verifyChain(c);
    assert.equal(v.exitCode, 0);
    assert.equal(v.stdout, 'VALID_UNANCHORED 0..13\nANCHOR_EVIDENCE_MISSING 10\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
});

test('006 AC-3 states-E1-E10', async (t) => {
  await t.test('E1: reconciled, nothing changed but the directory barrier', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    const before0 = await snapshot(c);
    const o = await open(c);
    assert.equal(o.writer!.startedFrom, 'E1');
    assert.deepEqual(o.fsd.calls, ['open .', 'fsync .', 'close .']);
    assert.equal(await snapshot(c), before0);
    await o.writer!.close();
  });
  await t.test('E2: durable-delete the resolved .tsq; reconciled', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E2_STATE);
    assert.deepEqual(names(c), ['10.anchor.json', '10.tsq', '10.tsr']);
    assert.equal(await pendingOf(c), null);
    const o = await open(c);
    assert.equal(o.writer!.startedFrom, 'E2');
    assert.deepEqual(names(c), ['10.anchor.json', '10.tsr']);
    await o.writer!.append(pausePayload(99));
    await o.writer!.close();
  });
  await t.test('E2 with a resolved checkpoint_failed', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E2_STATE, false);
    assert.deepEqual(names(c), ['10.tsq']);
    const o = await open(c);
    assert.equal(o.writer!.startedFrom, 'E2');
    assert.deepEqual(names(c), []);
    await o.writer!.close();
  });
  await t.test('E3: two requests and no pending anchor: fail closed, no change', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E2_STATE);
    fs.writeFileSync(path.join(c.nsPath, '5.tsq'), 'stray');
    const before0 = await snapshot(c);
    assert.equal((await open(c)).code, 'RECONCILIATION_STATE_INCONSISTENT');
    assert.equal(await snapshot(c), before0);
  });
  await t.test('E3: an unconfirmed request (no control at m+1)', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    fs.writeFileSync(path.join(c.nsPath, '12.tsq'), 'stray');
    assert.equal((await open(c)).code, 'RECONCILIATION_STATE_INCONSISTENT');
  });
  for (const withTsq of [false, true]) {
    await t.test(`E4 (defensive)${withTsq ? ' with its .tsq' : ''}: barrier, clear pending, delete the .tsq`, async () => {
      const c = newAnchoredChain();
      await stateE4(c, withTsq);
      const o = await open(c);
      assert.equal(o.writer!.startedFrom, 'E4');
      assert.equal(await pendingOf(c), null);
      assert.deepEqual(names(c), ['10.anchor.json', '10.tsr']);
      assert.deepEqual(o.fsd.calls.slice(0, 3), ['open 10.tsr', 'isRegularFile 10.tsr', 'fsync 10.tsr']);
      await o.writer!.close();
    });
  }
  await t.test('E5 (defensive): delete residue for k, clear pending', async () => {
    const c = newAnchoredChain();
    await stateE5(c);
    assert.deepEqual(names(c), ['10.tsq']);
    const o = await open(c);
    assert.equal(o.writer!.startedFrom, 'E5');
    assert.equal(await pendingOf(c), null);
    assert.deepEqual(names(c), []);
    await o.writer!.close();
  });
  await t.test('E6: pending k, h = k+1, an anchored control whose package is missing: fail closed', async () => {
    const c = newAnchoredChain();
    await stateE4(c, false);
    fs.rmSync(path.join(c.nsPath, '10.anchor.json'));
    const before0 = await snapshot(c);
    assert.equal((await open(c)).code, 'RECONCILIATION_STATE_INCONSISTENT');
    assert.equal(await snapshot(c), before0);
  });
  await t.test('E7: barrier, then control and pending clear in one transaction, then delete the .tsq', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E7_STATE);
    assert.equal(await pendingOf(c), '10');
    assert.equal(await rowCount(c.chainId), 11);
    let rowsAtBarrierEnd = -1;
    const o = await open(c, {
      before: async (op, calls) => {
        if (op === 'close' && rowsAtBarrierEnd === -1 && calls.at(-1) === 'close .') rowsAtBarrierEnd = await rowCount(c.chainId);
      },
    });
    assert.equal(o.writer!.startedFrom, 'E7');
    assert.equal(rowsAtBarrierEnd, 11, 'the barrier ran before the success commit');
    const control = await payloadAt(c, 11);
    assert.equal(control!['event_type'], 'checkpoint_anchored');
    assert.equal(await pendingOf(c), null);
    assert.deepEqual(names(c), ['10.anchor.json', '10.tsr']);
    await o.writer!.close();
    assert.match((await verifyChain(c)).stdout, /^VERIFIED_ANCHORED 0\.\.10\n/);
  });
  await t.test('E8: delete residue for k and repeat the TSA flow with a fresh nonce', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E8_STATE);
    assert.deepEqual(names(c), ['10.tsq', '10.tsr.tmp']);
    const oldTsq = fs.readFileSync(path.join(c.nsPath, '10.tsq'));
    const o = await open(c);
    assert.equal(o.writer!.startedFrom, 'E8');
    assert.equal(o.tsa.requests.length, 1);
    assert.ok(!Buffer.from(o.tsa.requests[0]!.der).equals(oldTsq), 'a fresh request (new nonce)');
    assert.equal((await payloadAt(c, 11))!['event_type'], 'checkpoint_anchored');
    assert.deepEqual(names(c), ['10.anchor.json', '10.tsr']);
    await o.writer!.close();
  });
  await t.test('E9: past the 60 s window: delete residue, checkpoint_failed anchor_window_expired', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E8_STATE);
    const o = await open(c, { clock: () => Date.now() + 61_000 });
    assert.equal(o.writer!.startedFrom, 'E9');
    assert.equal(o.tsa.requests.length, 0, 'no TSA call');
    assert.deepEqual(await payloadAt(c, 11), { event_type: 'checkpoint_failed', operation: 'tear.checkpoint', target_seq: 10, error_type: 'anchor_window_expired' });
    assert.deepEqual(names(c), []);
    await o.writer!.close();
  });
  await t.test('E10: pending k with h > k+1: fail closed, no change', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    await setPending(c, 10);
    const before0 = await snapshot(c);
    assert.equal((await open(c)).code, 'RECONCILIATION_STATE_INCONSISTENT');
    assert.equal(await snapshot(c), before0);
  });
  await t.test('E10: pending k, h = k, foreign residue', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E7_STATE);
    fs.writeFileSync(path.join(c.nsPath, '5.tsq'), 'stray');
    assert.equal((await open(c)).code, 'RECONCILIATION_STATE_INCONSISTENT');
  });
});

test('006 AC-4 recovered-package-barrier', async (t) => {
  for (const [label, failOn] of [
    ['the .tsr fsync', { op: 'fsync', nth: 1, code: 'EIO' }],
    ['the .anchor.json fsync', { op: 'fsync', nth: 2, code: 'EIO' }],
    ['the directory fsync', { op: 'fsync', nth: 3, code: 'EIO' }],
  ] as const) {
    await t.test(`E7: a failure at ${label} aborts without clearing pending or admitting traffic`, async () => {
      const c = newAnchoredChain();
      await crashDuringAnchor(c, E7_STATE);
      const o = await open(c, { failOn });
      assert.equal(o.code, 'NAMESPACE_MUTATION_FAILED');
      assert.equal(await pendingOf(c), '10');
      assert.equal(await rowCount(c.chainId), 11);
      await waitFor(() => o.exits.length === 1);
    });
    await t.test(`E4: a failure at ${label} aborts without clearing pending`, async () => {
      const c = newAnchoredChain();
      await stateE4(c, false);
      const o = await open(c, { failOn });
      assert.equal(o.code, 'NAMESPACE_MUTATION_FAILED');
      assert.equal(await pendingOf(c), '10');
    });
  }
  await t.test('the barrier refuses a symlink in place of a recovered file', async () => {
    const c = newAnchoredChain();
    await stateE4(c, false);
    const p = path.join(c.nsPath, '10.tsr');
    fs.renameSync(p, path.join(c.root, 'real.tsr'));
    fs.symlinkSync(path.join(c.root, 'real.tsr'), p);
    assert.equal((await open(c)).code, 'RECONCILIATION_STATE_INCONSISTENT');
    assert.equal(await pendingOf(c), '10');
  });
});

test('006 AC-5 inspection-with-classifier', async (t) => {
  const states: [string, (c: Chain) => Promise<void>, boolean][] = [
    ['E2', (c) => crashDuringAnchor(c, E2_STATE), true],
    ['E7', (c) => crashDuringAnchor(c, E7_STATE), true],
    ['E1 + recognized .tmp', async (c) => {
      await stateE1(c);
      fs.writeFileSync(path.join(c.nsPath, '20.tsr.tmp'), 'partial');
    }, true],
    ['E4', (c) => stateE4(c, true), true],
    ['E5', stateE5, true],
    ['E8', (c) => crashDuringAnchor(c, E8_STATE), true],
    ['E3', async (c) => {
      await crashDuringAnchor(c, E2_STATE);
      fs.writeFileSync(path.join(c.nsPath, '5.tsq'), 'stray');
    }, false],
    ['E6', async (c) => {
      await stateE4(c, false);
      fs.rmSync(path.join(c.nsPath, '10.anchor.json'));
    }, false],
    ['E10', async (c) => {
      await stateE1(c);
      await setPending(c, 10);
    }, false],
  ];
  for (const [label, make, recoverable] of states) {
    await t.test(`${label}: base, cut1 and cut1-2 → ${recoverable ? 'RECOVERY_REQUIRED' : 'RECONCILIATION_STATE_INCONSISTENT'}; cut1-3 and cut1-4 → inconsistent; no mutation`, async () => {
      const c = newAnchoredChain();
      await make(c);
      const before0 = await snapshot(c);
      for (const profile of ['base', 'cut1', 'cut1-2'] as const) {
        assert.equal(await codeOf(initializeChain(initOpts(c, profile))), recoverable ? 'OK' : 'RECONCILIATION_STATE_INCONSISTENT');
        if (recoverable) assert.equal(await initializeChain(initOpts(c, profile)), 'RECOVERY_REQUIRED');
      }
      for (const profile of ['cut1-3', 'cut1-4'] as const) {
        assert.equal(await codeOf(initializeChain(initOpts(c, profile))), 'RECONCILIATION_STATE_INCONSISTENT');
      }
      assert.equal(await snapshot(c), before0, 'no mutation, no TSA call');
    });
  }
  await t.test('E9: RECOVERY_REQUIRED when classified with a clock past the window', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E8_STATE);
    const late = () => (BigInt(Date.now()) + 61_000n) * 1_000_000n;
    assert.equal(await initializeChain({ ...initOpts(c), now: late }), 'RECOVERY_REQUIRED');
  });
  await t.test('after a successful recovery the repeated call returns ALREADY_INITIALIZED', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E7_STATE);
    assert.equal(await initializeChain(initOpts(c)), 'RECOVERY_REQUIRED');
    const o = await open(c);
    await o.writer!.close();
    assert.equal(await initializeChain(initOpts(c)), 'ALREADY_INITIALIZED');
  });
  await t.test('a valid different genesis wins over recoverable residue: CHAIN_INITIALIZATION_CONFLICT', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E7_STATE);
    assert.equal(await codeOf(initializeChain({ ...initOpts(c), pepperId: 'another' })), 'CHAIN_INITIALIZATION_CONFLICT');
  });
});

test('006 AC-6 startup-dir-barrier', async (t) => {
  await t.test('the chain directory is fsynced before traffic, from E1', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    const o = await open(c);
    assert.deepEqual(o.fsd.calls.slice(0, 3), ['open .', 'fsync .', 'close .']);
    await o.writer!.append(pausePayload(1));
    await o.writer!.close();
  });
  await t.test('an injected failure at that barrier aborts start-up', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    const o = await open(c, { failOn: { op: 'fsync', nth: 1, code: 'EIO' } });
    assert.equal(o.code, 'NAMESPACE_MUTATION_FAILED');
    assert.equal(o.writer, null);
  });
  await t.test('E1 barrier after a real crash between unlink(.tsq) and the directory fsync', async () => {
    const r = await crashChild('e1');
    assert.equal(r.signal, 'SIGKILL');
    assert.equal(await pendingOf(r.chain), null);
    const o = await open(r.chain);
    assert.equal(o.writer!.startedFrom, 'E1');
    assert.deepEqual(o.fsd.calls.slice(0, 2), ['open .', 'fsync .']);
    await o.writer!.append(pausePayload(1));
    await o.writer!.close();
    const fail = await open(r.chain, { failOn: { op: 'fsync', nth: 1, code: 'EIO' } });
    assert.equal(fail.code, 'NAMESPACE_MUTATION_FAILED');
  });
});

interface Crash {
  chain: Chain;
  signal: NodeJS.Signals | null;
  stdout: string;
}

async function crashChild(mode: 'e7' | 'e1' | 'agent'): Promise<Crash> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-crash-'));
  const chainId = randomUUID();
  const nsPath = provisionNamespace(root, chainId);
  const pkiDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-crash-pki-'));
  const r = spawnSync(process.execPath, ['dist/test/helpers/crash-child.js', root, chainId, pkiDir, mode], { encoding: 'utf8', timeout: 60_000 });
  const pki = loadPki(pkiDir);
  fs.rmSync(pkiDir, { recursive: true, force: true });
  const [g] = await admin<{ ts: string }>('SELECT ts FROM tear_events WHERE chain_id = $1 AND seq = 0', [chainId]);
  assert.ok(g !== undefined, r.stderr);
  return { chain: { root, chainId, nsPath, pki, genesisTs: g!.ts }, signal: r.signal, stdout: r.stdout };
}

test('006 AC-7 e7-crash', async (t) => {
  await t.test('killed after the anchor.json rename: recovery runs both barriers before the success commit', async () => {
    const r = await crashChild('e7');
    assert.equal(r.signal, 'SIGKILL');
    assert.equal(await pendingOf(r.chain), '10');
    assert.deepEqual(names(r.chain), ['10.anchor.json', '10.tsq', '10.tsr']);
    let rowsAtDirFsync = -1;
    const o = await open(r.chain, {
      before: async (op, calls) => {
        if (op === 'fsync' && rowsAtDirFsync === -1 && calls.at(-1) === 'fsync .') rowsAtDirFsync = await rowCount(r.chain.chainId);
      },
    });
    assert.equal(o.writer!.startedFrom, 'E7');
    assert.equal(rowsAtDirFsync, 11, 'the directory barrier ran before the success commit');
    const calls = o.fsd.calls;
    const commitIdx = calls.indexOf('unlink 10.tsq');
    assert.deepEqual(calls.slice(0, commitIdx), [
      'open 10.tsr', 'isRegularFile 10.tsr', 'fsync 10.tsr', 'close 10.tsr',
      'open 10.anchor.json', 'isRegularFile 10.anchor.json', 'fsync 10.anchor.json', 'close 10.anchor.json',
      'open .', 'fsync .', 'close .',
    ]);
    assert.equal((await payloadAt(r.chain, 11))!['event_type'], 'checkpoint_anchored');
    await o.writer!.append(pausePayload(1));
    await o.writer!.close();
  });
  for (const [label, failOn, pendingAfter] of [
    ['the .tsr barrier', { op: 'fsync', nth: 1, code: 'EIO' }, '10'],
    ['the .anchor.json barrier', { op: 'fsync', nth: 2, code: 'EIO' }, '10'],
    ['the directory barrier', { op: 'fsync', nth: 3, code: 'EIO' }, '10'],
    ['the request deletion', { op: 'unlink', nth: 1, code: 'EIO' }, null],
  ] as const) {
    await t.test(`a failure at ${label}: no next append, no success`, async () => {
      const r = await crashChild('e7');
      const o = await open(r.chain, { failOn });
      assert.equal(o.code, 'NAMESPACE_MUTATION_FAILED');
      assert.equal(o.writer, null, 'no writer, so no next append');
      assert.equal(await pendingOf(r.chain), pendingAfter);
      await waitFor(() => o.exits.length === 1);
    });
  }
});

test('006 AC-8 sealed-chain', async (t) => {
  await t.test('a sealed chain refuses application events and still accepts closeChain', async () => {
    const c = newAnchoredChain();
    await create(c);
    const o = await open(c);
    assert.equal((await o.writer!.closeChain()).result, 'CLOSED_NO_ANCHOR');
    assert.equal(await codeOf(o.writer!.append(pausePayload(1))), 'CHAIN_SEALED');
    assert.equal((await o.writer!.closeChain()).result, 'CLOSED_NO_ANCHOR');
    await o.writer!.close();
    const again = await open(c);
    assert.equal(again.writer!.sealedChain, true);
    assert.equal(await codeOf(again.writer!.append(pausePayload(1))), 'CHAIN_SEALED');
    assert.equal((await again.writer!.closeChain()).result, 'CLOSED_NO_ANCHOR');
    await again.writer!.close();
  });
});

test('006 AC-9 close-branches', async (t) => {
  await t.test('B0: genesis only → CLOSED_NO_ANCHOR, no TSA call', async () => {
    const c = newAnchoredChain();
    await create(c);
    const o = await open(c);
    assert.deepEqual(await o.writer!.closeChain(), { result: 'CLOSED_NO_ANCHOR', branch: 'B0' });
    assert.equal(o.tsa.requests.length, 0);
    await o.writer!.close();
    assert.equal((await verifyChain(c)).stdout, 'VALID_UNANCHORED 0..0\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
  await t.test('B2: unanchored tail → anchors the head (mode close) → ANCHORED_FIRST_ATTEMPT', async () => {
    const c = newAnchoredChain();
    await create(c);
    const o = await open(c);
    await appendN(o.writer!, 5);
    const r = await o.writer!.closeChain();
    assert.equal(r.result, 'ANCHORED_FIRST_ATTEMPT');
    assert.equal(r.branch, 'B2');
    assert.equal((await payloadAt(c, 6))!['anchored_seq'], 5);
    await o.writer!.close();
    assert.match((await verifyChain(c)).stdout, /^VERIFIED_ANCHORED 0\.\.5\n/);
  });
  await t.test('B2 failure → checkpoint_failed → UNANCHORED_FAILURE', async () => {
    const c = newAnchoredChain();
    await create(c);
    const o = await open(c);
    await appendN(o.writer!, 5);
    o.tsa.behaviors = [{ kind: 'transport', result: { kind: 'failure', reason: 'timeout', detail: 't' } }];
    assert.equal((await o.writer!.closeChain()).result, 'UNANCHORED_FAILURE');
    assert.equal((await payloadAt(c, 6))!['event_type'], 'checkpoint_failed');
    await o.writer!.close();
  });
  await t.test('B1: already anchored up to the last application event → ANCHORED_FIRST_ATTEMPT, no TSA call', async () => {
    const c = newAnchoredChain();
    await create(c);
    const o = await open(c);
    await appendN(o.writer!, 10);
    const calls = o.tsa.requests.length;
    assert.deepEqual(await o.writer!.closeChain(), { result: 'ANCHORED_FIRST_ATTEMPT', branch: 'B1' });
    assert.equal(o.tsa.requests.length, calls);
    await o.writer!.close();
  });
  await t.test('B3: head is checkpoint_failed; without retry UNANCHORED_FAILURE, with retry ANCHORED_AFTER_PREVIOUS_FAILURE; then B1 keeps it', async () => {
    const c = newAnchoredChain();
    await create(c);
    const o = await open(c);
    o.tsa.behaviors = [{ kind: 'transport', result: { kind: 'failure', reason: 'timeout', detail: 't' } }];
    await appendN(o.writer!, 10);
    const calls = o.tsa.requests.length;
    assert.deepEqual(await o.writer!.closeChain(), { result: 'UNANCHORED_FAILURE', branch: 'B3' });
    assert.equal(o.tsa.requests.length, calls, 'no TSA call without retry');
    o.tsa.behaviors = [{ kind: 'ok' }];
    const r = await o.writer!.closeChain({ retry: true });
    assert.equal(r.result, 'ANCHORED_AFTER_PREVIOUS_FAILURE');
    assert.equal((await payloadAt(c, 12))!['anchored_seq'], 11, 'B3 anchors h, the checkpoint_failed row');
    assert.deepEqual(await o.writer!.closeChain(), { result: 'ANCHORED_AFTER_PREVIOUS_FAILURE', branch: 'B1' });
    await o.writer!.close();
    assert.match((await verifyChain(c)).stdout, /^VERIFIED_ANCHORED 0\.\.11\n/);
  });
  await t.test('closeChain waits for a pending anchor', async () => {
    const c = newAnchoredChain();
    await create(c);
    const o = await open(c);
    let release!: () => void;
    const gate = new Promise<void>((settled) => (release = settled));
    o.tsa.behaviors = [{ kind: 'custom', run: async (req) => { await gate; return testTsa('inner', c.pki).request(req.der); } }];
    await appendN(o.writer!, 9);
    const tenth = o.writer!.append(pausePayload(10));
    await waitFor(() => o.tsa.requests.length === 1);
    let closed = false;
    const close = o.writer!.closeChain().then((settled) => {
      closed = true;
      return settled;
    });
    await new Promise((settled) => setTimeout(settled, 200));
    assert.equal(closed, false);
    const [s] = await admin<{ c: boolean }>('SELECT chain_closed AS c FROM tear_chain_state WHERE chain_id = $1', [c.chainId]);
    assert.equal(s!.c, false, 'not sealed while the anchor is pending');
    release();
    await tenth;
    assert.equal((await close).result, 'ANCHORED_FIRST_ATTEMPT');
    await o.writer!.close();
  });
  await t.test('a repeated close after restart on a sealed chain is accepted', async () => {
    const c = newAnchoredChain();
    await create(c);
    const o = await open(c);
    await appendN(o.writer!, 3);
    await o.writer!.closeChain();
    await o.writer!.close();
    const again = await open(c);
    assert.deepEqual(await again.writer!.closeChain(), { result: 'ANCHORED_FIRST_ATTEMPT', branch: 'B1' });
    await again.writer!.close();
  });
});

test('006 AC-10 close-time-predicate', async (t) => {
  for (const [label, offsetMs, expected] of [
    ['genTime 30 s after ts[h] with the host clock 2 h ahead → accepted', 30_000, 'ANCHORED_FIRST_ATTEMPT'],
    ['genTime 120 s after ts[h] → UNANCHORED_FAILURE', 120_000, 'UNANCHORED_FAILURE'],
  ] as const) {
    await t.test(label, async () => {
      const c = newAnchoredChain();
      await create(c);
      let skew = 0;
      const o = await open(c, { clock: () => Date.now() + skew });
      await appendN(o.writer!, 5);
      skew = 2 * 3600_000; // The host clock at close time plays no part.
      o.tsa.behaviors = [{ kind: 'ok', genTimeOffsetMs: offsetMs }];
      assert.equal((await o.writer!.closeChain()).result, expected);
      await o.writer!.close();
    });
  }
});

test('006 AC-11 evidence-package', async (t) => {
  await t.test('copies only complete pairs, then exports; a package published after the copy is ANCHOR_EVIDENCE_MISSING', async () => {
    const c = newAnchoredChain();
    await create(c);
    const o = await open(c);
    await appendN(o.writer!, 15);
    fs.writeFileSync(path.join(c.nsPath, '40.tsq'), 'x');
    fs.writeFileSync(path.join(c.nsPath, '40.tsr.tmp'), 'x');
    fs.writeFileSync(path.join(c.nsPath, '50.tsr'), 'x');
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tear-ev-')), 'evidence');
    const ev = await buildEvidencePackage({
      checkpointsRoot: c.root,
      chainId: c.chainId,
      pg: pgConfig,
      bundleBytes: c.pki.bundle,
      outDir: out,
      afterCopyForTests: async () => {
        for (let i = 0; i < 6; i++) await o.writer!.append(pausePayload(100 + i)); // Anchors 20 meanwhile.
      },
    });
    assert.deepEqual(ev.copied, [10]);
    assert.deepEqual(fs.readdirSync(ev.checkpointsPath).sort(), ['10.anchor.json', '10.tsr']);
    const bundlePath = path.join(out, 'bundle.pem');
    fs.writeFileSync(bundlePath, c.pki.bundle);
    const v = verifyOffline({ logPath: ev.logPath, checkpointsPath: ev.checkpointsPath, bundlePath });
    assert.equal(v.exitCode, 0);
    assert.match(v.stdout, /^VERIFIED_ANCHORED 0\.\.10\nVALID_UNANCHORED 11\.\.\d+\nANCHOR_EVIDENCE_MISSING 20\n/);
    await o.writer!.close();
  });
});

test('006 AC-12 cut-profiles', async (t) => {
  await t.test('Cut 2: B3 never starts (retry is ignored, no TSA call)', async () => {
    const c = newAnchoredChain();
    await create(c, 'cut1-2');
    const o = await open(c, { profile: 'cut1-2' });
    o.tsa.behaviors = [{ kind: 'transport', result: { kind: 'failure', reason: 'timeout', detail: 't' } }];
    await appendN(o.writer!, 10);
    const calls = o.tsa.requests.length;
    o.tsa.behaviors = [{ kind: 'ok' }];
    assert.deepEqual(await o.writer!.closeChain({ retry: true }), { result: 'UNANCHORED_FAILURE', branch: 'B3' });
    assert.equal(o.tsa.requests.length, calls);
    await o.writer!.close();
  });
  for (const [label, make] of [
    ['a recognized .tmp', async (c: Chain) => {
      await stateE1(c);
      fs.writeFileSync(path.join(c.nsPath, '20.tsr.tmp'), 'partial');
    }],
    ['an E2 request', (c: Chain) => crashDuringAnchor(c, E2_STATE)],
    ['an E7 pending package', (c: Chain) => crashDuringAnchor(c, E7_STATE)],
  ] as const) {
    await t.test(`Cut 3: ${label} → inconsistent; no cleanup, no repair`, async () => {
      const c = newAnchoredChain();
      await make(c);
      const before0 = await snapshot(c);
      assert.equal((await open(c, { profile: 'cut1-3' })).code, 'RECONCILIATION_STATE_INCONSISTENT');
      assert.equal(await snapshot(c), before0);
    });
  }
  await t.test('Cut 3: a clean E1 starts, with the directory barrier', async () => {
    const c = newAnchoredChain();
    await stateE1(c);
    const o = await open(c, { profile: 'cut1-3' });
    assert.deepEqual(o.fsd.calls, ['open .', 'fsync .', 'close .']);
    await o.writer!.close();
  });
});

test('006 AC-13 guard-stopped-publish', async (t) => {
  await t.test('a .tmp left by a publish the guard stopped is classified under §5.6 (E8 after the .tmp deletion)', async () => {
    const c = newAnchoredChain();
    await create(c);
    let o!: Opened;
    o = await open(c, {
      before: (op, calls) => {
        if (op === 'write' && calls.at(-1) === 'write 10.tsq.tmp') o.writer!.connForTests.invalidate();
      },
    });
    await appendN(o.writer!, 9);
    assert.equal(await codeOf(o.writer!.append(pausePayload(10))), 'WRITER_INVALIDATED');
    await waitFor(() => o.exits.length === 1);
    assert.deepEqual(names(c), ['10.tsq.tmp']);
    assert.equal(await initializeChain(initOpts(c)), 'RECOVERY_REQUIRED');
    const again = await open(c);
    assert.equal(again.writer!.startedFrom, 'E8');
    assert.equal((await payloadAt(c, 11))!['event_type'], 'checkpoint_anchored');
    await again.writer!.close();
  });
});

test('006 single-session handoff during recovery', async (t) => {
  await t.test('every load and mutation of an E7 recovery runs on the lock-owning writerConn', async () => {
    const c = newAnchoredChain();
    await crashDuringAnchor(c, E7_STATE);
    const o = await open(c);
    assert.ok(o.writer!.observedPids.length >= 1);
    assert.ok(o.writer!.observedPids.every((p) => p === o.writer!.backendPid));
    const locks = await admin<{ n: string }>("SELECT count(*)::text AS n FROM pg_locks WHERE locktype = 'advisory' AND granted AND pid = $1", [o.writer!.backendPid]);
    assert.equal(locks[0]!.n, '1', 'the session that recovered holds the advisory lock');
    await o.writer!.close();
  });
});

test('006 two concurrent chains on one host', async (t) => {
  await t.test('two writers anchor and close independently; both exports verify', async () => {
    const a = newAnchoredChain();
    const b = newAnchoredChain();
    await create(a);
    await create(b);
    const [oa, ob] = await Promise.all([open(a), open(b)]);
    await Promise.all([appendN(oa.writer!, 23), appendN(ob.writer!, 17)]);
    await Promise.all([oa.writer!.closeChain(), ob.writer!.closeChain()]);
    await Promise.all([oa.writer!.close(), ob.writer!.close()]);
    assert.match((await verifyChain(a)).stdout, /^VERIFIED_ANCHORED 0\.\.\d+\n/);
    assert.match((await verifyChain(b)).stdout, /^VERIFIED_ANCHORED 0\.\.\d+\n/);
    assert.notEqual(oa.tsa.requests[0]!.der.toString(), ob.tsa.requests[0]!.der.toString());
  });
});

test('006 end-to-end: scripted agent → crash mid-anchor → recovery → continuation → close → export → verify', async (t) => {
  await t.test('the chain verifies after recovery and close', async () => {
    const r = await crashChild('agent');
    assert.equal(r.signal, 'SIGKILL');
    assert.match(r.stdout, /dying after: rename 10\.tsr\.tmp -> 10\.tsr/);
    assert.equal(await pendingOf(r.chain), '10');
    assert.equal(await initializeChain({ ...initOpts(r.chain), pepperId: 'crash-pepper' }), 'RECOVERY_REQUIRED');
    const o = await open(r.chain);
    assert.equal(o.writer!.startedFrom, 'E8');
    for (let i = 0; i < 12; i++) await o.writer!.append(pausePayload(200 + i));
    const closed = await o.writer!.closeChain();
    assert.equal(closed.result, 'ANCHORED_FIRST_ATTEMPT');
    await o.writer!.close();
    assert.equal(await initializeChain({ ...initOpts(r.chain), pepperId: 'crash-pepper' }), 'ALREADY_INITIALIZED');
    const v = await verifyChain(r.chain);
    assert.equal(v.exitCode, 0, v.stdout);
    // The close anchors h; its control at h+1 is the only unanchored row (§5.8, §6 Step 3).
    const h = (await rowCount(r.chain.chainId)) - 2;
    assert.match(v.stdout, new RegExp(`^VERIFIED_ANCHORED 0\\.\\.${String(h)}\nVALID_UNANCHORED ${String(h + 1)}\\.\\.${String(h + 1)}\n`));
  });
});

