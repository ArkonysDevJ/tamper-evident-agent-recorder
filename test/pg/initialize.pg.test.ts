// SPDX-License-Identifier: AGPL-3.0-or-later
// Requires local PostgreSQL (npm run test:pg).
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { before, test } from 'node:test';
import { initializeChain } from '../../src/chain/initialize.js';
import { ChainWriter } from '../../src/chain/writer.js';
import { canonicalize } from '../../src/json/jcs.js';
import { pausePayload } from '../helpers/chain-builder.js';
import {
  admin,
  cleanE1ForTests,
  codeOf,
  ensureSchema,
  fixedClassifier,
  initOptions,
  newChain,
  snapshot,
  writerOptions,
} from '../helpers/pg.js';

before(ensureSchema);

test('001 AC-17 initialize-new', async (t) => {
  const c = newChain();
  assert.equal(await initializeChain(initOptions(c)), 'INITIALIZED');
  await t.test('genesis row matches the requested block and state is clean', async () => {
    const [row] = await admin<{ block_json: string; seq: string }>(
      'SELECT block_json, seq::text AS seq FROM tear_events WHERE chain_id = $1',
      [c.chainId],
    );
    const block = JSON.parse(row!.block_json) as Record<string, unknown>;
    assert.equal(row!.seq, '0');
    assert.equal(block['ts'], c.genesisTs);
    assert.equal(block['prev_hash'], '0'.repeat(64));
    assert.deepEqual(block['payload'], {
      chain_version: '1.0.4',
      event_type: 'chain_genesis',
      operation: 'tear.genesis',
      pepper_id: 'test-pepper',
      tsa_ca_bundle_sha256: '10335e1e5d816b98665e5f4cb21ed92dd0637d2957658e0c34d55c365240ccfd',
    });
    const [state] = await admin('SELECT * FROM tear_chain_state WHERE chain_id = $1', [c.chainId]);
    assert.deepEqual(
      [state!['chain_closed'], state!['pending_anchor_seq'], state!['pending_entry_hash'], state!['pending_ts'], state!['pending_mode']],
      [false, null, null, null, null],
    );
  });
  await t.test('the namespace only holds the lock file (no TSA request)', () => {
    assert.deepEqual(fs.readdirSync(c.nsPath), ['.writer.lock']);
  });
  await t.test('invalid arguments fail before any SQL work', async () => {
    const d = newChain();
    assert.equal(await codeOf(initializeChain(initOptions(d, { genesisTs: '2026-11-13T12:00:00Z' }))), 'INITIALIZATION_ARGUMENT_INVALID');
    assert.equal(await codeOf(initializeChain(initOptions(d, { pepperId: '' }))), 'INITIALIZATION_ARGUMENT_INVALID');
    assert.equal(await codeOf(initializeChain(initOptions(d, { chainId: 'not-a-uuid' }))), 'INITIALIZATION_ARGUMENT_INVALID');
    assert.equal(await codeOf(initializeChain(initOptions(d, { bundleBytes: new Uint8Array() }))), 'INITIALIZATION_ARGUMENT_INVALID');
    assert.equal((await admin('SELECT 1 FROM tear_chain_state WHERE chain_id = $1', [d.chainId])).length, 0);
  });
});

test('001 AC-18 initialize-existing', async (t) => {
  await t.test('exact retry on clean E1 returns ALREADY_INITIALIZED without changes', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    const before = await snapshot(c);
    assert.equal(await initializeChain(initOptions(c, { classifier: cleanE1ForTests })), 'ALREADY_INITIALIZED');
    assert.equal(await snapshot(c), before);
  });
  await t.test('a sealed clean chain also returns ALREADY_INITIALIZED and stays sealed', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    await admin('UPDATE tear_chain_state SET chain_closed = true WHERE chain_id = $1', [c.chainId]);
    const before = await snapshot(c);
    assert.equal(await initializeChain(initOptions(c, { classifier: cleanE1ForTests })), 'ALREADY_INITIALIZED');
    assert.equal(await snapshot(c), before);
  });
  await t.test('a valid different genesis returns CHAIN_INITIALIZATION_CONFLICT, even with a later corruption', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    const w = await ChainWriter.open(writerOptions(c));
    await w.append(pausePayload(1));
    await w.close();
    await admin(`UPDATE tear_events SET ts = 'corrupt' WHERE chain_id = $1 AND seq = 1`, [c.chainId]);
    const before = await snapshot(c);
    assert.equal(await codeOf(initializeChain(initOptions(c, { pepperId: 'other-pepper' }))), 'CHAIN_INITIALIZATION_CONFLICT');
    assert.equal(await snapshot(c), before);
  });
  await t.test('an invalid or mirror-corrupt genesis is inconsistent, not a conflict', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    await admin(`UPDATE tear_events SET payload = payload || '{"pepper_id":"x"}' WHERE chain_id = $1 AND seq = 0`, [c.chainId]);
    const before = await snapshot(c);
    assert.equal(await codeOf(initializeChain(initOptions(c, { pepperId: 'other-pepper' }))), 'RECONCILIATION_STATE_INCONSISTENT');
    assert.equal(await codeOf(initializeChain(initOptions(c))), 'RECONCILIATION_STATE_INCONSISTENT');
    assert.equal(await snapshot(c), before);
  });
  await t.test('identical genesis with a later invalid row is inconsistent', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    const w = await ChainWriter.open(writerOptions(c));
    await w.append(pausePayload(1));
    await w.close();
    await admin(`UPDATE tear_events SET ts = 'corrupt' WHERE chain_id = $1 AND seq = 1`, [c.chainId]);
    assert.equal(await codeOf(initializeChain(initOptions(c, { classifier: cleanE1ForTests }))), 'RECONCILIATION_STATE_INCONSISTENT');
  });
  await t.test('each partial state is inconsistent and left unchanged', async () => {
    const onlyEvents = newChain();
    await initializeChain(initOptions(onlyEvents));
    await admin('DELETE FROM tear_chain_state WHERE chain_id = $1', [onlyEvents.chainId]);
    let before = await snapshot(onlyEvents);
    assert.equal(await codeOf(initializeChain(initOptions(onlyEvents))), 'RECONCILIATION_STATE_INCONSISTENT');
    assert.equal(await snapshot(onlyEvents), before);

    const onlyState = newChain();
    await initializeChain(initOptions(onlyState));
    await admin('DELETE FROM tear_events WHERE chain_id = $1', [onlyState.chainId]);
    before = await snapshot(onlyState);
    assert.equal(await codeOf(initializeChain(initOptions(onlyState))), 'RECONCILIATION_STATE_INCONSISTENT');
    assert.equal(await snapshot(onlyState), before);

    const noGenesis = newChain();
    await initializeChain(initOptions(noGenesis));
    const w = await ChainWriter.open(writerOptions(noGenesis));
    await w.append(pausePayload(1));
    await w.close();
    await admin('DELETE FROM tear_events WHERE chain_id = $1 AND seq = 0', [noGenesis.chainId]);
    assert.equal(await codeOf(initializeChain(initOptions(noGenesis))), 'RECONCILIATION_STATE_INCONSISTENT');

    const dirty = newChain();
    fs.writeFileSync(path.join(dirty.nsPath, '3.tsq'), 'x');
    before = await snapshot(dirty);
    assert.equal(await codeOf(initializeChain(initOptions(dirty))), 'RECONCILIATION_STATE_INCONSISTENT');
    assert.equal(await snapshot(dirty), before);
  });
});

test('001 AC-19 inspection-mapping', async (t) => {
  async function run(profile: 'base' | 'cut1' | 'cut1-2' | 'cut1-3' | 'cut1-4', state: 'E1' | 'E2' | 'E3' | 'E6' | 'E7' | 'E10', tmp: boolean): Promise<{ code: string; entries: string[] }> {
    const c = newChain();
    await initializeChain(initOptions(c));
    if (tmp) fs.writeFileSync(path.join(c.nsPath, '10.tsr.tmp'), 'partial');
    const classifier = fixedClassifier(state);
    const before = await snapshot(c);
    const r = initializeChain(initOptions(c, { profile, classifier }));
    const code = await r.then((v) => v, (e: unknown) => (e as { code?: string }).code ?? 'other');
    assert.equal(await snapshot(c), before, 'inspection must not mutate');
    return { code: String(code), entries: classifier.lastEntries };
  }
  await t.test('without a classifier implementation the result is explicit', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    assert.equal(await codeOf(initializeChain(initOptions(c))), 'RECOVERY_CLASSIFIER_NOT_IMPLEMENTED');
  });
  for (const profile of ['base', 'cut1', 'cut1-2'] as const) {
    await t.test(`${profile}: E1 clean → ALREADY_INITIALIZED; E1 + .tmp, E2, E7 → RECOVERY_REQUIRED; E3, E6, E10 → inconsistent`, async () => {
      assert.equal((await run(profile, 'E1', false)).code, 'ALREADY_INITIALIZED');
      const withTmp = await run(profile, 'E1', true);
      assert.equal(withTmp.code, 'RECOVERY_REQUIRED');
      assert.deepEqual(withTmp.entries, [], 'recognized .tmp files are excluded from the view');
      assert.equal((await run(profile, 'E2', false)).code, 'RECOVERY_REQUIRED');
      assert.equal((await run(profile, 'E7', false)).code, 'RECOVERY_REQUIRED');
      for (const s of ['E3', 'E6', 'E10'] as const) {
        assert.equal((await run(profile, s, false)).code, 'RECONCILIATION_STATE_INCONSISTENT');
      }
    });
  }
  for (const profile of ['cut1-3', 'cut1-4'] as const) {
    await t.test(`${profile}: never RECOVERY_REQUIRED`, async () => {
      assert.equal((await run(profile, 'E1', false)).code, 'ALREADY_INITIALIZED');
      assert.equal((await run(profile, 'E1', true)).code, 'RECONCILIATION_STATE_INCONSISTENT');
      assert.equal((await run(profile, 'E2', false)).code, 'RECONCILIATION_STATE_INCONSISTENT');
      assert.equal((await run(profile, 'E7', false)).code, 'RECONCILIATION_STATE_INCONSISTENT');
    });
  }
});

test('001 AC-20 startup-without-chain', async (t) => {
  await ensureSchema();
  await t.test('neither events nor state → CHAIN_NOT_INITIALIZED', async () => {
    const c = newChain();
    assert.equal(await codeOf(ChainWriter.open(writerOptions(c))), 'CHAIN_NOT_INITIALIZED');
  });
  await t.test('only one of them → RECONCILIATION_STATE_INCONSISTENT', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    await admin('DELETE FROM tear_chain_state WHERE chain_id = $1', [c.chainId]);
    assert.equal(await codeOf(ChainWriter.open(writerOptions(c))), 'RECONCILIATION_STATE_INCONSISTENT');
  });
  await t.test('unknown initialization commit outcome returns no success; an exact retry resolves it', async () => {
    const c = newChain();
    const killOwnBackend = async (pid: number): Promise<void> => {
      await admin('SELECT pg_terminate_backend($1)', [pid]);
      await new Promise((r) => setTimeout(r, 300));
    };
    assert.equal(await codeOf(initializeChain(initOptions(c, { beforeCreateCommitForTests: killOwnBackend }))), 'COMMIT_OUTCOME_UNKNOWN');
    const retry = await initializeChain(initOptions(c, { classifier: cleanE1ForTests }));
    assert.ok(retry === 'INITIALIZED' || retry === 'ALREADY_INITIALIZED', retry);
    const [row] = await admin<{ block_json: string }>('SELECT block_json FROM tear_events WHERE chain_id = $1 AND seq = 0', [c.chainId]);
    assert.equal(JSON.parse(row!.block_json).ts, c.genesisTs);
    assert.equal(canonicalize(JSON.parse(row!.block_json)), row!.block_json);
  });
});
