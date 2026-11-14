// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { checkSqlRow } from '../../src/chain/sql-rows.js';
import type { SqlEventRow } from '../../src/chain/sql-rows.js';
import { runStep1 } from '../../src/chain/step1.js';
import type { RowInput, Step1Context } from '../../src/chain/step1.js';
import { sha256Hex } from '../../src/crypto/digests.js';
import { canonicalize } from '../../src/json/jcs.js';
import type { JsonObject } from '../../src/json/strict-json.js';
import { TEST_BUNDLE_SHA256, buildChain, chainIdOf, envelope, obj, pausePayload, rehash } from '../helpers/chain-builder.js';
import type { BuiltRow } from '../helpers/chain-builder.js';

const H = 'c'.repeat(64);

function inputs(rows: BuiltRow[]): RowInput[] {
  return rows.map((r) => ({ kind: 'json', value: envelope(r.block, r.entry_hash) }));
}

function ctxFor(rows: BuiltRow[]): Step1Context {
  return { bundleSha256: TEST_BUNDLE_SHA256, namespaceChainId: chainIdOf(rows) };
}

function first(rows: BuiltRow[], ctx = ctxFor(rows)): string {
  const r = runStep1(inputs(rows), ctx);
  return r.ok ? 'OK' : `${r.failure.code} ${r.failure.param}`;
}

function pauses(n: number): JsonObject[] {
  return Array.from({ length: n }, (_, i) => pausePayload(i + 1));
}

function call(callId: string, task: string): JsonObject {
  return obj({ event_type: 'tool_call', operation: 'execute_tool', tool_name: 't', call_id: callId, task_id: task, args_hmac: H });
}

function result(callId: string, task: string): JsonObject {
  return obj({ event_type: 'tool_result', operation: 'execute_tool', call_id: callId, task_id: task, error_type: null, result_digest: H, summary: 's' });
}

test('001 AC-27 step1-core', async (t) => {
  await t.test('a valid chain passes and reports seq_final and unmatched calls', () => {
    const rows = buildChain([...pauses(3), call('c1', 'k'), call('c2', 'k'), result('c1', 'k')]);
    const r = runStep1(inputs(rows), ctxFor(rows));
    assert.ok(r.ok);
    assert.equal(r.seqFinal, 6);
    assert.deepEqual(r.unmatchedCalls, [5]);
  });
  await t.test('1.1 malformed row: GENESIS_INVALID 0 at row 0, JCS_SCHEMA_INVALID <expected_seq> later', () => {
    const rows = buildChain(pauses(3));
    const ins = inputs(rows);
    assert.equal(fmt(runStep1([{ kind: 'malformed' }, ...ins.slice(1)], ctxFor(rows))), 'GENESIS_INVALID 0');
    ins[2] = { kind: 'malformed' };
    assert.equal(fmt(runStep1(ins, ctxFor(rows))), 'JCS_SCHEMA_INVALID 2');
  });
  await t.test('1.1 schema failure uses O_i.seq when the schema supplies a valid seq', () => {
    const rows = buildChain(pauses(3));
    rows[2]!.block['seq'] = 7;
    rows[2]!.block['payload'] = obj({ ...pausePayload(2), extra: 'x' });
    assert.equal(first(rows), 'JCS_SCHEMA_INVALID 7');
    rows[2]!.block['seq'] = 'x';
    assert.equal(first(rows), 'JCS_SCHEMA_INVALID 2');
  });
  await t.test('1.2 genesis rules', () => {
    const a = buildChain([]);
    a[0]!.block['prev_hash'] = H;
    rehash(a);
    assert.equal(first(a), 'GENESIS_INVALID 0');
    const b = buildChain(pauses(1));
    assert.equal(first([b[1]!]), 'GENESIS_INVALID 0');
    const c = buildChain(pauses(2));
    c[2]!.block['payload'] = c[0]!.block['payload']!;
    rehash(c, 2);
    assert.equal(first(c), 'JCS_SCHEMA_INVALID 2');
  });
  await t.test('1.3 bundle digest', () => {
    const rows = buildChain([]);
    assert.equal(first(rows, { bundleSha256: H, namespaceChainId: chainIdOf(rows) }), 'TSA_BUNDLE_MISMATCH 0');
  });
  await t.test('1.4 time format', () => {
    const rows = buildChain(pauses(2));
    rows[2]!.block['ts'] = '2026-02-30T00:00:00.000Z';
    rehash(rows, 2);
    assert.equal(first(rows), 'TIME_FORMAT_INVALID 2');
  });
  await t.test('1.5 identity against genesis and namespace', () => {
    const rows = buildChain(pauses(2));
    assert.equal(first(rows, { bundleSha256: TEST_BUNDLE_SHA256, namespaceChainId: randomUUID() }), 'CHAIN_ID_MISMATCH 0');
    rows[2]!.block['chain_id'] = randomUUID();
    rehash(rows, 2);
    assert.equal(first(rows), 'CHAIN_ID_MISMATCH 2');
  });
  await t.test('1.6 sequence', () => {
    const dup = buildChain(pauses(3));
    dup.splice(3, 0, structuredClone(dup[2]!));
    assert.equal(first(dup), 'SEQ_DUPLICATE 2');
    const gap = buildChain(pauses(3));
    gap.splice(2, 1);
    assert.equal(first(gap), 'SEQ_GAP 2');
  });
  await t.test('1.7 monotonicity; ties pass', () => {
    const tie = buildChain(pauses(2));
    tie[2]!.block['ts'] = tie[1]!.block['ts']!;
    rehash(tie, 2);
    assert.equal(first(tie), 'OK');
    const back = buildChain(pauses(2));
    back[2]!.block['ts'] = back[0]!.block['ts']!;
    back[1]!.block['ts'] = '2026-11-13T12:00:05.000Z';
    rehash(back, 1);
    assert.equal(first(back), 'TS_REGRESSION 2');
  });
  await t.test('1.8 hash', () => {
    const rows = buildChain(pauses(3));
    (rows[2]!.block['payload'] as JsonObject)['reason'] = 'tampered';
    assert.equal(first(rows), 'HASH_MISMATCH 2');
  });
  await t.test('1.9 link', () => {
    const rows = buildChain(pauses(3));
    rows[2]!.block['prev_hash'] = H;
    rehash([rows[2]!]); // valid own hash, broken link
    assert.equal(first(rows), 'PREV_HASH_MISMATCH 2');
  });
  await t.test('1.10 call pairing', () => {
    assert.equal(first(buildChain([result('c1', 'k')])), 'CALL_CORRELATION_INVALID 1');
    assert.equal(first(buildChain([call('c1', 'k'), result('c1', 'k'), call('c1', 'k')])), 'CALL_CORRELATION_INVALID 3');
    assert.equal(first(buildChain([call('c1', 'k'), result('c1', 'other')])), 'CALL_CORRELATION_INVALID 2');
    assert.equal(first(buildChain([call('c1', 'k'), result('c1', 'k'), result('c1', 'k')])), 'CALL_CORRELATION_INVALID 3');
  });
  await t.test('an earlier rule on the same row prevails', () => {
    const rows = buildChain([call('c1', 'k'), result('c1', 'other')]);
    (rows[2]!.block['payload'] as JsonObject)['summary'] = 'changed';
    assert.equal(first(rows), 'HASH_MISMATCH 2');
  });
  await t.test('the first failing row in order is reported', () => {
    const rows = buildChain(pauses(4));
    (rows[3]!.block['payload'] as JsonObject)['reason'] = 'x';
    rows[2]!.block['ts'] = 'bad';
    assert.equal(first(rows), 'TIME_FORMAT_INVALID 2');
  });
  await t.test('an empty sequence is GENESIS_INVALID 0', () => {
    assert.equal(fmt(runStep1([], { bundleSha256: TEST_BUNDLE_SHA256, namespaceChainId: randomUUID() })), 'GENESIS_INVALID 0');
  });
});

function fmt(r: ReturnType<typeof runStep1>): string {
  return r.ok ? 'OK' : `${r.failure.code} ${r.failure.param}`;
}

function sqlRowOf(row: BuiltRow): SqlEventRow {
  const blockJson = canonicalize(row.block);
  return {
    chain_id: row.block['chain_id'] as string,
    seq: String(row.block['seq']),
    ts: row.block['ts'] as string,
    prev_hash: row.block['prev_hash'] as string,
    payload: canonicalize(row.block['payload']!),
    block_json: blockJson,
    entry_hash: row.entry_hash,
  };
}

test('001 AC-16 sql-representation (row check)', async (t) => {
  const [, row] = buildChain(pauses(1));
  const good = sqlRowOf(row!);
  await t.test('a consistent row passes', () => assert.equal(checkSqlRow(good).ok, true));
  await t.test('each isolated mirror discrepancy fails', () => {
    for (const change of [
      { payload: canonicalize(obj({ ...pausePayload(1), reason: 'other' })) },
      { ts: '2026-11-13T12:00:09.000Z' },
      { prev_hash: H },
      { seq: '9' },
      { seq: '01' },
      { chain_id: randomUUID() },
    ]) {
      assert.equal(checkSqlRow({ ...good, ...change }).ok, false, JSON.stringify(change));
    }
  });
  await t.test('noncanonical, malformed, duplicate-key block_json and a bad entry_hash fail', () => {
    const spaced = good.block_json.replace(':', ': ');
    assert.equal(checkSqlRow({ ...good, block_json: spaced, entry_hash: sha256Hex(Buffer.from(spaced)) }).ok, false);
    assert.equal(checkSqlRow({ ...good, block_json: good.block_json.slice(1) }).ok, false);
    const dup = good.block_json.replace('{', '{"seq":1,');
    assert.equal(checkSqlRow({ ...good, block_json: dup, entry_hash: sha256Hex(Buffer.from(dup)) }).ok, false);
    assert.equal(checkSqlRow({ ...good, entry_hash: H }).ok, false);
  });
  await t.test('a jsonb rendering with other key order and spacing passes', () => {
    const p = pausePayload(1);
    const rendered = `{"reason": "${p['reason'] as string}", "task_id": "${p['task_id'] as string}", "operation": "tear.epistemic_pause", "event_type": "epistemic_pause", "missing_sources": []}`;
    assert.equal(checkSqlRow({ ...good, payload: rendered }).ok, true);
  });
});

test('001 AC-26 sql-logical-step1', async (t) => {
  await t.test('canonical SQL tuples pass Step 1 without LF bytes in block_json', () => {
    const rows = buildChain(pauses(3));
    const ins: RowInput[] = rows.map((r) => {
      const sql = sqlRowOf(r);
      assert.ok(!sql.block_json.includes('\n'));
      const check = checkSqlRow(sql);
      assert.ok(check.ok);
      return { kind: 'json', value: check.envelope };
    });
    assert.equal(fmt(runStep1(ins, ctxFor(rows))), 'OK');
  });
});
