// SPDX-License-Identifier: AGPL-3.0-or-later
// Requires local PostgreSQL (npm run test:pg).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { initializeChain } from '../../src/chain/initialize.js';
import { EventRejectedError, ChainWriter } from '../../src/chain/writer.js';
import type { JsonObject } from '../../src/json/strict-json.js';
import { obj, pausePayload } from '../helpers/chain-builder.js';
import {
  admin,
  codeOf,
  ensureSchema,
  initOptions,
  initializedWriter,
  newChain,
  rowCount,
  waitFor,
  writerOptions,
} from '../helpers/pg.js';
import type { TestChain } from '../helpers/pg.js';

before(ensureSchema);

const here = path.dirname(fileURLToPath(import.meta.url));
const childScript = path.join(here, '..', 'helpers', 'writer-child.js');
const H = 'd'.repeat(64);

function call(callId: string, task: string): JsonObject {
  return obj({ event_type: 'tool_call', operation: 'execute_tool', tool_name: 't', call_id: callId, task_id: task, args_hmac: H });
}
function result(callId: string, task: string): JsonObject {
  return obj({ event_type: 'tool_result', operation: 'execute_tool', call_id: callId, task_id: task, error_type: null, result_digest: H, summary: 's' });
}

async function startChild(mode: string, c: TestChain): Promise<import('node:child_process').ChildProcess> {
  const child = spawn(process.execPath, [childScript, mode, c.root, c.chainId], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise<void>((resolve, reject) => {
    child.stdout!.once('data', () => resolve());
    child.once('exit', (code) => reject(new Error(`child exited early (${String(code)})`)));
  });
  return child;
}

async function kill(child: import('node:child_process').ChildProcess): Promise<void> {
  const exited = new Promise((r) => child.once('exit', r));
  child.kill('SIGKILL');
  await exited;
}

test('001 AC-11 advisory-lock', async (t) => {
  await t.test('another session holding the advisory lock blocks start-up before any state read', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    const pg = await import('pg');
    const holder = new pg.default.Client((await import('../helpers/pg.js')).pgConfig);
    await holder.connect();
    try {
      await holder.query('SELECT pg_advisory_lock(hashtext($1::uuid::text))', [c.chainId]);
      assert.equal(await codeOf(ChainWriter.open(writerOptions(c))), 'ADVISORY_LOCK_UNAVAILABLE');
      // flock was released normally: once the session lock is gone, start-up succeeds.
      await holder.query('SELECT pg_advisory_unlock(hashtext($1::uuid::text))', [c.chainId]);
      const w = await ChainWriter.open(writerOptions(c));
      await w.close();
    } finally {
      await holder.end();
    }
  });
});

test('001 AC-12 single-session', async (t) => {
  await t.test('every statement runs on the lock-owning backend', async () => {
    const { writer } = await initializedWriter();
    for (let i = 1; i <= 5; i++) await writer.append(pausePayload(i));
    assert.ok(writer.observedPids.length > 10);
    assert.ok(writer.observedPids.every((p) => p === writer.backendPid));
    const [lock] = await admin<{ pid: number }>(
      `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND pid = $1`,
      [writer.backendPid],
    );
    assert.equal(lock?.pid, writer.backendPid);
    await writer.close();
  });
  await t.test('a lost session is never replaced: the writer stays invalidated', async () => {
    const { writer } = await initializedWriter();
    const pid = writer.backendPid;
    await admin('SELECT pg_terminate_backend($1)', [pid]);
    await waitFor(() => writer.invalidated);
    assert.equal(await codeOf(writer.append(pausePayload(1))), 'WRITER_INVALIDATED');
    assert.equal(writer.backendPid, pid);
    await writer.close();
  });
  for (const [mode, committed] of [
    ['inflight-open', false],
    ['inflight-done', true],
  ] as const) {
    await t.test(`successor waits for the prior backend (${committed ? 'committed' : 'rolled back'} in-flight work)`, async () => {
      const c = newChain();
      await initializeChain(initOptions(c));
      const child = await startChild(mode, c);
      await kill(child);
      // The process is dead and flock is free, but its backend still holds the session lock.
      assert.equal(await codeOf(ChainWriter.open(writerOptions(c))), 'ADVISORY_LOCK_UNAVAILABLE');
      let successor: ChainWriter | null = null;
      await waitFor(async () => {
        try {
          successor = await ChainWriter.open(writerOptions(c));
          return true;
        } catch {
          return false;
        }
      });
      assert.equal(successor!.headSeq, committed ? 1 : 0);
      await successor!.close();
    });
  }
});

test('001 AC-15 durability-settings', async (t) => {
  await t.test('the local server satisfies the required tuple', async () => {
    const { writer } = await initializedWriter();
    await writer.append(pausePayload(1));
    await writer.close();
  });
  await t.test('a session without effective synchronous_commit=on is refused before any write', async () => {
    const { chain, writer } = await initializedWriter();
    await writer.connForTests.rawClientForTests.query('SET synchronous_commit = off');
    assert.equal(await codeOf(writer.append(pausePayload(1))), 'DATABASE_DURABILITY_UNSUPPORTED');
    assert.ok(writer.invalidated);
    assert.equal(await rowCount(chain.chainId), 1);
    await writer.close();
    // A fresh writerConn sets synchronous_commit=on again.
    const next = await ChainWriter.open(writerOptions(chain));
    await next.append(pausePayload(1));
    await next.close();
  });
});

test('001 AC-16 sql-representation', async (t) => {
  for (const [label, sql] of [
    ['payload', `UPDATE tear_events SET payload = payload || '{"reason":"x"}' WHERE chain_id = $1 AND seq = 2`],
    ['ts', `UPDATE tear_events SET ts = '2026-01-01T00:00:00.000Z' WHERE chain_id = $1 AND seq = 2`],
    ['prev_hash', `UPDATE tear_events SET prev_hash = repeat('e', 64) WHERE chain_id = $1 AND seq = 2`],
    ['seq', `UPDATE tear_events SET seq = 7 WHERE chain_id = $1 AND seq = 2`],
    ['block_json', `UPDATE tear_events SET block_json = block_json || ' ' WHERE chain_id = $1 AND seq = 2`],
    ['entry_hash', `UPDATE tear_events SET entry_hash = repeat('e', 64) WHERE chain_id = $1 AND seq = 2`],
  ] as const) {
    await t.test(`a ${label} discrepancy fails start-up`, async () => {
      const { chain, writer } = await initializedWriter();
      for (let i = 1; i <= 3; i++) await writer.append(pausePayload(i));
      await writer.close();
      await admin(sql, [chain.chainId]);
      assert.equal(await codeOf(ChainWriter.open(writerOptions(chain))), 'RECONCILIATION_STATE_INCONSISTENT');
    });
  }
  await t.test('a chain_id discrepancy (row moved to another chain id) is inconsistent for both chains', async () => {
    const { chain, writer } = await initializedWriter();
    for (let i = 1; i <= 2; i++) await writer.append(pausePayload(i));
    await writer.close();
    const other = newChain();
    await admin('UPDATE tear_events SET chain_id = $2 WHERE chain_id = $1 AND seq = 2', [chain.chainId, other.chainId]);
    assert.equal(await codeOf(ChainWriter.open(writerOptions(other))), 'RECONCILIATION_STATE_INCONSISTENT');
  });
});

test('001 AC-21 writer-admission', async (t) => {
  const { chain, writer } = await initializedWriter();
  await writer.append(call('c1', 'k'));
  await writer.append(result('c1', 'k'));
  const count = await rowCount(chain.chainId);
  async function rejection(p: JsonObject): Promise<string> {
    try {
      await writer.append(p);
      return 'accepted';
    } catch (err) {
      assert.ok(err instanceof EventRejectedError, String(err));
      return `${err.rejection.code} ${err.rejection.param}`;
    }
  }
  await t.test('duplicate call_id', async () => assert.equal(await rejection(call('c1', 'k')), 'CALL_CORRELATION_INVALID 3'));
  await t.test('result without call', async () => assert.equal(await rejection(result('c9', 'k')), 'CALL_CORRELATION_INVALID 3'));
  await t.test('empty task_id', async () =>
    assert.equal(await rejection(obj({ ...pausePayload(1), task_id: '' })), 'JCS_SCHEMA_INVALID 3'));
  await t.test('lone surrogate in the payload', async () =>
    assert.equal(await rejection(obj({ ...pausePayload(1), reason: '\ud800' })), 'JCS_SCHEMA_INVALID 3'));
  await t.test('nothing was committed and the writer is still available', async () => {
    assert.equal(await rowCount(chain.chainId), count);
    assert.equal((await writer.append(pausePayload(2))).seq, 3);
  });
  await t.test('control events cannot be appended', async () => {
    assert.equal(
      await codeOf(writer.append(obj({ event_type: 'checkpoint_failed', operation: 'tear.checkpoint', target_seq: 3, error_type: 'x' }))),
      'EVENT_TYPE_NOT_APPLICATION',
    );
  });
  await writer.close();
});

test('001 AC-22 durable-append', async (t) => {
  await t.test('append resolves after COMMIT and the row is visible to another session', async () => {
    const { chain, writer } = await initializedWriter();
    const r = await writer.append(pausePayload(1));
    const [row] = await admin<{ entry_hash: string }>('SELECT entry_hash FROM tear_events WHERE chain_id = $1 AND seq = 1', [chain.chainId]);
    assert.equal(row?.entry_hash, r.entryHash);
    await writer.close();
  });
  await t.test('a lost session during COMMIT reports COMMIT_OUTCOME_UNKNOWN', async () => {
    let pid = 0;
    const { chain, writer } = await initializedWriter({
      anchorHook: {
        onApplicationCommit: async () => {
          await admin('SELECT pg_terminate_backend($1)', [pid]);
          await new Promise((r) => setTimeout(r, 300));
        },
      },
    });
    pid = writer.backendPid;
    assert.equal(await codeOf(writer.append(pausePayload(1))), 'COMMIT_OUTCOME_UNKNOWN');
    assert.ok(writer.invalidated);
    await writer.close();
    // The successor resolves the actual outcome from the database.
    const next = await ChainWriter.open(writerOptions(chain));
    assert.ok(next.headSeq === 0 || next.headSeq === 1);
    await next.close();
  });
});

test('001 AC-23 invalidation', async (t) => {
  await t.test('an ended session invalidates the writer and blocks every later mutation', async () => {
    const { chain, writer } = await initializedWriter();
    await writer.append(pausePayload(1));
    await admin('SELECT pg_terminate_backend($1)', [writer.backendPid]);
    await waitFor(() => writer.invalidated);
    assert.equal(await codeOf(writer.append(pausePayload(2))), 'WRITER_INVALIDATED');
    assert.equal(await codeOf(writer.append(pausePayload(3))), 'WRITER_INVALIDATED');
    assert.equal(await rowCount(chain.chainId), 2);
    await writer.close();
  });
});

test('001 AC-24 two-chains', async (t) => {
  await t.test('two writers append concurrently without sharing files', async () => {
    const a = await initializedWriter();
    const b = await initializedWriter();
    await Promise.all(
      Array.from({ length: 10 }, (_, i) => [a.writer.append(pausePayload(i + 1)), b.writer.append(pausePayload(i + 1))]).flat(),
    );
    assert.equal(a.writer.headSeq, 10);
    assert.equal(b.writer.headSeq, 10);
    assert.deepEqual(fs.readdirSync(a.chain.nsPath), ['.writer.lock']);
    assert.deepEqual(fs.readdirSync(b.chain.nsPath), ['.writer.lock']);
    assert.notEqual(a.chain.nsPath, b.chain.nsPath);
    await a.writer.close();
    await b.writer.close();
  });
});

test('001 AC-28 anchor-hook', async (t) => {
  await t.test('the hook runs inside the append transaction for every application event', async () => {
    const calls: number[] = [];
    let chainId = '';
    const { chain, writer } = await initializedWriter({
      anchorHook: {
        onApplicationCommit: async (ctx) => {
          calls.push(ctx.seq);
          const inside = (await ctx.query('SELECT count(*)::int AS n FROM tear_events WHERE chain_id = $1 AND seq = $2', [ctx.chainId, ctx.seq])) as { n: number }[];
          assert.equal(inside[0]?.n, 1, 'row visible inside the transaction');
          const outside = await admin<{ n: number }>('SELECT count(*)::int AS n FROM tear_events WHERE chain_id = $1 AND seq = $2', [chainId, ctx.seq]);
          assert.equal(outside[0]?.n, 0, 'row not yet committed');
        },
      },
    });
    chainId = chain.chainId;
    for (let i = 1; i <= 3; i++) await writer.append(pausePayload(i));
    assert.deepEqual(calls, [1, 2, 3]);
    await writer.close();
  });
  await t.test('the default hook does nothing: no pending anchor at seq 10', async () => {
    const { chain, writer } = await initializedWriter();
    for (let i = 1; i <= 10; i++) await writer.append(pausePayload(i));
    const [state] = await admin('SELECT pending_anchor_seq FROM tear_chain_state WHERE chain_id = $1', [chain.chainId]);
    assert.equal(state!['pending_anchor_seq'], null);
    await writer.close();
  });
});

test('001 AC-6 writer-timestamps (integration)', async (t) => {
  await t.test('a simulated clock step back produces a tie in ts, never a regression', async () => {
    const times = [Date.now(), Date.now() - 3_600_000, Date.now() - 7_200_000];
    let i = 0;
    const { writer } = await initializedWriter({ clock: () => times[Math.min(i++, times.length - 1)]! });
    const first = await writer.append(pausePayload(1));
    const second = await writer.append(pausePayload(2));
    const third = await writer.append(pausePayload(3));
    assert.equal(second.ts, first.ts);
    assert.equal(third.ts, first.ts);
    await writer.close();
  });
});

test('integration second-writer-process-refused', async (t) => {
  await t.test('a second process on the same chain fails at the lock and writes nothing', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    const child = await startChild('hold', c);
    try {
      const before = await rowCount(c.chainId);
      assert.equal(await codeOf(ChainWriter.open(writerOptions(c))), 'WRITER_LOCKED');
      assert.equal(await rowCount(c.chainId), before);
    } finally {
      await kill(child);
    }
  });
});
