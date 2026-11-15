// SPDX-License-Identifier: AGPL-3.0-or-later
// Requires local PostgreSQL (npm run test:pg). The write-ahead interceptor and
// the scripted reference agent (spec 005), with in-process test TSAs.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { before, test } from 'node:test';
import { autoAnchorHook } from '../../src/anchor/trigger.js';
import { exportChain } from '../../src/chain/export.js';
import { initializeChain } from '../../src/chain/initialize.js';
import type { AnchorHook } from '../../src/chain/interfaces.js';
import { ChainWriter } from '../../src/chain/writer.js';
import { entryHashOf, resultDigest, responseDigest, sha256Hex } from '../../src/crypto/digests.js';
import { provisionNamespace } from '../../src/fs/namespace.js';
import { Interceptor, ToolError, failedToolValue } from '../../src/interceptor/interceptor.js';
import { PEPPER_ENV } from '../../src/interceptor/pepper.js';
import { TearError } from '../../src/errors.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { verifyOffline } from '../../src/verify/verify.js';
import { interceptedRecorder, runAgent } from '../agent/scripted-agent.js';
import { testPki } from '../helpers/pki.js';
import { admin, bundleBytes, codeOf, ensureSchema, initOptions, newChain, pgConfig, rowCount, writerOptions } from '../helpers/pg.js';
import { stateClassifier } from '../../src/recovery/classifier.js';
import { testTsa } from '../helpers/test-tsa.js';

before(ensureSchema);

const pki = testPki(3);

interface Setup {
  root: string;
  chainId: string;
  nsPath: string;
  writer: ChainWriter;
  icp: Interceptor;
  pepperHex: string;
  bundle: Uint8Array;
  exits: unknown[];
  runs: { name: string; n: number }[];
  initialized: string;
}

/** A new chain started in the creation session, with a fresh pepper and the test PKI. */
async function setup(o: { hook?: AnchorHook; anchors?: boolean } = {}): Promise<Setup> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-icp-'));
  const chainId = randomUUID();
  const nsPath = provisionNamespace(root, chainId);
  const pepperHex = randomBytes(32).toString('hex');
  const exits: unknown[] = [];
  const { interceptor, writer, initialized } = await Interceptor.start(
    {
      checkpointsRoot: root,
      chainId,
      genesisTs: formatTimestamp(Date.now() - 1000),
      pepperId: 'test-pepper-v1',
      bundleBytes: pki.bundle,
      pg: pgConfig,
      profile: 'base',
      anchorHook: o.hook ?? autoAnchorHook(o.anchors === false ? 0 : Number.POSITIVE_INFINITY),
      tsas: [testTsa('test-tsa', pki)],
      exit: (c: unknown) => exits.push(c),
    },
    { [PEPPER_ENV]: pepperHex },
  );
  const runs: { name: string; n: number }[] = [];
  return { root, chainId, nsPath, writer, icp: interceptor, pepperHex, bundle: pki.bundle, exits, runs, initialized };
}

/** A tool with an observable trace. */
function traced(s: Setup, name: string, result: unknown = { ok: true }): void {
  const entry = { name, n: 0 };
  s.runs.push(entry);
  s.icp.register(name, () => {
    entry.n++;
    return result as never;
  });
}

const ran = (s: Setup, name: string): number => s.runs.find((r) => r.name === name)?.n ?? -1;

async function exportVerify(s: Setup): Promise<ReturnType<typeof verifyOffline>> {
  const log = path.join(s.root, 'events.jsonl');
  await exportChain({ pg: pgConfig, chainId: s.chainId, bundleBytes: s.bundle, outPath: log });
  const bundlePath = path.join(s.root, 'bundle.pem');
  fs.writeFileSync(bundlePath, s.bundle);
  return verifyOffline({ logPath: log, checkpointsPath: s.nsPath, bundlePath });
}

/** A hook that ends the writer session during the COMMIT of the record whose seq is `at`. */
function loseSessionAt(at: number, pid: () => number): AnchorHook {
  return {
    onApplicationCommit: async (ctx) => {
      if (ctx.seq === at) {
        await admin('SELECT pg_terminate_backend($1)', [pid()]);
        await new Promise((r) => setTimeout(r, 300));
      }
      return null;
    },
  };
}

/** A hook that makes the transaction of record `at` fail (rolled back). */
function failAt(at: number): AnchorHook {
  return {
    onApplicationCommit: async (ctx) => {
      if (ctx.seq === at) throw new TearError('INJECTED_WRITE_FAILURE', 'the transaction fails and is rolled back');
      return null;
    },
  };
}

test('005 start-up through initializeChain and the §5.6 writer start (spec 006)', async (t) => {
  await t.test('a new namespace: INITIALIZED, then the writer starts under fresh exclusion', async () => {
    const s = await setup({ anchors: false });
    assert.equal(s.initialized, 'INITIALIZED');
    await s.icp.epistemicPause('task-1', 'first', []);
    assert.equal(await rowCount(s.chainId), 2);
    await s.writer.close();
  });
  await t.test('an existing chain: ALREADY_INITIALIZED, and the writer continues it', async () => {
    const c = newChain();
    await initializeChain(initOptions(c));
    const first = await ChainWriter.open({ ...writerOptions(c), classifier: stateClassifier });
    await first.close();
    const { interceptor, writer, initialized } = await Interceptor.start(
      { ...writerOptions(c), classifier: stateClassifier, genesisTs: c.genesisTs, pepperId: 'test-pepper' },
      { [PEPPER_ENV]: randomBytes(32).toString('hex') },
    );
    assert.equal(initialized, 'ALREADY_INITIALIZED');
    await interceptor.epistemicPause('task-1', 'resumed', []);
    assert.equal(writer.headSeq, 1);
    await writer.close();
  });
});

test('005 AC-1 call-before-tool', async (t) => {
  await t.test('the tool runs only after the tool_call COMMIT is confirmed', async () => {
    const s = await setup({ anchors: false });
    let committedWhenRun = -1;
    s.icp.register('probe', async () => {
      committedWhenRun = await rowCount(s.chainId);
      return 'done';
    });
    assert.equal(await s.icp.callTool('task-1', 'probe', 'c-1', {}), 'done');
    assert.equal(committedWhenRun, 2, 'genesis and tool_call were committed when the tool ran');
    await s.writer.close();
  });
  await t.test('an unknown COMMIT outcome: the tool does not run', async () => {
    let s!: Setup;
    s = await setup({ hook: loseSessionAt(1, () => s.writer.backendPid) });
    traced(s, 'send');
    assert.equal(await codeOf(s.icp.callTool('task-1', 'send', 'c-1', {})), 'COMMIT_OUTCOME_UNKNOWN');
    assert.equal(ran(s, 'send'), 0);
    await s.writer.close();
  });
  await t.test('a failed write (rolled back): the tool does not run', async () => {
    const s = await setup({ hook: failAt(1) });
    traced(s, 'send');
    assert.equal(await codeOf(s.icp.callTool('task-1', 'send', 'c-1', {})), 'INJECTED_WRITE_FAILURE');
    assert.equal(ran(s, 'send'), 0);
    assert.equal(await rowCount(s.chainId), 1);
    await s.writer.close();
  });
});

test('005 AC-2 commit-before-delivery', async (t) => {
  await t.test('the tool result is not delivered when its tool_result COMMIT outcome is unknown', async () => {
    let s!: Setup;
    s = await setup({ hook: loseSessionAt(2, () => s.writer.backendPid) });
    traced(s, 'compute', { value: 42 });
    let delivered: unknown = 'nothing';
    const code = await codeOf(s.icp.callTool('task-1', 'compute', 'c-1', {}).then((v) => (delivered = v)));
    assert.equal(code, 'COMMIT_OUTCOME_UNKNOWN');
    assert.equal(delivered, 'nothing');
    assert.equal(ran(s, 'compute'), 1);
    await s.writer.close();
  });
  await t.test('the final answer is not delivered when its COMMIT fails', async () => {
    const s = await setup({ hook: failAt(1) });
    let delivered: unknown = 'nothing';
    assert.equal(await codeOf(s.icp.finalResponse('task-1', 'the answer').then((v) => (delivered = v))), 'INJECTED_WRITE_FAILURE');
    assert.equal(delivered, 'nothing');
    await s.writer.close();
  });
  await t.test('a delivered answer and result were committed first', async () => {
    const s = await setup({ anchors: false });
    traced(s, 'compute', { value: 42 });
    assert.deepEqual(await s.icp.callTool('task-1', 'compute', 'c-1', {}), { value: 42 });
    assert.equal(await s.icp.finalResponse('task-1', 'the answer'), 'the answer');
    const rows = await admin<{ p: Record<string, unknown> }>('SELECT payload AS p FROM tear_events WHERE chain_id = $1 ORDER BY seq', [s.chainId]);
    assert.equal(rows[2]!.p['result_digest'], resultDigest({ value: 42 }));
    assert.equal(rows[3]!.p['response_digest'], responseDigest('the answer'));
    assert.equal(rows[3]!.p['operation'], 'invoke_agent');
    assert.equal(rows[1]!.p['operation'], 'execute_tool');
    await s.writer.close();
  });
});

test('005 AC-4 adapter-json-domain', async (t) => {
  await t.test('invalid arguments fail before anything is written or run', async () => {
    const s = await setup({ anchors: false });
    traced(s, 'send');
    assert.equal(await codeOf(s.icp.callTool('task-1', 'send', 'c-1', { n: Number.NaN })), 'ADAPTER_JSON_INVALID');
    assert.equal(await codeOf(s.icp.callTool('task-1', 'send', 'c-2', { s: '\uD800' })), 'ADAPTER_JSON_INVALID');
    assert.equal(await codeOf(s.icp.finalResponse('task-1', { d: new Date(0) })), 'ADAPTER_JSON_INVALID');
    assert.equal(ran(s, 'send'), 0);
    assert.equal(await rowCount(s.chainId), 1);
    await s.writer.close();
  });
  await t.test('a tool returning a value outside the domain: nothing is delivered and no result is recorded', async () => {
    const s = await setup({ anchors: false });
    traced(s, 'bad', { x: 10n });
    assert.equal(await codeOf(s.icp.callTool('task-1', 'bad', 'c-1', {})), 'ADAPTER_JSON_INVALID');
    assert.equal(await rowCount(s.chainId), 2, 'only the tool_call');
    await s.writer.close();
    const v = await exportVerify(s);
    assert.match(v.stdout, /\nINCOMPLETE_EXECUTION 1\n/);
  });
});

test('005 AC-5 rejected-admission', async (t) => {
  await t.test('a duplicate call_id anywhere in the chain is rejected; the tool does not run', async () => {
    const s = await setup({ anchors: false });
    traced(s, 'send');
    await s.icp.callTool('task-1', 'send', 'call-x', {});
    assert.equal(await codeOf(s.icp.callTool('task-2', 'send', 'call-x', {})), 'EVENT_REJECTED');
    await s.icp.callTool('task-2', 'send', 'call-y', {}).catch(() => undefined);
    assert.equal(ran(s, 'send'), 2, 'only the two admitted calls ran');
    await s.writer.close();
    assert.equal((await exportVerify(s)).exitCode, 0);
  });
  await t.test('EVENT_REJECTED carries the Step 1 code: duplicate call, orphan result, empty task_id', async () => {
    const s = await setup({ anchors: false });
    traced(s, 'send');
    await s.icp.callTool('task-1', 'send', 'c-1', {});
    const reasons: string[] = [];
    for (const p of [
      s.icp.beginCall('task-1', 'send', 'c-1', {}),
      s.icp.completeCall({ callId: 'never-called', taskId: 'task-1', toolName: 'send' }, { ok: true, value: null }),
      s.icp.beginCall('', 'send', 'c-2', {}),
    ]) {
      try {
        await p;
        reasons.push('accepted');
      } catch (err) {
        reasons.push((err as Error).message);
      }
    }
    assert.match(reasons[0]!, /^EVENT_REJECTED: CALL_CORRELATION_INVALID \d+$/);
    assert.match(reasons[1]!, /^EVENT_REJECTED: CALL_CORRELATION_INVALID \d+$/);
    assert.match(reasons[2]!, /^EVENT_REJECTED: JCS_SCHEMA_INVALID \d+$/);
    assert.equal(ran(s, 'send'), 1);
    assert.equal(await rowCount(s.chainId), 3);
    await s.writer.close();
    assert.equal((await exportVerify(s)).exitCode, 0, 'the exported chain still verifies');
  });
  await t.test('a result whose task_id does not match its call is rejected', async () => {
    const s = await setup({ anchors: false });
    traced(s, 'send');
    const h = await s.icp.beginCall('task-1', 'send', 'c-1', {});
    await assert.rejects(s.icp.completeCall({ ...h, taskId: 'task-2' }, { ok: true, value: null }), /CALL_CORRELATION_INVALID/);
    await s.writer.close();
    const v = await exportVerify(s);
    assert.match(v.stdout, /\nINCOMPLETE_EXECUTION 1\n/, 'the open call stays visible');
  });
});

test('005 adapter pairing in an exported log (verifier side)', async (t) => {
  async function exportedRows(): Promise<{ s: Setup; lines: string[] }> {
    const s = await setup({ anchors: false });
    traced(s, 'send');
    await s.icp.callTool('task-1', 'send', 'c-1', {});
    await s.icp.callTool('task-1', 'send', 'c-2', {});
    await s.writer.close();
    const log = path.join(s.root, 'events.jsonl');
    await exportChain({ pg: pgConfig, chainId: s.chainId, bundleBytes: s.bundle, outPath: log });
    return { s, lines: fs.readFileSync(log, 'utf8').trimEnd().split('\n') };
  }
  /** Rewrites row `seq` with `edit` and recomputes the tail (as an operator with database access would). */
  function rewrite(s: Setup, lines: string[], seq: number, edit: (p: Record<string, unknown>) => void): ReturnType<typeof verifyOffline> {
    const rows = lines.map((l) => JSON.parse(l) as { block: Record<string, unknown>; entry_hash: string });
    edit(rows[seq]!.block['payload'] as Record<string, unknown>);
    for (let i = seq; i < rows.length; i++) {
      if (i > 0) rows[i]!.block['prev_hash'] = rows[i - 1]!.entry_hash;
      rows[i]!.entry_hash = entryHashOf(rows[i]!.block as never);
    }
    const log = path.join(s.root, 'mutated.jsonl');
    fs.writeFileSync(log, rows.map((r) => `${JSON.stringify(r)}\n`).join(''));
    const bundlePath = path.join(s.root, 'bundle.pem');
    fs.writeFileSync(bundlePath, s.bundle);
    return verifyOffline({ logPath: log, checkpointsPath: s.nsPath, bundlePath });
  }
  await t.test('an orphan result → CALL_CORRELATION_INVALID', async () => {
    const { s, lines } = await exportedRows();
    assert.equal(rewrite(s, lines, 2, (p) => (p['call_id'] = 'nobody')).stdout, 'CALL_CORRELATION_INVALID 2\n');
  });
  await t.test('a duplicate call_id → CALL_CORRELATION_INVALID', async () => {
    const { s, lines } = await exportedRows();
    assert.equal(rewrite(s, lines, 3, (p) => (p['call_id'] = 'c-1')).stdout, 'CALL_CORRELATION_INVALID 3\n');
  });
  await t.test('a mismatched task_id → CALL_CORRELATION_INVALID', async () => {
    const { s, lines } = await exportedRows();
    assert.equal(rewrite(s, lines, 2, (p) => (p['task_id'] = 'task-9')).stdout, 'CALL_CORRELATION_INVALID 2\n');
  });
  await t.test('a final call without result → INCOMPLETE_EXECUTION', async () => {
    const { s, lines } = await exportedRows();
    const v = rewrite(s, lines.slice(0, 4), 3, () => undefined);
    assert.equal(v.exitCode, 0);
    assert.match(v.stdout, /\nINCOMPLETE_EXECUTION 3\n/);
  });
});

test('005 AC-6 incomplete-execution', async (t) => {
  await t.test('the process dies after the tool ran: the export verifies with INCOMPLETE_EXECUTION, no retry', async () => {
    await ensureSchema();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-icp-kill-'));
    const chainId = randomUUID();
    const nsPath = provisionNamespace(root, chainId);
    const marker = path.join(root, 'marker.txt');
    const pepperHex = randomBytes(32).toString('hex');
    const r = spawnSync(process.execPath, ['dist/test/helpers/agent-child.js', root, chainId, marker], {
      encoding: 'utf8',
      env: { ...process.env, [PEPPER_ENV]: pepperHex },
    });
    assert.equal(r.signal, 'SIGKILL');
    assert.equal(fs.readFileSync(marker, 'utf8'), 'sent\n', 'the tool ran exactly once');
    // The successor's locks: the dead backend releases its advisory lock when the server ends the session.
    const log = path.join(root, 'events.jsonl');
    await exportChain({ pg: pgConfig, chainId, bundleBytes, outPath: log });
    const v = verifyOffline({ logPath: log, checkpointsPath: nsPath, bundlePath: path.resolve('certs/tsa_roots.pem') });
    assert.equal(v.exitCode, 0);
    assert.equal(v.stdout, 'VALID_UNANCHORED 0..2\nINCOMPLETE_EXECUTION 2\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
    assert.equal(fs.readFileSync(marker, 'utf8'), 'sent\n', 'nothing retried the tool');
    for (const text of [r.stdout, r.stderr]) assert.ok(!text.includes(pepperHex));
  });
});

test('005 AC-7 pepper-not-persisted', async (t) => {
  await t.test('an invalid TEAR_HMAC_PEPPER refuses start-up before any write', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-icp-pep-'));
    const chainId = randomUUID();
    const nsPath = provisionNamespace(root, chainId);
    const opts = { checkpointsRoot: root, chainId, genesisTs: formatTimestamp(Date.now()), pepperId: 'p', bundleBytes, pg: pgConfig, profile: 'base' as const };
    for (const env of [{}, { [PEPPER_ENV]: 'ABCD'.repeat(16) }, { [PEPPER_ENV]: 'ab'.repeat(31) }]) {
      const code = await codeOf(Interceptor.start(opts, env));
      assert.ok(code === 'PEPPER_MISSING' || code === 'PEPPER_INVALID', code);
    }
    assert.equal(await rowCount(chainId), 0);
    assert.deepEqual(fs.readdirSync(nsPath), [], 'not even .writer.lock was created');
  });
  await t.test('the pepper bytes appear nowhere: database, export, namespace; only pepper_id is recorded', async () => {
    const s = await setup();
    await runAgent(interceptedRecorder(s.icp), 27);
    await s.writer.close();
    const v = await exportVerify(s);
    assert.equal(v.exitCode, 0);
    const pepper = Buffer.from(s.pepperHex, 'hex');
    const needles = [Buffer.from(s.pepperHex), Buffer.from(s.pepperHex.toUpperCase()), Buffer.from(pepper.toString('base64')), pepper];
    const haystacks: [string, Buffer][] = [
      ['events table', Buffer.from(JSON.stringify(await admin('SELECT * FROM tear_events WHERE chain_id = $1', [s.chainId])))],
      ['state table', Buffer.from(JSON.stringify(await admin('SELECT * FROM tear_chain_state WHERE chain_id = $1', [s.chainId])))],
      ['export', fs.readFileSync(path.join(s.root, 'events.jsonl'))],
      ...fs.readdirSync(s.nsPath).map((n) => [`namespace ${n}`, fs.readFileSync(path.join(s.nsPath, n))] as [string, Buffer]),
    ];
    for (const [where, hay] of haystacks) for (const n of needles) assert.equal(hay.indexOf(n), -1, where);
    const [genesis] = await admin<{ p: Record<string, unknown> }>('SELECT payload AS p FROM tear_events WHERE chain_id = $1 AND seq = 0', [s.chainId]);
    assert.equal(genesis!.p['pepper_id'], 'test-pepper-v1');
  });
});

test('005 AC-8 agent-end-to-end', async (t) => {
  await t.test('a full scripted run (100 events, anchored by a test TSA) exports and verifies with exit 0', async () => {
    const s = await setup();
    const timings = await runAgent(interceptedRecorder(s.icp), 100);
    await s.writer.close();
    const v = await exportVerify(s);
    assert.equal(v.exitCode, 0, v.stdout);
    assert.match(v.stdout, /^VERIFIED_ANCHORED 0\.\.\d+\n/);
    assert.ok(!v.stdout.includes('VALID_UNANCHORED 0..'), 'anchored by the test TSA');
    assert.ok(!v.stdout.includes('INCOMPLETE_EXECUTION'));
    assert.equal(timings.reduce((n, t2) => n + t2.eventsMs.length, 0), 100);
    const failed = await admin<{ n: string }>(
      "SELECT count(*)::text AS n FROM tear_events WHERE chain_id = $1 AND payload->>'event_type' = 'tool_result' AND payload->>'error_type' = 'not_found'",
      [s.chainId],
    );
    assert.ok(Number(failed[0]!.n) >= 1, 'the run includes failed tool calls');
  });
});

test('005 AC-10 pause-and-resolution-boundary', async (t) => {
  for (const [label, at, step] of [
    ['epistemic_pause', 1, 'pause'],
    ['human_resolution', 2, 'resolution'],
  ] as const) {
    await t.test(`the agent does not continue after an unconfirmed ${label}`, async () => {
      let s!: Setup;
      s = await setup({ hook: loseSessionAt(at, () => s.writer.backendPid) });
      traced(s, 'next');
      // Seq 1 is the pause, seq 2 the resolution; the session is lost while committing the one under test.
      const agent = async (): Promise<void> => {
        await s.icp.epistemicPause('task-1', 'need a reviewer', ['doc']);
        if (step === 'resolution') await s.icp.humanResolution('task-1', 'reviewer-1', 'go on');
        await s.icp.callTool('task-1', 'next', 'c-1', {});
      };
      assert.equal(await codeOf(agent()), 'COMMIT_OUTCOME_UNKNOWN');
      assert.equal(ran(s, 'next'), 0);
      await s.writer.close();
    });
  }
  await t.test('it continues only once the COMMIT is confirmed', async () => {
    const s = await setup({ anchors: false });
    let rowsWhenNext = -1;
    s.icp.register('next', async () => {
      rowsWhenNext = await rowCount(s.chainId);
      return null;
    });
    await s.icp.epistemicPause('task-1', 'need a reviewer', ['doc']);
    await s.icp.humanResolution('task-1', 'reviewer-1', 'go on');
    await s.icp.callTool('task-1', 'next', 'c-1', {});
    assert.equal(rowsWhenNext, 4);
    await s.writer.close();
  });
});

test('005 AC-11 failed-tool-digest', async (t) => {
  await t.test('a failing tool records error_type and the digest of {error_type, message}; the agent gets the error', async () => {
    const s = await setup({ anchors: false });
    s.icp.register('lookup', () => {
      throw new ToolError('not_found', 'no record with id rec-1');
    });
    await assert.rejects(s.icp.callTool('task-1', 'lookup', 'c-1', { id: 'rec-1' }), (e: unknown) => e instanceof ToolError && e.errorType === 'not_found');
    const [r] = await admin<{ p: Record<string, unknown> }>('SELECT payload AS p FROM tear_events WHERE chain_id = $1 AND seq = 2', [s.chainId]);
    assert.equal(r!.p['error_type'], 'not_found');
    assert.equal(r!.p['result_digest'], resultDigest(failedToolValue('not_found', 'no record with id rec-1')));
    assert.equal(r!.p['result_digest'], sha256Hex(Buffer.from('{"error_type":"not_found","message":"no record with id rec-1"}')));
    await s.writer.close();
  });
});
