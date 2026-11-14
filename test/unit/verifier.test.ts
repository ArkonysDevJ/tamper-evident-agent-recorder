// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import type { JsonObject } from '../../src/json/strict-json.js';
import { parseArgs } from '../../src/verify/args.js';
import { buildChain, chainIdOf, obj, pausePayload, rehash } from '../helpers/chain-builder.js';
import type { BuiltRow } from '../helpers/chain-builder.js';
import { BUNDLE_SHA256, cliArgs, out, runCli, serialize, verifyBytes, writeInputs } from '../helpers/verify-files.js';

const H = 'f'.repeat(64);

function chain(payloads: JsonObject[] = [pausePayload(1), pausePayload(2), pausePayload(3)]): BuiltRow[] {
  return buildChain(payloads, { bundleSha256: BUNDLE_SHA256 });
}
function call(callId: string, task: string): JsonObject {
  return obj({ event_type: 'tool_call', operation: 'execute_tool', tool_name: 't', call_id: callId, task_id: task, args_hmac: H });
}
function result(callId: string, task: string): JsonObject {
  return obj({ event_type: 'tool_result', operation: 'execute_tool', call_id: callId, task_id: task, error_type: null, result_digest: H, summary: 's' });
}
function verifyRows(rows: BuiltRow[]): string {
  return out(chainIdOf(rows), serialize(rows));
}
const OK3 = 'VALID_UNANCHORED 0..3\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n';

test('002 AC-1 invocation', async (t) => {
  const rows = chain();
  const good = writeInputs(chainIdOf(rows), serialize(rows));
  const unavailable = (r: { status: number | null; stdout: Buffer; stderr: Buffer }): void => {
    assert.equal(r.stdout.toString(), 'INPUT_UNAVAILABLE 0\n');
    assert.equal(r.status, 2);
    assert.equal(r.stderr.length, 0);
  };
  await t.test('a valid invocation verifies', () => {
    const r = runCli(cliArgs(good));
    assert.equal(r.status, 0);
    assert.equal(r.stdout.toString(), OK3);
  });
  await t.test('the namespace basename must be a lowercase UUID', () => {
    for (const name of ['not-a-uuid', chainIdOf(rows).toUpperCase()]) {
      const dir = path.join(path.dirname(good.logPath), name);
      fs.mkdirSync(dir, { recursive: true });
      unavailable(runCli(cliArgs({ ...good, checkpointsPath: dir })));
    }
  });
  await t.test('a missing or non-directory namespace', () => {
    unavailable(runCli(cliArgs({ ...good, checkpointsPath: path.join(os.tmpdir(), randomUUID()) })));
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tear-v-')), randomUUID());
    fs.writeFileSync(file, '');
    unavailable(runCli(cliArgs({ ...good, checkpointsPath: file })));
  });
  await t.test('a missing, unreadable or directory log', () => {
    unavailable(runCli(cliArgs({ ...good, logPath: `${good.logPath}.missing` })));
    unavailable(runCli(cliArgs({ ...good, logPath: path.dirname(good.logPath) })));
    if (process.getuid?.() !== 0) {
      const locked = writeInputs(chainIdOf(rows), serialize(rows));
      fs.chmodSync(locked.logPath, 0o000);
      unavailable(runCli(cliArgs(locked)));
    }
  });
  await t.test('a missing CA bundle', () => {
    unavailable(runCli(cliArgs({ ...good, bundlePath: `${good.bundlePath}.missing` })));
  });
  await t.test('namespace identity is checked before the log', () => {
    unavailable(runCli(cliArgs({ ...good, checkpointsPath: '/nonexistent/not-a-uuid', logPath: '/nonexistent/log' })));
  });
  await t.test('a malformed command line is an invocation failure', () => {
    assert.equal(parseArgs(['--log', 'a', '--checkpoints', 'b']), null);
    assert.equal(parseArgs(['--log', 'a', '--log', 'a', '--checkpoints', 'b', '--tsa-ca-bundle', 'c']), null);
    assert.equal(parseArgs(['--log', 'a', '--checkpoints', 'b', '--tsa-ca-bundle', 'c', '--extra', 'd']), null);
    unavailable(runCli(['--log', good.logPath]));
  });
});

test('002 AC-2 framing', async (t) => {
  const rows = chain();
  const id = chainIdOf(rows);
  const bytes = serialize(rows);
  await t.test('zero-byte file → GENESIS_INVALID 0', () => assert.equal(out(id, Buffer.alloc(0)), 'GENESIS_INVALID 0\n'));
  await t.test('empty row 0 → GENESIS_INVALID 0', () => assert.equal(out(id, Buffer.from('\n')), 'GENESIS_INVALID 0\n'));
  await t.test('a later empty row → JCS_SCHEMA_INVALID <expected_seq>', () => {
    assert.equal(out(id, Buffer.concat([bytes, Buffer.from('\n')])), 'JCS_SCHEMA_INVALID 4\n');
  });
  await t.test('a nonempty last row without LF → schema failure at that row', () => {
    assert.equal(out(id, bytes.subarray(0, bytes.length - 1)), 'JCS_SCHEMA_INVALID 3\n');
    assert.equal(out(id, serialize(rows.slice(0, 1)).subarray(0, -1)), 'GENESIS_INVALID 0\n');
    const garbage = Buffer.concat([serialize(rows.slice(0, 2)), Buffer.from('{"x"')]);
    assert.equal(out(id, garbage), 'JCS_SCHEMA_INVALID 2\n');
  });
  await t.test('the unterminated row uses its own seq when the schema supplies it', () => {
    const shifted = chain();
    shifted[3]!.block['seq'] = 9;
    assert.equal(out(chainIdOf(shifted), serialize(shifted).subarray(0, -1)), 'JCS_SCHEMA_INVALID 9\n');
  });
  await t.test('a UTF-8 BOM is not permitted', () => {
    assert.equal(out(id, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes])), 'GENESIS_INVALID 0\n');
  });
  await t.test('invalid UTF-8 is a schema failure, never replaced', () => {
    const lines = bytes.toString('utf8').split('\n');
    const bad = Buffer.concat([Buffer.from(lines.slice(0, 2).join('\n') + '\n'), Buffer.from([0xff, 0xfe, 0x0a]), Buffer.from(lines.slice(3).join('\n'))]);
    assert.equal(out(id, bad), 'JCS_SCHEMA_INVALID 2\n');
  });
  await t.test('an earlier failure keeps precedence over a later framing defect', () => {
    const broken = chain();
    (broken[1]!.block['payload'] as JsonObject)['reason'] = 'x';
    assert.equal(out(chainIdOf(broken), Buffer.concat([serialize(broken), Buffer.from('\n')])), 'HASH_MISMATCH 1\n');
  });
});

test('002 AC-3 schema', async (t) => {
  await t.test('a schema failure at row 0 is GENESIS_INVALID 0', () => {
    const rows = chain();
    rows[0]!.block['extra'] = 1;
    assert.equal(verifyRows(rows), 'GENESIS_INVALID 0\n');
  });
  await t.test('later rows use O_i.seq, or expected_seq when no valid seq exists', () => {
    const rows = chain();
    (rows[2]!.block['payload'] as JsonObject)['extra'] = 'x';
    assert.equal(verifyRows(rows), 'JCS_SCHEMA_INVALID 2\n');
    const noSeq = chain();
    noSeq[2]!.block['seq'] = 'two';
    assert.equal(verifyRows(noSeq), 'JCS_SCHEMA_INVALID 2\n');
    const base = chain();
    const lines = serialize(base).toString('utf8').split('\n');
    lines[3] = '{bad';
    assert.equal(out(chainIdOf(base), Buffer.from(lines.join('\n'))), 'JCS_SCHEMA_INVALID 3\n');
  });
});

test('002 AC-4 genesis', async (t) => {
  await t.test('a nonzero genesis prev_hash', () => {
    const rows = chain();
    rows[0]!.block['prev_hash'] = H;
    rehash(rows);
    assert.equal(verifyRows(rows), 'GENESIS_INVALID 0\n');
  });
  await t.test('genesis not at row 0', () => {
    const rows = chain();
    assert.equal(out(chainIdOf(rows), serialize(rows.slice(1))), 'GENESIS_INVALID 0\n');
  });
  await t.test('chain_genesis at a later row', () => {
    const rows = chain();
    rows[2]!.block['payload'] = rows[0]!.block['payload']!;
    rehash(rows, 2);
    assert.equal(verifyRows(rows), 'JCS_SCHEMA_INVALID 2\n');
  });
});

test('002 AC-5 bundle-digest', async (t) => {
  await t.test('genesis digest different from the bundle file → TSA_BUNDLE_MISMATCH 0', () => {
    const rows = buildChain([pausePayload(1)]);
    assert.equal(verifyRows(rows), 'TSA_BUNDLE_MISMATCH 0\n');
  });
});

test('002 AC-6 time-format', async (t) => {
  await t.test('an invalid calendar date', () => {
    const rows = chain();
    rows[2]!.block['ts'] = '2026-02-29T00:00:00.000Z';
    rehash(rows, 2);
    assert.equal(verifyRows(rows), 'TIME_FORMAT_INVALID 2\n');
  });
});

test('002 AC-7 chain-id', async (t) => {
  await t.test('a row from another chain', () => {
    const rows = chain();
    rows[3]!.block['chain_id'] = randomUUID();
    rehash(rows, 3);
    assert.equal(verifyRows(rows), 'CHAIN_ID_MISMATCH 3\n');
  });
  await t.test('a namespace for another chain', () => {
    const rows = chain();
    assert.equal(out(randomUUID(), serialize(rows)), 'CHAIN_ID_MISMATCH 0\n');
  });
});

test('002 AC-8 sequence', async (t) => {
  await t.test('duplicate and gap', () => {
    const dup = chain();
    dup.splice(3, 0, dup[2]!);
    assert.equal(verifyRows(dup), 'SEQ_DUPLICATE 2\n');
    const gap = chain();
    gap.splice(2, 1);
    assert.equal(verifyRows(gap), 'SEQ_GAP 2\n');
  });
});

test('002 AC-9 monotonicity', async (t) => {
  await t.test('regression fails, tie passes', () => {
    const tie = chain();
    tie[2]!.block['ts'] = tie[1]!.block['ts']!;
    rehash(tie, 2);
    assert.equal(verifyRows(tie), OK3);
    const back = chain();
    back[2]!.block['ts'] = back[0]!.block['ts']!;
    rehash(back, 2);
    assert.equal(verifyRows(back), 'TS_REGRESSION 2\n');
  });
});

test('002 AC-10 hash', async (t) => {
  await t.test('an edited payload without recomputation', () => {
    const rows = chain();
    (rows[2]!.block['payload'] as JsonObject)['reason'] = 'tampered';
    assert.equal(verifyRows(rows), 'HASH_MISMATCH 2\n');
  });
});

test('002 AC-11 link', async (t) => {
  await t.test('a broken prev_hash with a self-consistent hash', () => {
    const rows = chain();
    rows[2]!.block['prev_hash'] = H;
    rehash([rows[2]!]);
    assert.equal(verifyRows(rows), 'PREV_HASH_MISMATCH 2\n');
  });
});

test('002 AC-12 call-pairing', async (t) => {
  await t.test('orphan result, duplicate call_id, mismatched task_id', () => {
    assert.equal(verifyRows(chain([result('c', 'k')])), 'CALL_CORRELATION_INVALID 1\n');
    assert.equal(verifyRows(chain([call('c', 'k'), call('c', 'k')])), 'CALL_CORRELATION_INVALID 2\n');
    assert.equal(verifyRows(chain([call('c', 'k'), result('c', 'j')])), 'CALL_CORRELATION_INVALID 2\n');
  });
  await t.test('an earlier same-row defect prevails', () => {
    const rows = chain([call('c', 'k'), result('c', 'j')]);
    (rows[2]!.block['payload'] as JsonObject)['summary'] = 'edited';
    assert.equal(verifyRows(rows), 'HASH_MISMATCH 2\n');
  });
  await t.test('a matching result closes its call', () => {
    assert.equal(verifyRows(chain([call('c', 'k'), result('c', 'k')])), 'VALID_UNANCHORED 0..2\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
});

test('002 AC-13 precedence', async (t) => {
  await t.test('first failure in file order, then rule order', () => {
    const rows = chain();
    (rows[3]!.block['payload'] as JsonObject)['reason'] = 'x';
    rows[2]!.block['ts'] = 'bad';
    assert.equal(verifyRows(rows), 'TIME_FORMAT_INVALID 2\n');
  });
});

test('002 AC-14 unicode', async (t) => {
  await t.test('a valid escaped surrogate pair is accepted', () => {
    const rows = chain([obj({ ...pausePayload(1), reason: '\u{1F600}' })]);
    const text = serialize(rows).toString('utf8').replace('\u{1F600}', '\\ud83d\\ude00');
    assert.equal(out(chainIdOf(rows), Buffer.from(text)), 'VALID_UNANCHORED 0..1\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
  await t.test('a lone surrogate fails with the location-specific schema error', () => {
    const rows = chain([pausePayload(1), pausePayload(2)]);
    const text = serialize(rows).toString('utf8');
    const lines = text.split('\n');
    lines[2] = lines[2]!.replace('"reason 2"', '"\\ud800"');
    assert.equal(out(chainIdOf(rows), Buffer.from(lines.join('\n'))), 'JCS_SCHEMA_INVALID 2\n');
    const atGenesis = text.replace('"test-pepper"', '"\\udc00"');
    assert.equal(out(chainIdOf(rows), Buffer.from(atGenesis)), 'GENESIS_INVALID 0\n');
  });
});

test('002 AC-15 output-format', async (t) => {
  const rows = chain([call('c', 'k'), pausePayload(1)]);
  const ok = writeInputs(chainIdOf(rows), serialize(rows));
  await t.test('success: exact bytes, exit 0, empty stderr', () => {
    const r = runCli(cliArgs(ok));
    assert.equal(r.status, 0);
    assert.equal(r.stderr.length, 0);
    assert.deepEqual(r.stdout, Buffer.from('VALID_UNANCHORED 0..2\nINCOMPLETE_EXECUTION 1\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n'));
  });
  await t.test('failure: one line <CODE> <parameter>, exit 1, empty stderr', () => {
    const bad = chain();
    (bad[1]!.block['payload'] as JsonObject)['reason'] = 'x';
    const r = runCli(cliArgs(writeInputs(chainIdOf(bad), serialize(bad))));
    assert.equal(r.status, 1);
    assert.equal(r.stderr.length, 0);
    assert.deepEqual(r.stdout, Buffer.from('HASH_MISMATCH 1\n'));
  });
  await t.test('output is deterministic', () => {
    assert.deepEqual(runCli(cliArgs(ok)).stdout, runCli(cliArgs(ok)).stdout);
  });
});

test('002 AC-16 unanchored-success', async (t) => {
  await t.test('VALID_UNANCHORED, one INCOMPLETE_EXECUTION per unmatched call, zero gap and failures', () => {
    const rows = chain([call('a', 'k'), call('b', 'k'), result('a', 'k'), pausePayload(1)]);
    assert.equal(verifyRows(rows), 'VALID_UNANCHORED 0..4\nINCOMPLETE_EXECUTION 2\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
  await t.test('a genesis-only log', () => {
    assert.equal(verifyRows(chain([])), 'VALID_UNANCHORED 0..0\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
});

test('verifier extension points', async (t) => {
  await t.test('namespace entries need Step 2 (spec 003): exit 3, no canonical output', () => {
    const rows = chain();
    const inputs = writeInputs(chainIdOf(rows), serialize(rows));
    fs.writeFileSync(path.join(inputs.checkpointsPath, '10.tsr'), 'x');
    const r = runCli(cliArgs(inputs));
    assert.equal(r.status, 3);
    assert.equal(r.stdout.length, 0);
    assert.match(r.stderr.toString(), /not implemented/);
  });
  await t.test('control events need Step 2b (spec 003): exit 3', () => {
    const rows = chain([pausePayload(1), obj({ event_type: 'checkpoint_failed', operation: 'tear.checkpoint', target_seq: 1, error_type: 'x' })]);
    assert.equal(verifyBytes(chainIdOf(rows), serialize(rows)).exitCode, 3);
  });
  await t.test('.writer.lock is ignored', () => {
    const rows = chain();
    const inputs = writeInputs(chainIdOf(rows), serialize(rows));
    fs.writeFileSync(path.join(inputs.checkpointsPath, '.writer.lock'), '');
    assert.equal(runCli(cliArgs(inputs)).stdout.toString(), OK3);
  });
});
