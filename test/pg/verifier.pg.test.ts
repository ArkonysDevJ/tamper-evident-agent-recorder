// SPDX-License-Identifier: AGPL-3.0-or-later
// Requires local PostgreSQL (npm run test:pg).
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { before, test } from 'node:test';
import { exportChain } from '../../src/chain/export.js';
import { EventRejectedError } from '../../src/chain/writer.js';
import { entryHashOf } from '../../src/crypto/digests.js';
import { canonicalize } from '../../src/json/jcs.js';
import { parseStrictJson } from '../../src/json/strict-json.js';
import type { JsonObject } from '../../src/json/strict-json.js';
import { verifyOffline } from '../../src/verify/verify.js';
import { obj, pausePayload } from '../helpers/chain-builder.js';
import { bundleBytes, ensureSchema, initializedWriter, pgConfig } from '../helpers/pg.js';
import { BUNDLE_PATH, cliArgs, runCli } from '../helpers/verify-files.js';

before(ensureSchema);

/** Exports a chain of n pause events and returns the verifier inputs. */
async function exported(n: number): Promise<{ chainId: string; logPath: string; nsPath: string }> {
  const { chain, writer } = await initializedWriter();
  for (let i = 1; i <= n; i++) await writer.append(pausePayload(i));
  await writer.close();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-vpg-'));
  const logPath = path.join(dir, 'events.jsonl');
  await exportChain({ pg: pgConfig, chainId: chain.chainId, bundleBytes, outPath: logPath });
  const nsPath = path.join(dir, chain.chainId);
  fs.mkdirSync(nsPath);
  return { chainId: chain.chainId, logPath, nsPath };
}

function verifyText(e: { logPath: string; nsPath: string }, text: Buffer | string): string {
  const p = path.join(path.dirname(e.logPath), `variant-${Math.random().toString(16).slice(2)}.jsonl`);
  fs.writeFileSync(p, text);
  return verifyOffline({ logPath: p, checkpointsPath: e.nsPath, bundlePath: BUNDLE_PATH }).stdout;
}

test('002 AC-17 export-framing', async (t) => {
  const e = await exported(5);
  const bytes = fs.readFileSync(e.logPath);
  await t.test('the export passes full offline framing', () => {
    assert.equal(verifyText(e, bytes), 'VALID_UNANCHORED 0..5\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
  await t.test('malformed copies fail with their framing diagnostic', () => {
    assert.equal(verifyText(e, bytes.subarray(0, -1)), 'JCS_SCHEMA_INVALID 5\n');
    assert.equal(verifyText(e, Buffer.concat([bytes, Buffer.from('\n')])), 'JCS_SCHEMA_INVALID 6\n');
    assert.equal(verifyText(e, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes])), 'GENESIS_INVALID 0\n');
  });
});

test('shared Step 1 core: writer admission and verifier give the same diagnostic', async (t) => {
  await t.test('a tool_result without its call', async () => {
    const result = obj({
      event_type: 'tool_result',
      operation: 'execute_tool',
      call_id: 'never-called',
      task_id: 'k',
      error_type: null,
      result_digest: 'a'.repeat(64),
      summary: 's',
    });
    const { chain, writer } = await initializedWriter();
    await writer.append(pausePayload(1));
    let writerDiag = '';
    try {
      await writer.append(result);
    } catch (err) {
      assert.ok(err instanceof EventRejectedError);
      writerDiag = `${err.rejection.code} ${String(err.rejection.param)}`;
    }
    await writer.close();

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-shared-'));
    const logPath = path.join(dir, 'events.jsonl');
    await exportChain({ pg: pgConfig, chainId: chain.chainId, bundleBytes, outPath: logPath });
    // Forge the rejected row onto the export, with a valid link and hash.
    const lines = fs.readFileSync(logPath, 'utf8').trimEnd().split('\n');
    const head = parseStrictJson(lines[lines.length - 1]!) as JsonObject;
    const headBlock = head['block'] as JsonObject;
    const block = obj({
      chain_id: chain.chainId,
      seq: 2,
      ts: headBlock['ts'] as string,
      prev_hash: head['entry_hash'] as string,
      payload: result,
    });
    fs.appendFileSync(logPath, `{"block":${canonicalize(block)},"entry_hash":"${entryHashOf(block)}"}\n`);
    fs.mkdirSync(path.join(dir, chain.chainId));
    const verifierDiag = verifyOffline({ logPath, checkpointsPath: path.join(dir, chain.chainId), bundlePath: BUNDLE_PATH }).stdout;

    assert.equal(writerDiag, 'CALL_CORRELATION_INVALID 2');
    assert.equal(verifierDiag, `${writerDiag}\n`);
  });
});

test('integration 25-event export verifies and detects edits', async (t) => {
  const e = await exported(25);
  const text = fs.readFileSync(e.logPath, 'utf8');
  const lines = text.slice(0, -1).split('\n');
  await t.test('the exported chain verifies', () => {
    assert.equal(verifyText(e, text), 'VALID_UNANCHORED 0..25\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
  await t.test('one altered byte → HASH_MISMATCH 7', () => {
    const edited = [...lines];
    edited[7] = edited[7]!.replace('"reason 7"', '"reason X"');
    assert.notEqual(edited[7], lines[7]);
    assert.equal(verifyText(e, edited.join('\n') + '\n'), 'HASH_MISMATCH 7\n');
  });
  await t.test('one deleted row → SEQ_GAP 12', () => {
    const deleted = lines.filter((_, i) => i !== 12);
    assert.equal(verifyText(e, deleted.join('\n') + '\n'), 'SEQ_GAP 12\n');
  });
  await t.test('two reordered rows → SEQ_GAP 10', () => {
    const swapped = [...lines];
    [swapped[10], swapped[11]] = [swapped[11]!, swapped[10]!];
    assert.equal(verifyText(e, swapped.join('\n') + '\n'), 'SEQ_GAP 10\n');
  });
  await t.test('two runs of the command produce identical bytes', () => {
    const args = cliArgs({ logPath: e.logPath, checkpointsPath: e.nsPath, bundlePath: BUNDLE_PATH });
    const a = runCli(args);
    const b = runCli(args);
    assert.equal(a.status, 0);
    assert.deepEqual(a.stdout, b.stdout);
    assert.deepEqual(a.stderr, b.stderr);
  });
});
