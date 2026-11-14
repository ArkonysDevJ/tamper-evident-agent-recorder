// SPDX-License-Identifier: AGPL-3.0-or-later
// Requires local PostgreSQL (npm run test:pg).
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { before, test } from 'node:test';
import { exportChain } from '../../src/chain/export.js';
import { runStep1 } from '../../src/chain/step1.js';
import type { RowInput } from '../../src/chain/step1.js';
import { bundleSha256 } from '../../src/crypto/digests.js';
import { parseStrictJson } from '../../src/json/strict-json.js';
import { pausePayload } from '../helpers/chain-builder.js';
import { admin, bundleBytes, codeOf, ensureSchema, initializedWriter, pgConfig } from '../helpers/pg.js';

before(ensureSchema);

function readBack(file: string, chainId: string): ReturnType<typeof runStep1> {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(fs.readFileSync(file));
  assert.ok(text.endsWith('\n'));
  const lines = text.slice(0, -1).split('\n');
  const rows: RowInput[] = lines.map((l) => ({ kind: 'json', value: parseStrictJson(l) }));
  return runStep1(rows, { bundleSha256: bundleSha256(bundleBytes), namespaceChainId: chainId });
}

test('001 AC-25 export', async (t) => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-export-'));
  await t.test('emits the exact canonical rows with a final LF', async () => {
    const { chain, writer } = await initializedWriter();
    for (let i = 1; i <= 5; i++) await writer.append(pausePayload(i));
    await writer.close();
    const file = path.join(out, 'events.jsonl');
    assert.deepEqual(await exportChain({ pg: pgConfig, chainId: chain.chainId, bundleBytes, outPath: file }), { rows: 6 });
    const rows = await admin<{ block_json: string; entry_hash: string }>(
      'SELECT block_json, entry_hash FROM tear_events WHERE chain_id = $1 ORDER BY seq',
      [chain.chainId],
    );
    const expected = rows.map((r) => `{"block":${r.block_json},"entry_hash":"${r.entry_hash}"}\n`).join('');
    assert.equal(fs.readFileSync(file, 'utf8'), expected);
    const r = readBack(file, chain.chainId);
    assert.ok(r.ok);
    assert.equal(r.seqFinal, 5);
  });
  await t.test('a representation failure leaves no output file', async () => {
    const { chain, writer } = await initializedWriter();
    await writer.append(pausePayload(1));
    await writer.close();
    await admin(`UPDATE tear_events SET payload = payload || '{"reason":"x"}' WHERE chain_id = $1 AND seq = 1`, [chain.chainId]);
    const file = path.join(out, 'bad.jsonl');
    assert.equal(
      await codeOf(exportChain({ pg: pgConfig, chainId: chain.chainId, bundleBytes, outPath: file })),
      'RECONCILIATION_STATE_INCONSISTENT',
    );
    assert.equal(fs.existsSync(file), false);
    assert.deepEqual(fs.readdirSync(out).filter((n) => n.startsWith('bad')), []);
  });
});

test('integration provision-initialize-append-export', async (t) => {
  await t.test('25 application events export and read back with valid hashes and links', async () => {
    const { chain, writer } = await initializedWriter();
    for (let i = 1; i <= 25; i++) await writer.append(pausePayload(i));
    await writer.close();
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tear-int-')), 'events.jsonl');
    await exportChain({ pg: pgConfig, chainId: chain.chainId, bundleBytes, outPath: file });
    const r = readBack(file, chain.chainId);
    assert.ok(r.ok, r.ok ? '' : `${r.failure.code} ${r.failure.param}`);
    assert.equal(r.seqFinal, 25);
    assert.equal(r.rows.length, 26);
    for (let i = 1; i < r.rows.length; i++) {
      assert.equal(r.rows[i]!.block.prev_hash, r.rows[i - 1]!.entryHash);
    }
  });
});
