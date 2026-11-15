// SPDX-License-Identifier: AGPL-3.0-or-later
// Review finding 3: the value recorded must be the value executed or delivered. A caller or a tool that mutates
// its object while the write is pending must not change what the tool receives or what is delivered (Blueprint
// §4.4: these are JSON values at the adapter boundary).

import assert from 'node:assert/strict';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { before, test } from 'node:test';
import type { AnchorHook } from '../../src/chain/interfaces.js';
import { resultDigest, responseDigest } from '../../src/crypto/digests.js';
import { provisionNamespace } from '../../src/fs/namespace.js';
import { Interceptor } from '../../src/interceptor/interceptor.js';
import { PEPPER_ENV } from '../../src/interceptor/pepper.js';
import { canonicalize } from '../../src/json/jcs.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { admin, bundleBytes, ensureSchema, pgConfig } from '../helpers/pg.js';

before(ensureSchema);

/** Delays the COMMIT of every record, so the caller can act while the write is pending. */
function slowCommits(ms: number, onPending: (seq: number) => void): AnchorHook {
  return {
    onApplicationCommit: async (ctx) => {
      onPending(ctx.seq);
      await new Promise((r) => setTimeout(r, ms));
      return null;
    },
  };
}

async function start(hook: AnchorHook): Promise<{ icp: Interceptor; chainId: string; pepper: Buffer; close: () => Promise<void> }> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-h3-'));
  const chainId = randomUUID();
  provisionNamespace(root, chainId);
  const pepper = randomBytes(32);
  const { interceptor, writer } = await Interceptor.start(
    { checkpointsRoot: root, chainId, genesisTs: formatTimestamp(Date.now() - 1000), pepperId: 'h3', bundleBytes, pg: pgConfig, profile: 'base', anchorHook: hook, tsas: [] },
    { [PEPPER_ENV]: pepper.toString('hex') },
  );
  return { icp: interceptor, chainId, pepper, close: () => writer.close() };
}

async function payload(chainId: string, seq: number): Promise<Record<string, unknown>> {
  const [r] = await admin<{ p: Record<string, unknown> }>('SELECT payload AS p FROM tear_events WHERE chain_id = $1 AND seq = $2', [chainId, seq]);
  return r!.p;
}

test('review H3: recorded value = executed or delivered value', async (t) => {
  await t.test('arguments mutated by the caller while tool_call is being committed', async () => {
    const args: { to: string } = { to: 'alice' };
    const s = await start(slowCommits(150, (seq) => seq === 1 && setTimeout(() => (args.to = 'mallory'), 20)));
    let received: unknown = null;
    s.icp.register('send', (a) => {
      received = JSON.parse(JSON.stringify(a));
      return null;
    });
    try {
      await s.icp.callTool('task-1', 'send', 'c-1', args);
      const recorded = (await payload(s.chainId, 1))['args_hmac'];
      assert.equal(createHmac('sha256', s.pepper).update(canonicalize(received as never)).digest('hex'), recorded, 'the tool received the recorded value');
    } finally {
      await s.close();
    }
  });
  await t.test('a result mutated by the tool while tool_result is being committed', async () => {
    const s = await start(slowCommits(150, () => undefined));
    s.icp.register('compute', () => {
      const out = { value: 1 };
      setTimeout(() => (out.value = 2), 50); // while tool_result is being committed
      return out;
    });
    try {
      const delivered = await s.icp.callTool('task-1', 'compute', 'c-1', {});
      assert.equal(resultDigest(delivered), (await payload(s.chainId, 2))['result_digest'], 'the delivered result is the recorded one');
    } finally {
      await s.close();
    }
  });
  await t.test('a final response mutated by the caller while it is being committed', async () => {
    const response: { text: string } = { text: 'approved' };
    const s = await start(slowCommits(150, (seq) => seq === 1 && setTimeout(() => (response.text = 'rejected'), 20)));
    try {
      const delivered = await s.icp.finalResponse('task-1', response);
      assert.equal(responseDigest(delivered), (await payload(s.chainId, 1))['response_digest'], 'the delivered answer is the recorded one');
    } finally {
      await s.close();
    }
  });
});
