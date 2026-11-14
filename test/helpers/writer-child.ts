// SPDX-License-Identifier: AGPL-3.0-or-later
// Child process for writer handoff tests.
//   argv: <mode> <checkpointsRoot> <chainId>
//   hold            open the writer and hold it
//   inflight-open   append with a transaction still open (pg_sleep before COMMIT)
//   inflight-done   append and commit, then keep the session busy (pg_sleep)
// Prints "ready" when the parent may kill the process.

import { ChainWriter } from '../../src/chain/writer.js';
import { pausePayload } from './chain-builder.js';
import { writerOptions } from './pg.js';

const [mode, root, chainId] = process.argv.slice(2);
if (mode === undefined || root === undefined || chainId === undefined) throw new Error('usage');
const chain = { root, chainId, nsPath: '', genesisTs: '' };

const SLEEP = 'SELECT pg_sleep(4)';

if (mode === 'hold') {
  await ChainWriter.open(writerOptions(chain));
  process.stdout.write('ready\n');
  setInterval(() => undefined, 1000);
} else if (mode === 'inflight-open') {
  const writer = await ChainWriter.open(
    writerOptions(chain, {
      anchorHook: {
        onApplicationCommit: async (ctx) => {
          process.stdout.write('ready\n');
          await ctx.query(SLEEP);
        },
      },
    }),
  );
  await writer.append(pausePayload(1));
} else if (mode === 'inflight-done') {
  const writer = await ChainWriter.open(writerOptions(chain));
  await writer.append(pausePayload(1));
  const pending = writer.connForTests.query(SLEEP);
  process.stdout.write('ready\n');
  await pending;
} else {
  throw new Error(`unknown mode ${mode}`);
}
