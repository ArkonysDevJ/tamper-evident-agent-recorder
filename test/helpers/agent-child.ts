// SPDX-License-Identifier: AGPL-3.0-or-later
// Child process for spec 005 AC-6: records a tool_call, runs a tool that leaves
// a marker file, and dies (SIGKILL) before its tool_result is committed.
// argv: <checkpointsRoot> <chainId> <markerPath>. The pepper comes from the environment.

import * as fs from 'node:fs';
import { noAnchorHook } from '../../src/chain/interfaces.js';
import { Interceptor } from '../../src/interceptor/interceptor.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { bundleBytes, pgConfig } from './pg.js';

const [root, chainId, marker] = process.argv.slice(2) as [string, string, string];
const { interceptor } = await Interceptor.start({
  checkpointsRoot: root,
  chainId,
  genesisTs: formatTimestamp(Date.now()),
  pepperId: 'child-pepper',
  bundleBytes,
  pg: pgConfig,
  profile: 'base',
  anchorHook: noAnchorHook,
  tsas: [],
});
interceptor.register('send_email', () => {
  fs.appendFileSync(marker, 'sent\n');
  process.stdout.write('tool ran\n');
  process.kill(process.pid, 'SIGKILL');
  return null;
});
await interceptor.epistemicPause('task-1', 'before the call', []);
await interceptor.callTool('task-1', 'send_email', 'call-1', { to: 'someone' });
