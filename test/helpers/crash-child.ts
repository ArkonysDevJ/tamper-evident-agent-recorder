// SPDX-License-Identifier: AGPL-3.0-or-later
// Child process for spec 006: writes a run-time test PKI to <pkiDir>, creates a
// chain anchored by an in-process test TSA, and dies by SIGKILL at an exact
// point of the anchor at 10. argv: <root> <chainId> <pkiDir> <mode>
//   e7     after the 10.anchor.json rename, before the directory fsync
//   e1     after unlink(10.tsq), before the directory fsync
//   agent  scripted agent through the interceptor; dies after the 10.tsr rename
//          (before 10.anchor.json is published)

import { randomBytes } from 'node:crypto';
import { autoAnchorHook } from '../../src/anchor/trigger.js';
import { initializeChain } from '../../src/chain/initialize.js';
import { ChainWriter } from '../../src/chain/writer.js';
import { Interceptor } from '../../src/interceptor/interceptor.js';
import { PEPPER_ENV } from '../../src/interceptor/pepper.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { interceptedRecorder, runAgent } from '../agent/scripted-agent.js';
import { RecordingFs } from './fs-double.js';
import { pausePayload } from './chain-builder.js';
import { pgConfig } from './pg.js';
import { savePki } from './pki-files.js';
import { testPki } from './pki.js';
import { testTsa } from './test-tsa.js';
import { namespacePath } from '../../src/fs/namespace.js';

const [root, chainId, pkiDir, mode] = process.argv.slice(2) as [string, string, string, 'e7' | 'e1' | 'agent'];
const pki = testPki(40);
savePki(pki, pkiDir);
const fsd = new RecordingFs(namespacePath(root, chainId));
const dieAfter: Record<typeof mode, string> = {
  e7: 'rename 10.anchor.json.tmp -> 10.anchor.json',
  e1: 'unlink 10.tsq',
  agent: 'rename 10.tsr.tmp -> 10.tsr',
};
fsd.before = (op) => {
  if (op === 'open' && fsd.calls.at(-1) === 'open .' && fsd.calls.at(-2) === dieAfter[mode]) {
    process.stdout.write(`dying after: ${dieAfter[mode]}\n`);
    process.kill(process.pid, 'SIGKILL');
  }
};
const opts = {
  checkpointsRoot: root,
  chainId,
  bundleBytes: pki.bundle,
  pg: pgConfig,
  profile: 'base' as const,
  anchorHook: autoAnchorHook(),
  tsas: [testTsa('test-tsa', pki)],
  fsOps: fsd,
};
if (mode === 'agent') {
  const { interceptor } = await Interceptor.start(
    { ...opts, genesisTs: formatTimestamp(Date.now() - 1000), pepperId: 'crash-pepper' },
    { [PEPPER_ENV]: randomBytes(32).toString('hex') },
  );
  await runAgent(interceptedRecorder(interceptor), 30);
} else {
  await initializeChain({ ...opts, genesisTs: formatTimestamp(Date.now() - 1000), pepperId: 'crash-pepper' });
  const writer = await ChainWriter.open(opts);
  for (let i = 1; i <= 10; i++) await writer.append(pausePayload(i));
}
process.stdout.write('not killed\n');
