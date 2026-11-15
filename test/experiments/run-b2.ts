// SPDX-License-Identifier: AGPL-3.0-or-later
// Experiment B2, run once locally: the first 150 application events of the
// synthetic dataset through the real interceptor, anchored by the real TSAs
// (FreeTSA, then DigiCert on failure). Stores the evidence packages taken
// before and after closeChain in experiments/b2/, so the time analysis can be
// repeated offline. Needs local PostgreSQL, network access to the TSAs and
// TEAR_HMAC_PEPPER exported by the operator. Refuses to overwrite artifacts.
//
// Run: npm run experiments:b2

import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildEvidencePackage } from '../../src/chain/evidence.js';
import { provisionNamespace } from '../../src/fs/namespace.js';
import { Interceptor } from '../../src/interceptor/interceptor.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { retainedTsas } from '../../src/tsa/transport.js';
import type { TsaEndpoint } from '../../src/tsa/transport.js';
import { ensureSchema, pgConfig } from '../helpers/pg.js';
import { readDataset, replay } from './replay.js';

const B2_DIR = path.resolve('experiments/b2');
const EVENTS = 150;

async function main(): Promise<void> {
  if (fs.existsSync(B2_DIR)) throw new Error(`${B2_DIR} exists: the B2 artifacts are never regenerated`);
  const bundle = fs.readFileSync(path.resolve('certs/tsa_roots.pem'));
  await ensureSchema();
  const stamps: Record<string, number> = {};
  const tsas: TsaEndpoint[] = retainedTsas().map((t) => ({
    name: t.name,
    request: (tsq) => {
      stamps[t.name] = (stamps[t.name] ?? 0) + 1;
      return t.request(tsq);
    },
  }));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-b2-'));
  const chainId = randomUUID();
  provisionNamespace(root, chainId);
  const { interceptor, writer } = await Interceptor.start({
    checkpointsRoot: root,
    chainId,
    genesisTs: formatTimestamp(Date.now()),
    pepperId: 'b2-pepper',
    bundleBytes: bundle,
    pg: pgConfig,
    profile: 'base',
    tsas,
  });
  const records = await replay(interceptor, readDataset(), EVENTS);
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-b2-out-'));
  await buildEvidencePackage({ checkpointsRoot: root, chainId, pg: pgConfig, bundleBytes: bundle, outDir: path.join(stage, 'pre-close') });
  const closed = await writer.closeChain();
  await writer.close();
  await buildEvidencePackage({ checkpointsRoot: root, chainId, pg: pgConfig, bundleBytes: bundle, outDir: path.join(stage, 'post-close') });
  fs.writeFileSync(
    path.join(stage, 'meta.json'),
    `${JSON.stringify({ description: 'Experiment B2 artifacts (real TSAs), recorded once; analyzed offline by npm run test:experiments.', chain_id: chainId, events: records.length, stamps, close: closed.result }, null, 2)}\n`,
  );
  fs.cpSync(stage, B2_DIR, { recursive: true });
  process.stdout.write(`B2 stored in ${B2_DIR}: ${String(records.length)} events, stamps ${JSON.stringify(stamps)}, close ${closed.result}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`B2 failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
