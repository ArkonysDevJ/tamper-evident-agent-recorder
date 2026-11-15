// SPDX-License-Identifier: AGPL-3.0-or-later
// M3 harness (Blueprint §7, M3): the scripted reference agent on 100
// application events per run, with and without the interceptor, 5 runs each,
// after one unmeasured warm-up run. Needs local PostgreSQL, network access to
// the TSAs for the anchor points, and TEAR_HMAC_PEPPER exported by the operator.
// Writes test-results/m3-results.md and m3-results.json. CI does not run it.
//
// Implementation choice (not normative): each measured run with the interceptor
// is a new chain of its own with max_auto_anchor_seq = 20, so it anchors at 10
// and 20: 10 anchor samples over 5 runs, the fewest that give a p95 here. The
// warm-up run does not anchor (max_auto_anchor_seq = 0).
//
// Run: npm run m3

import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import pg from 'pg';
import { exportChain } from '../../src/chain/export.js';
import { provisionNamespace } from '../../src/fs/namespace.js';
import { Interceptor } from '../../src/interceptor/interceptor.js';
import { readPepper } from '../../src/interceptor/pepper.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { retainedTsas } from '../../src/tsa/transport.js';
import type { TsaEndpoint } from '../../src/tsa/transport.js';
import { verifyOffline } from '../../src/verify/verify.js';
import { directRecorder, interceptedRecorder, runAgent } from '../agent/scripted-agent.js';
import { ensureSchema, pgConfig } from '../helpers/pg.js';
import { renderM3, summarize } from './report.js';
import type { RunSample } from './report.js';

const EVENTS = 100;
const RUNS = 5;
const BUNDLE_PATH = path.resolve('certs/tsa_roots.pem');
const OUT_DIR = path.resolve('test-results');

/** Counts requests per TSA without changing them. */
function counted(stamps: Record<string, number>): TsaEndpoint[] {
  return retainedTsas().map((t) => ({
    name: t.name,
    request: (tsq) => {
      stamps[t.name] = (stamps[t.name] ?? 0) + 1;
      return t.request(tsq);
    },
  }));
}

async function interceptedRun(bundle: Buffer, maxAuto: number, stamps: Record<string, number>): Promise<RunSample> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-m3-'));
  const chainId = randomUUID();
  const nsPath = provisionNamespace(root, chainId);
  const { interceptor, writer } = await Interceptor.start({
    checkpointsRoot: root,
    chainId,
    genesisTs: formatTimestamp(Date.now()),
    pepperId: 'm3-pepper',
    bundleBytes: bundle,
    pg: pgConfig,
    profile: 'base',
    maxAutoAnchorSeq: maxAuto,
    tsas: counted(stamps),
  });
  const timings = await runAgent(interceptedRecorder(interceptor), EVENTS);
  await writer.close();
  const logPath = path.join(root, 'events.jsonl');
  await exportChain({ pg: pgConfig, chainId, bundleBytes: bundle, outPath: logPath });
  const v = verifyOffline({ logPath, checkpointsPath: nsPath, bundlePath: BUNDLE_PATH });
  if (v.exitCode !== 0) throw new Error(`measurement chain does not verify: ${v.stdout}`);
  const recordBytes = fs
    .readFileSync(logPath, 'utf8')
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => Buffer.byteLength(l, 'utf8') + 1);
  const events = timings.flatMap((t) => t.eventsMs.map((ms, i) => ({ ms, anchored: t.anchored[i] === true })));
  return { ordinaryMs: events.filter((e) => !e.anchored).map((e) => e.ms), anchorMs: events.filter((e) => e.anchored).map((e) => e.ms), recordBytes };
}

async function directRun(): Promise<RunSample> {
  const timings = await runAgent(directRecorder, EVENTS);
  return { ordinaryMs: timings.flatMap((t) => t.eventsMs), anchorMs: [], recordBytes: [] };
}

async function environment(): Promise<Record<string, string>> {
  const c = new pg.Client(pgConfig);
  await c.connect();
  const q = async (setting: string): Promise<string> => String((await c.query<{ v: string }>(`SELECT current_setting('${setting}') AS v`)).rows[0]!.v);
  const env: Record<string, string> = {
    'CPU': `${os.cpus()[0]?.model ?? 'unknown'} × ${String(os.cpus().length)}`,
    'Memory': `${String(Math.round(os.totalmem() / 2 ** 30))} GiB`,
    'Kernel': `${os.type()} ${os.release()}`,
    'Node.js': process.version,
    'PostgreSQL': await q('server_version'),
    'synchronous_commit': await q('synchronous_commit'),
    'fsync': await q('fsync'),
    'full_page_writes': await q('full_page_writes'),
    'wal_level': await q('wal_level'),
    'Checkpoint filesystem (statfs type)': `0x${fs.statfsSync(os.tmpdir()).type.toString(16)}`,
  };
  await c.end();
  return env;
}

async function main(): Promise<void> {
  readPepper(); // Stops here, before any write, if the operator has not exported a valid pepper.
  const bundle = fs.readFileSync(BUNDLE_PATH);
  await ensureSchema();
  const stamps: Record<string, number> = {};
  await interceptedRun(bundle, 0, stamps); // Warm-up, unmeasured, no anchors.
  await directRun();
  const withInterceptor: RunSample[] = [];
  const withoutInterceptor: RunSample[] = [];
  for (let r = 0; r < RUNS; r++) {
    withInterceptor.push(await interceptedRun(bundle, 20, stamps));
    withoutInterceptor.push(await directRun());
    process.stdout.write(`run ${String(r + 1)}/${String(RUNS)} done\n`);
  }
  // Provenance: the commit measured and whether the working tree matched it (tracked files only).
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const worktreeClean = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { encoding: 'utf8' }).trim() === '';
  const environment_ = { Commit: `${commit}${worktreeClean ? '' : ' (working tree modified)'}`, ...(await environment()) };
  const input = { withInterceptor, withoutInterceptor, environment: environment_, stamps, eventsPerRun: EVENTS, commit, worktreeClean, finishedAt: new Date().toISOString() };
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, 'm3-results.md'), renderM3(input));
  fs.writeFileSync(path.join(OUT_DIR, 'm3-results.json'), `${JSON.stringify({ ...input, summary: summarize(input) }, null, 2)}\n`);
  process.stdout.write(renderM3(input));
}

main().catch((err: unknown) => {
  process.stderr.write(`m3 failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
