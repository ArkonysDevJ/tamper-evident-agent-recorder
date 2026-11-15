// SPDX-License-Identifier: AGPL-3.0-or-later
// Builds the frozen M1 fixture (Blueprint §7) once, with real receipts from
// both retained TSAs, through the real writer, export and evidence-package
// procedure. It needs local PostgreSQL and network access to the two TSAs,
// and refuses to overwrite an existing fixture: frozen receipts are never
// regenerated.
//
// Implementation choice (not normative): to obtain receipts from both TSAs
// while keeping the §5.7 order, the primary (FreeTSA) is made to fail locally
// with HTTP 503, without contacting it, for anchors 20 and 40; the writer's
// own fallback then obtains real DigiCert receipts. Anchors 10 and 30 come
// from FreeTSA.
//
// Run: npm run fixture:build

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { autoAnchorHook } from '../../src/anchor/trigger.js';
import { exportChain } from '../../src/chain/export.js';
import { initializeChain } from '../../src/chain/initialize.js';
import { ChainWriter } from '../../src/chain/writer.js';
import { bundleSha256, sha256Hex } from '../../src/crypto/digests.js';
import { provisionNamespace } from '../../src/fs/namespace.js';
import { formatTimestamp } from '../../src/time/timestamps.js';
import { parseReceipt } from '../../src/tsa/receipt.js';
import { RETAINED_TSA_URLS, httpTsa } from '../../src/tsa/transport.js';
import type { TsaEndpoint } from '../../src/tsa/transport.js';
import { verifyOffline } from '../../src/verify/verify.js';
import { obj } from '../helpers/chain-builder.js';
import { cleanE1ForTests, ensureSchema, pgConfig } from '../helpers/pg.js';
import { FIXTURE_DIR, describeReceipt } from './fixture-files.js';

const BUNDLE_PATH = path.resolve('certs/tsa_roots.pem');
const FORCED_PRIMARY_FAILURE = new Set([20, 40]);
const EXPECTED_TSA: Record<number, string> = { 10: 'freetsa', 20: 'digicert', 30: 'freetsa', 40: 'digicert' };
const MIN_GAP_MS = 150;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** The primary with a local forced failure for chosen anchors; a pause keeps timestamps >= 100 ms apart. */
function primary(anchorOrder: number[]): TsaEndpoint {
  const real = httpTsa('freetsa', RETAINED_TSA_URLS.freetsa);
  let call = 0;
  return {
    name: 'freetsa',
    async request(tsq) {
      const k = anchorOrder[call++]!;
      await sleep(MIN_GAP_MS);
      if (FORCED_PRIMARY_FAILURE.has(k)) return { kind: 'failure', reason: 'http_status', detail: '503 (forced locally, not sent)' };
      return real.request(tsq);
    },
  };
}

function pause(seq: number): ReturnType<typeof obj> {
  return obj({
    event_type: 'epistemic_pause',
    operation: 'tear.epistemic_pause',
    task_id: `fixture-task-${String(seq)}`,
    reason: seq === 25 ? 'baseline' : `fixture pause ${String(seq)}`,
    missing_sources: [],
  });
}

async function main(): Promise<void> {
  if (fs.existsSync(FIXTURE_DIR)) throw new Error(`${FIXTURE_DIR} exists: frozen receipts are never regenerated`);
  const bundle = fs.readFileSync(BUNDLE_PATH);
  await ensureSchema();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-fixture-'));
  const chainId = randomUUID();
  const nsPath = provisionNamespace(root, chainId);
  await initializeChain({
    checkpointsRoot: root,
    chainId,
    genesisTs: formatTimestamp(Date.now()),
    pepperId: 'fixture-pepper',
    bundleBytes: bundle,
    pg: pgConfig,
    profile: 'base',
  });
  // Historical note: the frozen fixture was built before spec 006, with the clean-E1 test classifier.
  const writer = await ChainWriter.open({
    checkpointsRoot: root,
    chainId,
    bundleBytes: bundle,
    pg: pgConfig,
    profile: 'base',
    classifier: cleanE1ForTests,
    anchorHook: autoAnchorHook(40),
    tsas: [primary([10, 20, 30, 40]), httpTsa('digicert', RETAINED_TSA_URLS.digicert)],
    exit: (cause) => {
      throw cause instanceof Error ? cause : new Error(String(cause));
    },
  });
  const anchors: Record<number, { tsa: string; attempts: unknown }> = {};
  while (writer.headSeq < 50) {
    await sleep(MIN_GAP_MS);
    const seq = writer.headSeq + 1;
    const r = await writer.append(pause(seq));
    if (r.anchor !== undefined) {
      if (r.anchor.kind !== 'anchored' || r.anchor.tsa !== EXPECTED_TSA[r.anchor.k]) {
        throw new Error(`anchor ${String(r.anchor.k)}: ${JSON.stringify(r.anchor)}`);
      }
      anchors[r.anchor.k] = { tsa: r.anchor.tsa, attempts: r.anchor.attempts };
      process.stdout.write(`anchor ${String(r.anchor.k)}: ${r.anchor.tsa}\n`);
    }
  }
  await writer.close();

  // Evidence package for offline verification (§5.3): complete pairs first, then the export.
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-fixture-out-'));
  const outNs = path.join(stage, chainId);
  fs.mkdirSync(outNs);
  for (const name of fs.readdirSync(nsPath).sort()) {
    const m = /^([1-9][0-9]*)\.tsr$/.exec(name);
    if (m === null || !fs.existsSync(path.join(nsPath, `${m[1]!}.anchor.json`))) continue;
    fs.copyFileSync(path.join(nsPath, name), path.join(outNs, name));
    fs.copyFileSync(path.join(nsPath, `${m[1]!}.anchor.json`), path.join(outNs, `${m[1]!}.anchor.json`));
  }
  const logPath = path.join(stage, 'events.jsonl');
  await exportChain({ pg: pgConfig, chainId, bundleBytes: bundle, outPath: logPath });

  // §7: strictly increasing timestamps, at least 100 ms apart.
  const ts = fs
    .readFileSync(logPath, 'utf8')
    .trimEnd()
    .split('\n')
    .map((l) => Date.parse((JSON.parse(l) as { block: { ts: string } }).block.ts));
  for (let i = 1; i < ts.length; i++) {
    if (ts[i]! - ts[i - 1]! < 100) throw new Error(`rows ${String(i - 1)} and ${String(i)} are less than 100 ms apart`);
  }

  const result = verifyOffline({ logPath, checkpointsPath: outNs, bundlePath: BUNDLE_PATH });
  if (result.exitCode !== 0 || !result.stdout.startsWith('VERIFIED_ANCHORED 0..40\nVALID_UNANCHORED 41..50\n')) {
    throw new Error(`fixture does not verify: ${result.stdout}`);
  }

  const files: Record<string, string> = { 'events.jsonl': sha256Hex(fs.readFileSync(logPath)) };
  const receipts = [10, 20, 30, 40].map((k) => {
    const tsr = fs.readFileSync(path.join(outNs, `${String(k)}.tsr`));
    files[`${chainId}/${String(k)}.tsr`] = sha256Hex(tsr);
    files[`${chainId}/${String(k)}.anchor.json`] = sha256Hex(fs.readFileSync(path.join(outNs, `${String(k)}.anchor.json`)));
    const parsed = parseReceipt(tsr);
    if (!parsed.ok) throw new Error(`receipt ${String(k)} does not parse`);
    return { k, tsa: anchors[k]!.tsa, attempts: anchors[k]!.attempts, ...describeReceipt(tsr, parsed.receipt) };
  });
  const manifest = {
    description: 'Frozen M1 fixture (Blueprint §7). Built once with real receipts; never regenerated.',
    built_at: new Date().toISOString(),
    chain_id: chainId,
    tsa_ca_bundle_sha256: bundleSha256(bundle),
    max_auto_anchor_seq: 40,
    rows: 51,
    files,
    receipts,
    expected_stdout: result.stdout,
    expected_exit_code: 0,
  };
  fs.writeFileSync(path.join(stage, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  fs.mkdirSync(path.dirname(FIXTURE_DIR), { recursive: true });
  fs.cpSync(stage, FIXTURE_DIR, { recursive: true });
  process.stdout.write(`fixture written to ${FIXTURE_DIR}\n${result.stdout}`);
}

main().catch((err: unknown) => {
  process.stderr.write(`fixture build failed: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});
