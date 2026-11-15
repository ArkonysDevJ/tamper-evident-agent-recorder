// SPDX-License-Identifier: AGPL-3.0-or-later
// Evidence package for offline verification (Blueprint §5.3), safe while a
// writer may be running:
//   1. copy only complete pairs <k>.tsr + <k>.anchor.json from the namespace
//      (skip .writer.lock, every .tsq and .tmp, and a .tsr without its .anchor.json);
//   2. only then run the SQL export.
// A package published after step 1 belongs to a row the export still
// contains, so it shows as ANCHOR_EVIDENCE_MISSING (exit 0), never as
// TRUNCATED_BELOW_ANCHOR or ANCHOR_PACKAGE_INCOMPLETE.

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ClientConfig } from 'pg';
import { TearError } from '../errors.js';
import { namespacePath } from '../fs/namespace.js';
import { readRegularNoFollow } from '../verify/anchors.js';
import { exportChain } from './export.js';

export interface EvidenceOptions {
  readonly checkpointsRoot: string;
  readonly chainId: string;
  readonly pg: ClientConfig;
  readonly bundleBytes: Uint8Array;
  /** Output directory: receives <chainId>/ and events.jsonl. It must not exist yet. */
  readonly outDir: string;
  /** Test seam: runs after the copy and before the export. */
  readonly afterCopyForTests?: () => Promise<void>;
}

export interface EvidenceResult {
  readonly copied: readonly number[];
  readonly rows: number;
  readonly logPath: string;
  readonly checkpointsPath: string;
}

const TSR_RE = /^([1-9][0-9]*)\.tsr$/;

export async function buildEvidencePackage(opts: EvidenceOptions): Promise<EvidenceResult> {
  const nsPath = namespacePath(opts.checkpointsRoot, opts.chainId);
  if (fs.existsSync(opts.outDir)) throw new TearError('EVIDENCE_OUTPUT_EXISTS', opts.outDir);
  const outNs = path.join(opts.outDir, opts.chainId);
  fs.mkdirSync(outNs, { recursive: true });

  // Step 1: complete pairs only.
  const copied: number[] = [];
  for (const name of fs.readdirSync(nsPath).sort()) {
    const m = TSR_RE.exec(name);
    if (m === null) continue;
    const tsr = readRegularNoFollow(path.join(nsPath, name));
    const json = readRegularNoFollow(path.join(nsPath, `${m[1]!}.anchor.json`));
    if (tsr === null || json === null) continue;
    fs.writeFileSync(path.join(outNs, name), tsr);
    fs.writeFileSync(path.join(outNs, `${m[1]!}.anchor.json`), json);
    copied.push(Number(m[1]));
  }
  if (opts.afterCopyForTests !== undefined) await opts.afterCopyForTests();

  // Step 2: the SQL export, from its own read-only REPEATABLE READ snapshot.
  const logPath = path.join(opts.outDir, 'events.jsonl');
  const { rows } = await exportChain({ pg: opts.pg, chainId: opts.chainId, bundleBytes: opts.bundleBytes, outPath: logPath });
  return { copied: copied.sort((a, b) => a - b), rows, logPath, checkpointsPath: outNs };
}
