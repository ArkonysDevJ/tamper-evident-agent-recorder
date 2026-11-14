// SPDX-License-Identifier: AGPL-3.0-or-later
// Offline verification (Blueprint §6, §6b). Reads only the exported log, the
// checkpoint namespace and the CA bundle: no PostgreSQL, no network, no pepper.
// Input loading order (§6b): namespace identity/access, log access, bundle.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { isChainId } from '../chain/ids.js';
import { Step1Checker } from '../chain/step1.js';
import { bundleSha256 } from '../crypto/digests.js';
import { WRITER_LOCK_NAME } from '../fs/writer-lock.js';
import { defaultExtensions } from './extensions.js';
import type { VerifierExtensions } from './extensions.js';
import type { LoadedBundle } from '../pki/bundle.js';
import { logRows } from './framing.js';
import {
  EXIT_FAILED,
  EXIT_INPUT_UNAVAILABLE,
  EXIT_OK,
  INPUT_UNAVAILABLE_OUTPUT,
  failureOutput,
  successOutput,
} from './output.js';

export interface VerifyInputs {
  readonly logPath: string;
  readonly checkpointsPath: string;
  readonly bundlePath: string;
}

/**
 * Exit 3 is outside the §6b contract: an internal error (an unclassified
 * exception). stdout is empty and stderr says why; there is no successful
 * verification after it (§6b).
 */
export const EXIT_OUTSIDE_CONTRACT = 3;

export interface VerifyResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

const inputUnavailable: VerifyResult = { exitCode: EXIT_INPUT_UNAVAILABLE, stdout: INPUT_UNAVAILABLE_OUTPUT, stderr: '' };

export function verifyOffline(inputs: VerifyInputs, ext: VerifierExtensions = defaultExtensions): VerifyResult {
  // 1. Namespace identity and access.
  const nsPath = path.resolve(inputs.checkpointsPath);
  const chainId = path.basename(nsPath);
  if (!isChainId(chainId)) return inputUnavailable;
  let entries: string[];
  try {
    if (!fs.statSync(nsPath).isDirectory()) return inputUnavailable;
    entries = fs.readdirSync(nsPath).filter((n) => n !== WRITER_LOCK_NAME).sort();
  } catch {
    return inputUnavailable;
  }

  // 2. Log access.
  let logBytes: Buffer;
  try {
    logBytes = fs.readFileSync(inputs.logPath);
  } catch {
    return inputUnavailable;
  }

  // 3. CA bundle access, grammar and TEAR-TSA-01 loading.
  let bundleBytes: Buffer;
  let bundle: LoadedBundle;
  try {
    bundleBytes = fs.readFileSync(inputs.bundlePath);
    bundle = ext.bundleLoader.load(bundleBytes);
  } catch {
    return inputUnavailable;
  }

  // Step 1: the same rule core the writer uses for admission.
  const checker = new Step1Checker({ bundleSha256: bundleSha256(bundleBytes), namespaceChainId: chainId });
  for (const row of logRows(logBytes)) {
    const failure = checker.accept(row);
    if (failure !== null) return { exitCode: EXIT_FAILED, stdout: failureOutput(failure.code, failure.param), stderr: '' };
  }
  const head = checker.head;
  if (head === undefined) return { exitCode: EXIT_FAILED, stdout: failureOutput('GENESIS_INVALID', 0), stderr: '' };

  // Steps 2 and 2b, and the anchored part of Step 3.
  const anchors = ext.anchorVerifier.verify({ nsPath, chainId, entries, rows: checker.accepted, bundle });
  if (anchors.kind === 'failure') {
    return { exitCode: EXIT_FAILED, stdout: failureOutput(anchors.code, anchors.param), stderr: '' };
  }

  // Step 3.
  return {
    exitCode: EXIT_OK,
    stdout: successOutput(head.block.seq, checker.unmatchedCalls(), anchors.coverage),
    stderr: '',
  };
}
