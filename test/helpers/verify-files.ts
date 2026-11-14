// SPDX-License-Identifier: AGPL-3.0-or-later
// Writes verifier inputs (events.jsonl and a namespace directory) for tests.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { bundleSha256 } from '../../src/crypto/digests.js';
import { canonicalize } from '../../src/json/jcs.js';
import { verifyOffline } from '../../src/verify/verify.js';
import type { VerifyInputs, VerifyResult } from '../../src/verify/verify.js';
import type { BuiltRow } from './chain-builder.js';

export const BUNDLE_PATH = path.resolve('certs/tsa_roots.pem');
export const BUNDLE_SHA256 = bundleSha256(fs.readFileSync(BUNDLE_PATH));
export const CLI_PATH = path.resolve('dist/src/cli/tear-verify.js');

export function serialize(rows: BuiltRow[]): Buffer {
  return Buffer.from(rows.map((r) => `{"block":${canonicalize(r.block)},"entry_hash":"${r.entry_hash}"}\n`).join(''), 'utf8');
}

/** Creates <tmp>/<chainId>/ and <tmp>/events.jsonl with the given bytes. */
export function writeInputs(chainId: string, logBytes: Uint8Array): VerifyInputs {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-verify-'));
  const ns = path.join(dir, chainId);
  fs.mkdirSync(ns);
  const log = path.join(dir, 'events.jsonl');
  fs.writeFileSync(log, logBytes);
  return { logPath: log, checkpointsPath: `${ns}/`, bundlePath: BUNDLE_PATH };
}

export function verifyBytes(chainId: string, logBytes: Uint8Array): VerifyResult {
  return verifyOffline(writeInputs(chainId, logBytes));
}

/** stdout of a verification, for compact assertions. */
export function out(chainId: string, logBytes: Uint8Array): string {
  return verifyBytes(chainId, logBytes).stdout;
}

export interface CliRun {
  readonly status: number | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
}

export function runCli(args: string[]): CliRun {
  const r = spawnSync(process.execPath, [CLI_PATH, ...args], { encoding: 'buffer' });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

export function cliArgs(i: VerifyInputs): string[] {
  return ['--log', i.logPath, '--checkpoints', i.checkpointsPath, '--tsa-ca-bundle', i.bundlePath];
}
