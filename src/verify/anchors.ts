// SPDX-License-Identifier: AGPL-3.0-or-later
// Steps 2, 2b and the anchored part of Step 3 of tear-verify (Blueprint §6,
// §6b), under TEAR-TSA-01 (§6a). Inputs are only the namespace, the log rows
// already checked by Step 1 and the loaded bundle.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { checkAnchorPackage } from '../anchor/package.js';
import type { AnchorPackage } from '../anchor/package.js';
import type { AcceptedRow } from '../chain/step1.js';
import { sha256Hex } from '../crypto/digests.js';
import { canonicalize } from '../json/jcs.js';
import type { LoadedBundle } from '../pki/bundle.js';
import { checkCommitment, checkSignature, parseReceipt, timePredicate } from '../tsa/receipt.js';
import type { Accuracy } from '../tsa/receipt.js';

export type StepFailure = { readonly code: string; readonly param: bigint };

const PACKAGE_RE = /^([1-9][0-9]*)\.(tsr|anchor\.json)$/;
const PREFIX_RE = /^([1-9][0-9]*)\./;

/** Opens without following symlinks and requires a regular file; returns its bytes or null. */
export function readRegularNoFollow(p: string): Buffer | null {
  let fd: number;
  try {
    fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  } catch {
    return null;
  }
  try {
    if (!fs.fstatSync(fd).isFile()) return null;
    return fs.readFileSync(fd);
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

function openableRegular(p: string): boolean {
  try {
    if (!fs.lstatSync(p).isFile()) return false;
  } catch {
    return false;
  }
  let fd: number;
  try {
    fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  } catch {
    return false;
  }
  try {
    return fs.fstatSync(fd).isFile();
  } finally {
    fs.closeSync(fd);
  }
}

function inventoryParam(name: string): bigint {
  const m = PREFIX_RE.exec(name);
  return m === null ? 0n : BigInt(m[1]!);
}

/**
 * Canonical inventory (Step 2): returns the package numbers in ascending order,
 * or the inventory failure with the smallest derived parameter.
 */
export function inventoryPackages(nsPath: string, entries: readonly string[]): bigint[] | StepFailure {
  const failures: bigint[] = [];
  const kinds = new Map<bigint, Set<string>>();
  for (const name of entries) {
    const m = PACKAGE_RE.exec(name);
    if (m === null || !openableRegular(path.join(nsPath, name))) {
      failures.push(inventoryParam(name));
      continue;
    }
    const k = BigInt(m[1]!);
    const set = kinds.get(k) ?? new Set<string>();
    set.add(m[2]!);
    kinds.set(k, set);
  }
  for (const [k, set] of kinds) if (set.size !== 2) failures.push(k);
  if (failures.length > 0) {
    const min = failures.reduce((a, b) => (b < a ? b : a));
    return { code: 'ANCHOR_PACKAGE_INCOMPLETE', param: min };
  }
  return [...kinds.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

export interface ValidPackage {
  readonly k: number;
  readonly pkg: AnchorPackage;
  readonly genTime: string;
  readonly genTimeNs: bigint;
  readonly accuracy: Accuracy | null;
  readonly tsrSha256: string;
}

/** Steps 2.1 to 2.7 for one complete package. */
export function checkPackage(
  nsPath: string,
  kBig: bigint,
  chainId: string,
  rows: readonly AcceptedRow[],
  bundle: LoadedBundle,
): ValidPackage | StepFailure {
  const fail = (code: string): StepFailure => ({ code, param: kBig });
  const k = kBig <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(kBig) : -1;

  // 2.1 package JSON schema and identity.
  const json = readRegularNoFollow(path.join(nsPath, `${kBig}.anchor.json`));
  const pkg = json === null || k < 1 ? null : checkAnchorPackage(json, chainId, k);
  if (pkg === null) return fail('ANCHOR_PACKAGE_INCOMPLETE');

  // 2.2 structure and genTime syntax.
  const tsr = readRegularNoFollow(path.join(nsPath, `${kBig}.tsr`));
  if (tsr === null) return fail('TSA_SIGNATURE_INVALID');
  const parsed = parseReceipt(tsr);
  if (!parsed.ok) return fail(parsed.stage === 'structure' ? 'TSA_SIGNATURE_INVALID' : 'TSA_TIME_FORMAT_INVALID');

  // 2.3 signature, signer identity and path.
  if (checkSignature(parsed.receipt, parsed.genTimeNs, bundle) !== null) return fail('TSA_SIGNATURE_INVALID');

  // 2.4 commitment.
  if (!checkCommitment(parsed.receipt, pkg.entryHash, pkg.nonceHex)) return fail('ANCHOR_COMMITMENT_MISMATCH');

  // 2.5 log range.
  const row = rows[k];
  if (row === undefined) return fail('TRUNCATED_BELOW_ANCHOR');

  // 2.6 log commitment.
  if (pkg.entryHash !== row.entryHash || canonicalize(pkg.block) !== canonicalize(row.block)) {
    return fail('CHECKPOINT_DIVERGENCE');
  }

  // 2.7 temporal predicate against log row k.
  if (!timePredicate(parsed.genTimeNs, row.tsNs)) return fail('TSA_TIME_INCONSISTENT');

  return {
    k,
    pkg,
    genTime: parsed.receipt.tstInfo.genTime,
    genTimeNs: parsed.genTimeNs,
    accuracy: parsed.receipt.tstInfo.accuracy,
    tsrSha256: sha256Hex(tsr),
  };
}

export interface ControlResult {
  readonly evidenceMissing: number[];
}

/** Step 2b: control relations, after every presented package passed Step 2. */
export function checkControls(rows: readonly AcceptedRow[], valid: ReadonlyMap<number, ValidPackage>): ControlResult | StepFailure {
  const evidenceMissing: number[] = [];
  for (const row of rows) {
    const p = row.block.payload;
    const type = p['event_type'];
    if (type !== 'checkpoint_anchored' && type !== 'checkpoint_failed') continue;
    const seq = row.block.seq;
    const target = type === 'checkpoint_anchored' ? p['anchored_seq'] : p['target_seq'];
    if (typeof target !== 'number' || target !== seq - 1 || target < 1 || rows[target] === undefined) {
      return { code: 'CONTROL_EVENT_INVALID', param: BigInt(seq) };
    }
    if (type !== 'checkpoint_anchored') continue;
    const pkg = valid.get(target);
    if (pkg === undefined) {
      evidenceMissing.push(target);
      continue;
    }
    if (p['tsr_sha256'] !== pkg.tsrSha256 || p['tsa_gen_time'] !== pkg.genTime) {
      return { code: 'CHECKPOINT_METADATA_MISMATCH', param: BigInt(seq) };
    }
  }
  return { evidenceMissing };
}

/** One ANCHOR_TIME line (§6b group 7). Accuracy subfields that are absent count as zero. */
export function anchorTimeLine(p: ValidPackage): string {
  const a = p.accuracy;
  if (a === null) return `ANCHOR_TIME ${String(p.k)} ${p.genTime} ACCURACY_NS unspecified LATEST_BOUND_NS unspecified`;
  const ns = (a.seconds ?? 0n) * 1_000_000_000n + (a.millis ?? 0n) * 1_000_000n + (a.micros ?? 0n) * 1_000n;
  return `ANCHOR_TIME ${String(p.k)} ${p.genTime} ACCURACY_NS ${ns.toString()} LATEST_BOUND_NS ${(p.genTimeNs + ns).toString()}`;
}
