// SPDX-License-Identifier: AGPL-3.0-or-later
// Checkpoint namespace provisioning and start-up filesystem contract
// (Blueprint §5.1, §5.2). Provisioning is a separate step; the writer and the
// recoverer never create the namespace or its ancestors.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { isChainId } from '../chain/ids.js';
import { TearError } from '../errors.js';

/** statfs(2) magic numbers accepted at runtime (§5.1). */
export const EXT_FAMILY_MAGIC = 0xef53;
export const XFS_MAGIC = 0x58465342;

/** Filesystem operations used by provisioning; injectable so tests can check call order. */
export interface ProvisionOps {
  mkdirIfMissing(dir: string): void;
  fsyncDir(dir: string): void;
}

/**
 * Opens a directory with O_RDONLY | O_DIRECTORY, fsyncs it and closes it in finally.
 * libuv opens every descriptor with O_CLOEXEC, so the descriptor is never inherited.
 */
export function fsyncDirectory(dir: string): void {
  const fd = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export const realProvisionOps: ProvisionOps = {
  mkdirIfMissing(dir) {
    try {
      fs.mkdirSync(dir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      if (!fs.lstatSync(dir).isDirectory()) throw err;
    }
  },
  fsyncDir: fsyncDirectory,
};

export function assertChainId(chainId: string): void {
  if (!isChainId(chainId)) throw new TearError('CHAIN_ID_INVALID', 'chain_id must be a lowercase canonical UUID');
}

/** The namespace path for a chain. Validates chain_id before building any path. */
export function namespacePath(checkpointsRoot: string, chainId: string): string {
  assertChainId(chainId);
  return path.join(path.resolve(checkpointsRoot), chainId);
}

/**
 * Provisioning (§5.1): create every missing level down to <chain_id> and, for
 * every level, fsync its parent directory unconditionally.
 */
export function provisionNamespace(checkpointsRoot: string, chainId: string, ops: ProvisionOps = realProvisionOps): string {
  const target = namespacePath(checkpointsRoot, chainId);
  const parts = target.split(path.sep).filter((p) => p.length > 0);
  let current: string = path.sep;
  for (const part of parts) {
    const parent = current;
    current = path.join(current, part);
    ops.mkdirIfMissing(current);
    ops.fsyncDir(parent);
  }
  return target;
}

/** Start-up check: the namespace exists as a directory. Fails before any PostgreSQL work. */
export function assertProvisioned(nsPath: string): void {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(nsPath);
  } catch {
    throw new TearError('NAMESPACE_NOT_PROVISIONED', nsPath);
  }
  if (!st.isDirectory()) throw new TearError('NAMESPACE_NOT_PROVISIONED', nsPath);
}

export type StatfsType = (p: string) => number;
export const realStatfsType: StatfsType = (p) => fs.statfsSync(p).type;

/** Runtime statfs(2) guard on the checkpoint root and the namespace (§5.1). */
export function assertSupportedFilesystem(checkpointsRoot: string, nsPath: string, statfsType: StatfsType = realStatfsType): void {
  for (const p of [checkpointsRoot, nsPath]) {
    const type = statfsType(p);
    if (type !== EXT_FAMILY_MAGIC && type !== XFS_MAGIC) {
      throw new TearError('FILESYSTEM_UNSUPPORTED', `${p}: statfs type 0x${type.toString(16)}`);
    }
  }
}
