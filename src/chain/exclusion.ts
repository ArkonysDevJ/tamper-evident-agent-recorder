// SPDX-License-Identifier: AGPL-3.0-or-later
// Start-up order shared by initializeChain and the writer (Blueprint §5.1, §5.3):
// namespace checks before PostgreSQL, then flock, then writerConn with its
// session advisory lock. Nothing reads chain state before both locks are held.

import type { ClientConfig } from 'pg';
import { WriterConn } from '../db/writer-conn.js';
import { TearError } from '../errors.js';
import { assertProvisioned, assertSupportedFilesystem, namespacePath } from '../fs/namespace.js';
import type { StatfsType } from '../fs/namespace.js';
import { WriterLock } from '../fs/writer-lock.js';

export interface ExclusionOptions {
  readonly checkpointsRoot: string;
  readonly chainId: string;
  readonly pg: ClientConfig;
  /** Test seam for the statfs(2) guard. */
  readonly statfsType?: StatfsType;
}

export interface Exclusion {
  readonly nsPath: string;
  readonly lock: WriterLock;
  readonly conn: WriterConn;
}

export async function acquireExclusion(opts: ExclusionOptions): Promise<Exclusion> {
  const nsPath = namespacePath(opts.checkpointsRoot, opts.chainId);
  assertProvisioned(nsPath);
  assertSupportedFilesystem(opts.checkpointsRoot, nsPath, opts.statfsType);
  const lock = WriterLock.acquire(nsPath);
  let conn: WriterConn | null;
  try {
    conn = await WriterConn.open(opts.pg, opts.chainId);
  } catch (err) {
    lock.release();
    throw err;
  }
  if (conn === null) {
    lock.release();
    throw new TearError('ADVISORY_LOCK_UNAVAILABLE', 'another session holds the chain advisory lock');
  }
  return { nsPath, lock, conn };
}

/** Normal release: close writerConn (which releases the advisory lock), then flock. */
export async function releaseExclusion(ex: Exclusion): Promise<void> {
  await ex.conn.close();
  ex.lock.release();
}
