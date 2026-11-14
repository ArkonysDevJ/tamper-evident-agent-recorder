// SPDX-License-Identifier: AGPL-3.0-or-later
// Layer 1 of mutual exclusion (Blueprint §5.3): flock(2) on .writer.lock.
// Node.js core does not expose flock(2); fs-ext provides the native binding.
// The lock file is never deleted, renamed or truncated. Its descriptor stays
// open for the writer's lifetime; libuv opens it with O_CLOEXEC, so child
// processes do not inherit it.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { flockSync } from 'fs-ext';
import { TearError } from '../errors.js';

export const WRITER_LOCK_NAME = '.writer.lock';

export class WriterLock {
  private fd: number | null;

  private constructor(fd: number) {
    this.fd = fd;
  }

  /** Opens .writer.lock with O_CREAT | O_RDWR and takes LOCK_EX | LOCK_NB. */
  static acquire(nsPath: string): WriterLock {
    const fd = fs.openSync(path.join(nsPath, WRITER_LOCK_NAME), fs.constants.O_CREAT | fs.constants.O_RDWR, 0o600);
    try {
      flockSync(fd, 'exnb');
    } catch (err) {
      fs.closeSync(fd);
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'EAGAIN' || code === 'EWOULDBLOCK') throw new TearError('WRITER_LOCKED', 'another writer holds the chain lock');
      throw err;
    }
    return new WriterLock(fd);
  }

  get held(): boolean {
    return this.fd !== null;
  }

  /** Releases the lock by closing the descriptor. The file itself stays. */
  release(): void {
    if (this.fd === null) return;
    const fd = this.fd;
    this.fd = null;
    fs.closeSync(fd);
  }
}
