// SPDX-License-Identifier: AGPL-3.0-or-later
// A DurableFsOps double: records every call (with paths relative to a base
// directory) and delegates to the real file system, optionally failing one call.

import * as path from 'node:path';
import { realDurableFsOps } from '../../src/fs/durable.js';
import type { DurableFsOps, MutationGuard } from '../../src/fs/durable.js';

export type OpName = keyof DurableFsOps;

export class RecordingFs implements DurableFsOps {
  readonly calls: string[] = [];
  private readonly fdPaths = new Map<number, string>();
  /** Fail the n-th call (1-based) of this operation with this errno code. */
  failOn: { op: OpName; nth: number; code: string } | null = null;
  /** Hook run before each call, after it is recorded. */
  before: ((op: OpName, calls: readonly string[]) => Promise<void> | void) | null = null;
  private counts = new Map<OpName, number>();

  constructor(private readonly base: string) {}

  private rel(p: string): string {
    const r = path.relative(this.base, p);
    return r === '' ? '.' : r;
  }

  private async step<T>(op: OpName, label: string, run: () => Promise<T>): Promise<T> {
    this.calls.push(`${op} ${label}`);
    if (this.before !== null) await this.before(op, this.calls);
    const n = (this.counts.get(op) ?? 0) + 1;
    this.counts.set(op, n);
    if (this.failOn !== null && this.failOn.op === op && this.failOn.nth === n) {
      const err = new Error(`injected ${this.failOn.code} on ${op}`) as NodeJS.ErrnoException;
      err.code = this.failOn.code;
      throw err;
    }
    return run();
  }

  open(file: string, flags: number, mode?: number): Promise<number> {
    return this.step('open', this.rel(file), async () => {
      const fd = await realDurableFsOps.open(file, flags, mode);
      this.fdPaths.set(fd, this.rel(file));
      return fd;
    });
  }
  write(fd: number, data: Uint8Array): Promise<void> {
    return this.step('write', this.fdPaths.get(fd) ?? '?', () => realDurableFsOps.write(fd, data));
  }
  fsync(fd: number): Promise<void> {
    return this.step('fsync', this.fdPaths.get(fd) ?? '?', () => realDurableFsOps.fsync(fd));
  }
  close(fd: number): Promise<void> {
    return this.step('close', this.fdPaths.get(fd) ?? '?', () => realDurableFsOps.close(fd));
  }
  rename(from: string, to: string): Promise<void> {
    return this.step('rename', `${this.rel(from)} -> ${this.rel(to)}`, () => realDurableFsOps.rename(from, to));
  }
  unlink(file: string): Promise<void> {
    return this.step('unlink', this.rel(file), () => realDurableFsOps.unlink(file));
  }
  isRegularFile(fd: number): Promise<boolean> {
    return this.step('isRegularFile', this.fdPaths.get(fd) ?? '?', () => realDurableFsOps.isRegularFile(fd));
  }
}

export class TestGuard implements MutationGuard {
  invalidated = false;
  invalidate(): void {
    this.invalidated = true;
  }
}
