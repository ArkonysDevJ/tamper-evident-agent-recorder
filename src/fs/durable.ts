// SPDX-License-Identifier: AGPL-3.0-or-later
// Durable publish, durable delete and the recovered-package durability barrier
// inside a provisioned checkpoint namespace (Blueprint §5.5), under the
// invalidation and mutation barrier of §5.3.
//
// - Every operation runs on one strict FIFO queue per namespace and is tracked
//   until it settles; drain() waits for all of them.
// - The guard (writerInvalidated == false and writerConn connected) is checked
//   before the operation begins and again before each mutating system call.
// - Any failure invalidates the writer, stops admitting work and runs the
//   drain-and-exit handler. Nothing is cleaned up: a partial .tmp or an
//   unconfirmed rename is left for inspection and recovery.
// Descriptors come from libuv, which opens every file with O_CLOEXEC on Linux;
// Node.js does not expose that flag.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { TearError } from '../errors.js';
import { SerialQueue } from '../util/serial-queue.js';
import { WRITER_LOCK_NAME } from './writer-lock.js';

/** The writer state that every namespace mutation must check (§5.3). */
export interface MutationGuard {
  /** True once writerInvalidated is set or writerConn is no longer connected. */
  readonly invalidated: boolean;
  invalidate(): void;
}

/** File system calls used by the primitives; injectable for fault-injection tests. */
export interface DurableFsOps {
  open(file: string, flags: number, mode?: number): Promise<number>;
  write(fd: number, data: Uint8Array): Promise<void>;
  fsync(fd: number): Promise<void>;
  close(fd: number): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  unlink(file: string): Promise<void>;
  isRegularFile(fd: number): Promise<boolean>;
}

function call<T>(fn: (cb: (err: NodeJS.ErrnoException | null, value: T) => void) => void): Promise<T> {
  return new Promise((resolve, reject) => fn((err, value) => (err ? reject(err) : resolve(value))));
}

export const realDurableFsOps: DurableFsOps = {
  open: (file, flags, mode) => call<number>((cb) => fs.open(file, flags, mode ?? 0o600, cb)),
  async write(fd, data) {
    let offset = 0;
    while (offset < data.length) {
      const written = await call<number>((cb) => fs.write(fd, data, offset, data.length - offset, null, cb));
      offset += written;
    }
  },
  fsync: (fd) => call<void>((cb) => fs.fsync(fd, (err) => cb(err, undefined))),
  close: (fd) => call<void>((cb) => fs.close(fd, (err) => cb(err ?? null, undefined))),
  rename: (from, to) => call<void>((cb) => fs.rename(from, to, (err) => cb(err, undefined))),
  unlink: (file) => call<void>((cb) => fs.unlink(file, (err) => cb(err, undefined))),
  isRegularFile: async (fd) => (await call<fs.Stats>((cb) => fs.fstat(fd, cb))).isFile(),
};

const { O_CREAT, O_TRUNC, O_WRONLY, O_RDONLY, O_DIRECTORY, O_NOFOLLOW } = fs.constants;

export interface DeleteTarget {
  readonly name: string;
  /** ENOENT is ignored only for a target declared optional (§5.5). */
  readonly optional: boolean;
}

export interface DurableNamespaceOptions {
  readonly fsOps?: DurableFsOps;
  /**
   * Drain-and-exit (§5.3): called once, after every already-started mutation
   * has settled, when a mutation failed. The owner closes writerConn, releases
   * flock and exits; it must not clean up.
   */
  readonly onFatal?: (cause: unknown) => void;
}

export class DurableNamespace {
  private readonly queue = new SerialQueue();
  private readonly ops: DurableFsOps;
  private failure: unknown = null;

  constructor(
    readonly nsPath: string,
    private readonly guard: MutationGuard,
    private readonly opts: DurableNamespaceOptions = {},
  ) {
    this.ops = opts.fsOps ?? realDurableFsOps;
  }

  /** True after a mutation failed; no further work is admitted. */
  get failed(): boolean {
    return this.failure !== null;
  }

  /** Publish <name>: write <name>.tmp, fsync, close, rename, fsync the directory (§5.5). */
  publish(name: string, data: Uint8Array): Promise<void> {
    let target: string;
    try {
      target = this.entryPath(name);
    } catch (err) {
      return Promise.reject(err);
    }
    const tmp = `${target}.tmp`;
    return this.run(async () => {
      const fd = await this.ops.open(tmp, O_CREAT | O_TRUNC | O_WRONLY, 0o600);
      let open = true;
      try {
        this.check();
        await this.ops.write(fd, data);
        this.check();
        await this.ops.fsync(fd);
        open = false;
        await this.ops.close(fd);
      } finally {
        if (open) await this.ops.close(fd).catch(() => undefined);
      }
      this.check();
      await this.ops.rename(tmp, target);
      await this.fsyncDirectory();
    });
  }

  /** Durable delete: unlink each target, then fsync the directory (§5.5). */
  durableDelete(targets: readonly DeleteTarget[]): Promise<void> {
    let paths: { file: string; optional: boolean }[];
    try {
      paths = targets.map((t) => ({ file: this.entryPath(t.name), optional: t.optional }));
    } catch (err) {
      return Promise.reject(err);
    }
    return this.run(async () => {
      for (const t of paths) {
        this.check();
        try {
          await this.ops.unlink(t.file);
        } catch (err) {
          if (!(t.optional && (err as NodeJS.ErrnoException).code === 'ENOENT')) throw err;
        }
      }
      await this.fsyncDirectory();
    });
  }

  /**
   * Recovered-package durability barrier (§5.5): open each file as a regular
   * file without following symlinks, fsync it, close it in finally; then fsync
   * the chain directory.
   */
  recoveredPackageBarrier(names: readonly string[]): Promise<void> {
    let files: string[];
    try {
      files = names.map((n) => this.entryPath(n));
    } catch (err) {
      return Promise.reject(err);
    }
    return this.run(async () => {
      for (const file of files) {
        this.check();
        const fd = await this.ops.open(file, O_RDONLY | O_NOFOLLOW);
        let open = true;
        try {
          if (!(await this.ops.isRegularFile(fd))) {
            throw new TearError('NAMESPACE_ENTRY_NOT_REGULAR', path.basename(file));
          }
          await this.ops.fsync(fd);
          open = false;
          await this.ops.close(fd);
        } finally {
          if (open) await this.ops.close(fd).catch(() => undefined);
        }
      }
      await this.fsyncDirectory();
    });
  }

  /** Resolves once every queued or running mutation has settled. */
  async drain(): Promise<void> {
    await this.queue.drain();
  }

  private async fsyncDirectory(): Promise<void> {
    this.check();
    const fd = await this.ops.open(this.nsPath, O_RDONLY | O_DIRECTORY);
    try {
      await this.ops.fsync(fd);
    } finally {
      await this.ops.close(fd);
    }
  }

  private check(): void {
    if (this.failure !== null || this.guard.invalidated) {
      throw new TearError('WRITER_INVALIDATED', 'namespace mutation refused');
    }
  }

  private run(op: () => Promise<void>): Promise<void> {
    if (this.failure !== null || this.guard.invalidated) {
      return Promise.reject(new TearError('WRITER_INVALIDATED', 'namespace mutation refused'));
    }
    return this.queue.run(async () => {
      this.check();
      try {
        await op();
      } catch (err) {
        if (err instanceof TearError && err.code === 'WRITER_INVALIDATED') throw err;
        this.fail(err);
        throw new TearError('NAMESPACE_MUTATION_FAILED', err instanceof Error ? err.message : String(err), { cause: err });
      }
    });
  }

  private fail(cause: unknown): void {
    if (this.failure !== null) return;
    this.failure = cause;
    this.guard.invalidate();
    const onFatal = this.opts.onFatal;
    if (onFatal !== undefined) {
      // Run after the failing operation and anything already queued have settled.
      void this.queue.drain().then(() => onFatal(cause));
    }
  }

  /** A plain entry name inside this namespace; never a path, never the lock file. */
  private entryPath(name: string): string {
    if (name.length === 0 || name === '.' || name === '..' || name.includes('/') || name.includes('\u0000')) {
      throw new TearError('NAMESPACE_ENTRY_NAME_INVALID', JSON.stringify(name));
    }
    if (name === WRITER_LOCK_NAME || name === `${WRITER_LOCK_NAME}.tmp`) {
      throw new TearError('NAMESPACE_ENTRY_NAME_INVALID', 'the lock file is never published, renamed or deleted');
    }
    return path.join(this.nsPath, name);
  }
}
