// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { TearError } from '../../src/errors.js';
import { WRITER_LOCK_NAME, WriterLock } from '../../src/fs/writer-lock.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const holder = path.join(here, '..', 'helpers', 'lock-holder.js');

test('001 AC-10 flock-exclusion', async (t) => {
  const ns = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-lock-'));
  const lockFile = path.join(ns, WRITER_LOCK_NAME);

  await t.test('a second process cannot take the lock and gets WRITER_LOCKED', async () => {
    const child = spawn(process.execPath, [holder, ns], { stdio: ['ignore', 'pipe', 'inherit'] });
    await new Promise<void>((resolve, reject) => {
      child.stdout.once('data', () => resolve());
      child.once('exit', () => reject(new Error('holder exited early')));
    });
    try {
      assert.throws(() => WriterLock.acquire(ns), (err) => err instanceof TearError && err.code === 'WRITER_LOCKED');
    } finally {
      child.kill('SIGKILL');
      await new Promise((r) => child.once('exit', r));
    }
    const lock = WriterLock.acquire(ns);
    lock.release();
  });

  await t.test('the lock file is never deleted, renamed or truncated', () => {
    fs.writeFileSync(lockFile, 'keep');
    const before = fs.statSync(lockFile).ino;
    const lock = WriterLock.acquire(ns);
    lock.release();
    assert.equal(fs.readFileSync(lockFile, 'utf8'), 'keep');
    assert.equal(fs.statSync(lockFile).ino, before);
  });

  await t.test('the descriptor is not inherited by child processes', () => {
    const lock = WriterLock.acquire(ns);
    try {
      const fds = execFileSync('sh', ['-c', 'ls -l /proc/$$/fd 2>/dev/null'], { encoding: 'utf8' });
      assert.ok(!fds.includes(WRITER_LOCK_NAME), fds);
    } finally {
      lock.release();
    }
  });
});
