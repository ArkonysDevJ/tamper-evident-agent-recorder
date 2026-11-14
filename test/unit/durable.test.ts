// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { TearError } from '../../src/errors.js';
import { DurableNamespace } from '../../src/fs/durable.js';
import { EXT_FAMILY_MAGIC, XFS_MAGIC, provisionNamespace } from '../../src/fs/namespace.js';
import { RecordingFs, TestGuard } from '../helpers/fs-double.js';
import type { OpName } from '../helpers/fs-double.js';

interface Setup {
  ns: string;
  fsd: RecordingFs;
  guard: TestGuard;
  files: DurableNamespace;
  fatal: unknown[];
}

function setup(): Setup {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-durable-'));
  const ns = provisionNamespace(root, randomUUID());
  const fsd = new RecordingFs(ns);
  const guard = new TestGuard();
  const fatal: unknown[] = [];
  const files = new DurableNamespace(ns, guard, { fsOps: fsd, onFatal: (c) => fatal.push(c) });
  return { ns, fsd, guard, files, fatal };
}

function ls(ns: string): string[] {
  return fs.readdirSync(ns).sort();
}

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'OK';
  } catch (err) {
    return err instanceof TearError ? err.code : `other: ${String(err)}`;
  }
}

test('the tests run on ext4 or xfs', () => {
  const type = fs.statfsSync(os.tmpdir()).type;
  assert.ok(type === EXT_FAMILY_MAGIC || type === XFS_MAGIC, `statfs type 0x${type.toString(16)}`);
});

test('008 AC-1 publish', async (t) => {
  await t.test('follows the §5.5 call sequence', async () => {
    const s = setup();
    await s.files.publish('10.tsr', Buffer.from('receipt'));
    assert.deepEqual(s.fsd.calls, [
      'open 10.tsr.tmp',
      'write 10.tsr.tmp',
      'fsync 10.tsr.tmp',
      'close 10.tsr.tmp',
      'rename 10.tsr.tmp -> 10.tsr',
      'open .',
      'fsync .',
      'close .',
    ]);
    assert.deepEqual(ls(s.ns), ['10.tsr']);
    assert.equal(fs.readFileSync(path.join(s.ns, '10.tsr'), 'utf8'), 'receipt');
  });
  await t.test('replaces the temporary content (O_TRUNC) and the published bytes are exact', async () => {
    const s = setup();
    fs.writeFileSync(path.join(s.ns, '20.tsq.tmp'), 'stale content that is longer');
    await s.files.publish('20.tsq', Buffer.from([0, 1, 2]));
    assert.deepEqual(fs.readFileSync(path.join(s.ns, '20.tsq')), Buffer.from([0, 1, 2]));
    assert.deepEqual(ls(s.ns), ['20.tsq']);
  });
  await t.test('names stay inside the namespace and never touch the lock file', async () => {
    const s = setup();
    for (const bad of ['../x', 'a/b', '.', '..', '', '.writer.lock']) {
      assert.equal(await codeOf(s.files.publish(bad, Buffer.from('x'))), 'NAMESPACE_ENTRY_NAME_INVALID', bad);
      assert.equal(await codeOf(s.files.durableDelete([{ name: bad, optional: true }])), 'NAMESPACE_ENTRY_NAME_INVALID', bad);
      assert.equal(await codeOf(s.files.recoveredPackageBarrier([bad])), 'NAMESPACE_ENTRY_NAME_INVALID', bad);
    }
    assert.deepEqual(s.fsd.calls, []);
    assert.equal(s.guard.invalidated, false, 'a rejected name is not a mutation failure');
  });
});

test('008 AC-2 durable-delete', async (t) => {
  await t.test('unlinks each target, then fsyncs the directory', async () => {
    const s = setup();
    fs.writeFileSync(path.join(s.ns, '10.tsq'), 'x');
    fs.writeFileSync(path.join(s.ns, '10.tsr.tmp'), 'x');
    await s.files.durableDelete([
      { name: '10.tsq', optional: false },
      { name: '10.tsr.tmp', optional: false },
    ]);
    assert.deepEqual(s.fsd.calls, ['unlink 10.tsq', 'unlink 10.tsr.tmp', 'open .', 'fsync .', 'close .']);
    assert.deepEqual(ls(s.ns), []);
  });
  await t.test('ENOENT is ignored for an optional target', async () => {
    const s = setup();
    await s.files.durableDelete([{ name: '30.tsq', optional: true }]);
    assert.equal(s.guard.invalidated, false);
  });
  await t.test('ENOENT on a required target is a mutation failure', async () => {
    const s = setup();
    assert.equal(await codeOf(s.files.durableDelete([{ name: '30.tsq', optional: false }])), 'NAMESPACE_MUTATION_FAILED');
    assert.equal(s.guard.invalidated, true);
  });
});

test('008 AC-3 recovered-package-barrier', async (t) => {
  await t.test('fsyncs each file without following symlinks, then the directory', async () => {
    const s = setup();
    fs.writeFileSync(path.join(s.ns, '10.tsr'), 'r');
    fs.writeFileSync(path.join(s.ns, '10.anchor.json'), '{}');
    await s.files.recoveredPackageBarrier(['10.tsr', '10.anchor.json']);
    assert.deepEqual(s.fsd.calls, [
      'open 10.tsr',
      'isRegularFile 10.tsr',
      'fsync 10.tsr',
      'close 10.tsr',
      'open 10.anchor.json',
      'isRegularFile 10.anchor.json',
      'fsync 10.anchor.json',
      'close 10.anchor.json',
      'open .',
      'fsync .',
      'close .',
    ]);
    assert.equal(s.guard.invalidated, false);
  });
  await t.test('a symlink is rejected and invalidates the writer', async () => {
    const s = setup();
    const outside = path.join(path.dirname(s.ns), 'outside');
    fs.writeFileSync(outside, 'x');
    fs.symlinkSync(outside, path.join(s.ns, '10.tsr'));
    assert.equal(await codeOf(s.files.recoveredPackageBarrier(['10.tsr'])), 'NAMESPACE_MUTATION_FAILED');
    assert.equal(s.guard.invalidated, true);
    assert.ok(fs.lstatSync(path.join(s.ns, '10.tsr')).isSymbolicLink(), 'nothing removed');
  });
  await t.test('a directory in place of a file is rejected', async () => {
    const s = setup();
    fs.mkdirSync(path.join(s.ns, '10.tsr'));
    assert.equal(await codeOf(s.files.recoveredPackageBarrier(['10.tsr'])), 'NAMESPACE_MUTATION_FAILED');
    assert.equal(s.guard.invalidated, true);
  });
});

test('008 AC-4 guarded-and-queued', async (t) => {
  await t.test('a mutation requested on an invalidated writer never touches the disk', async () => {
    const s = setup();
    s.guard.invalidate();
    fs.writeFileSync(path.join(s.ns, '10.tsq'), 'x');
    assert.equal(await codeOf(s.files.publish('10.tsr', Buffer.from('x'))), 'WRITER_INVALIDATED');
    assert.equal(await codeOf(s.files.durableDelete([{ name: '10.tsq', optional: false }])), 'WRITER_INVALIDATED');
    assert.equal(await codeOf(s.files.recoveredPackageBarrier(['10.tsq'])), 'WRITER_INVALIDATED');
    assert.deepEqual(s.fsd.calls, []);
    assert.deepEqual(ls(s.ns), ['10.tsq']);
  });
  await t.test('invalidation during a publish stops it before the next system call, without cleanup', async () => {
    const s = setup();
    s.fsd.before = (op) => {
      if (op === 'fsync') s.guard.invalidate();
    };
    assert.equal(await codeOf(s.files.publish('10.tsr', Buffer.from('x'))), 'WRITER_INVALIDATED');
    assert.deepEqual(s.fsd.calls, ['open 10.tsr.tmp', 'write 10.tsr.tmp', 'fsync 10.tsr.tmp', 'close 10.tsr.tmp']);
    assert.deepEqual(ls(s.ns), ['10.tsr.tmp'], 'the partial .tmp stays for recovery');
  });
  await t.test('concurrent mutations run in arrival order, never overlapping', async () => {
    const s = setup();
    let active = 0;
    s.fsd.before = async () => {
      active++;
      assert.equal(active, 1);
      await new Promise((r) => setImmediate(r));
      active--;
    };
    fs.writeFileSync(path.join(s.ns, '5.tsq'), 'x');
    await Promise.all([
      s.files.publish('10.tsr', Buffer.from('a')),
      s.files.durableDelete([{ name: '5.tsq', optional: false }]),
      s.files.publish('10.anchor.json', Buffer.from('b')),
    ]);
    const firstOf = (needle: string): number => s.fsd.calls.findIndex((c) => c.includes(needle));
    const lastOf = (needle: string): number => s.fsd.calls.map((c) => c.includes(needle)).lastIndexOf(true);
    assert.ok(lastOf('10.tsr') < firstOf('5.tsq'));
    assert.ok(lastOf('5.tsq') < firstOf('10.anchor.json'));
    assert.deepEqual(ls(s.ns), ['10.anchor.json', '10.tsr']);
  });
});

test('008 AC-5 mutation-failure', async (t) => {
  const cases: [OpName, number, string][] = [
    ['write', 1, 'publish'],
    ['fsync', 1, 'publish'],
    ['close', 1, 'publish'],
    ['rename', 1, 'publish'],
    ['fsync', 2, 'publish'],
    ['close', 2, 'publish'],
    ['unlink', 1, 'delete'],
    ['fsync', 1, 'delete'],
    ['close', 1, 'delete'],
    ['fsync', 1, 'barrier'],
    ['fsync', 2, 'barrier'],
  ];
  for (const [op, nth, kind] of cases) {
    await t.test(`${kind}: failure on ${op} #${String(nth)} invalidates, drains, exits and cleans nothing`, async () => {
      const s = setup();
      fs.writeFileSync(path.join(s.ns, '7.tsq'), 'keep');
      fs.writeFileSync(path.join(s.ns, '7.tsr'), 'keep');
      const before = ls(s.ns);
      s.fsd.failOn = { op, nth, code: 'EIO' };
      const attempt =
        kind === 'publish'
          ? s.files.publish('10.tsr', Buffer.from('x'))
          : kind === 'delete'
            ? s.files.durableDelete([{ name: '7.tsq', optional: false }])
            : s.files.recoveredPackageBarrier(['7.tsr']);
      // A second mutation queued behind the failing one must never reach the disk.
      const queued = s.files.publish('11.tsr', Buffer.from('y'));
      assert.equal(await codeOf(attempt), 'NAMESPACE_MUTATION_FAILED');
      assert.equal(await codeOf(queued), 'WRITER_INVALIDATED');
      assert.equal(s.guard.invalidated, true);
      assert.equal(s.files.failed, true);
      const callsAfterFailure = s.fsd.calls.length;
      assert.equal(await codeOf(s.files.publish('12.tsr', Buffer.from('z'))), 'WRITER_INVALIDATED');
      assert.equal(s.fsd.calls.length, callsAfterFailure, 'no more work admitted');
      assert.ok(!s.fsd.calls.some((c) => c.includes('11.tsr') || c.includes('12.tsr')));
      await s.files.drain();
      await new Promise((r) => setImmediate(r));
      assert.equal(s.fatal.length, 1, 'drain-and-exit handler called once');
      // No cleanup: the namespace is exactly what the failed operation left behind.
      const expected = new Set(before);
      if (kind === 'publish') {
        const renamed = nth === 2; // failure in the directory fsync or close, after rename
        expected.add(renamed ? '10.tsr' : '10.tsr.tmp');
      }
      if (kind === 'delete' && op !== 'unlink') expected.delete('7.tsq'); // unlinked before the failing directory step
      assert.deepEqual(ls(s.ns), [...expected].sort());
      const unlinks = s.fsd.calls.filter((c) => c.startsWith('unlink'));
      assert.deepEqual(unlinks, kind === 'delete' ? ['unlink 7.tsq'] : [], 'no cleanup unlink');
    });
  }
});
