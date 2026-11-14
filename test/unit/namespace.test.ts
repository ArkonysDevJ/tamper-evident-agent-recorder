// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { TearError } from '../../src/errors.js';
import {
  EXT_FAMILY_MAGIC,
  XFS_MAGIC,
  assertProvisioned,
  assertSupportedFilesystem,
  namespacePath,
  provisionNamespace,
  realProvisionOps,
} from '../../src/fs/namespace.js';
import type { ProvisionOps } from '../../src/fs/namespace.js';

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    return err instanceof TearError ? err.code : 'other';
  }
}

test('001 AC-8 provisioning', async (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-ns-'));
  await t.test('creates every missing level and fsyncs each parent, in order', () => {
    const calls: string[] = [];
    const ops: ProvisionOps = {
      mkdirIfMissing: (d) => {
        calls.push(`mkdir ${d}`);
        realProvisionOps.mkdirIfMissing(d);
      },
      fsyncDir: (d) => {
        calls.push(`fsync ${d}`);
        realProvisionOps.fsyncDir(d);
      },
    };
    const id = randomUUID();
    const root = path.join(base, 'a', 'b');
    const ns = provisionNamespace(root, id, ops);
    assert.equal(ns, path.join(root, id));
    assert.ok(fs.statSync(ns).isDirectory());
    const levels = ns.split(path.sep).filter(Boolean);
    let cur: string = path.sep;
    const expected: string[] = [];
    for (const part of levels) {
      const parent = cur;
      cur = path.join(cur, part);
      expected.push(`mkdir ${cur}`, `fsync ${parent}`);
    }
    assert.deepEqual(calls, expected);
  });
  await t.test('fsyncs parents again when everything already exists', () => {
    const id = randomUUID();
    provisionNamespace(base, id);
    const fsyncs: string[] = [];
    provisionNamespace(base, id, { mkdirIfMissing: realProvisionOps.mkdirIfMissing, fsyncDir: (d) => fsyncs.push(d) });
    assert.equal(fsyncs.length, path.join(base, id).split(path.sep).filter(Boolean).length);
  });
  await t.test('a missing namespace fails NAMESPACE_NOT_PROVISIONED', () => {
    assert.equal(codeOf(() => assertProvisioned(path.join(base, randomUUID()))), 'NAMESPACE_NOT_PROVISIONED');
    const file = path.join(base, 'not-a-dir');
    fs.writeFileSync(file, '');
    assert.equal(codeOf(() => assertProvisioned(file)), 'NAMESPACE_NOT_PROVISIONED');
  });
});

test('001 AC-9 filesystem-guard', async (t) => {
  await t.test('chain_id is validated before any path is built', () => {
    for (const bad of ['../etc', 'ABCDEF00-0000-4000-8000-000000000000', '', `${randomUUID()}/x`]) {
      assert.equal(codeOf(() => namespacePath('/tmp', bad)), 'CHAIN_ID_INVALID', bad);
    }
  });
  await t.test('only ext2/3/4 and xfs magic numbers are accepted', () => {
    assert.equal(codeOf(() => assertSupportedFilesystem('/r', '/r/n', () => EXT_FAMILY_MAGIC)), undefined);
    assert.equal(codeOf(() => assertSupportedFilesystem('/r', '/r/n', () => XFS_MAGIC)), undefined);
    for (const magic of [0x01021994 /* tmpfs */, 0x794c7630 /* overlayfs */, 0x6969 /* nfs */]) {
      assert.equal(codeOf(() => assertSupportedFilesystem('/r', '/r/n', () => magic)), 'FILESYSTEM_UNSUPPORTED');
    }
  });
  await t.test('both the root and the namespace are checked', () => {
    const seen: string[] = [];
    assertSupportedFilesystem('/r', '/r/n', (p) => {
      seen.push(p);
      return EXT_FAMILY_MAGIC;
    });
    assert.deepEqual(seen, ['/r', '/r/n']);
    assert.equal(codeOf(() => assertSupportedFilesystem('/r', '/r/n', (p) => (p === '/r/n' ? 0x01021994 : EXT_FAMILY_MAGIC))), 'FILESYSTEM_UNSUPPORTED');
  });
  await t.test('real statfs on this host', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-fs-'));
    const type = fs.statfsSync(dir).type;
    const expectOk = type === EXT_FAMILY_MAGIC || type === XFS_MAGIC;
    assert.equal(codeOf(() => assertSupportedFilesystem(dir, dir)), expectOk ? undefined : 'FILESYSTEM_UNSUPPORTED');
    if (fs.existsSync('/dev/shm') && fs.statfsSync('/dev/shm').type === 0x01021994) {
      assert.equal(codeOf(() => assertSupportedFilesystem('/dev/shm', '/dev/shm')), 'FILESYSTEM_UNSUPPORTED');
    }
  });
});
