// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { test } from 'node:test';
import { assertDatabaseSettings } from '../../src/db/settings.js';
import type { DatabaseSettings } from '../../src/db/settings.js';
import { TearError } from '../../src/errors.js';
import { SerialQueue } from '../../src/util/serial-queue.js';

test('001 AC-13 serial-queue', async (t) => {
  await t.test('operations run one at a time in FIFO order', async () => {
    const q = new SerialQueue();
    const log: string[] = [];
    let active = 0;
    const op = (name: string, ms: number) => async () => {
      active++;
      assert.equal(active, 1);
      log.push(`start ${name}`);
      await sleep(ms);
      log.push(`end ${name}`);
      active--;
      return name;
    };
    const results = await Promise.all([q.run(op('a', 30)), q.run(op('b', 1)), q.run(op('c', 10))]);
    assert.deepEqual(results, ['a', 'b', 'c']);
    assert.deepEqual(log, ['start a', 'end a', 'start b', 'end b', 'start c', 'end c']);
  });
  await t.test('a failed operation does not block the next one', async () => {
    const q = new SerialQueue();
    await assert.rejects(q.run(async () => Promise.reject(new Error('x'))));
    assert.equal(await q.run(async () => 1), 1);
  });
  await t.test('drain stops admitting work', async () => {
    const q = new SerialQueue();
    await q.drain();
    await assert.rejects(q.run(async () => 1));
  });
});

const GOOD: DatabaseSettings = {
  serverEncoding: 'UTF8',
  fsync: 'on',
  fullPageWrites: 'on',
  walLevel: 'replica',
  synchronousCommit: 'on',
};

function codeOf(s: Partial<DatabaseSettings>): string | undefined {
  try {
    assertDatabaseSettings({ ...GOOD, ...s });
    return undefined;
  } catch (err) {
    return err instanceof TearError ? err.code : 'other';
  }
}

test('001 AC-14 encoding', async (t) => {
  await t.test('a non-UTF8 database fails DATABASE_ENCODING_UNSUPPORTED', () => {
    assert.equal(codeOf({ serverEncoding: 'SQL_ASCII' }), 'DATABASE_ENCODING_UNSUPPORTED');
    assert.equal(codeOf({ serverEncoding: null }), 'DATABASE_ENCODING_UNSUPPORTED');
  });
  await t.test('encoding is checked before the durability tuple', () => {
    assert.equal(codeOf({ serverEncoding: 'LATIN1', fsync: 'off' }), 'DATABASE_ENCODING_UNSUPPORTED');
  });
});

test('001 AC-15 durability-settings (decision)', async (t) => {
  await t.test('the required tuple is accepted, logical WAL too', () => {
    assert.equal(codeOf({}), undefined);
    assert.equal(codeOf({ walLevel: 'logical' }), undefined);
  });
  await t.test('each missing requirement fails closed', () => {
    for (const bad of [
      { fullPageWrites: 'off' },
      { fsync: 'off' },
      { walLevel: 'minimal' },
      { synchronousCommit: 'off' },
      { synchronousCommit: 'local' },
      { fsync: null },
    ]) {
      assert.equal(codeOf(bad), 'DATABASE_DURABILITY_UNSUPPORTED', JSON.stringify(bad));
    }
  });
});
