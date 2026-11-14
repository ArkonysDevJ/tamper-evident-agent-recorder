// SPDX-License-Identifier: AGPL-3.0-or-later
// Requires local PostgreSQL (npm run test:pg).
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { before, test } from 'node:test';
import { DurableNamespace } from '../../src/fs/durable.js';
import { RecordingFs } from '../helpers/fs-double.js';
import { admin, codeOf, ensureSchema, initializedWriter, waitFor } from '../helpers/pg.js';

before(ensureSchema);

test('008 AC-4 guarded-and-queued (writerConn)', async (t) => {
  await t.test('a connected writerConn admits mutations; once its session ends, nothing reaches the disk', async () => {
    const { chain, writer } = await initializedWriter();
    const fsd = new RecordingFs(chain.nsPath);
    const files = new DurableNamespace(chain.nsPath, writer.connForTests, { fsOps: fsd });
    await files.publish('10.tsr', Buffer.from('x'));
    assert.ok(fs.existsSync(`${chain.nsPath}/10.tsr`));

    await admin('SELECT pg_terminate_backend($1)', [writer.backendPid]);
    await waitFor(() => writer.invalidated);
    const calls = fsd.calls.length;
    assert.equal(await codeOf(files.publish('20.tsr', Buffer.from('y'))), 'WRITER_INVALIDATED');
    assert.equal(fsd.calls.length, calls);
    assert.equal(fs.existsSync(`${chain.nsPath}/20.tsr.tmp`), false);
    await writer.close();
  });
});
