// SPDX-License-Identifier: AGPL-3.0-or-later
// Canonical log export SQL -> events.jsonl (Blueprint §5.3). The exporter is
// the read-only exception to the single-session invariant: its own connection,
// one REPEATABLE READ READ ONLY snapshot, no mutation of chain data. Nothing is
// written unless the whole snapshot passes the representation check and Step 1.

import * as fs from 'node:fs';
import pg from 'pg';
import type { ClientConfig } from 'pg';
import { bundleSha256 } from '../crypto/digests.js';
import { LOAD_EVENTS_SQL } from './sql-rows.js';
import type { SqlEventRow } from './sql-rows.js';
import { validateEvents } from './state.js';

export interface ExportOptions {
  readonly pg: ClientConfig;
  readonly chainId: string;
  readonly bundleBytes: Uint8Array;
  readonly outPath: string;
}

export async function exportChain(opts: ExportOptions): Promise<{ rows: number }> {
  const client = new pg.Client(opts.pg);
  await client.connect();
  let events: SqlEventRow[];
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    events = (await client.query<SqlEventRow & Record<string, unknown>>(LOAD_EVENTS_SQL, [opts.chainId])).rows;
    await client.query('COMMIT');
  } finally {
    await client.end();
  }

  // Throws RECONCILIATION_STATE_INCONSISTENT before any output exists.
  validateEvents(events, opts.chainId, bundleSha256(opts.bundleBytes));

  const body = events.map((r) => `{"block":${r.block_json},"entry_hash":"${r.entry_hash}"}\n`).join('');
  const tmp = `${opts.outPath}.${process.pid}.partial`;
  try {
    fs.writeFileSync(tmp, body, { flag: 'wx' });
    fs.renameSync(tmp, opts.outPath);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  return { rows: events.length };
}
