// SPDX-License-Identifier: AGPL-3.0-or-later
// Local PostgreSQL helpers for tests marked "pg". Connection settings come
// from the standard libpq variables (PGHOST, PGDATABASE, PGUSER); defaults are
// the local Unix socket and database tear_test. No password is read here.

import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import pg from 'pg';
import type { ClientConfig } from 'pg';
import { initializeChain } from '../../src/chain/initialize.js';
import type { InitializeOptions } from '../../src/chain/initialize.js';
import { noAnchorHook } from '../../src/chain/interfaces.js';
import type { RecoveryClassifier } from '../../src/chain/interfaces.js';
import { ChainWriter } from '../../src/chain/writer.js';
import type { WriterOptions } from '../../src/chain/writer.js';
import { provisionSchema } from '../../src/db/schema.js';
import { provisionNamespace } from '../../src/fs/namespace.js';
import { TearError } from '../../src/errors.js';
import { formatTimestamp } from '../../src/time/timestamps.js';

export const pgConfig: ClientConfig = {
  host: process.env['PGHOST'] ?? '/var/run/postgresql',
  database: process.env['PGDATABASE'] ?? 'tear_test',
  ...(process.env['PGUSER'] !== undefined ? { user: process.env['PGUSER'] } : {}),
};

export const bundleBytes = fs.readFileSync(path.resolve('certs/tsa_roots.pem'));

let schemaReady: Promise<void> | null = null;
export function ensureSchema(): Promise<void> {
  schemaReady ??= provisionSchema(pgConfig);
  return schemaReady;
}

export async function admin<R extends pg.QueryResultRow = pg.QueryResultRow>(text: string, values?: unknown[]): Promise<R[]> {
  const c = new pg.Client(pgConfig);
  await c.connect();
  try {
    return (await c.query<R>(text, values)).rows;
  } finally {
    await c.end();
  }
}

/**
 * Test-only classifier: reports clean E1 when the view has no namespace
 * entries and no pending anchor. It stands in for the §5.6 classifier of a
 * later package so writer start-up can be exercised now.
 */
export const cleanE1ForTests: RecoveryClassifier = {
  classify: async (view) =>
    view.entries.length === 0 && view.state.pending === null
      ? { kind: 'state', state: 'E1' }
      : { kind: 'inconsistent', reason: 'test classifier only knows clean E1' },
};

export function fixedClassifier(state: 'E1' | 'E2' | 'E3' | 'E6' | 'E7' | 'E10'): RecoveryClassifier & { lastEntries: string[] } {
  const c = {
    lastEntries: [] as string[],
    classify: async (view: Parameters<RecoveryClassifier['classify']>[0]) => {
      c.lastEntries = view.entries.map((e) => e.name);
      return { kind: 'state' as const, state };
    },
  };
  return c;
}

export interface TestChain {
  readonly root: string;
  readonly chainId: string;
  readonly nsPath: string;
  readonly genesisTs: string;
}

export function newChain(): TestChain {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-pg-'));
  const chainId = randomUUID();
  const nsPath = provisionNamespace(root, chainId);
  return { root, chainId, nsPath, genesisTs: formatTimestamp(Date.now() - 60_000) };
}

export function initOptions(c: TestChain, extra: Partial<InitializeOptions> = {}): InitializeOptions {
  return {
    checkpointsRoot: c.root,
    chainId: c.chainId,
    genesisTs: c.genesisTs,
    pepperId: 'test-pepper',
    bundleBytes,
    pg: pgConfig,
    profile: 'base',
    ...extra,
  };
}

export function writerOptions(c: TestChain, extra: Partial<WriterOptions> = {}): WriterOptions {
  return {
    checkpointsRoot: c.root,
    chainId: c.chainId,
    bundleBytes,
    pg: pgConfig,
    profile: 'base',
    classifier: cleanE1ForTests,
    // Data-core tests never anchor; spec 003 tests pass the automatic hook and test TSAs.
    anchorHook: noAnchorHook,
    tsas: [],
    ...extra,
  };
}

export async function initializedWriter(extra: Partial<WriterOptions> = {}): Promise<{ chain: TestChain; writer: ChainWriter }> {
  await ensureSchema();
  const chain = newChain();
  await initializeChain(initOptions(chain));
  const writer = await ChainWriter.open(writerOptions(chain, extra));
  return { chain, writer };
}

export async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'OK';
  } catch (err) {
    return err instanceof TearError ? err.code : `other: ${String(err)}`;
  }
}

export async function rowCount(chainId: string): Promise<number> {
  const rows = await admin<{ n: string }>('SELECT count(*)::text AS n FROM tear_events WHERE chain_id = $1', [chainId]);
  return Number(rows[0]!.n);
}

/**
 * Everything initializeChain must leave untouched: SQL rows, state row and
 * namespace bytes. .writer.lock is excluded: creating it if absent is the
 * control-file exception of §5.3a.
 */
export async function snapshot(c: TestChain): Promise<string> {
  const events = await admin('SELECT * FROM tear_events WHERE chain_id = $1 ORDER BY seq', [c.chainId]);
  const state = await admin('SELECT * FROM tear_chain_state WHERE chain_id = $1', [c.chainId]);
  const files = fs
    .readdirSync(c.nsPath)
    .filter((n) => n !== '.writer.lock')
    .sort()
    .map((n) => `${n}:${fs.readFileSync(path.join(c.nsPath, n)).toString('base64')}`);
  return JSON.stringify({ events, state, files });
}

export async function waitFor(cond: () => boolean | Promise<boolean>, timeoutMs = 15_000): Promise<void> {
  const start = Date.now();
  while (!(await cond())) {
    if (Date.now() - start > timeoutMs) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 50));
  }
}
