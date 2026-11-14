// SPDX-License-Identifier: AGPL-3.0-or-later
// writerConn: the single dedicated PostgreSQL session of a writer generation
// (Blueprint §5.3, single-session SQL invariant; §5.4 durable commit boundary).
// It is a plain pg.Client, never a pool. It is never reconnected: any error,
// end or timeout invalidates it for the rest of the generation.

import pg from 'pg';
import type { ClientConfig, QueryResultRow } from 'pg';
import { TearError } from '../errors.js';
import { SETTINGS_QUERY, assertDatabaseSettings, settingsFromRow } from './settings.js';

export type CommitOutcome = 'committed' | 'rolled_back' | 'unknown';

export class WriterConn {
  private invalidatedFlag = false;
  private inTransaction = false;
  readonly backendPid: number;
  /** Backend pid observed on every statement; used to prove the single-session invariant. */
  readonly observedPids: number[] = [];

  private constructor(
    private readonly client: pg.Client,
    backendPid: number,
  ) {
    this.backendPid = backendPid;
    const invalidate = (): void => {
      this.invalidatedFlag = true;
    };
    client.on('error', invalidate);
    client.on('end', invalidate);
  }

  /**
   * Opens the session, checks encoding and durability, sets and verifies
   * synchronous_commit=on, then takes the session advisory lock as an
   * autocommit statement. Returns null if the advisory lock is not available;
   * no chain data has been read at that point.
   */
  static async open(config: ClientConfig, chainId: string): Promise<WriterConn | null> {
    const client = new pg.Client(config);
    await client.connect();
    try {
      await client.query('SET synchronous_commit = on');
      const settings = settingsFromRow((await client.query(SETTINGS_QUERY)).rows[0]);
      assertDatabaseSettings(settings);
      const pidRow = (await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0];
      const lockRow = (
        await client.query<{ locked: boolean }>('SELECT pg_try_advisory_lock(hashtext($1::uuid::text)) AS locked', [chainId])
      ).rows[0];
      if (lockRow?.locked !== true || pidRow === undefined) {
        await client.end();
        return null;
      }
      return new WriterConn(client, pidRow.pid);
    } catch (err) {
      await client.end().catch(() => undefined);
      throw err;
    }
  }

  get invalidated(): boolean {
    return this.invalidatedFlag;
  }

  invalidate(): void {
    this.invalidatedFlag = true;
  }

  private assertUsable(): void {
    if (this.invalidatedFlag) throw new TearError('WRITER_INVALIDATED', 'writerConn is invalidated');
  }

  async query<R extends QueryResultRow>(text: string, values?: unknown[]): Promise<R[]> {
    this.assertUsable();
    try {
      const res = await this.client.query<R>(text, values);
      this.observedPids.push(this.client.processID ?? -1);
      return res.rows;
    } catch (err) {
      if (!isServerError(err)) this.invalidatedFlag = true;
      throw err;
    }
  }

  /** Rechecks the durability settings; a loss after start-up invalidates the writer (§5.4). */
  async recheckSettings(): Promise<void> {
    const rows = await this.query(SETTINGS_QUERY);
    try {
      assertDatabaseSettings(settingsFromRow(rows[0]));
    } catch (err) {
      this.invalidatedFlag = true;
      throw err;
    }
  }

  /** Read-only snapshot for loading chain state under the lock. */
  async readSnapshot<T>(fn: () => Promise<T>): Promise<T> {
    await this.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    try {
      const out = await fn();
      await this.query('COMMIT');
      return out;
    } catch (err) {
      await this.client.query('ROLLBACK').catch(() => undefined);
      throw err;
    }
  }

  /**
   * Runs one mutating transaction. Durability is rechecked inside the
   * transaction before any write. A lost connection after BEGIN gives
   * 'unknown': a rejected promise is not evidence of server rollback.
   */
  async mutate(fn: () => Promise<void>): Promise<CommitOutcome> {
    this.assertUsable();
    if (this.inTransaction) throw new TearError('WRITER_BUSY', 'nested transaction');
    this.inTransaction = true;
    try {
      try {
        await this.query('BEGIN');
      } catch (err) {
        if (this.invalidatedFlag) return 'unknown';
        throw err;
      }
      try {
        await this.recheckSettings();
        await fn();
      } catch (err) {
        if (this.invalidatedFlag && !(err instanceof TearError && err.code === 'DATABASE_DURABILITY_UNSUPPORTED')) {
          return 'unknown';
        }
        await this.client.query('ROLLBACK').catch(() => {
          this.invalidatedFlag = true;
        });
        throw err;
      }
      let res: pg.QueryResult;
      try {
        this.assertUsable();
        res = await this.client.query('COMMIT');
        this.observedPids.push(this.client.processID ?? -1);
      } catch {
        this.invalidatedFlag = true;
        return 'unknown';
      }
      if (res.command === 'COMMIT') return 'committed';
      return 'rolled_back';
    } finally {
      this.inTransaction = false;
    }
  }

  /** Closes the session. Ending the session releases the advisory lock. */
  async close(): Promise<void> {
    this.invalidatedFlag = true;
    await this.client.end().catch(() => undefined);
  }

  /** Test access to the raw session, used only to simulate faults. */
  get rawClientForTests(): pg.Client {
    return this.client;
  }
}

/**
 * True for an ordinary SQL error reported by a live session. FATAL and PANIC
 * end the session (for example pg_terminate_backend), so they invalidate it.
 */
function isServerError(err: unknown): boolean {
  if (!(err instanceof Error) || !('severity' in err)) return false;
  const severity = (err as { severity?: unknown }).severity;
  return severity !== 'FATAL' && severity !== 'PANIC';
}
