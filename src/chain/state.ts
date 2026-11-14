// SPDX-License-Identifier: AGPL-3.0-or-later
// Loading and validating chain state under exclusion (Blueprint §5.3, §5.3a).
// Every read runs on writerConn after both locks are held.

import type { WriterConn } from '../db/writer-conn.js';
import { TearError } from '../errors.js';
import { parseTimestampMs } from '../time/timestamps.js';
import { isHex64 } from './ids.js';
import { LOAD_EVENTS_SQL, checkSqlRow } from './sql-rows.js';
import type { SqlEventRow } from './sql-rows.js';
import { Step1Checker } from './step1.js';

export type PendingMode = 'auto' | 'close' | 'close_retry';

export interface ChainState {
  readonly chainClosed: boolean;
  readonly pending: null | {
    readonly anchorSeq: number;
    readonly entryHash: string;
    readonly ts: string;
    readonly mode: PendingMode;
  };
}

interface SqlStateRow {
  chain_closed: boolean;
  pending_anchor_seq: string | null;
  pending_entry_hash: string | null;
  pending_ts: string | null;
  pending_mode: string | null;
}

const LOAD_STATE_SQL = `SELECT chain_closed, pending_anchor_seq::text AS pending_anchor_seq,
  pending_entry_hash, pending_ts, pending_mode FROM tear_chain_state WHERE chain_id = $1`;

export interface LoadedChain {
  readonly events: readonly SqlEventRow[];
  readonly stateRow: SqlStateRow | null;
}

/** Loads every event column and the state row in one read-only snapshot. */
export async function loadChain(conn: WriterConn, chainId: string): Promise<LoadedChain> {
  return conn.readSnapshot(async () => {
    const events = await conn.query<SqlEventRow & Record<string, unknown>>(LOAD_EVENTS_SQL, [chainId]);
    const states = await conn.query<SqlStateRow & Record<string, unknown>>(LOAD_STATE_SQL, [chainId]);
    return { events, stateRow: states[0] ?? null };
  });
}

function inconsistent(reason: string): TearError {
  return new TearError('RECONCILIATION_STATE_INCONSISTENT', reason);
}

/**
 * Validates every loaded row (SQL representation, then Step 1 with
 * expected_seq = row index) and returns a checker holding the chain.
 */
export function validateEvents(events: readonly SqlEventRow[], chainId: string, bundleSha256: string): Step1Checker {
  if (events.length === 0) throw inconsistent('no genesis row');
  const checker = new Step1Checker({ bundleSha256, namespaceChainId: chainId });
  for (const row of events) {
    const check = checkSqlRow(row);
    if (!check.ok) throw inconsistent(`seq ${row.seq}: ${check.reason}`);
    const failure = checker.accept({ kind: 'json', value: check.envelope });
    if (failure !== null) throw inconsistent(`${failure.code} ${failure.param}`);
  }
  return checker;
}

/** State invariants of §5.3a: pending fields all NULL or all valid, and consistent with the chain. */
export function validateState(row: SqlStateRow, checker: Step1Checker): ChainState {
  const fields = [row.pending_anchor_seq, row.pending_entry_hash, row.pending_ts, row.pending_mode];
  if (fields.every((f) => f === null)) return { chainClosed: row.chain_closed, pending: null };
  if (fields.some((f) => f === null)) throw inconsistent('pending fields partially NULL');
  const seqText = row.pending_anchor_seq!;
  const seq = /^[1-9][0-9]*$/.test(seqText) ? Number(seqText) : NaN;
  if (!Number.isSafeInteger(seq)) throw inconsistent('pending_anchor_seq');
  const entryHash = row.pending_entry_hash!;
  const ts = row.pending_ts!;
  const mode = row.pending_mode!;
  if (!isHex64(entryHash) || parseTimestampMs(ts) === null) throw inconsistent('pending hash or ts');
  if (mode !== 'auto' && mode !== 'close' && mode !== 'close_retry') throw inconsistent('pending_mode');
  if ((mode === 'close' || mode === 'close_retry') && !row.chain_closed) throw inconsistent('close pending on open chain');
  const target = checker.accepted[seq];
  if (target === undefined || target.entryHash !== entryHash || target.block.ts !== ts) {
    throw inconsistent('pending target does not match the chain');
  }
  return { chainClosed: row.chain_closed, pending: { anchorSeq: seq, entryHash, ts, mode } };
}
