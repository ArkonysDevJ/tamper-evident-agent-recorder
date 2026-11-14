// SPDX-License-Identifier: AGPL-3.0-or-later
// Step 1 rule core (Blueprint §6 Step 1, rules 1.1–1.10), applied to an ordered
// sequence of row envelopes with expected_seq = zero-based index. Physical JSONL
// framing (BOM, LF, empty rows) is not handled here: the offline verifier
// decodes rows first, and SQL tuples have no framing (§5.3).

import { entryHashOf } from '../crypto/digests.js';
import type { JsonValue } from '../json/strict-json.js';
import { parseTimestampNs } from '../time/timestamps.js';
import { CHAIN_VERSION, ZERO_HASH } from './ids.js';
import { checkRowSchema } from './schema.js';
import type { Block } from './schema.js';

/**
 * A decoded row; a row whose bytes could not be decoded as one JSON value
 * (including an empty physical row); or a nonempty last row without its
 * required LF, with its decoded value when it has one (§6 Step 1).
 */
export type RowInput =
  | { kind: 'json'; value: JsonValue }
  | { kind: 'malformed' }
  | { kind: 'unterminated'; value: JsonValue | null };

export interface Step1Context {
  /** SHA-256 of the --tsa-ca-bundle bytes (Step 1.3). */
  readonly bundleSha256: string;
  /** Expected chain id: the checkpoint namespace basename (Step 1.5). */
  readonly namespaceChainId: string;
}

export interface Step1Failure {
  readonly code: string;
  readonly param: number;
}

export interface AcceptedRow {
  readonly block: Block;
  readonly entryHash: string;
  readonly tsNs: bigint;
}

interface OpenCall {
  readonly taskId: string;
  readonly seq: number;
}

/**
 * Incremental Step 1 checker. `check` evaluates the next row without changing
 * state; `accept` evaluates it and, on success, extends the checked chain.
 * Writer admission (§5.4) uses `check` on a candidate row before COMMIT.
 */
export class Step1Checker {
  private readonly rows: AcceptedRow[] = [];
  private readonly seenCallIds = new Set<string>();
  private readonly openCalls = new Map<string, OpenCall>();

  constructor(private readonly ctx: Step1Context) {}

  get length(): number {
    return this.rows.length;
  }

  get head(): AcceptedRow | undefined {
    return this.rows[this.rows.length - 1];
  }

  get accepted(): readonly AcceptedRow[] {
    return this.rows;
  }

  /** Seqs of tool_call rows with no matching tool_result, ascending. */
  unmatchedCalls(): number[] {
    return [...this.openCalls.values()].map((c) => c.seq).sort((a, b) => a - b);
  }

  check(row: RowInput): Step1Failure | null {
    const r = this.evaluate(row);
    return 'code' in r ? r : null;
  }

  accept(row: RowInput): Step1Failure | null {
    const r = this.evaluate(row);
    if ('code' in r) return r;
    this.rows.push(r.accepted);
    const p = r.accepted.block.payload;
    if (p['event_type'] === 'tool_call') {
      const callId = p['call_id'] as string;
      this.seenCallIds.add(callId);
      this.openCalls.set(callId, { taskId: p['task_id'] as string, seq: r.accepted.block.seq });
    } else if (p['event_type'] === 'tool_result') {
      this.openCalls.delete(p['call_id'] as string);
    }
    return null;
  }

  private evaluate(row: RowInput): { accepted: AcceptedRow } | Step1Failure {
    const index = this.rows.length;
    const atGenesis = index === 0;

    // 1.1 JSON / outer-envelope schema.
    if (row.kind === 'malformed') return atGenesis ? fail('GENESIS_INVALID', 0) : fail('JCS_SCHEMA_INVALID', index);
    if (row.kind === 'unterminated') {
      // A schema failure at that row, with the Step 1.1 parameter rules.
      if (atGenesis) return fail('GENESIS_INVALID', 0);
      const s = row.value === null ? null : checkRowSchema(row.value);
      const seq = s === null ? null : s.ok ? s.block.seq : s.seq;
      return fail('JCS_SCHEMA_INVALID', seq ?? index);
    }
    const schema = checkRowSchema(row.value);
    if (!schema.ok) return atGenesis ? fail('GENESIS_INVALID', 0) : fail('JCS_SCHEMA_INVALID', schema.seq ?? index);
    const { block, entryHash, eventType } = schema;
    const seq = block.seq;
    const payload = block.payload;

    // 1.2 Genesis.
    if (atGenesis) {
      if (
        seq !== 0 ||
        block.prev_hash !== ZERO_HASH ||
        eventType !== 'chain_genesis' ||
        payload['chain_version'] !== CHAIN_VERSION
      ) {
        return fail('GENESIS_INVALID', 0);
      }
    } else if (eventType === 'chain_genesis') {
      return fail('JCS_SCHEMA_INVALID', seq);
    }

    // 1.3 TSA verification bundle.
    if (atGenesis && payload['tsa_ca_bundle_sha256'] !== this.ctx.bundleSha256) return fail('TSA_BUNDLE_MISMATCH', 0);

    // 1.4 Local time format.
    const tsNs = parseTimestampNs(block.ts);
    if (tsNs === null) return fail('TIME_FORMAT_INVALID', seq);

    // 1.5 Identity.
    const genesisChainId = atGenesis ? block.chain_id : this.rows[0]!.block.chain_id;
    if (block.chain_id !== genesisChainId || block.chain_id !== this.ctx.namespaceChainId) {
      return fail('CHAIN_ID_MISMATCH', seq);
    }

    // 1.6 Sequence.
    if (seq < index) return fail('SEQ_DUPLICATE', seq);
    if (seq > index) return fail('SEQ_GAP', index);

    const prev = this.head;
    // 1.7 Monotonicity.
    if (prev !== undefined && tsNs < prev.tsNs) return fail('TS_REGRESSION', seq);

    // 1.8 Hash.
    if (entryHashOf(block) !== entryHash) return fail('HASH_MISMATCH', seq);

    // 1.9 Link.
    if (prev !== undefined && block.prev_hash !== prev.entryHash) return fail('PREV_HASH_MISMATCH', seq);

    // 1.10 Call pairing.
    if (eventType === 'tool_call') {
      if (this.seenCallIds.has(payload['call_id'] as string)) return fail('CALL_CORRELATION_INVALID', seq);
    } else if (eventType === 'tool_result') {
      const open = this.openCalls.get(payload['call_id'] as string);
      if (open === undefined || open.taskId !== payload['task_id']) return fail('CALL_CORRELATION_INVALID', seq);
    }

    return { accepted: { block, entryHash, tsNs } };
  }
}

function fail(code: string, param: number): Step1Failure {
  return { code, param };
}

export type Step1Result =
  | { ok: true; seqFinal: number; rows: readonly AcceptedRow[]; unmatchedCalls: number[] }
  | { ok: false; failure: Step1Failure };

/** Runs Step 1 over a whole sequence, stopping at the first failure. */
export function runStep1(rows: Iterable<RowInput>, ctx: Step1Context): Step1Result {
  const checker = new Step1Checker(ctx);
  for (const row of rows) {
    const failure = checker.accept(row);
    if (failure !== null) return { ok: false, failure };
  }
  const head = checker.head;
  if (head === undefined) return { ok: false, failure: fail('GENESIS_INVALID', 0) };
  return { ok: true, seqFinal: head.block.seq, rows: checker.accepted, unmatchedCalls: checker.unmatchedCalls() };
}
