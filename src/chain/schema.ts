// SPDX-License-Identifier: AGPL-3.0-or-later
// Row envelope and payload schemas (Blueprint §4.1, §4.4). This is the lexical
// check of Step 1.1; relational checks (genesis, identity, sequence, time,
// hash, link, pairing) live in step1.ts.

import { hasOwn, isJsonObject } from '../json/strict-json.js';
import type { JsonObject, JsonValue } from '../json/strict-json.js';
import { parseGeneralizedTimeNs } from '../time/timestamps.js';
import { isChainId, isHex64 } from './ids.js';

export const APPLICATION_EVENT_TYPES = [
  'tool_call',
  'tool_result',
  'epistemic_pause',
  'human_resolution',
  'agent_final_response',
] as const;
export const CONTROL_EVENT_TYPES = ['checkpoint_anchored', 'checkpoint_failed'] as const;

export type ApplicationEventType = (typeof APPLICATION_EVENT_TYPES)[number];
export type ControlEventType = (typeof CONTROL_EVENT_TYPES)[number];
export type EventType = 'chain_genesis' | ApplicationEventType | ControlEventType;

/** O_i: exactly chain_id, seq, ts, prev_hash, payload. */
export interface Block extends JsonObject {
  chain_id: string;
  seq: number;
  ts: string;
  prev_hash: string;
  payload: JsonObject;
}

export type RowSchemaResult =
  | { ok: true; block: Block; entryHash: string; eventType: EventType }
  // seq is the block's own seq when the schema could supply a valid one (§6 Step 1.1).
  | { ok: false; seq: number | null; reason: string };

type FieldCheck = (v: JsonValue | undefined) => boolean;

const nonEmptyString: FieldCheck = (v) => typeof v === 'string' && v.length > 0;
const nullableNonEmptyString: FieldCheck = (v) => v === null || nonEmptyString(v);
const hex64: FieldCheck = (v) => isHex64(v);
const safeIntAtLeast =
  (min: number): FieldCheck =>
  (v) =>
    typeof v === 'number' && Number.isSafeInteger(v) && v >= min;
const nonEmptyStringArray: FieldCheck = (v) => Array.isArray(v) && v.every((x) => nonEmptyString(x));
const genTimeLexical: FieldCheck = (v) => typeof v === 'string' && parseGeneralizedTimeNs(v) !== null;

const PAYLOAD_SCHEMAS: Record<EventType, Record<string, FieldCheck>> = {
  chain_genesis: {
    chain_version: (v) => v === '1.0.4',
    pepper_id: nonEmptyString,
    tsa_ca_bundle_sha256: hex64,
  },
  tool_call: { tool_name: nonEmptyString, call_id: nonEmptyString, task_id: nonEmptyString, args_hmac: hex64 },
  tool_result: {
    call_id: nonEmptyString,
    task_id: nonEmptyString,
    error_type: nullableNonEmptyString,
    result_digest: hex64,
    summary: nonEmptyString,
  },
  epistemic_pause: { task_id: nonEmptyString, reason: nonEmptyString, missing_sources: nonEmptyStringArray },
  human_resolution: { task_id: nonEmptyString, reviewer_id: nonEmptyString, decision: nonEmptyString },
  agent_final_response: { task_id: nonEmptyString, response_digest: hex64 },
  checkpoint_anchored: { anchored_seq: safeIntAtLeast(1), tsr_sha256: hex64, tsa_gen_time: genTimeLexical },
  checkpoint_failed: { target_seq: safeIntAtLeast(1), error_type: nonEmptyString },
};

export function isEventType(v: unknown): v is EventType {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(PAYLOAD_SCHEMAS, v);
}

export function isApplicationEventType(v: unknown): v is ApplicationEventType {
  return (APPLICATION_EVENT_TYPES as readonly string[]).includes(v as string);
}

function hasExactKeys(obj: JsonObject, keys: readonly string[]): boolean {
  const own = Object.keys(obj);
  return own.length === keys.length && keys.every((k) => hasOwn(obj, k));
}

/** True if every string inside the value is well-formed Unicode and free of U+0000 (§4.3, §4.4). */
function payloadStringsValid(v: JsonValue): boolean {
  if (typeof v === 'string') return v.isWellFormed() && !v.includes('\u0000');
  if (Array.isArray(v)) return v.every(payloadStringsValid);
  if (isJsonObject(v)) return Object.keys(v).every((k) => k.isWellFormed() && payloadStringsValid(v[k]!));
  return true;
}

/** True if every string and key in the value is well-formed Unicode (§4.3). */
export function allStringsWellFormed(v: JsonValue): boolean {
  if (typeof v === 'string') return v.isWellFormed();
  if (Array.isArray(v)) return v.every(allStringsWellFormed);
  if (isJsonObject(v)) return Object.keys(v).every((k) => k.isWellFormed() && allStringsWellFormed(v[k]!));
  return true;
}

/** Validates a payload object for its event type, including the seq category rules of §4.4. */
export function checkPayload(payload: JsonValue | undefined, seq: number | null): string | null {
  if (!isJsonObject(payload)) return 'payload is not an object';
  const eventType = payload['event_type'];
  if (!isEventType(eventType)) return 'unknown event_type';
  if (!nonEmptyString(payload['operation'])) return 'operation must be a non-empty string';
  const schema = PAYLOAD_SCHEMAS[eventType];
  const keys = ['event_type', 'operation', ...Object.keys(schema)];
  if (!hasExactKeys(payload, keys)) return `payload keys do not match ${eventType}`;
  for (const [key, check] of Object.entries(schema)) {
    if (!check(payload[key])) return `invalid ${eventType}.${key}`;
  }
  if (!payloadStringsValid(payload)) return 'payload string contains U+0000 or a lone surrogate';
  if (seq !== null) {
    if (eventType === 'chain_genesis' && seq !== 0) return 'chain_genesis is only permitted at seq 0';
    if (eventType !== 'chain_genesis' && seq < 1) return `${eventType} is only permitted at seq >= 1`;
  }
  return null;
}

/** Step 1.1: envelope and payload schema of one row (§4.1, §4.4, §6). */
export function checkRowSchema(row: JsonValue): RowSchemaResult {
  if (!isJsonObject(row) || !hasExactKeys(row, ['block', 'entry_hash'])) {
    return { ok: false, seq: null, reason: 'row must have exactly block and entry_hash' };
  }
  const block = row['block'];
  if (!isJsonObject(block)) return { ok: false, seq: null, reason: 'block is not an object' };
  const rawSeq = block['seq'];
  const seq = typeof rawSeq === 'number' && Number.isSafeInteger(rawSeq) && rawSeq >= 0 ? rawSeq : null;
  const fail = (reason: string): RowSchemaResult => ({ ok: false, seq, reason });

  if (!hasExactKeys(block, ['chain_id', 'seq', 'ts', 'prev_hash', 'payload'])) return fail('block keys');
  if (seq === null) return fail('seq must be a safe nonnegative integer');
  const entryHash = row['entry_hash'];
  if (!isHex64(entryHash)) return fail('entry_hash must be 64 lowercase hex');
  if (!isChainId(block['chain_id'])) return fail('chain_id must be a lowercase UUID');
  if (!isHex64(block['prev_hash'])) return fail('prev_hash must be 64 lowercase hex');
  if (typeof block['ts'] !== 'string') return fail('ts must be a string');
  if (!allStringsWellFormed(block)) return fail('block contains a lone surrogate');
  const payloadError = checkPayload(block['payload'], seq);
  if (payloadError !== null) return fail(payloadError);
  const payload = block['payload'] as JsonObject;
  return { ok: true, block: block as Block, entryHash, eventType: payload['event_type'] as EventType };
}
