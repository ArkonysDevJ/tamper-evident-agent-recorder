// SPDX-License-Identifier: AGPL-3.0-or-later
// SQL representation authority and consistency (Blueprint §5.3): block_json is
// the authoritative O_i, entry_hash its commitment, the other columns are
// mirrors. Every loaded row is checked before it is used for any decision.

import { sha256Hex } from '../crypto/digests.js';
import { canonicalize } from '../json/jcs.js';
import { StrictJsonError, newJsonObject, parseStrictJson } from '../json/strict-json.js';
import type { JsonValue } from '../json/strict-json.js';
import { checkRowSchema } from './schema.js';
import type { Block } from './schema.js';

/** One tear_events row as loaded; bigint and jsonb columns arrive as text. */
export interface SqlEventRow {
  readonly chain_id: string;
  readonly seq: string;
  readonly ts: string;
  readonly prev_hash: string;
  readonly payload: string;
  readonly block_json: string;
  readonly entry_hash: string;
}

export const LOAD_EVENTS_SQL = `SELECT chain_id::text AS chain_id, seq::text AS seq, ts, prev_hash,
  payload::text AS payload, block_json, entry_hash
  FROM tear_events WHERE chain_id = $1 ORDER BY tear_events.seq ASC`;
// Order by the bigint column, not the text alias: text order puts "10" before "2".

export type SqlRowCheck = { ok: true; envelope: JsonValue; block: Block } | { ok: false; reason: string };

/**
 * Checks one SQL row: strict parse of block_json, byte equality with its
 * RFC 8785 reserialization, entry_hash, row schema, and equality of every
 * mirror with the parsed block. No column is ever repaired or preferred.
 */
export function checkSqlRow(row: SqlEventRow): SqlRowCheck {
  let parsed: JsonValue;
  try {
    parsed = parseStrictJson(row.block_json);
  } catch (err) {
    if (err instanceof StrictJsonError) return { ok: false, reason: `block_json: ${err.kind}` };
    throw err;
  }
  if (canonicalize(parsed) !== row.block_json) return { ok: false, reason: 'block_json is not canonical' };
  if (sha256Hex(Buffer.from(row.block_json, 'utf8')) !== row.entry_hash) return { ok: false, reason: 'entry_hash mismatch' };

  const envelope = newJsonObject();
  envelope['block'] = parsed;
  envelope['entry_hash'] = row.entry_hash;
  const schema = checkRowSchema(envelope);
  if (!schema.ok) return { ok: false, reason: `block schema: ${schema.reason}` };
  const block = schema.block;

  if (row.chain_id !== block.chain_id) return { ok: false, reason: 'chain_id mirror' };
  if (!/^(0|[1-9][0-9]*)$/.test(row.seq) || BigInt(row.seq) !== BigInt(block.seq)) {
    return { ok: false, reason: 'seq mirror' };
  }
  if (row.ts !== block.ts) return { ok: false, reason: 'ts mirror' };
  if (row.prev_hash !== block.prev_hash) return { ok: false, reason: 'prev_hash mirror' };
  let mirrorPayload: JsonValue;
  try {
    mirrorPayload = parseStrictJson(row.payload);
  } catch {
    return { ok: false, reason: 'payload mirror is not valid JSON' };
  }
  if (canonicalize(mirrorPayload) !== canonicalize(block.payload)) return { ok: false, reason: 'payload mirror' };
  return { ok: true, envelope, block };
}
