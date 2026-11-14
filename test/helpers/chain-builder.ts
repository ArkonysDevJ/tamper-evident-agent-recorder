// SPDX-License-Identifier: AGPL-3.0-or-later
// Builds valid in-memory chains for tests.

import { randomUUID } from 'node:crypto';
import { entryHashOf } from '../../src/crypto/digests.js';
import { ZERO_HASH } from '../../src/chain/ids.js';
import { newJsonObject } from '../../src/json/strict-json.js';
import type { JsonObject, JsonValue } from '../../src/json/strict-json.js';
import { formatTimestamp } from '../../src/time/timestamps.js';

export const TEST_BUNDLE_SHA256 = 'a'.repeat(64);

export function obj(fields: Record<string, JsonValue>): JsonObject {
  const o = newJsonObject();
  for (const [k, v] of Object.entries(fields)) o[k] = v;
  return o;
}

export function genesisPayload(bundle = TEST_BUNDLE_SHA256): JsonObject {
  return obj({
    event_type: 'chain_genesis',
    operation: 'tear.genesis',
    chain_version: '1.0.4',
    pepper_id: 'test-pepper',
    tsa_ca_bundle_sha256: bundle,
  });
}

export function pausePayload(i: number): JsonObject {
  return obj({
    event_type: 'epistemic_pause',
    operation: 'tear.epistemic_pause',
    task_id: `task-${i}`,
    reason: `reason ${i}`,
    missing_sources: [],
  });
}

export interface BuiltRow {
  block: JsonObject;
  entry_hash: string;
}

export function envelope(block: JsonObject, entryHash: string): JsonObject {
  return obj({ block, entry_hash: entryHash });
}

/** Builds rows 0..payloads.length with valid links, hashes and increasing timestamps. */
export function buildChain(
  payloads: JsonObject[],
  opts: { chainId?: string; startMs?: number; bundleSha256?: string } = {},
): BuiltRow[] {
  const chainId = opts.chainId ?? randomUUID();
  const start = opts.startMs ?? Date.UTC(2026, 10, 13, 12, 0, 0);
  const rows: BuiltRow[] = [];
  let prev = ZERO_HASH;
  [genesisPayload(opts.bundleSha256), ...payloads].forEach((payload, seq) => {
    const block = obj({ chain_id: chainId, seq, ts: formatTimestamp(start + seq * 100), prev_hash: prev, payload });
    const entry = entryHashOf(block);
    rows.push({ block, entry_hash: entry });
    prev = entry;
  });
  return rows;
}

/** Recomputes entry_hash and prev_hash from row `from` to the end. */
export function rehash(rows: BuiltRow[], from = 0): void {
  for (let i = from; i < rows.length; i++) {
    const row = rows[i]!;
    if (i > 0) row.block['prev_hash'] = rows[i - 1]!.entry_hash;
    row.entry_hash = entryHashOf(row.block);
  }
}

export function chainIdOf(rows: BuiltRow[]): string {
  return rows[0]!.block['chain_id'] as string;
}
