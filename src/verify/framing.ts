// SPDX-License-Identifier: AGPL-3.0-or-later
// Physical JSONL framing of an exported log (Blueprint §6 Step 1).
// Rows are LF-terminated. A single final LF ends the last row; an extra LF is
// an empty row. UTF-8 is decoded strictly and a BOM is never stripped, so a
// leading BOM makes row 0 invalid. Rows are produced lazily in file order: no
// pre-scan for later empty rows.

import type { RowInput } from '../chain/step1.js';
import { parseStrictJson } from '../json/strict-json.js';
import type { JsonValue } from '../json/strict-json.js';

const LF = 0x0a;

function decodeRow(bytes: Uint8Array): JsonValue | null {
  if (bytes.length === 0) return null;
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    return parseStrictJson(text);
  } catch {
    return null;
  }
}

export function* logRows(bytes: Uint8Array): Generator<RowInput> {
  if (bytes.length === 0) {
    // A zero-byte file: row 0 is empty.
    yield { kind: 'malformed' };
    return;
  }
  let start = 0;
  for (;;) {
    const end = bytes.indexOf(LF, start);
    if (end === -1) {
      if (start < bytes.length) yield { kind: 'unterminated', value: decodeRow(bytes.subarray(start)) };
      return;
    }
    const value = decodeRow(bytes.subarray(start, end));
    yield value === null ? { kind: 'malformed' } : { kind: 'json', value };
    start = end + 1;
  }
}
