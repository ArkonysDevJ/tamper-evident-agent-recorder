// SPDX-License-Identifier: AGPL-3.0-or-later
// RFC 8785 JSON Canonicalization Scheme (Blueprint §4.3).
// JSON.stringify already produces the RFC 8785 forms for numbers (ECMAScript
// Number serialization) and for well-formed strings (short escapes for
// \b \t \n \f \r, lowercase \u00xx for other controls, nothing else escaped).
// Lone surrogates are rejected before serialization, never repaired.

import type { JsonValue } from './strict-json.js';

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalizationError';
  }
}

export function canonicalize(value: JsonValue): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new CanonicalizationError('non-finite number');
      return JSON.stringify(value);
    case 'string':
      return serializeString(value);
    default:
      break;
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  // Property names sort by 16-bit code units, which is the default string order.
  const keys = Object.keys(value).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const member = value[key];
    if (member === undefined) throw new CanonicalizationError('undefined member');
    parts.push(serializeString(key) + ':' + canonicalize(member));
  }
  return '{' + parts.join(',') + '}';
}

function serializeString(s: string): string {
  if (!s.isWellFormed()) throw new CanonicalizationError('string contains a lone surrogate');
  return JSON.stringify(s);
}

export function canonicalBytes(value: JsonValue): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}
