// SPDX-License-Identifier: AGPL-3.0-or-later
// Lexical forms shared by rows, packages and paths (Blueprint §4.1).

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const HEX64_RE = /^[0-9a-f]{64}$/;
export const ZERO_HASH = '0'.repeat(64);
export const CHAIN_VERSION = '1.0.4';

export function isChainId(v: unknown): v is string {
  return typeof v === 'string' && UUID_RE.test(v);
}

export function isHex64(v: unknown): v is string {
  return typeof v === 'string' && HEX64_RE.test(v);
}
