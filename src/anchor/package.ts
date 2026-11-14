// SPDX-License-Identifier: AGPL-3.0-or-later
// Anchor package <k>.anchor.json (Blueprint §4.5) and its Step 2.1 check.

import { entryHashOf } from '../crypto/digests.js';
import { isChainId, isHex64 } from '../chain/ids.js';
import type { Block } from '../chain/schema.js';
import { canonicalize, CanonicalizationError } from '../json/jcs.js';
import { hasOwn, isJsonObject, newJsonObject, parseStrictJson } from '../json/strict-json.js';
import type { JsonObject } from '../json/strict-json.js';
import { NONCE_HEX_RE } from '../tsa/request.js';

export const ANCHOR_VERSION = '1.0';

const PACKAGE_KEYS = [
  'anchor_version',
  'chain_id',
  'anchored_seq',
  'entry_hash',
  'block',
  'request_nonce_hex',
  'tsq_der_sha256',
] as const;

export interface AnchorPackage {
  readonly chainId: string;
  readonly anchoredSeq: number;
  readonly entryHash: string;
  readonly block: JsonObject;
  readonly nonceHex: string;
  readonly tsqSha256: string;
}

/** The bytes written to <k>.anchor.json: the RFC 8785 serialization of the package. */
export function anchorPackageBytes(p: AnchorPackage): Uint8Array {
  const o = newJsonObject();
  o['anchor_version'] = ANCHOR_VERSION;
  o['chain_id'] = p.chainId;
  o['anchored_seq'] = p.anchoredSeq;
  o['entry_hash'] = p.entryHash;
  o['block'] = p.block;
  o['request_nonce_hex'] = p.nonceHex;
  o['tsq_der_sha256'] = p.tsqSha256;
  return Buffer.from(canonicalize(o), 'utf8');
}

/**
 * Step 2.1: valid UTF-8 JSON without duplicate keys, the exact §4.5 schema,
 * chain id, anchored_seq == k, block.seq == k and the block hash. Returns the
 * package or null (ANCHOR_PACKAGE_INCOMPLETE <k>).
 *
 * Implementation choice (not normative; §10 leaves the placement open): Step
 * 2.1 checks block only as a JSON object with seq == k whose canonical hash is
 * entry_hash. Its full row schema is checked at Step 2.6, through byte
 * equality with the log row k that already passed Step 1.
 */
export function checkAnchorPackage(bytes: Uint8Array, chainId: string, k: number): AnchorPackage | null {
  let value;
  try {
    value = parseStrictJson(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    return null;
  }
  if (!isJsonObject(value)) return null;
  const keys = Object.keys(value);
  if (keys.length !== PACKAGE_KEYS.length || !PACKAGE_KEYS.every((key) => hasOwn(value, key))) return null;
  const v = value;
  if (v['anchor_version'] !== ANCHOR_VERSION) return null;
  if (!isChainId(v['chain_id']) || v['chain_id'] !== chainId) return null;
  const seq = v['anchored_seq'];
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 1 || seq !== k) return null;
  if (!isHex64(v['entry_hash'])) return null;
  const nonce = v['request_nonce_hex'];
  if (typeof nonce !== 'string' || !NONCE_HEX_RE.test(nonce)) return null;
  if (!isHex64(v['tsq_der_sha256'])) return null;
  const block = v['block'];
  if (!isJsonObject(block) || block['seq'] !== k) return null;
  let hash: string;
  try {
    hash = entryHashOf(block);
  } catch (err) {
    if (err instanceof CanonicalizationError) return null;
    throw err;
  }
  if (hash !== v['entry_hash']) return null;
  return { chainId, anchoredSeq: k, entryHash: hash, block: block as Block, nonceHex: nonce, tsqSha256: v['tsq_der_sha256'] };
}
