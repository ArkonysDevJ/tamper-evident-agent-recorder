// SPDX-License-Identifier: AGPL-3.0-or-later
// Hash and HMAC derivations of Blueprint §4.3 and §4.4.

import { createHash, createHmac } from 'node:crypto';
import { canonicalBytes } from '../json/jcs.js';
import type { JsonValue } from '../json/strict-json.js';

export function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** entry_hash[i] = HEX_LOWER(SHA256(UTF8_ENCODE(JCS_SERIALIZE(O_i)))) */
export function entryHashOf(block: JsonValue): string {
  return sha256Hex(canonicalBytes(block));
}

/** tsa_ca_bundle_sha256 = HEX_LOWER(SHA256(raw_bytes(tsa_roots.pem))) */
export function bundleSha256(rawBundleBytes: Uint8Array): string {
  return sha256Hex(rawBundleBytes);
}

/** args_hmac = HEX_LOWER(HMAC_SHA256(pepper_bytes, UTF8_ENCODE(JCS_SERIALIZE(args)))) */
export function argsHmac(pepper: Uint8Array, args: JsonValue): string {
  return createHmac('sha256', pepper).update(canonicalBytes(args)).digest('hex');
}

/** result_digest = HEX_LOWER(SHA256(UTF8_ENCODE(JCS_SERIALIZE(result)))) */
export function resultDigest(result: JsonValue): string {
  return sha256Hex(canonicalBytes(result));
}

/** response_digest = HEX_LOWER(SHA256(UTF8_ENCODE(JCS_SERIALIZE(final_response)))) */
export function responseDigest(response: JsonValue): string {
  return sha256Hex(canonicalBytes(response));
}
