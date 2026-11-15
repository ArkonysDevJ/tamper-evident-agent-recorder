// SPDX-License-Identifier: AGPL-3.0-or-later
// RFC 3161 request for anchor k (Blueprint §5.7 step 1): 8 CSPRNG bytes with
// the top bits forced, and a DER TimeStampReq built field by field.

import { randomBytes } from 'node:crypto';
import { algorithm, boolean, integer, octetString, sequence } from '../asn1/encode.js';
import { sha256Hex } from '../crypto/digests.js';
import { OID } from '../pki/oids.js';

/** request_nonce_hex: 16 lowercase hex characters for an integer in [2^62, 2^63 - 1]. */
export function newNonceHex(random: (n: number) => Uint8Array = (n) => randomBytes(n)): string {
  const buf = Uint8Array.from(random(8));
  if (buf.length !== 8) throw new RangeError('nonce needs 8 random bytes');
  buf[0] = (buf[0]! & 0x3f) | 0x40;
  return Buffer.from(buf).toString('hex');
}

export const NONCE_HEX_RE = /^[4-7][0-9a-f]{15}$/;

/**
 * TimeStampReq ::= SEQUENCE { version 1, messageImprint { SHA-256, entry_hash },
 * nonce, certReq TRUE }. No reqPolicy and no extensions. The SHA-256
 * AlgorithmIdentifier has absent parameters (RFC 5754 §2, as §6a asks of new CMS generation).
 */
export function buildTimeStampReq(entryHash: string, nonceHex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(entryHash)) throw new RangeError('entry_hash must be 64 lowercase hex characters');
  if (!NONCE_HEX_RE.test(nonceHex)) throw new RangeError('nonce must match ^[4-7][0-9a-f]{15}$');
  return sequence(
    integer(1n),
    sequence(algorithm(OID.sha256), octetString(Buffer.from(entryHash, 'hex'))),
    integer(BigInt(`0x${nonceHex}`)),
    boolean(true),
  );
}

export interface TimeStampRequest {
  readonly nonceHex: string;
  readonly der: Uint8Array;
  /** tsq_der_sha256 = HEX_LOWER(SHA256(tsq_der_bytes)) */
  readonly derSha256: string;
}

export function newTimeStampRequest(entryHash: string, random?: (n: number) => Uint8Array): TimeStampRequest {
  const nonceHex = newNonceHex(random);
  const der = buildTimeStampReq(entryHash, nonceHex);
  return { nonceHex, der, derSha256: sha256Hex(der) };
}
