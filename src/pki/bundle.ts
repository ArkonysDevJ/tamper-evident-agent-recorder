// SPDX-License-Identifier: AGPL-3.0-or-later
// --tsa-ca-bundle loading (Blueprint §6a): the strict PEM grammar of RFC 7468,
// one DER certificate per CERTIFICATE block, each role derived from the
// certificate bytes alone, and the loading checks of the pinned profile.
// Loading reads only the given bytes: no network and no system trust store.

import { allowedPublicKey } from './algorithms.js';
import type { AllowedKey } from './algorithms.js';
import { KEY_USAGE, parseCertificate } from './certificate.js';
import type { Certificate } from './certificate.js';
import { bitSet, highestBit } from '../asn1/types.js';
import { OID } from './oids.js';

export class BundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BundleError';
  }
}

export type Role = 'root' | 'intermediate' | 'signer';

export interface BundleCertificate {
  readonly cert: Certificate;
  readonly role: Role;
  readonly key: AllowedKey;
}

export interface LoadedBundle {
  readonly certificates: readonly BundleCertificate[];
}

const BEGIN = '-----BEGIN CERTIFICATE-----';
const END = '-----END CERTIFICATE-----';
const B64_LINE = /^[A-Za-z0-9+/]+={0,2}$/;

/** Splits the file into lines, accepting LF or CRLF line breaks only. */
function lines(text: string): string[] {
  const out: string[] = [];
  let p = 0;
  while (p < text.length) {
    const lf = text.indexOf('\n', p);
    if (lf < 0) {
      if (text.includes('\r', p)) throw new BundleError('bare CR');
      out.push(text.slice(p));
      return out;
    }
    let line = text.slice(p, lf);
    if (line.endsWith('\r')) line = line.slice(0, -1);
    if (line.includes('\r')) throw new BundleError('bare CR');
    out.push(line);
    p = lf + 1;
  }
  return out;
}

/** Parses the strict RFC 7468 grammar and returns the DER of each CERTIFICATE block. */
export function parsePemBundle(raw: Uint8Array): Uint8Array[] {
  const text = new TextDecoder('ascii', { fatal: false }).decode(raw);
  for (const b of raw) if (b > 0x7e) throw new BundleError('non-ASCII byte');
  const ls = lines(text);
  const blocks: Uint8Array[] = [];
  let i = 0;
  while (i < ls.length) {
    const line = ls[i]!;
    if (line === '') {
      i++;
      continue;
    }
    if (line !== BEGIN) throw new BundleError(`unexpected text outside a block at line ${String(i + 1)}`);
    i++;
    const body: string[] = [];
    while (i < ls.length && ls[i] !== END) body.push(ls[i++]!);
    if (i >= ls.length) throw new BundleError('unterminated block');
    i++; // The END line may close the file without a final line break.
    if (body.length === 0) throw new BundleError('empty block');
    body.forEach((b, n) => {
      const isLast = n === body.length - 1;
      if (!B64_LINE.test(b)) throw new BundleError('invalid base64 line');
      if (!isLast && b.length !== 64) throw new BundleError('base64 line is not 64 characters');
      if (isLast && (b.length === 0 || b.length > 64 || b.length % 4 !== 0)) throw new BundleError('invalid final base64 line');
      if (!isLast && b.includes('=')) throw new BundleError('padding before the final line');
    });
    const b64 = body.join('');
    const der = Buffer.from(b64, 'base64');
    if (der.toString('base64') !== b64) throw new BundleError('noncanonical base64');
    blocks.push(new Uint8Array(der));
  }
  if (blocks.length === 0) throw new BundleError('no CERTIFICATE block');
  return blocks;
}

/** Signer requirements of "Path acceptance": critical EKU of exactly id-kp-timeStamping, and keyUsage limits. */
export function meetsSignerRequirements(cert: Certificate): boolean {
  const eku = cert.extendedKeyUsage;
  if (eku === null || !eku.critical) return false;
  if (eku.purposes.length !== 1 || eku.purposes[0] !== OID.kpTimeStamping) return false;
  const ku = cert.keyUsage;
  if (ku !== null) {
    const allowed = bitSet(ku, KEY_USAGE.digitalSignature) || bitSet(ku, KEY_USAGE.contentCommitment);
    if (!allowed || highestBit(ku) > KEY_USAGE.contentCommitment) return false;
  }
  return true;
}

const ALLOWED_CRITICAL: ReadonlySet<string> = new Set([
  OID.extKeyUsage,
  OID.extBasicConstraints,
  OID.extExtendedKeyUsage,
  OID.extSubjectAltName,
]);

function hasKeyCertSignIfKeyUsage(cert: Certificate): boolean {
  return cert.keyUsage === null || bitSet(cert.keyUsage, KEY_USAGE.keyCertSign);
}

/** Derives the role of a certificate from its bytes and applies the loading checks of its role. */
export function classify(cert: Certificate): Role {
  const isCa = cert.basicConstraints?.ca === true;
  if (cert.selfIssued) {
    if (!isCa) throw new BundleError('self-issued certificate without CA=true');
    if (!hasKeyCertSignIfKeyUsage(cert)) throw new BundleError('root keyUsage without keyCertSign');
    return 'root';
  }
  if (isCa) {
    if (!hasKeyCertSignIfKeyUsage(cert)) throw new BundleError('intermediate keyUsage without keyCertSign');
    return 'intermediate';
  }
  if (!meetsSignerRequirements(cert)) throw new BundleError('signer does not meet the signer requirements');
  return 'signer';
}

/** Loads the bundle; throws BundleError (or a DER error) on any loading failure. */
export function loadBundle(raw: Uint8Array): LoadedBundle {
  const certificates: BundleCertificate[] = [];
  for (const der of parsePemBundle(raw)) {
    let cert: Certificate;
    try {
      cert = parseCertificate(der);
    } catch (err) {
      throw new BundleError(`certificate does not decode: ${(err as Error).message}`);
    }
    const key = allowedPublicKey(cert.spki);
    if (key === null) throw new BundleError('public key outside the profile');
    for (const e of cert.extensions) {
      if (e.critical && !ALLOWED_CRITICAL.has(e.oid)) throw new BundleError(`critical extension outside the allowlist: ${e.oid}`);
    }
    certificates.push({ cert, role: classify(cert), key });
  }
  if (!certificates.some((c) => c.role === 'root')) throw new BundleError('no root');
  if (!certificates.some((c) => c.role === 'signer')) throw new BundleError('no signer');
  return { certificates };
}
