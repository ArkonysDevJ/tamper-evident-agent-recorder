// SPDX-License-Identifier: AGPL-3.0-or-later
// Path acceptance of TEAR-TSA-01 (Blueprint §6a). A path is the signer, zero
// or more pinned intermediates, then one bundle root, chained by DER-identical
// issuer and subject Names. Only bundle certificates form paths. Every path is
// tried, so acceptance does not depend on the order of candidates.

import { certificateSignatureScheme, verifySignature } from './algorithms.js';
import type { AllowedKey } from './algorithms.js';
import { meetsSignerRequirements } from './bundle.js';
import type { BundleCertificate, LoadedBundle } from './bundle.js';
import { bytesEqual } from './certificate.js';
import type { Certificate } from './certificate.js';

function validAt(cert: Certificate, atNs: bigint): boolean {
  return cert.notBeforeNs <= atNs && atNs <= cert.notAfterNs;
}

/** The certificate's own signature verifies under the issuer key, with matching inner and outer algorithms. */
export function signedBy(cert: Certificate, issuerKey: AllowedKey): boolean {
  if (!bytesEqual(cert.innerSignatureAlgorithm.encoding, cert.outerSignatureAlgorithm.encoding)) return false;
  const scheme = certificateSignatureScheme(cert.outerSignatureAlgorithm);
  if (scheme === null) return false;
  return verifySignature(issuerKey, scheme, cert.tbs, cert.signature);
}

/**
 * True when at least one acceptable path exists from the signer to a bundle
 * root at the signed genTime. The signer must be DER-identical to a pinned
 * signer. Implementation choice: a root's own pathLenConstraint is not applied
 * (Blueprint §10 leaves it open); intermediates' values are.
 */
export function acceptPath(signer: Certificate, bundle: LoadedBundle, genTimeNs: bigint): boolean {
  const pinned = bundle.certificates.find((c) => c.role === 'signer' && bytesEqual(c.cert.der, signer.der));
  if (pinned === undefined) return false;
  if (!meetsSignerRequirements(pinned.cert) || !validAt(pinned.cert, genTimeNs)) return false;
  const issuers = bundle.certificates.filter((c) => c.role !== 'signer');

  // intermediatesBelow: count of intermediates between the signer and the candidate.
  const extend = (current: Certificate, used: ReadonlySet<BundleCertificate>, intermediatesBelow: number): boolean => {
    for (const next of issuers) {
      if (used.has(next) || !bytesEqual(current.issuer, next.cert.subject)) continue;
      if (!validAt(next.cert, genTimeNs) || !signedBy(current, next.key)) continue;
      if (next.role === 'root') return true;
      const limit = next.cert.basicConstraints?.pathLen ?? null;
      if (limit !== null && BigInt(intermediatesBelow) > limit) continue;
      const nextUsed = new Set(used);
      nextUsed.add(next);
      if (extend(next.cert, nextUsed, intermediatesBelow + 1)) return true;
    }
    return false;
  };
  return extend(pinned.cert, new Set(), 0);
}
