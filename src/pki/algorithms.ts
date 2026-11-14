// SPDX-License-Identifier: AGPL-3.0-or-later
// Algorithm identifiers, public keys and signature checks allowed by
// TEAR-TSA-01 (Blueprint §6a). Every hash, key load and signature check goes
// through node:crypto; this module only decides what is allowed.

import { createPublicKey, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { decodeDer, encodingOf } from '../asn1/der.js';
import type { DerDocument, Tlv } from '../asn1/der.js';
import { Asn1Error, Fields, TAG, bitString, expectTag, nullValue, oid, seq } from '../asn1/types.js';
import { DIGEST_BY_OID, NAMED_CURVE_BY_OID, OID } from './oids.js';
import type { DigestName } from './oids.js';

export type ParamsForm = 'absent' | 'null' | 'other';

export interface AlgorithmId {
  readonly oid: string;
  readonly params: ParamsForm;
  /** The full DER encoding of the AlgorithmIdentifier. */
  readonly encoding: Uint8Array;
}

export function algorithmId(doc: DerDocument, el: Tlv | undefined, what: string): AlgorithmId {
  const items = seq(doc, el, what);
  const id = oid(doc, items[0], `${what}.algorithm`);
  if (items.length > 2) throw new Asn1Error(`${what}: extra fields`);
  let params: ParamsForm = 'absent';
  const p = items[1];
  if (p !== undefined) {
    if (p.tag === TAG.NULL) {
      nullValue(doc, p, `${what}.parameters`);
      params = 'null';
    } else {
      params = 'other';
    }
  }
  return { oid: id, params, encoding: encodingOf(doc, el!) };
}

/** A SHA-2 digest identifier with absent or NULL parameters (RFC 5754 §2, RFC 4055 §2.1), or null. */
export function sha2Digest(a: AlgorithmId): DigestName | null {
  if (a.params === 'other') return null;
  return DIGEST_BY_OID.get(a.oid) ?? null;
}

export type KeyFamily = 'rsa' | 'ec';

export interface SignatureScheme {
  readonly family: KeyFamily;
  readonly digest: DigestName;
}

const RSA_WITH: ReadonlyMap<string, DigestName> = new Map([
  [OID.sha256WithRSA, 'sha256'],
  [OID.sha384WithRSA, 'sha384'],
  [OID.sha512WithRSA, 'sha512'],
]);
const ECDSA_WITH: ReadonlyMap<string, DigestName> = new Map([
  [OID.ecdsaSha256, 'sha256'],
  [OID.ecdsaSha384, 'sha384'],
  [OID.ecdsaSha512, 'sha512'],
]);

/**
 * A certificate signatureAlgorithm: RSA PKCS#1 v1.5 with SHA-2 (parameters NULL
 * or absent) or ECDSA with SHA-2 (parameters absent). Anything else is null.
 */
export function certificateSignatureScheme(a: AlgorithmId): SignatureScheme | null {
  const rsa = RSA_WITH.get(a.oid);
  if (rsa !== undefined) return a.params === 'other' ? null : { family: 'rsa', digest: rsa };
  const ec = ECDSA_WITH.get(a.oid);
  if (ec !== undefined) return a.params === 'absent' ? { family: 'ec', digest: ec } : null;
  return null;
}

/**
 * A CMS SignerInfo signatureAlgorithm combined with its digestAlgorithm. The
 * digest must agree, including when rsaEncryption names PKCS#1 v1.5 alone.
 */
export function cmsSignatureScheme(signature: AlgorithmId, digest: DigestName): SignatureScheme | null {
  if (signature.oid === OID.rsaEncryption) return signature.params === 'other' ? null : { family: 'rsa', digest };
  const s = certificateSignatureScheme(signature);
  return s !== null && s.digest === digest ? s : null;
}

export interface AllowedKey {
  readonly family: KeyFamily;
  readonly key: KeyObject;
}

/**
 * Loads a SubjectPublicKeyInfo if it is an allowed key: RSA (rsaEncryption,
 * NULL parameters) of at least 2048 bits, or EC on a named P-256, P-384 or
 * P-521 curve. Explicit EC parameters, RSA-PSS, DSA, EdDSA and others are null.
 */
export function allowedPublicKey(spki: Uint8Array): AllowedKey | null {
  let doc: DerDocument;
  let alg: AlgorithmId;
  let curveOid: string | null = null;
  try {
    doc = decodeDer(spki);
    const f = new Fields(seq(doc, doc.root, 'SubjectPublicKeyInfo'), 'SubjectPublicKeyInfo');
    const algEl = f.next(TAG.SEQUENCE, 'algorithm');
    alg = algorithmId(doc, algEl, 'SubjectPublicKeyInfo.algorithm');
    bitString(doc, f.next(TAG.BIT_STRING, 'subjectPublicKey'), 'subjectPublicKey');
    f.end();
    if (alg.oid === OID.ecPublicKey) {
      const params = seq(doc, algEl, 'algorithm')[1];
      if (params?.tag !== TAG.OID) return null;
      curveOid = oid(doc, expectTag(params, TAG.OID, 'namedCurve'), 'namedCurve');
    }
  } catch {
    return null;
  }
  let key: KeyObject;
  try {
    key = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
  } catch {
    return null;
  }
  const details = key.asymmetricKeyDetails;
  if (alg.oid === OID.rsaEncryption) {
    if (alg.params !== 'null' || key.asymmetricKeyType !== 'rsa') return null;
    return (details?.modulusLength ?? 0) >= 2048 ? { family: 'rsa', key } : null;
  }
  if (alg.oid === OID.ecPublicKey && curveOid !== null) {
    const curve = NAMED_CURVE_BY_OID.get(curveOid);
    if (curve === undefined || key.asymmetricKeyType !== 'ec' || details?.namedCurve !== curve) return null;
    return { family: 'ec', key };
  }
  return null;
}

/** Verifies a signature with node:crypto; any error counts as an invalid signature. */
export function verifySignature(key: AllowedKey, scheme: SignatureScheme, data: Uint8Array, signature: Uint8Array): boolean {
  if (key.family !== scheme.family) return false;
  try {
    return verify(scheme.digest, data, key.key, signature);
  } catch {
    return false;
  }
}
