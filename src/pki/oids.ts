// SPDX-License-Identifier: AGPL-3.0-or-later
// Object identifiers used by the TEAR-TSA-01 profile (Blueprint §6a).

export const OID = {
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',

  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  sha384WithRSA: '1.2.840.113549.1.1.12',
  sha512WithRSA: '1.2.840.113549.1.1.13',
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  ecdsaSha384: '1.2.840.10045.4.3.3',
  ecdsaSha512: '1.2.840.10045.4.3.4',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.3.132.0.34',
  p521: '1.3.132.0.35',

  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  attrContentType: '1.2.840.113549.1.9.3',
  attrMessageDigest: '1.2.840.113549.1.9.4',
  attrSigningCertificate: '1.2.840.113549.1.9.16.2.12',
  attrSigningCertificateV2: '1.2.840.113549.1.9.16.2.47',

  extKeyUsage: '2.5.29.15',
  extBasicConstraints: '2.5.29.19',
  extExtendedKeyUsage: '2.5.29.37',
  extSubjectAltName: '2.5.29.17',
  kpTimeStamping: '1.3.6.1.5.5.7.3.8',
} as const;

export type DigestName = 'sha256' | 'sha384' | 'sha512';

/** The CMS digest OIDs this profile allows, with their node:crypto names. */
export const DIGEST_BY_OID: ReadonlyMap<string, DigestName> = new Map([
  [OID.sha256, 'sha256'],
  [OID.sha384, 'sha384'],
  [OID.sha512, 'sha512'],
]);

export const NAMED_CURVE_BY_OID: ReadonlyMap<string, string> = new Map([
  [OID.p256, 'prime256v1'],
  [OID.p384, 'secp384r1'],
  [OID.p521, 'secp521r1'],
]);
