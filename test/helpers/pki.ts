// SPDX-License-Identifier: AGPL-3.0-or-later
// Test PKI: builds certificates, PEM bundles and RFC 3161 responses with
// node:crypto keys, so every TEAR-TSA-01 vector can be constructed with
// consistent signatures. Test-only; nothing here is used by src/.

import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import {
  algorithm,
  boolean,
  concat,
  integer,
  nullValue,
  octetString,
  oid,
  sequence,
  set,
  tlv,
} from '../../src/asn1/encode.js';
import { parseCertificate } from '../../src/pki/certificate.js';
import { OID } from '../../src/pki/oids.js';

export { algorithm, boolean, concat, integer, nullValue, octetString, oid, sequence, set, tlv };

// ---------- keys ----------

export interface KeyPair {
  readonly publicKey: KeyObject;
  readonly privateKey: KeyObject;
  readonly family: 'rsa' | 'ec';
}

const keyCache = new Map<string, KeyPair>();

/** Cached key pairs; `id` lets a test ask for a distinct key of the same kind. */
export function key(kind: 'rsa2048' | 'rsa1024' | 'p256' | 'p384' | 'secp256k1' | 'ed25519' | 'rsa-pss', id = 0): KeyPair {
  const cacheKey = `${kind}/${String(id)}`;
  const hit = keyCache.get(cacheKey);
  if (hit !== undefined) return hit;
  let kp: { publicKey: KeyObject; privateKey: KeyObject };
  let family: 'rsa' | 'ec' = 'rsa';
  switch (kind) {
    case 'rsa2048':
      kp = generateKeyPairSync('rsa', { modulusLength: 2048 });
      break;
    case 'rsa1024':
      kp = generateKeyPairSync('rsa', { modulusLength: 1024 });
      break;
    case 'rsa-pss':
      kp = generateKeyPairSync('rsa-pss', { modulusLength: 2048 });
      break;
    case 'p256':
      kp = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      family = 'ec';
      break;
    case 'p384':
      kp = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
      family = 'ec';
      break;
    case 'secp256k1':
      kp = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
      family = 'ec';
      break;
    case 'ed25519':
      kp = generateKeyPairSync('ed25519');
      family = 'ec';
      break;
  }
  const pair = { ...kp, family };
  keyCache.set(cacheKey, pair);
  return pair;
}

export function spkiOf(k: KeyPair): Uint8Array {
  return new Uint8Array(k.publicKey.export({ type: 'spki', format: 'der' }));
}

// ---------- names ----------

export type StringType = 'utf8' | 'printable';

/** A Name with one attribute per RDN: [type OID, value, string type]. */
export function name(...attrs: [string, string, StringType?][]): Uint8Array {
  return sequence(
    ...attrs.map(([type, value, st]) =>
      set(sequence(oid(type), tlv(st === 'printable' ? 0x13 : 0x0c, Buffer.from(value, 'utf8')))),
    ),
  );
}

export const CN = '2.5.4.3';
export const O = '2.5.4.10';

export function cn(value: string, st: StringType = 'utf8'): Uint8Array {
  return name([O, 'TEAR test'], [CN, value, st]);
}

// ---------- extensions ----------

export interface ExtSpec {
  readonly oid: string;
  readonly critical?: boolean;
  /** Encode critical FALSE explicitly (a DER violation). */
  readonly explicitFalse?: boolean;
  readonly value: Uint8Array;
}

export function extension(e: ExtSpec): Uint8Array {
  const parts = [oid(e.oid)];
  if (e.critical === true) parts.push(boolean(true));
  else if (e.explicitFalse === true) parts.push(boolean(false));
  parts.push(octetString(e.value));
  return sequence(...parts);
}

export function basicConstraintsValue(ca: boolean, pathLen?: bigint): Uint8Array {
  const parts: Uint8Array[] = [];
  if (ca) parts.push(boolean(true));
  if (pathLen !== undefined) parts.push(integer(pathLen));
  return sequence(...parts);
}

/** keyUsage BIT STRING with the given bit numbers set, minimal (no trailing zero bits). */
export function keyUsageValue(bits: number[]): Uint8Array {
  const max = Math.max(...bits);
  const bytes = new Uint8Array((max >> 3) + 1);
  for (const b of bits) bytes[b >> 3]! |= 0x80 >> (b & 7);
  const unused = 7 - (max & 7);
  return tlv(0x03, concat([Uint8Array.of(unused), bytes]));
}

export function ekuValue(purposes: string[]): Uint8Array {
  return sequence(...purposes.map((p) => oid(p)));
}

export function directoryName(n: Uint8Array): Uint8Array {
  return tlv(0xa4, n);
}

export function dnsName(host: string): Uint8Array {
  return tlv(0x82, Buffer.from(host, 'ascii'));
}

export function sanValue(names: Uint8Array[]): Uint8Array {
  return sequence(...names);
}

export const ext = {
  bc: (ca: boolean, critical = true, pathLen?: bigint): ExtSpec => ({
    oid: OID.extBasicConstraints,
    critical,
    value: basicConstraintsValue(ca, pathLen),
  }),
  ku: (bits: number[], critical = true): ExtSpec => ({ oid: OID.extKeyUsage, critical, value: keyUsageValue(bits) }),
  eku: (purposes: string[], critical = true): ExtSpec => ({ oid: OID.extExtendedKeyUsage, critical, value: ekuValue(purposes) }),
  san: (names: Uint8Array[], critical = false): ExtSpec => ({ oid: OID.extSubjectAltName, critical, value: sanValue(names) }),
  raw: (id: string, value: Uint8Array, critical = false): ExtSpec => ({ oid: id, critical, value }),
};

// ---------- certificates ----------

export type SigAlg = 'rsa-sha256' | 'rsa-sha384' | 'rsa-sha512' | 'ecdsa-sha256' | 'ecdsa-sha384' | 'rsa-sha1';

const SIG_OID: Record<SigAlg, string> = {
  'rsa-sha256': OID.sha256WithRSA,
  'rsa-sha384': OID.sha384WithRSA,
  'rsa-sha512': OID.sha512WithRSA,
  'ecdsa-sha256': OID.ecdsaSha256,
  'ecdsa-sha384': OID.ecdsaSha384,
  'rsa-sha1': '1.2.840.113549.1.1.5',
};
const SIG_HASH: Record<SigAlg, string> = {
  'rsa-sha256': 'sha256',
  'rsa-sha384': 'sha384',
  'rsa-sha512': 'sha512',
  'ecdsa-sha256': 'sha256',
  'ecdsa-sha384': 'sha384',
  'rsa-sha1': 'sha1',
};

export function sigAlgId(alg: SigAlg): Uint8Array {
  return alg.startsWith('rsa') ? algorithm(SIG_OID[alg], nullValue()) : algorithm(SIG_OID[alg]);
}

export function defaultSigAlg(k: KeyPair): SigAlg {
  return k.family === 'rsa' ? 'rsa-sha256' : 'ecdsa-sha256';
}

/** GeneralizedTime for a Date (whole seconds). */
export function genTimeOf(d: Date): string {
  return d.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function utcTime(d: Date): Uint8Array {
  return tlv(0x17, Buffer.from(genTimeOf(d).slice(2), 'ascii'));
}

export interface CertSpec {
  readonly subject: Uint8Array;
  readonly issuer: Uint8Array;
  readonly subjectKey: KeyPair;
  /** Key that signs the certificate. */
  readonly issuerKey: KeyPair;
  readonly serial?: bigint;
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  readonly extensions?: ExtSpec[];
  readonly sigAlg?: SigAlg;
  /** Inner signature AlgorithmIdentifier bytes, when they must differ from the outer one. */
  readonly innerSigAlg?: Uint8Array;
  /** Flip a byte of the signature (a mathematically invalid signature). */
  readonly badSignature?: boolean;
  /** Raw SubjectPublicKeyInfo in place of subjectKey's. */
  readonly spki?: Uint8Array;
}

let serialCounter = 1000n;

export function certificate(spec: CertSpec): Uint8Array {
  const alg = spec.sigAlg ?? defaultSigAlg(spec.issuerKey);
  const outer = sigAlgId(alg);
  const exts = spec.extensions ?? [];
  const tbs = sequence(
    tlv(0xa0, integer(2n)),
    integer(spec.serial ?? serialCounter++),
    spec.innerSigAlg ?? outer,
    spec.issuer,
    sequence(utcTime(spec.notBefore ?? new Date(Date.UTC(2020, 0, 1))), utcTime(spec.notAfter ?? new Date(Date.UTC(2040, 0, 1)))),
    spec.subject,
    spec.spki ?? spkiOf(spec.subjectKey),
    ...(exts.length > 0 ? [tlv(0xa3, sequence(...exts.map(extension)))] : []),
  );
  const sig = new Uint8Array(sign(SIG_HASH[alg], tbs, spec.issuerKey.privateKey));
  if (spec.badSignature === true) sig[sig.length - 5]! ^= 0x01;
  return sequence(tbs, outer, tlv(0x03, concat([Uint8Array.of(0), sig])));
}

export function pem(ders: Uint8Array[], eol = '\n'): Buffer {
  const blocks = ders.map((d) => {
    const b64 = Buffer.from(d).toString('base64');
    const lines = b64.match(/.{1,64}/g) ?? [];
    return ['-----BEGIN CERTIFICATE-----', ...lines, '-----END CERTIFICATE-----'].join(eol) + eol;
  });
  return Buffer.from(blocks.join(''), 'ascii');
}

// ---------- a standard test hierarchy ----------

export interface TestPki {
  readonly rootKey: KeyPair;
  readonly intKey: KeyPair;
  readonly signerKey: KeyPair;
  readonly rootName: Uint8Array;
  readonly intName: Uint8Array;
  readonly signerName: Uint8Array;
  readonly root: Uint8Array;
  readonly intermediate: Uint8Array;
  readonly signer: Uint8Array;
  /** root + intermediate + signer, LF line breaks. */
  readonly bundle: Buffer;
}

export const SIGNER_EXTS = (): ExtSpec[] => [ext.ku([0]), ext.eku([OID.kpTimeStamping])];

export function testPki(variant = 0): TestPki {
  const rootKey = key('rsa2048', 100 + variant);
  const intKey = key('rsa2048', 200 + variant);
  const signerKey = key('p256', 300 + variant);
  const rootName = cn(`Test Root ${String(variant)}`);
  const intName = cn(`Test Intermediate ${String(variant)}`);
  const signerName = cn(`Test TSA Signer ${String(variant)}`);
  const root = certificate({
    subject: rootName,
    issuer: rootName,
    subjectKey: rootKey,
    issuerKey: rootKey,
    extensions: [ext.bc(true), ext.ku([5, 6])],
  });
  const intermediate = certificate({
    subject: intName,
    issuer: rootName,
    subjectKey: intKey,
    issuerKey: rootKey,
    extensions: [ext.bc(true, true, 0n), ext.ku([5, 6])],
  });
  const signer = certificate({
    subject: signerName,
    issuer: intName,
    subjectKey: signerKey,
    issuerKey: intKey,
    extensions: SIGNER_EXTS(),
  });
  return { rootKey, intKey, signerKey, rootName, intName, signerName, root, intermediate, signer, bundle: pem([root, intermediate, signer]) };
}

// ---------- RFC 3161 responses ----------

export type DigestName = 'sha256' | 'sha384' | 'sha512';
const DIGEST_OID: Record<DigestName | 'sha1', string> = {
  sha1: OID.sha1,
  sha256: OID.sha256,
  sha384: OID.sha384,
  sha512: OID.sha512,
};

export function digestAlg(d: DigestName, params: 'absent' | 'null' | 'other' = 'absent'): Uint8Array {
  if (params === 'absent') return algorithm(DIGEST_OID[d]);
  if (params === 'null') return algorithm(DIGEST_OID[d], nullValue());
  return algorithm(DIGEST_OID[d], integer(1n));
}

function hash(d: DigestName | 'sha1', data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash(d).update(data).digest());
}

export interface TstSpec {
  readonly version?: bigint;
  readonly policy?: string;
  readonly imprintAlg?: Uint8Array;
  readonly hashedMessage: Uint8Array;
  readonly serial?: bigint;
  /** Raw genTime string (any bytes the test wants). */
  readonly genTime: string;
  readonly accuracy?: { seconds?: bigint; millis?: bigint; micros?: bigint };
  readonly ordering?: boolean | 'explicit-false';
  readonly nonce?: bigint | null;
  /** Full GeneralName encoding for TSTInfo.tsa. */
  readonly tsa?: Uint8Array;
  readonly extensions?: ExtSpec[];
}

export function tstInfo(t: TstSpec): Uint8Array {
  const parts: Uint8Array[] = [
    integer(t.version ?? 1n),
    oid(t.policy ?? '1.2.3.4.1'),
    sequence(t.imprintAlg ?? digestAlg('sha256'), octetString(t.hashedMessage)),
    integer(t.serial ?? 4242n),
    tlv(0x18, Buffer.from(t.genTime, 'latin1')),
  ];
  if (t.accuracy !== undefined) {
    const a: Uint8Array[] = [];
    if (t.accuracy.seconds !== undefined) a.push(integer(t.accuracy.seconds));
    if (t.accuracy.millis !== undefined) a.push(tlv(0x80, integer(t.accuracy.millis).subarray(2)));
    if (t.accuracy.micros !== undefined) a.push(tlv(0x81, integer(t.accuracy.micros).subarray(2)));
    parts.push(sequence(...a));
  }
  if (t.ordering === true) parts.push(boolean(true));
  if (t.ordering === 'explicit-false') parts.push(boolean(false));
  if (t.nonce !== null && t.nonce !== undefined) parts.push(integer(t.nonce));
  if (t.tsa !== undefined) parts.push(tlv(0xa0, t.tsa));
  if (t.extensions !== undefined) parts.push(tlv(0xa1, concat(t.extensions.map(extension))));
  return sequence(...parts);
}

export interface EssSpec {
  readonly version: 1 | 2;
  /** For v2: the hashAlgorithm field ('omit' for the DEFAULT SHA-256). */
  readonly alg?: 'omit' | Uint8Array;
  readonly hash?: DigestName | 'sha1';
  /** Certificate the reference points at (default: the signer). */
  readonly cert?: Uint8Array;
  readonly issuerSerial?: { issuerName: Uint8Array; serial: bigint };
  /** Replace the certHash with these bytes. */
  readonly certHash?: Uint8Array;
}

function essAttr(e: EssSpec, signer: Uint8Array): Uint8Array {
  const target = e.cert ?? signer;
  const h = e.hash ?? (e.version === 1 ? 'sha1' : 'sha256');
  const parts: Uint8Array[] = [];
  if (e.version === 2 && e.alg !== undefined && e.alg !== 'omit') parts.push(e.alg);
  parts.push(octetString(e.certHash ?? hash(h, target)));
  if (e.issuerSerial !== undefined) {
    parts.push(sequence(sequence(directoryName(e.issuerSerial.issuerName)), integer(e.issuerSerial.serial)));
  }
  const id = e.version === 1 ? OID.attrSigningCertificate : OID.attrSigningCertificateV2;
  return attribute(id, sequence(sequence(sequence(...parts))));
}

/** X.690 §11.6 order: octet strings compared with the shorter one padded with zeros. */
export function derCompare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export function attribute(id: string, ...values: Uint8Array[]): Uint8Array {
  return sequence(oid(id), set(...values));
}

export interface TokenSpec {
  readonly tst: Uint8Array;
  readonly signerCert: Uint8Array;
  readonly signerKey: KeyPair;
  readonly signerIssuer: Uint8Array;
  readonly signerSerial: bigint;
  /** Certificates embedded in SignedData (default: the signer only). */
  readonly certificates?: Uint8Array[];
  readonly digest?: DigestName;
  /** digestAlgorithms SET contents (default: one identifier for `digest`, absent parameters). */
  readonly digestSet?: Uint8Array[];
  /** SignerInfo.digestAlgorithm (default: `digest`, absent parameters). */
  readonly signerDigestAlg?: Uint8Array;
  /** SignerInfo.signatureAlgorithm (default: from the key family and `digest`). */
  readonly signatureAlg?: Uint8Array;
  readonly ess?: EssSpec[];
  readonly contentTypeValue?: string;
  readonly messageDigest?: Uint8Array;
  /** Extra signed attributes appended as-is. */
  readonly extraAttrs?: Uint8Array[];
  readonly omitContentType?: boolean;
  readonly omitMessageDigest?: boolean;
  readonly noSignedAttrs?: boolean;
  readonly badSignature?: boolean;
  /** Add a second SignerInfo. */
  readonly twoSigners?: boolean;
  readonly detached?: boolean;
  readonly eContentType?: string;
  readonly status?: bigint;
  readonly omitToken?: boolean;
  /** Append bytes after the TimeStampResp. */
  readonly trailing?: Uint8Array;
  readonly sidKind?: 'issuerSerial' | 'ski';
  /** Keep signed attributes in the given order instead of DER order (signature still over the sent bytes). */
  readonly unsortedAttrs?: boolean;
  readonly ski?: Uint8Array;
}

function signatureAlgFor(k: KeyPair, d: DigestName): Uint8Array {
  if (k.family === 'rsa') return algorithm(OID.rsaEncryption, nullValue());
  return algorithm(d === 'sha256' ? OID.ecdsaSha256 : d === 'sha384' ? OID.ecdsaSha384 : OID.ecdsaSha512);
}

export function timeStampResp(t: TokenSpec): Uint8Array {
  const d = t.digest ?? 'sha256';
  const attrs: Uint8Array[] = [];
  if (t.omitContentType !== true) attrs.push(attribute(OID.attrContentType, oid(t.contentTypeValue ?? OID.tstInfo)));
  if (t.omitMessageDigest !== true) attrs.push(attribute(OID.attrMessageDigest, octetString(t.messageDigest ?? hash(d, t.tst))));
  for (const e of t.ess ?? [{ version: 2 }]) attrs.push(essAttr(e, t.signerCert));
  attrs.push(...(t.extraAttrs ?? []));
  if (t.unsortedAttrs !== true) attrs.sort(derCompare);
  else if (attrs.length > 1 && derCompare(attrs[0]!, attrs[1]!) <= 0) attrs.reverse();
  const signedAttrsSet = set(...attrs);
  const sig = new Uint8Array(sign(d, signedAttrsSet, t.signerKey.privateKey));
  if (t.badSignature === true) sig[sig.length - 3]! ^= 0x01;
  const sid =
    t.sidKind === 'ski'
      ? tlv(0x80, t.ski ?? new Uint8Array(20))
      : sequence(t.signerIssuer, integer(t.signerSerial));
  const signerInfo = sequence(
    integer(t.sidKind === 'ski' ? 3n : 1n),
    sid,
    t.signerDigestAlg ?? digestAlg(d),
    ...(t.noSignedAttrs === true ? [] : [tlv(0xa0, concat(attrs))]),
    t.signatureAlg ?? signatureAlgFor(t.signerKey, d),
    octetString(sig),
  );
  const certs = t.certificates ?? [t.signerCert];
  const signedData = sequence(
    integer(3n),
    set(...(t.digestSet ?? [digestAlg(d)])),
    sequence(oid(t.eContentType ?? OID.tstInfo), ...(t.detached === true ? [] : [tlv(0xa0, octetString(t.tst))])),
    ...(certs.length > 0 ? [tlv(0xa0, concat(certs))] : []),
    set(signerInfo, ...(t.twoSigners === true ? [signerInfo] : [])),
  );
  const token = sequence(oid(OID.signedData), tlv(0xa0, signedData));
  const resp = sequence(sequence(integer(t.status ?? 0n)), ...(t.omitToken === true ? [] : [token]));
  return t.trailing === undefined ? resp : concat([resp, t.trailing]);
}

/** Issuer Name and serial of a certificate built here (read with the production parser). */
export function issuerAndSerial(certDer: Uint8Array): { issuer: Uint8Array; serial: bigint } {
  const c = parseCertificate(certDer);
  return { issuer: c.issuer, serial: c.serial };
}
