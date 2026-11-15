// SPDX-License-Identifier: AGPL-3.0-or-later
// X.509 certificate interpretation for TEAR-TSA-01 (Blueprint §6a). Names are
// kept as their exact DER bytes: two Names are equal only if those bytes are
// identical. keyUsage, basicConstraints, extendedKeyUsage and subjectAltName
// are always decoded, critical or not; any other extension is only checked as
// a valid DER Extension. Duplicate extension identifiers are rejected.

import { checkTree, decodeDer, encodingOf } from '../asn1/der.js';
import type { DerDocument, Tlv } from '../asn1/der.js';
import {
  Asn1Error,
  Fields,
  TAG,
  bitString,
  boolean,
  ctx,
  highestBit,
  integer,
  integerBytes,
  octetString,
  oid,
  seq,
  setOf,
  x509Time,
} from '../asn1/types.js';
import { algorithmId } from './algorithms.js';
import type { AlgorithmId } from './algorithms.js';
import { OID } from './oids.js';

export interface Extension {
  readonly oid: string;
  readonly critical: boolean;
  /** Contents of extnValue (the DER of the extension value). */
  readonly value: Uint8Array;
}

export interface BasicConstraints {
  readonly ca: boolean;
  readonly pathLen: bigint | null;
}

export interface Certificate {
  readonly der: Uint8Array;
  readonly tbs: Uint8Array;
  readonly serial: bigint;
  readonly innerSignatureAlgorithm: AlgorithmId;
  readonly outerSignatureAlgorithm: AlgorithmId;
  readonly signature: Uint8Array;
  /** DER bytes of the issuer and subject Names. */
  readonly issuer: Uint8Array;
  readonly subject: Uint8Array;
  readonly notBeforeNs: bigint;
  readonly notAfterNs: bigint;
  readonly spki: Uint8Array;
  readonly extensions: readonly Extension[];
  readonly basicConstraints: BasicConstraints | null;
  /** keyUsage bits, or null when the extension is absent. */
  readonly keyUsage: Uint8Array | null;
  readonly extendedKeyUsage: { readonly critical: boolean; readonly purposes: readonly string[] } | null;
  /** Full DER encoding of each subjectAltName GeneralName, or null when absent. */
  readonly subjectAltNames: readonly Uint8Array[] | null;
  readonly selfIssued: boolean;
}

export const KEY_USAGE = { digitalSignature: 0, contentCommitment: 1, keyCertSign: 5 } as const;

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Checks the structure of a Name (RDNSequence: SEQUENCE OF non-empty SET OF AttributeTypeAndValue). */
export function checkName(doc: DerDocument, el: Tlv | undefined, what: string): Uint8Array {
  for (const rdn of seq(doc, el, what)) {
    const atvs = setOf(doc, rdn, `${what}.rdn`);
    if (atvs.length === 0) throw new Asn1Error(`${what}: empty RDN`);
    for (const atv of atvs) {
      const parts = seq(doc, atv, `${what}.atv`);
      if (parts.length !== 2) throw new Asn1Error(`${what}: AttributeTypeAndValue needs type and value`);
      oid(doc, parts[0], `${what}.type`);
    }
  }
  return encodingOf(doc, el!);
}

const GENERAL_NAME_MAX_TAG = 8;

/** Checks one GeneralName and returns its full encoding. */
export function checkGeneralName(doc: DerDocument, el: Tlv | undefined, what: string): Uint8Array {
  if (el === undefined || el.tagClass !== 2 || el.tagNumber > GENERAL_NAME_MAX_TAG) {
    throw new Asn1Error(`${what}: not a GeneralName`);
  }
  if (el.tagNumber === 4) {
    const inner = seq(doc, el, what, ctx(4, true));
    if (inner.length !== 1) throw new Asn1Error(`${what}: directoryName needs one Name`);
    checkName(doc, inner[0], `${what}.directoryName`);
  }
  return encodingOf(doc, el);
}

/** The Name inside a directoryName GeneralName, or null for any other form. */
export function directoryNameOf(generalName: Uint8Array): Uint8Array | null {
  const doc = decodeDer(generalName);
  if (doc.root.tag !== ctx(4, true)) return null;
  const inner = seq(doc, doc.root, 'directoryName', ctx(4, true));
  return encodingOf(doc, inner[0]!);
}

function parseExtensions(doc: DerDocument, el: Tlv): Extension[] {
  const list = seq(doc, seq(doc, el, 'extensions', ctx(3, true))[0], 'Extensions');
  if (list.length === 0) throw new Asn1Error('Extensions: empty');
  return parseExtensionList(doc, list);
}

/** Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }. */
export function parseExtensionList(doc: DerDocument, list: readonly Tlv[]): Extension[] {
  const out: Extension[] = [];
  const seen = new Set<string>();
  for (const e of list) {
    const f = new Fields(seq(doc, e, 'Extension'), 'Extension');
    const id = oid(doc, f.next(TAG.OID, 'extnID'), 'extnID');
    const crit = f.optional(TAG.BOOLEAN);
    const critical = crit === undefined ? false : boolean(doc, crit, 'critical');
    if (crit !== undefined && !critical) throw new Asn1Error('Extension: DEFAULT FALSE encoded explicitly');
    const value = octetString(doc, f.next(TAG.OCTET_STRING, 'extnValue'), 'extnValue');
    f.end();
    if (seen.has(id)) throw new Asn1Error(`Extension: duplicate extnID ${id}`);
    seen.add(id);
    out.push({ oid: id, critical, value });
  }
  return out;
}

function parseBasicConstraints(value: Uint8Array): BasicConstraints {
  const doc = decodeDer(value);
  const f = new Fields(seq(doc, doc.root, 'basicConstraints'), 'basicConstraints');
  const caEl = f.optional(TAG.BOOLEAN);
  const ca = caEl === undefined ? false : boolean(doc, caEl, 'cA');
  if (caEl !== undefined && !ca) throw new Asn1Error('basicConstraints: DEFAULT FALSE encoded explicitly');
  const lenEl = f.optional(TAG.INTEGER);
  const pathLen = lenEl === undefined ? null : integer(doc, lenEl, 'pathLenConstraint');
  if (pathLen !== null && pathLen < 0n) throw new Asn1Error('basicConstraints: negative pathLenConstraint');
  f.end();
  return { ca, pathLen };
}

function parseKeyUsage(value: Uint8Array): Uint8Array {
  const doc = decodeDer(value);
  const { bytes } = bitString(doc, doc.root, 'keyUsage');
  if (highestBit(bytes) < 0) throw new Asn1Error('keyUsage: no bit set');
  return bytes;
}

function parseExtendedKeyUsage(value: Uint8Array): string[] {
  const doc = decodeDer(value);
  const items = seq(doc, doc.root, 'extendedKeyUsage');
  if (items.length === 0) throw new Asn1Error('extendedKeyUsage: empty');
  return items.map((i) => oid(doc, i, 'KeyPurposeId'));
}

function parseSubjectAltName(value: Uint8Array): Uint8Array[] {
  const doc = decodeDer(value);
  const items = seq(doc, doc.root, 'subjectAltName');
  if (items.length === 0) throw new Asn1Error('subjectAltName: empty');
  return items.map((i) => checkGeneralName(doc, i, 'subjectAltName'));
}

/** Parses a DER certificate; throws on any structural or DER violation. */
export function parseCertificate(der: Uint8Array): Certificate {
  const doc = decodeDer(der);
  checkTree(doc);
  const top = new Fields(seq(doc, doc.root, 'Certificate'), 'Certificate');
  const tbsEl = top.next(TAG.SEQUENCE, 'tbsCertificate');
  const outer = algorithmId(doc, top.next(TAG.SEQUENCE, 'signatureAlgorithm'), 'signatureAlgorithm');
  const sig = bitString(doc, top.next(TAG.BIT_STRING, 'signatureValue'), 'signatureValue');
  top.end();
  if (sig.unused !== 0) throw new Asn1Error('signatureValue: unused bits');

  const f = new Fields(seq(doc, tbsEl, 'tbsCertificate'), 'tbsCertificate');
  const versionEl = f.optional(ctx(0, true));
  let version = 0n;
  if (versionEl !== undefined) {
    const v = seq(doc, versionEl, 'version', ctx(0, true));
    if (v.length !== 1) throw new Asn1Error('version: one INTEGER expected');
    version = integer(doc, v[0], 'version');
    if (version === 0n) throw new Asn1Error('version: DEFAULT v1 encoded explicitly');
    if (version !== 1n && version !== 2n) throw new Asn1Error('version: unknown');
  }
  const serialEl = f.next(TAG.INTEGER, 'serialNumber');
  integerBytes(doc, serialEl, 'serialNumber');
  const serial = integer(doc, serialEl, 'serialNumber');
  const inner = algorithmId(doc, f.next(TAG.SEQUENCE, 'signature'), 'signature');
  const issuer = checkName(doc, f.next(TAG.SEQUENCE, 'issuer'), 'issuer');
  const validity = seq(doc, f.next(TAG.SEQUENCE, 'validity'), 'validity');
  if (validity.length !== 2) throw new Asn1Error('validity: two times expected');
  const notBeforeNs = x509Time(doc, validity[0], 'notBefore');
  const notAfterNs = x509Time(doc, validity[1], 'notAfter');
  const subject = checkName(doc, f.next(TAG.SEQUENCE, 'subject'), 'subject');
  const spki = encodingOf(doc, f.next(TAG.SEQUENCE, 'subjectPublicKeyInfo'));
  f.optional(ctx(1, false));
  f.optional(ctx(2, false));
  const extEl = f.optional(ctx(3, true));
  f.end();
  if (extEl !== undefined && version !== 2n) throw new Asn1Error('extensions require version 3');
  const extensions = extEl === undefined ? [] : parseExtensions(doc, extEl);

  const find = (id: string): Extension | undefined => extensions.find((e) => e.oid === id);
  const bc = find(OID.extBasicConstraints);
  const ku = find(OID.extKeyUsage);
  const eku = find(OID.extExtendedKeyUsage);
  const san = find(OID.extSubjectAltName);
  return {
    der,
    tbs: encodingOf(doc, tbsEl),
    serial,
    innerSignatureAlgorithm: inner,
    outerSignatureAlgorithm: outer,
    signature: sig.bytes,
    issuer,
    subject,
    notBeforeNs,
    notAfterNs,
    spki,
    extensions,
    basicConstraints: bc === undefined ? null : parseBasicConstraints(bc.value),
    keyUsage: ku === undefined ? null : parseKeyUsage(ku.value),
    extendedKeyUsage: eku === undefined ? null : { critical: eku.critical, purposes: parseExtendedKeyUsage(eku.value) },
    subjectAltNames: san === undefined ? null : parseSubjectAltName(san.value),
    selfIssued: bytesEqual(issuer, subject),
  };
}

/**
 * The subjectKeyIdentifier value, decoded only when a SignerInfo identifies its
 * signer by key identifier. Outside the four decoded extensions an unreadable
 * value is ignored, so this returns null instead of failing the certificate.
 */
export function subjectKeyIdentifierOf(cert: Certificate): Uint8Array | null {
  const ext = cert.extensions.find((e) => e.oid === '2.5.29.14');
  if (ext === undefined) return null;
  try {
    const doc = decodeDer(ext.value);
    return octetString(doc, doc.root, 'subjectKeyIdentifier');
  } catch {
    return null;
  }
}
