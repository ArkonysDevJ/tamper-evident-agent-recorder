// SPDX-License-Identifier: AGPL-3.0-or-later
// RFC 3161 receipt (.tsr) checks under TEAR-TSA-01 (Blueprint §6 Step 2.2–2.4
// and §6a). The same functions serve the writer, the recoverer and the
// verifier, so a receipt is accepted under one set of rules only.
//
// Stage order: structure (2.2) → genTime grammar (2.2) → signature, signer
// identity and path (2.3) → commitment (2.4). The time predicate (2.7, or
// §5.7 step 3 in the writer) is a separate function.

import { createHash } from 'node:crypto';
import { checkTree, decodeDer, encodingOf } from '../asn1/der.js';
import type { DerDocument, Tlv } from '../asn1/der.js';
import {
  Asn1Error,
  Fields,
  TAG,
  bitString,
  boolean,
  ctx,
  expectTag,
  generalizedTimeDer,
  integer,
  octetString,
  oid,
  seq,
  setOf,
} from '../asn1/types.js';
import { algorithmId, allowedPublicKey, cmsSignatureScheme, sha2Digest, verifySignature } from '../pki/algorithms.js';
import type { AlgorithmId } from '../pki/algorithms.js';
import type { LoadedBundle } from '../pki/bundle.js';
import {
  bytesEqual,
  checkGeneralName,
  checkName,
  directoryNameOf,
  parseCertificate,
  parseExtensionList,
  subjectKeyIdentifierOf,
} from '../pki/certificate.js';
import type { Certificate } from '../pki/certificate.js';
import { OID } from '../pki/oids.js';
import type { DigestName } from '../pki/oids.js';
import { acceptPath } from '../pki/path.js';
import { parseGeneralizedTimeNs } from '../time/timestamps.js';

export interface Accuracy {
  readonly seconds: bigint | null;
  readonly millis: bigint | null;
  readonly micros: bigint | null;
}

export interface TstInfo {
  readonly policy: string;
  readonly hashAlgorithm: AlgorithmId;
  readonly hashedMessage: Uint8Array;
  readonly serial: bigint;
  /** Exact ASCII lexical value of genTime. */
  readonly genTime: string;
  readonly accuracy: Accuracy | null;
  readonly ordering: boolean;
  readonly nonce: bigint | null;
  /** Full encoding of the tsa GeneralName, or null. */
  readonly tsa: Uint8Array | null;
  readonly extensionOids: readonly string[];
}

interface Attribute {
  readonly oid: string;
  readonly values: readonly Tlv[];
}

export interface ParsedReceipt {
  readonly status: bigint;
  readonly tstInfo: TstInfo;
  /** DER bytes of the encapsulated TSTInfo (the eContent octets). */
  readonly eContent: Uint8Array;
  /** Encodings of every embedded certificate in the certificate set (CertificateChoices "certificate" only). */
  readonly certificates: readonly Uint8Array[];
  readonly otherCertificateChoices: number;
  readonly crlsPresent: boolean;
  readonly digest: DigestName;
  readonly signer: {
    readonly sid: { kind: 'issuerSerial'; issuer: Uint8Array; serial: bigint } | { kind: 'ski'; ski: Uint8Array };
    readonly signedAttrs: { readonly doc: DerDocument; readonly el: Tlv; readonly attrs: readonly Attribute[] } | null;
    readonly signatureAlgorithm: AlgorithmId;
    readonly signature: Uint8Array;
    readonly unsignedAttrsPresent: boolean;
  };
}

export type StructureResult =
  | { readonly ok: true; readonly receipt: ParsedReceipt; readonly genTimeNs: bigint }
  | { readonly ok: false; readonly stage: 'structure' | 'time_format'; readonly reason: string };

function fail(reason: string): never {
  throw new Asn1Error(reason);
}

function parseAttributes(doc: DerDocument, el: Tlv): Attribute[] {
  return setOf(doc, el, 'attributes', el.tag).map((a) => {
    const parts = seq(doc, a, 'Attribute');
    if (parts.length !== 2) fail('Attribute: type and values expected');
    const values = setOf(doc, parts[1], 'Attribute.values');
    if (values.length === 0) fail('Attribute: empty value set');
    return { oid: oid(doc, parts[0], 'Attribute.type'), values };
  });
}

function parseAccuracy(doc: DerDocument, el: Tlv): Accuracy {
  const f = new Fields(seq(doc, el, 'accuracy'), 'accuracy');
  const s = f.optional(TAG.INTEGER);
  const ms = f.optional(ctx(0, false));
  const us = f.optional(ctx(1, false));
  f.end();
  const seconds = s === undefined ? null : integer(doc, s, 'accuracy.seconds');
  const millis = ms === undefined ? null : integer(doc, ms, 'accuracy.millis', ctx(0, false));
  const micros = us === undefined ? null : integer(doc, us, 'accuracy.micros', ctx(1, false));
  if (seconds !== null && seconds < 0n) fail('accuracy.seconds negative');
  for (const v of [millis, micros]) if (v !== null && (v < 1n || v > 999n)) fail('accuracy subfield outside 1..999');
  return { seconds, millis, micros };
}

function parseTstInfo(bytes: Uint8Array): TstInfo {
  const doc = decodeDer(bytes);
  checkTree(doc);
  const f = new Fields(seq(doc, doc.root, 'TSTInfo'), 'TSTInfo');
  if (integer(doc, f.next(TAG.INTEGER, 'version'), 'TSTInfo.version') !== 1n) fail('TSTInfo.version is not 1');
  const policy = oid(doc, f.next(TAG.OID, 'policy'), 'TSTInfo.policy');
  const mi = seq(doc, f.next(TAG.SEQUENCE, 'messageImprint'), 'messageImprint');
  if (mi.length !== 2) fail('messageImprint: two fields expected');
  const hashAlgorithm = algorithmId(doc, mi[0], 'messageImprint.hashAlgorithm');
  const hashedMessage = octetString(doc, mi[1], 'messageImprint.hashedMessage');
  const serial = integer(doc, f.next(TAG.INTEGER, 'serialNumber'), 'TSTInfo.serialNumber');
  if (serial <= 0n) fail('TSTInfo.serialNumber is not positive');
  const genTime = generalizedTimeDer(doc, f.next(TAG.GeneralizedTime, 'genTime'), 'TSTInfo.genTime');
  const accEl = f.optional(TAG.SEQUENCE);
  const accuracy = accEl === undefined ? null : parseAccuracy(doc, accEl);
  const ordEl = f.optional(TAG.BOOLEAN);
  const ordering = ordEl === undefined ? false : boolean(doc, ordEl, 'TSTInfo.ordering');
  if (ordEl !== undefined && !ordering) fail('TSTInfo.ordering: DEFAULT FALSE encoded explicitly');
  const nonceEl = f.optional(TAG.INTEGER);
  const nonce = nonceEl === undefined ? null : integer(doc, nonceEl, 'TSTInfo.nonce');
  const tsaEl = f.optional(ctx(0, true));
  let tsa: Uint8Array | null = null;
  if (tsaEl !== undefined) {
    const inner = seq(doc, tsaEl, 'TSTInfo.tsa', ctx(0, true));
    if (inner.length !== 1) fail('TSTInfo.tsa: one GeneralName expected');
    tsa = checkGeneralName(doc, inner[0], 'TSTInfo.tsa');
  }
  const extEl = f.optional(ctx(1, true));
  f.end();
  let extensionOids: string[] = [];
  if (extEl !== undefined) {
    const list = seq(doc, extEl, 'TSTInfo.extensions', ctx(1, true));
    if (list.length === 0) fail('TSTInfo.extensions: empty');
    const exts = parseExtensionList(doc, list);
    if (exts.some((e) => e.critical)) fail('TSTInfo: critical extension');
    extensionOids = exts.map((e) => e.oid);
  }
  return { policy, hashAlgorithm, hashedMessage, serial, genTime, accuracy, ordering, nonce, tsa, extensionOids };
}

function parseStructure(tsr: Uint8Array): ParsedReceipt {
  const doc = decodeDer(tsr);
  checkTree(doc);
  const resp = new Fields(seq(doc, doc.root, 'TimeStampResp'), 'TimeStampResp');
  const statusInfo = new Fields(seq(doc, resp.next(TAG.SEQUENCE, 'status'), 'PKIStatusInfo'), 'PKIStatusInfo');
  const status = integer(doc, statusInfo.next(TAG.INTEGER, 'status'), 'PKIStatus');
  const freeText = statusInfo.optional(TAG.SEQUENCE);
  if (freeText !== undefined) for (const t of seq(doc, freeText, 'statusString')) expectTag(t, TAG.UTF8String, 'statusString');
  const failInfo = statusInfo.optional(TAG.BIT_STRING);
  if (failInfo !== undefined) bitString(doc, failInfo, 'failInfo');
  statusInfo.end();
  if (status !== 0n && status !== 1n) fail('PKIStatus is not granted');
  const tokenEl = resp.next(TAG.SEQUENCE, 'timeStampToken');
  resp.end();

  const ci = new Fields(seq(doc, tokenEl, 'ContentInfo'), 'ContentInfo');
  if (oid(doc, ci.next(TAG.OID, 'contentType'), 'contentType') !== OID.signedData) fail('token is not SignedData');
  const sdWrap = seq(doc, ci.next(ctx(0, true), 'content'), 'content', ctx(0, true));
  ci.end();
  if (sdWrap.length !== 1) fail('content: one SignedData expected');

  const sd = new Fields(seq(doc, sdWrap[0], 'SignedData'), 'SignedData');
  integer(doc, sd.next(TAG.INTEGER, 'version'), 'SignedData.version');
  const digestSet = setOf(doc, sd.next(TAG.SET, 'digestAlgorithms'), 'digestAlgorithms');
  if (digestSet.length !== 1) fail('digestAlgorithms must hold exactly one identifier');
  const setDigest = algorithmId(doc, digestSet[0], 'digestAlgorithms[0]');
  const eci = new Fields(seq(doc, sd.next(TAG.SEQUENCE, 'encapContentInfo'), 'encapContentInfo'), 'encapContentInfo');
  if (oid(doc, eci.next(TAG.OID, 'eContentType'), 'eContentType') !== OID.tstInfo) fail('eContentType is not id-ct-TSTInfo');
  const eWrap = eci.optional(ctx(0, true));
  eci.end();
  if (eWrap === undefined) fail('detached content');
  const eInner = seq(doc, eWrap, 'eContent', ctx(0, true));
  if (eInner.length !== 1) fail('eContent: one OCTET STRING expected');
  const eContent = octetString(doc, eInner[0], 'eContent');

  const certsEl = sd.optional(ctx(0, true));
  const certificates: Uint8Array[] = [];
  let otherCertificateChoices = 0;
  if (certsEl !== undefined) {
    // The only SET OF whose DER order is not enforced: the real DigiCert receipts carry it unsorted.
    for (const c of seq(doc, certsEl, 'certificates', ctx(0, true))) {
      if (c.tag === TAG.SEQUENCE) certificates.push(encodingOf(doc, c));
      else otherCertificateChoices++;
    }
  }
  const crlsEl = sd.optional(ctx(1, true));
  if (crlsEl !== undefined) setOf(doc, crlsEl, 'crls', ctx(1, true));
  const crlsPresent = crlsEl !== undefined;
  const signerInfos = setOf(doc, sd.next(TAG.SET, 'signerInfos'), 'signerInfos');
  sd.end();
  if (signerInfos.length !== 1) fail('exactly one SignerInfo required');

  const si = new Fields(seq(doc, signerInfos[0], 'SignerInfo'), 'SignerInfo');
  integer(doc, si.next(TAG.INTEGER, 'version'), 'SignerInfo.version');
  let sid: ParsedReceipt['signer']['sid'];
  const sidSeq = si.optional(TAG.SEQUENCE);
  if (sidSeq !== undefined) {
    const ias = seq(doc, sidSeq, 'IssuerAndSerialNumber');
    if (ias.length !== 2) fail('IssuerAndSerialNumber: two fields expected');
    sid = { kind: 'issuerSerial', issuer: checkName(doc, ias[0], 'sid.issuer'), serial: integer(doc, ias[1], 'sid.serial') };
  } else {
    sid = { kind: 'ski', ski: octetString(doc, si.next(ctx(0, false), 'sid'), 'sid.ski', ctx(0, false)) };
  }
  const signerDigest = algorithmId(doc, si.next(TAG.SEQUENCE, 'digestAlgorithm'), 'SignerInfo.digestAlgorithm');
  const saEl = si.optional(ctx(0, true));
  const signedAttrs = saEl === undefined ? null : { doc, el: saEl, attrs: parseAttributes(doc, saEl) };
  const signatureAlgorithm = algorithmId(doc, si.next(TAG.SEQUENCE, 'signatureAlgorithm'), 'signatureAlgorithm');
  const signature = octetString(doc, si.next(TAG.OCTET_STRING, 'signature'), 'signature');
  const uaEl = si.optional(ctx(1, true));
  if (uaEl !== undefined) parseAttributes(doc, uaEl);
  si.end();

  // CMS digest-set rule: one allowed SHA-2 identifier, equivalent to the signer's.
  const a = sha2Digest(setDigest);
  const b = sha2Digest(signerDigest);
  if (a === null || b === null || a !== b) fail('digest set does not match the signer digest');

  return {
    status,
    tstInfo: parseTstInfo(eContent),
    eContent,
    certificates,
    otherCertificateChoices,
    crlsPresent,
    digest: a,
    signer: { sid, signedAttrs, signatureAlgorithm, signature, unsignedAttrsPresent: uaEl !== undefined },
  };
}

/** Step 2.2: structure, then the §5.7 genTime grammar. */
export function parseReceipt(tsr: Uint8Array): StructureResult {
  let receipt: ParsedReceipt;
  try {
    receipt = parseStructure(tsr);
  } catch (err) {
    return { ok: false, stage: 'structure', reason: (err as Error).message };
  }
  const genTimeNs = parseGeneralizedTimeNs(receipt.tstInfo.genTime);
  if (genTimeNs === null) return { ok: false, stage: 'time_format', reason: 'genTime grammar' };
  return { ok: true, receipt, genTimeNs };
}

function digestOf(name: DigestName | 'sha1', data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash(name).update(data).digest());
}

interface EssRef {
  readonly hash: DigestName | 'sha1';
  readonly certHash: Uint8Array;
  readonly issuerSerial: { readonly names: readonly Uint8Array[]; readonly serial: bigint } | null;
}

function parseIssuerSerial(doc: DerDocument, el: Tlv): EssRef['issuerSerial'] {
  const parts = seq(doc, el, 'IssuerSerial');
  if (parts.length !== 2) fail('IssuerSerial: two fields expected');
  const names = seq(doc, parts[0], 'IssuerSerial.issuer').map((g) => checkGeneralName(doc, g, 'IssuerSerial.issuer'));
  return { names, serial: integer(doc, parts[1], 'IssuerSerial.serial') };
}

/** The first certificate reference of a SigningCertificate or SigningCertificateV2 attribute value. */
function firstEssRef(doc: DerDocument, value: Tlv, v2: boolean): EssRef {
  const outer = seq(doc, value, 'SigningCertificate');
  if (outer.length < 1 || outer.length > 2) fail('SigningCertificate: certs and optional policies');
  const certs = seq(doc, outer[0], 'SigningCertificate.certs');
  if (certs.length === 0) fail('SigningCertificate: no certificate reference');
  const f = new Fields(seq(doc, certs[0], 'ESSCertID'), 'ESSCertID');
  let hash: DigestName | 'sha1' = 'sha1';
  if (v2) {
    const algEl = f.optional(TAG.SEQUENCE);
    hash = 'sha256';
    if (algEl !== undefined) {
      const d = sha2Digest(algorithmId(doc, algEl, 'ESSCertIDv2.hashAlgorithm'));
      if (d === null) fail('ESSCertIDv2.hashAlgorithm not allowed');
      hash = d;
    }
  }
  const certHash = octetString(doc, f.next(TAG.OCTET_STRING, 'certHash'), 'certHash');
  const isEl = f.optional(TAG.SEQUENCE);
  f.end();
  return { hash, certHash, issuerSerial: isEl === undefined ? null : parseIssuerSerial(doc, isEl) };
}

function refMatches(ref: EssRef, cert: Certificate): boolean {
  if (!bytesEqual(digestOf(ref.hash, cert.der), ref.certHash)) return false;
  if (ref.issuerSerial === null) return true;
  if (ref.issuerSerial.serial !== cert.serial) return false;
  return ref.issuerSerial.names.some((n) => {
    const dn = directoryNameOf(n);
    return dn !== null && bytesEqual(dn, cert.issuer);
  });
}

/**
 * CMS SignedAttributes are signed as their DER SET OF encoding: the [0] tag is
 * replaced by SET. Structure checks already required DER order, so the received
 * bytes are that DER encoding.
 */
function signedAttributesInput(doc: DerDocument, el: Tlv): Uint8Array {
  const enc = Uint8Array.from(encodingOf(doc, el));
  enc[0] = TAG.SET;
  return enc;
}

/**
 * Step 2.3: signed attributes, ESS binding to the embedded signer, signature,
 * TSTInfo.tsa identity and path acceptance at the signed genTime. Returns
 * null on success or the reason for TSA_SIGNATURE_INVALID.
 */
export function checkSignature(r: ParsedReceipt, genTimeNs: bigint, bundle: LoadedBundle): string | null {
  try {
    const sa = r.signer.signedAttrs;
    if (sa === null) return 'no signed attributes';
    const seen = new Set<string>();
    for (const a of sa.attrs) {
      if (seen.has(a.oid)) return `duplicate signed attribute ${a.oid}`;
      seen.add(a.oid);
    }
    const attr = (id: string): Attribute | undefined => sa.attrs.find((a) => a.oid === id);
    const ct = attr(OID.attrContentType);
    if (ct === undefined || ct.values.length !== 1 || oid(sa.doc, ct.values[0], 'content-type') !== OID.tstInfo) {
      return 'content-type attribute';
    }
    const md = attr(OID.attrMessageDigest);
    if (md === undefined || md.values.length !== 1) return 'message-digest attribute';
    if (!bytesEqual(octetString(sa.doc, md.values[0], 'message-digest'), digestOf(r.digest, r.eContent))) {
      return 'message-digest does not match the TSTInfo';
    }

    const v1 = attr(OID.attrSigningCertificate);
    const v2 = attr(OID.attrSigningCertificateV2);
    if (v1 === undefined && v2 === undefined) return 'no signing-certificate attribute';
    const refs: EssRef[] = [];
    for (const [a, isV2] of [
      [v1, false],
      [v2, true],
    ] as const) {
      if (a === undefined) continue;
      if (a.values.length !== 1) return 'signing-certificate attribute with several values';
      refs.push(firstEssRef(sa.doc, a.values[0]!, isV2));
    }
    // The signer is the embedded certificate the ESS binding identifies; every reference must agree.
    let signer: Certificate | null = null;
    for (const der of r.certificates) {
      let cert: Certificate;
      try {
        cert = parseCertificate(der);
      } catch {
        continue; // Embedded certificates other than the signer are ignored.
      }
      if (refs.every((ref) => refMatches(ref, cert))) {
        signer = cert;
        break;
      }
    }
    if (signer === null) return 'the ESS-identified signer is not embedded';

    const sid = r.signer.sid;
    if (sid.kind === 'issuerSerial') {
      if (!bytesEqual(sid.issuer, signer.issuer) || sid.serial !== signer.serial) return 'sid does not identify the signer';
    } else {
      const ski = subjectKeyIdentifierOf(signer);
      if (ski === null || !bytesEqual(ski, sid.ski)) return 'sid does not identify the signer';
    }

    const key = allowedPublicKey(signer.spki);
    if (key === null) return 'signer key outside the profile';
    const scheme = cmsSignatureScheme(r.signer.signatureAlgorithm, r.digest);
    if (scheme === null) return 'signature algorithm outside the profile or digest mismatch';
    if (!verifySignature(key, scheme, signedAttributesInput(sa.doc, sa.el), r.signer.signature)) return 'signature';

    const tsa = r.tstInfo.tsa;
    if (tsa !== null) {
      const dn = directoryNameOf(tsa);
      const named =
        (dn !== null && bytesEqual(dn, signer.subject)) || (signer.subjectAltNames ?? []).some((g) => bytesEqual(g, tsa));
      if (!named) return 'TSTInfo.tsa does not name the signer';
    }

    if (!acceptPath(signer, bundle, genTimeNs)) return 'no acceptable path';
    return null;
  } catch (err) {
    return `binding: ${(err as Error).message}`;
  }
}

/** Step 2.4: messageImprint (SHA-256, absent or NULL parameters) and nonce. */
export function checkCommitment(r: ParsedReceipt, entryHash: string, nonceHex: string): boolean {
  const t = r.tstInfo;
  if (t.hashAlgorithm.oid !== OID.sha256 || sha2Digest(t.hashAlgorithm) !== 'sha256') return false;
  if (!bytesEqual(t.hashedMessage, Buffer.from(entryHash, 'hex'))) return false;
  return t.nonce !== null && t.nonce === BigInt(`0x${nonceHex}`);
}

/** The inclusive §5.7 predicate: -5 s <= genTime - ts <= +60 s. */
export function timePredicate(genTimeNs: bigint, blockTsNs: bigint): boolean {
  const d = genTimeNs - blockTsNs;
  return d >= -5_000_000_000n && d <= 60_000_000_000n;
}

export type ReceiptCheck =
  | { readonly ok: true; readonly receipt: ParsedReceipt; readonly genTimeNs: bigint }
  | {
      readonly ok: false;
      readonly code: 'TSA_SIGNATURE_INVALID' | 'TSA_TIME_FORMAT_INVALID' | 'ANCHOR_COMMITMENT_MISMATCH';
      readonly reason: string;
    };

/** Steps 2.2 to 2.4 in order, stopping at the first failure. */
export function checkReceipt(tsr: Uint8Array, bundle: LoadedBundle, entryHash: string, nonceHex: string): ReceiptCheck {
  const parsed = parseReceipt(tsr);
  if (!parsed.ok) {
    return {
      ok: false,
      code: parsed.stage === 'structure' ? 'TSA_SIGNATURE_INVALID' : 'TSA_TIME_FORMAT_INVALID',
      reason: parsed.reason,
    };
  }
  const sig = checkSignature(parsed.receipt, parsed.genTimeNs, bundle);
  if (sig !== null) return { ok: false, code: 'TSA_SIGNATURE_INVALID', reason: sig };
  if (!checkCommitment(parsed.receipt, entryHash, nonceHex)) {
    return { ok: false, code: 'ANCHOR_COMMITMENT_MISMATCH', reason: 'messageImprint or nonce' };
  }
  return parsed;
}

