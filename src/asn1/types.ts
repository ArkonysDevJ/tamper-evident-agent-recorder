// SPDX-License-Identifier: AGPL-3.0-or-later
// Interpretation of universal ASN.1 types on top of the DER reader, with the
// DER rules of each type. Every function throws Asn1Error when the element is
// not the expected type or breaks a DER rule.

import { children, contentOf } from './der.js';
import type { DerDocument, Tlv } from './der.js';

export class Asn1Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Asn1Error';
  }
}

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8String: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PrintableString: 0x13,
  IA5String: 0x16,
  UTCTime: 0x17,
  GeneralizedTime: 0x18,
} as const;

/** Context-specific tag octet: [n] constructed or primitive. */
export function ctx(n: number, constructed: boolean): number {
  return 0x80 | (constructed ? 0x20 : 0) | n;
}

export function expectTag(el: Tlv | undefined, tag: number, what: string): Tlv {
  if (el === undefined) throw new Asn1Error(`${what}: missing`);
  if (el.tag !== tag) throw new Asn1Error(`${what}: expected tag 0x${tag.toString(16)}, found 0x${el.tag.toString(16)}`);
  return el;
}

/** Children of a SEQUENCE or SET (or a constructed context tag), with the expected tag checked. */
export function seq(doc: DerDocument, el: Tlv | undefined, what: string, tag: number = TAG.SEQUENCE): Tlv[] {
  return children(doc, expectTag(el, tag, what));
}

/**
 * DER order of SET OF (X.690 §11.6): element encodings in ascending order,
 * compared as octet strings with the shorter one padded with zero octets.
 */
export function inDerSetOrder(doc: DerDocument, items: readonly Tlv[]): boolean {
  for (let i = 1; i < items.length; i++) {
    const a = doc.bytes.subarray(items[i - 1]!.start, items[i - 1]!.end);
    const b = doc.bytes.subarray(items[i]!.start, items[i]!.end);
    const n = Math.max(a.length, b.length);
    for (let j = 0; j < n; j++) {
      const x = a[j] ?? 0;
      const y = b[j] ?? 0;
      if (x < y) break;
      if (x > y) return false;
    }
  }
  return true;
}

/** Children of a SET OF (or an implicitly tagged one), required to be in DER order. */
export function setOf(doc: DerDocument, el: Tlv | undefined, what: string, tag: number = TAG.SET): Tlv[] {
  const items = seq(doc, el, what, tag);
  if (!inDerSetOrder(doc, items)) throw new Asn1Error(`${what}: SET OF not in DER order`);
  return items;
}

/** A cursor over the children of a constructed element, for OPTIONAL and DEFAULT fields. */
export class Fields {
  private i = 0;
  constructor(
    private readonly items: readonly Tlv[],
    private readonly what: string,
  ) {}
  next(tag: number, field: string): Tlv {
    const el = expectTag(this.items[this.i], tag, `${this.what}.${field}`);
    this.i++;
    return el;
  }
  optional(tag: number): Tlv | undefined {
    const el = this.items[this.i];
    if (el !== undefined && el.tag === tag) {
      this.i++;
      return el;
    }
    return undefined;
  }
  peekTag(): number | undefined {
    return this.items[this.i]?.tag;
  }
  end(): void {
    if (this.i !== this.items.length) throw new Asn1Error(`${this.what}: unexpected element at index ${String(this.i)}`);
  }
}

/** INTEGER: non-empty, minimal two's complement. */
export function integer(doc: DerDocument, el: Tlv | undefined, what: string, tag: number = TAG.INTEGER): bigint {
  const c = contentOf(doc, expectTag(el, tag, what));
  if (c.length === 0) throw new Asn1Error(`${what}: empty INTEGER`);
  if (c.length > 1 && ((c[0] === 0x00 && c[1]! < 0x80) || (c[0] === 0xff && c[1]! >= 0x80))) {
    throw new Asn1Error(`${what}: non-minimal INTEGER`);
  }
  let v = 0n;
  for (const b of c) v = (v << 8n) | BigInt(b);
  if (c[0]! >= 0x80) v -= 1n << BigInt(c.length * 8);
  return v;
}

/** The contents octets of an INTEGER, after the DER checks. */
export function integerBytes(doc: DerDocument, el: Tlv | undefined, what: string, tag: number = TAG.INTEGER): Uint8Array {
  integer(doc, el, what, tag);
  return contentOf(doc, el!);
}

/** BOOLEAN: one octet, 0x00 or 0xFF. */
export function boolean(doc: DerDocument, el: Tlv | undefined, what: string): boolean {
  const c = contentOf(doc, expectTag(el, TAG.BOOLEAN, what));
  if (c.length !== 1 || (c[0] !== 0x00 && c[0] !== 0xff)) throw new Asn1Error(`${what}: invalid DER BOOLEAN`);
  return c[0] === 0xff;
}

export function nullValue(doc: DerDocument, el: Tlv | undefined, what: string): void {
  if (contentOf(doc, expectTag(el, TAG.NULL, what)).length !== 0) throw new Asn1Error(`${what}: NULL with contents`);
}

/** OBJECT IDENTIFIER in dotted form; every subidentifier minimal. */
export function oid(doc: DerDocument, el: Tlv | undefined, what: string): string {
  const c = contentOf(doc, expectTag(el, TAG.OID, what));
  if (c.length === 0) throw new Asn1Error(`${what}: empty OID`);
  const arcs: bigint[] = [];
  let v = 0n;
  let fresh = true;
  for (const b of c) {
    if (fresh && b === 0x80) throw new Asn1Error(`${what}: non-minimal OID subidentifier`);
    fresh = false;
    v = (v << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(v);
      v = 0n;
      fresh = true;
    }
  }
  if (!fresh) throw new Asn1Error(`${what}: truncated OID`);
  const first = arcs[0]!;
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...head, ...arcs.slice(1)].map(String).join('.');
}

export function octetString(doc: DerDocument, el: Tlv | undefined, what: string, tag: number = TAG.OCTET_STRING): Uint8Array {
  return contentOf(doc, expectTag(el, tag, what));
}

/** BIT STRING: unused-bit count 0..7, zero when empty, and the unused bits set to zero. */
export function bitString(doc: DerDocument, el: Tlv | undefined, what: string): { bytes: Uint8Array; unused: number } {
  const c = contentOf(doc, expectTag(el, TAG.BIT_STRING, what));
  if (c.length === 0) throw new Asn1Error(`${what}: empty BIT STRING`);
  const unused = c[0]!;
  if (unused > 7 || (c.length === 1 && unused !== 0)) throw new Asn1Error(`${what}: invalid unused-bit count`);
  const bytes = c.subarray(1);
  if (unused > 0 && (bytes[bytes.length - 1]! & ((1 << unused) - 1)) !== 0) {
    throw new Asn1Error(`${what}: nonzero unused bits`);
  }
  return { bytes, unused };
}

/** Bit n of a BIT STRING (bit 0 is the most significant bit of the first octet). */
export function bitSet(bytes: Uint8Array, n: number): boolean {
  const b = bytes[n >> 3];
  return b !== undefined && (b & (0x80 >> (n & 7))) !== 0;
}

/** Highest set bit index, or -1. */
export function highestBit(bytes: Uint8Array): number {
  for (let n = bytes.length * 8 - 1; n >= 0; n--) if (bitSet(bytes, n)) return n;
  return -1;
}

const ASCII_GEN_TIME_DER = /^[0-9]{14}(\.[0-9]*[1-9])?Z$/;

/**
 * GeneralizedTime under DER: digits, seconds present, an optional fraction
 * without trailing zeros and not empty, and a final Z. Calendar validity and
 * the nine-digit fraction limit are not DER rules; they are checked by the
 * caller's grammar (Blueprint §5.7).
 */
export function generalizedTimeDer(doc: DerDocument, el: Tlv | undefined, what: string): string {
  const c = contentOf(doc, expectTag(el, TAG.GeneralizedTime, what));
  let s = '';
  for (const b of c) {
    if (b > 0x7e || b < 0x20) throw new Asn1Error(`${what}: non-ASCII GeneralizedTime`);
    s += String.fromCharCode(b);
  }
  if (!ASCII_GEN_TIME_DER.test(s)) throw new Asn1Error(`${what}: GeneralizedTime breaks DER rules`);
  return s;
}

const UTC_TIME_DER = /^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$/;

function epochNs(y: number, mo: number, d: number, h: number, mi: number, s: number): bigint {
  const days = [31, (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (mo < 1 || mo > 12 || d < 1 || d > days[mo - 1]! || h > 23 || mi > 59 || s > 59) {
    throw new Asn1Error('invalid calendar time');
  }
  const date = new Date(Date.UTC(2000, mo - 1, d, h, mi, s));
  date.setUTCFullYear(y); // Date.UTC alone maps years 0..99 to 1900..1999.
  return BigInt(date.getTime()) * 1_000_000n;
}

/** X.509 Time (UTCTime or GeneralizedTime, DER forms) as epoch nanoseconds. */
export function x509Time(doc: DerDocument, el: Tlv | undefined, what: string): bigint {
  if (el?.tag === TAG.UTCTime) {
    const c = contentOf(doc, el);
    const m = UTC_TIME_DER.exec(String.fromCharCode(...c));
    if (m === null) throw new Asn1Error(`${what}: UTCTime breaks DER rules`);
    const yy = Number(m[1]);
    return epochNs(yy >= 50 ? 1900 + yy : 2000 + yy, +m[2]!, +m[3]!, +m[4]!, +m[5]!, +m[6]!);
  }
  const g = generalizedTimeDer(doc, el, what);
  const fraction = g.length > 15 ? BigInt(g.slice(15, -1).padEnd(9, '0')) : 0n;
  return (
    epochNs(+g.slice(0, 4), +g.slice(4, 6), +g.slice(6, 8), +g.slice(8, 10), +g.slice(10, 12), +g.slice(12, 14)) + fraction
  );
}
