// SPDX-License-Identifier: AGPL-3.0-or-later
// Strict DER reader. It only splits bytes into TLV elements and byte ranges; it
// does not interpret any structure. Interpretation of each type lives in
// separate modules (asn1/types.ts, pki/*, tsa/*).
//
// Accepted: single-byte identifier octets (tag numbers 0..30) and definite
// lengths in their minimal form. Rejected: high-tag-number form, end-of-contents
// (tag 0x00), indefinite length, non-minimal lengths, lengths over 4 bytes,
// lengths that run past the enclosing element, trailing bytes, inputs over the
// size limit and nesting over the depth limit.

export const DER_LIMITS = {
  /** Largest input accepted, in bytes. */
  maxInputBytes: 1 << 20,
  /** Deepest nesting accepted; the top-level element has depth 0. */
  maxDepth: 32,
} as const;

export type DerErrorReason =
  | 'too_large'
  | 'truncated'
  | 'high_tag_number'
  | 'end_of_contents'
  | 'indefinite_length'
  | 'non_minimal_length'
  | 'length_too_long'
  | 'length_out_of_bounds'
  | 'trailing_bytes'
  | 'not_constructed'
  | 'too_deep';

export class DerError extends Error {
  readonly reason: DerErrorReason;
  constructor(reason: DerErrorReason, at: number) {
    super(`DER ${reason} at offset ${String(at)}`);
    this.name = 'DerError';
    this.reason = reason;
  }
}

export const TAG_CLASS = { universal: 0, application: 1, context: 2, private: 3 } as const;

/** One element: identifier and length octets at [start, contentStart), contents at [contentStart, end). */
export interface Tlv {
  /** The identifier octet. */
  readonly tag: number;
  readonly tagClass: number;
  readonly constructed: boolean;
  readonly tagNumber: number;
  readonly start: number;
  readonly contentStart: number;
  readonly end: number;
  readonly depth: number;
}

/** A buffer with its decoded top-level element. */
export interface DerDocument {
  readonly bytes: Uint8Array;
  readonly root: Tlv;
}

function readTlv(buf: Uint8Array, offset: number, limit: number, depth: number): Tlv {
  if (depth > DER_LIMITS.maxDepth) throw new DerError('too_deep', offset);
  if (offset >= limit) throw new DerError('truncated', offset);
  const tag = buf[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError('high_tag_number', offset);
  if (tag === 0x00) throw new DerError('end_of_contents', offset);
  let p = offset + 1;
  if (p >= limit) throw new DerError('truncated', p);
  const first = buf[p++]!;
  let length: number;
  if (first < 0x80) {
    length = first;
  } else if (first === 0x80) {
    throw new DerError('indefinite_length', offset);
  } else {
    const count = first & 0x7f;
    if (count > 4) throw new DerError('length_too_long', offset);
    if (p + count > limit) throw new DerError('truncated', p);
    if (buf[p] === 0x00) throw new DerError('non_minimal_length', offset);
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buf[p++]!;
    if (length < 0x80) throw new DerError('non_minimal_length', offset);
  }
  const end = p + length;
  if (end > limit) throw new DerError('length_out_of_bounds', offset);
  return {
    tag,
    tagClass: tag >> 6,
    constructed: (tag & 0x20) !== 0,
    tagNumber: tag & 0x1f,
    start: offset,
    contentStart: p,
    end,
    depth,
  };
}

/** Decodes exactly one element spanning the whole input. */
export function decodeDer(bytes: Uint8Array): DerDocument {
  if (bytes.length > DER_LIMITS.maxInputBytes) throw new DerError('too_large', 0);
  const root = readTlv(bytes, 0, bytes.length, 0);
  if (root.end !== bytes.length) throw new DerError('trailing_bytes', root.end);
  return { bytes, root };
}

/** The elements inside a constructed element; they must fill its contents exactly. */
export function children(doc: DerDocument, parent: Tlv): Tlv[] {
  if (!parent.constructed) throw new DerError('not_constructed', parent.start);
  const out: Tlv[] = [];
  let p = parent.contentStart;
  while (p < parent.end) {
    const child = readTlv(doc.bytes, p, parent.end, parent.depth + 1);
    out.push(child);
    p = child.end;
  }
  return out;
}

/** Decodes the whole tree once, so that every structural rule is checked up front. */
export function checkTree(doc: DerDocument, el: Tlv = doc.root): void {
  if (!el.constructed) return;
  for (const c of children(doc, el)) checkTree(doc, c);
}

/** The full encoding of an element (identifier, length and contents). */
export function encodingOf(doc: DerDocument, el: Tlv): Uint8Array {
  return doc.bytes.subarray(el.start, el.end);
}

/** The contents octets of an element. */
export function contentOf(doc: DerDocument, el: Tlv): Uint8Array {
  return doc.bytes.subarray(el.contentStart, el.end);
}

/** Decodes the contents of a primitive element (for example an OCTET STRING) as a nested DER document. */
export function decodeNested(doc: DerDocument, el: Tlv): DerDocument {
  return decodeDer(contentOf(doc, el));
}
