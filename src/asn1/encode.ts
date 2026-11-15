// SPDX-License-Identifier: AGPL-3.0-or-later
// Minimal DER encoder for the structures TEAR builds itself (the RFC 3161
// TimeStampReq). Every function returns the full encoding of one element.

function lengthOctets(n: number): Uint8Array {
  if (n < 0x80) return Uint8Array.of(n);
  const out: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
  return Uint8Array.of(0x80 | out.length, ...out);
}

export function concat(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function tlv(tag: number, contents: Uint8Array): Uint8Array {
  return concat([Uint8Array.of(tag), lengthOctets(contents.length), contents]);
}

export function sequence(...items: Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(items));
}

export function set(...items: Uint8Array[]): Uint8Array {
  return tlv(0x31, concat(items));
}

/** INTEGER in minimal two's complement. */
export function integer(value: bigint): Uint8Array {
  const bytes: number[] = [];
  let v = value;
  for (;;) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
    const top = bytes[0]!;
    if ((v === 0n && top < 0x80) || (v === -1n && top >= 0x80)) break;
  }
  return tlv(0x02, Uint8Array.from(bytes));
}

/** INTEGER whose value is the unsigned big-endian bytes given. */
export function unsignedInteger(bytes: Uint8Array): Uint8Array {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return integer(v);
}

export function boolean(value: boolean): Uint8Array {
  return tlv(0x01, Uint8Array.of(value ? 0xff : 0x00));
}

export function nullValue(): Uint8Array {
  return Uint8Array.of(0x05, 0x00);
}

export function octetString(bytes: Uint8Array): Uint8Array {
  return tlv(0x04, bytes);
}

export function oid(dotted: string): Uint8Array {
  const arcs = dotted.split('.').map((a) => BigInt(a));
  if (arcs.length < 2) throw new RangeError('OID needs at least two arcs');
  const encoded: number[] = [];
  const sub = [arcs[0]! * 40n + arcs[1]!, ...arcs.slice(2)];
  for (const a of sub) {
    const group: number[] = [Number(a & 0x7fn)];
    for (let v = a >> 7n; v > 0n; v >>= 7n) group.unshift(Number(v & 0x7fn) | 0x80);
    encoded.push(...group);
  }
  return tlv(0x06, Uint8Array.from(encoded));
}

/** AlgorithmIdentifier with absent parameters. */
export function algorithm(dotted: string, params?: Uint8Array): Uint8Array {
  return params === undefined ? sequence(oid(dotted)) : sequence(oid(dotted), params);
}
