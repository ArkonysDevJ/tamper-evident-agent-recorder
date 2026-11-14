// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DER_LIMITS, DerError, checkTree, children, decodeDer } from '../../src/asn1/der.js';
import * as enc from '../../src/asn1/encode.js';
import {
  Asn1Error,
  bitString,
  boolean,
  generalizedTimeDer,
  integer,
  nullValue,
  oid,
  x509Time,
} from '../../src/asn1/types.js';

const b = (...bytes: number[]): Uint8Array => Uint8Array.from(bytes);

function reason(bytes: Uint8Array, deep = false): string {
  try {
    const doc = decodeDer(bytes);
    if (deep) checkTree(doc);
    return 'OK';
  } catch (err) {
    return err instanceof DerError ? err.reason : `other: ${String(err)}`;
  }
}

test('DER reader: accepted encodings', async (t) => {
  await t.test('short and long definite lengths in minimal form', () => {
    assert.equal(reason(b(0x04, 0x01, 0xaa)), 'OK');
    const long = enc.octetString(new Uint8Array(200));
    assert.deepEqual([...long.subarray(0, 3)], [0x04, 0x81, 200]);
    assert.equal(reason(long), 'OK');
    assert.equal(reason(enc.octetString(new Uint8Array(70000))), 'OK');
  });
  await t.test('a nested tree returns TLVs and byte ranges only', () => {
    const der = enc.sequence(enc.integer(5n), enc.sequence(enc.boolean(true)));
    const doc = decodeDer(der);
    const kids = children(doc, doc.root);
    assert.equal(kids.length, 2);
    assert.deepEqual({ tag: kids[0]!.tag, start: kids[0]!.start, contentStart: kids[0]!.contentStart, end: kids[0]!.end }, { tag: 0x02, start: 2, contentStart: 4, end: 5 });
    assert.equal(kids[1]!.depth, 1);
    assert.equal(children(doc, kids[1]!)[0]!.depth, 2);
  });
});

test('DER reader: every rejection rule', async (t) => {
  const vectors: [string, Uint8Array, string, boolean?][] = [
    ['high-tag-number form', b(0x1f, 0x81, 0x00, 0x00), 'high_tag_number'],
    ['end-of-contents tag', b(0x00, 0x00), 'end_of_contents'],
    ['indefinite length', b(0x30, 0x80, 0x00, 0x00), 'indefinite_length'],
    ['long form for a short length', b(0x04, 0x81, 0x01, 0xaa), 'non_minimal_length'],
    ['leading zero length octet', b(0x04, 0x82, 0x00, 0x81, ...new Array<number>(0x81).fill(0)), 'non_minimal_length'],
    ['length over 4 octets', b(0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00), 'length_too_long'],
    ['length past the end', b(0x04, 0x05, 0x01), 'length_out_of_bounds'],
    ['no length octet', b(0x04), 'truncated'],
    ['long length octets missing', b(0x04, 0x82, 0x01), 'truncated'],
    ['empty input', b(), 'truncated'],
    ['trailing bytes', b(0x05, 0x00, 0x00), 'trailing_bytes'],
    ['child runs past its parent', b(0x30, 0x03, 0x04, 0x05, 0x00), 'length_out_of_bounds', true],
    ['indefinite length inside a parent', b(0x30, 0x04, 0x30, 0x80, 0x00, 0x00), 'indefinite_length', true],
  ];
  for (const [label, bytes, expected, deep] of vectors) {
    await t.test(label, () => assert.equal(reason(bytes, deep), expected));
  }
  await t.test('input over the size limit', () => {
    assert.equal(reason(new Uint8Array(DER_LIMITS.maxInputBytes + 1)), 'too_large');
  });
  await t.test('nesting over the depth limit', () => {
    let el = enc.nullValue();
    for (let i = 0; i <= DER_LIMITS.maxDepth; i++) el = enc.sequence(el);
    assert.equal(reason(el, true), 'too_deep');
    let ok = enc.nullValue();
    for (let i = 0; i < DER_LIMITS.maxDepth; i++) ok = enc.sequence(ok);
    assert.equal(reason(ok, true), 'OK');
  });
  await t.test('children of a primitive element', () => {
    const doc = decodeDer(b(0x04, 0x00));
    assert.throws(() => children(doc, doc.root), (e: unknown) => e instanceof DerError && e.reason === 'not_constructed');
  });
});

function typeErr(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch (err) {
    return err instanceof Asn1Error;
  }
}

test('ASN.1 types: DER rules of each interpreted type', async (t) => {
  const one = (bytes: Uint8Array) => {
    const doc = decodeDer(bytes);
    return { doc, el: doc.root };
  };
  await t.test('INTEGER: minimal two’s complement, round trip', () => {
    for (const v of [0n, 1n, 127n, 128n, -1n, -128n, -129n, 2n ** 63n - 1n, 2n ** 64n]) {
      const { doc, el } = one(enc.integer(v));
      assert.equal(integer(doc, el, 'x'), v);
    }
    for (const bad of [b(0x02, 0x00), b(0x02, 0x02, 0x00, 0x7f), b(0x02, 0x02, 0xff, 0x80)]) {
      const { doc, el } = one(bad);
      assert.ok(typeErr(() => integer(doc, el, 'x')));
    }
  });
  await t.test('BOOLEAN: one octet, 0x00 or 0xFF', () => {
    assert.equal(boolean(one(b(0x01, 0x01, 0xff)).doc, one(b(0x01, 0x01, 0xff)).el, 'x'), true);
    for (const bad of [b(0x01, 0x01, 0x01), b(0x01, 0x02, 0x00, 0x00), b(0x01, 0x00)]) {
      const { doc, el } = one(bad);
      assert.ok(typeErr(() => boolean(doc, el, 'x')));
    }
  });
  await t.test('NULL: no contents', () => {
    const { doc, el } = one(b(0x05, 0x01, 0x00));
    assert.ok(typeErr(() => nullValue(doc, el, 'x')));
  });
  await t.test('OID: minimal subidentifiers, round trip', () => {
    for (const id of ['2.16.840.1.101.3.4.2.1', '1.2.840.113549.1.9.16.1.4', '2.999.1']) {
      const { doc, el } = one(enc.oid(id));
      assert.equal(oid(doc, el, 'x'), id);
    }
    for (const bad of [b(0x06, 0x00), b(0x06, 0x02, 0x2a, 0x80), b(0x06, 0x02, 0x80, 0x01), b(0x06, 0x01, 0x81)]) {
      const { doc, el } = one(bad);
      assert.ok(typeErr(() => oid(doc, el, 'x')));
    }
  });
  await t.test('BIT STRING: unused-bit count and zero padding bits', () => {
    const ok = one(b(0x03, 0x02, 0x07, 0x80));
    assert.equal(bitString(ok.doc, ok.el, 'x').unused, 7);
    for (const bad of [b(0x03, 0x00), b(0x03, 0x01, 0x01), b(0x03, 0x02, 0x08, 0x00), b(0x03, 0x02, 0x01, 0x01)]) {
      const { doc, el } = one(bad);
      assert.ok(typeErr(() => bitString(doc, el, 'x')));
    }
  });
  await t.test('GeneralizedTime: DER form only (no offset, no empty or trailing-zero fraction)', () => {
    const g = (s: string) => one(enc.tlv(0x18, Buffer.from(s, 'latin1')));
    for (const s of ['20261114230819Z', '20261114230819.5Z', '20261114230819.1234567891Z', '20260230000000Z']) {
      const { doc, el } = g(s);
      assert.equal(generalizedTimeDer(doc, el, 'x'), s);
    }
    for (const s of ['2026111423081AZ', '20261114230819+0100', '20261114230819.50Z', '20261114230819.Z', '202611142308Z', '20261114230819', '20261114230819,5Z']) {
      const { doc, el } = g(s);
      assert.ok(typeErr(() => generalizedTimeDer(doc, el, 'x')), s);
    }
  });
  await t.test('X.509 UTCTime: years 50..99 are 19xx, 00..49 are 20xx', () => {
    const u = (s: string) => one(enc.tlv(0x17, Buffer.from(s, 'ascii')));
    const a = u('500101000000Z');
    assert.equal(x509Time(a.doc, a.el, 'x'), BigInt(Date.UTC(1950, 0, 1)) * 1_000_000n);
    const c = u('491231235959Z');
    assert.equal(x509Time(c.doc, c.el, 'x'), BigInt(Date.UTC(2049, 11, 31, 23, 59, 59)) * 1_000_000n);
    const bad = u('4912312359Z');
    assert.ok(typeErr(() => x509Time(bad.doc, bad.el, 'x')));
  });
});
