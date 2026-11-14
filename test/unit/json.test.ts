// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkRowSchema } from '../../src/chain/schema.js';
import { entryHashOf, sha256Hex } from '../../src/crypto/digests.js';
import { CanonicalizationError, canonicalize } from '../../src/json/jcs.js';
import { StrictJsonError, parseStrictJson } from '../../src/json/strict-json.js';
import { buildChain, envelope, obj, pausePayload } from '../helpers/chain-builder.js';

function jsonErrorKind(text: string): string | null {
  try {
    parseStrictJson(text);
    return null;
  } catch (err) {
    assert.ok(err instanceof StrictJsonError);
    return err.kind;
  }
}

test('001 AC-1 jcs-and-entry-hash', async (t) => {
  await t.test('RFC 8785 §3.2.2 example', () => {
    const input =
      '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
      '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}';
    const expected =
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
      '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
    assert.equal(canonicalize(parseStrictJson(input)), expected);
  });
  await t.test('property names sort by 16-bit code units', () => {
    const input = '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}';
    // Compare the serialized text: JSON.parse would reorder integer-like keys.
    const order: [string, string][] = [
      ['\r', 'Carriage Return'],
      ['1', 'One'],
      ['\u0080', 'Control'],
      ['ö', 'Latin Small Letter O With Diaeresis'],
      ['€', 'Euro Sign'],
      ['😀', 'Emoji: Grinning Face'],
      ['דּ', 'Hebrew Letter Dalet With Dagesh'],
    ];
    const expected = '{' + order.map(([k, v]) => `${JSON.stringify(k)}:${JSON.stringify(v)}`).join(',') + '}';
    assert.equal(canonicalize(parseStrictJson(input)), expected);
  });
  await t.test('-0 serializes as 0 and nested objects are sorted', () => {
    assert.equal(canonicalize(parseStrictJson('{"b":[-0,{"z":1,"a":2}],"a":1}')), '{"a":1,"b":[0,{"a":2,"z":1}]}');
  });
  await t.test('entry_hash = SHA-256 of the UTF-8 JCS serialization', () => {
    const [genesis] = buildChain([]);
    assert.equal(entryHashOf(genesis!.block), sha256Hex(Buffer.from(canonicalize(genesis!.block), 'utf8')));
    assert.match(genesis!.entry_hash, /^[0-9a-f]{64}$/);
  });
});

test('001 AC-3 row-lexical-rules', async (t) => {
  await t.test('duplicate keys at any depth are rejected', () => {
    assert.equal(jsonErrorKind('{"a":1,"a":2}'), 'duplicate_key');
    assert.equal(jsonErrorKind('{"a":{"b":[{"c":1,"c":1}]}}'), 'duplicate_key');
  });
  await t.test('NaN, Infinity and out-of-range numbers are rejected', () => {
    assert.equal(jsonErrorKind('NaN'), 'syntax');
    assert.equal(jsonErrorKind('[Infinity]'), 'syntax');
    assert.equal(jsonErrorKind('[-Infinity]'), 'syntax');
    assert.equal(jsonErrorKind('[1e400]'), 'non_finite_number');
  });
  await t.test('non-JSON syntax is rejected', () => {
    for (const bad of ['{a:1}', "{'a':1}", '[1,]', '01', '[1] x', '"\t"', '+1']) {
      assert.notEqual(jsonErrorKind(bad), null, bad);
    }
  });
  await t.test('integer fields must be safe nonnegative integers', () => {
    const rows = buildChain([pausePayload(1)]);
    for (const seq of [-1, 1.5, 2 ** 53, '1']) {
      const block = obj({ ...rows[1]!.block, seq });
      assert.equal(checkRowSchema(envelope(block, rows[1]!.entry_hash)).ok, false, String(seq));
    }
    const control = obj({ ...rows[1]!.block, payload: obj({
      event_type: 'checkpoint_failed', operation: 'tear.checkpoint', target_seq: 2 ** 53, error_type: 'x',
    }) });
    assert.equal(checkRowSchema(envelope(control, rows[1]!.entry_hash)).ok, false);
  });
});

test('001 AC-4 unicode-domain', async (t) => {
  await t.test('a lone surrogate is rejected by the parser and the serializer', () => {
    assert.equal(jsonErrorKind('"\\ud800"'), 'invalid_unicode');
    assert.equal(jsonErrorKind('"\\udc00x"'), 'invalid_unicode');
    assert.equal(jsonErrorKind('{"\\ud800":1}'), 'invalid_unicode');
    assert.throws(() => canonicalize('\ud800'), CanonicalizationError);
  });
  await t.test('an escaped valid surrogate pair is accepted', () => {
    assert.equal(parseStrictJson('"\\ud83d\\ude00"'), '\u{1F600}');
    assert.equal(canonicalize('\u{1F600}'), '"\u{1F600}"');
  });
  await t.test('U+0000 is rejected in persisted payload strings', () => {
    const rows = buildChain([pausePayload(1)]);
    const block = obj({ ...rows[1]!.block, payload: obj({ ...pausePayload(1), reason: 'a\u0000b' }) });
    assert.equal(checkRowSchema(envelope(block, rows[1]!.entry_hash)).ok, false);
    const nested = obj({ ...rows[1]!.block, payload: obj({ ...pausePayload(1), missing_sources: ['ok', '\u0000'] }) });
    assert.equal(checkRowSchema(envelope(nested, rows[1]!.entry_hash)).ok, false);
  });
  await t.test('U+0000 is accepted in transient values', () => {
    assert.equal(canonicalize(obj({ arg: 'a\u0000b' })), '{"arg":"a\\u0000b"}');
  });
});
