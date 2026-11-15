// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { TearError } from '../../src/errors.js';
import { argsHmac, resultDigest, responseDigest } from '../../src/crypto/digests.js';
import { adapterJson, failedToolValue } from '../../src/interceptor/interceptor.js';
import { PEPPER_ENV, readPepper } from '../../src/interceptor/pepper.js';
import { median, percentile, renderM3, summarize } from '../m3/report.js';

const sha = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

function codeOf(fn: () => unknown): string {
  try {
    fn();
    return 'OK';
  } catch (err) {
    return err instanceof TearError ? err.code : `other: ${String(err)}`;
  }
}

test('005 AC-7 pepper-not-persisted (format)', async (t) => {
  const hex = randomBytes(32).toString('hex');
  await t.test('lowercase hex of 64 characters decodes to 32 bytes', () => {
    assert.deepEqual(Buffer.from(readPepper({ [PEPPER_ENV]: hex })), Buffer.from(hex, 'hex'));
    assert.equal(readPepper({ [PEPPER_ENV]: randomBytes(48).toString('hex') }).length, 48);
  });
  const bad: [string, string | undefined, string][] = [
    ['unset', undefined, 'PEPPER_MISSING'],
    ['empty', '', 'PEPPER_MISSING'],
    ['uppercase hex', hex.toUpperCase(), 'PEPPER_INVALID'],
    ['31 bytes', hex.slice(0, 62), 'PEPPER_INVALID'],
    ['odd length', `${hex}a`, 'PEPPER_INVALID'],
    ['not hex', `${hex.slice(0, 63)}g`, 'PEPPER_INVALID'],
    ['surrounding whitespace', ` ${hex}`, 'PEPPER_INVALID'],
    ['base64', randomBytes(32).toString('base64'), 'PEPPER_INVALID'],
  ];
  for (const [label, value, code] of bad) {
    await t.test(`${label} → ${code}, without echoing the value`, () => {
      const env = value === undefined ? {} : { [PEPPER_ENV]: value };
      assert.equal(codeOf(() => readPepper(env)), code);
      try {
        readPepper(env);
      } catch (err) {
        if (value !== undefined && value !== '') assert.ok(!(err as Error).message.includes(value));
      }
    });
  }
});

test('005 AC-3 adapter-digests', async (t) => {
  const pepper = randomBytes(32);
  await t.test('args_hmac is HMAC-SHA256 over the RFC 8785 bytes of the arguments', () => {
    const args = { b: 2, a: [1, 'x'] };
    assert.equal(argsHmac(pepper, args), createHmac('sha256', pepper).update('{"a":[1,"x"],"b":2}').digest('hex'));
  });
  await t.test('a textual result or answer is hashed as a JSON string, with quotes and escapes', () => {
    assert.equal(resultDigest('hello'), sha('"hello"'));
    assert.equal(responseDigest('line\n"two"'), sha('"line\\n\\"two\\""'));
    assert.notEqual(resultDigest('hello'), sha('hello'));
  });
  await t.test('key order does not change the digest', () => {
    assert.equal(resultDigest({ x: 1, y: 2 }), resultDigest({ y: 2, x: 1 }));
  });
});

test('005 AC-4 adapter-json-domain (values)', async (t) => {
  const cyclic: Record<string, unknown> = {};
  cyclic['self'] = cyclic;
  const withGetter = Object.defineProperty({}, 'g', { get: () => 1, enumerable: true });
  const sparse = [1, , 3]; // eslint-disable-line no-sparse-arrays
  const bad: [string, unknown][] = [
    ['undefined', undefined],
    ['a member set to undefined', { a: undefined }],
    ['NaN', Number.NaN],
    ['Infinity', [Number.POSITIVE_INFINITY]],
    ['a BigInt', 10n],
    ['a function', () => 1],
    ['a symbol', Symbol('s')],
    ['a Date', new Date(0)],
    ['a Map', new Map()],
    ['a class instance', new (class Box {})()],
    ['a lone surrogate in a value', { a: '\uD800' }],
    ['a lone surrogate in a key', { '\uDC00': 1 }],
    ['a cycle', cyclic],
    ['a getter', withGetter],
    ['a sparse array', sparse],
    ['a symbol key', { [Symbol('k')]: 1 }],
  ];
  for (const [label, value] of bad) {
    await t.test(`${label} → ADAPTER_JSON_INVALID`, () => assert.equal(codeOf(() => adapterJson(value, 'x')), 'ADAPTER_JSON_INVALID'));
  }
  const good: [string, unknown][] = [
    ['null', null],
    ['a nested plain object', { a: [1, true, null, 'é', { b: -0.5 }] }],
    ['a null-prototype object', Object.assign(Object.create(null) as object, { a: 1 })],
    ['a string with U+0000 (transient arguments may carry it)', 'a\u0000b'],
  ];
  for (const [label, value] of good) await t.test(`${label} is accepted`, () => assert.equal(codeOf(() => adapterJson(value, 'x')), 'OK'));
});

test('005 AC-11 failed-tool-digest (value)', () => {
  const v = failedToolValue('not_found', 'no record with id rec-1');
  assert.equal(resultDigest(v), sha('{"error_type":"not_found","message":"no record with id rec-1"}'));
});

test('005 AC-9 m3-report', async (t) => {
  await t.test('median and nearest-rank percentiles', () => {
    assert.equal(median([3, 1, 2]), 2);
    assert.equal(median([4, 1, 3, 2]), 2.5);
    assert.equal(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50), 5);
    assert.equal(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95), 10);
    assert.equal(percentile([7], 95), 7);
  });
  const run = (ord: number[], anc: number[], bytes: number[]) => ({ ordinaryMs: ord, anchorMs: anc, recordBytes: bytes });
  const base = { environment: { PostgreSQL: '16.15' }, stamps: { freetsa: 10 }, eventsPerRun: 100 };
  await t.test('targets are marked met or not met with the measured number', () => {
    const met = summarize({ ...base, withInterceptor: [run([2, 3, 4], [300, 400], [700, 800])], withoutInterceptor: [run([0.01, 0.02], [], [])] });
    assert.deepEqual([met.ordinaryMet, met.recordMet, met.ordinaryMedianMs, met.meanRecordBytes], [true, true, 3, 750]);
    const notMet = summarize({ ...base, withInterceptor: [run([20, 30, 16], [], [3000])], withoutInterceptor: [run([0.01], [], [])] });
    assert.deepEqual([notMet.ordinaryMet, notMet.recordMet, notMet.anchorP50Ms], [false, false, null]);
    const text = renderM3({ ...base, withInterceptor: [run([20, 30, 16], [], [3000])], withoutInterceptor: [run([0.01], [], [])] });
    assert.match(text, /\| Ordinary records, median per event \(with interceptor\) \| under 15 ms \| 20\.000 ms \| not met \|/);
    assert.match(text, /\| Anchor points, p95 \(0 samples\) \| reported \| unmeasured \| — \|/);
    assert.match(text, /\| Average record size \(exported row\) \| under 2048 bytes \| 3000\.0 bytes \| not met \|/);
  });
  await t.test('anchor points are reported apart from ordinary records, with p50 and p95', () => {
    const s = summarize({ ...base, withInterceptor: [run([1, 1], [100, 200, 300], [10]), run([2, 2], [400], [20])], withoutInterceptor: [run([0], [], [])] });
    assert.deepEqual([s.ordinaryMedianMs, s.anchorP50Ms, s.anchorP95Ms, s.anchorSamples], [1.5, 200, 400, 4]);
    assert.deepEqual(s.perRunMediansMs, [1, 2]);
  });
  await t.test('the same input renders the same text (no clock, no randomness)', () => {
    const i = { ...base, withInterceptor: [run([1, 2], [5], [10])], withoutInterceptor: [run([0], [], [])] };
    assert.equal(renderM3(i), renderM3(i));
  });
});
