// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  formatTimestamp,
  parseGeneralizedTimeNs,
  parseTimestampNs,
  writerTimestamp,
} from '../../src/time/timestamps.js';

test('001 AC-5 timestamp-grammar', async (t) => {
  await t.test('valid values convert to BigInt(epoch_ms) * 1_000_000n', () => {
    assert.equal(parseTimestampNs('1970-01-01T00:00:00.000Z'), 0n);
    assert.equal(parseTimestampNs('2026-11-13T12:00:00.123Z'), BigInt(Date.UTC(2026, 10, 13, 12, 0, 0, 123)) * 1_000_000n);
    assert.equal(parseTimestampNs('2024-02-29T23:59:59.999Z'), BigInt(Date.UTC(2024, 1, 29, 23, 59, 59, 999)) * 1_000_000n);
    assert.equal(parseTimestampNs('0001-01-01T00:00:00.000Z'), -62135596800000n * 1_000_000n);
    assert.notEqual(parseTimestampNs('9999-12-31T23:59:59.999Z'), null);
  });
  await t.test('invalid format or calendar is rejected', () => {
    for (const bad of [
      '2026-11-13T12:00:00Z',
      '2026-11-13T12:00:00.12Z',
      '2026-11-13T12:00:00.1234Z',
      '2026-11-13T12:00:00.123+00:00',
      '2026-11-13 12:00:00.123Z',
      '2026-11-13t12:00:00.123z',
      '2025-02-29T00:00:00.000Z',
      '2026-02-30T00:00:00.000Z',
      '2026-13-01T00:00:00.000Z',
      '2026-00-01T00:00:00.000Z',
      '2026-11-13T24:00:00.000Z',
      '2026-11-13T12:60:00.000Z',
      '2026-11-13T12:00:60.000Z',
      '0000-01-01T00:00:00.000Z',
      '1900-02-29T00:00:00.000Z',
    ]) {
      assert.equal(parseTimestampNs(bad), null, bad);
    }
  });
  await t.test('GeneralizedTime grammar of §5.7', () => {
    assert.equal(parseGeneralizedTimeNs('19700101000000Z'), 0n);
    assert.equal(parseGeneralizedTimeNs('19700101000000.5Z'), 500_000_000n);
    assert.equal(parseGeneralizedTimeNs('19700101000000.000000001Z'), 1n);
    for (const bad of ['19700101000000.Z', '19700101000000,5Z', '19700101000000.1234567891Z', '197001010000Z', '20260230000000Z', '19700101000060Z', '19700101000000+0000']) {
      assert.equal(parseGeneralizedTimeNs(bad), null, bad);
    }
  });
  await t.test('formatting round-trips', () => {
    for (const ms of [0, 1, Date.UTC(2026, 10, 13, 12, 0, 0, 123), -62135596800000]) {
      assert.equal(parseTimestampNs(formatTimestamp(ms)), BigInt(ms) * 1_000_000n);
    }
  });
});

test('001 AC-6 writer-timestamps', async (t) => {
  const head = '2026-11-13T12:00:00.500Z';
  await t.test('a later clock is used, truncated to whole milliseconds', () => {
    assert.equal(writerTimestamp(Date.UTC(2026, 10, 13, 12, 0, 1, 0) + 0.9, head), '2026-11-13T12:00:01.000Z');
  });
  await t.test('a clock step back produces a tie, never a regression', () => {
    assert.equal(writerTimestamp(Date.UTC(2026, 10, 13, 11, 0, 0, 0), head), head);
  });
});
