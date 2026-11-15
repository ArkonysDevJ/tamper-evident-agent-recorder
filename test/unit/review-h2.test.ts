// SPDX-License-Identifier: AGPL-3.0-or-later
// Review finding 2: Step 2.2 must enforce the RFC 3161 field types and constraints (Blueprint §6a), including
// PKIStatusInfo.statusString (PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseReceipt } from '../../src/tsa/receipt.js';
import { baseTokenSpec } from '../helpers/anchors.js';
import { genTimeOf, sequence, testPki, timeStampResp, tlv } from '../helpers/pki.js';

const pki = testPki();
const ctx = { k: 10, entryHash: 'ab'.repeat(32), nonce: 0x4123456789abcdefn, genTime: genTimeOf(new Date(Date.UTC(2026, 10, 13, 12, 0, 3))), pki };

function stage(statusExtra: Uint8Array[]): string {
  const r = parseReceipt(timeStampResp({ ...baseTokenSpec(ctx), statusExtra }));
  return r.ok ? 'accepted' : r.stage;
}

test('review H2: statusString constraints (RFC 3161 PKIStatusInfo, PKIFreeText)', async (t) => {
  await t.test('a valid statusString is accepted', () => assert.equal(stage([sequence(tlv(0x0c, Buffer.from('granted')))]), 'accepted'));
  await t.test('an empty statusString (SIZE (1..MAX)) fails Step 2.2', () => assert.equal(stage([sequence()]), 'structure'));
  await t.test('a statusString element that is not valid UTF-8 fails Step 2.2', () => assert.equal(stage([sequence(tlv(0x0c, Uint8Array.of(0xff, 0xfe)))]), 'structure'));
});
