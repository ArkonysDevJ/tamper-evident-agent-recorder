// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { argsHmac, bundleSha256, responseDigest, resultDigest } from '../../src/crypto/digests.js';
import { obj } from '../helpers/chain-builder.js';

test('001 AC-7 derivations', async (t) => {
  // The pepper is generated at run time and never written anywhere.
  const pepper = randomBytes(32);
  await t.test('tsa_ca_bundle_sha256 is over the raw bytes', () => {
    const lf = Buffer.from('-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n');
    const crlf = Buffer.from(lf.toString().replace(/\n/g, '\r\n'));
    assert.equal(bundleSha256(lf), createHash('sha256').update(lf).digest('hex'));
    assert.notEqual(bundleSha256(lf), bundleSha256(crlf));
  });
  await t.test('args_hmac is HMAC-SHA256 over the JCS bytes of the arguments', () => {
    const args = obj({ b: 1, a: 'x' });
    assert.equal(argsHmac(pepper, args), createHmac('sha256', pepper).update('{"a":"x","b":1}').digest('hex'));
  });
  await t.test('result and response digests are SHA-256 over JCS bytes', () => {
    assert.equal(resultDigest(obj({ ok: true })), createHash('sha256').update('{"ok":true}').digest('hex'));
    assert.equal(responseDigest([1, 2]), createHash('sha256').update('[1,2]').digest('hex'));
  });
  await t.test('a textual value is hashed as a JSON string with quotes', () => {
    assert.equal(resultDigest('done'), createHash('sha256').update('"done"').digest('hex'));
    assert.notEqual(resultDigest('done'), createHash('sha256').update('done').digest('hex'));
  });
});
