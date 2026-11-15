// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkTree, children, contentOf, decodeDer, encodingOf } from '../../src/asn1/der.js';
import { boolean, integer, octetString, oid } from '../../src/asn1/types.js';
import { sha256Hex } from '../../src/crypto/digests.js';
import { OID } from '../../src/pki/oids.js';
import { NONCE_HEX_RE, buildTimeStampReq, newNonceHex, newTimeStampRequest } from '../../src/tsa/request.js';

const fill = (v: number) => (n: number) => new Uint8Array(n).fill(v);

test('003 AC-1 nonce', async (t) => {
  await t.test('the top two bits are forced: buf[0] = (buf[0] & 0x3f) | 0x40', () => {
    assert.equal(newNonceHex(fill(0x00)), '4000000000000000');
    assert.equal(newNonceHex(fill(0xff)), '7fffffffffffffff');
    assert.equal(newNonceHex(fill(0xc0)), '40c0c0c0c0c0c0c0');
  });
  await t.test('random nonces are 16 lowercase hex in [2^62, 2^63 - 1]', () => {
    for (let i = 0; i < 500; i++) {
      const h = newNonceHex();
      assert.match(h, NONCE_HEX_RE);
      const v = BigInt(`0x${h}`);
      assert.ok(v >= 2n ** 62n && v <= 2n ** 63n - 1n);
    }
  });
  await t.test('the default source is the CSPRNG (no two of 1000 nonces collide)', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) seen.add(newNonceHex());
    assert.equal(seen.size, 1000);
  });
});

test('003 AC-2 request-der', async (t) => {
  const entryHash = 'ab'.repeat(32);
  await t.test('exactly version 1, messageImprint SHA-256 + entry_hash, nonce, certReq TRUE', () => {
    const der = buildTimeStampReq(entryHash, '4123456789abcdef');
    const doc = decodeDer(der);
    checkTree(doc);
    const f = children(doc, doc.root);
    assert.equal(f.length, 4, 'no reqPolicy and no extensions');
    assert.equal(integer(doc, f[0], 'version'), 1n);
    const mi = children(doc, f[1]!);
    const alg = children(doc, mi[0]!);
    assert.equal(oid(doc, alg[0], 'alg'), OID.sha256);
    assert.equal(alg.length, 1, 'absent parameters');
    assert.equal(Buffer.from(octetString(doc, mi[1], 'hash')).toString('hex'), entryHash);
    assert.equal(integer(doc, f[2], 'nonce'), 0x4123456789abcdefn);
    assert.equal(boolean(doc, f[3], 'certReq'), true);
    assert.equal(Buffer.from(contentOf(doc, f[2]!)).toString('hex'), '4123456789abcdef', 'positive INTEGER of 8 octets');
    assert.equal(encodingOf(doc, doc.root).length, der.length);
  });
  await t.test('the exact bytes', () => {
    const der = buildTimeStampReq('00'.repeat(32), '4000000000000000');
    const expected = [
      '3041', // SEQUENCE, 65 octets
      '020101', // version 1
      '302f', // messageImprint
      '300b0609608648016503040201', // SHA-256, absent parameters
      `0420${'00'.repeat(32)}`, // hashedMessage
      '02084000000000000000', // nonce
      '0101ff', // certReq TRUE
    ].join('');
    assert.equal(Buffer.from(der).toString('hex'), expected);
  });
  await t.test('tsq_der_sha256 is the digest of the DER bytes', () => {
    const r = newTimeStampRequest(entryHash);
    assert.equal(r.derSha256, sha256Hex(r.der));
    assert.match(r.nonceHex, NONCE_HEX_RE);
  });
  await t.test('inputs outside the forms are refused', () => {
    assert.throws(() => buildTimeStampReq('AB'.repeat(32), '4000000000000000'));
    assert.throws(() => buildTimeStampReq(entryHash, '8000000000000000'));
  });
});
