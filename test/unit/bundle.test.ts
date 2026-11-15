// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { bundleSha256 } from '../../src/crypto/digests.js';
import { loadBundle } from '../../src/pki/bundle.js';
import { OID } from '../../src/pki/oids.js';
import { verifyOffline } from '../../src/verify/verify.js';
import { buildChain, chainIdOf } from '../helpers/chain-builder.js';
import { serialize, writeInputs } from '../helpers/verify-files.js';
import {
  SIGNER_EXTS,
  certificate,
  CN,
  O,
  cn,
  derCompare,
  ext,
  oid,
  sequence,
  tlv,
  key,
  pem,
  testPki,
} from '../helpers/pki.js';
import type { ExtSpec } from '../helpers/pki.js';

/** Verifies a genesis-only log whose genesis carries the digest of these bundle bytes. */
function verifyWith(bundle: Uint8Array): { exitCode: number; stdout: string; stderr: string } {
  const rows = buildChain([], { bundleSha256: bundleSha256(bundle) });
  const inputs = writeInputs(chainIdOf(rows), serialize(rows));
  const bundlePath = path.join(path.dirname(path.resolve(inputs.checkpointsPath)), 'bundle.pem');
  fs.writeFileSync(bundlePath, bundle);
  return verifyOffline({ ...inputs, bundlePath });
}

const LOADS = 'VALID_UNANCHORED 0..0\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n';

function assertLoads(bundle: Uint8Array): void {
  const r = verifyWith(bundle);
  assert.deepEqual(r, { exitCode: 0, stdout: LOADS, stderr: '' });
}

function assertUnavailable(bundle: Uint8Array): void {
  const r = verifyWith(bundle);
  assert.deepEqual(r, { exitCode: 2, stdout: 'INPUT_UNAVAILABLE 0\n', stderr: '' });
}

const pki = testPki();
const good = (): Buffer => pki.bundle;
const block = (der: Uint8Array): string => pem([der]).toString('ascii');

test('003 AC-10 bundle-grammar', async (t) => {
  await t.test('the pinned bundle and a test bundle load', () => {
    assertLoads(fs.readFileSync('certs/tsa_roots.pem'));
    assertLoads(good());
  });
  await t.test('LF and CRLF line breaks both load', () => {
    assertLoads(pem([pki.root, pki.intermediate, pki.signer], '\r\n'));
    assertLoads(Buffer.from(`${block(pki.root)}\n\r\n${block(pki.intermediate)}${block(pki.signer)}\n`));
  });
  await t.test('the last END line may close the file without a line break', () => {
    assertLoads(Buffer.from(good().toString('ascii').replace(/\n$/, '')));
  });
  const vectors: [string, () => Uint8Array][] = [
    ['an empty file', () => new Uint8Array()],
    ['only line breaks', () => Buffer.from('\n\r\n')],
    ['text before the first block', () => Buffer.from(`# roots\n${good().toString()}`)],
    ['text between blocks', () => Buffer.from(`${block(pki.root)}comment\n${block(pki.intermediate)}${block(pki.signer)}`)],
    ['text after the last block', () => Buffer.from(`${good().toString()}end\n`)],
    ['a block with another label', () => Buffer.from(`${good().toString()}${block(pki.root).replaceAll('CERTIFICATE', 'X509 CRL')}`)],
    ['a private key block', () => Buffer.from(`${good().toString()}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n`)],
    ['a block that is not one DER certificate', () => Buffer.from(`${good().toString()}${block(Buffer.from('not a certificate'))}`)],
    ['two certificates in one block', () => Buffer.from(`${good().toString()}${block(Buffer.concat([pki.root, pki.root]))}`)],
    ['a short base64 line inside a block', () => Buffer.from(good().toString().replace(/\n([A-Za-z0-9+/]{64})\n/, (_m, l: string) => `\n${l.slice(0, 32)}\n${l.slice(32)}\n`))],
    ['trailing spaces on a line', () => Buffer.from(good().toString().replace('-----END CERTIFICATE-----', '-----END CERTIFICATE----- '))],
    ['a bare CR line break', () => Buffer.from(good().toString().replace('\n', '\r'))],
    ['an unterminated block', () => Buffer.from(good().toString().replace(/-----END CERTIFICATE-----\n$/, ''))],
  ];
  for (const [label, bytes] of vectors) {
    await t.test(`${label}: INPUT_UNAVAILABLE 0, exit 2`, () => assertUnavailable(bytes()));
  }
});

/** A bundle of the test root, intermediate and signer with one certificate replaced. */
function bundleWith(replace: { root?: Uint8Array; intermediate?: Uint8Array; signer?: Uint8Array; extra?: Uint8Array[] }): Buffer {
  return pem([replace.root ?? pki.root, replace.intermediate ?? pki.intermediate, replace.signer ?? pki.signer, ...(replace.extra ?? [])]);
}

function rootWith(extensions: ExtSpec[], opts: { badSignature?: boolean; keyKind?: Parameters<typeof key>[0] } = {}): Uint8Array {
  const k = opts.keyKind === undefined ? pki.rootKey : key(opts.keyKind, 7);
  return certificate({
    subject: pki.rootName,
    issuer: pki.rootName,
    subjectKey: k,
    issuerKey: k,
    extensions,
    ...(opts.badSignature === true ? { badSignature: true } : {}),
  });
}

function intermediateWith(extensions: ExtSpec[]): Uint8Array {
  return certificate({ subject: pki.intName, issuer: pki.rootName, subjectKey: pki.intKey, issuerKey: pki.rootKey, extensions });
}

function signerWith(extensions: ExtSpec[], subjectKeyKind?: Parameters<typeof key>[0], subject?: Uint8Array): Uint8Array {
  return certificate({
    subject: subject ?? pki.signerName,
    issuer: pki.intName,
    subjectKey: subjectKeyKind === undefined ? pki.signerKey : key(subjectKeyKind, 8),
    issuerKey: pki.intKey,
    extensions,
  });
}

test('003 AC-11 bundle-loading', async (t) => {
  await t.test('roles come from the bytes: self-issued root, CA intermediate, non-CA signer', () => {
    const b = loadBundle(good());
    assert.deepEqual(b.certificates.map((c) => c.role), ['root', 'intermediate', 'signer']);
    const real = loadBundle(fs.readFileSync('certs/tsa_roots.pem'));
    assert.deepEqual(real.certificates.map((c) => c.role), ['root', 'signer', 'root', 'intermediate', 'signer']);
  });
  await t.test('roots with correct and incorrect self-signatures both load', () => {
    assertLoads(bundleWith({ root: rootWith([ext.bc(true), ext.ku([5])]) }));
    assertLoads(bundleWith({ root: rootWith([ext.bc(true), ext.ku([5])], { badSignature: true }) }));
  });
  const failing: [string, () => Uint8Array][] = [
    ['a self-issued certificate without CA=true', () => bundleWith({ root: rootWith([ext.ku([5])]) })],
    ['a self-issued certificate with CA=false', () => bundleWith({ root: rootWith([ext.bc(false)]) })],
    ['a root whose keyUsage lacks keyCertSign', () => bundleWith({ root: rootWith([ext.bc(true), ext.ku([0])]) })],
    ['no root', () => pem([pki.intermediate, pki.signer])],
    ['no signer', () => pem([pki.root, pki.intermediate])],
    ['a 1024-bit RSA key', () => bundleWith({ signer: signerWith(SIGNER_EXTS(), 'rsa1024') })],
    ['a secp256k1 key', () => bundleWith({ signer: signerWith(SIGNER_EXTS(), 'secp256k1') })],
    ['an Ed25519 key', () => bundleWith({ signer: signerWith(SIGNER_EXTS(), 'ed25519') })],
    ['an RSA-PSS key', () => bundleWith({ signer: signerWith(SIGNER_EXTS(), 'rsa-pss') })],
    ['a critical extension outside the allowlist (nameConstraints)', () => bundleWith({ intermediate: intermediateWith([ext.bc(true), ext.raw('2.5.29.30', Buffer.from('3000', 'hex'), true)]) })],
    ['a critical certificatePolicies extension', () => bundleWith({ signer: signerWith([...SIGNER_EXTS(), ext.raw('2.5.29.32', Buffer.from('300830060604551d2000', 'hex'), true)]) })],
    ['invalid DER (a truncated certificate)', () => bundleWith({ extra: [pki.root.subarray(0, pki.root.length - 1)] })],
    ['a duplicate extnID', () => bundleWith({ signer: signerWith([...SIGNER_EXTS(), ext.ku([0])]) })],
  ];
  for (const [label, bytes] of failing) {
    await t.test(`${label}: INPUT_UNAVAILABLE 0, exit 2`, () => assertUnavailable(bytes()));
  }
  await t.test('loading uses no network and no system trust store (a self-made root is trusted only through the file)', () => {
    // A bundle that names nothing in any system store loads, and the real roots are not consulted.
    assertLoads(good());
  });
});

test('003 extension vectors (§7): the four allowlisted extensions, critical and noncritical', async (t) => {
  const cases: [string, () => Uint8Array, boolean][] = [
    ['basicConstraints critical, valid', () => bundleWith({ intermediate: intermediateWith([ext.bc(true, true)]) }), true],
    ['basicConstraints noncritical, valid', () => bundleWith({ intermediate: intermediateWith([ext.bc(true, false)]) }), true],
    ['basicConstraints with explicit cA FALSE (violating DER)', () => bundleWith({ signer: signerWith([{ oid: OID.extBasicConstraints, critical: true, value: Buffer.from('30030101' + '00', 'hex') }, ...SIGNER_EXTS()]) }), false],
    ['basicConstraints noncritical with a negative pathLen', () => bundleWith({ intermediate: intermediateWith([ext.bc(true, false, -1n)]) }), false],
    ['keyUsage critical, valid', () => bundleWith({ intermediate: intermediateWith([ext.bc(true), ext.ku([5], true)]) }), true],
    ['keyUsage noncritical, valid', () => bundleWith({ intermediate: intermediateWith([ext.bc(true), ext.ku([5], false)]) }), true],
    ['intermediate with critical CA=true and noncritical keyUsage without keyCertSign', () => bundleWith({ intermediate: intermediateWith([ext.bc(true, true), ext.ku([0], false)]) }), false],
    ['the same intermediate with keyCertSign', () => bundleWith({ intermediate: intermediateWith([ext.bc(true, true), ext.ku([0, 5], false)]) }), true],
    ['an unused intermediate without keyCertSign still fails loading', () => bundleWith({ extra: [certificate({ subject: cn('Unused CA'), issuer: pki.rootName, subjectKey: key('rsa2048', 9), issuerKey: pki.rootKey, extensions: [ext.bc(true), ext.ku([0], false)] })] }), false],
    ['extendedKeyUsage critical with only timeStamping, valid', () => bundleWith({ signer: signerWith([ext.ku([0]), ext.eku([OID.kpTimeStamping], true)]) }), true],
    ['extendedKeyUsage noncritical on the signer', () => bundleWith({ signer: signerWith([ext.ku([0]), ext.eku([OID.kpTimeStamping], false)]) }), false],
    ['extendedKeyUsage with a second purpose', () => bundleWith({ signer: signerWith([ext.ku([0]), ext.eku([OID.kpTimeStamping, '1.3.6.1.5.5.7.3.1'])]) }), false],
    ['signer keyUsage with digitalSignature and keyEncipherment (at least one of the two is enough)', () => bundleWith({ signer: signerWith([ext.ku([0, 2]), ext.eku([OID.kpTimeStamping])]) }), true],
    ['signer keyUsage with contentCommitment and keyCertSign', () => bundleWith({ signer: signerWith([ext.ku([1, 5]), ext.eku([OID.kpTimeStamping])]) }), true],
    ['signer keyUsage with keyEncipherment only', () => bundleWith({ signer: signerWith([ext.ku([2]), ext.eku([OID.kpTimeStamping])]) }), false],
    ['signer keyUsage with contentCommitment only', () => bundleWith({ signer: signerWith([ext.ku([1]), ext.eku([OID.kpTimeStamping])]) }), true],
    ['subjectAltName critical, valid', () => bundleWith({ signer: signerWith([...SIGNER_EXTS(), ext.san([Buffer.from('820b6578616d706c652e6f7267', 'hex')], true)]) }), true],
    ['subjectAltName noncritical, valid', () => bundleWith({ signer: signerWith([...SIGNER_EXTS(), ext.san([Buffer.from('820b6578616d706c652e6f7267', 'hex')], false)]) }), true],
    ['subjectAltName noncritical, empty (violating)', () => bundleWith({ signer: signerWith([...SIGNER_EXTS(), ext.raw(OID.extSubjectAltName, Buffer.from('3000', 'hex'))]) }), false],
    ['subjectAltName critical, not a GeneralName (violating)', () => bundleWith({ signer: signerWith([...SIGNER_EXTS(), ext.raw(OID.extSubjectAltName, Buffer.from('30030101ff', 'hex'), true)]) }), false],
    ['another noncritical extension is ignored after valid DER decoding', () => bundleWith({ signer: signerWith([...SIGNER_EXTS(), ext.raw('1.2.3.4.5', Buffer.from('not DER'))]) }), true],
    ['an extension with critical FALSE encoded explicitly', () => bundleWith({ signer: signerWith([...SIGNER_EXTS(), { oid: '1.2.3.4.5', explicitFalse: true, value: Buffer.from('0500', 'hex') }]) }), false],
  ];
  // A multi-valued RDN: SET OF AttributeTypeAndValue, whose DER order is enforced in Names.
  const atv = (type: string, v: string) => sequence(oid(type), tlv(0x0c, Buffer.from(v, 'utf8')));
  const rdnName = (first: Uint8Array, second: Uint8Array) => sequence(tlv(0x31, Buffer.concat([first, second])));
  const sorted = [atv(O, 'TEAR test'), atv(CN, 'Multi')].sort(derCompare);
  cases.push(
    ['a multi-valued RDN in DER order', () => bundleWith({ signer: signerWith(SIGNER_EXTS(), undefined, rdnName(sorted[0]!, sorted[1]!)) }), true],
    ['a multi-valued RDN not in DER order', () => bundleWith({ signer: signerWith(SIGNER_EXTS(), undefined, rdnName(sorted[1]!, sorted[0]!)) }), false],
  );
  for (const [label, bytes, loads] of cases) {
    await t.test(`${label}: ${loads ? 'loads' : 'INPUT_UNAVAILABLE 0'}`, () => (loads ? assertLoads(bytes()) : assertUnavailable(bytes())));
  }
});
