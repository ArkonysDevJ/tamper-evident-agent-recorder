// SPDX-License-Identifier: AGPL-3.0-or-later
// Steps 2, 2b and 3 of tear-verify under TEAR-TSA-01, with receipts built by
// the test PKI. Every vector checks the exact canonical output line.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { OID } from '../../src/pki/oids.js';
import { parseGeneralizedTimeNs } from '../../src/time/timestamps.js';
import { buildScenario, baseTokenSpec, firstLine, verifyScenario, writeScenario } from '../helpers/anchors.js';
import type { Scenario, ScenarioOptions, TokenContext } from '../helpers/anchors.js';
import { rehash } from '../helpers/chain-builder.js';
import {
  SIGNER_EXTS,
  algorithm,
  attribute,
  certificate,
  cn,
  digestAlg,
  directoryName,
  dnsName,
  ext,
  integer,
  issuerAndSerial,
  key,
  name,
  nullValue,
  octetString,
  oid,
  pem,
  sequence,
  testPki,
  timeStampResp,
  tstInfo,
  CN,
  O,
} from '../helpers/pki.js';
import type { TokenSpec, TstSpec } from '../helpers/pki.js';
import { CLI_PATH, cliArgs } from '../helpers/verify-files.js';

const pki = testPki();

/** A scenario (anchors 10 and 20, rows 0..25) whose receipt for k=10 is modified. */
function at10(mod: (c: TokenContext, base: TokenSpec) => TokenSpec | Uint8Array, opts: ScenarioOptions = {}): Scenario {
  return buildScenario({
    last: 25,
    pki,
    ...opts,
    token: (c) => {
      const base = baseTokenSpec(c);
      if (c.k !== 10) return timeStampResp(base);
      const r = mod(c, base);
      return r instanceof Uint8Array ? r : timeStampResp(r);
    },
  });
}

/** Rebuilds the TSTInfo of the base spec with some fields changed. */
function tst(c: TokenContext, fields: Partial<TstSpec>): Uint8Array {
  return tstInfo({ hashedMessage: Buffer.from(c.entryHash, 'hex'), genTime: c.genTime, nonce: c.nonce, ...fields });
}

function line(s: Scenario): string {
  return firstLine(verifyScenario(s));
}

const OK_FIRST = 'VERIFIED_ANCHORED 0..20';

function expectAt10(code: string) {
  return (s: Scenario): void => {
    const r = verifyScenario(s);
    assert.equal(r.exitCode, code === 'OK' ? 0 : 1, r.stdout);
    assert.equal(firstLine(r), code === 'OK' ? OK_FIRST : `${code} 10`);
    assert.equal(r.stderr, '');
  };
}

const SIG = expectAt10('TSA_SIGNATURE_INVALID');
const OK = expectAt10('OK');
const FMT = expectAt10('TSA_TIME_FORMAT_INVALID');
const COMMIT = expectAt10('ANCHOR_COMMITMENT_MISMATCH');

test('003 baseline: a valid anchored log', () => {
  const s = buildScenario({ last: 25, pki });
  const r = verifyScenario(s);
  const g10 = s.packages.get(10)!.genTime;
  const g20 = s.packages.get(20)!.genTime;
  assert.equal(
    r.stdout,
    [
      'VERIFIED_ANCHORED 0..20',
      'VALID_UNANCHORED 21..25',
      'MAX_ANCHOR_GAP 10',
      'ANCHORED_CHECKPOINT_FAILURES 0',
      `ANCHOR_TIME 10 ${g10} ACCURACY_NS unspecified LATEST_BOUND_NS unspecified`,
      `ANCHOR_TIME 20 ${g20} ACCURACY_NS unspecified LATEST_BOUND_NS unspecified`,
      '',
    ].join('\n'),
  );
  assert.equal(r.exitCode, 0);
});

// ---------------- AC-12 inventory ----------------

function withNamespace(s: Scenario, change: (ns: string) => void): string {
  const inputs = writeScenario(s);
  change(path.resolve(inputs.checkpointsPath));
  return writeAndVerifyLine(inputs);
}

function writeAndVerifyLine(inputs: ReturnType<typeof writeScenario>): string {
  const r = spawnSync(process.execPath, [CLI_PATH, ...cliArgs(inputs)], { encoding: 'utf8' });
  assert.equal(r.stderr, '');
  return r.stdout.split('\n')[0]!;
}

test('003 AC-12 inventory', async (t) => {
  const s = buildScenario({ last: 25, pki });
  const v: [string, (ns: string) => void, string][] = [
    ['a directory in place of 20.tsr', (ns) => { fs.rmSync(path.join(ns, '20.tsr')); fs.mkdirSync(path.join(ns, '20.tsr')); }, 'ANCHOR_PACKAGE_INCOMPLETE 20'],
    ['a symlink in place of 20.anchor.json', (ns) => { const p = path.join(ns, '20.anchor.json'); fs.renameSync(p, path.join(ns, '..', 'real.json')); fs.symlinkSync(path.join(ns, '..', 'real.json'), p); }, 'ANCHOR_PACKAGE_INCOMPLETE 20'],
    ['a FIFO in place of 20.tsr', (ns) => { fs.rmSync(path.join(ns, '20.tsr')); assert.equal(spawnSync('mkfifo', [path.join(ns, '20.tsr')]).status, 0); }, 'ANCHOR_PACKAGE_INCOMPLETE 20'],
    ['an unreadable 20.tsr', (ns) => fs.chmodSync(path.join(ns, '20.tsr'), 0o000), 'ANCHOR_PACKAGE_INCOMPLETE 20'],
    ['an unpaired 20.tsr', (ns) => fs.rmSync(path.join(ns, '20.anchor.json')), 'ANCHOR_PACKAGE_INCOMPLETE 20'],
    ['an unpaired 20.anchor.json', (ns) => fs.rmSync(path.join(ns, '20.tsr')), 'ANCHOR_PACKAGE_INCOMPLETE 20'],
    ['a noncanonical 010.tsr (parameter 0)', (ns) => fs.writeFileSync(path.join(ns, '010.tsr'), 'x'), 'ANCHOR_PACKAGE_INCOMPLETE 0'],
    ['an unknown name (parameter 0)', (ns) => fs.writeFileSync(path.join(ns, 'notes.txt'), 'x'), 'ANCHOR_PACKAGE_INCOMPLETE 0'],
    ['a request file 15.tsq (parameter 15)', (ns) => fs.writeFileSync(path.join(ns, '15.tsq'), 'x'), 'ANCHOR_PACKAGE_INCOMPLETE 15'],
    ['a temporary file 15.tsr.tmp (parameter 15)', (ns) => fs.writeFileSync(path.join(ns, '15.tsr.tmp'), 'x'), 'ANCHOR_PACKAGE_INCOMPLETE 15'],
    ['an oversized decimal filename keeps its exact value', (ns) => fs.writeFileSync(path.join(ns, '123456789012345678901234567890.tsr'), 'x'), 'ANCHOR_PACKAGE_INCOMPLETE 123456789012345678901234567890'],
    ['several failures: the smallest parameter wins, 0 first', (ns) => { fs.writeFileSync(path.join(ns, '15.tsq'), 'x'); fs.writeFileSync(path.join(ns, 'zz'), 'x'); }, 'ANCHOR_PACKAGE_INCOMPLETE 0'],
    ['several failures: 15 before 20', (ns) => { fs.writeFileSync(path.join(ns, '15.tsq'), 'x'); fs.rmSync(path.join(ns, '20.tsr')); }, 'ANCHOR_PACKAGE_INCOMPLETE 15'],
    ['.writer.lock is ignored', (ns) => fs.writeFileSync(path.join(ns, '.writer.lock'), ''), 'VERIFIED_ANCHORED 0..20'],
  ];
  for (const [label, change, expected] of v) await t.test(label, () => assert.equal(withNamespace(s, change), expected));
  await t.test('inventory precedes the package loop (a bad package 10 and an unpaired 20)', () => {
    const bad = at10((_c, b) => ({ ...b, badSignature: true }));
    assert.equal(withNamespace(bad, (ns) => fs.rmSync(path.join(ns, '20.tsr'))), 'ANCHOR_PACKAGE_INCOMPLETE 20');
  });
});

// ---------------- AC-13 package schema ----------------

function withPackageJson(edit: (o: Record<string, unknown>, raw: string) => string | Record<string, unknown>): Scenario {
  const s = buildScenario({ last: 25, pki });
  const p = s.packages.get(10)!;
  const raw = Buffer.from(p.json).toString('utf8');
  const out = edit(JSON.parse(raw) as Record<string, unknown>, raw);
  p.json = Buffer.from(typeof out === 'string' ? out : JSON.stringify(out), 'utf8');
  return s;
}

test('003 AC-13 package-schema', async (t) => {
  const INC = expectAt10('ANCHOR_PACKAGE_INCOMPLETE');
  const v: [string, Parameters<typeof withPackageJson>[0]][] = [
    ['not JSON', () => '{'],
    ['invalid UTF-8', () => '�'],
    ['a BOM', (_o, raw) => `﻿${raw}`],
    ['a duplicate key', (_o, raw) => raw.replace('{', '{"anchor_version":"1.0",')],
    ['an extra key', (o) => ({ ...o, extra: 1 })],
    ['a missing key', (o) => { delete o['tsq_der_sha256']; return o; }],
    ['anchor_version "1.1"', (o) => ({ ...o, anchor_version: '1.1' })],
    ['an uppercase chain_id', (o) => ({ ...o, chain_id: String(o['chain_id']).toUpperCase() })],
    ['another chain_id', (o) => ({ ...o, chain_id: '00000000-0000-4000-8000-000000000000' })],
    ['anchored_seq not equal to k', (o) => ({ ...o, anchored_seq: 11 })],
    ['anchored_seq as a string', (o) => ({ ...o, anchored_seq: '10' })],
    ['an uppercase entry_hash', (o) => ({ ...o, entry_hash: String(o['entry_hash']).toUpperCase() })],
    ['block.seq not equal to k', (o) => ({ ...o, block: { ...(o['block'] as object), seq: 11 } })],
    ['block that does not hash to entry_hash', (o) => ({ ...o, block: { ...(o['block'] as object), ts: '2026-11-13T12:00:02.001Z' } })],
    ['request_nonce_hex outside [4-7]', (o) => ({ ...o, request_nonce_hex: '8123456789abcdef' })],
    ['request_nonce_hex of 15 characters', (o) => ({ ...o, request_nonce_hex: '412345678abcdef' })],
    ['tsq_der_sha256 not hex64', (o) => ({ ...o, tsq_der_sha256: 'x' })],
  ];
  for (const [label, edit] of v) await t.test(`${label} → ANCHOR_PACKAGE_INCOMPLETE 10`, () => INC(withPackageJson(edit)));
  await t.test('invalid UTF-8 bytes', () => {
    const s = buildScenario({ last: 25, pki });
    s.packages.get(10)!.json = Buffer.concat([Buffer.from([0xff]), s.packages.get(10)!.json]);
    INC(s);
  });
  await t.test('tsq_der_sha256 is syntax-only: another valid hex64 passes', () => OK(withPackageJson((o) => ({ ...o, tsq_der_sha256: 'f'.repeat(64) }))));
});

// ---------------- AC-14 structure ----------------

test('003 AC-14 structure', async (t) => {
  await t.test('trailing bytes after TimeStampResp', () => SIG(at10((_c, b) => ({ ...b, trailing: Uint8Array.of(0) }))));
  await t.test('status 2 (rejection)', () => SIG(at10((_c, b) => ({ ...b, status: 2n }))));
  await t.test('status 1 (granted with mods) is accepted', () => OK(at10((_c, b) => ({ ...b, status: 1n }))));
  await t.test('no timeStampToken', () => SIG(at10((_c, b) => ({ ...b, omitToken: true }))));
  await t.test('detached content', () => SIG(at10((_c, b) => ({ ...b, detached: true }))));
  await t.test('eContentType is not id-ct-TSTInfo', () => SIG(at10((_c, b) => ({ ...b, eContentType: '1.2.840.113549.1.7.1' }))));
  await t.test('two SignerInfos', () => SIG(at10((_c, b) => ({ ...b, twoSigners: true }))));
  await t.test('TSTInfo version 2', () => SIG(at10((c, b) => ({ ...b, tst: tst(c, { version: 2n }) }))));
  await t.test('serialNumber 0', () => SIG(at10((c, b) => ({ ...b, tst: tst(c, { serial: 0n }) }))));
  await t.test('accuracy millis 0', () => SIG(at10((c, b) => ({ ...b, tst: tst(c, { accuracy: { millis: 0n } }) }))));
  await t.test('accuracy micros 1000', () => SIG(at10((c, b) => ({ ...b, tst: tst(c, { accuracy: { micros: 1000n } }) }))));
  await t.test('accuracy seconds negative', () => SIG(at10((c, b) => ({ ...b, tst: tst(c, { accuracy: { seconds: -1n } }) }))));
  await t.test('ordering FALSE encoded explicitly (DER default)', () => SIG(at10((c, b) => ({ ...b, tst: tst(c, { ordering: 'explicit-false' }) }))));
  await t.test('ordering TRUE is accepted', () => OK(at10((c, b) => ({ ...b, tst: tst(c, { ordering: true }) }))));
  await t.test('any valid policy OID is accepted', () => OK(at10((c, b) => ({ ...b, tst: tst(c, { policy: '2.16.840.1.114412.7.1' }) }))));
  await t.test('a critical TSTInfo extension, unknown', () => SIG(at10((c, b) => ({ ...b, tst: tst(c, { extensions: [ext.raw('1.2.3.4.9', nullValue(), true)] }) }))));
  await t.test('a critical TSTInfo extension the backend would recognize', () =>
    SIG(at10((c, b) => ({ ...b, tst: tst(c, { extensions: [ext.raw(OID.extKeyUsage, Buffer.from('03020780', 'hex'), true)] }) }))),
  );
  await t.test('a noncritical TSTInfo extension is ignored', () => OK(at10((c, b) => ({ ...b, tst: tst(c, { extensions: [ext.raw('1.2.3.4.9', Buffer.from('anything'))] }) }))));
  await t.test('duplicate TSTInfo extnIDs, noncritical', () =>
    SIG(at10((c, b) => ({ ...b, tst: tst(c, { extensions: [ext.raw('1.2.3.4.9', nullValue()), ext.raw('1.2.3.4.9', nullValue())] }) }))),
  );
  const g = (genTime: string) => at10((c, b) => ({ ...b, tst: tst(c, { genTime }) }));
  await t.test('genTime: a non-digit character (DER) → TSA_SIGNATURE_INVALID', () => SIG(g('2026111312000AZ')));
  await t.test('genTime: an offset instead of Z (DER) → TSA_SIGNATURE_INVALID', () => SIG(g('20261113120003+0000')));
  await t.test('genTime: a fraction with a trailing zero (DER) → TSA_SIGNATURE_INVALID', () => SIG(g('20261113120003.10Z')));
  await t.test('genTime: an empty fraction (DER) → TSA_SIGNATURE_INVALID', () => SIG(g('20261113120003.Z')));
  await t.test('genTime: ten fractional digits → TSA_TIME_FORMAT_INVALID', () => FMT(g('20261113120003.1234567891Z')));
  await t.test('genTime: February 30 → TSA_TIME_FORMAT_INVALID', () => FMT(g('20260230120003Z')));
  await t.test('genTime: second 60 (no leap seconds) → TSA_TIME_FORMAT_INVALID', () => FMT(g('20261113120060Z')));
  await t.test('genTime: year 0000 → TSA_TIME_FORMAT_INVALID', () => FMT(g('00001113120003Z')));
  await t.test('genTime: nine fractional digits are accepted', () => OK(g('20261113120003.123456789Z')));
});

test('003 CMS digest-set vectors (§7)', async (t) => {
  for (const d of ['sha256', 'sha384', 'sha512'] as const) {
    for (const [a, b2] of [['absent', 'absent'], ['null', 'null'], ['absent', 'null'], ['null', 'absent']] as const) {
      await t.test(`${d}: set ${a}, signer ${b2} → passes`, () =>
        OK(at10((_c, b) => ({ ...b, digest: d, digestSet: [digestAlg(d, a)], signerDigestAlg: digestAlg(d, b2) }))),
      );
    }
  }
  await t.test('an empty set', () => SIG(at10((_c, b) => ({ ...b, digestSet: [] }))));
  await t.test('an extra digest', () => SIG(at10((_c, b) => ({ ...b, digestSet: [digestAlg('sha256'), digestAlg('sha384')] }))));
  await t.test('a second encoding of the same digest', () => SIG(at10((_c, b) => ({ ...b, digestSet: [digestAlg('sha256'), digestAlg('sha256', 'null')] }))));
  await t.test('the signer digest is missing from the set', () => SIG(at10((_c, b) => ({ ...b, digest: 'sha384', digestSet: [digestAlg('sha256')] }))));
  await t.test('non-NULL parameters', () => SIG(at10((_c, b) => ({ ...b, digestSet: [digestAlg('sha256', 'other')], signerDigestAlg: digestAlg('sha256', 'other') }))));
  await t.test('an unsupported digest (SHA-1)', () => SIG(at10((_c, b) => ({ ...b, digestSet: [algorithm(OID.sha1)], signerDigestAlg: algorithm(OID.sha1) }))));
  await t.test('a digest-set failure takes precedence over an invalid genTime', () =>
    SIG(at10((c, b) => ({ ...b, digestSet: [], tst: tst(c, { genTime: '20260230120003Z' }) }))),
  );
  await t.test('MessageImprint SHA-256 stays separate from a SHA-384 or SHA-512 CMS digest', () => {
    OK(at10((_c, b) => ({ ...b, digest: 'sha384' })));
    OK(at10((_c, b) => ({ ...b, digest: 'sha512' })));
  });
});

// ---------------- AC-15 signature and path ----------------

function signerCert(over: Partial<Parameters<typeof certificate>[0]> = {}): Uint8Array {
  return certificate({
    subject: pki.signerName,
    issuer: pki.intName,
    subjectKey: pki.signerKey,
    issuerKey: pki.intKey,
    extensions: SIGNER_EXTS(),
    ...over,
  });
}

/** A scenario whose bundle pins `signer` and whose receipt at 10 is signed by it. */
function withSigner(signer: Uint8Array, bundleCerts?: Uint8Array[], token: Partial<TokenSpec> = {}, signerKey = pki.signerKey): Scenario {
  // Package 20 keeps the standard signer, so the bundle always pins it too.
  const certs = bundleCerts ?? [pki.root, pki.intermediate, signer];
  const bundle = pem(certs.includes(pki.signer) ? certs : [...certs, pki.signer]);
  const { issuer, serial } = issuerAndSerial(signer);
  return at10((_c, b) => ({ ...b, signerCert: signer, signerKey, signerIssuer: issuer, signerSerial: serial, certificates: [signer], ...token }), { bundle });
}

test('003 AC-15 signature-and-path', async (t) => {
  await t.test('a mathematically invalid CMS signature', () => SIG(at10((_c, b) => ({ ...b, badSignature: true }))));
  await t.test('message-digest does not match the TSTInfo', () => SIG(at10((_c, b) => ({ ...b, messageDigest: new Uint8Array(32) }))));
  await t.test('content-type is not id-ct-TSTInfo', () => SIG(at10((_c, b) => ({ ...b, contentTypeValue: '1.2.840.113549.1.7.1' }))));
  await t.test('content-type is missing', () => SIG(at10((_c, b) => ({ ...b, omitContentType: true }))));
  await t.test('message-digest is missing', () => SIG(at10((_c, b) => ({ ...b, omitMessageDigest: true }))));
  await t.test('a duplicate signed attribute', () => SIG(at10((_c, b) => ({ ...b, extraAttrs: [attribute(OID.attrContentType, oid(OID.tstInfo))] }))));
  await t.test('no signed attributes', () => SIG(at10((_c, b) => ({ ...b, noSignedAttrs: true }))));
  await t.test('no signing-certificate attribute', () => SIG(at10((_c, b) => ({ ...b, ess: [] }))));
  await t.test('legacy ESS (SHA-1 ESSCertID) is accepted', () => OK(at10((_c, b) => ({ ...b, ess: [{ version: 1 }] }))));
  await t.test('ESSCertIDv2 with omitted hashAlgorithm (default SHA-256) is accepted', () => OK(at10((_c, b) => ({ ...b, ess: [{ version: 2, alg: 'omit' }] }))));
  for (const d of ['sha256', 'sha384', 'sha512'] as const) {
    for (const params of ['absent', 'null'] as const) {
      await t.test(`ESSCertIDv2 explicit ${d}, ${params} parameters, is accepted`, () =>
        OK(at10((_c, b) => ({ ...b, ess: [{ version: 2, alg: digestAlg(d, params), hash: d }] }))),
      );
    }
  }
  await t.test('ESSCertIDv2 hashAlgorithm with inadmissible parameters', () =>
    SIG(at10((_c, b) => ({ ...b, ess: [{ version: 2, alg: digestAlg('sha256', 'other') }] }))),
  );
  await t.test('ESSCertIDv2 with SHA-1', () => SIG(at10((_c, b) => ({ ...b, ess: [{ version: 2, alg: algorithm(OID.sha1), hash: 'sha1' }] }))));
  await t.test('both ESS attributes agreeing are accepted', () => OK(at10((_c, b) => ({ ...b, ess: [{ version: 1 }, { version: 2 }] }))));
  await t.test('both ESS attributes, disagreeing', () => SIG(at10((_c, b) => ({ ...b, ess: [{ version: 1, cert: pki.intermediate }, { version: 2 }], certificates: [pki.signer, pki.intermediate] }))));
  await t.test('a wrong binding (the hash of another certificate)', () => SIG(at10((_c, b) => ({ ...b, ess: [{ version: 2, cert: pki.intermediate }], certificates: [pki.signer, pki.intermediate] }))));
  await t.test('a binding hash that matches no embedded certificate', () => SIG(at10((_c, b) => ({ ...b, ess: [{ version: 2, certHash: new Uint8Array(32) }] }))));
  await t.test('issuerSerial matching the signer is accepted', () => {
    const { issuer, serial } = issuerAndSerial(pki.signer);
    OK(at10((_c, b) => ({ ...b, ess: [{ version: 2, issuerSerial: { issuerName: issuer, serial } }] })));
  });
  await t.test('issuerSerial with another serial', () => {
    const { issuer, serial } = issuerAndSerial(pki.signer);
    SIG(at10((_c, b) => ({ ...b, ess: [{ version: 2, issuerSerial: { issuerName: issuer, serial: serial + 1n } }] })));
  });
  await t.test('sid naming another serial', () => SIG(at10((_c, b) => ({ ...b, signerSerial: b.signerSerial + 1n }))));
  await t.test('sid by subjectKeyIdentifier matching the signer is accepted', () => {
    const skiBytes = Buffer.from('0102030405060708090a0b0c0d0e0f1011121314', 'hex');
    const s = signerCert({ extensions: [...SIGNER_EXTS(), ext.raw('2.5.29.14', octetString(skiBytes))] });
    OK(withSigner(s, [pki.root, pki.intermediate, s], { sidKind: 'ski', ski: skiBytes }));
    SIG(withSigner(s, [pki.root, pki.intermediate, s], { sidKind: 'ski', ski: new Uint8Array(20) }));
  });
  await t.test('the CMS signature algorithm uses SHA-1', () => SIG(at10((_c, b) => ({ ...b, signatureAlg: algorithm('1.2.840.10045.4.1') }))));
  await t.test('the CMS signature algorithm disagrees with the digest', () => SIG(at10((_c, b) => ({ ...b, signatureAlg: algorithm(OID.ecdsaSha384) }))));
  await t.test('ECDSA signature algorithm with NULL parameters', () => SIG(at10((_c, b) => ({ ...b, signatureAlg: algorithm(OID.ecdsaSha256, nullValue()) }))));
  await t.test('an RSA signer with rsaEncryption and with sha256WithRSAEncryption is accepted', () => {
    const k = key('rsa2048', 11);
    const s = signerCert({ subjectKey: k });
    OK(withSigner(s, [pki.root, pki.intermediate, s], {}, k));
    OK(withSigner(s, [pki.root, pki.intermediate, s], { signatureAlg: algorithm(OID.sha256WithRSA, nullValue()) }, k));
  });
  // Pinned-profile vectors.
  await t.test('the embedded signer is not pinned', () => {
    const unpinned = signerCert({ subjectKey: key('p256', 12) });
    SIG(withSigner(unpinned, [pki.root, pki.intermediate, pki.signer], {}, key('p256', 12)));
  });
  await t.test('a rotated, unpinned signer of the same TSA', () => {
    const rotated = signerCert({ subjectKey: key('p256', 13), serial: 99n });
    SIG(withSigner(rotated, [pki.root, pki.intermediate, pki.signer], {}, key('p256', 13)));
  });
  await t.test('the token does not embed its signer', () => SIG(at10((_c, b) => ({ ...b, certificates: [] }))));
  await t.test('an intermediate present only in the bundle passes', () => OK(at10((_c, b) => ({ ...b, certificates: [pki.signer] }))));
  await t.test('an intermediate needed for the path but present only in the token fails', () =>
    SIG(withSigner(pki.signer, [pki.root, pki.signer], { certificates: [pki.signer, pki.intermediate] })),
  );
  await t.test('an unused extra embedded certificate is ignored', () => OK(at10((_c, b) => ({ ...b, certificates: [pki.root, pki.signer, sequence(integer(1n))] }))));
  await t.test('issuer and subject with the same text in different string types are unequal', () => {
    const printableIssuer = name([O, 'TEAR test'], [CN, 'Test Intermediate 0', 'printable']);
    const s = signerCert({ issuer: printableIssuer });
    SIG(withSigner(s, [pki.root, pki.intermediate, s]));
  });
  await t.test('the signer has expired at genTime', () => {
    const s = signerCert({ notAfter: new Date(Date.UTC(2026, 10, 13, 11, 0, 0)) });
    SIG(withSigner(s, [pki.root, pki.intermediate, s]));
  });
  await t.test('validity is judged at genTime, not at the local clock (a signer expired today passes)', () => {
    const s = signerCert({ notAfter: new Date(Date.UTC(2026, 10, 13, 13, 0, 0)) });
    OK(withSigner(s, [pki.root, pki.intermediate, s]));
  });
  await t.test('the intermediate has expired at genTime', () => {
    const i = certificate({ subject: pki.intName, issuer: pki.rootName, subjectKey: pki.intKey, issuerKey: pki.rootKey, extensions: [ext.bc(true)], notAfter: new Date(Date.UTC(2025, 0, 1)) });
    SIG(withSigner(pki.signer, [pki.root, i, pki.signer]));
  });
  await t.test('an intermediate signed with SHA-1', () => {
    const i = certificate({ subject: pki.intName, issuer: pki.rootName, subjectKey: pki.intKey, issuerKey: pki.rootKey, extensions: [ext.bc(true)], sigAlg: 'rsa-sha1' });
    SIG(withSigner(pki.signer, [pki.root, i, pki.signer]));
  });
  await t.test('a bad signature below an accepted root', () => {
    const i = certificate({ subject: pki.intName, issuer: pki.rootName, subjectKey: pki.intKey, issuerKey: pki.rootKey, extensions: [ext.bc(true)], badSignature: true });
    SIG(withSigner(pki.signer, [pki.root, i, pki.signer]));
  });
  await t.test('inner and outer signature algorithms disagree on the signer certificate', () => {
    const s = signerCert({ innerSigAlg: algorithm(OID.sha384WithRSA, nullValue()) });
    SIG(withSigner(s, [pki.root, pki.intermediate, s]));
  });
  await t.test('two candidate paths where only one validates, in both orders', () => {
    const forged = certificate({ subject: pki.intName, issuer: pki.rootName, subjectKey: key('rsa2048', 14), issuerKey: key('rsa2048', 15), extensions: [ext.bc(true)] });
    OK(withSigner(pki.signer, [pki.root, forged, pki.intermediate, pki.signer]));
    OK(withSigner(pki.signer, [pki.root, pki.intermediate, forged, pki.signer]));
  });
  await t.test('pathLenConstraint 0 on the upper intermediate with a second intermediate below', () => {
    const upperKey = key('rsa2048', 16);
    const upperName = cn('Upper CA');
    const upper = certificate({ subject: upperName, issuer: pki.rootName, subjectKey: upperKey, issuerKey: pki.rootKey, extensions: [ext.bc(true, true, 0n)] });
    const lower = certificate({ subject: pki.intName, issuer: upperName, subjectKey: pki.intKey, issuerKey: upperKey, extensions: [ext.bc(true)] });
    SIG(withSigner(pki.signer, [pki.root, upper, lower, pki.signer]));
    const upper1 = certificate({ subject: upperName, issuer: pki.rootName, subjectKey: upperKey, issuerKey: pki.rootKey, extensions: [ext.bc(true, true, 1n)] });
    OK(withSigner(pki.signer, [pki.root, upper1, lower, pki.signer]));
  });
  // TSTInfo.tsa identity.
  await t.test('TSTInfo.tsa as the signer subject directoryName is accepted', () => OK(at10((c, b) => ({ ...b, tst: tst(c, { tsa: directoryName(pki.signerName) }) }))));
  await t.test('TSTInfo.tsa naming another directoryName', () => SIG(at10((c, b) => ({ ...b, tst: tst(c, { tsa: directoryName(pki.intName) }) }))));
  await t.test('TSTInfo.tsa matching a subjectAltName GeneralName byte for byte', () => {
    const s = signerCert({ extensions: [...SIGNER_EXTS(), ext.san([dnsName('tsa.example.org')])] });
    const tsaTst = (c: TokenContext) => tst(c, { tsa: dnsName('tsa.example.org') });
    const bundle = pem([pki.root, pki.intermediate, s, pki.signer]);
    const { issuer, serial } = issuerAndSerial(s);
    OK(at10((c, b) => ({ ...b, tst: tsaTst(c), signerCert: s, signerIssuer: issuer, signerSerial: serial, certificates: [s] }), { bundle }));
    SIG(at10((c, b) => ({ ...b, tst: tst(c, { tsa: dnsName('other.example.org') }), signerCert: s, signerIssuer: issuer, signerSerial: serial, certificates: [s] }), { bundle }));
  });
});

// ---------------- AC-16 commitment ----------------

test('003 AC-16 commitment', async (t) => {
  await t.test('hashedMessage differs from entry_hash', () => COMMIT(at10((c, b) => ({ ...b, tst: tst(c, { hashedMessage: new Uint8Array(32) }) }))));
  await t.test('MessageImprint uses SHA-384', () => COMMIT(at10((c, b) => ({ ...b, tst: tst(c, { imprintAlg: digestAlg('sha384') }) }))));
  await t.test('MessageImprint SHA-256 with NULL parameters is accepted', () => OK(at10((c, b) => ({ ...b, tst: tst(c, { imprintAlg: digestAlg('sha256', 'null') }) }))));
  await t.test('MessageImprint SHA-256 with absent parameters is accepted', () => OK(at10((c, b) => ({ ...b, tst: tst(c, { imprintAlg: digestAlg('sha256', 'absent') }) }))));
  await t.test('MessageImprint with DER-decodable but inadmissible parameters', () => COMMIT(at10((c, b) => ({ ...b, tst: tst(c, { imprintAlg: digestAlg('sha256', 'other') }) }))));
  await t.test('nonce absent', () => COMMIT(at10((c, b) => ({ ...b, tst: tst(c, { nonce: null }) }))));
  await t.test('nonce different', () => COMMIT(at10((c, b) => ({ ...b, tst: tst(c, { nonce: c.nonce + 1n }) }))));
  await t.test('invalid genTime syntax precedes a commitment failure', () =>
    FMT(at10((c, b) => ({ ...b, tst: tst(c, { genTime: '20260230120003Z', nonce: 1n }) }))),
  );
});

// ---------------- AC-17 log relations ----------------

test('003 AC-17 log-relations', async (t) => {
  await t.test('k beyond the log → TRUNCATED_BELOW_ANCHOR 20', () => {
    const s = buildScenario({ last: 25, pki });
    s.rows.splice(16);
    const r = verifyScenario(s);
    assert.equal(r.stdout, 'TRUNCATED_BELOW_ANCHOR 20\n');
  });
  await t.test('a recomputed log that no longer matches package 10 → CHECKPOINT_DIVERGENCE 10', () => {
    const s = buildScenario({ last: 25, pki });
    (s.rows[5]!.block['payload'] as Record<string, unknown>)['reason'] = 'tampered';
    rehash(s.rows, 5);
    assert.equal(line(s), 'CHECKPOINT_DIVERGENCE 10');
  });
  const off = (genTime: string) => at10((c, b) => ({ ...b, tst: tst(c, { genTime }) }));
  // Row 10 ts is 2026-11-13T12:00:02.000Z.
  await t.test('genTime = ts + 60 s is accepted (inclusive)', () => OK(off('20261113120102Z')));
  await t.test('genTime = ts + 60.000000001 s → TSA_TIME_INCONSISTENT 10', () => expectAt10('TSA_TIME_INCONSISTENT')(off('20261113120102.000000001Z')));
  await t.test('genTime = ts - 5 s is accepted (inclusive)', () => OK(off('20261113115957Z')));
  await t.test('genTime = ts - 5.1 s → TSA_TIME_INCONSISTENT 10', () => expectAt10('TSA_TIME_INCONSISTENT')(off('20261113115956.9Z')));
});

// ---------------- AC-18 control relations ----------------

function setControl(s: Scenario, seq: number, fields: Record<string, unknown>): void {
  const p = s.rows[seq]!.block['payload'] as Record<string, unknown>;
  Object.assign(p, fields);
  rehash(s.rows, seq);
}

test('003 AC-18 control-relations', async (t) => {
  // Rows changed here come after every package they could affect, so Step 2 still passes.
  await t.test('anchored_seq not equal to seq-1 → CONTROL_EVENT_INVALID 11', () => {
    const s = buildScenario({ last: 25, pki, anchors: [10] });
    setControl(s, 11, { anchored_seq: 9 });
    assert.equal(line(s), 'CONTROL_EVENT_INVALID 11');
  });
  await t.test('checkpoint_failed with target_seq not equal to seq-1', () => {
    const s = buildScenario({ last: 25, pki, anchors: [10], failedAt: [16] });
    setControl(s, 16, { target_seq: 14 });
    assert.equal(line(s), 'CONTROL_EVENT_INVALID 16');
  });
  await t.test('a target after the control row (not present before it)', () => {
    const s = buildScenario({ last: 25, pki, anchors: [10], failedAt: [16] });
    setControl(s, 16, { target_seq: 30 });
    assert.equal(line(s), 'CONTROL_EVENT_INVALID 16');
  });
  await t.test('target 0 is a Step 1 schema failure, not a Step 2b one', () => {
    const s = buildScenario({ last: 25, pki, failedAt: [1] });
    assert.equal(line(s), 'JCS_SCHEMA_INVALID 1');
  });
  await t.test('tsr_sha256 differs from the receipt → CHECKPOINT_METADATA_MISMATCH 21', () => {
    const s = buildScenario({ last: 25, pki });
    setControl(s, 21, { tsr_sha256: 'a'.repeat(64) });
    assert.equal(line(s), 'CHECKPOINT_METADATA_MISMATCH 21');
  });
  await t.test('tsa_gen_time differs lexically from the receipt', () => {
    const s = buildScenario({ last: 25, pki, anchors: [10] });
    const g = String((s.rows[11]!.block['payload'] as Record<string, unknown>)['tsa_gen_time']);
    setControl(s, 11, { tsa_gen_time: g.replace('Z', '.5Z') });
    assert.equal(line(s), 'CHECKPOINT_METADATA_MISMATCH 11');
  });
  await t.test('at one row, a target failure precedes a metadata failure', () => {
    const s = buildScenario({ last: 25, pki, anchors: [10] });
    setControl(s, 11, { anchored_seq: 9, tsr_sha256: 'a'.repeat(64) });
    assert.equal(line(s), 'CONTROL_EVENT_INVALID 11');
  });
  await t.test('Step 2b runs only after every package passed Step 2', () => {
    const s = buildScenario({ last: 25, pki });
    setControl(s, 11, { anchored_seq: 9 });
    const pkg20 = s.packages.get(20)!;
    pkg20.tsr = Uint8Array.of(0x30, 0x00);
    assert.equal(line(s), 'TSA_SIGNATURE_INVALID 20');
  });
  await t.test('a missing package skips receipt equality and reports ANCHOR_EVIDENCE_MISSING', () => {
    const s = buildScenario({ last: 25, pki, anchors: [10] });
    s.packages.delete(10);
    setControl(s, 11, { tsr_sha256: 'a'.repeat(64) });
    const r = verifyScenario(s);
    assert.equal(r.exitCode, 0);
    assert.equal(r.stdout, 'VALID_UNANCHORED 0..25\nANCHOR_EVIDENCE_MISSING 10\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
  await t.test('a valid package without a control row (the export ends at k)', () => {
    const s = buildScenario({ last: 25, pki });
    s.rows.splice(21);
    const r = verifyScenario(s);
    assert.equal(r.exitCode, 0);
    assert.match(r.stdout, /^VERIFIED_ANCHORED 0..20\nMAX_ANCHOR_GAP 10\n/);
  });
});

// ---------------- AC-19 coverage ----------------

test('003 AC-19 coverage', async (t) => {
  await t.test('zero anchors', () => {
    const s = buildScenario({ last: 5, pki, anchors: [] });
    assert.equal(verifyScenario(s).stdout, 'VALID_UNANCHORED 0..5\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\n');
  });
  await t.test('one anchor at the head: no unanchored tail', () => {
    const s = buildScenario({ last: 10, pki, anchors: [10] });
    const g = s.packages.get(10)!.genTime;
    assert.equal(
      verifyScenario(s).stdout,
      `VERIFIED_ANCHORED 0..10\nMAX_ANCHOR_GAP 0\nANCHORED_CHECKPOINT_FAILURES 0\nANCHOR_TIME 10 ${g} ACCURACY_NS unspecified LATEST_BOUND_NS unspecified\n`,
    );
  });
  await t.test('several anchors, the largest gap, and failures counted only up to max_k', () => {
    const s = buildScenario({ last: 45, pki, anchors: [10, 20, 40], failedAt: [16, 31, 44] });
    const out = verifyScenario(s).stdout.split('\n');
    assert.deepEqual(out.slice(0, 4), ['VERIFIED_ANCHORED 0..40', 'VALID_UNANCHORED 41..45', 'MAX_ANCHOR_GAP 20', 'ANCHORED_CHECKPOINT_FAILURES 2']);
  });
  await t.test('ANCHOR_TIME with accuracy present: ACCURACY_NS and LATEST_BOUND_NS', () => {
    const s = at10((c, b) => ({ ...b, tst: tst(c, { accuracy: { seconds: 1n, millis: 500n, micros: 7n }, genTime: '20261113120003.25Z' }) }));
    const r = verifyScenario(s).stdout.split('\n').find((l) => l.startsWith('ANCHOR_TIME 10 '))!;
    const base = parseGeneralizedTimeNs('20261113120003.25Z')!;
    assert.equal(r, `ANCHOR_TIME 10 20261113120003.25Z ACCURACY_NS 1500007000 LATEST_BOUND_NS ${(base + 1_500_007_000n).toString()}`);
  });
  await t.test('accuracy with only millis: absent subfields count as zero', () => {
    const s = at10((c, b) => ({ ...b, tst: tst(c, { accuracy: { millis: 3n } }) }));
    const r = verifyScenario(s).stdout.split('\n').find((l) => l.startsWith('ANCHOR_TIME 10 '))!;
    assert.match(r, / ACCURACY_NS 3000000 LATEST_BOUND_NS \d+$/);
  });
  await t.test('incomplete execution and evidence-missing lines keep their §6b order', () => {
    const s = buildScenario({ last: 25, pki });
    s.packages.delete(20);
    const out = verifyScenario(s).stdout.split('\n');
    assert.deepEqual(out.slice(0, 5), ['VERIFIED_ANCHORED 0..10', 'VALID_UNANCHORED 11..25', 'ANCHOR_EVIDENCE_MISSING 20', 'MAX_ANCHOR_GAP 0', 'ANCHORED_CHECKPOINT_FAILURES 0']);
  });
});

// ---------------- AC-20 closed inputs ----------------

const GUARD = `
import net from 'node:net';
import dns from 'node:dns';
import tls from 'node:tls';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
const deny = (what) => () => { process.stderr.write('NETWORK ' + what + '\\n'); process.exit(97); };
net.Socket.prototype.connect = deny('net.connect');
net.connect = deny('net.connect'); net.createConnection = deny('net.createConnection');
tls.connect = deny('tls.connect'); dns.lookup = deny('dns.lookup'); dns.resolve = deny('dns.resolve');
globalThis.fetch = deny('fetch');
const allowed = (process.env.TEAR_ALLOWED_ROOTS || '').split(':');
const watch = (orig, name) => function (p, ...rest) {
  const s = typeof p === 'string' ? p : p instanceof URL ? p.pathname : '';
  if (s !== '' && !allowed.some((a) => s.startsWith(a))) { process.stderr.write('FILE ' + name + ' ' + s + '\\n'); process.exit(98); }
  return orig.call(this, p, ...rest);
};
for (const n of ['openSync', 'readFileSync', 'readdirSync', 'statSync', 'lstatSync']) fs[n] = watch(fs[n], n);
syncBuiltinESMExports();
`;

test('003 AC-20 closed-inputs', async (t) => {
  await t.test('verification opens only the log, the namespace and the bundle, and never the network', () => {
    const s = buildScenario({ last: 25, pki });
    const inputs = writeScenario(s);
    const dir = path.dirname(path.resolve(inputs.checkpointsPath));
    const guardPath = path.join(dir, 'guard.mjs');
    fs.writeFileSync(guardPath, GUARD);
    const r = spawnSync(process.execPath, ['--import', guardPath, CLI_PATH, ...cliArgs(inputs)], {
      encoding: 'utf8',
      env: { ...process.env, TEAR_ALLOWED_ROOTS: `${dir}:${path.resolve('dist')}:${path.resolve('node_modules')}`, SSL_CERT_FILE: '/nonexistent', SSL_CERT_DIR: '/nonexistent' },
    });
    assert.equal(r.stderr, '');
    assert.equal(r.status, 0);
    assert.match(r.stdout, /^VERIFIED_ANCHORED 0..20\n/);
  });
  await t.test('a path that needs a certificate outside the bundle and the token fails; nothing else is searched', () => {
    SIG(withSigner(pki.signer, [pki.root, pki.signer], { certificates: [pki.signer] }));
  });
});

// ---------------- AC-21 stage precedence ----------------

test('003 AC-21 stage-precedence', async (t) => {
  await t.test('a critical TSTInfo extension (2.2) with a commitment defect (2.4) → TSA_SIGNATURE_INVALID', () =>
    SIG(at10((c, b) => ({ ...b, tst: tst(c, { extensions: [ext.raw('1.2.3.4.9', nullValue(), true)], nonce: 5n }) }))),
  );
  await t.test('a signature defect (2.3) with a commitment defect (2.4) → TSA_SIGNATURE_INVALID', () =>
    SIG(at10((c, b) => ({ ...b, badSignature: true, tst: tst(c, { hashedMessage: new Uint8Array(32) }) }))),
  );
  await t.test('a profile defect at 20 with k beyond the log → TSA_SIGNATURE_INVALID 20, not TRUNCATED_BELOW_ANCHOR', () => {
    const s = buildScenario({ last: 25, pki, token: (c) => timeStampResp({ ...baseTokenSpec(c), badSignature: c.k === 20 }) });
    s.rows.splice(16);
    assert.equal(line(s), 'TSA_SIGNATURE_INVALID 20');
  });
  await t.test('a package identity defect (2.1) precedes a structural defect (2.2)', () => {
    const s = withPackageJson((o) => ({ ...o, anchored_seq: 11 }));
    s.packages.get(10)!.tsr = Uint8Array.of(0x30, 0x00);
    expectAt10('ANCHOR_PACKAGE_INCOMPLETE')(s);
  });
  await t.test('a commitment defect (2.4) precedes a control defect (2b)', () => {
    const s = at10((c, b) => ({ ...b, tst: tst(c, { nonce: 5n }) }));
    setControl(s, 21, { tsr_sha256: 'a'.repeat(64) });
    COMMIT(s);
  });
});

