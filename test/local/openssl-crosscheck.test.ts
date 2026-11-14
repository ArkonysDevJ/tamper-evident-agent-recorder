// SPDX-License-Identifier: AGPL-3.0-or-later
// Local check (npm run test:local; needs the openssl command, no network):
// the in-repository DER reader against OpenSSL on every real receipt of the
// frozen fixture and every real certificate (pinned and embedded). It compares
// the TLV tree (offsets, header and content lengths, depth, constructed flag)
// and the extracted fields: subject, issuer, serial, critical extensions,
// genTime, messageImprint and nonce.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { checkTree, children, decodeDer } from '../../src/asn1/der.js';
import type { DerDocument, Tlv } from '../../src/asn1/der.js';
import { parsePemBundle } from '../../src/pki/bundle.js';
import { parseCertificate } from '../../src/pki/certificate.js';
import { parseReceipt } from '../../src/tsa/receipt.js';
import { FIXTURE_DIR } from '../fixture-tools/fixture-files.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tear-openssl-'));
let fileNo = 0;
function tmpFile(bytes: Uint8Array): string {
  const p = path.join(tmp, `f${String(fileNo++)}.der`);
  fs.writeFileSync(p, bytes);
  return p;
}

function openssl(args: string[]): string {
  return execFileSync('openssl', args, { encoding: 'latin1' });
}

interface Node {
  offset: number;
  depth: number;
  hl: number;
  l: number;
  cons: boolean;
}

/** `openssl asn1parse` lines: "  off:d=D  hl=H l=  L cons|prim: ...". */
function opensslTree(bytes: Uint8Array, strparse?: number): Node[] {
  const args = ['asn1parse', '-inform', 'DER', '-in', tmpFile(bytes)];
  if (strparse !== undefined) args.push('-strparse', String(strparse));
  return openssl(args)
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => {
      const m = /^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)\s+(cons|prim):/.exec(l);
      assert.ok(m !== null, l);
      return { offset: +m[1]!, depth: +m[2]!, hl: +m[3]!, l: +m[4]!, cons: m[5] === 'cons' };
    });
}

function ourTree(doc: DerDocument, el: Tlv = doc.root, out: Node[] = []): Node[] {
  out.push({ offset: el.start, depth: el.depth, hl: el.contentStart - el.start, l: el.end - el.contentStart, cons: el.constructed });
  if (el.constructed) for (const c of children(doc, el)) ourTree(doc, c, out);
  return out;
}

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

/** Byte slice of the d=2 child `index` of the TBSCertificate, located from openssl's own tree. */
function tbsChildBytes(der: Uint8Array, nodes: Node[], index: number): Uint8Array {
  const kids = nodes.filter((n) => n.depth === 2 && n.offset < nodes[1]!.offset + nodes[1]!.hl + nodes[1]!.l);
  const n = kids[index]!;
  return der.subarray(n.offset, n.offset + n.hl + n.l);
}

const EXT_NAMES: Record<string, string> = {
  'X509v3 Basic Constraints': '2.5.29.19',
  'X509v3 Key Usage': '2.5.29.15',
  'X509v3 Extended Key Usage': '2.5.29.37',
  'X509v3 Subject Alternative Name': '2.5.29.17',
  'X509v3 Certificate Policies': '2.5.29.32',
  'X509v3 Name Constraints': '2.5.29.30',
  'X509v3 Subject Key Identifier': '2.5.29.14',
  'X509v3 Authority Key Identifier': '2.5.29.35',
  'X509v3 CRL Distribution Points': '2.5.29.31',
  'Authority Information Access': '1.3.6.1.5.5.7.1.1',
};

function crossCheckCertificate(der: Uint8Array, label: string): void {
  const doc = decodeDer(der);
  checkTree(doc);
  const nodes = opensslTree(der);
  assert.deepEqual(ourTree(doc), nodes, `${label}: TLV tree`);
  const cert = parseCertificate(der);
  // TBSCertificate children: [0] version, serial, signature, issuer, validity, subject.
  assert.equal(hex(cert.issuer), hex(tbsChildBytes(der, nodes, 3)), `${label}: issuer`);
  assert.equal(hex(cert.subject), hex(tbsChildBytes(der, nodes, 5)), `${label}: subject`);
  const file = tmpFile(der);
  const serial = /serial=([0-9A-F]+)/.exec(openssl(['x509', '-inform', 'DER', '-in', file, '-noout', '-serial']))![1]!;
  assert.equal(BigInt(`0x${serial}`), cert.serial, `${label}: serial`);
  const text = openssl(['x509', '-inform', 'DER', '-in', file, '-noout', '-text']);
  const critical = [...text.matchAll(/^\s+([^\n:]+): critical$/gm)].map((m) => EXT_NAMES[m[1]!.trim()] ?? m[1]!.trim()).sort();
  assert.deepEqual(cert.extensions.filter((e) => e.critical).map((e) => e.oid).sort(), critical, `${label}: critical extensions`);
}

const manifest = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.json'), 'utf8')) as { chain_id: string; receipts: { k: number }[] };
const ns = path.join(FIXTURE_DIR, manifest.chain_id);

test('DER reader against openssl: pinned bundle certificates', async (t) => {
  for (const [i, der] of parsePemBundle(fs.readFileSync('certs/tsa_roots.pem')).entries()) {
    await t.test(`bundle certificate ${String(i)}`, () => crossCheckCertificate(der, `bundle ${String(i)}`));
  }
});

test('DER reader against openssl: real receipts of the frozen fixture', async (t) => {
  for (const { k } of manifest.receipts) {
    await t.test(`receipt ${String(k)}`, async (t2) => {
      const tsr = fs.readFileSync(path.join(ns, `${String(k)}.tsr`));
      const doc = decodeDer(tsr);
      checkTree(doc);
      await t2.test('TLV tree of the whole TimeStampResp', () => assert.deepEqual(ourTree(doc), opensslTree(tsr)));
      const parsed = parseReceipt(tsr);
      assert.ok(parsed.ok);
      const r = parsed.receipt;
      // Locate the eContent OCTET STRING in openssl's tree and parse it with -strparse.
      const eOffset = tsr.indexOf(Buffer.from(r.eContent)) - (r.eContent.length < 128 ? 2 : r.eContent.length < 256 ? 3 : 4);
      await t2.test('TLV tree of the TSTInfo', () => assert.deepEqual(ourTree(decodeDer(r.eContent)), opensslTree(tsr, eOffset)));
      const tstLines = openssl(['asn1parse', '-inform', 'DER', '-in', tmpFile(tsr), '-strparse', String(eOffset)]);
      await t2.test('genTime', () => assert.equal(/GENERALIZEDTIME\s+:(\S+)/.exec(tstLines)![1], r.tstInfo.genTime));
      const reply = openssl(['ts', '-reply', '-in', tmpFile(tsr), '-text']);
      await t2.test('serial and nonce', () => {
        assert.equal(BigInt(/Serial number: (0x[0-9A-F]+)/.exec(reply)![1]!), r.tstInfo.serial);
        assert.equal(BigInt(/Nonce: (0x[0-9A-F]+)/.exec(reply)![1]!), r.tstInfo.nonce);
      });
      await t2.test('messageImprint', () => {
        assert.equal(/Hash Algorithm: (\S+)/.exec(reply)![1], 'sha256');
        const dump = [...reply.matchAll(/^\s+[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -]){15}[0-9a-f]{2})/gm)].map((m) => m[1]!.replace(/[ -]/g, '')).join('');
        assert.equal(dump, hex(r.tstInfo.hashedMessage));
      });
      await t2.test('embedded certificates', () => {
        for (const [i, der] of r.certificates.entries()) crossCheckCertificate(der, `receipt ${String(k)} certificate ${String(i)}`);
      });
    });
  }
});
