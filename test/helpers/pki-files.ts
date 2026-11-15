// SPDX-License-Identifier: AGPL-3.0-or-later
// Shares a run-time test PKI between a test and its child process through a
// temporary directory (never the repository): certificates, bundle and the
// private keys generated for this run.

import { createPrivateKey, createPublicKey } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { KeyPair, TestPki } from './pki.js';

const KEYS = ['rootKey', 'intKey', 'signerKey'] as const;
const DERS = ['rootName', 'intName', 'signerName', 'root', 'intermediate', 'signer'] as const;

export function savePki(pki: TestPki, dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
  for (const k of KEYS) {
    const kp = pki[k];
    fs.writeFileSync(path.join(dir, `${k}.pem`), kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(path.join(dir, `${k}.family`), kp.family);
  }
  for (const d of DERS) fs.writeFileSync(path.join(dir, `${d}.der`), pki[d]);
  fs.writeFileSync(path.join(dir, 'bundle.pem'), pki.bundle);
}

export function loadPki(dir: string): TestPki {
  const key = (k: (typeof KEYS)[number]): KeyPair => {
    const privateKey = createPrivateKey(fs.readFileSync(path.join(dir, `${k}.pem`)));
    return { privateKey, publicKey: createPublicKey(privateKey), family: fs.readFileSync(path.join(dir, `${k}.family`), 'utf8') as 'rsa' | 'ec' };
  };
  const der = (d: (typeof DERS)[number]): Uint8Array => new Uint8Array(fs.readFileSync(path.join(dir, `${d}.der`)));
  return {
    rootKey: key('rootKey'),
    intKey: key('intKey'),
    signerKey: key('signerKey'),
    rootName: der('rootName'),
    intName: der('intName'),
    signerName: der('signerName'),
    root: der('root'),
    intermediate: der('intermediate'),
    signer: der('signer'),
    bundle: fs.readFileSync(path.join(dir, 'bundle.pem')),
  };
}
