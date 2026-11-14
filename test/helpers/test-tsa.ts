// SPDX-License-Identifier: AGPL-3.0-or-later
// In-process TSA for writer tests: reads the DER request with the production
// reader and answers with a receipt signed by the test PKI. Its behavior can be
// replaced per call to produce every §5.7 step 2 and step 3 failure.

import { children, decodeDer } from '../../src/asn1/der.js';
import { integer, octetString } from '../../src/asn1/types.js';
import type { TransportResult, TsaEndpoint } from '../../src/tsa/transport.js';
import { genTimeOf, issuerAndSerial, timeStampResp, tstInfo } from './pki.js';
import type { TestPki, TokenSpec, TstSpec } from './pki.js';

export interface ParsedRequest {
  readonly der: Uint8Array;
  readonly hashedMessage: Uint8Array;
  readonly nonce: bigint;
}

export function parseRequest(der: Uint8Array): ParsedRequest {
  const doc = decodeDer(der);
  const f = children(doc, doc.root);
  const mi = children(doc, f[1]!);
  return { der, hashedMessage: octetString(doc, mi[1], 'hash'), nonce: integer(doc, f[2], 'nonce') };
}

export type Behavior =
  | { kind: 'ok'; tst?: Partial<TstSpec>; token?: Partial<TokenSpec>; genTimeOffsetMs?: number }
  | { kind: 'transport'; result: TransportResult }
  | { kind: 'body'; body: Uint8Array }
  | { kind: 'custom'; run: (req: ParsedRequest) => Promise<TransportResult> };

export interface TestTsa extends TsaEndpoint {
  readonly requests: ParsedRequest[];
  /** Behavior for each call, in order; the last one repeats. Default: ok. */
  behaviors: Behavior[];
}

export function testTsa(name: string, pki: TestPki, clock: () => number = Date.now): TestTsa {
  const t: TestTsa = {
    name,
    requests: [],
    behaviors: [{ kind: 'ok' }],
    async request(der) {
      const req = parseRequest(der);
      t.requests.push(req);
      const b = t.behaviors[Math.min(t.requests.length - 1, t.behaviors.length - 1)] ?? { kind: 'ok' };
      if (b.kind === 'transport') return b.result;
      if (b.kind === 'body') return { kind: 'response', body: b.body };
      if (b.kind === 'custom') return b.run(req);
      const { issuer, serial } = issuerAndSerial(pki.signer);
      const tst = tstInfo({
        hashedMessage: req.hashedMessage,
        genTime: genTimeOf(new Date(clock() + (b.genTimeOffsetMs ?? 0))),
        nonce: req.nonce,
        ...b.tst,
      });
      return {
        kind: 'response',
        body: timeStampResp({ tst, signerCert: pki.signer, signerKey: pki.signerKey, signerIssuer: issuer, signerSerial: serial, ...b.token }),
      };
    },
  };
  return t;
}
