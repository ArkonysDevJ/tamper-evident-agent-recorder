// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { parseGeneralizedTimeNs, parseTimestampNs } from '../../src/time/timestamps.js';
import { timePredicate } from '../../src/tsa/receipt.js';
import { MAX_RESPONSE_BYTES, RETAINED_TSA_URLS, TSA_TIMEOUT_MS, httpTsa, retainedTsas } from '../../src/tsa/transport.js';
import { buildScenario, firstLine, verifyScenario } from '../helpers/anchors.js';
import { obj, rehash } from '../helpers/chain-builder.js';
import { testPki } from '../helpers/pki.js';

test('003 AC-9 time-rules', async (t) => {
  const ts = parseTimestampNs('2026-11-13T12:00:02.000Z')!;
  await t.test('the predicate is inclusive at -5 s and +60 s', () => {
    assert.equal(timePredicate(ts - 5_000_000_000n, ts), true);
    assert.equal(timePredicate(ts - 5_000_000_001n, ts), false);
    assert.equal(timePredicate(ts + 60_000_000_000n, ts), true);
    assert.equal(timePredicate(ts + 60_000_000_001n, ts), false);
    assert.equal(timePredicate(ts, ts), true);
  });
  await t.test('genTime grammar: valid forms and BigInt nanoseconds', () => {
    assert.equal(parseGeneralizedTimeNs('20261113120002Z'), ts);
    assert.equal(parseGeneralizedTimeNs('20261113120002.5Z'), ts + 500_000_000n);
    assert.equal(parseGeneralizedTimeNs('20261113120002.000000001Z'), ts + 1n);
    for (const bad of ['20261113120002', '20261113120002.Z', '20261113120002,5Z', '20261113120002+0000', '20261113120060Z', '20260229120002Z', '00001113120002Z', '20261113120002.1234567890Z']) {
      assert.equal(parseGeneralizedTimeNs(bad), null, bad);
    }
  });
  await t.test('the network timeout is 5000 ms per TSA, a transport bound separate from the predicate', async () => {
    assert.equal(TSA_TIMEOUT_MS, 5000);
    assert.deepEqual(retainedTsas().map((e) => e.name), ['freetsa', 'digicert']);
    assert.deepEqual(RETAINED_TSA_URLS, { freetsa: 'https://freetsa.org/tsr', digicert: 'http://timestamp.digicert.com' });
  });
});

test('003 TSA transport over HTTP (local server, no external network)', async (t) => {
  let handler: (req: http.IncomingMessage, res: http.ServerResponse) => void = () => undefined;
  const seen: { method?: string; type?: string; body?: Buffer }[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      seen.push({ method: req.method ?? '', type: req.headers['content-type'] ?? '', body: Buffer.concat(chunks) });
      handler(req, res);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}/tsr`;
  t.after(() => server.close());

  await t.test('POSTs the DER request with Content-Type application/timestamp-query', async () => {
    handler = (_q, res) => res.writeHead(200, { 'Content-Type': 'text/plain' }).end(Buffer.from([0x30, 0x00]));
    const r = await httpTsa('local', url).request(Uint8Array.of(1, 2, 3));
    assert.deepEqual(r, { kind: 'response', body: Uint8Array.of(0x30, 0x00) }, 'the response Content-Type plays no part');
    assert.deepEqual(seen.at(-1), { method: 'POST', type: 'application/timestamp-query', body: Buffer.from([1, 2, 3]) });
  });
  await t.test('an HTTP status other than 200 is a failure', async () => {
    handler = (_q, res) => res.writeHead(503).end();
    assert.deepEqual(await httpTsa('local', url).request(Uint8Array.of(1)), { kind: 'failure', reason: 'http_status', detail: '503' });
  });
  await t.test('a response slower than the timeout is a timeout failure', async () => {
    handler = (_q, res) => setTimeout(() => res.writeHead(200).end(), 600);
    const r = await httpTsa('local', url, 150).request(Uint8Array.of(1));
    assert.equal(r.kind === 'failure' && r.reason, 'timeout');
  });
  await t.test('an oversized response is a failure', async () => {
    handler = (_q, res) => res.writeHead(200).end(Buffer.alloc(MAX_RESPONSE_BYTES + 1));
    const r = await httpTsa('local', url).request(Uint8Array.of(1));
    assert.equal(r.kind === 'failure' && r.reason, 'too_large');
  });
  await t.test('a redirect is not followed', async () => {
    handler = (_q, res) => res.writeHead(302, { Location: 'http://127.0.0.1:9/' }).end();
    const r = await httpTsa('local', url).request(Uint8Array.of(1));
    assert.equal(r.kind, 'failure');
  });
  await t.test('an unreachable TSA is a network failure', async () => {
    const r = await httpTsa('local', 'http://127.0.0.1:9/').request(Uint8Array.of(1));
    assert.equal(r.kind === 'failure' && r.reason, 'network');
  });
});

test('003 AC-7 failure-path (verifier side): any non-empty error_type in the payload domain is accepted', async (t) => {
  const pki = testPki();
  for (const errorType of ['tsa_timeout', 'Ünïcode — free text', 'x', 'anchor_window_expired']) {
    await t.test(JSON.stringify(errorType), () => {
      const s = buildScenario({ last: 15, pki, anchors: [10], failedAt: [13] });
      Object.assign(s.rows[13]!.block['payload'] as object, obj({ error_type: errorType }));
      rehash(s.rows, 13);
      const r = verifyScenario(s);
      assert.equal(r.exitCode, 0);
      assert.equal(firstLine(r), 'VERIFIED_ANCHORED 0..10');
    });
  }
});
