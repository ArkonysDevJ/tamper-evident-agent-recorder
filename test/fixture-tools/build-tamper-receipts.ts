// SPDX-License-Identifier: AGPL-3.0-or-later
// Requests, once, the fresh real receipts that T6a and T6b need (Blueprint
// §7) and stores them with the T6b base time, so that the tamper battery runs
// offline and identically every time. Needs network access to the two TSAs;
// refuses to overwrite stored receipts.
//
// Implementation choice (not normative): the receipts for 30 come from
// FreeTSA and those for 40 from DigiCert, so the battery replaces receipts of
// both retained TSAs; four requests in total.
//
// Run: npm run tamper:receipts

import * as fs from 'node:fs';
import * as path from 'node:path';
import { sha256Hex } from '../../src/crypto/digests.js';
import { loadBundle } from '../../src/pki/bundle.js';
import { checkReceipt } from '../../src/tsa/receipt.js';
import { newTimeStampRequest } from '../../src/tsa/request.js';
import { RETAINED_TSA_URLS, httpTsa } from '../../src/tsa/transport.js';
import { CASES } from '../tamper/cases.js';
import type { ReceiptSource } from '../tamper/cases.js';
import { BUNDLE_PATH, Evidence } from '../tamper/model.js';
import { TAMPER_RECEIPTS_DIR } from '../tamper/receipts.js';
import type { StoredReceipt, TamperReceiptsManifest } from '../tamper/receipts.js';

const TSA_FOR: Record<30 | 40, 'freetsa' | 'digicert'> = { 30: 'freetsa', 40: 'digicert' };

async function main(): Promise<void> {
  if (fs.existsSync(TAMPER_RECEIPTS_DIR)) throw new Error(`${TAMPER_RECEIPTS_DIR} exists: stored receipts are never requested again`);
  const fixtureTs = Date.parse(new Evidence().rows[50]!.block['ts'] as string);
  if (Date.now() - fixtureTs <= 10 * 60_000) throw new Error('§7: the fixture timestamps must be more than 10 minutes old');
  const bundle = loadBundle(fs.readFileSync(BUNDLE_PATH));
  const files = new Map<string, Uint8Array>();
  const receipts: Record<string, StoredReceipt> = {};
  const t6bBase = Date.now() - 3000;

  const live: ReceiptSource = {
    t6bBaseMs: () => t6bBase,
    async obtain(id, k, entryHash) {
      const tsaName = TSA_FOR[k];
      const req = newTimeStampRequest(entryHash);
      const res = await httpTsa(tsaName, RETAINED_TSA_URLS[tsaName]).request(req.der);
      if (res.kind !== 'response') throw new Error(`${id}-${String(k)}: ${res.reason} ${res.detail}`);
      const check = checkReceipt(res.body, bundle, entryHash, req.nonceHex);
      if (!check.ok) throw new Error(`${id}-${String(k)}: ${check.code} ${check.reason}`);
      const file = `${id}-${String(k)}.tsr`;
      files.set(file, res.body);
      receipts[`${id}-${String(k)}`] = {
        tsa: tsaName,
        file,
        entry_hash: entryHash,
        nonce_hex: req.nonceHex,
        tsr_sha256: sha256Hex(res.body),
        gen_time: check.receipt.tstInfo.genTime,
        serial_hex: check.receipt.tstInfo.serial.toString(16),
      };
      process.stdout.write(`${id}-${String(k)}: ${tsaName} ${check.receipt.tstInfo.genTime}\n`);
      return { tsr: res.body, nonceHex: req.nonceHex };
    },
  };
  for (const id of ['T6a-A2b', 'T6b-A2b']) await CASES.find((c) => c.id === id)!.build(live);

  const manifest: TamperReceiptsManifest = {
    description: 'Real replacement receipts for T6a and T6b (Blueprint §7), requested once; never requested again.',
    t6b_base_ms: t6bBase,
    receipts,
  };
  fs.mkdirSync(TAMPER_RECEIPTS_DIR, { recursive: true });
  for (const [f, b] of files) fs.writeFileSync(path.join(TAMPER_RECEIPTS_DIR, f), b);
  fs.writeFileSync(path.join(TAMPER_RECEIPTS_DIR, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`stored in ${TAMPER_RECEIPTS_DIR}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`tamper receipts failed: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});
