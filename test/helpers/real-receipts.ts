// SPDX-License-Identifier: AGPL-3.0-or-later
// The real TSA receipts that test/local/openssl-crosscheck.test.ts compares with OpenSSL.

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface RealReceipt {
  readonly label: string;
  readonly file: string;
}

/**
 * The receipts cross-checked against OpenSSL: every distinct real receipt in the repository — the frozen
 * fixture's four, the four replacement receipts of T6a and T6b, and the distinct B2 receipts (the pre-close and
 * post-close copies share bytes; each distinct receipt is listed once).
 */
export function crossCheckedReceipts(): RealReceipt[] {
  const out: RealReceipt[] = [];
  const frozen = path.resolve('test/fixtures/frozen-m1');
  const m = JSON.parse(fs.readFileSync(path.join(frozen, 'manifest.json'), 'utf8')) as { chain_id: string; receipts: { k: number }[] };
  for (const r of m.receipts) out.push({ label: `frozen ${String(r.k)}`, file: path.join(frozen, m.chain_id, `${String(r.k)}.tsr`) });
  const tamper = path.resolve('test/fixtures/tamper-receipts');
  for (const f of fs.readdirSync(tamper).filter((n) => n.endsWith('.tsr')).sort()) out.push({ label: f.replace(/\.tsr$/, ''), file: path.join(tamper, f) });
  const seen = new Set<string>();
  for (const phase of ['pre-close', 'post-close']) {
    const dir = path.resolve('experiments/b2', phase);
    const ns = fs.readdirSync(dir).find((n) => n !== 'events.jsonl')!;
    for (const f of fs.readdirSync(path.join(dir, ns)).filter((n) => n.endsWith('.tsr'))) {
      const bytes = fs.readFileSync(path.join(dir, ns, f)).toString('base64');
      if (seen.has(bytes)) continue;
      seen.add(bytes);
      out.push({ label: `B2 ${f.replace(/\.tsr$/, '')}`, file: path.join(dir, ns, f) });
    }
  }
  return out;
}
