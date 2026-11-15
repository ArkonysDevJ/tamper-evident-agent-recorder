// SPDX-License-Identifier: AGPL-3.0-or-later
// The real TSA receipts that test/local/openssl-crosscheck.test.ts compares with OpenSSL.

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface RealReceipt {
  readonly label: string;
  readonly file: string;
}

/** The receipts cross-checked against OpenSSL: the frozen fixture's four. */
export function crossCheckedReceipts(): RealReceipt[] {
  const dir = path.resolve('test/fixtures/frozen-m1');
  const m = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8')) as { chain_id: string; receipts: { k: number }[] };
  return m.receipts.map((r) => ({ label: `frozen ${String(r.k)}`, file: path.join(dir, m.chain_id, `${String(r.k)}.tsr`) }));
}
