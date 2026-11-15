// SPDX-License-Identifier: AGPL-3.0-or-later
// Review finding 6: the OpenSSL cross-check must cover every real receipt in the repository, not only the four of
// the frozen fixture: 4 frozen, 4 replacement (T6a, T6b) and 17 distinct B2 receipts.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { test } from 'node:test';
import { crossCheckedReceipts } from '../helpers/real-receipts.js';

test('review H6: the OpenSSL cross-check covers the 25 distinct real receipts', () => {
  const list = crossCheckedReceipts();
  const distinct = new Set(list.map((r) => createHash('sha256').update(fs.readFileSync(r.file)).digest('hex')));
  assert.equal(distinct.size, 25);
  assert.equal(list.filter((r) => r.label.startsWith('frozen')).length, 4);
  assert.equal(list.filter((r) => r.label.startsWith('T6')).length, 4);
  assert.equal(list.filter((r) => r.label.startsWith('B2')).length, 17);
});
